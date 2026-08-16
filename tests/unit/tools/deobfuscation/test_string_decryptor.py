"""Unit tests for string decryptor and stack string recovery engine."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.deobfuscation.deobfuscation_tools import deobfuscate_strings
from reversecore_mcp.tools.deobfuscation.string_decryptor import (
    _extract_printable_strings,
    _parse_offset,
    _parse_val,
    _run_r2_command,
    deobfuscate_strings_impl,
)


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.write_bytes(content)
        return f

    return _create


@pytest.mark.unit
class TestStringDecryptor:
    """Test deobfuscate_strings_impl and string extraction helpers."""

    def test_parse_helpers(self):
        assert _parse_offset("+ 0x20") == 0x20
        assert _parse_offset("- 0x10") == -0x10
        assert _parse_offset("+16") == 16
        assert _parse_offset("-32") == -32
        assert _parse_offset("0x40") == 0x40

        assert _parse_val("0x61") == 0x61
        assert _parse_val("97") == 97

    def test_extract_printable_strings(self):
        ascii_buf = b"\x00\x00http://c2.server.com/gate\x00\x00"
        extracted_ascii = _extract_printable_strings(ascii_buf, min_len=4)
        assert len(extracted_ascii) >= 1
        assert extracted_ascii[0]["type"] == "ascii"
        assert "http://c2.server.com/gate" in extracted_ascii[0]["string"]

        wide_buf = "powershell.exe".encode("utf-16le") + b"\x00\x00"
        extracted_wide = _extract_printable_strings(wide_buf, min_len=4)
        assert len(extracted_wide) >= 1
        assert any(x["string"] == "powershell.exe" for x in extracted_wide)

    @pytest.mark.asyncio
    async def test_run_r2_command_helper(self, workspace_file):
        test_bin = workspace_file("helper_test2.bin")
        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = ("out", 0)
            out = await _run_r2_command(test_bin, "i", timeout=5)
            assert out == "out"

    @pytest.mark.asyncio
    async def test_invalid_path_raises_validation_error(self):
        """Ensure ValidationError propagates when the path does not exist in workspace."""
        with patch(
            "reversecore_mcp.tools.deobfuscation.string_decryptor.validate_file_path",
            side_effect=ValidationError("Invalid file path"),
        ):
            with pytest.raises(ValidationError):
                await deobfuscate_strings_impl("/non/existent/path/sample.bin")

    @pytest.mark.asyncio
    async def test_invalid_path_via_tool_wrapper(self):
        res = await deobfuscate_strings("/non/existent/__no_such_file_xyzabc__.bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_stack_string_recovery_success_and_edge_cases(self, workspace_file):
        test_bin = workspace_file("sample_stack.exe")

        # Function with offset and function without offset
        afl_json = (
            '[{"offset": 4198400, "name": "sym.construct_stack_string"}, {"name": "no_offset"}]'
        )
        # Emulate mov byte [rbp - 0x20], 'c', 'm', 'd', '.', 'e', 'x', 'e', '\0'
        # and dword, qword movs
        pdf_json = """{
            "ops": [
                {"offset": 4198400, "disasm": "mov byte ptr [rbp - 0x20], 0x63", "type": "mov"},
                {"offset": 4198404, "disasm": "mov byte ptr [rbp - 0x1f], 0x6d", "type": "mov"},
                {"offset": 4198408, "disasm": "mov byte ptr [rbp - 0x1e], 0x64", "type": "mov"},
                {"offset": 4198412, "disasm": "mov byte ptr [rbp - 0x1d], 0x2e", "type": "mov"},
                {"offset": 4198416, "disasm": "mov byte ptr [rbp - 0x1c], 0x65", "type": "mov"},
                {"offset": 4198420, "disasm": "mov byte ptr [rbp - 0x1b], 0x78", "type": "mov"},
                {"offset": 4198424, "disasm": "mov byte ptr [rbp - 0x1a], 0x65", "type": "mov"},
                {"offset": 4198428, "disasm": "mov byte ptr [rbp - 0x19], 0x00", "type": "mov"},
                {"offset": 4198432, "disasm": "mov dword ptr [rsp + 0x10], 0x6e69772e", "type": "mov"},
                {"offset": 4198440, "disasm": "mov qword ptr [rsp + 0x20], 0x646c6c2e32337377", "type": "mov"}
            ]
        }"""

        async def mock_r2_cmd(path, cmd, timeout=30):
            if "aflj" in cmd:
                return afl_json
            if "pdfj" in cmd:
                return pdf_json
            return "{}"

        with patch(
            "reversecore_mcp.tools.deobfuscation.string_decryptor._run_r2_command",
            side_effect=mock_r2_cmd,
        ):
            res = await deobfuscate_strings_impl(str(test_bin))

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["total_strings_recovered"] >= 1
        assert any("cmd.exe" in item["string"] for item in data["recovered_strings"])

    @pytest.mark.asyncio
    async def test_emulated_loop_string_extraction(self, workspace_file):
        test_bin = workspace_file("xor_loop.exe")

        afl_json = '[{"offset": 4198400, "name": "sym.xor_loop"}]'
        # Loop jumping backwards (offset 4198420 jumps to 4198410)
        pdf_json = """{
            "ops": [
                {"offset": 4198400, "disasm": "xor eax, eax", "type": "xor"},
                {"offset": 4198410, "disasm": "xor byte ptr [rbp + rax], 0x5a", "type": "xor"},
                {"offset": 4198415, "disasm": "inc rax", "type": "add"},
                {"offset": 4198418, "disasm": "cmp rax, 10", "type": "cmp"},
                {"offset": 4198420, "disasm": "jl 0x40100a", "type": "cjmp", "jump": 4198410}
            ]
        }"""
        # pxj returns decrypted bytes for 'secret_payload_url'
        decrypted_bytes = list(b"https://malicious-c2.net/payload.bin\x00\x00")
        px_json = str(decrypted_bytes)

        async def mock_r2_cmd(path, cmd, timeout=30):
            if "aflj" in cmd:
                return afl_json
            if "pdfj" in cmd:
                return pdf_json
            if "pxj" in cmd:
                return px_json
            return "{}"

        with patch(
            "reversecore_mcp.tools.deobfuscation.string_decryptor._run_r2_command",
            side_effect=mock_r2_cmd,
        ):
            res = await deobfuscate_strings_impl(str(test_bin), function_address="0x401000")

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert any(
            "https://malicious-c2.net" in item["string"] for item in data["recovered_strings"]
        )
