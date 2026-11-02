"""Unit tests for API hash resolver and PEB walking detector."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.deobfuscation.api_hash_resolver import (
    RAW_FALLBACK_MAX_OFFSET,
    _run_r2_command,
    pe_has_peb_indicators,
    resolve_api_hashes_impl,
)
from reversecore_mcp.tools.deobfuscation.data.hash_algorithms import ror13
from reversecore_mcp.tools.deobfuscation.deobfuscation_tools import resolve_api_hashes


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.write_bytes(content)
        return f

    return _create


@pytest.mark.unit
class TestApiHashResolver:
    """Test resolve_api_hashes_impl and helper functions."""

    @pytest.mark.asyncio
    async def test_invalid_path_raises_validation_error(self):
        with pytest.raises(ValidationError):
            await resolve_api_hashes_impl("/non/existent/file.bin")

    @pytest.mark.asyncio
    async def test_invalid_path_via_tool_wrapper(self):
        res = await resolve_api_hashes("/non/existent/file.bin")
        assert res.status == "error"

    def test_pe_has_peb_indicators(self):
        assert pe_has_peb_indicators([{"pattern": "fs:[0x30]"}]) is True
        assert pe_has_peb_indicators([]) is False

    @pytest.mark.asyncio
    async def test_run_r2_command_helper(self, workspace_file):
        test_bin = workspace_file("helper_test.bin")
        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = ("stdout_data", 0)
            out = await _run_r2_command(test_bin, "i", timeout=5)
            assert out == "stdout_data"

    @pytest.mark.asyncio
    async def test_resolve_api_hashes_success_and_edge_cases(self, workspace_file):
        test_bin = workspace_file("sample_api.exe")

        # Mock radare2 outputs with edge cases: invalid custom hash, function without offset, corrupt pdf
        afl_json = '[{"offset": 4198400, "name": "sym.peb_resolver"}, {"name": "no_offset"}]'
        h_virtualalloc = ror13("VirtualAlloc")
        pdf_json = f"""{{
            "ops": [
                {{"offset": 4198400, "disasm": "mov eax, dword fs:[0x30]", "type": "mov"}},
                {{"offset": 4198406, "disasm": "mov edx, dword [eax + 0x0c]", "type": "mov"}},
                {{"offset": 4198412, "disasm": "push 0x{h_virtualalloc:x}", "type": "push"}},
                {{"offset": 4198417, "disasm": "push 123456789", "type": "push"}},
                {{"offset": 4198422, "disasm": "call sym.resolve_api", "type": "call"}}
            ]
        }}"""

        async def mock_r2_cmd(path, cmd, timeout=30):
            if "aflj" in cmd:
                return afl_json
            if "pdfj" in cmd:
                return pdf_json
            return "{}"

        with patch(
            "reversecore_mcp.tools.deobfuscation.api_hash_resolver._run_r2_command",
            side_effect=mock_r2_cmd,
        ):
            res = await resolve_api_hashes_impl(
                str(test_bin),
                algorithm="ror13",
                custom_hashes={
                    "0x12345678": "custom.dll!CustomSecretAPI",
                    "invalid_hash": "custom.dll!Bad",
                },
            )

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["peb_walking_detected"] is True
        assert len(data["peb_walking_indicators"]) >= 2
        assert data["total_resolved_apis"] >= 1
        assert any(item["api_name"] == "VirtualAlloc" for item in data["resolved_apis"])

    @pytest.mark.asyncio
    async def test_raw_binary_scan_fallback(self, workspace_file):
        h_virtualalloc = ror13("VirtualAlloc")
        raw_data = b"\x90\x90\x90\x90" + h_virtualalloc.to_bytes(4, "little") + b"\x90\x90\x90\x90"
        test_bin = workspace_file("raw_shellcode.bin", content=raw_data)

        # Mock r2 to return no functions so raw scan fallback triggers
        async def mock_r2_cmd(path, cmd, timeout=30):
            return "[]"

        with patch(
            "reversecore_mcp.tools.deobfuscation.api_hash_resolver._run_r2_command",
            side_effect=mock_r2_cmd,
        ):
            res = await resolve_api_hashes_impl(str(test_bin), algorithm="ror13")

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert any(item["api_name"] == "VirtualAlloc" for item in data["resolved_apis"])
        assert res.metadata["raw_scan_bytes"] == len(raw_data)
        assert res.metadata["file_size"] == len(raw_data)
        assert res.metadata["raw_scan_partial"] is False

    @pytest.mark.asyncio
    async def test_raw_fallback_bounded_read_on_large_sparse_fixture(self):
        """Verify raw fallback on large binaries is strictly bounded to the 1 MiB window."""
        h_virtualalloc = ror13("VirtualAlloc")
        h_createfilew = ror13("CreateFileW")

        # Create sparse 100 MiB file
        ws = get_workspace_config().workspace
        test_bin = ws / "large_sparse_sample.bin"
        with test_bin.open("wb") as f:
            # Place VirtualAlloc at offset 0x100 (inside 1 MiB window)
            f.seek(0x100)
            f.write(h_virtualalloc.to_bytes(4, "little"))
            # Place CreateFileW at offset 2 MiB (outside 1 MiB window)
            f.seek(2 * 1024 * 1024)
            f.write(h_createfilew.to_bytes(4, "little"))
            # Extend file to 100 MiB
            f.seek(100 * 1024 * 1024 - 1)
            f.write(b"\x00")

        file_size = test_bin.stat().st_size
        assert file_size == 100 * 1024 * 1024

        async def mock_r2_cmd(path, cmd, timeout=30):
            return "[]"

        # Intercept Path.open to track bytes read
        real_open = Path.open
        bytes_read_list: list[int] = []

        def tracked_open(self_path, *args, **kwargs):
            handle = real_open(self_path, *args, **kwargs)
            mode = args[0] if args else kwargs.get("mode", "r")
            if self_path == test_bin and "b" in mode:
                real_read = handle.read

                def tracked_read(size=-1):
                    data = real_read(size)
                    bytes_read_list.append(len(data))
                    return data

                handle.read = tracked_read
            return handle

        with (
            patch(
                "reversecore_mcp.tools.deobfuscation.api_hash_resolver._run_r2_command",
                side_effect=mock_r2_cmd,
            ),
            patch.object(
                Path, "read_bytes", side_effect=AssertionError("read_bytes() must not be called")
            ),
            patch.object(Path, "open", tracked_open),
        ):
            res = await resolve_api_hashes_impl(str(test_bin), algorithm="ror13")

        assert res.status == "success"
        data = res.data
        assert data is not None

        # 1. Bounded read verified
        assert len(bytes_read_list) >= 1
        assert max(bytes_read_list) <= RAW_FALLBACK_MAX_OFFSET + 4

        # 2. Metadata reports partial scan of large file
        assert res.metadata["raw_scan_bytes"] == RAW_FALLBACK_MAX_OFFSET
        assert res.metadata["file_size"] == file_size
        assert res.metadata["raw_scan_partial"] is True

        # 3. Only the constant in the 1 MiB window is resolved
        resolved_names = [item["api_name"] for item in data["resolved_apis"]]
        assert "VirtualAlloc" in resolved_names
        assert "CreateFileW" not in resolved_names

    @pytest.mark.asyncio
    async def test_raw_fallback_bounded_memory_on_sparse_file(self):
        """Verify peak memory consumption remains under 10 MiB on a 500 MiB sparse fixture."""
        import tracemalloc

        ws = get_workspace_config().workspace
        test_bin = ws / "huge_sparse_sample.bin"
        with test_bin.open("wb") as f:
            f.seek(0x200)
            f.write(ror13("VirtualAlloc").to_bytes(4, "little"))
            f.seek(500 * 1024 * 1024 - 1)
            f.write(b"\x00")

        async def mock_r2_cmd(path, cmd, timeout=30):
            return "[]"

        tracemalloc.start()
        try:
            with patch(
                "reversecore_mcp.tools.deobfuscation.api_hash_resolver._run_r2_command",
                side_effect=mock_r2_cmd,
            ):
                res = await resolve_api_hashes_impl(str(test_bin), algorithm="ror13")
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert res.status == "success"
        assert res.metadata["raw_scan_partial"] is True
        # If the 500MB file were read into memory, peak_bytes would exceed 500MB.
        # With bounded read, peak allocated memory for the read buffer is ~1-3 MB.
        assert peak_bytes < 10 * 1024 * 1024, f"Peak memory was too high: {peak_bytes} bytes"
