"""Unit tests for dead code and opaque predicate eliminator."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.deobfuscation.dead_code_eliminator import (
    _run_r2_command,
    eliminate_dead_code_impl,
)
from reversecore_mcp.tools.deobfuscation.deobfuscation_tools import eliminate_dead_code


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.write_bytes(content)
        return f

    return _create


@pytest.mark.unit
class TestDeadCodeEliminator:
    """Test eliminate_dead_code_impl."""

    @pytest.mark.asyncio
    async def test_run_r2_command_helper(self, workspace_file):
        test_bin = workspace_file("helper_test3.bin")
        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = ("out", "err", 1)
            out = await _run_r2_command(test_bin, "i", timeout=5)
            assert out == "out"

    @pytest.mark.asyncio
    async def test_invalid_path_raises_validation_error(self):
        with pytest.raises(ValidationError):
            await eliminate_dead_code_impl("/non/existent/file.bin")

    @pytest.mark.asyncio
    async def test_invalid_path_via_tool_wrapper(self):
        res = await eliminate_dead_code("/non/existent/file.bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_opaque_predicate_detection(self, workspace_file):
        test_bin = workspace_file("sample_dead_code.exe")

        afl_json = '[{"offset": 4198400, "name": "sym.obfuscated_func"}, {"name": "no_offset"}]'
        afb_json = """[
            {"offset": 4198400, "size": 32, "jump": 4198432, "fail": 4198464},
            {"offset": 4198432, "size": 16, "jump": 4198464},
            {"offset": 4198464, "size": 8}
        ]"""
        # pdf with zero_xor_test and stc_jnc and redundant jump
        pdf_json = """{
            "ops": [
                {"offset": 4198400, "disasm": "xor eax, eax", "type": "xor"},
                {"offset": 4198402, "disasm": "test eax, eax", "type": "cmp"},
                {"offset": 4198404, "disasm": "jz 0x401020", "type": "cjmp", "jump": 4198432},
                {"offset": 4198410, "disasm": "stc", "type": "up"},
                {"offset": 4198411, "disasm": "jnc 0x401040", "type": "cjmp"},
                {"offset": 4198416, "disasm": "jmp 0x401015", "type": "jmp", "jump": 4198421, "size": 5}
            ]
        }"""

        async def mock_r2_cmd(path, cmd, timeout=30):
            if "aflj" in cmd:
                return afl_json
            if "afbj" in cmd:
                return afb_json
            if "pdfj" in cmd:
                return pdf_json
            return "{}"

        with patch(
            "reversecore_mcp.tools.deobfuscation.dead_code_eliminator._run_r2_command",
            side_effect=mock_r2_cmd,
        ):
            res = await eliminate_dead_code_impl(
                str(test_bin), function_address="sym.obfuscated_func"
            )

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["total_opaque_predicates"] >= 2
        pred_types = [p["type"] for p in data["opaque_predicates"]]
        assert "zero_xor_test" in pred_types
        assert "stc_jnc" in pred_types
        assert len(data["cfg_simplifications"]) >= 1
