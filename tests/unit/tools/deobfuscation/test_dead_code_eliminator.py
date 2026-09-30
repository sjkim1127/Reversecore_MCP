"""Unit tests for dead code and opaque predicate eliminator."""

import json
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
            mock_exec.return_value = ("out", 0)
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
        assert data["total_opaque_predicates"] == len(data["opaque_predicates"])
        assert data["total_dead_blocks"] == len(data["dead_blocks"]) == 0
        assert data["total_redundant_jumps"] == len(data["redundant_jumps"]) == 1
        assert data["summary_counts"] == {
            "opaque_predicates": 2,
            "dead_blocks": 0,
            "redundant_jumps": 1,
        }

    @pytest.mark.asyncio
    async def test_reports_unreachable_blocks_and_separates_redundant_jumps(self, workspace_file):
        test_bin = workspace_file("unreachable_blocks.bin")
        functions = [
            {"addr": 0x1000, "name": "first_function", "size": 0x40},
            {"offset": 0x2000, "name": "second_function", "size": 0x30},
        ]
        blocks_by_entry = {
            0x1000: [
                {"addr": 0x1000, "size": 5, "jump": 0x1005},
                {"addr": 0x1005, "size": 5, "jump": 0x1010},
                {"addr": 0x1010, "size": 1},
                {"addr": 0x1020, "size": 2, "jump": 0x1030},
                {"addr": 0x1030, "size": 1},
            ],
            0x2000: [
                {
                    "offset": 0x2000,
                    "size": 4,
                    "jump": 0x2010,
                    "instrs": [0x2000],
                },
                {"offset": 0x2010, "size": 8, "instrs": [0x2010, 0x2014]},
            ],
        }
        disassembly_by_entry = {
            0x1000: {
                "ops": [
                    {
                        "addr": 0x1000,
                        "size": 5,
                        "type": "jmp",
                        "jump": 0x1005,
                        "disasm": "jmp 0x1005",
                    }
                ]
            },
            0x2000: {"ops": []},
        }
        linear_disassembly_by_entry = {
            0x1000: [],
            0x2000: [
                {"addr": 0x2000, "size": 4, "type": "jmp", "jump": 0x2010},
                {"addr": 0x2004, "size": 4, "type": "nop", "disasm": "nop"},
                {"addr": 0x2008, "size": 4, "type": "nop", "disasm": "nop"},
                {"addr": 0x2010, "size": 4, "type": "mov", "disasm": "mov w0, 0"},
                {"addr": 0x2014, "size": 4, "type": "ret", "disasm": "ret"},
            ],
        }

        async def mock_r2_cmd(path, cmd, timeout=30):
            if "aflj" in cmd:
                return json.dumps(functions)
            entry = int(cmd.rsplit("@", maxsplit=1)[1].strip(), 0)
            if "afbj" in cmd:
                assert f"af @ {entry}" in cmd
                return json.dumps(blocks_by_entry[entry])
            if "pDj" in cmd:
                return json.dumps(linear_disassembly_by_entry[entry])
            if "pdfj" in cmd:
                assert f"af @ {entry}" in cmd
                return json.dumps(disassembly_by_entry[entry])
            return "{}"

        with patch(
            "reversecore_mcp.tools.deobfuscation.dead_code_eliminator._run_r2_command",
            side_effect=mock_r2_cmd,
        ):
            res = await eliminate_dead_code_impl(str(test_bin))

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert [(item["function"], item["address"]) for item in data["dead_blocks"]] == [
            ("first_function", "0x1020"),
            ("first_function", "0x1030"),
            ("second_function", "0x2004"),
        ]
        assert all(item["type"] == "unreachable_basic_block" for item in data["dead_blocks"])
        assert data["dead_blocks"][1]["evidence"]["incoming_edges"] == ["0x1020"]
        assert data["total_opaque_predicates"] == len(data["opaque_predicates"]) == 0
        assert data["total_dead_blocks"] == len(data["dead_blocks"]) == 3
        assert data["dead_blocks"][2]["evidence"]["instructions"] == [
            {"address": "0x2004", "size": 4, "type": "nop", "instruction": "nop"},
            {"address": "0x2008", "size": 4, "type": "nop", "instruction": "nop"},
        ]
        assert data["total_redundant_jumps"] == len(data["redundant_jumps"]) == 1
        assert data["redundant_jumps"][0]["function"] == "first_function"
        assert data["summary_counts"] == {
            "opaque_predicates": 0,
            "dead_blocks": 3,
            "redundant_jumps": 1,
        }
        assert "3 unreachable dead blocks" in data["summary"]
        assert "0 opaque predicates" in data["summary"]
        assert "1 redundant jumps" in data["summary"]
        assert [
            (
                item["function"],
                item["original_blocks"],
                item["effective_blocks"],
                item["unreachable_blocks"],
            )
            for item in data["cfg_simplifications"]
        ] == [
            ("first_function", 5, 3, 2),
            ("second_function", 3, 2, 1),
        ]
        assert data["analysis_complete"] is True
        assert data["linear_sweep_skipped_functions"] == []
