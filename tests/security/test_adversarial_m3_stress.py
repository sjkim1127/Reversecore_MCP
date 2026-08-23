# Milestone 3 Comprehensive Adversarial Stress Testing
# Tests disassembly, decompilation, xrefs, diffing, pagination, boundary conditions, and schema resilience.

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.result import (
    PaginationMeta,
    ToolError,
    ToolSuccess,
    success,
)
from reversecore_mcp.tools.analysis.diff_tools import (
    analyze_variant_changes,
    diff_binaries,
    match_libraries,
    patch_diff_1day,
)
from reversecore_mcp.tools.radare2.r2_analysis import analyze_xrefs
from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile
from reversecore_mcp.tools.radare2.radare2_mcp_tools import Radare2ToolsPlugin

pytestmark = pytest.mark.security


def get_registered_plugin_and_tools() -> tuple[Radare2ToolsPlugin, dict]:
    plugin = Radare2ToolsPlugin()
    mock_mcp = MagicMock()
    mock_mcp.tools = {}

    def capture_tool(*args, **kwargs):
        if args and callable(args[0]):
            func = args[0]
            mock_mcp.tools[func.__name__] = func
            return func

        def decorator(func):
            mock_mcp.tools[func.__name__] = func
            return func

        return decorator

    mock_mcp.tool = capture_tool
    plugin.register(mock_mcp)
    return plugin, mock_mcp.tools


# ============================================================================
# 1. Disassembly Adversarial Tests
# ============================================================================


class TestDisassemblyAdversarialStress:
    """Stress-test disassembly tool on weird, corrupt, empty, and huge functions."""

    @pytest.mark.asyncio
    async def test_disasm_empty_function_compact(self):
        """Test disassembly of an empty function (0 instructions) in compact mode."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        async def mock_cmd(session, cmd):
            if "pdfj" in cmd:
                return '{"name": "sym.empty", "ops": []}'
            elif "pdf" in cmd:
                return ""
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", side_effect=mock_cmd),
        ):
            disasm_fn = tools["Radare2_disassemble_function"]
            res = await disasm_fn("/workspace/test.bin", "0x401000", format="compact")

            assert res["status"] == "success"
            assert res["format"] == "raw"
            assert res["disassembly"] == ""
            assert res["has_more"] is False
            assert res["next_cursor"] is None

    @pytest.mark.asyncio
    async def test_disasm_malformed_ops_missing_fields(self):
        """Test disassembly with corrupt/missing op fields (no mnemonic, offset=None, opcode only)."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        malformed_ops = [
            {"offset": None, "opcode": "nop"},
            {
                "offset": 0x401001,
                "disasm": "xor eax, eax",
                "ptr_comment": "zero out eax",
            },
            {"offset": "0x401003", "mnemonic": "ret", "operands": ""},
            {"offset": 0x401004},
        ]
        pdfj_payload = {"name": "sym.malformed", "ops": malformed_ops}

        async def mock_cmd(session, cmd):
            if "pdfj" in cmd:
                return json.dumps(pdfj_payload)
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", side_effect=mock_cmd),
        ):
            disasm_fn = tools["Radare2_disassemble_function"]
            res = await disasm_fn("/workspace/test.bin", "0x401000", format="compact")

            assert res["status"] == "success"
            assert res["format"] == "compact"
            assert res["total_instructions"] == 4
            instructions = res["instructions"]
            assert len(instructions) == 4

            # Verify safe extraction
            assert instructions[0] == ["", "nop", "", ""]
            assert instructions[1] == ["0x401001", "xor", "eax, eax", "zero out eax"]
            assert instructions[2] == ["0x401003", "ret", "", ""]
            assert instructions[3] == ["0x401004", "", "", ""]

    @pytest.mark.asyncio
    async def test_disasm_invalid_format_fallback(self):
        """Test unknown format parameter falls back gracefully to raw text output."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        async def mock_cmd(session, cmd):
            if "pdf" in cmd:
                return "0x401000  mov eax, 1\n0x401005  ret"
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", side_effect=mock_cmd),
        ):
            disasm_fn = tools["Radare2_disassemble_function"]
            res = await disasm_fn(
                "/workspace/test.bin", "0x401000", format="unsupported_custom_format"
            )

            assert res["status"] == "success"
            assert res["format"] == "raw"
            assert "mov eax, 1" in res["disassembly"]

    @pytest.mark.asyncio
    async def test_disasm_pagination_adversarial_inputs(self):
        """Test disassembly pagination with negative page_size, negative cursor, non-numeric cursor, huge cursor."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        ops = [{"offset": 0x401000 + i, "mnemonic": "nop", "operands": ""} for i in range(20)]
        pdfj_payload = {"name": "sym.nop_sled", "ops": ops}

        async def mock_cmd(session, cmd):
            if "pdfj" in cmd:
                return json.dumps(pdfj_payload)
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", side_effect=mock_cmd),
        ):
            disasm_fn = tools["Radare2_disassemble_function"]

            # 1. Negative cursor -> should default to 0
            res_neg_cur = await disasm_fn(
                "/workspace/test.bin", "0x401000", cursor="-5", page_size=5
            )
            assert res_neg_cur["status"] == "success"
            assert len(res_neg_cur["instructions"]) == 5
            assert res_neg_cur["instructions"][0][0] == "0x401000"

            # 2. Non-numeric cursor -> should default to 0
            res_str_cur = await disasm_fn(
                "/workspace/test.bin", "0x401000", cursor="invalid_offset", page_size=5
            )
            assert res_str_cur["status"] == "success"
            assert len(res_str_cur["instructions"]) == 5

            # 3. Cursor beyond total -> returns empty instructions list
            res_oob = await disasm_fn("/workspace/test.bin", "0x401000", cursor="100", page_size=5)
            assert res_oob["status"] == "success"
            assert len(res_oob["instructions"]) == 0
            assert res_oob["has_more"] is False
            assert res_oob["next_cursor"] is None

            # 4. Page size 0 or negative -> defaults to 100
            res_zero_page = await disasm_fn("/workspace/test.bin", "0x401000", page_size=0)
            assert res_zero_page["status"] == "success"
            assert len(res_zero_page["instructions"]) == 20

            # 5. Page size > MAX_PAGE_SIZE (500) -> clamped to 500
            res_huge_page = await disasm_fn("/workspace/test.bin", "0x401000", page_size=100000)
            assert res_huge_page["status"] == "success"
            assert len(res_huge_page["instructions"]) == 20


# ============================================================================
# 2. Decompilation Adversarial Tests
# ============================================================================


class TestDecompilationAdversarialStress:
    """Stress-test decompilation tools on windowing boundary anomalies."""

    @pytest.mark.asyncio
    async def test_r2_decompile_offset_exceeding_total_lines(self, tmp_path):
        """Test line_offset far exceeding total decompiled lines."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x90" * 100)

        pseudo_c = "int main() {\n    return 0;\n}\n"
        with (
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools._execute_r2_command",
                return_value=(pseudo_c, len(pseudo_c)),
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.get_cached_decompile",
                return_value=None,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.set_cached_decompile",
                new_callable=AsyncMock,
            ),
        ):
            res = await r2_decompile(str(test_file), "main", line_offset=5000, max_lines=50)
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["total_lines"] == 3
            assert data["line_offset"] == 5000
            assert data["pseudo_c"] == ""
            assert data["has_more"] is False
            assert data["next_line_offset"] is None
            assert res.pagination.has_more is False
            assert res.pagination.next_cursor is None

    @pytest.mark.asyncio
    async def test_r2_decompile_negative_offset_and_zero_max_lines(self, tmp_path):
        """Test negative line_offset and max_lines=0 (should default safely without ZeroDivisionError)."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x90" * 100)

        pseudo_c = "int calculate(int a, int b) {\n    return a + b;\n}"
        with (
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools._execute_r2_command",
                return_value=(pseudo_c, len(pseudo_c)),
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.get_cached_decompile",
                return_value=None,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.set_cached_decompile",
                new_callable=AsyncMock,
            ),
        ):
            res = await r2_decompile(str(test_file), "calculate", line_offset=-100, max_lines=0)
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["line_offset"] == 0
            assert data["total_lines"] == 3
            assert data["max_lines"] == 3
            assert data["pseudo_c"] == pseudo_c
            assert data["has_more"] is False
            assert res.pagination.page == 1

    @pytest.mark.asyncio
    async def test_r2_decompile_comments_only_signature_extraction(self, tmp_path):
        """Test signature extraction when decompilation contains only comment lines."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x90" * 100)

        pseudo_c = "// Header comment 1\n/* Block comment 2 */\n// Footer comment 3"
        with (
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools._execute_r2_command",
                return_value=(pseudo_c, len(pseudo_c)),
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.get_cached_decompile",
                return_value=None,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.set_cached_decompile",
                new_callable=AsyncMock,
            ),
        ):
            res = await r2_decompile(str(test_file), "0x401000", line_offset=0, max_lines=10)
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["summary"]["signature"] == "// Header comment 1"
            assert data["total_lines"] == 3

    @pytest.mark.asyncio
    async def test_radare2_mcp_decompile_function_boundary_cases(self):
        """Test Radare2_decompile_function in radare2_mcp_tools with extreme parameters."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        decomp_text = "\n".join([f"line_{i:03d}();" for i in range(50)])

        async def mock_cmd(session, cmd):
            if "pdc" in cmd:
                return decomp_text
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", side_effect=mock_cmd),
        ):
            decompile_fn = tools["Radare2_decompile_function"]

            # 1. max_lines=0 -> defaults to 200
            res_zero = await decompile_fn(
                "/workspace/test.bin", "0x401000", line_offset=0, max_lines=0
            )
            assert res_zero["status"] == "success"
            assert res_zero["max_lines"] == 200
            assert res_zero["total_lines"] == 50
            assert len(res_zero["decompiled"].splitlines()) == 50
            assert res_zero["has_more"] is False

            # 2. line_offset=40, max_lines=5 -> lines 40..45
            res_mid = await decompile_fn(
                "/workspace/test.bin", "0x401000", line_offset=40, max_lines=5
            )
            assert res_mid["status"] == "success"
            assert res_mid["summary"]["window_lines"] == "41-45"
            assert res_mid["has_more"] is True
            assert res_mid["next_cursor"] == "45"
            assert res_mid["next_line_offset"] == 45

            # 3. line_offset=48, max_lines=10 -> partial final window
            res_end = await decompile_fn(
                "/workspace/test.bin", "0x401000", line_offset=48, max_lines=10
            )
            assert res_end["status"] == "success"
            assert res_end["summary"]["window_lines"] == "49-50"
            assert res_end["has_more"] is False
            assert res_end["next_cursor"] is None
            assert len(res_end["decompiled"].splitlines()) == 2


# ============================================================================
# 3. Cross-References Adversarial Tests
# ============================================================================


class TestCrossReferencesAdversarialStress:
    """Stress-test xrefs tools against high-fan-in, orphan, and malformed inputs."""

    @pytest.mark.asyncio
    async def test_xrefs_invalid_address_rejection(self, tmp_path):
        """Verify rejection of malformed address inputs with SQLi / command injection characters."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x90" * 100)

        # Radare2_xrefs_to
        plugin, tools = get_registered_plugin_and_tools()
        xrefs_fn = tools["Radare2_xrefs_to"]

        res_bad_addr = await xrefs_fn(str(test_file), "0x401000; rm -rf /")
        assert res_bad_addr["status"] == "error"
        assert (
            "safe characters" in res_bad_addr["message"].lower()
            or "invalid" in res_bad_addr["message"].lower()
        )

        # analyze_xrefs
        res_bad_r2 = await analyze_xrefs(str(test_file), "sym.foo`cat /etc/passwd`")
        assert isinstance(res_bad_r2, ToolError)
        assert res_bad_r2.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_xrefs_missing_or_corrupted_fields_in_json(self):
        """Verify resilient grouping when r2 JSON has missing or mixed-type keys (e.g. from=None, fcn_name missing)."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        corrupt_xrefs = [
            {"from": 0x401020, "type": "CALL", "fcn_addr": 0x401000},
            {"from": None, "type": "DATA", "name": "sym.data_accessor"},
            {"from": "0x402000", "type": "JMP"},
            {"type": "CALL"},
        ]

        async def mock_cmd(session, cmd):
            if "axtj" in cmd:
                return json.dumps(corrupt_xrefs)
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", side_effect=mock_cmd),
        ):
            xrefs_fn = tools["Radare2_xrefs_to"]
            res = await xrefs_fn("/workspace/test.bin", "0x401000")

            assert res["status"] == "success"
            assert res["xref_count"] == 4
            callers = res["callers_by_function"]
            assert "0x401000" in callers
            assert "sym.data_accessor" in callers
            assert "unknown" in callers

    @pytest.mark.asyncio
    async def test_analyze_xrefs_direction_filters(self, tmp_path):
        """Verify analyze_xrefs handles xref_type='to', 'from', and 'all' properly."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x90" * 100)

        to_json = json.dumps([{"from": 0x401010, "type": "call", "fcn_name": "entry0"}])
        from_json = json.dumps([{"addr": 0x402020, "type": "call", "fcn_name": "sym.imp.puts"}])
        mock_output = to_json + "\n" + from_json

        with (
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis._execute_r2_command",
                return_value=(mock_output, len(mock_output)),
            ),
        ):
            res = await analyze_xrefs(str(test_file), "main", xref_type="all")
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["total_refs_to"] == 1
            assert data["total_refs_from"] == 1
            assert len(data["xrefs_to"]) == 1
            assert len(data["xrefs_from"]) == 1
            assert "1 reference(s) TO" in data["summary"]
            assert "1 reference(s) FROM" in data["summary"]
            assert res.pagination.total_items == 2


# ============================================================================
# 4. Diffing Tools Adversarial Tests
# ============================================================================


class TestDiffToolsAdversarialStress:
    """Stress-test binary diffing and library matching across edge scenarios."""

    @pytest.mark.asyncio
    async def test_diff_binaries_identical_binaries(self):
        """Test diffing two identical binaries (similarity=1.0, 0 changes)."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch("reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async") as mock_sub,
        ):
            mock_sub.side_effect = [
                ("", 0),
                ("similarity: 1.0\n", 16),
            ]

            res = await diff_binaries("bin_v1.exe", "bin_v1_copy.exe")
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["similarity"] == 1.0
            assert data["total_changes"] == 0
            assert len(data["changes"]) == 0
            assert data["summary"]["similarity_score"] == 1.0
            assert data["summary"]["total_changes"] == 0
            assert res.pagination.has_more is False
            assert res.pagination.total_items == 0

    @pytest.mark.asyncio
    async def test_diff_binaries_pagination_out_of_bounds(self):
        """Test requesting page=50 when total changes is only 3."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch("reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async") as mock_sub,
        ):
            mock_diff = "0x401000 new block\n0x401020 removed block\n0x401040 modified code\n"
            mock_sub.side_effect = [
                (mock_diff, len(mock_diff)),
                ("similarity: 0.85\n", 18),
            ]

            res = await diff_binaries("bin_a.exe", "bin_b.exe", page=50, page_size=20)
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["total_changes"] == 3
            assert len(data["changes"]) == 0
            assert res.pagination.page == 50
            assert res.pagination.has_more is False
            assert res.pagination.next_cursor is None

    @pytest.mark.asyncio
    async def test_diff_binaries_negative_page_and_zero_page_size(self):
        """Test page=-1 and page_size=0 (should clamp safely)."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch("reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async") as mock_sub,
        ):
            mock_diff = "0x401000 new block\n"
            mock_sub.side_effect = [
                (mock_diff, len(mock_diff)),
                ("similarity: 0.90\n", 18),
            ]

            res = await diff_binaries("bin_a.exe", "bin_b.exe", page=-1, page_size=0)
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert len(data["changes"]) == 1
            assert res.pagination.page == 1
            assert res.pagination.page_size == 20

    @pytest.mark.asyncio
    async def test_analyze_variant_changes_corrupted_offsets_and_empty_functions(self):
        """Test analyze_variant_changes when aflj returns malformed/empty function list."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch("reversecore_mcp.tools.analysis.diff_tools.diff_binaries") as mock_diff,
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                return_value=("[]", 2),
            ),
        ):
            mock_diff.return_value = ToolSuccess(
                data={
                    "similarity": 0.50,
                    "total_changes": 2,
                    "changes": [
                        {"address": "0x401000", "type": "new_block"},
                        {"address": "NOT_A_HEX", "type": "code_change"},
                    ],
                }
            )

            res = await analyze_variant_changes("bin_orig.exe", "bin_var.exe")
            assert isinstance(res, ToolSuccess)
            assert res.data["similarity"] == 0.50
            assert res.data["total_changes"] == 2
            assert res.data["top_modified_functions"] == []

    @pytest.mark.asyncio
    async def test_match_libraries_zero_functions(self):
        """Test match_libraries on binary with 0 discovered functions (e.g. raw shellcode blob)."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch(
                "reversecore_mcp.tools.analysis.diff_tools._execute_r2_command",
                return_value=("[]", 2),
            ),
            patch("os.path.getsize", return_value=1024),
        ):
            res = await match_libraries("blob.bin")
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["total_functions"] == 0
            assert data["library_functions"] == 0
            assert data["user_functions"] == 0
            assert data["noise_reduction_percentage"] == 0.0
            assert "No library functions matched" in data["hint"]

    @pytest.mark.asyncio
    async def test_patch_diff_1day_identical_and_divergent(self):
        """Test patch_diff_1day handling of nearly identical (>0.999) vs divergent binaries."""
        with (
            patch("reversecore_mcp.tools.analysis.diff_tools.diff_binaries") as mock_diff,
            patch("reversecore_mcp.tools.analysis.diff_tools.analyze_variant_changes") as mock_var,
        ):
            # 1. Identical
            mock_diff.return_value = ToolSuccess(data={"similarity": 1.0})
            res_ident = await patch_diff_1day("v1.exe", "v1_clone.exe")
            assert isinstance(res_ident, ToolSuccess)
            assert "nearly identical" in res_ident.data["message"]

            # 2. Divergent
            mock_diff.return_value = ToolSuccess(
                data={"similarity": 0.80, "changes": [{"address": "0x401000"}]}
            )
            mock_var.return_value = ToolSuccess(
                data={
                    "similarity": 0.80,
                    "top_modified_functions": [
                        {
                            "function": "sym.auth_verify",
                            "change_count": 5,
                            "cfg_mermaid": "graph TD;",
                        }
                    ],
                }
            )
            res_div = await patch_diff_1day("v1.exe", "v2_patched.exe")
            assert isinstance(res_div, ToolSuccess)
            assert res_div.data["similarity_score"] == 0.80
            assert len(res_div.data["top_modified_functions"]) == 1


# ============================================================================
# 5. Schema & Serialization Adversarial Tests
# ============================================================================


class TestSchemaSerializationAdversarialStress:
    """Stress-test PaginationMeta, ToolSuccess, and json_utils serialization across extreme objects."""

    def test_pagination_meta_model_validation(self):
        """Verify PaginationMeta validation with diverse edge-case values."""
        p1 = PaginationMeta()
        assert p1.has_more is False
        assert p1.page == 1
        assert p1.page_size == 100
        assert p1.total_items is None

        p2 = PaginationMeta(
            has_more=True,
            next_cursor="200",
            total_items=1500,
            page=2,
            page_size=200,
            truncated=True,
        )
        assert p2.has_more is True
        assert p2.next_cursor == "200"
        assert p2.total_items == 1500
        assert p2.page == 2
        assert p2.page_size == 200
        assert p2.truncated is True

        # Serialization roundtrip
        json_bytes = json.dumps(p2.model_dump())
        parsed = json.loads(json_bytes)
        p2_rebuilt = PaginationMeta(**parsed)
        assert p2_rebuilt == p2

    def test_tool_success_serialization_resilience(self):
        """Verify ToolSuccess with PaginationMeta serializes cleanly through orjson."""
        meta = PaginationMeta(has_more=True, next_cursor="50", total_items=100)
        res = success(
            {"items": list(range(50))},
            pagination=meta,
            execution_time_ms=12.5,
            cached=False,
        )

        wire_str = json.dumps(res.model_dump())
        parsed = json.loads(wire_str)

        assert parsed["status"] == "success"
        assert len(parsed["data"]["items"]) == 50
        assert parsed["pagination"]["has_more"] is True
        assert parsed["pagination"]["next_cursor"] == "50"
        assert parsed["pagination"]["total_items"] == 100
        assert parsed["metadata"]["execution_time_ms"] == 12.5
        assert parsed["metadata"]["cached"] is False
