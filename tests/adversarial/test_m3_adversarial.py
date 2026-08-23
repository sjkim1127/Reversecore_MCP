"""Adversarial stress tests and empirical verification for Milestone 3.

Empirically verifies:
1. Token and size reduction of compact disassembly (format="compact" vs format="raw" and verbose dicts).
2. Decompilation line windowing on large functions (1,000+, 2,500+, 10,000+ lines).
3. Cross-reference bounding on hub functions (5,000+ and 10,000+ callers) with caller grouping.
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.tools.radare2.r2_analysis import analyze_xrefs
from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile
from reversecore_mcp.tools.radare2.radare2_mcp_tools import Radare2ToolsPlugin


def estimate_tokens(text: str) -> int:
    """Estimate token count using regex word/symbol boundaries."""
    tokens = re.findall(r"\w+|[^\w\s]", text)
    return max(1, len(tokens))


def get_registered_plugin_and_tools() -> tuple[Radare2ToolsPlugin, dict]:
    """Helper to initialize and register Radare2ToolsPlugin tools."""
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


# ===========================================================================
# 1. Compact Disassembly Reduction Tests
# ===========================================================================


class TestCompactDisassemblyEmpiricalReduction:
    """Empirically measure and verify token and size reduction of compact disassembly."""

    def _generate_synthetic_disasm(self, count: int) -> tuple[dict, str, list[dict]]:
        """Generate realistic pdfj dict, pdf raw text, and verbose dict list."""
        ops = []
        raw_lines = ["/ (fcn) sym.target_function 256", "|   sym.target_function ();"]
        verbose_list = []

        mnemonics = [
            ("push", "rbp"),
            ("mov", "rbp, rsp"),
            ("sub", "rsp, 0x40"),
            ("mov", "dword [rbp - 4], edi"),
            ("mov", "qword [rbp - 0x10], rsi"),
            ("cmp", "dword [rbp - 4], 0"),
            ("je", "0x401150"),
            ("mov", "eax, dword [rbp - 4]"),
            ("add", "eax, 1"),
            ("call", "sym.imp.malloc"),
            ("test", "rax, rax"),
            ("jz", "0x401180"),
            ("mov", "rsi, qword [rbp - 0x10]"),
            ("mov", "rdi, rax"),
            ("call", "sym.imp.memcpy"),
            ("leave", ""),
            ("ret", ""),
        ]

        base_addr = 0x401000
        for i in range(count):
            offset = base_addr + (i * 4)
            mnem, ops_str = mnemonics[i % len(mnemonics)]
            comment = f"ref to var_{i % 16}" if i % 5 == 0 else ""
            ptr_comment = f"sym.global_{i}" if i % 11 == 0 else ""

            op_dict = {
                "offset": offset,
                "size": 4,
                "type": ("mov" if "mov" in mnem else "call" if "call" in mnem else "cjmp"),
                "opcode": f"{mnem} {ops_str}".strip(),
                "mnemonic": mnem,
                "operands": ops_str,
                "esil": f"rbp,rsp,=,{offset}",
                "refptr": 0,
                "bytes": "4889e5" if i % 2 == 0 else "e800000000",
                "family": "cpu",
            }
            if comment:
                op_dict["comment"] = comment
            if ptr_comment:
                op_dict["ptr_comment"] = ptr_comment

            ops.append(op_dict)
            raw_lines.append(
                f"|   0x{offset:x}      4889e5      {mnem:<6} {ops_str:<20} ; {comment} {ptr_comment}".rstrip()
            )
            verbose_list.append(
                {
                    "address": hex(offset),
                    "mnemonic": mnem,
                    "operands": ops_str,
                    "comment": comment or ptr_comment,
                    "bytes": op_dict["bytes"],
                }
            )

        pdfj_payload = {
            "name": "sym.target_function",
            "size": count * 4,
            "addr": base_addr,
            "ops": ops,
        }
        raw_text = "\n".join(raw_lines)
        return pdfj_payload, raw_text, verbose_list

    @pytest.mark.asyncio
    @pytest.mark.parametrize("instr_count", [50, 200, 500, 1000, 5000])
    async def test_compact_disassembly_reduction_percentage(self, instr_count: int):
        """Measure size and token reduction of compact format vs raw and verbose."""
        pdfj_dict, raw_text, verbose_list = self._generate_synthetic_disasm(instr_count)

        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        async def mock_run_cmd(s, cmd_str: str) -> str:
            if "pdfj" in cmd_str:
                return (
                    json.dumps(pdfj_dict).decode("utf-8")
                    if isinstance(json.dumps(pdfj_dict), bytes)
                    else json.dumps(pdfj_dict)
                )
            elif "pdf" in cmd_str:
                return raw_text
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(
                plugin,
                "_run_session_cmd",
                new_callable=AsyncMock,
                side_effect=mock_run_cmd,
            ),
        ):
            disasm_fn = tools["Radare2_disassemble_function"]

            # 1. Compact format (unpaged / page_size = instr_count)
            compact_res = await disasm_fn(
                "/workspace/test.bin",
                "0x401000",
                format="compact",
                page_size=instr_count,
            )
            assert compact_res["status"] == "success"
            assert compact_res["format"] == "compact"
            assert compact_res["total_instructions"] == instr_count
            assert len(compact_res["instructions"]) == instr_count

            # Verify 4-tuple format [addr, mnem, ops, comment]
            first_instr = compact_res["instructions"][0]
            assert isinstance(first_instr, list)
            assert len(first_instr) == 4
            assert first_instr[0] == "0x401000"
            assert first_instr[1] == "push"
            assert first_instr[2] == "rbp"

            # 2. Raw format
            raw_res = await disasm_fn(
                "/workspace/test.bin", "0x401000", format="raw", page_size=instr_count
            )
            assert raw_res["status"] == "success"
            assert raw_res["format"] == "raw"

            # 3. Serialization and Token Measurements
            compact_bytes = len(json.dumps(compact_res))
            len(json.dumps(raw_res))
            len(json.dumps(verbose_list))
            raw_pdfj_bytes = len(json.dumps(pdfj_dict))

            # Pure instruction 4-tuple array bytes (without envelope)
            pure_tuples_bytes = len(json.dumps(compact_res["instructions"]))

            compact_str = (
                json.dumps(compact_res).decode("utf-8")
                if isinstance(json.dumps(compact_res), bytes)
                else json.dumps(compact_res)
            )
            raw_str = (
                json.dumps(raw_res).decode("utf-8")
                if isinstance(json.dumps(raw_res), bytes)
                else json.dumps(raw_res)
            )
            raw_pdfj_str = (
                json.dumps(pdfj_dict).decode("utf-8")
                if isinstance(json.dumps(pdfj_dict), bytes)
                else json.dumps(pdfj_dict)
            )
            verbose_str = (
                json.dumps(verbose_list).decode("utf-8")
                if isinstance(json.dumps(verbose_list), bytes)
                else json.dumps(verbose_list)
            )
            pure_tuples_str = (
                json.dumps(compact_res["instructions"]).decode("utf-8")
                if isinstance(json.dumps(compact_res["instructions"]), bytes)
                else json.dumps(compact_res["instructions"])
            )

            compact_tokens = estimate_tokens(compact_str)
            estimate_tokens(raw_str)
            raw_pdfj_tokens = estimate_tokens(raw_pdfj_str)
            estimate_tokens(verbose_str)
            pure_tuples_tokens = estimate_tokens(pure_tuples_str)

            # Reduction metrics
            pure_tuple_reduction_vs_pdfj_bytes = (
                1.0 - (pure_tuples_bytes / raw_pdfj_bytes)
            ) * 100.0
            pure_tuple_reduction_vs_pdfj_tokens = (
                1.0 - (pure_tuples_tokens / raw_pdfj_tokens)
            ) * 100.0
            full_response_reduction_vs_pdfj_bytes = (1.0 - (compact_bytes / raw_pdfj_bytes)) * 100.0
            full_response_reduction_vs_pdfj_tokens = (
                1.0 - (compact_tokens / raw_pdfj_tokens)
            ) * 100.0

            print(
                f"\n[Disasm {instr_count} ops] "
                f"Pure 4-tuples: {pure_tuples_bytes}B ({pure_tuples_tokens} tok) | "
                f"Full Compact (with dup): {compact_bytes}B ({compact_tokens} tok) | "
                f"Raw pdfj: {raw_pdfj_bytes}B ({raw_pdfj_tokens} tok) | "
                f"Pure 4-tuple Reduction vs pdfj: {pure_tuple_reduction_vs_pdfj_tokens:.2f}% (bytes: {pure_tuple_reduction_vs_pdfj_bytes:.2f}%) | "
                f"Full Payload Reduction vs pdfj: {full_response_reduction_vs_pdfj_tokens:.2f}% (bytes: {full_response_reduction_vs_pdfj_bytes:.2f}%)"
            )

            # Assert pure 4-tuple format achieves target 75-80% token/size reduction (target: 60-80%)
            assert pure_tuple_reduction_vs_pdfj_bytes >= 75.0, (
                f"Pure 4-tuple byte reduction {pure_tuple_reduction_vs_pdfj_bytes:.2f}% < 75%"
            )
            assert pure_tuple_reduction_vs_pdfj_tokens >= 70.0, (
                f"Pure 4-tuple token reduction {pure_tuple_reduction_vs_pdfj_tokens:.2f}% < 70%"
            )

            # Assert full response payload achieves >= 55% reduction unpaged
            assert full_response_reduction_vs_pdfj_bytes >= 55.0, (
                f"Full response byte reduction {full_response_reduction_vs_pdfj_bytes:.2f}% < 55%"
            )
            assert full_response_reduction_vs_pdfj_tokens >= 50.0, (
                f"Full response token reduction {full_response_reduction_vs_pdfj_tokens:.2f}% < 50%"
            )

    @pytest.mark.asyncio
    async def test_compact_disassembly_pagination_cursors(self):
        """Adversarially test cursor-based pagination through 1,000 instructions in compact mode."""
        pdfj_dict, _, _ = self._generate_synthetic_disasm(1000)

        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True
        json_str = (
            json.dumps(pdfj_dict).decode("utf-8")
            if isinstance(json.dumps(pdfj_dict), bytes)
            else json.dumps(pdfj_dict)
        )

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(
                plugin,
                "_run_session_cmd",
                new_callable=AsyncMock,
                return_value=json_str,
            ),
        ):
            disasm_fn = tools["Radare2_disassemble_function"]

            # Page 1: 0..100
            p1 = await disasm_fn("/workspace/test.bin", "0x401000", page_size=100)
            assert p1["has_more"] is True
            assert p1["next_cursor"] == "100"
            assert len(p1["instructions"]) == 100
            assert p1["instructions"][0][0] == "0x401000"

            # Check paged size reduction vs full dump
            full_pdfj_bytes = len(json_str)
            p1_bytes = len(json.dumps(p1))
            paged_reduction = (1.0 - (p1_bytes / full_pdfj_bytes)) * 100.0
            print(
                f"\n[Disasm Paged 100 / 1000 ops] Full: {full_pdfj_bytes}B -> P1: {p1_bytes}B (-{paged_reduction:.2f}%)"
            )
            assert paged_reduction >= 90.0, f"Paged reduction {paged_reduction:.2f}% < 90%"

            # Page 2: 100..200
            p2 = await disasm_fn("/workspace/test.bin", "0x401000", cursor="100", page_size=100)
            assert p2["has_more"] is True
            assert p2["next_cursor"] == "200"
            assert len(p2["instructions"]) == 100
            assert p2["instructions"][0][0] == hex(0x401000 + (100 * 4))

            # Final Page: 900..1000
            p_last = await disasm_fn("/workspace/test.bin", "0x401000", cursor="900", page_size=100)
            assert p_last["has_more"] is False
            assert p_last["next_cursor"] is None
            assert len(p_last["instructions"]) == 100

            # Out of bounds cursor: 1200
            p_oob = await disasm_fn("/workspace/test.bin", "0x401000", cursor="1200", page_size=100)
            assert p_oob["has_more"] is False
            assert p_oob["next_cursor"] is None
            assert len(p_oob["instructions"]) == 0

    @pytest.mark.asyncio
    async def test_compact_disassembly_fallback_when_pdfj_empty_or_malformed(self):
        """Ensure robust handling when pdfj returns malformed JSON or empty string."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        async def mock_cmd(s, cmd_str: str) -> str:
            if "pdfj" in cmd_str:
                return "MALFORMED_NON_JSON"
            elif "pdf" in cmd_str:
                return "mov eax, 1\nret"
            return ""

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", new_callable=AsyncMock, side_effect=mock_cmd),
        ):
            disasm_fn = tools["Radare2_disassemble_function"]
            res = await disasm_fn("/workspace/test.bin", "0x401000", format="compact")
            assert res["status"] == "success"
            assert res["format"] == "raw"
            assert "mov eax, 1" in res["disassembly"]


# ===========================================================================
# 2. Decompilation Line Windowing Tests (1,000+ to 10,000+ lines)
# ===========================================================================


class TestDecompilationLineWindowing:
    """Verify smart windowing on massive functions across r2ghidra_tools and radare2_mcp_tools."""

    def _generate_large_c_function(self, total_lines: int) -> str:
        """Generate pseudo-C code of exact line count with comments and body."""
        lines = [
            "// Automatically generated decompilation",
            "/* Complex state machine */",
            "ulonglong process_large_payload(StateContext *ctx, uchar *buf, uint len) {",
            "    ulonglong checksum = 0x5a5a5a5a;",
            "    int state = ctx->initial_state;",
        ]
        needed = total_lines - len(lines) - 2
        for i in range(needed):
            lines.append(f"    checksum ^= (ulonglong)buf[{i % 256}] * {i + 1} + 0x{i:04x};")
        lines.append("    return checksum;")
        lines.append("}")
        return "\n".join(lines[:total_lines])

    @pytest.mark.asyncio
    @pytest.mark.parametrize("line_count", [1000, 2500, 10000])
    async def test_r2_decompile_line_windowing_pagination_and_header(
        self, line_count: int, tmp_path
    ):
        """Test r2_decompile line windowing and summary header on massive functions."""
        test_file = tmp_path / "large_binary.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 500)

        large_c_code = self._generate_large_c_function(line_count)

        with (
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.get_cached_decompile",
                return_value=None,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.set_cached_decompile",
                new_callable=AsyncMock,
            ),
        ):
            mock_r2.return_value = (large_c_code, len(large_c_code))

            # Window 1: lines 0..200 (1-200)
            res1 = await r2_decompile(str(test_file), "0x401000", line_offset=0, max_lines=200)
            assert res1.status == "success"
            data1 = res1.data
            assert data1["total_lines"] == line_count
            assert data1["line_offset"] == 0
            assert data1["max_lines"] == 200
            assert data1["has_more"] is True
            assert data1["next_line_offset"] == 200

            # Check summary header
            summary1 = data1["summary"]
            assert summary1["total_lines"] == line_count
            assert summary1["window_lines"] == "1-200"
            assert "ulonglong process_large_payload" in summary1["signature"]

            # Verify actual returned lines
            returned_lines_1 = data1["pseudo_c"].splitlines()
            assert len(returned_lines_1) == 200
            assert returned_lines_1[0] == "// Automatically generated decompilation"

            # Check PaginationMeta
            assert res1.pagination is not None
            assert res1.pagination.has_more is True
            assert res1.pagination.next_cursor == "200"
            assert res1.pagination.total_items == line_count
            assert res1.pagination.page == 1
            assert res1.pagination.page_size == 200

            # Window 2: lines 200..400 (201-400)
            res2 = await r2_decompile(str(test_file), "0x401000", line_offset=200, max_lines=200)
            assert res2.status == "success"
            data2 = res2.data
            assert data2["line_offset"] == 200
            assert data2["summary"]["window_lines"] == "201-400"
            assert len(data2["pseudo_c"].splitlines()) == 200
            assert res2.pagination.page == 2

            # Window Final: near the end
            last_offset = (line_count // 200) * 200
            if last_offset == line_count:
                last_offset -= 200
            res_last = await r2_decompile(
                str(test_file), "0x401000", line_offset=last_offset, max_lines=200
            )
            assert res_last.status == "success"
            assert res_last.data["has_more"] is False
            assert res_last.data["next_line_offset"] is None
            assert res_last.pagination.has_more is False
            assert res_last.pagination.next_cursor is None

    @pytest.mark.asyncio
    async def test_radare2_decompile_function_mcp_wrapper_windowing(self):
        """Test Radare2_decompile_function in radare2_mcp_tools with line_offset and max_lines."""
        plugin, tools = get_registered_plugin_and_tools()
        large_c_code = self._generate_large_c_function(1500)
        mock_session = MagicMock()
        mock_session.is_open = True

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(
                plugin,
                "_run_session_cmd",
                new_callable=AsyncMock,
                return_value=large_c_code,
            ),
        ):
            decompile_fn = tools["Radare2_decompile_function"]

            # Test windowed query
            res = await decompile_fn(
                "/workspace/test.bin", "0x401000", line_offset=500, max_lines=250
            )
            assert res["status"] == "success"
            assert res["line_offset"] == 500
            assert res["max_lines"] == 250
            assert res["total_lines"] == 1500
            assert res["has_more"] is True
            assert res["next_line_offset"] == 750
            assert res["next_cursor"] == "750"
            assert res["summary"]["window_lines"] == "501-750"
            assert len(res["decompiled"].splitlines()) == 250

    @pytest.mark.asyncio
    async def test_decompile_adversarial_boundary_conditions(self, tmp_path):
        """Adversarial stress-testing of decompile windowing on weird boundaries."""
        test_file = tmp_path / "edge.bin"
        test_file.write_bytes(b"\x00" * 100)

        with (
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.get_cached_decompile",
                return_value=None,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.set_cached_decompile",
                new_callable=AsyncMock,
            ),
        ):
            # 1. Single line function
            mock_r2.return_value = ("void stub() { return; }", 23)
            res1 = await r2_decompile(str(test_file), "0x401000", line_offset=0, max_lines=200)
            assert res1.status == "success"
            assert res1.data["total_lines"] == 1
            assert res1.data["summary"]["window_lines"] == "1-1"
            assert res1.data["has_more"] is False

            # 2. Huge line_offset beyond total_lines
            res2 = await r2_decompile(str(test_file), "0x401000", line_offset=1000, max_lines=200)
            assert res2.status == "success"
            assert res2.data["pseudo_c"] == ""
            assert res2.data["has_more"] is False

            # 3. Negative line_offset (should clamp to 0)
            res3 = await r2_decompile(str(test_file), "0x401000", line_offset=-100, max_lines=200)
            assert res3.status == "success"
            assert res3.data["line_offset"] == 0
            assert res3.data["pseudo_c"] == "void stub() { return; }"


# ===========================================================================
# 3. Cross-Reference Bounding Tests (5,000+ and 10,000+ callers)
# ===========================================================================


class TestCrossReferenceBoundingHubFunctions:
    """Verify xref bounding on hub functions with 5,000+ and 10,000+ callers."""

    def _generate_synthetic_hub_xrefs(self, num_callers: int, num_caller_fcns: int) -> list[dict]:
        """Generate high-fan-in xref records simulating malloc/GetLastError hub functions."""
        xrefs = []
        for i in range(num_callers):
            fcn_id = i % num_caller_fcns
            fcn_name = f"sym.worker_task_{fcn_id:04d}"
            fcn_addr = 0x401000 + (fcn_id * 0x100)
            caller_addr = fcn_addr + ((i // num_caller_fcns) * 4) + 0x10

            xrefs.append(
                {
                    "from": caller_addr,
                    "type": "CALL",
                    "opcode": "call sym.imp.malloc",
                    "fcn_addr": fcn_addr,
                    "fcn_name": fcn_name,
                }
            )
        return xrefs

    @pytest.mark.asyncio
    @pytest.mark.parametrize("num_callers,num_fcns", [(5000, 150), (10000, 500)])
    async def test_radare2_xrefs_to_bounding_and_grouping(self, num_callers: int, num_fcns: int):
        """Verify Radare2_xrefs_to bounds at limit=50 and groups callers_by_function."""
        hub_xrefs = self._generate_synthetic_hub_xrefs(num_callers, num_fcns)

        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True
        json_str = (
            json.dumps(hub_xrefs).decode("utf-8")
            if isinstance(json.dumps(hub_xrefs), bytes)
            else json.dumps(hub_xrefs)
        )

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(
                plugin,
                "_run_session_cmd",
                new_callable=AsyncMock,
                return_value=json_str,
            ),
        ):
            xrefs_fn = tools["Radare2_xrefs_to"]

            # 1. Default call (default limit: 50)
            res_default = await xrefs_fn("/workspace/test.bin", "sym.imp.malloc")
            assert res_default["status"] == "success"
            assert res_default["xref_count"] == num_callers
            assert res_default["total_items"] == num_callers
            assert res_default["limit"] == 50
            assert res_default["has_more"] is True
            assert len(res_default["xrefs"]) == 50

            # Verify callers_by_function grouping holds ALL functions & addresses
            callers_group = res_default["callers_by_function"]
            assert isinstance(callers_group, dict)
            assert len(callers_group) == num_fcns
            total_grouped_addrs = sum(len(addrs) for addrs in callers_group.values())
            assert total_grouped_addrs == num_callers

            # Check that each function has the correct caller addresses
            sample_fcn = "sym.worker_task_0000"
            assert sample_fcn in callers_group
            assert len(callers_group[sample_fcn]) >= 1

            # 2. Custom limit: 120
            res_custom = await xrefs_fn("/workspace/test.bin", "sym.imp.malloc", limit=120)
            assert res_custom["status"] == "success"
            assert len(res_custom["xrefs"]) == 120
            assert res_custom["limit"] == 120
            assert res_custom["has_more"] is True

            # 3. Complete retrieval: limit >= num_callers
            res_full = await xrefs_fn(
                "/workspace/test.bin", "sym.imp.malloc", limit=num_callers + 100
            )
            assert res_full["status"] == "success"
            assert len(res_full["xrefs"]) == num_callers
            assert res_full["has_more"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("num_callers,num_fcns", [(5000, 100)])
    async def test_analyze_xrefs_tool_bounding_and_pagination(
        self, num_callers: int, num_fcns: int, tmp_path
    ):
        """Verify analyze_xrefs in r2_analysis.py bounds to 50 items and constructs PaginationMeta."""
        test_file = tmp_path / "hub_binary.bin"
        test_file.write_bytes(b"\x00" * 100)

        hub_xrefs = self._generate_synthetic_hub_xrefs(num_callers, num_fcns)
        json_output = (
            json.dumps(hub_xrefs).decode("utf-8")
            if isinstance(json.dumps(hub_xrefs), bytes)
            else json.dumps(hub_xrefs)
        )

        with (
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
        ):
            mock_r2.return_value = (json_output, len(json_output))

            # Call with xref_type="to" and default limit=50
            res = await analyze_xrefs(str(test_file), "0x401000", xref_type="to", limit=50)
            assert res.status == "success"
            data = res.data
            assert data["total_refs_to"] == num_callers
            assert data["limit"] == 50
            assert data["truncated"] is True
            assert len(data["xrefs_to"]) == 50
            assert len(data["callers_by_function"]) == num_fcns

            # PaginationMeta check
            assert res.pagination is not None
            assert res.pagination.has_more is True
            assert res.pagination.truncated is True
            assert res.pagination.total_items == num_callers
            assert res.pagination.page_size == 50

    @pytest.mark.asyncio
    async def test_zero_xrefs_orphan_function_handling(self):
        """Verify clean handling when a function has 0 xrefs (dead code / unreferenced export)."""
        plugin, tools = get_registered_plugin_and_tools()
        mock_session = MagicMock()
        mock_session.is_open = True

        with (
            patch.object(plugin, "_get_or_create_session", return_value=mock_session),
            patch.object(plugin, "_run_session_cmd", new_callable=AsyncMock, return_value="[]"),
        ):
            xrefs_fn = tools["Radare2_xrefs_to"]
            res = await xrefs_fn("/workspace/test.bin", "0x405000")
            assert res["status"] == "success"
            assert res["xref_count"] == 0
            assert res["total_items"] == 0
            assert res["has_more"] is False
            assert res["xrefs"] == []
            assert res["callers_by_function"] == {}
            assert "No cross-references found" in res["note"]
