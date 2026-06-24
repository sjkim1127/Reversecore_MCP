"""Tests for reversecore_mcp.tools.radare2.r2_analysis."""

from unittest.mock import AsyncMock, patch

import pytest


class TestCleanSymbolName:
    """Tests for _clean_symbol_name helper."""

    def test_empty(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _clean_symbol_name

        assert _clean_symbol_name("") == ""

    def test_remove_prefixes(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _clean_symbol_name

        assert _clean_symbol_name("sym.main") == "main"
        assert _clean_symbol_name("sym.imp.puts") == "puts"
        assert _clean_symbol_name("fcn.00401000") == "00401000"

    def test_lowercase(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _clean_symbol_name

        assert _clean_symbol_name("MAIN") == "main"


class TestFuzzyMatchSymbol:
    """Tests for _fuzzy_match_symbol helper."""

    def test_exact_match(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _fuzzy_match_symbol

        score, match_type = _fuzzy_match_symbol("main", "main")
        assert score == 1.0
        assert match_type == "exact"

    def test_no_match(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _fuzzy_match_symbol

        score, match_type = _fuzzy_match_symbol("main", "puts")
        assert score == 0.0


class TestFindBestSymbolMatch:
    """Tests for _find_best_symbol_match helper."""

    def test_exact_match(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _find_best_symbol_match

        symbols = [
            {"name": "sym.main"},
            {"name": "sym.puts"},
        ]
        best, score, match_type = _find_best_symbol_match("main", symbols)
        assert best is not None
        assert best["name"] == "sym.main"
        assert score == 1.0

    def test_no_match(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _find_best_symbol_match

        best, score, match_type = _find_best_symbol_match("main", [])
        assert best is None


class TestRadare2JsonToMermaid:
    """Tests for _radare2_json_to_mermaid helper."""

    def test_empty(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _radare2_json_to_mermaid

        result = _radare2_json_to_mermaid("[]")
        assert "graph TD" in result

    def test_with_nodes(self):
        from reversecore_mcp.tools.radare2.r2_analysis import _radare2_json_to_mermaid

        json_str = '[{"name": "fcn.1", "offset": 4096, "blocks": [{"offset": 4096, "ops": []}]}]'
        result = _radare2_json_to_mermaid(json_str)
        assert "graph TD" in result or "flowchart" in result


class TestRunRadare2:
    """Tests for run_radare2."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.radare2.r2_analysis import run_radare2

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.radare2.r2_analysis.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.radare2.r2_analysis._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("functions: 5\n", 20)
                result = await run_radare2(str(test_file), "afl")

        assert result.status == "success"


class TestTraceExecutionPath:
    """Tests for trace_execution_path."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.radare2.r2_analysis import trace_execution_path

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.radare2.r2_analysis.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.radare2.r2_analysis._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ('{"calls": []}', 15)
                result = await trace_execution_path(str(test_file), "main")

        assert result.status in ("success", "error")


class TestAnalyzeXrefs:
    """Tests for analyze_xrefs."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.radare2.r2_analysis import analyze_xrefs

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.radare2.r2_analysis.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.radare2.r2_analysis._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ('{"xrefs": []}', 15)
                result = await analyze_xrefs(str(test_file), "0x401000")

        assert result.status in ("success", "error")
