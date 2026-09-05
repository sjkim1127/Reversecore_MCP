"""Unit tests for taint_trace tool."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from reversecore_mcp.tools.analysis.taint_analysis import (
    TAINT_SINKS,
    TAINT_SOURCES,
    _find_sink_calls,
    _find_source_calls,
    taint_trace,
)


class TestTaintDatabases:
    """Tests for taint source/sink databases."""

    def test_sources_non_empty(self):
        assert len(TAINT_SOURCES) >= 10

    def test_sinks_non_empty(self):
        assert len(TAINT_SINKS) >= 10

    def test_sources_have_required_fields(self):
        for name, info in TAINT_SOURCES.items():
            assert "category" in info, f"Source {name} missing category"
            assert "description" in info, f"Source {name} missing description"
            assert info["category"] in ("stdin", "argv", "env", "network", "file")

    def test_sinks_have_required_fields(self):
        for name, info in TAINT_SINKS.items():
            assert "cwe" in info, f"Sink {name} missing cwe"
            assert "severity" in info, f"Sink {name} missing severity"
            assert "category" in info, f"Sink {name} missing category"
            assert info["cwe"].startswith("CWE-")
            assert info["severity"] in ("critical", "high", "medium", "low")

    def test_critical_sinks_present(self):
        """High-impact sinks must be present."""
        critical_sinks = {"strcpy", "system", "execve", "gets", "popen"}
        for sink in critical_sinks:
            assert sink in TAINT_SINKS, f"Critical sink '{sink}' missing"

    def test_common_sources_present(self):
        common_sources = {"fgets", "recv", "read", "getenv", "argv"}
        for src in common_sources:
            assert src in TAINT_SOURCES, f"Common source '{src}' missing"


class TestTaintTrace:
    """Tests for taint_trace MCP tool."""

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis.validate_file_path")
    async def test_invalid_sources_returns_error(self, mock_validate, tmp_path):
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        mock_validate.return_value = binary

        result = await taint_trace(
            file_path=str(binary),
            sources=["nonexistent_source_xyz"],
        )
        assert result.status == "error"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis.validate_file_path")
    async def test_invalid_sinks_returns_error(self, mock_validate, tmp_path):
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        mock_validate.return_value = binary

        result = await taint_trace(
            file_path=str(binary),
            sinks=["totally_nonexistent_sink_abc"],
        )
        assert result.status == "error"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_sink_calls")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_source_calls")
    async def test_no_sinks_found_returns_success_empty(
        self, mock_sources, mock_sinks, mock_validate, tmp_path
    ):
        """When no sinks are found in binary, return success with empty paths."""
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        mock_validate.return_value = binary
        mock_sinks.return_value = []
        mock_sources.return_value = [
            {
                "source_api": "fgets",
                "call_address": "0x401000",
                "category": "stdin",
                "description": "fgets stdin",
            }
        ]

        result = await taint_trace(str(binary), verify_with_angr=False)
        assert result.status == "success"
        assert result.data["taint_paths"] == []
        assert result.data["sinks_found"] == []

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_sink_calls")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_source_calls")
    async def test_static_paths_found_without_angr(
        self, mock_sources, mock_sinks, mock_validate, tmp_path
    ):
        """Without angr verification, paths should appear in static_paths."""
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        mock_validate.return_value = binary

        mock_sources.return_value = [
            {
                "source_api": "fgets",
                "call_address": "0x401010",
                "category": "stdin",
                "description": "fgets",
            },
        ]
        mock_sinks.return_value = [
            {
                "sink_api": "strcpy",
                "call_address": "0x401050",
                "cwe": "CWE-120",
                "severity": "critical",
                "category": "buffer_overflow",
                "description": "Unbounded copy",
            },
        ]

        result = await taint_trace(str(binary), verify_with_angr=False, max_paths=5)
        assert result.status == "success"
        assert len(result.data["static_paths"]) > 0
        assert result.data["verified_paths"] == []

        path = result.data["static_paths"][0]
        assert path["source_api"] == "fgets"
        assert path["sink_api"] == "strcpy"
        assert path["cwe"] == "CWE-120"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_sink_calls")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_source_calls")
    @patch("reversecore_mcp.tools.analysis.taint_analysis.verify_path_and_get_args")
    async def test_angr_verified_path(
        self, mock_angr, mock_sources, mock_sinks, mock_validate, tmp_path
    ):
        """When angr confirms reachability, path goes into verified_paths."""
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        mock_validate.return_value = binary

        mock_sources.return_value = [
            {
                "source_api": "recv",
                "call_address": "0x401020",
                "category": "network",
                "description": "recv",
            },
        ]
        mock_sinks.return_value = [
            {
                "sink_api": "system",
                "call_address": "0x401080",
                "cwe": "CWE-78",
                "severity": "critical",
                "category": "command_injection",
                "description": "Shell execution",
            },
        ]

        # angr says: reachable with concrete input "exploit_string"
        mock_angr.return_value = {
            "satisfiable": True,
            "concrete_input": "exploit_string",
            "inputs": {"argv1": "exploit_string"},
        }

        result = await taint_trace(str(binary), verify_with_angr=True, max_paths=5)
        assert result.status == "success"
        assert len(result.data["verified_paths"]) == 1

        vpath = result.data["verified_paths"][0]
        assert vpath["path_verified"] is True
        assert vpath["concrete_input"] == "exploit_string"
        assert vpath["source_api"] == "recv"
        assert vpath["sink_api"] == "system"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_sink_calls")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_source_calls")
    async def test_result_has_required_keys(
        self, mock_sources, mock_sinks, mock_validate, tmp_path
    ):
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        mock_validate.return_value = binary
        mock_sinks.return_value = []
        mock_sources.return_value = []

        result = await taint_trace(str(binary), verify_with_angr=False)
        assert result.status == "success"
        for key in [
            "taint_paths",
            "verified_paths",
            "static_paths",
            "sources_found",
            "sinks_found",
            "top_path",
            "statistics",
            "next_steps",
        ]:
            assert key in result.data, f"Missing key: {key}"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_sink_calls")
    @patch("reversecore_mcp.tools.analysis.taint_analysis._find_source_calls")
    async def test_custom_sources_filter(self, mock_sources, mock_sinks, mock_validate, tmp_path):
        """Custom sources list should filter the active sources."""
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        mock_validate.return_value = binary
        mock_sinks.return_value = []
        mock_sources.return_value = [
            {
                "source_api": "recv",
                "call_address": "0x0",
                "category": "network",
                "description": "recv",
            },
        ]

        result = await taint_trace(
            str(binary),
            sources=["recv"],
            sinks=["strcpy"],
            verify_with_angr=False,
        )
        assert result.status == "success"


class TestFindCalls:
    """Direct tests for _find_sink_calls and _find_source_calls."""

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis._execute_r2_command")
    async def test_find_sink_calls_batch_success(self, mock_r2):
        # 1st call: batch returns symbols including strcpy
        # 2nd call: xrefs for strcpy
        mock_r2.side_effect = [
            ("0x401000 imp.strcpy\n0x401050 imp.printf\n", 40),
            ('[{"from": 4198420, "type": "CALL"}]', 35),
        ]
        sinks = await _find_sink_calls("/fake/path", timeout=30)
        assert len(sinks) >= 1
        assert any(s["sink_api"] == "strcpy" for s in sinks)

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis._execute_r2_command")
    async def test_find_sink_calls_batch_fallback(self, mock_r2):
        # 1st call raises Exception -> triggers fallback loop
        mock_r2.side_effect = Exception("r2 batch failed")
        sinks = await _find_sink_calls("/fake/path", timeout=30)
        assert sinks == []

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis._execute_r2_command")
    async def test_find_source_calls_batch_success(self, mock_r2):
        mock_r2.return_value = ("0x401000 imp.fgets\n0x401050 imp.recv\n", 40)
        sources = await _find_source_calls("/fake/path", timeout=30)
        source_names = [s["source_api"] for s in sources]
        assert "argv" in source_names
        assert "fgets" in source_names
        assert "recv" in source_names

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.taint_analysis._execute_r2_command")
    async def test_find_source_calls_batch_fallback(self, mock_r2):
        mock_r2.side_effect = Exception("r2 batch failed")
        sources = await _find_source_calls("/fake/path", timeout=30)
        assert len(sources) == 1
        assert sources[0]["source_api"] == "argv"
