"""Unit tests for capa_tools module."""

import pytest
from unittest.mock import patch, MagicMock

from reversecore_mcp.core.result import ToolSuccess, ToolError, success, failure


class TestCapaAvailability:
    """Tests for CAPA availability check."""

    def test_is_capa_available_returns_bool(self):
        """Test that _is_capa_available returns a boolean."""
        from reversecore_mcp.tools.analysis.capa_tools import _is_capa_available

        result = _is_capa_available()
        assert isinstance(result, bool)


class TestRunCapa:
    """Tests for run_capa tool."""

    @pytest.mark.asyncio
    async def test_run_capa_not_installed(self):
        """Test when CAPA is not installed."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools._is_capa_available",
            return_value=False,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.capa_tools.validate_file_path",
                return_value="/path/to/file.exe",
            ):
                result = await run_capa("/path/to/file.exe")
                assert isinstance(result, ToolError)
                assert "not installed" in result.message.lower()


class TestRunCapaQuick:
    """Tests for run_capa_quick tool."""

    @pytest.mark.asyncio
    async def test_run_capa_quick_filters_high_risk(self):
        """Test that quick scan filters to high-risk capabilities."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = success(
            data={
                "capabilities": [
                    {"name": "encrypt data", "namespace": "defense-evasion"},
                    {"name": "delete file", "namespace": "impact"},
                    {"name": "read file size", "namespace": "file-system"},  # Not high-risk
                ],
                "mitre_attack": ["T1486"],
            },
            message="test",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolSuccess)
            # Should have filtered out non-high-risk
            assert len(result.data["high_risk_capabilities"]) == 2

    @pytest.mark.asyncio
    async def test_run_capa_quick_propagates_error(self):
        """Test that errors from run_capa are propagated."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = failure(
            error_code="CAPA_ERROR",
            message="CAPA analysis failed",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolError)


class TestHighRiskNamespaces:
    """Tests for high-risk namespace filtering."""

    @pytest.mark.asyncio
    async def test_anti_analysis_is_high_risk(self):
        """Test that anti-analysis is marked as high risk."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = success(
            data={
                "capabilities": [
                    {"name": "detect debugger", "namespace": "anti-analysis/anti-debugging"},
                ],
                "mitre_attack": [],
            },
            message="test",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolSuccess)
            assert len(result.data["high_risk_capabilities"]) == 1

    @pytest.mark.asyncio
    async def test_persistence_is_high_risk(self):
        """Test that persistence is marked as high risk."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = success(
            data={
                "capabilities": [
                    {"name": "create service", "namespace": "persistence/service"},
                ],
                "mitre_attack": [],
            },
            message="test",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolSuccess)
            assert len(result.data["high_risk_capabilities"]) == 1
