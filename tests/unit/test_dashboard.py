"""Tests for reversecore_mcp.dashboard."""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")

from reversecore_mcp.dashboard import (
    _generate_csrf_token,
    _sanitize_for_display,
    _verify_csrf_token,
    get_router,
    get_static_files,
)


class TestCSRFToken:
    """Tests for CSRF token functions."""

    def test_generate_and_verify(self):
        token = _generate_csrf_token("session1")
        assert len(token) > 0
        assert _verify_csrf_token("session1", token) is True

    def test_verify_invalid(self):
        assert _verify_csrf_token("session2", "invalid") is False


class TestSanitizeForDisplay:
    """Tests for _sanitize_for_display."""

    def test_clean_text(self):
        result = _sanitize_for_display("hello world")
        assert result == "hello world"

    def test_html_escape(self):
        result = _sanitize_for_display("<script>alert(1)</script>")
        assert "&lt;" in result

    def test_max_length(self):
        long_text = "a" * 2000
        result = _sanitize_for_display(long_text)
        assert len(result) <= 1020  # HTML escape may add overhead


class TestGetRouter:
    """Tests for get_router."""

    def test_returns_router(self):
        router = get_router()
        assert router is not None


class TestGetStaticFiles:
    """Tests for get_static_files."""

    def test_returns_static_files(self):
        static_files = get_static_files()
        assert static_files is not None


class TestDashboardRoutes:
    """Tests for dashboard routes."""

    @pytest.mark.asyncio
    async def test_dashboard_index(self, tmp_path):
        from reversecore_mcp.dashboard import dashboard_index

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "test.exe").write_bytes(b"MZ")

        with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config

            request = MagicMock()
            result = await dashboard_index(request)

        assert result is not None

    @pytest.mark.asyncio
    async def test_dashboard_analysis(self, tmp_path):
        from reversecore_mcp.dashboard import dashboard_analysis

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "test.exe").write_bytes(b"MZ")

        with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            with patch(
                "reversecore_mcp.core.security.validate_file_path",
                return_value=workspace / "test.exe",
            ):
                request = MagicMock()
                result = await dashboard_analysis(request, "test.exe")

        assert result is not None
