"""Tests for reversecore_mcp.dashboard."""

from unittest.mock import AsyncMock, MagicMock, patch

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

    def test_expired_tokens_are_pruned(self):
        from reversecore_mcp.dashboard import _csrf_tokens, _prune_csrf_tokens

        token = _generate_csrf_token("expiry-test-session")
        expires_at = _csrf_tokens["expiry-test-session"][1]

        _prune_csrf_tokens(now=expires_at)

        assert _verify_csrf_token("expiry-test-session", token) is False
        assert "expiry-test-session" not in _csrf_tokens

    def test_token_store_rejects_new_sessions_when_full_without_evicting_live_tokens(
        self, monkeypatch
    ):
        from fastapi import HTTPException

        from reversecore_mcp import dashboard

        previous_tokens = dashboard._csrf_tokens.copy()
        dashboard._csrf_tokens.clear()
        monkeypatch.setattr(dashboard, "_CSRF_TOKEN_MAX_SESSIONS", 2)
        try:
            first_token = _generate_csrf_token("first-session")
            second_token = _generate_csrf_token("second-session")

            with pytest.raises(HTTPException) as exc_info:
                _generate_csrf_token("third-session")

            assert exc_info.value.status_code == 503
            assert len(dashboard._csrf_tokens) == 2
            assert _verify_csrf_token("first-session", first_token) is True
            assert _verify_csrf_token("second-session", second_token) is True
        finally:
            dashboard._csrf_tokens.clear()
            dashboard._csrf_tokens.update(previous_tokens)


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
            with patch("starlette.templating.Jinja2Templates.TemplateResponse") as mock_tr:
                mock_tr.return_value = MagicMock()
                request = MagicMock()
                result = await dashboard_index(request)

        assert result is not None

    @pytest.mark.asyncio
    async def test_dashboard_reports_mints_separate_sessions_for_legacy_clients(self, tmp_path):
        from reversecore_mcp.dashboard import (
            _CSRF_TOKEN_TTL_SECONDS,
            _csrf_tokens,
            _verify_csrf_token,
            dashboard_reports,
        )

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        response_a = MagicMock()
        response_b = MagicMock()

        with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config

            with patch(
                "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
            ) as mock_get_tools:
                mock_tools = MagicMock()
                mock_tools.list_reports = AsyncMock(return_value={"reports": []})
                mock_get_tools.return_value = mock_tools

                with patch(
                    "starlette.templating.Jinja2Templates.TemplateResponse",
                    side_effect=[response_a, response_b],
                ) as mock_template:
                    request_a = MagicMock()
                    request_a.cookies = {"session_id": "default_session"}
                    request_a.url.scheme = "https"
                    request_b = MagicMock()
                    request_b.cookies = {"session_id": "default_session"}
                    request_b.url.scheme = "https"

                    await dashboard_reports(request_a)
                    await dashboard_reports(request_b)

        session_a = response_a.set_cookie.call_args.args[1]
        session_b = response_b.set_cookie.call_args.args[1]
        context_a = mock_template.call_args_list[0].args[2]
        context_b = mock_template.call_args_list[1].args[2]
        token_a = context_a["csrf_token"]
        token_b = context_b["csrf_token"]

        assert session_a != session_b
        assert len(session_a) >= 40
        assert len(session_b) >= 40
        for response in (response_a, response_b):
            cookie_options = response.set_cookie.call_args.kwargs
            assert cookie_options["httponly"] is True
            assert cookie_options["secure"] is True
            assert cookie_options["samesite"] == "lax"
            assert cookie_options["max_age"] == _CSRF_TOKEN_TTL_SECONDS

        # A second client's GET must not invalidate the first client's form.
        assert _verify_csrf_token(session_a, token_a) is True
        assert _verify_csrf_token(session_b, token_b) is True

        _csrf_tokens.pop(session_a, None)
        _csrf_tokens.pop(session_b, None)

    @pytest.mark.asyncio
    async def test_dashboard_reports_keeps_http_cookie_usable_for_local_dashboard(self, tmp_path):
        from reversecore_mcp.dashboard import dashboard_reports

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        response = MagicMock()

        with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config

            with patch(
                "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
            ) as mock_get_tools:
                mock_tools = MagicMock()
                mock_tools.list_reports = AsyncMock(return_value={"reports": []})
                mock_get_tools.return_value = mock_tools

                with patch(
                    "starlette.templating.Jinja2Templates.TemplateResponse",
                    return_value=response,
                ):
                    request = MagicMock()
                    request.cookies = {}
                    request.url.scheme = "http"

                    await dashboard_reports(request)

        assert response.set_cookie.call_args.kwargs["secure"] is False

    @pytest.mark.asyncio
    async def test_dashboard_reports_refreshes_cookie_lifetime_for_existing_session(self, tmp_path):
        from reversecore_mcp.dashboard import (
            _CSRF_TOKEN_TTL_SECONDS,
            _csrf_tokens,
            _verify_csrf_token,
            dashboard_reports,
        )

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        response_a = MagicMock()
        response_b = MagicMock()

        with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config

            with patch(
                "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
            ) as mock_get_tools:
                mock_tools = MagicMock()
                mock_tools.list_reports = AsyncMock(return_value={"reports": []})
                mock_get_tools.return_value = mock_tools

                with patch(
                    "starlette.templating.Jinja2Templates.TemplateResponse",
                    side_effect=[response_a, response_b],
                ) as mock_template:
                    request_a = MagicMock()
                    request_a.cookies = {}
                    request_a.url.scheme = "https"
                    await dashboard_reports(request_a)

                    session_id = response_a.set_cookie.call_args.args[1]
                    request_b = MagicMock()
                    request_b.cookies = {"session_id": session_id}
                    request_b.url.scheme = "https"
                    await dashboard_reports(request_b)

        refreshed_session_id = response_b.set_cookie.call_args.args[1]
        token_b = mock_template.call_args_list[1].args[2]["csrf_token"]

        assert refreshed_session_id == session_id
        assert response_b.set_cookie.call_args.kwargs["max_age"] == _CSRF_TOKEN_TTL_SECONDS
        assert _verify_csrf_token(session_id, token_b) is True
        _csrf_tokens.pop(session_id, None)

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
                with patch("starlette.templating.Jinja2Templates.TemplateResponse") as mock_tr:
                    mock_tr.return_value = MagicMock()
                    request = MagicMock()
                    result = await dashboard_analysis(request, "test.exe")

        assert result is not None
