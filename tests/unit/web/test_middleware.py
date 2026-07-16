"""Unit tests for reversecore_mcp/web/middleware.py.

Tests both SecurityHeadersMiddleware and LoopbackOnlyMiddleware using
lightweight ASGI test helpers — no external network calls required.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Minimal ASGI test harness
# ---------------------------------------------------------------------------


def _make_http_scope(
    path: str = "/", client: tuple[str, int] | None = ("127.0.0.1", 12345)
) -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [],
        "client": client,
    }


def _make_non_http_scope(scope_type: str = "websocket") -> dict:
    return {"type": scope_type, "path": "/ws"}


async def _capture_response(app, scope, receive=None, send=None):
    """Run an ASGI app and capture the response start message."""
    captured: dict = {}

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        if message["type"] == "http.response.start":
            captured.update(message)
        # Silently drop http.response.body

    await app(scope, receive or _receive, send or _send)
    return captured


async def _simple_200_app(scope, receive, send):
    """Minimal ASGI app that always returns HTTP 200."""
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [],
        }
    )
    await send({"type": "http.response.body", "body": b"ok", "more_body": False})


async def _passthrough_app(scope, receive, send):
    """Non-HTTP ASGI app for lifespan/websocket passthrough tests."""
    pass  # must not call send for non-http scopes


# ---------------------------------------------------------------------------
# SecurityHeadersMiddleware
# ---------------------------------------------------------------------------


class TestSecurityHeadersMiddleware:
    @pytest.fixture(autouse=True)
    def _import(self):
        from reversecore_mcp.web.middleware import SecurityHeadersMiddleware

        self.Middleware = SecurityHeadersMiddleware

    @pytest.mark.asyncio
    async def test_adds_hsts_header(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(app, _make_http_scope())
        headers = dict(response.get("headers", []))
        assert b"strict-transport-security" in headers
        assert b"max-age=31536000" in headers[b"strict-transport-security"]

    @pytest.mark.asyncio
    async def test_adds_x_content_type_options(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(app, _make_http_scope())
        headers = dict(response.get("headers", []))
        assert headers.get(b"x-content-type-options") == b"nosniff"

    @pytest.mark.asyncio
    async def test_adds_x_frame_options(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(app, _make_http_scope())
        headers = dict(response.get("headers", []))
        assert headers.get(b"x-frame-options") == b"DENY"

    @pytest.mark.asyncio
    async def test_adds_content_security_policy(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(app, _make_http_scope())
        headers = dict(response.get("headers", []))
        assert b"content-security-policy" in headers

    @pytest.mark.asyncio
    async def test_does_not_overwrite_existing_hsts(self):
        """If the app already sets HSTS, the middleware should not duplicate it."""
        custom_value = b"max-age=0"

        async def _app_with_hsts(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"strict-transport-security", custom_value)],
                }
            )
            await send({"type": "http.response.body", "body": b""})

        app = self.Middleware(_app_with_hsts)
        response = await _capture_response(app, _make_http_scope())
        headers_list = response.get("headers", [])
        hsts_values = [v for k, v in headers_list if k == b"strict-transport-security"]
        assert len(hsts_values) == 1  # not duplicated
        assert hsts_values[0] == custom_value

    @pytest.mark.asyncio
    async def test_non_http_scope_passthrough(self):
        """Non-HTTP scopes must be forwarded without modification."""
        calls: list[str] = []

        async def _tracking_app(scope, receive, send):
            calls.append(scope["type"])

        app = self.Middleware(_tracking_app)
        scope = _make_non_http_scope("lifespan")
        await app(scope, None, None)
        assert calls == ["lifespan"]


# ---------------------------------------------------------------------------
# LoopbackOnlyMiddleware
# ---------------------------------------------------------------------------


class TestLoopbackOnlyMiddleware:
    @pytest.fixture(autouse=True)
    def _import(self):
        from reversecore_mcp.web.middleware import LoopbackOnlyMiddleware

        self.Middleware = LoopbackOnlyMiddleware

    @pytest.mark.asyncio
    async def test_loopback_127_0_0_1_allowed(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(
            app, _make_http_scope("/analyze", client=("127.0.0.1", 1234))
        )
        assert response.get("status") == 200

    @pytest.mark.asyncio
    async def test_loopback_localhost_string_allowed(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(
            app, _make_http_scope("/analyze", client=("localhost", 1234))
        )
        assert response.get("status") == 200

    @pytest.mark.asyncio
    async def test_loopback_ipv6_allowed(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(app, _make_http_scope("/analyze", client=("::1", 1234)))
        assert response.get("status") == 200

    @pytest.mark.asyncio
    async def test_external_ip_blocked_on_private_path(self):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(
            app, _make_http_scope("/analyze", client=("10.0.0.1", 1234))
        )
        assert response.get("status") == 403

    @pytest.mark.asyncio
    async def test_external_ip_blocked_returns_json_detail(self):
        captured_body: list[bytes] = []

        async def _capturing_send(message):
            if message["type"] == "http.response.body":
                captured_body.append(message.get("body", b""))

        app = self.Middleware(_simple_200_app)
        scope = _make_http_scope("/secret", client=("8.8.8.8", 1234))

        response_start: dict = {}

        async def _full_send(message):
            if message["type"] == "http.response.start":
                response_start.update(message)
            elif message["type"] == "http.response.body":
                captured_body.append(message.get("body", b""))

        await app(scope, None, _full_send)
        assert response_start.get("status") == 403
        import json

        body = json.loads(b"".join(captured_body))
        assert "detail" in body

    @pytest.mark.asyncio
    @pytest.mark.parametrize("public_path", ["/health", "/health/live", "/health/ready"])
    async def test_public_paths_allowed_from_external_ip(self, public_path: str):
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(
            app, _make_http_scope(public_path, client=("203.0.113.1", 1234))
        )
        assert response.get("status") == 200

    @pytest.mark.asyncio
    async def test_missing_client_info_is_blocked(self):
        """If there's no client in scope, treat as non-loopback (deny)."""
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(app, _make_http_scope("/analyze", client=None))
        assert response.get("status") == 403

    @pytest.mark.asyncio
    async def test_non_http_scope_passthrough(self):
        calls: list[str] = []

        async def _tracking_app(scope, receive, send):
            calls.append(scope["type"])

        app = self.Middleware(_tracking_app)
        await app({"type": "lifespan", "path": "/"}, None, None)
        assert calls == ["lifespan"]

    @pytest.mark.asyncio
    async def test_invalid_ip_string_is_blocked(self):
        """Malformed IP address strings should be treated as non-loopback."""
        app = self.Middleware(_simple_200_app)
        response = await _capture_response(
            app, _make_http_scope("/analyze", client=("not-an-ip", 1234))
        )
        assert response.get("status") == 403
