"""ASGI security middleware used by the HTTP transport."""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.responses import JSONResponse

ASGIApp = Callable[
    [dict[str, Any], Callable[..., Awaitable[Any]], Callable[..., Awaitable[Any]]], Awaitable[None]
]


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))

                def has_header(name_bytes):
                    return any(header[0].lower() == name_bytes for header in headers)

                if not has_header(b"strict-transport-security"):
                    headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=31536000; includeSubDomains",
                        )
                    )
                if not has_header(b"x-content-type-options"):
                    headers.append((b"x-content-type-options", b"nosniff"))
                if not has_header(b"x-frame-options"):
                    headers.append((b"x-frame-options", b"DENY"))
                if not has_header(b"content-security-policy"):
                    headers.append((b"content-security-policy", b"default-src 'self'"))

                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class LoopbackOnlyMiddleware:
    """Restrict unauthenticated HTTP access to loopback clients.

    Containerized servers may need to listen on ``0.0.0.0`` so a public health
    probe can reach them. When no API key is configured, this middleware keeps
    all non-health routes private while preserving the existing public liveness
    contract.
    """

    PUBLIC_PATHS = frozenset({"/health", "/health/live", "/health/ready"})

    def __init__(self, app: ASGIApp):
        self.app = app

    @staticmethod
    def _is_loopback(scope: dict[str, Any]) -> bool:
        client = scope.get("client")
        if not client:
            return False

        host = str(client[0]).strip()
        if host.lower() == "localhost":
            return True

        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self.PUBLIC_PATHS or self._is_loopback(scope):
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            status_code=403,
            content={
                "detail": "MCP_API_KEY is required for non-loopback HTTP access.",
            },
        )
        await response(scope, receive, send)
