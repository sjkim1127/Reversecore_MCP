"""
Authentication verification dependencies for Reversecore MCP HTTP transport.
"""

import secrets

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class APIKeyAuthMiddleware:
    """ASGI middleware to enforce API Key authentication globally (including mounted sub-apps)."""

    def __init__(self, app, api_key: str):
        self.app = app
        self.api_key = api_key

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Public health check endpoints
        exempt_paths = {"/health", "/health/live", "/health/ready"}
        if path in exempt_paths:
            await self.app(scope, receive, send)
            return

        # Extract X-API-Key or Authorization Bearer header
        headers = dict(scope.get("headers", []))
        req_key = None

        if b"x-api-key" in headers:
            req_key = headers[b"x-api-key"].decode("utf-8", errors="ignore")
        elif b"authorization" in headers:
            auth_val = headers[b"authorization"].decode("utf-8", errors="ignore")
            if auth_val.lower().startswith("bearer "):
                req_key = auth_val[7:]

        if not req_key or not secrets.compare_digest(req_key, self.api_key):
            # Send 403 response directly at ASGI level
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"detail": "Invalid or missing API key. Use X-API-Key or Authorization: Bearer token."}',
                    "more_body": False,
                }
            )
            return

        await self.app(scope, receive, send)
