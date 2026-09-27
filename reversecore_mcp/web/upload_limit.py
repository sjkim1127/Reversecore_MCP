"""Request-body limits for multipart uploads before FastAPI parses them."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Any

from reversecore_mcp.core.config import get_config

ASGIMessage = dict[str, Any]
Receive = Callable[[], Awaitable[ASGIMessage]]
Send = Callable[[ASGIMessage], Awaitable[None]]
MULTIPART_OVERHEAD_LIMIT = 64 * 1024


class _UploadBodyTooLarge(Exception):
    """Raised when a streaming upload exceeds its bounded request size."""


class UploadRequestLimitMiddleware:
    """Reject oversized or disabled uploads before multipart file spooling."""

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != "/upload"
        ):
            await self.app(scope, receive, send)
            return

        if os.getenv("REVERSECORE_UPLOAD_ENABLED", "true").lower() != "true":
            await self._respond(send, 400, "File upload is disabled on this server.")
            return

        max_body_size = get_config().max_upload_size + MULTIPART_OVERHEAD_LIMIT
        content_lengths = [
            value.strip()
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-length"
        ]
        if content_lengths:
            if len(set(content_lengths)) != 1 or not content_lengths[0].isdigit():
                await self._respond(send, 400, "Invalid Content-Length header.")
                return
            if int(content_lengths[0]) > max_body_size:
                await self._respond(send, 413, "Request body exceeds the upload size limit.")
                return

        received_bytes = 0

        async def limited_receive() -> ASGIMessage:
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > max_body_size:
                    raise _UploadBodyTooLarge
            return message

        response_started = False

        async def tracked_send(message: ASGIMessage) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _UploadBodyTooLarge:
            if not response_started:
                await self._respond(send, 413, "Request body exceeds the upload size limit.")

    @staticmethod
    async def _respond(send: Send, status_code: int, detail: str) -> None:
        body = ('{"detail":"' + detail.replace('"', "'") + '"}').encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})
