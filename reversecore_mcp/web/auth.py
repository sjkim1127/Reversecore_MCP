"""
Authentication verification dependencies for Reversecore MCP HTTP transport.
"""

import os
import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


def setup_authentication():
    """
    Setup API Key authentication for HTTP transport mode.

    To enable authentication, set environment variable:
        MCP_API_KEY=your-secret-key

    All HTTP requests must include header:
        X-API-Key: your-secret-key
    or header:
        Authorization: Bearer your-secret-key
    """
    api_key = os.getenv("MCP_API_KEY")

    if not api_key:
        logger.info("🔓 API Key authentication disabled (MCP_API_KEY not set)")
        return None

    logger.info("🔐 API Key authentication enabled")

    # APIKeyHeader extracts from "X-API-Key"
    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def verify_api_key(
        request: Request,
        key: str | None = Depends(api_key_header),
    ) -> str | None:
        # Check X-API-Key header or Authorization Bearer header
        req_key = key

        # If not present in X-API-Key, check Authorization header
        if not req_key:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                req_key = auth_header[7:]

        # If no key provided at all
        if not req_key:
            logger.warning(
                f"⚠️ Unauthorized access attempt (no key provided) from {request.client.host if request.client else 'unknown'} to {request.url.path}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing API key. Use X-API-Key header or Authorization: Bearer token.",
            )

        # Constant-time comparison to prevent side-channel timing attacks
        if not secrets.compare_digest(req_key, api_key):
            logger.warning(
                f"⚠️ Unauthorized access attempt (invalid key) from {request.client.host if request.client else 'unknown'} to {request.url.path}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid API key. Use X-API-Key header or Authorization: Bearer token.",
            )

        return req_key

    return Depends(verify_api_key)
