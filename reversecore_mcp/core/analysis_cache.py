"""Redis-based caching for binary analysis results, specifically Ghidra decompilation.

This module provides high-performance result caching based on the SHA256 of the binary file,
avoiding repetitive decompilation of unmodified binaries.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import redis.asyncio as aioredis

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolError, ToolResult, ToolSuccess

logger = get_logger(__name__)

# Singleton Redis connection pool / client
_redis_client: aioredis.Redis | None = None
_redis_enabled: bool = True  # Disabled if connection fails persistently


def get_redis_client() -> aioredis.Redis | None:
    """Get or initialize the global async Redis client."""
    global _redis_client, _redis_enabled
    if not _redis_enabled:
        return None

    if _redis_client is None:
        try:
            config = get_config()
            # Initialize Redis client using the URL from configuration settings
            _redis_client = aioredis.from_url(
                config.redis_url,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
            logger.info(f"Initialized Redis client with URL: {config.redis_url}")
        except Exception as e:
            logger.warning(f"Failed to initialize Redis client: {e}. Caching is disabled.")
            _redis_enabled = False
            return None

    return _redis_client


async def close_redis() -> None:
    """Close the global Redis client connection pool."""
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.aclose()
            logger.info("Redis client connection closed.")
        except Exception as e:
            logger.debug(f"Error closing Redis client: {e}")
        finally:
            _redis_client = None


def calculate_file_sha256(file_path: Path | str) -> str:
    """Calculate SHA256 hash of a file efficiently by reading in chunks."""
    sha256 = hashlib.sha256()
    path = Path(file_path)
    if not path.exists():
        return ""

    try:
        # Read in 64KB chunks to optimize memory and disk I/O
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating SHA256 for {file_path}: {e}")
        return ""


def _serialize_result(result: ToolResult) -> str:
    """Serialize ToolResult object to JSON string."""
    if isinstance(result, ToolSuccess):
        data = {
            "status": "success",
            "data": result.data,
            "metadata": result.metadata,
        }
    else:
        data = {
            "status": "error",
            "error_code": result.error_code,
            "message": result.message,
            "hint": result.hint,
            "details": result.details,
        }
    return json.dumps(data)


def _deserialize_result(serialized: str) -> ToolResult | None:
    """Deserialize JSON string to ToolResult object."""
    try:
        data = json.loads(serialized)
        status = data.get("status")
        if status == "success":
            return ToolSuccess(
                data=data.get("data", ""),
                metadata=data.get("metadata"),
            )
        elif status == "error":
            return ToolError(
                error_code=data.get("error_code", "UNKNOWN_ERROR"),
                message=data.get("message", ""),
                hint=data.get("hint"),
                details=data.get("details"),
            )
    except Exception as e:
        logger.warning(f"Failed to deserialize cached result: {e}")
    return None


async def get_cached_decompile(
    file_path: Path | str,
    function_address: str,
    use_ghidra: bool = True,
) -> ToolResult | None:
    """Retrieve cached decompilation result from Redis.

    Args:
        file_path: Path to the binary file.
        function_address: Target function name or address.
        use_ghidra: Whether Ghidra decompiler was used.

    Returns:
        ToolResult if found in cache, otherwise None.
    """
    client = get_redis_client()
    if client is None:
        return None

    # Calculate file SHA256 to invalidate cache if binary gets modified
    file_hash = calculate_file_sha256(file_path)
    if not file_hash:
        return None

    # Construct the unique cache key
    decompiler = "ghidra" if use_ghidra else "radare2"
    cache_key = f"ghidra:decompile:{file_hash}:{function_address}:{decompiler}"

    try:
        serialized = await client.get(cache_key)
        if serialized:
            result = _deserialize_result(serialized)
            if result:
                logger.info(f"Cache HIT for {function_address} in {file_path}")
                # Inject a flag indicating this result came from cache
                if isinstance(result, ToolSuccess):
                    if result.metadata is None:
                        result.metadata = {}
                    result.metadata["cache_hit"] = True
                return result
    except Exception as e:
        logger.debug(f"Redis get error: {e}. Proceeding with cache miss.")

    return None


async def set_cached_decompile(
    file_path: Path | str,
    function_address: str,
    result: ToolResult,
    use_ghidra: bool = True,
    ttl_seconds: int = 3600,
) -> None:
    """Store decompilation result in Redis with a TTL.

    Args:
        file_path: Path to the binary file.
        function_address: Target function name or address.
        result: The ToolResult to cache.
        use_ghidra: Whether Ghidra decompiler was used.
        ttl_seconds: Time-to-live in seconds (default: 1 hour).
    """
    # Do not cache failed results (unless transient errors are handled differently)
    if not isinstance(result, ToolSuccess):
        return

    client = get_redis_client()
    if client is None:
        return

    file_hash = calculate_file_sha256(file_path)
    if not file_hash:
        return

    decompiler = "ghidra" if use_ghidra else "radare2"
    cache_key = f"ghidra:decompile:{file_hash}:{function_address}:{decompiler}"

    try:
        serialized = _serialize_result(result)
        await client.setex(cache_key, ttl_seconds, serialized)
        logger.debug(
            f"Cached decompile for {function_address} in {file_path} (TTL: {ttl_seconds}s)"
        )
    except Exception as e:
        logger.warning(f"Failed to cache decompile result in Redis: {e}")
