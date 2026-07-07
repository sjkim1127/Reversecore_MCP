"""Redis-based caching for binary analysis results, specifically Ghidra decompilation.

This module provides high-performance result caching based on the SHA256 of the binary file,
avoiding repetitive decompilation of unmodified binaries.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolError, ToolResult, ToolSuccess

logger = get_logger(__name__)

# Singleton/global state for SQLite initialization
_sqlite_db_path: Path | None = None
_sqlite_initialized: bool = False


def _init_sqlite_db() -> Path:
    """Initialize the SQLite database and create the table if it does not exist."""
    global _sqlite_db_path, _sqlite_initialized
    config = get_config()
    current_db_path = config.workspace / ".reversecore_cache.db"

    # If the workspace path changed (e.g., in a test environment), reset initialization
    if _sqlite_db_path != current_db_path:
        _sqlite_db_path = current_db_path
        _sqlite_initialized = False

    # Ensure parent directory exists
    _sqlite_db_path.parent.mkdir(parents=True, exist_ok=True)

    if not _sqlite_initialized:
        conn = sqlite3.connect(_sqlite_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS decompilation_cache (
                    file_hash TEXT,
                    function_address TEXT,
                    decompiler TEXT,
                    status TEXT,
                    data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (file_hash, function_address, decompiler)
                )
            """)
            conn.commit()
            _sqlite_initialized = True
            logger.info(f"SQLite caching database initialized at {_sqlite_db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize SQLite cache database: {e}")
        finally:
            conn.close()

    return _sqlite_db_path


def _read_from_sqlite(
    db_path: Path, file_hash: str, function_address: str, decompiler: str
) -> str | None:
    """Read serialized data from SQLite database."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT data FROM decompilation_cache WHERE file_hash = ? AND function_address = ? AND decompiler = ?",
            (file_hash, function_address, decompiler),
        )
        row = cursor.fetchone()
        if row and isinstance(row[0], str):
            return row[0]
    except Exception as e:
        logger.error(f"SQLite read error for {function_address} in {file_hash}: {e}")
    finally:
        conn.close()
    return None


def _write_to_sqlite(
    db_path: Path,
    file_hash: str,
    function_address: str,
    decompiler: str,
    status: str,
    data: str,
) -> None:
    """Write serialized data to SQLite database."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO decompilation_cache (file_hash, function_address, decompiler, status, data, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (file_hash, function_address, decompiler, status, data),
        )
        conn.commit()
    except Exception as e:
        logger.error(f"SQLite write error for {function_address} in {file_hash}: {e}")
    finally:
        conn.close()


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
    """Retrieve cached decompilation result from Redis or SQLite.

    Args:
        file_path: Path to the binary file.
        function_address: Target function name or address.
        use_ghidra: Whether Ghidra decompiler was used.

    Returns:
        ToolResult if found in cache, otherwise None.
    """
    # Calculate file SHA256 to invalidate cache if binary gets modified
    file_hash = calculate_file_sha256(file_path)
    if not file_hash:
        return None

    decompiler = "ghidra" if use_ghidra else "radare2"

    # 1. Try Redis first (if enabled)
    client = get_redis_client()
    if client is not None:
        cache_key = f"ghidra:decompile:{file_hash}:{function_address}:{decompiler}"
        try:
            serialized = await client.get(cache_key)
            if serialized:
                result = _deserialize_result(serialized)
                if result:
                    logger.info(f"Redis cache HIT for {function_address} in {file_path}")
                    # Inject a flag indicating this result came from cache
                    if isinstance(result, ToolSuccess):
                        if result.metadata is None:
                            result.metadata = {}
                        result.metadata["cache_hit"] = True
                    return result
        except Exception as e:
            logger.debug(f"Redis get error: {e}. Falling back to SQLite.")

    # 2. Try SQLite
    try:
        db_path = _init_sqlite_db()
        serialized = await asyncio.to_thread(
            _read_from_sqlite, db_path, file_hash, function_address, decompiler
        )
        if serialized:
            result = _deserialize_result(serialized)
            if result:
                logger.info(f"SQLite cache HIT for {function_address} in {file_path}")
                # Inject a flag indicating this result came from cache
                if isinstance(result, ToolSuccess):
                    if result.metadata is None:
                        result.metadata = {}
                    result.metadata["cache_hit"] = True
                return result
    except Exception as e:
        logger.error(f"SQLite get error: {e}")

    return None


async def set_cached_decompile(
    file_path: Path | str,
    function_address: str,
    result: ToolResult,
    use_ghidra: bool = True,
    ttl_seconds: int = 3600,
) -> None:
    """Store decompilation result in SQLite and Redis.

    Args:
        file_path: Path to the binary file.
        function_address: Target function name or address.
        result: The ToolResult to cache.
        use_ghidra: Whether Ghidra decompiler was used.
        ttl_seconds: Time-to-live in seconds for Redis (default: 1 hour).
    """
    # Do not cache failed results
    if not isinstance(result, ToolSuccess):
        return

    file_hash = calculate_file_sha256(file_path)
    if not file_hash:
        return

    decompiler = "ghidra" if use_ghidra else "radare2"
    serialized = _serialize_result(result)
    status = "success"

    # 1. Store in SQLite (Primary persistent local cache)
    try:
        db_path = _init_sqlite_db()
        await asyncio.to_thread(
            _write_to_sqlite,
            db_path,
            file_hash,
            function_address,
            decompiler,
            status,
            serialized,
        )
        logger.debug(f"Cached decompile in SQLite for {function_address} in {file_path}")
    except Exception as e:
        logger.error(f"Failed to cache decompile result in SQLite: {e}")

    # 2. Store in Redis (if enabled)
    client = get_redis_client()
    if client is not None:
        cache_key = f"ghidra:decompile:{file_hash}:{function_address}:{decompiler}"
        try:
            await client.setex(cache_key, ttl_seconds, serialized)
            logger.debug(
                f"Cached decompile in Redis for {function_address} in {file_path} (TTL: {ttl_seconds}s)"
            )
        except Exception as e:
            logger.warning(f"Failed to cache decompile result in Redis: {e}")


async def export_cache_by_hash(file_hash: str) -> dict:
    """Export decompilation cache for a given binary hash.

    Reads from SQLite (as it is the persistent source of truth).
    Returns a dictionary of cache data that can be serialized to JSON.
    """
    exported_data: dict[str, Any] = {
        "file_hash": file_hash,
        "format": "rcpack",
        "version": "1.0",
        "entries": [],
    }
    try:
        db_path = _init_sqlite_db()

        def _read_all():
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT function_address, decompiler, status, data FROM decompilation_cache WHERE file_hash = ?",
                (file_hash,),
            )
            return cursor.fetchall()

        rows = await asyncio.to_thread(_read_all)
        for row in rows:
            func_addr, decompiler, status, data = row
            exported_data["entries"].append(
                {
                    "function_address": func_addr,
                    "decompiler": decompiler,
                    "status": status,
                    "data": data,
                }
            )
    except Exception as e:
        logger.error(f"Failed to export SQLite cache: {e}")

    return exported_data


async def import_cache_data(cache_data: dict) -> int:
    """Import cache data exported via export_cache_by_hash.

    Restores data to SQLite and Redis (if enabled).
    Returns the number of imported entries.
    """
    if cache_data.get("format") != "rcpack":
        raise ValueError("Invalid cache data format")

    file_hash = cache_data.get("file_hash")
    entries = cache_data.get("entries", [])
    if not file_hash or not entries:
        return 0

    imported_count = 0
    client = get_redis_client()

    try:
        db_path = _init_sqlite_db()

        def _write_all():
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            for entry in entries:
                func_addr = entry["function_address"]
                decompiler = entry["decompiler"]
                status = entry["status"]
                data = entry["data"]

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO decompilation_cache (file_hash, function_address, decompiler, status, data, created_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (file_hash, func_addr, decompiler, status, data),
                )
            conn.commit()
            conn.close()

        await asyncio.to_thread(_write_all)

        for entry in entries:
            func_addr = entry["function_address"]
            decompiler = entry["decompiler"]
            data = entry["data"]

            # 2. Import to Redis
            if client is not None:
                cache_key = f"ghidra:decompile:{file_hash}:{func_addr}:{decompiler}"
                await client.setex(cache_key, 3600, data)

            imported_count += 1

    except Exception as e:
        logger.error(f"Failed to import cache data: {e}")

    return imported_count
