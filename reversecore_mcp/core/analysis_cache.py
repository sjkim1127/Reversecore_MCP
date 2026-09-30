"""Redis-based caching for binary analysis results, specifically Ghidra decompilation.

This module provides high-performance result caching based on the SHA256 of the binary file,
avoiding repetitive decompilation of unmodified binaries.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolError, ToolResult, ToolSuccess
from reversecore_mcp.core.validators import validate_address_format

logger = get_logger(__name__)

# Singleton/global state for SQLite initialization
_sqlite_db_path: Path | None = None
_sqlite_initialized: bool = False
_sqlite_lock = threading.Lock()


def _get_sqlite_conn(db_path: Path) -> sqlite3.Connection:
    """Create a SQLite connection with timeout, busy handler, and WAL mode."""
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def _init_sqlite_db() -> Path:
    """Initialize the SQLite database and create the table if it does not exist."""
    global _sqlite_db_path, _sqlite_initialized
    config = get_config()
    current_db_path = config.workspace / ".reversecore_cache.db"

    with _sqlite_lock:
        # If the workspace path changed (e.g., in a test environment), reset initialization
        if _sqlite_db_path != current_db_path:
            _sqlite_db_path = current_db_path
            _sqlite_initialized = False

        # Ensure parent directory exists
        _sqlite_db_path.parent.mkdir(parents=True, exist_ok=True)

        if not _sqlite_initialized:
            try:
                conn = _get_sqlite_conn(_sqlite_db_path)
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
                            provenance TEXT NOT NULL DEFAULT 'legacy_unverified',
                            PRIMARY KEY (file_hash, function_address, decompiler)
                        )
                    """)
                    columns = {
                        row[1] for row in cursor.execute("PRAGMA table_info(decompilation_cache)")
                    }
                    if "provenance" not in columns:
                        cursor.execute(
                            "ALTER TABLE decompilation_cache ADD COLUMN provenance "
                            "TEXT NOT NULL DEFAULT 'legacy_unverified'"
                        )
                    conn.commit()
                    _sqlite_initialized = True
                    logger.info(
                        f"SQLite caching database initialized at {_sqlite_db_path} (WAL enabled)"
                    )
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Failed to initialize SQLite cache database: {e}")

    return _sqlite_db_path


def _read_from_sqlite(
    db_path: Path, file_hash: str, function_address: str, decompiler: str
) -> tuple[str, str] | None:
    """Read serialized data from SQLite database."""
    try:
        conn = _get_sqlite_conn(db_path)
    except Exception as e:
        logger.error(f"Failed to open SQLite database: {e}")
        return None

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT data, provenance FROM decompilation_cache WHERE file_hash = ? AND function_address = ? AND decompiler = ?",
            (file_hash, function_address, decompiler),
        )
        row = cursor.fetchone()
        if row and isinstance(row[0], str):
            provenance = row[1] if isinstance(row[1], str) else "legacy_unverified"
            return row[0], provenance
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
    provenance: str = "local",
) -> None:
    """Write serialized data to SQLite database."""
    try:
        conn = _get_sqlite_conn(db_path)
    except Exception as e:
        logger.error(f"Failed to open SQLite database: {e}")
        return

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO decompilation_cache (file_hash, function_address, decompiler, status, data, created_at, provenance)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (file_hash, function_address, decompiler, status, data, provenance),
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


def _stamp_serialized_provenance(
    serialized: str, provenance: str, target_hash_verified: bool | None = None
) -> str:
    """Set authoritative cache provenance in serialized successful results."""
    try:
        data = json.loads(serialized)
    except Exception:
        return serialized
    if not isinstance(data, dict) or data.get("status") != "success":
        return serialized

    metadata = data.get("metadata")
    metadata = dict(metadata) if isinstance(metadata, dict) else {}
    metadata["cache_provenance"] = provenance
    if target_hash_verified is not None:
        metadata["cache_target_hash_verified"] = target_hash_verified
    elif provenance == "legacy_unverified":
        metadata["cache_target_hash_verified"] = False
    data["metadata"] = metadata
    return json.dumps(data)


def _apply_cache_provenance(result: ToolResult, provenance: str) -> ToolResult:
    """Override serialized metadata with the trusted cache-row provenance."""
    if not isinstance(result, ToolSuccess):
        return result
    if provenance not in {"local", "external_rcpack", "legacy_unverified"}:
        provenance = "legacy_unverified"

    metadata = dict(result.metadata or {})
    for reserved_key in ("data", "pagination", "hints"):
        metadata.pop(reserved_key, None)
    metadata["cache_provenance"] = provenance
    if provenance == "legacy_unverified":
        metadata["cache_target_hash_verified"] = False
    result.metadata = metadata
    return result


def _is_valid_decompilation_data(data: Any, decompiler: str, function_address: str) -> bool:
    """Check a cache payload against the shape consumed by its analysis tool."""
    if decompiler == "ghidra":
        if isinstance(data, str):
            return True
        if not isinstance(data, dict):
            return False
        pseudo_c_fields = ("full_pseudo_c", "pseudo_c")
        if not any(field in data for field in pseudo_c_fields):
            return False
        if any(
            data[field] is not None and not isinstance(data[field], str)
            for field in pseudo_c_fields
            if field in data
        ):
            return False
        if not any(isinstance(data.get(field), str) for field in pseudo_c_fields):
            return False
        return "function" not in data or data.get("function") == function_address

    if decompiler == "radare2":
        if not isinstance(data, dict):
            return False
        structures = data.get("structures")
        field_count = data.get("field_count")
        return (
            data.get("function") == function_address
            and isinstance(structures, list)
            and all(isinstance(item, dict) for item in structures)
            and isinstance(field_count, int)
            and not isinstance(field_count, bool)
            and field_count == len(structures)
        )

    return False


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
        cache_key = f"ghidra:decompile:v2:{file_hash}:{function_address}:{decompiler}"
        try:
            serialized = await client.get(cache_key)
            if serialized:
                result = _deserialize_result(serialized)
                if result and (
                    not isinstance(result, ToolSuccess)
                    or not _is_valid_decompilation_data(result.data, decompiler, function_address)
                ):
                    logger.warning("Ignoring malformed Redis cache entry for %s", function_address)
                    try:
                        await client.delete(cache_key)
                    except Exception:
                        pass
                    result = None
                if result:
                    logger.info(f"Redis cache HIT for {function_address} in {file_path}")
                    provenance = (
                        result.metadata.get("cache_provenance")
                        if isinstance(result, ToolSuccess) and result.metadata
                        else "legacy_unverified"
                    )
                    if not isinstance(provenance, str):
                        provenance = "legacy_unverified"
                    result = _apply_cache_provenance(result, provenance)
                    if isinstance(result, ToolSuccess):
                        metadata = result.metadata or {}
                        metadata["cache_hit"] = True
                        result.metadata = metadata
                    return result
        except Exception as e:
            logger.debug(f"Redis get error: {e}. Falling back to SQLite.")

    # 2. Try SQLite
    try:
        db_path = _init_sqlite_db()
        cached_row = await asyncio.to_thread(
            _read_from_sqlite, db_path, file_hash, function_address, decompiler
        )
        if cached_row:
            serialized, provenance = cached_row
            result = _deserialize_result(serialized)
            if result and (
                not isinstance(result, ToolSuccess)
                or not _is_valid_decompilation_data(result.data, decompiler, function_address)
            ):
                logger.warning("Ignoring malformed SQLite cache entry for %s", function_address)
                result = None
            if result:
                logger.info(f"SQLite cache HIT for {function_address} in {file_path}")
                result = _apply_cache_provenance(result, provenance)
                if isinstance(result, ToolSuccess):
                    metadata = result.metadata or {}
                    metadata["cache_hit"] = True
                    result.metadata = metadata
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
    serialized = _stamp_serialized_provenance(_serialize_result(result), "local")
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
            "local",
        )
        logger.debug(f"Cached decompile in SQLite for {function_address} in {file_path}")
    except Exception as e:
        logger.error(f"Failed to cache decompile result in SQLite: {e}")

    # 2. Store in Redis (if enabled)
    client = get_redis_client()
    if client is not None:
        cache_key = f"ghidra:decompile:v2:{file_hash}:{function_address}:{decompiler}"
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

        def _read_all() -> list[tuple]:
            conn = _get_sqlite_conn(db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT function_address, decompiler, status, data, provenance "
                "FROM decompilation_cache WHERE file_hash = ?",
                (file_hash,),
            )
            return cursor.fetchall()

        rows = await asyncio.to_thread(_read_all)
        for row in rows:
            func_addr, decompiler, status, data, provenance = row
            data = _stamp_serialized_provenance(
                data,
                provenance if isinstance(provenance, str) else "legacy_unverified",
            )
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


async def import_cache_data(
    cache_data: dict[str, Any], target_file: Path | str | None = None
) -> int:
    """Import cache data exported via export_cache_by_hash.

    Restores validated data to SQLite and Redis (if enabled). Imported results
    are always marked as external in their serialized ToolSuccess metadata. If
    target_file is supplied, its SHA256 must match the pack's declared hash.

    Args:
        cache_data: Parsed rcpack object.
        target_file: Optional local binary to verify against the pack hash.

    Returns the number of imported entries.

    Raises:
        ValueError: If the pack, an entry, a serialized result, or an optional
            target hash is invalid.
    """
    if not isinstance(cache_data, dict):
        raise ValueError("Cache data must be a JSON object")
    if cache_data.get("format") != "rcpack":
        raise ValueError("Invalid cache data format")

    file_hash = cache_data.get("file_hash")
    entries = cache_data.get("entries", [])
    if isinstance(entries, list) and not entries:
        return 0
    if cache_data.get("version") != "1.0":
        raise ValueError("Unsupported rcpack version")
    if not isinstance(file_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", file_hash):
        raise ValueError("rcpack file_hash must be a lowercase SHA-256 digest")
    if not isinstance(entries, list):
        raise ValueError("rcpack entries must be a list")

    target_hash_verified = False
    if target_file is not None:
        target_hash = calculate_file_sha256(target_file)
        if not target_hash or target_hash != file_hash:
            raise ValueError("rcpack file_hash does not match the supplied target file")
        target_hash_verified = True

    normalized_entries: list[tuple[str, str, str]] = []
    seen_keys: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"rcpack entry {index} must be an object")

        function_address = entry.get("function_address")
        decompiler = entry.get("decompiler")
        status = entry.get("status")
        serialized = entry.get("data")
        if not isinstance(function_address, str) or not function_address:
            raise ValueError(f"rcpack entry {index} has an invalid function_address")
        try:
            validate_address_format(function_address, "function_address")
        except Exception as exc:
            raise ValueError(f"rcpack entry {index} has an invalid function_address") from exc
        if not isinstance(decompiler, str) or decompiler not in {"ghidra", "radare2"}:
            raise ValueError(f"rcpack entry {index} has an unsupported decompiler")
        if status != "success":
            raise ValueError(f"rcpack entry {index} has an unsupported status")
        if not isinstance(serialized, str):
            raise ValueError(f"rcpack entry {index} data must be a serialized ToolSuccess")

        try:
            result_data = json.loads(serialized)
        except Exception as exc:
            raise ValueError(f"rcpack entry {index} data is not valid JSON") from exc
        if (
            not isinstance(result_data, dict)
            or result_data.get("status") != "success"
            or "data" not in result_data
            or not isinstance(result_data.get("data"), (str, dict))
        ):
            raise ValueError(f"rcpack entry {index} data is not a supported ToolSuccess")
        decompilation_data = result_data["data"]
        if not _is_valid_decompilation_data(decompilation_data, decompiler, function_address):
            raise ValueError(f"rcpack entry {index} has invalid {decompiler} decompilation data")
        metadata = result_data.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError(f"rcpack entry {index} has invalid ToolSuccess metadata")
        if {"data", "pagination", "hints"}.intersection(metadata or {}):
            raise ValueError(f"rcpack entry {index} metadata contains reserved ToolSuccess keys")

        entry_key = (function_address, decompiler)
        if entry_key in seen_keys:
            raise ValueError(f"rcpack contains duplicate entries for {function_address}")
        seen_keys.add(entry_key)

        imported_metadata = dict(metadata or {})
        imported_metadata["cache_provenance"] = "external_rcpack"
        imported_metadata["cache_target_hash_verified"] = target_hash_verified
        result_data["metadata"] = imported_metadata
        normalized_entries.append((function_address, decompiler, json.dumps(result_data)))

    imported_count = 0
    client = get_redis_client()

    try:
        db_path = _init_sqlite_db()

        def _write_all() -> None:
            conn = _get_sqlite_conn(db_path)
            cursor = conn.cursor()
            for func_addr, decompiler, data in normalized_entries:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO decompilation_cache (file_hash, function_address, decompiler, status, data, created_at, provenance)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'external_rcpack')
                    """,
                    (file_hash, func_addr, decompiler, "success", data),
                )
            conn.commit()
            conn.close()

        await asyncio.to_thread(_write_all)

        for func_addr, decompiler, data in normalized_entries:
            # 2. Import to Redis
            if client is not None:
                cache_key = f"ghidra:decompile:v2:{file_hash}:{func_addr}:{decompiler}"
                await client.setex(cache_key, 3600, data)

            imported_count += 1

    except Exception as e:
        logger.error(f"Failed to import cache data: {e}")

    return imported_count
