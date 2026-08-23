"""
SQLite-based persistence layer for r2 annotations.

Replaces Ghidra's project database (structures, bookmarks, data types) with a
lightweight SQLite file stored at ``R2GHIDRA_DB_PATH`` (default:
``/app/workspace/.r2db``).

The database is keyed on the SHA-256 hash of the binary file, so annotations
survive binary renames and workspace reorganisation.

Available tools (MCP-registered):
    r2_list_structures   — List saved struct definitions for a binary
    r2_get_structure     — Retrieve a single struct by name
    r2_create_structure  — Save a new struct definition
    r2_list_types        — List custom type definitions
    r2_list_bookmarks    — List saved bookmarks / comments
    r2_add_bookmark      — Add an annotated bookmark at an address
    r2_read_memory       — Read raw bytes from a binary at an address
"""

import asyncio
import hashlib
import os
import sqlite3
import time
from pathlib import Path

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import execute_r2_command as _execute_r2_command
from reversecore_mcp.core.result import (
    ToolError,
    ToolResult,
    ToolSuccess,
    failure,
    success,
)
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

_DB_PATH = Path(os.environ.get("R2GHIDRA_DB_PATH", "/app/workspace/.r2db"))

_DDL = """
CREATE TABLE IF NOT EXISTS structures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_hash TEXT NOT NULL,
    name        TEXT NOT NULL,
    fields_json TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(binary_hash, name)
);
CREATE TABLE IF NOT EXISTS bookmarks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_hash TEXT NOT NULL,
    address     TEXT NOT NULL,
    comment     TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT 'note',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(binary_hash, address)
);
CREATE TABLE IF NOT EXISTS types (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_hash TEXT NOT NULL,
    name        TEXT NOT NULL,
    definition  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(binary_hash, name)
);
CREATE TABLE IF NOT EXISTS analysis_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_hash TEXT NOT NULL,
    tool_name   TEXT NOT NULL,
    cache_key   TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL,
    UNIQUE(binary_hash, cache_key)
);
"""


def _get_db_sync() -> sqlite3.Connection:
    """Open (and initialise) the SQLite annotation DB synchronously."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(_DB_PATH))
    db.row_factory = sqlite3.Row
    db.executescript(_DDL)
    db.commit()
    return db


def _sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of *path* (first 64 KB for speed)."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        h.update(fh.read(65536))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# r2_list_structures
# ---------------------------------------------------------------------------


def _list_structures_sync(bh: str, limit: int, offset: int) -> list[dict]:
    with _get_db_sync() as db:
        cursor = db.execute(
            "SELECT name, fields_json, created_at FROM structures "
            "WHERE binary_hash=? ORDER BY name LIMIT ? OFFSET ?",
            (bh, limit, offset),
        )
        rows = cursor.fetchall()
        return [
            {
                "name": row["name"],
                "fields": json.loads(row["fields_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]


@log_execution(tool_name="r2_list_structures")
@track_metrics("r2_list_structures")
@handle_tool_errors
async def r2_list_structures(
    file_path: str,
    offset: int = 0,
    limit: int = 50,
) -> ToolResult:
    """List all saved C struct definitions for a binary."""
    validated = validate_file_path(file_path)
    bh = _sha256(validated)

    structs = await asyncio.to_thread(_list_structures_sync, bh, limit, offset)
    return success({"structures": structs, "count": len(structs)})


# ---------------------------------------------------------------------------
# r2_get_structure
# ---------------------------------------------------------------------------


def _get_structure_sync(bh: str, name: str) -> dict | None:
    with _get_db_sync() as db:
        cursor = db.execute(
            "SELECT name, fields_json, created_at FROM structures WHERE binary_hash=? AND name=?",
            (bh, name),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            "name": row["name"],
            "fields": json.loads(row["fields_json"]),
            "created_at": row["created_at"],
        }


@log_execution(tool_name="r2_get_structure")
@track_metrics("r2_get_structure")
@handle_tool_errors
async def r2_get_structure(
    file_path: str,
    name: str,
) -> ToolResult:
    """Retrieve a single saved struct definition by name."""
    validated = validate_file_path(file_path)
    bh = _sha256(validated)

    struct_data = await asyncio.to_thread(_get_structure_sync, bh, name)
    if struct_data is None:
        return failure("NOT_FOUND", f"Structure '{name}' not found for this binary.")

    return success(struct_data)


# ---------------------------------------------------------------------------
# r2_create_structure
# ---------------------------------------------------------------------------


def _create_structure_sync(bh: str, name: str, fields_json: str) -> None:
    with _get_db_sync() as db:
        db.execute(
            "INSERT INTO structures(binary_hash, name, fields_json) VALUES(?,?,?) "
            "ON CONFLICT(binary_hash, name) DO UPDATE SET fields_json=excluded.fields_json",
            (bh, name, fields_json),
        )
        db.commit()


@log_execution(tool_name="r2_create_structure")
@track_metrics("r2_create_structure")
@handle_tool_errors
async def r2_create_structure(
    file_path: str,
    name: str,
    fields: list[dict],
) -> ToolResult:
    """Save (or replace) a C struct definition in the annotation DB."""
    if not name or not name.isidentifier():
        return failure("VALIDATION_ERROR", "Struct name must be a valid C identifier.")
    if not isinstance(fields, list):
        return failure("VALIDATION_ERROR", "fields must be a list of dicts.")

    validated = validate_file_path(file_path)
    bh = _sha256(validated)
    fields_json = json.dumps(fields)

    await asyncio.to_thread(_create_structure_sync, bh, name, fields_json)
    return success({"created": name, "field_count": len(fields)})


# ---------------------------------------------------------------------------
# r2_list_types
# ---------------------------------------------------------------------------


def _list_types_sync(bh: str, limit: int, offset: int) -> list[dict]:
    with _get_db_sync() as db:
        cursor = db.execute(
            "SELECT name, definition, created_at FROM types "
            "WHERE binary_hash=? ORDER BY name LIMIT ? OFFSET ?",
            (bh, limit, offset),
        )
        rows = cursor.fetchall()
        return [
            {
                "name": row["name"],
                "definition": row["definition"],
                "source": "user",
                "created_at": row["created_at"],
            }
            for row in rows
        ]


@log_execution(tool_name="r2_list_types")
@track_metrics("r2_list_types")
@handle_tool_errors
async def r2_list_types(
    file_path: str,
    offset: int = 0,
    limit: int = 100,
) -> ToolResult:
    """List all custom type definitions saved for a binary."""
    validated = validate_file_path(file_path)
    bh = _sha256(validated)

    db_types = await asyncio.to_thread(_list_types_sync, bh, limit, offset)

    # r2 native types
    r2_output, _ = await _execute_r2_command(
        validated, ["tj"], analysis_level="aaa", max_output_size=1_000_000
    )
    r2_types: list[dict] = []
    try:
        parsed = json.loads(r2_output.strip())
        if isinstance(parsed, list):
            for t in parsed:
                if isinstance(t, dict):
                    r2_types.append(
                        {
                            "name": t.get("type", ""),
                            "definition": t.get("typestr", ""),
                            "source": "r2",
                        }
                    )
    except (json.JSONDecodeError, ValueError):
        pass

    all_types = db_types + r2_types
    return success({"types": all_types, "count": len(all_types)})


# ---------------------------------------------------------------------------
# r2_list_bookmarks
# ---------------------------------------------------------------------------


def _list_bookmarks_sync(bh: str, category: str | None, limit: int, offset: int) -> list[dict]:
    with _get_db_sync() as db:
        if category:
            cursor = db.execute(
                "SELECT address, comment, category, created_at FROM bookmarks "
                "WHERE binary_hash=? AND category=? ORDER BY address LIMIT ? OFFSET ?",
                (bh, category, limit, offset),
            )
        else:
            cursor = db.execute(
                "SELECT address, comment, category, created_at FROM bookmarks "
                "WHERE binary_hash=? ORDER BY address LIMIT ? OFFSET ?",
                (bh, limit, offset),
            )
        rows = cursor.fetchall()
        return [
            {
                "address": row["address"],
                "comment": row["comment"],
                "category": row["category"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]


@log_execution(tool_name="r2_list_bookmarks")
@track_metrics("r2_list_bookmarks")
@handle_tool_errors
async def r2_list_bookmarks(
    file_path: str,
    category: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> ToolResult:
    """List all saved bookmarks / address annotations for a binary."""
    validated = validate_file_path(file_path)
    bh = _sha256(validated)

    bookmarks = await asyncio.to_thread(_list_bookmarks_sync, bh, category, limit, offset)
    return success({"bookmarks": bookmarks, "count": len(bookmarks)})


# ---------------------------------------------------------------------------
# r2_add_bookmark
# ---------------------------------------------------------------------------


def _add_bookmark_sync(bh: str, address: str, comment: str, category: str) -> None:
    with _get_db_sync() as db:
        db.execute(
            "INSERT INTO bookmarks(binary_hash, address, comment, category) VALUES(?,?,?,?) "
            "ON CONFLICT(binary_hash, address) DO UPDATE SET comment=excluded.comment, category=excluded.category",
            (bh, address, comment, category),
        )
        db.commit()


@log_execution(tool_name="r2_add_bookmark")
@track_metrics("r2_add_bookmark")
@handle_tool_errors
async def r2_add_bookmark(
    file_path: str,
    address: str,
    comment: str,
    category: str = "note",
) -> ToolResult:
    """Add (or update) an annotated bookmark at a binary address."""
    from reversecore_mcp.core.exceptions import ValidationError
    from reversecore_mcp.core.validators import validate_address_format

    try:
        validate_address_format(address, "address")
    except ValidationError as exc:
        return failure("VALIDATION_ERROR", str(exc))

    if not comment:
        return failure("VALIDATION_ERROR", "comment must not be empty.")

    validated = validate_file_path(file_path)
    bh = _sha256(validated)

    await asyncio.to_thread(_add_bookmark_sync, bh, address, comment, category)
    return success(
        {
            "address": address,
            "comment": comment,
            "category": category,
            "saved": True,
        }
    )


# ---------------------------------------------------------------------------
# r2_read_memory
# ---------------------------------------------------------------------------


@log_execution(tool_name="r2_read_memory")
@track_metrics("r2_read_memory")
@handle_tool_errors
async def r2_read_memory(
    file_path: str,
    address: str,
    size: int = 64,
) -> ToolResult:
    """Read raw bytes from a binary at a given virtual address."""
    from reversecore_mcp.core.exceptions import ValidationError
    from reversecore_mcp.core.validators import validate_address_format

    try:
        validate_address_format(address, "address")
    except ValidationError as exc:
        return failure("VALIDATION_ERROR", str(exc))

    if not isinstance(size, int) or size < 1 or size > 4096:
        return failure("VALIDATION_ERROR", "size must be between 1 and 4096 bytes.")

    validated = validate_file_path(file_path)

    cmds = [
        f"s {address}",
        f"pxj {size}",  # hex dump as JSON byte array
        f"px {size}",  # human-readable hex dump
    ]
    output, _ = await _execute_r2_command(
        validated, cmds, analysis_level="aa", max_output_size=100_000
    )

    lines = [ln.strip() for ln in output.strip().split("\n") if ln.strip()]
    json_bytes: list[int] = []
    hex_dump = ""

    for line in lines:
        if line.startswith("["):
            try:
                json_bytes = json.loads(line)
                hex_dump = " ".join(f"{b:02x}" for b in json_bytes)
                break
            except (json.JSONDecodeError, ValueError):
                pass
        elif line.startswith("- offset -"):
            hex_dump = line  # fallback: include raw hex dump text

    return success(
        {
            "address": address,
            "size": size,
            "bytes": hex_dump,
            "json_bytes": json_bytes,
        }
    )


# ---------------------------------------------------------------------------
# analysis_cache (ToolResult caching)
# ---------------------------------------------------------------------------


def _get_cached_result_sync(bh: str, cache_key: str) -> dict | None:
    with _get_db_sync() as db:
        cursor = db.execute(
            "SELECT result_json FROM analysis_cache "
            "WHERE binary_hash=? AND cache_key=? AND (expires_at IS NULL OR expires_at > ?)",
            (bh, cache_key, time.time()),
        )
        row = cursor.fetchone()
        if row:
            try:
                return json.loads(row["result_json"])
            except json.JSONDecodeError:
                return None
        return None


def _set_cached_result_sync(
    bh: str, tool_name: str, cache_key: str, result_dict: dict, ttl: int | None = None
) -> None:
    now = time.time()
    expires_at = now + ttl if ttl else None

    with _get_db_sync() as db:
        db.execute(
            """
            INSERT INTO analysis_cache (binary_hash, tool_name, cache_key, result_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(binary_hash, cache_key) DO UPDATE SET
                result_json=excluded.result_json,
                created_at=excluded.created_at,
                expires_at=excluded.expires_at
            """,
            (bh, tool_name, cache_key, json.dumps(result_dict), now, expires_at),
        )


async def get_cached_result(file_path: str, cache_key: str) -> ToolResult | None:
    """Retrieve a cached ToolResult if available and not expired."""
    try:
        bh = await asyncio.to_thread(_sha256, Path(file_path))
        result_dict = await asyncio.to_thread(_get_cached_result_sync, bh, cache_key)
        if result_dict:
            if result_dict.get("status") == "error":
                return ToolError(**result_dict)
            return ToolSuccess(**result_dict)
    except Exception as e:
        logger.warning(f"Cache read error: {e}")
    return None


async def set_cached_result(
    file_path: str,
    tool_name: str,
    cache_key: str,
    result: ToolResult,
    ttl: int | None = None,
) -> None:
    """Save a ToolResult to the cache."""
    try:
        if hasattr(result, "model_dump"):
            result_dict = result.model_dump()
        else:
            result_dict = dict(result)
        bh = await asyncio.to_thread(_sha256, Path(file_path))
        await asyncio.to_thread(_set_cached_result_sync, bh, tool_name, cache_key, result_dict, ttl)
    except Exception as e:
        logger.warning(f"Cache write error: {e}")


async def invalidate_cache(file_path: str) -> int:
    """Invalidate all cache entries for a given file."""

    def _invalidate(bh: str) -> int:
        with _get_db_sync() as db:
            cursor = db.execute("DELETE FROM analysis_cache WHERE binary_hash=?", (bh,))
            return cursor.rowcount

    try:
        bh = await asyncio.to_thread(_sha256, Path(file_path))
        return await asyncio.to_thread(_invalidate, bh)
    except Exception:
        return 0


def purge_expired_cache() -> int:
    """Remove expired cache entries from the database (sync)."""
    try:
        with _get_db_sync() as db:
            cursor = db.execute(
                "DELETE FROM analysis_cache WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (time.time(),),
            )
            return cursor.rowcount
    except Exception:
        return 0
