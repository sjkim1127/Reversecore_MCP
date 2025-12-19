"""
High-performance JSON utilities with orjson fallback.

This module provides a drop-in replacement for the standard json module
with automatic fallback. It uses orjson when available for 3-5x faster
JSON parsing and serialization, falling back to the standard json module
if orjson is not installed.

Performance comparison:
- orjson.loads(): ~3-5x faster than json.loads()
- orjson.dumps(): ~3-5x faster than json.dumps()
- Particularly impactful for large JSON objects and hot paths
"""

import json as _stdlib_json
from typing import Any

try:
    import orjson

    _ORJSON_AVAILABLE = True
    # Expose stdlib JSONDecodeError for consistent error handling
    JSONDecodeError = _stdlib_json.JSONDecodeError

    def loads(s: str | bytes) -> Any:
        """
        Parse JSON with orjson (fast path).
        Wraps orjson.JSONDecodeError ensuring compatibility with stdlib json.
        """
        if isinstance(s, str):
            s = s.encode("utf-8")
        try:
            return orjson.loads(s)
        except orjson.JSONDecodeError as e:
            # Re-raise as stdlib JSONDecodeError for compatibility
            # orjson error message usually contains position info at the end
            raise _stdlib_json.JSONDecodeError(str(e), str(s), 0) from e

    def dumps(
        obj: Any,
        indent: int | None = None,
        ensure_ascii: bool = True,
        default: Any = None,
    ) -> str:
        """
        Serialize object to JSON with orjson (fast path).

        Note: orjson only supports 2-space indentation when indent is provided.
        Any non-None indent value will result in 2-space pretty-printing.
        This differs slightly from stdlib json which respects the exact indent value.

        Note: orjson always outputs UTF-8 (never escapes non-ASCII).
        The ensure_ascii parameter is accepted for API compatibility but ignored.

        Args:
            obj: Python object to serialize
            indent: If provided (any non-None value), pretty-print with 2-space indentation
            ensure_ascii: Ignored (orjson always uses UTF-8). Kept for API compatibility.
            default: Callable to serialize non-serializable objects (passed to stdlib as fallback)

        Returns:
            JSON string
        """
        try:
            if indent is not None:
                # orjson only supports 2-space indentation via OPT_INDENT_2
                # For compatibility, any indent value triggers pretty-printing
                result = orjson.dumps(obj, option=orjson.OPT_INDENT_2)
            else:
                result = orjson.dumps(obj)
            # orjson returns bytes, convert to str for compatibility
            return result.decode("utf-8")
        except TypeError:
            # orjson can't serialize some types, fall back to stdlib with default
            return _stdlib_json.dumps(
                obj, indent=indent, ensure_ascii=ensure_ascii, default=default
            )

except ImportError:
    # Fallback to standard library json
    _ORJSON_AVAILABLE = False
    # Use stdlib JSONDecodeError for compatibility
    JSONDecodeError = _stdlib_json.JSONDecodeError

    def loads(s: str | bytes) -> Any:
        """
        Parse JSON with standard library (fallback).

        Args:
            s: JSON string or bytes to parse

        Returns:
            Parsed Python object
        """
        if isinstance(s, bytes):
            s = s.decode("utf-8")
        return _stdlib_json.loads(s)

    def dumps(
        obj: Any,
        indent: int | None = None,
        ensure_ascii: bool = True,
        default: Any = None,
    ) -> str:
        """
        Serialize object to JSON with standard library (fallback).

        Args:
            obj: Python object to serialize
            indent: If provided, pretty-print with indentation
            ensure_ascii: If True, escape non-ASCII characters
            default: Callable to serialize non-serializable objects

        Returns:
            JSON string
        """
        return _stdlib_json.dumps(obj, indent=indent, ensure_ascii=ensure_ascii, default=default)


def is_orjson_available() -> bool:
    """
    Check if orjson is available.

    Returns:
        True if orjson is installed and being used, False if using fallback
    """
    return _ORJSON_AVAILABLE


# For compatibility, expose the same interface as json module
__all__ = ["loads", "dumps", "is_orjson_available", "JSONDecodeError"]
