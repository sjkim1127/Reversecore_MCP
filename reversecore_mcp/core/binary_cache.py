"""
Binary Metadata Cache

This module provides caching for binary analysis results.
It prevents redundant analysis of the same files.
"""

import time
from pathlib import Path
from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import metrics_collector

logger = get_logger(__name__)

# Configuration constants
DEFAULT_CACHE_TTL_SECONDS = 60  # Default time-to-live for cache validation


class BinaryMetadataCache:
    """
    Caches metadata for analyzed binaries.

    Keyed by file path and modification time (or hash).

    Performance optimizations:
    - TTL-based validation to reduce stat() calls
    - Cached mtime stored with last check time
    - Configurable cache lifetime (default: 60 seconds)
    """

    def __init__(self, ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS):
        self._cache: dict[str, Any] = {}
        # Store (mtime, last_check_time) tuple to reduce stat() calls
        self._file_timestamps: dict[str, tuple[float, float]] = {}
        self._ttl_seconds = ttl_seconds

    def _get_cache_key(self, file_path: str) -> str:
        """Generate a cache key based on file path."""
        return str(Path(file_path).absolute())

    def _is_valid(self, file_path: str) -> bool:
        """
        Check if cache entry is valid (file hasn't changed).

        Uses TTL-based checking to avoid excessive stat() calls:
        - If checked within TTL window, assume valid (fast path)
        - Otherwise, verify mtime hasn't changed (slow path)
        """
        key = self._get_cache_key(file_path)
        if key not in self._cache:
            return False

        if key not in self._file_timestamps:
            return False

        cached_mtime, last_check_time = self._file_timestamps[key]
        current_time = time.time()

        # Fast path: If within TTL window, trust the cache without stat()
        # Using < instead of <= for strict TTL boundary to avoid edge case stat() calls
        if current_time - last_check_time < self._ttl_seconds:
            return True

        # Slow path: TTL expired, need to check file modification time
        try:
            actual_mtime = Path(file_path).stat().st_mtime
            is_valid = cached_mtime == actual_mtime

            if is_valid:
                # Update last check time to reset TTL window
                self._file_timestamps[key] = (cached_mtime, current_time)
            else:
                # File changed, invalidate cache
                if key in self._cache:
                    del self._cache[key]
                if key in self._file_timestamps:
                    del self._file_timestamps[key]

            return is_valid
        except FileNotFoundError:
            # File deleted, invalidate cache
            if key in self._cache:
                del self._cache[key]
            if key in self._file_timestamps:
                del self._file_timestamps[key]
            return False

    def get(self, file_path: str, key: str) -> Any | None:
        """Get a specific metadata item for a file."""
        cache_key = self._get_cache_key(file_path)
        if self._is_valid(file_path):
            val = self._cache[cache_key].get(key)
            if val is not None:
                metrics_collector.record_cache_hit("binary_cache")
                return val

        metrics_collector.record_cache_miss("binary_cache")
        return None

    def set(self, file_path: str, key: str, value: Any):
        """Set a specific metadata item for a file."""
        cache_key = self._get_cache_key(file_path)

        # Initialize if needed
        if cache_key not in self._cache:
            self._cache[cache_key] = {}

        # Update timestamp with current time as last check
        try:
            mtime = Path(file_path).stat().st_mtime
            self._file_timestamps[cache_key] = (mtime, time.time())
        except FileNotFoundError:
            # For memory/stream analysis or temp files that no longer exist,
            # use current time as mtime to enable caching
            # Without this, cache always misses because _is_valid returns False
            current_time = time.time()
            self._file_timestamps[cache_key] = (current_time, current_time)

        self._cache[cache_key][key] = value
        logger.debug(f"Cached {key} for {file_path}")

    def clear(self, file_path: str = None):
        """Clear cache for a specific file or all files."""
        if file_path:
            key = self._get_cache_key(file_path)
            if key in self._cache:
                del self._cache[key]
            if key in self._file_timestamps:
                del self._file_timestamps[key]
        else:
            self._cache.clear()
            self._file_timestamps.clear()


# Global instance with default TTL
binary_cache = BinaryMetadataCache(ttl_seconds=DEFAULT_CACHE_TTL_SECONDS)
