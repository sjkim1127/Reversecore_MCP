"""
Radare2 Connection Pool

This module provides a connection pool for managing persistent r2pipe instances.
It helps reduce the overhead of spawning new radare2 processes for every command.

Features:
- Configurable pool size via REVERSECORE_R2_POOL_SIZE
- Configurable timeout via REVERSECORE_R2_POOL_TIMEOUT
- LRU eviction policy to limit memory usage
- Thread-safe and async-safe execution
- Automatic reconnection on failure
- Health checking for stale connections
"""

import asyncio
import threading
import time
from collections import OrderedDict
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from typing import Any

try:
    import r2pipe
except ImportError:
    r2pipe = None

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class R2PoolTimeout(Exception):
    """Raised when connection acquisition times out."""

    pass


class R2ConnectionPool:
    """
    Manages a pool of persistent r2pipe connections.

    Features:
    - Configurable pool size (default from config or 10)
    - Configurable acquisition timeout
    - LRU eviction policy to limit memory usage
    - Thread-safe and async-safe execution
    - Automatic reconnection on failure
    - Health checking for stale connections

    Configuration:
        Pool size and timeout can be configured via environment variables:
        - REVERSECORE_R2_POOL_SIZE: Maximum number of connections (default: 3)
        - REVERSECORE_R2_POOL_TIMEOUT: Acquisition timeout in seconds (default: 30)
    """

    def __init__(
        self,
        max_connections: int | None = None,
        acquisition_timeout: int | None = None,
        health_check_interval: int = 60,
    ):
        """Initialize the connection pool.

        Args:
            max_connections: Maximum number of connections to maintain.
                           If None, uses config value or default of 10.
            acquisition_timeout: Timeout in seconds for acquiring a connection.
                               If None, uses config value or default of 30.
            health_check_interval: Interval in seconds for health checks.
        """
        # Lazy-load config to avoid circular imports
        self._max_connections = max_connections
        self._acquisition_timeout = acquisition_timeout
        self._health_check_interval = health_check_interval
        self._config_loaded = False

        self._pool: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.RLock()
        self._async_lock: asyncio.Lock | None = None
        self._async_lock_init_lock = threading.Lock()
        self._last_access: dict[str, float] = {}
        self._analyzed_files: set[str] = set()
        self._last_health_check: dict[str, float] = {}

        # Semaphore for limiting concurrent connections
        self._connection_semaphore: threading.Semaphore | None = None
        self._async_semaphore: asyncio.Semaphore | None = None

        # Statistics
        self._stats = {
            "connections_created": 0,
            "connections_evicted": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "reconnections": 0,
        }

    def _load_config(self) -> None:
        """Load configuration values lazily."""
        if self._config_loaded:
            return

        try:
            from reversecore_mcp.core.config import get_config

            config = get_config()
            if self._max_connections is None:
                self._max_connections = config.r2_pool_size
            if self._acquisition_timeout is None:
                self._acquisition_timeout = config.r2_pool_timeout
        except Exception:
            # Fallback to defaults if config is not available
            if self._max_connections is None:
                self._max_connections = 10
            if self._acquisition_timeout is None:
                self._acquisition_timeout = 30

        self._config_loaded = True

    @property
    def max_connections(self) -> int:
        """Get maximum connections, loading from config if needed."""
        self._load_config()
        return self._max_connections or 10

    @property
    def acquisition_timeout(self) -> int:
        """Get acquisition timeout, loading from config if needed."""
        self._load_config()
        return self._acquisition_timeout or 30

    def _get_connection_semaphore(self) -> threading.Semaphore:
        """Get or create a connection semaphore for rate limiting."""
        if self._connection_semaphore is None:
            self._connection_semaphore = threading.Semaphore(self.max_connections)
        return self._connection_semaphore

    def _get_async_semaphore(self) -> asyncio.Semaphore:
        """Get or create an async semaphore for rate limiting."""
        if self._async_semaphore is None:
            self._async_semaphore = asyncio.Semaphore(self.max_connections)
        return self._async_semaphore

    def _get_async_lock(self) -> asyncio.Lock:
        """Get or create an async lock for thread-safe async operations.

        The lock is lazily initialized to ensure it's created in the correct
        event loop context. Uses double-checked locking pattern for thread-safety.
        """
        if self._async_lock is not None:
            return self._async_lock

        with self._async_lock_init_lock:
            if self._async_lock is None:
                self._async_lock = asyncio.Lock()
            return self._async_lock

    def _is_connection_healthy(self, file_path: str, r2: Any) -> bool:
        """Check if a connection is still healthy."""
        try:
            # Quick health check: try to get current seek position
            result = r2.cmd("s")
            return result is not None
        except Exception:
            return False

    def _maybe_health_check(self, file_path: str, r2: Any) -> bool:
        """Perform health check if enough time has passed."""
        now = time.time()
        last_check = self._last_health_check.get(file_path, 0)

        if now - last_check > self._health_check_interval:
            self._last_health_check[file_path] = now
            return self._is_connection_healthy(file_path, r2)
        return True  # Assume healthy if recently checked

    def get_connection(self, file_path: str) -> Any:
        """Get or create an r2pipe connection for the given file."""
        if r2pipe is None:
            raise ImportError("r2pipe is not installed")

        with self._lock:
            self._last_access[file_path] = time.time()

            if file_path in self._pool:
                r2 = self._pool[file_path]

                # Health check
                if not self._maybe_health_check(file_path, r2):
                    logger.warning(f"Stale connection for {file_path}, reconnecting")
                    self._remove_connection_unsafe(file_path)
                else:
                    self._pool.move_to_end(file_path)
                    self._stats["cache_hits"] += 1
                    return r2

            self._stats["cache_misses"] += 1

            # Evict if full
            while len(self._pool) >= self.max_connections:
                self._evict_oldest_connection()

            # Create new connection
            logger.info(f"Opening new r2 connection for {file_path}")
            try:
                r2 = r2pipe.open(file_path, flags=["-2"])
                self._pool[file_path] = r2
                self._last_health_check[file_path] = time.time()
                self._stats["connections_created"] += 1
                return r2
            except Exception as e:
                logger.error(f"Failed to open r2 connection for {file_path}: {e}")
                raise

    def _cleanup_connection_state(self, file_path: str) -> None:
        """Remove auxiliary state for a connection (caller must hold lock)."""
        self._last_access.pop(file_path, None)
        self._last_health_check.pop(file_path, None)
        self._analyzed_files.discard(file_path)

    def _evict_oldest_connection(self) -> None:
        """Evict the least-recently-used connection (caller must hold lock)."""
        oldest_file, oldest_r2 = self._pool.popitem(last=False)
        logger.debug(f"Evicting r2 connection for {oldest_file}")
        self._stats["connections_evicted"] += 1
        try:
            oldest_r2.quit()
        except Exception as e:
            logger.warning(f"Error closing r2 connection: {e}")
        self._cleanup_connection_state(oldest_file)

    def _remove_connection_unsafe(self, file_path: str) -> None:
        """Remove a connection without locking (caller must hold lock)."""
        if file_path in self._pool:
            try:
                self._pool[file_path].quit()
            except Exception as e:
                logger.debug("r2 quit on remove: %s", e)
            del self._pool[file_path]
        self._cleanup_connection_state(file_path)

    def execute(self, file_path: str, command: str) -> str:
        """Execute a command on the r2 connection for the given file."""
        with self._lock:
            try:
                r2 = self.get_connection(file_path)
                return r2.cmd(command)
            except Exception as e:
                logger.warning(f"r2 command failed, retrying connection: {e}")
                self._remove_connection_unsafe(file_path)
                self._stats["reconnections"] += 1

                try:
                    r2 = self.get_connection(file_path)
                    return r2.cmd(command)
                except Exception as retry_error:
                    logger.error(f"Retry failed: {retry_error}")
                    raise

    async def execute_async(self, file_path: str, command: str) -> str:
        """Execute a command asynchronously with proper async lock."""
        async with self._get_async_lock():
            return await asyncio.to_thread(self._execute_unsafe, file_path, command)

    def _execute_unsafe(self, file_path: str, command: str) -> str:
        """Execute with thread lock for safe asyncio.to_thread usage.
        
        Note: Despite the name 'unsafe', this method now acquires self._lock
        to ensure thread-safety when called from asyncio.to_thread().
        The async lock in execute_async() serializes async callers,
        while this thread lock protects against concurrent sync callers.
        """
        with self._lock:  # Thread lock for safe pool access
            try:
                r2 = self._get_connection_unsafe(file_path)
                return r2.cmd(command)
            except Exception as e:
                logger.warning(f"r2 command failed, retrying connection: {e}")
                self._remove_connection_unsafe(file_path)
                self._stats["reconnections"] += 1

                try:
                    r2 = self._get_connection_unsafe(file_path)
                    return r2.cmd(command)
                except Exception as retry_error:
                    logger.error(f"Retry failed: {retry_error}")
                    raise

    def _get_connection_unsafe(self, file_path: str) -> Any:
        """Get or create connection without locking (caller must hold lock)."""
        if r2pipe is None:
            raise ImportError("r2pipe is not installed")

        self._last_access[file_path] = time.time()

        if file_path in self._pool:
            r2 = self._pool[file_path]

            if not self._maybe_health_check(file_path, r2):
                logger.warning(f"Stale connection for {file_path}, reconnecting")
                self._remove_connection_unsafe(file_path)
            else:
                self._pool.move_to_end(file_path)
                self._stats["cache_hits"] += 1
                return r2

        self._stats["cache_misses"] += 1

        # Evict if full
        while len(self._pool) >= self.max_connections:
            self._evict_oldest_connection()

        # Create new connection
        logger.info(f"Opening new r2 connection for {file_path}")
        try:
            r2 = r2pipe.open(file_path, flags=["-2"])
            self._pool[file_path] = r2
            self._last_health_check[file_path] = time.time()
            self._stats["connections_created"] += 1
            return r2
        except Exception as e:
            logger.error(f"Failed to open r2 connection for {file_path}: {e}")
            raise

    @asynccontextmanager
    async def async_session(self, file_path: str) -> AsyncGenerator[Any, None]:
        """Async context manager for r2 connection.

        Usage:
            async with r2_pool.async_session(path) as r2:
                result = r2.cmd('aaa')
        """
        async with self._get_async_lock():
            r2 = await asyncio.to_thread(self._get_connection_unsafe, file_path)
            try:
                yield r2
            except Exception as e:
                logger.warning(f"Error in async session: {e}")
                # Invalidate connection on error
                if file_path in self._pool:
                    del self._pool[file_path]
                raise

    @contextmanager
    def sync_session(self, file_path: str) -> Generator[Any, None, None]:
        """Sync context manager for r2 connection.

        Usage:
            with r2_pool.sync_session(path) as r2:
                result = r2.cmd('aaa')
        """
        with self._lock:
            r2 = self._get_connection_unsafe(file_path)
            try:
                yield r2
            except Exception as e:
                logger.warning(f"Error in sync session: {e}")
                self._remove_connection_unsafe(file_path)
                raise

    def close_all(self):
        """Close all connections in the pool."""
        with self._lock:
            for _file_path, r2 in self._pool.items():
                try:
                    r2.quit()
                except Exception as e:
                    logger.debug("r2 quit on close_all: %s", e)
            self._pool.clear()
            self._last_access.clear()
            self._last_health_check.clear()
            self._analyzed_files.clear()

    def is_analyzed(self, file_path: str) -> bool:
        """Check if the file has been analyzed."""
        with self._lock:
            return file_path in self._analyzed_files

    def mark_analyzed(self, file_path: str):
        """Mark the file as analyzed."""
        with self._lock:
            if file_path in self._pool:
                self._analyzed_files.add(file_path)

    def get_stats(self) -> dict[str, Any]:
        """Get pool statistics."""
        with self._lock:
            return {
                **self._stats,
                "current_connections": len(self._pool),
                "max_connections": self.max_connections,
                "analyzed_files": len(self._analyzed_files),
            }


# Global instance (for backward compatibility)
# New code should use: from reversecore_mcp.core.container import get_r2_pool
r2_pool = R2ConnectionPool()
