"""
Radare2 Connection Pool

This module provides a connection pool for managing persistent r2pipe instances.
It helps reduce the overhead of spawning new radare2 processes for every command.
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


class R2ConnectionPool:
    """
    Manages a pool of persistent r2pipe connections.

    Features:
    - LRU eviction policy to limit memory usage
    - Thread-safe execution
    - Automatic reconnection on failure
    """

    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self._pool: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.RLock()
        self._async_lock: asyncio.Lock | None = None  # Lazy-initialized async lock
        self._async_lock_init_lock = threading.Lock()  # Protects async lock initialization
        self._last_access: dict[str, float] = {}
        self._analyzed_files = set()  # Track files that have been analyzed (aaa)

    def _get_async_lock(self) -> asyncio.Lock:
        """Get or create an async lock for thread-safe async operations.

        The lock is lazily initialized to ensure it's created in the correct
        event loop context. Uses double-checked locking pattern for thread-safety.
        """
        # Fast path: if already initialized, return it directly
        if self._async_lock is not None:
            return self._async_lock

        # Slow path: acquire thread lock to safely initialize
        with self._async_lock_init_lock:
            # Double-check after acquiring lock
            if self._async_lock is None:
                self._async_lock = asyncio.Lock()
            return self._async_lock

    def get_connection(self, file_path: str) -> Any:
        """Get or create an r2pipe connection for the given file."""
        if r2pipe is None:
            raise ImportError("r2pipe is not installed")

        with self._lock:
            # Update access time
            self._last_access[file_path] = time.time()

            if file_path in self._pool:
                # Move to end (most recently used)
                self._pool.move_to_end(file_path)
                return self._pool[file_path]

            # Evict if full
            if len(self._pool) >= self.max_connections:
                oldest_file, oldest_r2 = self._pool.popitem(last=False)
                logger.debug(f"Evicting r2 connection for {oldest_file}")
                try:
                    oldest_r2.quit()
                except Exception as e:
                    logger.warning(f"Error closing r2 connection: {e}")
                if oldest_file in self._last_access:
                    del self._last_access[oldest_file]
                if oldest_file in self._analyzed_files:
                    self._analyzed_files.discard(oldest_file)

            # Create new connection
            logger.info(f"Opening new r2 connection for {file_path}")
            try:
                # Open with -2 to disable stderr (cleaner output)
                r2 = r2pipe.open(file_path, flags=["-2"])
                self._pool[file_path] = r2
                return r2
            except Exception as e:
                logger.error(f"Failed to open r2 connection for {file_path}: {e}")
                raise

    def execute(self, file_path: str, command: str) -> str:
        """Execute a command on the r2 connection for the given file."""
        with self._lock:
            try:
                r2 = self.get_connection(file_path)
                return r2.cmd(command)
            except Exception as e:
                # If execution fails, try to reconnect once
                logger.warning(f"r2 command failed, retrying connection: {e}")
                if file_path in self._pool:
                    del self._pool[file_path]
                if file_path in self._analyzed_files:
                    self._analyzed_files.discard(file_path)

                try:
                    r2 = self.get_connection(file_path)
                    return r2.cmd(command)
                except Exception as retry_error:
                    logger.error(f"Retry failed: {retry_error}")
                    raise

    async def execute_async(self, file_path: str, command: str) -> str:
        """Execute a command asynchronously with proper async lock."""
        async with self._get_async_lock():
            # Run the blocking r2 operation in a thread pool
            return await asyncio.to_thread(self._execute_unsafe, file_path, command)

    def _execute_unsafe(self, file_path: str, command: str) -> str:
        """Execute without acquiring lock (caller must hold lock)."""
        try:
            r2 = self._get_connection_unsafe(file_path)
            return r2.cmd(command)
        except Exception as e:
            # If execution fails, try to reconnect once
            logger.warning(f"r2 command failed, retrying connection: {e}")
            if file_path in self._pool:
                del self._pool[file_path]
            if file_path in self._analyzed_files:
                self._analyzed_files.discard(file_path)

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

        # Update access time
        self._last_access[file_path] = time.time()

        if file_path in self._pool:
            # Move to end (most recently used)
            self._pool.move_to_end(file_path)
            return self._pool[file_path]

        # Evict if full
        if len(self._pool) >= self.max_connections:
            oldest_file, oldest_r2 = self._pool.popitem(last=False)
            logger.debug(f"Evicting r2 connection for {oldest_file}")
            try:
                oldest_r2.quit()
            except Exception as e:
                logger.warning(f"Error closing r2 connection: {e}")
            if oldest_file in self._last_access:
                del self._last_access[oldest_file]
            if oldest_file in self._analyzed_files:
                self._analyzed_files.discard(oldest_file)

        # Create new connection
        logger.info(f"Opening new r2 connection for {file_path}")
        try:
            r2 = r2pipe.open(file_path, flags=["-2"])
            self._pool[file_path] = r2
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
                # Invalidate connection on error
                if file_path in self._pool:
                    del self._pool[file_path]
                raise

    def close_all(self):
        """Close all connections in the pool."""
        with self._lock:
            for _file_path, r2 in self._pool.items():
                try:
                    r2.quit()
                except Exception:
                    pass
            self._pool.clear()
            self._last_access.clear()
            self._analyzed_files.clear()

    def is_analyzed(self, file_path: str) -> bool:
        """Check if the file has been analyzed."""
        with self._lock:
            # OPTIMIZATION: Single check instead of two separate dict lookups
            return file_path in self._analyzed_files

    def mark_analyzed(self, file_path: str):
        """Mark the file as analyzed."""
        with self._lock:
            if file_path in self._pool:
                self._analyzed_files.add(file_path)


# Global instance (for backward compatibility)
# New code should use: from reversecore_mcp.core.container import get_r2_pool
r2_pool = R2ConnectionPool()
