"""
Radare2 Connection Pool

This module provides a connection pool for managing persistent r2pipe instances.
It helps reduce the overhead of spawning new radare2 processes for every command.
"""

import asyncio
import threading
import time
from collections import OrderedDict
from typing import Dict, Any

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
        self._last_access: Dict[str, float] = {}
        self._analyzed_files = set()  # Track files that have been analyzed (aaa)

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
        """Execute a command asynchronously (runs in thread pool)."""
        return await asyncio.to_thread(self.execute, file_path, command)

    def close_all(self):
        """Close all connections in the pool."""
        with self._lock:
            for file_path, r2 in self._pool.items():
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


# Global instance
r2_pool = R2ConnectionPool()
