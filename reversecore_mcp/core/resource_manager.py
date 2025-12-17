"""
Resource Manager for Reversecore_MCP.

This module handles periodic cleanup of temporary files and stale cache entries
to prevent resource exhaustion over time.
"""

import asyncio
import time

import os
from contextlib import suppress

from reversecore_mcp.core import config
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class ResourceManager:
    """
    Manages background cleanup tasks.
    
    Responsibilities:
    1. Clean up stale temporary files (disk)
    2. Reap zombie processes (kernel)
    """

    def __init__(self, cleanup_interval: int = 3600, pid_check_interval: int = 60):  # Default: 1h files, 60s PIDs
        self.cleanup_interval = cleanup_interval
        self.pid_check_interval = pid_check_interval
        self._task: asyncio.Task | None = None
        self._pid_task: asyncio.Task | None = None
        self._running = False
        self._tracked_pids: set[int] = set()

    def track_pid(self, pid: int) -> None:
        """Track a subprocess PID for zombie cleanup."""
        self._tracked_pids.add(pid)

    async def start(self):
        """Start the background cleanup tasks."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._cleanup_loop())
        self._pid_task = asyncio.create_task(self._pid_check_loop())
        logger.info(
            f"Resource Manager started (cleanup: {self.cleanup_interval}s, pid_check: {self.pid_check_interval}s)"
        )

    async def stop(self):
        """Stop all background cleanup tasks."""
        self._running = False
        for task in [self._task, self._pid_task]:
            if task:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
        logger.info("Resource Manager stopped")

    async def _cleanup_loop(self):
        """Main resource cleanup loop (files, logs)."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    async def _pid_check_loop(self):
        """FAST PID health check loop (zombies)."""
        while self._running:
            try:
                await asyncio.sleep(self.pid_check_interval)
                self._reap_zombies()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in PID check loop: {e}")

    def _reap_zombies(self):
        """Reap tracked zombie processes."""
        if not self._tracked_pids:
            return

        reaped_count = 0
        dead_pids = set()

        for pid in list(self._tracked_pids):
            try:
                # Check if process is still alive and defunct
                # waitpid with WNOHANG returns (pid, status) if dead, (0, 0) if running
                wpid, status = os.waitpid(pid, os.WNOHANG)
                if wpid > 0:
                    # Process was a zombie and is now reaped
                    dead_pids.add(pid)
                    reaped_count += 1
            except ChildProcessError:
                # Process already gone or not our child
                dead_pids.add(pid)
            except Exception as e:
                logger.debug(f"Failed to check PID {pid}: {e}")

        if dead_pids:
            self._tracked_pids -= dead_pids
            if reaped_count > 0:
                logger.info(f"Reaped {reaped_count} zombie processes")

    async def cleanup(self):
        """Perform cleanup operations."""
        logger.info("Starting periodic resource cleanup...")

        # 1. Clear stale binary cache
        # (BinaryMetadataCache already checks mtime, but we can clear old entries if needed)
        # For now, we just log.
        # binary_cache.clear() # Too aggressive?

        # 2. Clean up temporary files
        cfg = config.get_config()
        workspace = cfg.workspace

        try:
            # Clean .tmp files older than 24 hours
            now = time.time()
            max_age = 24 * 3600

            cleaned_count = 0

            # OPTIMIZATION: Use itertools.chain to avoid multiple glob calls and iterations
            # This combines all temp file patterns into a single iterable for better performance
            from itertools import chain

            # Combine all patterns into a single iterable
            temp_files = chain(
                workspace.glob("*.tmp"), workspace.glob(".r2_*"), workspace.glob("*.r2")
            )

            # PERFORMANCE NOTE: For very large numbers of temp files (>1000),
            # consider using batch deletion with os.unlink_many() or parallel deletion
            # However, this is a rare case and the current implementation is sufficient
            for temp_file in temp_files:
                try:
                    if temp_file.is_file():
                        mtime = temp_file.stat().st_mtime
                        if now - mtime > max_age:
                            temp_file.unlink()
                            cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Failed to delete temp file {temp_file}: {e}")

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} stale temporary files")

        except Exception as e:
            logger.error(f"Failed to clean temp files: {e}")

        # 3. Check r2_pool health?
        # r2_pool manages itself via LRU.

        logger.info("Resource cleanup complete")


# Global instance (for backward compatibility)
# New code should use: from reversecore_mcp.core.container import get_resource_manager
resource_manager = ResourceManager()
