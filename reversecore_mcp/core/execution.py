"""
Safe subprocess execution with streaming and output limits.

This module provides functions to execute subprocess commands safely with:
- Streaming output to prevent OOM on large outputs
- Configurable output size limits
- Timeout handling
- Proper error handling and reporting
"""

import asyncio
import subprocess
import threading
from collections.abc import Coroutine
from typing import Any

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    ToolNotFoundError,
)


class _BackgroundLoopRunner:
    """Run asyncio coroutines on a dedicated background event loop."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="ReversecoreAsyncLoop",
            daemon=True,
        )
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro: Coroutine[Any, Any, tuple[str, int]]) -> tuple[str, int]:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()


_BACKGROUND_LOOP_LOCK = threading.Lock()
_BACKGROUND_LOOP_RUNNER: _BackgroundLoopRunner | None = None


def _get_background_runner() -> _BackgroundLoopRunner:
    global _BACKGROUND_LOOP_RUNNER
    with _BACKGROUND_LOOP_LOCK:
        if _BACKGROUND_LOOP_RUNNER is None:
            _BACKGROUND_LOOP_RUNNER = _BackgroundLoopRunner()
        return _BACKGROUND_LOOP_RUNNER


async def execute_subprocess_async(
    cmd: list[str],
    max_output_size: int = 10_000_000,  # 10 MB default
    timeout: int = 300,  # 5 minutes default
    encoding: str = "utf-8",
    errors: str = "replace",
) -> tuple[str, int]:
    """
    Execute a subprocess command asynchronously with streaming output and size limits.

    This function uses asyncio.create_subprocess_exec to stream output in chunks,
    preventing OOM issues when processing large files and avoiding CPU polling.
    Output is truncated if it exceeds max_output_size.

    Args:
        cmd: Command and arguments as a list (e.g., ["r2", "-q", "-c", "pdf @ main", "file.exe"])
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Maximum execution time in seconds (default: 300)
        encoding: Text encoding for output (default: "utf-8")
        errors: Error handling for encoding (default: "replace")

    Returns:
        Tuple of (output_text, bytes_read)
        - output_text: The captured output (truncated if limit exceeded)
        - bytes_read: Total bytes read (may exceed max_output_size if truncated)

    Raises:
        ToolNotFoundError: If the command executable is not found
        ExecutionTimeoutError: If the command exceeds the timeout
        subprocess.CalledProcessError: If the command returns non-zero exit code
    """
    try:
        # Start the process with piped stdout/stderr
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        # Track PID for zombie cleanup in case of abnormal termination
        from reversecore_mcp.core.resource_manager import resource_manager
        resource_manager.track_pid(process.pid)
        
    except FileNotFoundError:
        # Extract command name from cmd list
        tool_name = cmd[0] if cmd else "unknown"
        raise ToolNotFoundError(tool_name)

    # Read output in chunks
    output_chunks = []
    stderr_chunks = []
    bytes_read = 0

    try:
        # Read output in chunks with timeout checking
        async def read_stream():
            """Read stdout in chunks until EOF or size limit."""
            nonlocal bytes_read
            chunk_size = 8192  # 8KB chunks

            while True:
                chunk = await process.stdout.read(chunk_size)
                if not chunk:
                    break

                # Decode chunk
                decoded_chunk = chunk.decode(encoding, errors=errors)
                chunk_bytes = len(chunk)
                bytes_read += chunk_bytes

                # Only append if we haven't exceeded the limit
                if bytes_read <= max_output_size:
                    output_chunks.append(decoded_chunk)

        # Wait for process to complete with timeout
        # Wait for process to complete with timeout
        try:
            await asyncio.wait_for(read_stream(), timeout=timeout)
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise ExecutionTimeoutError(timeout)
        finally:
            # Critical: Ensure process is terminated to prevent zombies
            if process.returncode is None:
                try:
                    process.kill()
                    # Wait for process to die to reap the zombie
                    # We can't await indefinitely here, but usually kill is fast
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        logger.error(f"Process {process.pid} refused to die after kill")
                except Exception as e:
                    logger.error(f"Failed to kill process {process.pid}: {e}")

        # Read any remaining stderr
        stderr_data = await process.stderr.read()
        if stderr_data:
            stderr_chunks.append(stderr_data.decode(encoding, errors=errors))

        # Combine output chunks
        output_text = "".join(output_chunks)

        # Check if output was truncated
        if bytes_read > max_output_size:
            truncation_warning = (
                f"\n\n[WARNING: Output truncated at {max_output_size} bytes. "
                f"Total output size: {bytes_read} bytes]"
            )
            output_text += truncation_warning

        # If process failed, raise CalledProcessError with stderr
        if process.returncode != 0:
            stderr_text = "".join(stderr_chunks)
            raise subprocess.CalledProcessError(
                process.returncode, cmd, output=output_text, stderr=stderr_text
            )

        return output_text, bytes_read

    except ImportError:
        # Re-raise import errors (e.g. from missing dependencies)
        raise
    except Exception as e:
        if not isinstance(e, (ToolNotFoundError, ExecutionTimeoutError, subprocess.CalledProcessError)):
             logger.error(f"Command execution failed: {e}")
        raise


def execute_subprocess_streaming(
    cmd: list[str],
    max_output_size: int = 10_000_000,  # 10 MB default
    timeout: int = 300,  # 5 minutes default
    encoding: str = "utf-8",
    errors: str = "replace",
) -> tuple[str, int]:
    """
    Execute a subprocess command with streaming output and size limits.

    This is a synchronous wrapper around execute_subprocess_async that provides
    backward compatibility. It uses asyncio.run() to execute the async version.

    This function uses asyncio to stream output in chunks, preventing
    OOM issues when processing large files and avoiding CPU polling.
    Output is truncated if it exceeds max_output_size.

    Args:
        cmd: Command and arguments as a list (e.g., ["r2", "-q", "-c", "pdf @ main", "file.exe"])
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Maximum execution time in seconds (default: 300)
        encoding: Text encoding for output (default: "utf-8")
        errors: Error handling for encoding (default: "replace")

    Returns:
        Tuple of (output_text, bytes_read)
        - output_text: The captured output (truncated if limit exceeded)
        - bytes_read: Total bytes read (may exceed max_output_size if truncated)

    Raises:
        ToolNotFoundError: If the command executable is not found
        ExecutionTimeoutError: If the command exceeds the timeout
        subprocess.CalledProcessError: If the command returns non-zero exit code
    """
    coro = execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
        encoding=encoding,
        errors=errors,
    )

    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    if running_loop and running_loop.is_running():
        return _get_background_runner().run(coro)

    return asyncio.run(coro)
