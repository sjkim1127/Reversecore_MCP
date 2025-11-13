"""
Safe subprocess execution with streaming and output limits.

This module provides functions to execute subprocess commands safely with:
- Streaming output to prevent OOM on large outputs
- Configurable output size limits
- Timeout handling
- Proper error handling and reporting
"""

import select
import subprocess
import sys
import time
from typing import Tuple

from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    ToolNotFoundError,
)


def execute_subprocess_streaming(
    cmd: list[str],
    max_output_size: int = 10_000_000,  # 10 MB default
    timeout: int = 300,  # 5 minutes default
    encoding: str = "utf-8",
    errors: str = "replace",
) -> Tuple[str, int]:
    """
    Execute a subprocess command with streaming output and size limits.

    This function uses subprocess.Popen to stream output in chunks, preventing
    OOM issues when processing large files. Output is truncated if it exceeds
    max_output_size.

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
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding=encoding,
            errors=errors,
        )
    except FileNotFoundError:
        # Extract command name from cmd list
        tool_name = cmd[0] if cmd else "unknown"
        raise ToolNotFoundError(tool_name)

    # Read output in chunks
    output_chunks = []
    stderr_chunks = []
    bytes_read = 0

    try:
        # Use time-based timeout checking
        start_time = time.time()
        return_code = None

        # Use select for efficient I/O (Unix) or fallback to polling (Windows)
        use_select = hasattr(select, "select") and sys.platform != "win32"

        # Set adaptive sleep interval for Windows polling
        poll_interval = 0.05  # Start with 50ms

        # Read output in chunks with timeout checking
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                process.kill()
                process.wait()
                raise ExecutionTimeoutError(timeout)

            # Check if process has finished
            return_code = process.poll()
            if return_code is not None:
                break

            # Use select for efficient I/O on Unix, or fallback to polling on Windows
            if use_select:
                # Use select to check if data is available (non-blocking)
                ready, _, _ = select.select([process.stdout], [], [], 0.1)
                if ready:
                    chunk = process.stdout.read(8192)  # 8KB chunks
                    if chunk:
                        bytes_read += len(chunk.encode(encoding, errors=errors))
                        if bytes_read <= max_output_size:
                            output_chunks.append(chunk)
                        # Continue reading even if limit exceeded to drain the pipe
            else:
                # Windows: use non-blocking read with adaptive timeout
                # Try to read data - this is non-blocking with text mode
                try:
                    # Use a non-blocking approach with smaller chunk size initially
                    chunk = process.stdout.read(8192)  # 8KB chunks
                    if chunk:
                        bytes_read += len(chunk.encode(encoding, errors=errors))
                        if bytes_read <= max_output_size:
                            output_chunks.append(chunk)
                        # Reset poll interval when we receive data
                        poll_interval = 0.05
                    else:
                        # No data available, use adaptive backoff
                        time.sleep(poll_interval)
                        # Gradually increase sleep time up to 0.1s to reduce CPU usage
                        poll_interval = min(poll_interval * 1.5, 0.1)
                except Exception:
                    # If read fails, wait and try again
                    time.sleep(poll_interval)

        # Read remaining stdout and stderr
        remaining_stdout = process.stdout.read()
        if remaining_stdout:
            remaining_bytes = len(remaining_stdout.encode(encoding, errors=errors))
            bytes_read += remaining_bytes
            if bytes_read <= max_output_size:
                output_chunks.append(remaining_stdout)

        stderr_data = process.stderr.read()
        if stderr_data:
            stderr_chunks.append(stderr_data)

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
        if return_code != 0:
            stderr_text = "".join(stderr_chunks)
            raise subprocess.CalledProcessError(
                return_code, cmd, output=output_text, stderr=stderr_text
            )

        return output_text, bytes_read

    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise ExecutionTimeoutError(timeout)
    except Exception:
        # Ensure process is terminated
        try:
            process.kill()
            process.wait()
        except Exception:
            pass
        raise

