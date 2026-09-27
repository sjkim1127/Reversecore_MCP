"""
Safe subprocess execution with streaming and output limits.

This module provides functions to execute subprocess commands safely with:
- Streaming output to prevent OOM on large outputs
- Configurable output size limits
- Timeout handling
- Proper error handling and reporting
"""

import asyncio
import os
import shutil
import signal

# Subprocess module is required for execution; security is enforced via SandboxExecutor and limits.
import subprocess  # nosec B404
import sys
import threading
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    ToolNotFoundError,
)
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


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


def is_in_container() -> bool:
    """Detect whether the server is running inside a Docker container."""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup") as f:
            content = f.read()
            if "docker" in content or "kubepods" in content or "containerd" in content:
                return True
    except Exception:  # nosec B110
        pass
    return False


class SandboxExecutor:
    """Helper class to translate subprocess execution commands into sandboxed commands."""

    @staticmethod
    def wrap_cmd(cmd: list[str]) -> list[str]:
        """Wrap the command list to run in a sandbox if enabled and applicable.

        Args:
            cmd: Original command list.

        Returns:
            Wrapped/sandboxed command list.
        """
        from reversecore_mcp.core.config import get_config

        config = get_config()
        if not config.sandbox_enabled:
            return cmd

        mode = config.sandbox_mode.lower()
        if mode == "disabled":
            return cmd

        in_container = is_in_container()
        if mode == "auto":
            active_mode = "container" if in_container else "host"
        else:
            active_mode = mode

        if active_mode == "host":
            if not shutil.which("docker"):
                raise RuntimeError(
                    "Sandbox is enabled in host mode, but Docker is unavailable; "
                    "refusing to run the command without isolation"
                )

            # Build Docker command
            docker_cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
            ]

            # Mount workspace (read-only)
            workspace_path = str(config.workspace)
            docker_cmd.extend(["-v", f"{workspace_path}:{workspace_path}:ro"])

            # Mount .cache (read-write) for temporary files if it exists
            cache_path = config.workspace / ".cache"
            if cache_path.exists():
                docker_cmd.extend(["-v", f"{cache_path}:{cache_path}:rw"])

            # Mount read-only dirs
            for rd in config.read_only_dirs:
                rd_path = str(rd)
                docker_cmd.extend(["-v", f"{rd_path}:{rd_path}:ro"])

            # Add hardware limits
            if config.sandbox_cpu_limit:
                docker_cmd.extend(["--cpus", str(config.sandbox_cpu_limit)])
            if config.sandbox_memory_limit:
                docker_cmd.extend(["--memory", str(config.sandbox_memory_limit)])
            if config.sandbox_pids_limit:
                docker_cmd.extend(["--pids-limit", str(config.sandbox_pids_limit)])

            # Target image and original command
            docker_cmd.append(config.sandbox_docker_image)
            docker_cmd.extend(cmd)
            return docker_cmd

        elif active_mode == "container":
            # If already running as a non-root user (e.g., in Docker under USER appuser),
            # privilege separation is already enforced. Non-root users lack CAP_SETUID/CAP_SETGID
            # and cannot switch UIDs.
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                logger.debug(
                    "Already running as non-root user (UID=%d); skipping privilege drop.",
                    os.geteuid(),
                )
                return cmd

            target_user = config.sandbox_user
            target_gid = target_user
            if sys.platform != "win32":
                try:
                    import pwd

                    target_gid = str(pwd.getpwnam(target_user).pw_gid)
                except Exception:
                    pass

            if shutil.which("setpriv"):
                return [
                    "setpriv",
                    f"--reuid={target_user}",
                    f"--regid={target_gid}",
                    "--clear-groups",
                    "--",
                ] + cmd

        return cmd


def prepare_sandbox_access(path: Path) -> None:
    """Make an internal scratch path accessible to the configured container-mode user."""
    from reversecore_mcp.core.config import get_config

    config = get_config()
    if not config.sandbox_enabled or config.sandbox_mode.lower() == "disabled":
        return

    mode = config.sandbox_mode.lower()
    active_mode = "container" if mode == "auto" and is_in_container() else mode
    if active_mode != "container" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return

    cache_dir = config.workspace / ".cache"
    if cache_dir.is_symlink():
        raise RuntimeError("Workspace cache directory must not be a symbolic link")
    cache_root = cache_dir.resolve()
    if path.is_symlink():
        raise RuntimeError("Sandbox scratch paths must not be symbolic links")
    try:
        path.resolve(strict=True).relative_to(cache_root)
    except (OSError, ValueError) as exc:
        raise RuntimeError("Sandbox scratch paths must remain inside workspace/.cache") from exc

    try:
        import pwd

        sandbox_user = pwd.getpwnam(config.sandbox_user)
    except (ImportError, KeyError) as exc:
        raise RuntimeError(
            f"Cannot resolve sandbox user {config.sandbox_user!r} for scratch access"
        ) from exc

    os.chown(path, sandbox_user.pw_uid, sandbox_user.pw_gid)


async def execute_subprocess_async(
    cmd: list[str],
    max_output_size: int = 10_000_000,  # 10 MB default
    timeout: int = 300,  # 5 minutes default
    encoding: str = "utf-8",
    errors: str = "replace",
    capture_stderr: bool = False,
    kill_process_group: bool = False,
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
        capture_stderr: Include stderr in the bounded returned output.
        kill_process_group: Start a separate POSIX process group and terminate
            it on timeout or cancellation.

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
        # Wrap command and prepare kwargs for sandboxing
        wrapped_cmd = SandboxExecutor.wrap_cmd(cmd)

        extra_kwargs: dict[str, Any] = {}
        from reversecore_mcp.core.config import get_config

        config = get_config()
        if config.sandbox_enabled:
            mode = config.sandbox_mode.lower()
            if mode != "disabled":
                in_container = is_in_container()
                active_mode = (
                    "container"
                    if (mode == "auto" and in_container) or mode == "container"
                    else mode
                )

                if (
                    active_mode == "container"
                    and hasattr(os, "geteuid")
                    and os.geteuid() == 0
                    and not shutil.which("setpriv")
                ):
                    if sys.platform != "win32" and config.sandbox_user:
                        try:
                            import pwd

                            pw = pwd.getpwnam(config.sandbox_user)
                            extra_kwargs["user"] = pw.pw_uid
                            extra_kwargs["group"] = pw.pw_gid
                            extra_kwargs["extra_groups"] = ()
                        except Exception as err:
                            logger.warning(
                                "Failed to resolve sandbox user %s for privilege drop: %s",
                                config.sandbox_user,
                                err,
                            )
                            extra_kwargs["user"] = config.sandbox_user

        # Start the process with piped stdout/stderr
        process = await asyncio.create_subprocess_exec(
            *wrapped_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=kill_process_group and os.name == "posix",
            **extra_kwargs,
        )

        # Track PID for zombie cleanup in case of abnormal termination
        from reversecore_mcp.core.resource_manager import resource_manager

        resource_manager.track_pid(process.pid)

    except FileNotFoundError:
        # Extract command name from cmd list
        tool_name = cmd[0] if cmd else "unknown"
        raise ToolNotFoundError(tool_name)

    if process.stdout is None or process.stderr is None:
        raise RuntimeError("Process stdout or stderr stream is not available")

    # Read output in chunks
    output_chunks = []
    stderr_chunks = []
    bytes_read = 0
    stderr_bytes_read = 0

    def kill_process_tree() -> None:
        """Terminate the launched process, including same-group children when requested."""
        try:
            if kill_process_group and os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    try:
        try:
            # Read stdout and stderr in chunks concurrently with timeout checking
            async def read_stdout():
                """Read stdout in chunks until EOF or size limit."""
                nonlocal bytes_read
                chunk_size = 8192  # 8KB chunks

                # Assert stdout is not None for mypy
                assert process.stdout is not None  # nosec B101
                while True:
                    chunk = await process.stdout.read(chunk_size)
                    if not chunk:
                        break

                    chunk_bytes = len(chunk)
                    bytes_read += chunk_bytes

                    # Only append if we haven't exceeded the limit
                    if capture_stderr:
                        remaining = max_output_size - bytes_read + chunk_bytes - stderr_bytes_read
                        if remaining > 0:
                            output_chunks.append(chunk[:remaining].decode(encoding, errors=errors))
                    elif bytes_read <= max_output_size:
                        output_chunks.append(chunk.decode(encoding, errors=errors))

            async def read_stderr():
                """Read stderr in chunks until EOF or size limit to prevent pipe buffer deadlock."""
                chunk_size = 8192  # 8KB chunks
                nonlocal stderr_bytes_read

                # Assert stderr is not None for mypy
                assert process.stderr is not None  # nosec B101
                while True:
                    chunk = await process.stderr.read(chunk_size)
                    if not chunk:
                        break

                    # Decode chunk
                    chunk_bytes = len(chunk)
                    stderr_bytes_read += chunk_bytes

                    # Only append if we haven't exceeded the limit
                    if capture_stderr:
                        remaining = max_output_size - bytes_read - stderr_bytes_read + chunk_bytes
                        if remaining > 0:
                            stderr_chunks.append(chunk[:remaining].decode(encoding, errors=errors))
                    elif stderr_bytes_read <= max_output_size:
                        stderr_chunks.append(chunk.decode(encoding, errors=errors))

            # Wait for both streams and process to complete with timeout
            terminate_process_tree = False
            try:
                await asyncio.wait_for(
                    asyncio.gather(read_stdout(), read_stderr()),
                    timeout=timeout,
                )
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
                terminate_process_tree = True
                raise ExecutionTimeoutError(timeout)
            except asyncio.CancelledError:
                terminate_process_tree = True
                raise
            finally:
                # Critical: Ensure process is terminated to prevent zombies
                if process.returncode is None or terminate_process_tree:
                    try:
                        kill_process_tree()
                        # Wait for process to die to reap the zombie
                        if process.returncode is None:
                            try:
                                await asyncio.wait_for(process.wait(), timeout=2.0)
                            except asyncio.TimeoutError:
                                logger.error(f"Process {process.pid} refused to die after kill")
                    except Exception as e:
                        logger.error(f"Failed to kill process {process.pid}: {e}")

            # Combine output chunks
            output_text = "".join(output_chunks)
            stderr_text = "".join(stderr_chunks)
            if capture_stderr:
                output_text += stderr_text
            reported_bytes_read = bytes_read + stderr_bytes_read if capture_stderr else bytes_read

            # Check if output was truncated
            if capture_stderr:
                output_bytes = output_text.encode(encoding, errors=errors)
                if reported_bytes_read > max_output_size or len(output_bytes) > max_output_size:
                    marker = b"\n[output truncated]"
                    if max_output_size >= len(marker):
                        output_bytes = output_bytes[: max_output_size - len(marker)] + marker
                    else:
                        output_bytes = output_bytes[:max_output_size]
                    output_text = output_bytes.decode(encoding, errors="ignore")
            elif reported_bytes_read > max_output_size:
                truncation_warning = (
                    f"\n\n[WARNING: Output truncated at {max_output_size} bytes. "
                    f"Total output size: {bytes_read} bytes]"
                )
                output_text += truncation_warning

            # If process failed, raise CalledProcessError with stderr
            returncode = process.returncode
            if returncode is None:
                returncode = -1
            if returncode != 0:
                raise subprocess.CalledProcessError(
                    returncode, cmd, output=output_text, stderr=stderr_text
                )

            return output_text, reported_bytes_read
        finally:
            from reversecore_mcp.core.resource_manager import resource_manager

            resource_manager.untrack_pid(process.pid)

    except ImportError:
        # Re-raise import errors (e.g. from missing dependencies)
        raise
    except Exception as e:
        if not isinstance(
            e, (ToolNotFoundError, ExecutionTimeoutError, subprocess.CalledProcessError)
        ):
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
