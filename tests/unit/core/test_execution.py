"""Tests for reversecore_mcp.core.execution."""

import subprocess
import sys
from unittest.mock import patch

import pytest

from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.core.resource_manager import ResourceManager


class TestExecuteSubprocessAsync:
    """Tests for execute_subprocess_async."""

    @pytest.mark.asyncio
    async def test_success(self):
        """Execute a simple command successfully."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        with patch.object(ResourceManager, "track_pid"):
            output, bytes_read = await execute_subprocess_async(
                ["python", "-c", "print('hello')"],
                timeout=10,
            )
        assert "hello" in output
        assert bytes_read > 0

    @pytest.mark.asyncio
    async def test_pid_lifecycle_tracked_and_untracked(self):
        """Verify that spawned subprocess PID is tracked upon start and untracked upon exit."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        with (
            patch.object(ResourceManager, "track_pid") as mock_track,
            patch.object(ResourceManager, "untrack_pid") as mock_untrack,
        ):
            await execute_subprocess_async(
                ["python", "-c", "print('lifecycle')"],
                timeout=10,
            )
            mock_track.assert_called_once()
            mock_untrack.assert_called_once()
            tracked_pid = mock_track.call_args[0][0]
            untracked_pid = mock_untrack.call_args[0][0]
            assert tracked_pid == untracked_pid

    @pytest.mark.asyncio
    async def test_nonexistent_command(self):
        """Raise ToolNotFoundError for nonexistent command."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        with pytest.raises(ToolNotFoundError):
            await execute_subprocess_async(["nonexistent_command_12345"], timeout=10)

    @pytest.mark.asyncio
    async def test_output_truncation(self):
        """Truncate output when exceeding max_output_size."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        with patch.object(ResourceManager, "track_pid"):
            output, bytes_read = await execute_subprocess_async(
                ["python", "-c", "print('x' * 1000)"],
                max_output_size=100,
                timeout=10,
            )
        assert "[WARNING: Output truncated" in output
        assert bytes_read > 100

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self):
        """Raise CalledProcessError on nonzero exit code."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        with patch.object(ResourceManager, "track_pid"):
            with pytest.raises(subprocess.CalledProcessError):
                await execute_subprocess_async(
                    ["python", "-c", "import sys; sys.exit(1)"],
                    timeout=10,
                )

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Raise ExecutionTimeoutError on timeout."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        with patch.object(ResourceManager, "track_pid"):
            with pytest.raises(ExecutionTimeoutError):
                await execute_subprocess_async(
                    ["python", "-c", "import time; time.sleep(10)"],
                    timeout=1,
                )

    @pytest.mark.asyncio
    async def test_large_stderr_concurrent_no_deadlock(self):
        """Read large stderr (>64KB) concurrently with stdout without pipe buffer deadlock."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        code = (
            "import sys\n"
            "sys.stderr.write('E' * 128000)\n"
            "sys.stderr.flush()\n"
            "sys.stdout.write('O' * 1000)\n"
            "sys.stdout.flush()\n"
        )
        with patch.object(ResourceManager, "track_pid"):
            output, bytes_read = await execute_subprocess_async(
                ["python", "-c", code],
                timeout=10,
            )
        assert len(output) >= 1000
        assert "O" in output

    @pytest.mark.asyncio
    async def test_timeout_process_kill_cleanup(self):
        """Ensure process termination logic is exercised on timeout."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        with patch.object(ResourceManager, "track_pid"):
            with pytest.raises(ExecutionTimeoutError):
                await execute_subprocess_async(
                    ["python", "-c", "import time; time.sleep(10)"],
                    timeout=1,
                )


class TestExecuteSubprocessStreaming:
    """Tests for execute_subprocess_streaming synchronous wrapper."""

    def test_success(self):
        """Execute a simple command via sync wrapper."""
        from reversecore_mcp.core.execution import execute_subprocess_streaming

        with patch.object(ResourceManager, "track_pid"):
            output, bytes_read = execute_subprocess_streaming(
                ["python", "-c", "print('hello')"],
                timeout=10,
            )
        assert "hello" in output
        assert bytes_read > 0

    def test_nonexistent_command(self):
        """Raise ToolNotFoundError for nonexistent command."""
        from reversecore_mcp.core.execution import execute_subprocess_streaming

        with pytest.raises(ToolNotFoundError):
            execute_subprocess_streaming(["nonexistent_command_12345"], timeout=10)


class TestExecuteSubprocessLinesAsync:
    """Tests for bounded line-oriented subprocess output."""

    @pytest.mark.asyncio
    async def test_streams_lines_without_accumulating_them(self):
        from reversecore_mcp.core.execution import execute_subprocess_lines_async

        retained: list[str] = []
        line_count = 0

        def consume(line: str, line_truncated: bool) -> None:
            nonlocal line_count
            assert not line_truncated
            line_count += 1
            if len(retained) < 3:
                retained.append(line)

        code = "import sys; [print(f'line-{i}') for i in range(1000)]"
        with patch.object(ResourceManager, "track_pid"):
            (
                returncode,
                stderr,
                bytes_read,
                output_limited,
                line_truncated,
            ) = await execute_subprocess_lines_async(
                [sys.executable, "-c", code],
                consume,
                max_output_size=100_000,
                timeout=10,
            )

        assert returncode == 0
        assert stderr == ""
        assert bytes_read > 0
        assert line_count == 1000
        assert retained == ["line-0", "line-1", "line-2"]
        assert not output_limited
        assert not line_truncated

    @pytest.mark.asyncio
    async def test_terminates_when_output_byte_limit_is_exceeded(self):
        from reversecore_mcp.core.execution import execute_subprocess_lines_async

        observed: list[tuple[str, bool]] = []
        code = (
            "import sys,time; sys.stdout.write('x' * 10000000); sys.stdout.flush(); time.sleep(30)"
        )
        with patch.object(ResourceManager, "track_pid"):
            (
                returncode,
                _,
                bytes_read,
                output_limited,
                line_truncated,
            ) = await execute_subprocess_lines_async(
                [sys.executable, "-c", code],
                lambda line, line_truncated: observed.append((line, line_truncated)),
                max_output_size=4096,
                max_line_size=512,
                timeout=10,
            )

        assert returncode != 0
        assert bytes_read == 4096
        assert output_limited
        assert line_truncated
        assert observed
        assert observed[0][1]


class TestExecuteSubprocessBytesAsync:
    """Tests for bounded raw-byte subprocess output."""

    @pytest.mark.asyncio
    async def test_streams_binary_chunks_and_terminates_at_output_limit(self):
        from reversecore_mcp.core.execution import execute_subprocess_bytes_async

        captured = bytearray()
        code = (
            "import sys,time; sys.stdout.buffer.write(b'\\x00' * 10000000); "
            "sys.stdout.flush(); time.sleep(30)"
        )
        with (
            patch.object(ResourceManager, "track_pid"),
            patch.object(ResourceManager, "untrack_pid"),
        ):
            returncode, stderr, bytes_read, output_limited = await execute_subprocess_bytes_async(
                [sys.executable, "-c", code],
                captured.extend,
                max_output_size=4096,
                timeout=10,
            )

        assert returncode != 0
        assert stderr == ""
        assert bytes_read == 4096
        assert len(captured) == 4096
        assert captured == b"\x00" * 4096
        assert output_limited


class TestBackgroundLoopRunner:
    """Tests for _BackgroundLoopRunner."""

    def test_run_coroutine(self):
        """Run a simple coroutine on the background loop."""
        from reversecore_mcp.core.execution import _BackgroundLoopRunner

        runner = _BackgroundLoopRunner()

        async def coro():
            return ("result", 42)

        result = runner.run(coro())
        assert result == ("result", 42)
        runner._loop.call_soon_threadsafe(runner._loop.stop)
        runner._thread.join(timeout=2)
