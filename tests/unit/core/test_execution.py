"""Tests for reversecore_mcp.core.execution."""

import subprocess
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
