"""Unit tests for core.execution module."""

import asyncio
from io import StringIO
import subprocess
import sys

import pytest

from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.core.execution import execute_subprocess_streaming, execute_subprocess_async


class AsyncDummyProcess:
    """Fake async subprocess handle for execute_subprocess_async tests."""

    def __init__(
        self,
        stdout_data: bytes = b"",
        stderr_data: bytes = b"",
        return_code: int = 0,
    ) -> None:
        self.stdout = AsyncStreamReader(stdout_data)
        self.stderr = AsyncStreamReader(stderr_data)
        self.returncode = return_code
        self.killed = False

    async def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True


class AsyncStreamReader:
    """Fake async stream reader."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def read(self, n: int = -1):
        if n == -1:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
        else:
            chunk = self._data[self._pos:self._pos + n]
            self._pos += len(chunk)
        # Simulate async I/O
        await asyncio.sleep(0)
        return chunk


@pytest.fixture
def fake_async_subprocess(monkeypatch):
    """Patch asyncio.create_subprocess_exec to return controllable AsyncDummyProcess instances."""

    def _factory(**kwargs):
        process = AsyncDummyProcess(**kwargs)

        async def _create_subprocess(*cmd, stdout=None, stderr=None):
            return process

        monkeypatch.setattr(
            "reversecore_mcp.core.execution.asyncio.create_subprocess_exec",
            _create_subprocess,
        )
        return process

    return _factory


class TestExecuteSubprocessStreaming:
    """Test cases for execute_subprocess_streaming function."""

    def test_simple_command_success(self, fake_async_subprocess):
        """Test successful command execution."""
        fake_async_subprocess(stdout_data=b"hello world\n", return_code=0)
        output, bytes_read = execute_subprocess_streaming(
            ["fake", "command"], max_output_size=1000, timeout=10
        )
        assert "hello world" in output
        assert bytes_read == len(b"hello world\n")

    def test_command_not_found(self, monkeypatch):
        """Test that missing command raises ToolNotFoundError."""

        async def _create_subprocess(*_args, **_kwargs):
            raise FileNotFoundError

        monkeypatch.setattr(
            "reversecore_mcp.core.execution.asyncio.create_subprocess_exec",
            _create_subprocess,
        )
        with pytest.raises(ToolNotFoundError, match="not found"):
            execute_subprocess_streaming(
                ["nonexistent_command_xyz"], max_output_size=1000, timeout=10
            )

    def test_command_timeout(self, fake_async_subprocess, monkeypatch):
        """Test that long-running command raises ExecutionTimeoutError."""
        # Create a process that will take longer than timeout
        fake_async_subprocess(stdout_data=b"", return_code=0)
        
        # Patch asyncio.wait_for to raise TimeoutError
        original_wait_for = asyncio.wait_for
        
        async def fake_wait_for(coro, timeout):
            raise asyncio.TimeoutError()
        
        monkeypatch.setattr("asyncio.wait_for", fake_wait_for)

        with pytest.raises(ExecutionTimeoutError):
            execute_subprocess_streaming(
                ["long", "running"], max_output_size=1000, timeout=1
            )

    def test_output_size_limit(self, fake_async_subprocess):
        """Test that output is truncated when exceeding max_output_size."""
        fake_async_subprocess(stdout_data=b"x" * 2000, return_code=0)

        output, bytes_read = execute_subprocess_streaming(
            ["generate", "output"],
            max_output_size=1000,
            timeout=10,
        )

        assert bytes_read == 2000
        assert "Output truncated" in output

    def test_command_failure(self, fake_async_subprocess):
        """Test that command failure raises CalledProcessError."""
        fake_async_subprocess(
            stdout_data=b"",
            stderr_data=b"bad",
            return_code=1,
        )
        with pytest.raises(subprocess.CalledProcessError):
            execute_subprocess_streaming(
                ["fails"], max_output_size=1000, timeout=10
            )

    def test_empty_output(self, fake_async_subprocess):
        """Test command with no output."""
        fake_async_subprocess(stdout_data=b"", return_code=0)
        output, bytes_read = execute_subprocess_streaming(
            ["no", "output"], max_output_size=1000, timeout=10
        )
        assert bytes_read == 0 or len(output.strip()) == 0

