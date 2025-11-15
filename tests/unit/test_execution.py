"""Unit tests for core.execution module."""

from io import StringIO
import subprocess

import pytest

from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.core.execution import execute_subprocess_streaming


class DummyProcess:
    """Simple fake subprocess handle for execute_subprocess_streaming tests."""

    def __init__(
        self,
        stdout_data: str = "",
        stderr_data: str = "",
        return_code: int = 0,
        poll_sequence: list[int | None] | None = None,
    ) -> None:
        self.stdout = StringIO(stdout_data)
        self.stderr = StringIO(stderr_data)
        self.return_code = return_code
        self._poll_sequence = poll_sequence or [None, return_code]
        self._poll_index = 0
        self.killed = False

    def poll(self):
        if self._poll_sequence is None:
            return None
        if self._poll_index < len(self._poll_sequence):
            value = self._poll_sequence[self._poll_index]
            self._poll_index += 1
            return value
        return self.return_code

    def kill(self):
        self.killed = True

    def wait(self):
        return self.return_code


@pytest.fixture
def fake_popen(monkeypatch):
    """Patch subprocess.Popen to return controllable DummyProcess instances."""

    def _factory(**kwargs):
        process = DummyProcess(**kwargs)

        def _popen(cmd, stdout=None, stderr=None, encoding=None, errors=None):
            return process

        monkeypatch.setattr(
            "reversecore_mcp.core.execution.subprocess.Popen",
            _popen,
        )
        return process

    return _factory


class TestExecuteSubprocessStreaming:
    """Test cases for execute_subprocess_streaming function."""

    def test_simple_command_success(self, fake_popen):
        """Test successful command execution."""
        fake_popen(stdout_data="hello world\n", return_code=0, poll_sequence=[None, 0])
        output, bytes_read = execute_subprocess_streaming(
            ["fake", "command"], max_output_size=1000, timeout=10
        )
        assert "hello world" in output
        assert bytes_read == len("hello world\n".encode())

    def test_command_not_found(self, monkeypatch):
        """Test that missing command raises ToolNotFoundError."""

        def _popen(*_args, **_kwargs):
            raise FileNotFoundError

        monkeypatch.setattr(
            "reversecore_mcp.core.execution.subprocess.Popen",
            _popen,
        )
        with pytest.raises(ToolNotFoundError, match="not found"):
            execute_subprocess_streaming(
                ["nonexistent_command_xyz"], max_output_size=1000, timeout=10
            )

    def test_command_timeout(self, fake_popen, monkeypatch):
        """Test that long-running command raises ExecutionTimeoutError."""
        fake_popen(stdout_data="", return_code=0, poll_sequence=None)

        # Advance time monotonically so elapsed > timeout quickly
        times = iter([0, 0.5, 1.5, 2.5])

        def fake_time():
            try:
                return next(times)
            except StopIteration:
                return 3.0

        monkeypatch.setattr("reversecore_mcp.core.execution.time.time", fake_time)
        monkeypatch.setattr("reversecore_mcp.core.execution.time.sleep", lambda _t: None)

        with pytest.raises(ExecutionTimeoutError):
            execute_subprocess_streaming(
                ["long", "running"], max_output_size=1000, timeout=1
            )

    def test_output_size_limit(self, fake_popen):
        """Test that output is truncated when exceeding max_output_size."""
        fake_popen(stdout_data="x" * 2000, return_code=0, poll_sequence=[None, 0])

        output, bytes_read = execute_subprocess_streaming(
            ["generate", "output"],
            max_output_size=1000,
            timeout=10,
        )

        assert bytes_read == 2000
        assert "Output truncated" in output

    def test_command_failure(self, fake_popen):
        """Test that command failure raises CalledProcessError."""
        fake_popen(
            stdout_data="",
            stderr_data="bad",
            return_code=1,
            poll_sequence=[None, 1],
        )
        with pytest.raises(subprocess.CalledProcessError):
            execute_subprocess_streaming(
                ["fails"], max_output_size=1000, timeout=10
            )

    def test_empty_output(self, fake_popen):
        """Test command with no output."""
        fake_popen(stdout_data="", return_code=0, poll_sequence=[None, 0])
        output, bytes_read = execute_subprocess_streaming(
            ["no", "output"], max_output_size=1000, timeout=10
        )
        assert bytes_read == 0 or len(output.strip()) == 0

