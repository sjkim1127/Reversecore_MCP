"""
Unit tests for core.execution module.
"""

import subprocess
import time

import pytest

from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.core.execution import execute_subprocess_streaming


class TestExecuteSubprocessStreaming:
    """Test cases for execute_subprocess_streaming function."""

    def test_simple_command_success(self):
        """Test successful command execution."""
        output, bytes_read = execute_subprocess_streaming(
            ["echo", "hello world"], max_output_size=1000, timeout=10
        )
        assert "hello world" in output
        assert bytes_read > 0

    def test_command_not_found(self):
        """Test that missing command raises ToolNotFoundError."""
        with pytest.raises(ToolNotFoundError, match="not found"):
            execute_subprocess_streaming(
                ["nonexistent_command_xyz"], max_output_size=1000, timeout=10
            )

    def test_command_timeout(self):
        """Test that long-running command raises ExecutionTimeoutError."""
        with pytest.raises(ExecutionTimeoutError):
            execute_subprocess_streaming(
                ["sleep", "10"], max_output_size=1000, timeout=1
            )

    def test_output_size_limit(self):
        """Test that output is truncated when exceeding max_output_size."""
        # Generate large output
        output, bytes_read = execute_subprocess_streaming(
            ["yes", "test"], max_output_size=1000, timeout=2
        )
        
        # Output should be truncated
        assert bytes_read >= 1000
        assert "[WARNING: Output truncated" in output

    def test_command_failure(self):
        """Test that command failure raises CalledProcessError."""
        with pytest.raises(subprocess.CalledProcessError):
            execute_subprocess_streaming(
                ["false"], max_output_size=1000, timeout=10
            )

    def test_empty_output(self):
        """Test command with no output."""
        output, bytes_read = execute_subprocess_streaming(
            ["true"], max_output_size=1000, timeout=10
        )
        assert bytes_read == 0 or len(output.strip()) == 0

