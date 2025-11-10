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
        # Generate large output using Python to create predictable output
        import sys
        import subprocess
        
        # Try using Python to generate large output
        python_cmd = sys.executable  # Use the same Python interpreter running tests
        try:
            # Generate 2000 bytes of output, but limit to 1000
            output, bytes_read = execute_subprocess_streaming(
                [python_cmd, "-c", "import sys; sys.stdout.write('x' * 2000)"],
                max_output_size=1000,
                timeout=10
            )
        except (FileNotFoundError, ToolNotFoundError):
            pytest.skip("Python interpreter not available for output size limit test")
        
        # Output should be truncated
        assert bytes_read >= 1000
        # Check for truncation warning (may vary based on implementation)
        # The output should be limited to max_output_size
        assert len(output.encode('utf-8')) <= 1000 + 100  # Allow some margin for warning message

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

