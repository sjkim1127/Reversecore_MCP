"""
Unit tests for core.exceptions module.
"""

import pytest

from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ReversecoreError,
    ToolNotFoundError,
)


class TestExceptions:
    """Test cases for custom exception classes."""

    def test_tool_not_found_error(self):
        """Test ToolNotFoundError exception."""
        error = ToolNotFoundError("r2")
        assert error.tool_name == "r2"
        assert "r2" in str(error)
        assert "not found" in str(error).lower()

    def test_execution_timeout_error(self):
        """Test ExecutionTimeoutError exception."""
        error = ExecutionTimeoutError(300)
        assert error.timeout_seconds == 300
        assert "300" in str(error)
        assert "timed out" in str(error).lower() or "timeout" in str(error).lower()

    def test_output_limit_exceeded_error(self):
        """Test OutputLimitExceededError exception."""
        error = OutputLimitExceededError(max_size=1000, actual_size=2000)
        assert error.max_size == 1000
        assert error.actual_size == 2000
        assert "1000" in str(error)
        assert "2000" in str(error)
        assert "truncated" in str(error).lower()

    def test_exception_inheritance(self):
        """Test that all exceptions inherit from ReversecoreError."""
        assert issubclass(ToolNotFoundError, ReversecoreError)
        assert issubclass(ExecutionTimeoutError, ReversecoreError)
        assert issubclass(OutputLimitExceededError, ReversecoreError)

