"""Tests for error_handling module."""

import pytest
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.result import success


class TestHandleToolErrors:
    """Test error handling decorator."""

    def test_sync_function_success(self):
        """Test decorator with successful sync function."""
        @handle_tool_errors
        def test_tool():
            return success("OK")
        
        result = test_tool()
        assert result.status == "success"

    def test_sync_function_tool_not_found(self):
        """Test decorator with ToolNotFoundError."""
        @handle_tool_errors
        def test_tool():
            raise ToolNotFoundError("radare2")
        
        result = test_tool()
        assert result.status == "error"
        assert result.error_code == "TOOL_NOT_FOUND"
        assert "radare2" in result.message
        assert "apt-get install" in result.hint

    def test_sync_function_timeout(self):
        """Test decorator with ExecutionTimeoutError."""
        @handle_tool_errors
        def test_tool():
            raise ExecutionTimeoutError(timeout_seconds=30)
        
        result = test_tool()
        assert result.status == "error"
        assert result.error_code == "TIMEOUT"
        assert "30 seconds" in result.message

    def test_sync_function_output_limit(self):
        """Test decorator with OutputLimitExceededError."""
        @handle_tool_errors
        def test_tool():
            raise OutputLimitExceededError(max_size=1000, actual_size=2000)
        
        result = test_tool()
        assert result.status == "error"
        assert result.error_code == "OUTPUT_LIMIT"
        assert "Reduce output size" in result.hint
        # Details contains details dict (nested)
        assert result.details is not None
        assert "details" in result.details
        assert result.details["details"]["max_size"] == 1000
        assert result.details["details"]["actual_size"] == 2000

    def test_sync_function_validation_error(self):
        """Test decorator with ValidationError."""
        @handle_tool_errors
        def test_tool():
            raise ValidationError("Invalid file path", details={"path": "/invalid"})
        
        result = test_tool()
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
        assert "Invalid file path" in result.message
        assert "workspace directory" in result.hint

    def test_sync_function_generic_exception(self):
        """Test decorator with generic exception."""
        @handle_tool_errors
        def test_tool():
            raise ValueError("Something went wrong")
        
        result = test_tool()
        assert result.status == "error"
        assert result.error_code == "INTERNAL_ERROR"
        assert "Something went wrong" in result.message
        assert result.details["exception_type"] == "ValueError"

    @pytest.mark.asyncio
    async def test_async_function_success(self):
        """Test decorator with successful async function."""
        @handle_tool_errors
        async def test_tool():
            return success("OK")
        
        result = await test_tool()
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_async_function_tool_not_found(self):
        """Test decorator with ToolNotFoundError in async function."""
        @handle_tool_errors
        async def test_tool():
            raise ToolNotFoundError("ghidra")
        
        result = await test_tool()
        assert result.status == "error"
        assert result.error_code == "TOOL_NOT_FOUND"
        assert "ghidra" in result.message

    @pytest.mark.asyncio
    async def test_async_function_timeout(self):
        """Test decorator with ExecutionTimeoutError in async function."""
        @handle_tool_errors
        async def test_tool():
            raise ExecutionTimeoutError(timeout_seconds=60)
        
        result = await test_tool()
        assert result.status == "error"
        assert result.error_code == "TIMEOUT"
        assert "60 seconds" in result.message

    @pytest.mark.asyncio
    async def test_async_function_output_limit(self):
        """Test decorator with OutputLimitExceededError in async function."""
        @handle_tool_errors
        async def test_tool():
            raise OutputLimitExceededError(max_size=5000, actual_size=10000)
        
        result = await test_tool()
        assert result.status == "error"
        assert result.error_code == "OUTPUT_LIMIT"
        # Details contains details dict (nested)
        assert result.details is not None
        assert result.details["details"]["max_size"] == 5000

    @pytest.mark.asyncio
    async def test_async_function_validation_error(self):
        """Test decorator with ValidationError in async function."""
        @handle_tool_errors
        async def test_tool():
            raise ValidationError("Bad input")
        
        result = await test_tool()
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_async_function_generic_exception(self):
        """Test decorator with generic exception in async function."""
        @handle_tool_errors
        async def test_tool():
            raise RuntimeError("Unexpected error")
        
        result = await test_tool()
        assert result.status == "error"
        assert result.error_code == "INTERNAL_ERROR"
        assert "Unexpected error" in result.message
