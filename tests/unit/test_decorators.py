"""
Unit tests for core.decorators module.
"""

import pytest
from unittest.mock import Mock, patch

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.exceptions import ValidationError, ToolNotFoundError
from reversecore_mcp.core.result import ToolError, ToolResult, success


class TestLogExecutionDecorator:
    """Test cases for log_execution decorator."""

    @patch('reversecore_mcp.core.decorators.logger')
    def test_successful_execution_logging(self, mock_logger):
        """Test that successful execution is logged correctly."""
        @log_execution(tool_name="test_tool")
        def dummy_function(file_path: str) -> ToolResult:
            return success("success")
        
        result = dummy_function("/tmp/test.bin")
        
        assert result.status == "success"
        assert result.data == "success"
        assert mock_logger.info.call_count == 2  # Start and completion
        
        # Check that file_name was extracted
        first_call = mock_logger.info.call_args_list[0]
        assert first_call[1]['extra']['file_name'] == 'test.bin'

    @patch('reversecore_mcp.core.decorators.logger')
    def test_validation_error_handling(self, mock_logger):
        """Test that ValidationError is handled correctly."""
        @log_execution(tool_name="test_tool")
        def dummy_function(file_path: str) -> str:
            raise ValidationError("Invalid path")
        
        result = dummy_function("/tmp/test.bin")
        
        assert isinstance(result, ToolError)
        assert result.status == "error"
        assert "Invalid path" in result.message
        assert mock_logger.error.called

    @patch('reversecore_mcp.core.decorators.logger')
    def test_unexpected_error_handling(self, mock_logger):
        """Test that unexpected errors are handled correctly."""
        @log_execution()
        def dummy_function() -> str:
            raise RuntimeError("Unexpected error")
        
        result = dummy_function()
        
        assert isinstance(result, ToolError)
        assert result.status == "error"
        assert "Unexpected error" in result.message
        assert mock_logger.error.called

    def test_function_metadata_preserved(self):
        """Test that decorator preserves function metadata."""
        @log_execution(tool_name="test_tool")
        def dummy_function():
            """Test function docstring."""
            pass
        
        assert dummy_function.__name__ == "dummy_function"
        assert dummy_function.__doc__ == "Test function docstring."

    @patch('reversecore_mcp.core.decorators.logger')
    def test_tool_not_found_error_handling(self, mock_logger):
        """Test that ToolNotFoundError is handled correctly."""
        @log_execution(tool_name="test_tool")
        def dummy_function() -> str:
            raise ToolNotFoundError("Tool not found")
        
        result = dummy_function()
        
        assert isinstance(result, ToolError)
        assert result.status == "error"
        assert "Tool not found" in result.message
        assert mock_logger.error.called

    @patch('reversecore_mcp.core.decorators.logger')
    def test_file_name_extraction_from_kwargs(self, mock_logger):
        """Test file name extraction from keyword arguments."""
        @log_execution(tool_name="test_tool")
        def dummy_function(path: str):
            return success("success")
        
        result = dummy_function(path="/tmp/test_file.bin")
        
        assert result.status == "success"
        first_call = mock_logger.info.call_args_list[0]
        assert first_call[1]['extra']['file_name'] == 'test_file.bin'

    @patch('reversecore_mcp.core.decorators.logger')
    def test_execution_time_logging(self, mock_logger):
        """Test that execution time is logged."""
        @log_execution(tool_name="test_tool")
        def dummy_function():
            return success("success")
        
        result = dummy_function()
        
        assert result.status == "success"
        # Check completion log has execution_time_ms
        completion_call = mock_logger.info.call_args_list[1]
        assert 'execution_time_ms' in completion_call[1]['extra']
        assert completion_call[1]['extra']['execution_time_ms'] >= 0

    @patch('reversecore_mcp.core.decorators.logger')
    def test_default_tool_name_uses_function_name(self, mock_logger):
        """Test that default tool name is function name."""
        @log_execution()
        def my_custom_function():
            return success("success")
        
        result = my_custom_function()
        
        assert result.status == "success"
        # Check that function name was used as tool name
        first_call = mock_logger.info.call_args_list[0]
        assert "my_custom_function" in first_call[0][0]


@pytest.mark.asyncio
class TestLogExecutionDecoratorAsync:
    """Test cases for log_execution decorator with async functions."""
    
    @patch('reversecore_mcp.core.decorators.logger')
    async def test_async_successful_execution_logging(self, mock_logger):
        """Test that async successful execution is logged correctly."""
        @log_execution(tool_name="async_test_tool")
        async def dummy_async_function(file_path: str) -> ToolResult:
            return success("async success")
        
        result = await dummy_async_function("/tmp/async_test.bin")
        
        assert result.status == "success"
        assert result.data == "async success"
        assert mock_logger.info.call_count == 2
    
    @patch('reversecore_mcp.core.decorators.logger')
    async def test_async_error_handling(self, mock_logger):
        """Test that async errors are handled correctly."""
        @log_execution(tool_name="async_test_tool")
        async def dummy_async_function() -> str:
            raise RuntimeError("Async error")
        
        result = await dummy_async_function()
        
        assert isinstance(result, ToolError)
        assert result.status == "error"
        assert "Async error" in result.message
        assert mock_logger.error.called
