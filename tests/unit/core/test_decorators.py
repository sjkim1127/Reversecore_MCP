"""Tests for reversecore_mcp.core.decorators."""

from unittest.mock import patch

from reversecore_mcp.core.decorators import log_execution


class TestLogExecution:
    """Tests for log_execution decorator."""

    def test_sync_function(self):
        @log_execution("test_tool")
        def my_tool():
            return "success"

        result = my_tool()
        assert result == "success"

    def test_sync_with_error(self):
        @log_execution("test_tool")
        def my_tool():
            raise ValueError("fail")

        with patch("reversecore_mcp.core.decorators.logger") as mock_logger:
            with patch("reversecore_mcp.core.decorators.get_logger", return_value=mock_logger):
                try:
                    my_tool()
                except ValueError:
                    pass

    def test_async_function(self):
        import asyncio

        @log_execution("test_tool")
        async def my_tool():
            return "success"

        result = asyncio.run(my_tool())
        assert result == "success"
