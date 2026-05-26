"""Tests for reversecore_mcp.tools.common.server_tools."""

from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.common.server_tools import ServerToolsPlugin, _format_uptime


class TestFormatUptime:
    """Tests for _format_uptime."""

    def test_seconds(self):
        assert _format_uptime(45) == "0h 0m 45s"

    def test_minutes(self):
        assert _format_uptime(125) == "0h 2m 5s"

    def test_hours(self):
        assert _format_uptime(3665) == "1h 1m 5s"

    def test_days(self):
        assert _format_uptime(90061) == "1d 1h 1m"


class TestServerToolsPlugin:
    """Tests for ServerToolsPlugin."""

    def test_plugin_metadata(self):
        plugin = ServerToolsPlugin()
        assert plugin.name == "server_tools"
        assert "server" in plugin.description.lower()

    def test_registration(self):
        mock_mcp = MagicMock()
        mock_mcp.tools = {}

        def capture_tool(*args, **kwargs):
            if args and callable(args[0]) and not kwargs:
                func = args[0]
                mock_mcp.tools[func.__name__] = func
                return func

            def decorator(func):
                mock_mcp.tools[func.__name__] = func
                return func

            return decorator

        mock_mcp.tool = capture_tool

        plugin = ServerToolsPlugin()
        plugin.register(mock_mcp)

        assert len(mock_mcp.tools) > 0

    @pytest.mark.asyncio
    async def test_get_server_status(self):
        mock_mcp = MagicMock()
        mock_mcp.tools = {}

        def capture_tool(*args, **kwargs):
            if args and callable(args[0]) and not kwargs:
                func = args[0]
                mock_mcp.tools[func.__name__] = func
                return func

            def decorator(func):
                mock_mcp.tools[func.__name__] = func
                return func

            return decorator

        mock_mcp.tool = capture_tool

        plugin = ServerToolsPlugin()
        plugin.register(mock_mcp)

        with patch(
            "reversecore_mcp.tools.common.server_tools.metrics_collector.get_metrics",
            return_value={"tools": {}},
        ):
            tool = mock_mcp.tools["get_server_health"]
            result = await tool()

        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_get_tool_metrics(self):
        mock_mcp = MagicMock()
        mock_mcp.tools = {}

        def capture_tool(*args, **kwargs):
            if args and callable(args[0]) and not kwargs:
                func = args[0]
                mock_mcp.tools[func.__name__] = func
                return func

            def decorator(func):
                mock_mcp.tools[func.__name__] = func
                return func

            return decorator

        mock_mcp.tool = capture_tool

        plugin = ServerToolsPlugin()
        plugin.register(mock_mcp)

        with patch(
            "reversecore_mcp.tools.common.server_tools.metrics_collector.get_metrics",
            return_value={"tools": {"test_tool": {"calls": 5}}},
        ):
            tool = mock_mcp.tools["get_tool_metrics"]
            result = await tool()

        assert result.status == "success"
