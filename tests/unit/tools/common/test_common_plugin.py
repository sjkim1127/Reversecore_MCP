"""Unit tests for CommonToolsPlugin and plugin registration collision prevention."""

import logging
from pathlib import Path

from fastmcp import FastMCP

from reversecore_mcp.core.loader import PluginLoader
from reversecore_mcp.tools.common import CommonToolsPlugin


class TestCommonToolsPlugin:
    """Tests for CommonToolsPlugin registration behavior."""

    def test_plugin_metadata(self):
        """Test plugin name and description."""
        plugin = CommonToolsPlugin()
        assert plugin.name == "common_tools"
        assert "Unified common tools" in plugin.description

    def test_register_default_no_subplugins(self):
        """Test that default register() registers 7 tools without memory/server subplugins."""
        mcp = FastMCP("test_common_default")
        plugin = CommonToolsPlugin()

        plugin.register(mcp)

        tools = mcp._tool_manager._tools
        assert len(tools) == 7
        expected_tools = {
            "run_file",
            "copy_to_workspace",
            "create_directory",
            "list_workspace",
            "scan_workspace",
            "explain_patch",
            "assemble_instructions",
        }
        assert set(tools.keys()) == expected_tools

    def test_register_with_subplugins(self):
        """Test that register(include_subplugins=True) registers 20 tools."""
        mcp = FastMCP("test_common_with_subplugins")
        plugin = CommonToolsPlugin()

        plugin.register(mcp, include_subplugins=True)

        tools = mcp._tool_manager._tools
        assert len(tools) == 20
        # Check presence of subplugin tools
        assert "create_memory_session" in tools
        assert "get_server_health" in tools
        assert "run_file" in tools

    def test_no_duplicate_warnings_during_full_discovery_registration(self, caplog):
        """Verify that discovering and registering all plugins produces zero duplicate tool warnings."""
        mcp = FastMCP("test_full_registration")
        loader = PluginLoader()
        tools_dir = Path(__file__).resolve().parents[4] / "reversecore_mcp" / "tools"

        plugins = loader.discover_plugins(str(tools_dir), "reversecore_mcp.tools")
        assert len(plugins) >= 11

        with caplog.at_level(logging.WARNING):
            for p in plugins:
                p.register(mcp)

        # Ensure no duplicate tool warnings are emitted by FastMCP
        duplicate_warnings = [
            record.message for record in caplog.records if "Tool already exists" in record.message
        ]
        assert duplicate_warnings == [], f"Found duplicate tool warnings: {duplicate_warnings}"
        assert len(mcp._tool_manager._tools) >= 140
