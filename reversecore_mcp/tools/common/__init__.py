"""Common utility tools package.

Provides a unified CommonToolsPlugin that registers all common utility tools.
"""

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class CommonToolsPlugin(Plugin):
    """Unified plugin for all common utility tools."""

    @property
    def name(self) -> str:
        return "common_tools"

    @property
    def description(self) -> str:
        return "Unified common tools including memory management, server monitoring, file operations, and patch analysis."

    def register(self, mcp_server: Any) -> None:
        """Register all common tools."""
        # Import and delegate to specialized plugins
        from reversecore_mcp.tools.common.assembler import assemble_instructions
        from reversecore_mcp.tools.common.file_operations import (
            copy_to_workspace,
            create_directory,
            list_workspace,
            run_file,
            scan_workspace,
        )
        from reversecore_mcp.tools.common.memory_tools import MemoryToolsPlugin
        from reversecore_mcp.tools.common.patch_explainer import explain_patch
        from reversecore_mcp.tools.common.server_tools import ServerToolsPlugin

        # Register memory tools (plugin handles internal registration)
        memory_plugin = MemoryToolsPlugin()
        memory_plugin.register(mcp_server)

        # Register server tools (plugin handles internal registration)
        server_plugin = ServerToolsPlugin()
        server_plugin.register(mcp_server)

        # File operation tools
        mcp_server.tool(run_file)
        mcp_server.tool(copy_to_workspace)
        mcp_server.tool(create_directory)
        mcp_server.tool(list_workspace)
        mcp_server.tool(scan_workspace)

        # Patch explainer
        mcp_server.tool(explain_patch)

        # Assembler tool
        mcp_server.tool(assemble_instructions)

        logger.info(f"Registered {self.name} plugin with common utilities (unified)")


__all__ = ["CommonToolsPlugin"]
