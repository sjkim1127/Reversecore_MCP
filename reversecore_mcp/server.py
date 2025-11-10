"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
"""

import os

from fastmcp import FastMCP

from reversecore_mcp.tools import cli_tools, lib_tools

# Initialize the FastMCP server
mcp = FastMCP(name="Reversecore_MCP")

# Register all tool modules
cli_tools.register_cli_tools(mcp)
lib_tools.register_lib_tools(mcp)


def main():
    """Run the MCP server."""
    # Get transport mode from environment variable (default: stdio)
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()

    if transport == "http":
        # HTTP transport mode for network-based AI agents
        import uvicorn

        uvicorn.run(mcp.app, host="0.0.0.0", port=8000)
    else:
        # Stdio transport mode for local AI clients (default)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

