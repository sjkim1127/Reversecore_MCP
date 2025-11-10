"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
"""

import os

from fastmcp import FastMCP

from reversecore_mcp.core.logging_config import setup_logging
from reversecore_mcp.tools import cli_tools, lib_tools

# Setup logging
setup_logging()

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
        
        try:
            from slowapi import Limiter, _rate_limit_exceeded_handler
            from slowapi.util import get_remote_address
            from slowapi.errors import RateLimitExceeded

            # Setup rate limiting for HTTP mode
            rate_limit = int(os.environ.get("RATE_LIMIT", "60"))  # Default: 60 requests per minute
            limiter = Limiter(key_func=get_remote_address, default_limits=[f"{rate_limit}/minute"])
            
            # Apply rate limiting to the FastAPI app
            mcp.app.state.limiter = limiter
            mcp.app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
            
            # Apply rate limit to all routes
            @mcp.app.middleware("http")
            async def rate_limit_middleware(request, call_next):
                # Apply rate limiting
                response = await limiter.middleware(request, call_next)
                return response
        except ImportError:
            # slowapi not installed, skip rate limiting
            pass

        # Swagger UI is automatically available at /docs when using FastAPI
        # FastMCP is built on FastAPI, so /docs endpoint should work out of the box
        
        uvicorn.run(mcp.app, host="0.0.0.0", port=8000)
    else:
        # Stdio transport mode for local AI clients (default)
        # Rate limiting not needed for stdio mode (single client)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

