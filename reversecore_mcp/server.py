"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
"""

from fastmcp import FastMCP

from reversecore_mcp.core.config import get_settings
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
    # Get transport mode from settings (default: stdio)
    settings = get_settings()
    transport = settings.mcp_transport.lower()

    if transport == "http":
        # HTTP transport mode for network-based AI agents
        import uvicorn
        from fastapi import FastAPI

        # Build a host FastAPI app with docs enabled and mount FastMCP under /mcp
        app = FastAPI(
            title="Reversecore_MCP",
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
        )
        mcp_app = mcp.http_app()
        app.mount("/mcp", mcp_app)

        # Optional: apply rate limiting if slowapi is available
        try:
            from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore
            from slowapi.util import get_remote_address  # type: ignore
            from slowapi.errors import RateLimitExceeded  # type: ignore

            rate_limit = settings.rate_limit
            limiter = Limiter(key_func=get_remote_address, default_limits=[f"{rate_limit}/minute"])

            # Attach middleware and exception handler
            @app.middleware("http")
            async def rate_limit_middleware(request, call_next):  # pragma: no cover - integration
                return await limiter.middleware(request, call_next)

            app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        except Exception:
            # slowapi unavailable or version mismatch: skip gracefully
            pass

        # Run uvicorn with the FastMCP HTTP app
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        # Stdio transport mode for local AI clients (default)
        # Rate limiting not needed for stdio mode (single client)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

