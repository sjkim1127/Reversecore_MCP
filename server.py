"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
It includes health and metrics endpoints for monitoring in HTTP mode.
"""

from fastmcp import FastMCP

from reversecore_mcp.core.logging_config import setup_logging, get_logger
from reversecore_mcp.core.config import get_config
from reversecore_mcp.tools import cli_tools, lib_tools

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Initialize the FastMCP server
mcp = FastMCP(name="Reversecore_MCP")

# Register all tool modules
# Register all tool modules
cli_tools.register_cli_tools(mcp)
lib_tools.register_lib_tools(mcp)

# Register prompts
from reversecore_mcp import prompts
prompts.register_prompts(mcp)

# Register resources
from reversecore_mcp import resources
resources.register_resources(mcp)



def main():
    """Run the MCP server."""
    # Get transport mode from settings (default: stdio)
    settings = get_config()
    
    # Validate paths at startup
    try:
        settings.validate_paths()
        logger.info("Path validation successful")
    except ValueError as e:
        logger.error(f"Path validation failed: {e}")
        raise
    
    transport = settings.mcp_transport.lower()

    if transport == "http":
        # HTTP transport mode for network-based AI agents
        import uvicorn
        from fastapi import FastAPI, UploadFile, File
        from fastapi.responses import JSONResponse
        from reversecore_mcp.core.metrics import metrics_collector

        # Build a host FastAPI app with docs enabled and mount FastMCP under /mcp
        app = FastAPI(
            title="Reversecore_MCP",
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
        )
        mcp_app = mcp.http_app()
        app.mount("/mcp", mcp_app)

        # Add health endpoint
        @app.get("/health")
        async def health():
            """Health check endpoint."""
            return JSONResponse(
                content={
                    "status": "healthy",
                    "service": "Reversecore_MCP",
                    "transport": "http"
                }
            )

        # Add metrics endpoint
        @app.get("/metrics")
        async def metrics():
            """Metrics endpoint returning collected tool metrics."""
            return JSONResponse(content=metrics_collector.get_metrics())

        # Add file upload endpoint for remote clients (e.g., Claude.ai)
        @app.post("/upload")
        async def upload_file(file: UploadFile = File(...)):
            """
            Upload a file to the workspace for analysis.
            
            This endpoint allows remote clients (like Claude.ai) to upload files
            to the local workspace for analysis by MCP tools.
            
            Args:
                file: The file to upload (multipart/form-data)
            
            Returns:
                JSON response with file path and status
            """
            from pathlib import Path
            import shutil
            
            try:
                # Ensure workspace exists
                workspace = settings.workspace
                workspace.mkdir(parents=True, exist_ok=True)
                
                # Save uploaded file to workspace
                file_path = workspace / file.filename
                
                with open(file_path, "wb") as buffer:
                    shutil.copyfileobj(file.file, buffer)
                
                logger.info(f"File uploaded: {file.filename} -> {file_path}")
                
                return JSONResponse(
                    content={
                        "status": "success",
                        "message": f"File uploaded successfully",
                        "file_path": str(file_path),
                        "workspace_path": f"/app/workspace/{file.filename}" if str(workspace).endswith("workspace") else str(file_path),
                        "filename": file.filename,
                        "size": file_path.stat().st_size
                    }
                )
            except Exception as e:
                logger.error(f"File upload failed: {e}")
                return JSONResponse(
                    status_code=500,
                    content={
                        "status": "error",
                        "message": "File upload failed due to an internal error."
                    }
                )

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

