"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
It includes health and metrics endpoints for monitoring in HTTP mode.
"""

from fastmcp import FastMCP
from contextlib import asynccontextmanager
import shutil

from reversecore_mcp.core.logging_config import setup_logging, get_logger
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.resource_manager import resource_manager

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def server_lifespan(server: FastMCP):
    """
    Manage server lifecycle events.

    Startup:
        - Validate dependencies (radare2, java, etc.)
        - Ensure workspace directory exists
        - Initialize metrics collector

    Shutdown:
        - Cleanup temporary files
        - Log final statistics
    """
    # ============================================================================
    # STARTUP
    # ============================================================================
    logger.info("🚀 Reversecore MCP Server starting...")

    config = get_config()

    # 1. Ensure workspace exists
    try:
        config.workspace.mkdir(parents=True, exist_ok=True)
        logger.info(f"✅ Workspace ready: {config.workspace}")
    except Exception as e:
        logger.error(f"❌ Failed to create workspace: {e}")
        raise

    # 2. Check critical dependencies
    dependencies_ok = True

    # Check radare2
    if not shutil.which("radare2"):
        logger.warning("⚠️ radare2 not found in PATH")
        dependencies_ok = False
    else:
        logger.info("✅ radare2 found")

    # Check Java (for Ghidra)
    if not shutil.which("java"):
        logger.warning("⚠️ Java not found - Ghidra decompilation unavailable")
    else:
        logger.info("✅ Java found")

    # Check graphviz (for PNG CFG generation)
    if not shutil.which("dot"):
        logger.warning("⚠️ graphviz not found - PNG CFG generation unavailable")
    else:
        logger.info("✅ graphviz found")

    if not dependencies_ok:
        logger.warning("⚠️ Some dependencies missing, functionality may be limited")

    logger.info("✅ Server startup complete")

    # 3. Start Resource Manager
    await resource_manager.start()

    # ============================================================================
    # SERVER RUNNING (yield control)
    # ============================================================================
    yield

    # ============================================================================
    # SHUTDOWN
    # ============================================================================
    logger.info("🛑 Reversecore MCP Server shutting down...")

    # Stop Resource Manager
    await resource_manager.stop()

    # Cleanup temporary files
    try:
        temp_files = list(config.workspace.glob("*.tmp"))
        temp_files.extend(config.workspace.glob(".r2_*"))  # radare2 temp files

        for temp_file in temp_files:
            try:
                temp_file.unlink()
                logger.debug(f"Cleaned up: {temp_file.name}")
            except (OSError, FileNotFoundError) as e:
                logger.debug(f"Could not remove temp file {temp_file.name}: {e}")

        if temp_files:
            logger.info(f"🧹 Cleaned up {len(temp_files)} temporary files")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

    logger.info("👋 Server shutdown complete")


# Initialize the FastMCP server with lifespan management
mcp = FastMCP(name="Reversecore_MCP", lifespan=server_lifespan)

# Register all tool modules
from reversecore_mcp.tools import (  # noqa: E402
    cli_tools,
    lib_tools,
    ghost_trace,
    neural_decompiler,
    adaptive_vaccine,
    trinity_defense,
)

cli_tools.register_cli_tools(mcp)
lib_tools.register_lib_tools(mcp)
ghost_trace.register_ghost_trace(mcp)
neural_decompiler.register_neural_decompiler(mcp)
adaptive_vaccine.register_adaptive_vaccine(mcp)
trinity_defense.register_trinity_defense(mcp)

# Register prompts
from reversecore_mcp import prompts  # noqa: E402

prompts.register_prompts(mcp)

# Register resources (reversecore:// URIs)
from reversecore_mcp import resources  # noqa: E402

resources.register_resources(mcp)

# ============================================================================
# Server Composition (Mounting Sub-servers)
# ============================================================================
# If you have specialized sub-servers (e.g., Ghidra-only, Dynamic-analysis-only),
# you can mount them here to create a unified platform:
#
# Example:
#   from ghidra_server import ghidra_mcp
#   mcp.mount("ghidra", ghidra_mcp)
#
# Now clients can access ghidra tools with prefix: ghidra.tool_name
# This allows microservice-style architecture for large deployments.
# ============================================================================


# ============================================================================
# Authentication (HTTP mode only)
# ============================================================================
def setup_authentication():
    """
    Setup API Key authentication for HTTP transport mode.

    To enable authentication, set environment variable:
        MCP_API_KEY=your-secret-key

    All HTTP requests must include header:
        X-API-Key: your-secret-key
    """
    import os
    from fastapi import Depends, HTTPException, status, Request
    from fastapi.security import APIKeyHeader

    api_key = os.getenv("MCP_API_KEY")

    if not api_key:
        logger.info("🔓 API Key authentication disabled (MCP_API_KEY not set)")
        return None

    logger.info("🔐 API Key authentication enabled")

    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def verify_api_key(request: Request, key: str = Depends(api_key_header)):
        # Allow health endpoint without authentication
        if request.url.path == "/health":
            return

        if key != api_key:
            logger.warning(f"⚠️ Unauthorized access attempt from {request.client.host}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing API key",
            )
        return key

    return Depends(verify_api_key)


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

        # Setup authentication (if MCP_API_KEY is set)
        auth_dependency = setup_authentication()

        # Build a host FastAPI app with docs enabled and mount FastMCP under /mcp
        # Apply authentication to all endpoints if enabled
        dependencies = [auth_dependency] if auth_dependency else []

        app = FastAPI(
            title="Reversecore_MCP",
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
            dependencies=dependencies,  # Apply authentication globally
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
                    "transport": "http",
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
                        "message": "File uploaded successfully",
                        "file_path": str(file_path),
                        "workspace_path": str(file_path),
                        "filename": file.filename,
                        "size": file_path.stat().st_size,
                    }
                )
            except Exception as e:
                logger.error(f"File upload failed: {e}")
                return JSONResponse(
                    status_code=500,
                    content={
                        "status": "error",
                        "message": "File upload failed due to an internal error.",
                    },
                )

        # Optional: apply rate limiting if slowapi is available
        try:
            from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore
            from slowapi.util import get_remote_address  # type: ignore
            from slowapi.errors import RateLimitExceeded  # type: ignore

            rate_limit = settings.rate_limit
            limiter = Limiter(
                key_func=get_remote_address, default_limits=[f"{rate_limit}/minute"]
            )

            # Attach middleware and exception handler
            @app.middleware("http")
            async def rate_limit_middleware(
                request, call_next
            ):  # pragma: no cover - integration
                return await limiter.middleware(request, call_next)

            app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        except ImportError:
            # slowapi unavailable: skip gracefully
            logger.debug("slowapi not installed, rate limiting disabled")
        except Exception as e:
            # Version mismatch or other error
            logger.warning(f"Failed to setup rate limiting: {e}")

        # Run uvicorn with the FastMCP HTTP app
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        # Stdio transport mode for local AI clients (default)
        # Rate limiting not needed for stdio mode (single client)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
