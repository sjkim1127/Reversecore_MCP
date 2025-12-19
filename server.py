"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
It includes health and metrics endpoints for monitoring in HTTP mode.
"""

import asyncio
import re
import shutil
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import aiofiles

try:
    import magic
except ImportError:
    magic = None

from fastmcp import FastMCP

from reversecore_mcp.core.audit import AuditAction, audit_logger
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger, setup_logging
from reversecore_mcp.core.resource_manager import resource_manager

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncGenerator[None, None]:
    """
    Manage server lifecycle events.
    1. Initialize resources (DB, tools)
    2. Start background tasks (cleanup)
    3. Cleanup on shutdown
    """
    # Startup
    logger.info("🚀 Reversecore MCP Server starting...")
    settings = get_config()

    # 1. Ensure workspace exists
    try:
        settings.workspace.mkdir(parents=True, exist_ok=True)
        logger.info(f"✅ Workspace ready: {settings.workspace}")
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

    # 4. Initialize AI Memory Store
    from reversecore_mcp.core.memory import initialize_memory_store

    try:
        await initialize_memory_store()
        logger.info("✅ AI Memory store initialized")
    except Exception as e:
        logger.warning(f"⚠️ Memory store initialization failed: {e}")

    # Initialize async resources (e.g. SQLite memory)
    # This ensures "lazy" resources are ready before first request
    from reversecore_mcp.core.execution import initialize_async

    await initialize_async()
    logger.info("Async resources initialized")

    # Start cleanup task
    cleanup_task = asyncio.create_task(_cleanup_old_files())

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

    # Close AI Memory Store
    from reversecore_mcp.core.memory import get_memory_store

    try:
        memory_store = get_memory_store()
        await memory_store.close()
        logger.info("💾 AI Memory store closed")
    except Exception as e:
        logger.debug(f"Memory store close: {e}")

    # Cancel cleanup task
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    try:
        # Perform cleanup
        from reversecore_mcp.core.ghidra_manager import ghidra_manager

        ghidra_manager.close_all()

        # Cleanup temp directory if it exists
        temp_dir = settings.workspace / "tmp"
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info("Cleaned up temporary directory")

    except Exception as e:
        logger.error(f"Error during shutdown cleanup: {e}")

    # Cleanup temporary files (original logic, kept for now)
    try:
        temp_files = list(settings.workspace.glob("*.tmp"))
        temp_files.extend(settings.workspace.glob(".r2_*"))  # radare2 temp files

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


async def _cleanup_old_files():
    """Background task to delete files older than retention period."""
    settings = get_config()
    retention_seconds = settings.file_retention_minutes * 60
    logger.info(f"Started workspace cleaner (Retention: {settings.file_retention_minutes} mins)")

    while True:
        try:
            # Check every hour (or frequent enough)
            await asyncio.sleep(3600)

            workspace = settings.workspace
            if not workspace.exists():
                continue

            now = time.time()
            count = 0

            # Scan only tmp/ or uploads/ if organized, but here we scan workspace root files carefully
            # Usually safer to scan a dedicated uploads/tmp folder.
            # Assuming temporary files are in workspace root.
            # We will conservatively clean only things that look temp or explicitly marked.
            # For now, let's target the 'tmp' folder and specific file patterns if needed.

            targets = [
                workspace / "tmp",
                workspace,
            ]  # Include workspace root for files not in 'tmp'

            for target_dir in targets:
                if not target_dir.exists():
                    continue

                for p in target_dir.rglob("*"):
                    if p.is_file():
                        # Check mtime
                        if now - p.stat().st_mtime > retention_seconds:
                            # Only delete files that are clearly temporary or uploaded
                            # This is a safety measure to avoid deleting user's important files
                            if p.name.startswith(f"{uuid.UUID(int=0).hex[:8]}_") or p.suffix in [
                                ".tmp",
                                ".r2_",
                            ]:  # Placeholder for UUID prefix
                                try:
                                    p.unlink()
                                    count += 1
                                except Exception:
                                    pass

            if count > 0:
                logger.info(f"Cleaner: Removed {count} old files")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Cleaner task error: {e}")
            await asyncio.sleep(300)  # Retry sooner on error


async def _validate_file_magic(file_path: str, filename: str):
    """
    Validate file content matches extension using libmagic.

    prevents malicious renaming (e.g. malware.exe -> report.pdf).
    """
    if not magic:
        logger.warning("python-magic not installed. Skipping content validation.")
        return

    try:
        # Get MIME type from content
        mime = magic.from_file(file_path, mime=True)
        ext = filename.lower().split(".")[-1] if "." in filename else ""

        # Define suspicious mismatches
        # executing header but safe extension
        is_executable = mime in [
            "application/x-dosexec",
            "application/x-executable",
            "application/x-elf",
            "application/x-mach-binary",
        ]
        is_safe_ext = ext in [
            "txt",
            "pdf",
            "json",
            "yml",
            "yaml",
            "md",
            "csv",
            "log",
            "png",
            "jpg",
            "jpeg",
            "gif",
        ]

        if is_executable and is_safe_ext:
            logger.warning(f"SECURITY: Executable content detected in {filename} (MIME: {mime})")
            # In high security mode, we might delete it.
            # For now, log a prominent warning or rename it to .dangerous
            import os

            new_path = file_path + ".dangerous"
            os.rename(file_path, new_path)
            raise ValueError(
                f"Security Alert: File {filename} contains executable code but has safe extension. Renamed to .dangerous"
            )

    except Exception as e:
        if "Security Alert" in str(e):
            raise
        logger.warning(f"Magic validation failed for {filename}: {e}")
        # Re-raise if it's a critical validation failure, otherwise just log.
        # For now, we'll re-raise to prevent processing potentially malicious files.
        raise


# Initialize the FastMCP server with lifespan management
mcp = FastMCP(name="Reversecore_MCP", lifespan=server_lifespan)

# Register plugins dynamically
import os  # noqa: E402

from reversecore_mcp.core.loader import PluginLoader  # noqa: E402

# Initialize plugin loader
loader = PluginLoader()

# Discover and load plugins from the tools directory
# We assume tools are in the 'reversecore_mcp/tools' package
tools_dir = os.path.join(os.path.dirname(__file__), "reversecore_mcp", "tools")
if not os.path.exists(tools_dir):
    # Fallback for development environment where running from root
    tools_dir = os.path.join(os.getcwd(), "reversecore_mcp", "tools")

plugins = loader.discover_plugins(tools_dir, "reversecore_mcp.tools")

# Register each plugin with the MCP server
for plugin in plugins:
    try:
        plugin.register(mcp)
        logger.info(f"Registered plugin: {plugin.name}")
    except Exception as e:
        logger.error(f"Failed to register plugin {plugin.name}: {e}")

# Register prompts
from reversecore_mcp import prompts  # noqa: E402

prompts.register_prompts(mcp)

# Register resources (reversecore:// URIs)
from reversecore_mcp import resources  # noqa: E402

resources.register_resources(mcp)

# Register report tools for malware analysis reporting
from reversecore_mcp.tools.report.report_mcp_tools import register_report_tools  # noqa: E402

# Register report tools for malware analysis reporting

report_tools = register_report_tools(mcp)
logger.info("Registered report tools")

# ============================================================================
# Security Middleware
# ============================================================================
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.requests import Request  # noqa: E402


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response


# Access underlying FastAPI app to add middleware
# Note: FastMCP 2.13.1 exposes _fastapi_app or we can use mcp.fastapi_app if available
# Checking source or assuming standard access.
if hasattr(mcp, "_fastapi_app"):
    mcp._fastapi_app.add_middleware(SecurityHeadersMiddleware)
elif hasattr(mcp, "fastapi_app"):
    mcp.fastapi_app.add_middleware(SecurityHeadersMiddleware)

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

    from fastapi import Depends, HTTPException, Request, status
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
        from fastapi import FastAPI, File, UploadFile
        from fastapi.responses import JSONResponse

        from reversecore_mcp.core.metrics import metrics_collector

        # Setup authentication (if MCP_API_KEY is set)
        auth_dependency = setup_authentication()

        # Build a host FastAPI app with docs enabled and mount FastMCP under /mcp
        # Apply authentication to all endpoints if enabled
        dependencies = [auth_dependency] if auth_dependency else []

        mcp_app = mcp.http_app()

        # Fix: Wrap initialization in FastAPI lifespan
        @asynccontextmanager
        async def app_lifespan(app: FastAPI):
            # Run server startup logic
            async with server_lifespan(mcp):
                yield

        app = FastAPI(
            title="Reversecore_MCP",
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
            dependencies=dependencies,  # Apply authentication globally
            lifespan=app_lifespan,  # Register lifespan
        )
        app.mount("/mcp", mcp_app)

        # Add health endpoint
        @app.get("/health")
        async def health():
            """Health check endpoint with dependency status."""
            import platform
            import sys
            import time

            health_status = {
                "status": "healthy",
                "service": "Reversecore_MCP",
                "transport": "http",
                "version": "1.0.0",
                "timestamp": time.time(),
                "python_version": sys.version,
                "platform": platform.system(),
                "workspace": str(settings.workspace),
                "workspace_exists": settings.workspace.exists(),
                "dependencies": {},
            }

            # Check dependencies
            deps = health_status["dependencies"]

            # radare2
            if shutil.which("radare2"):
                deps["radare2"] = {"status": "available", "path": shutil.which("radare2")}
            else:
                deps["radare2"] = {"status": "unavailable"}
                health_status["status"] = "degraded"

            # Java (for Ghidra)
            if shutil.which("java"):
                deps["java"] = {"status": "available", "path": shutil.which("java")}
            else:
                deps["java"] = {"status": "unavailable"}

            # Graphviz
            if shutil.which("dot"):
                deps["graphviz"] = {"status": "available", "path": shutil.which("dot")}
            else:
                deps["graphviz"] = {"status": "unavailable"}

            # YARA
            if shutil.which("yara"):
                deps["yara"] = {"status": "available", "path": shutil.which("yara")}
            else:
                deps["yara"] = {"status": "unavailable"}

            # binwalk
            if shutil.which("binwalk"):
                deps["binwalk"] = {"status": "available", "path": shutil.which("binwalk")}
            else:
                deps["binwalk"] = {"status": "unavailable"}

            return JSONResponse(content=health_status)

        # Lightweight liveness probe
        @app.get("/health/live")
        async def liveness():
            """Kubernetes liveness probe endpoint."""
            return JSONResponse(content={"status": "alive"})

        # Readiness probe
        @app.get("/health/ready")
        async def readiness():
            """Kubernetes readiness probe endpoint."""
            is_ready = settings.workspace.exists() and shutil.which("radare2") is not None
            if is_ready:
                return JSONResponse(content={"status": "ready"})
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "reason": "Dependencies not available"},
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

            def _secure_filename(filename: str) -> str:
                """Sanitize filename to prevent path traversal and injection."""
                # Remove path components
                filename = filename.replace("/", "_").replace("\\", "_")
                # Remove dangerous characters, keep only safe ones
                filename = re.sub(r"[^\w\-.]", "_", filename)
                # Limit length
                if len(filename) > 200:
                    name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
                    filename = name[:195] + ("." + ext if ext else "")
                return filename or "unnamed_file"

            try:
                # Ensure workspace exists
                workspace = settings.workspace
                workspace.mkdir(parents=True, exist_ok=True)

                # SECURITY: Sanitize filename and add UUID prefix to prevent overwrites
                original_filename = file.filename or "unnamed"
                safe_filename = f"{uuid.uuid4().hex[:8]}_{_secure_filename(original_filename)}"
                file_path = workspace / safe_filename

                # PERFORMANCE: Use aiofiles for non-blocking async I/O
                # This prevents blocking the event loop during large file uploads

                async with aiofiles.open(file_path, "wb") as out_file:
                    while content := await file.read(1024 * 64):  # 64KB chunks
                        await out_file.write(content)

                # Security: Validate file content (Magic Number)
                try:
                    await _validate_file_magic(str(file_path), safe_filename)
                except Exception as e:
                    audit_logger.log_event(
                        AuditAction.FILE_UPLOAD,
                        safe_filename,
                        "FAILURE",
                        details={"error": str(e), "path": str(file_path)},
                    )
                    # Cleanup malicious file
                    try:
                        file_path.unlink()
                    except Exception:
                        pass
                    raise

                audit_logger.log_event(
                    AuditAction.FILE_UPLOAD,
                    safe_filename,
                    "SUCCESS",
                    details={"path": str(file_path)},
                )

                logger.info(f"File uploaded successfully: {safe_filename} ({file_path})")
                return JSONResponse(
                    content={
                        "status": "success",
                        "message": "File uploaded successfully",
                        # SECURITY: Don't expose absolute server paths
                        "filename": safe_filename,
                        "original_filename": original_filename,
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
            from slowapi.errors import RateLimitExceeded  # type: ignore
            from slowapi.util import get_remote_address  # type: ignore

            rate_limit = settings.rate_limit
            limiter = Limiter(key_func=get_remote_address, default_limits=[f"{rate_limit}/minute"])

            # Attach middleware and exception handler
            @app.middleware("http")
            async def rate_limit_middleware(request, call_next):  # pragma: no cover - integration
                return await limiter.middleware(request, call_next)

            app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        except ImportError:
            # slowapi unavailable: log warning as this is a security risk
            logger.warning(
                "slowapi not installed: Rate limiting is DISABLED. This is a security risk in production."
            )
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
