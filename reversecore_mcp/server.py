"""
Reversecore_MCP Server

This module initializes the FastMCP server and registers all available tools.
It includes health and metrics endpoints for monitoring in HTTP mode.
"""

import asyncio
import re
import shutil
import stat
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastmcp import FastMCP

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger, setup_logging
from reversecore_mcp.core.resource_manager import resource_manager
from reversecore_mcp.core.security import invalidate_path_cache

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

    # Note: Async resources are initialized lazily when first accessed
    logger.info("Async resources ready")

    # 5. Discover and activate extension plugins
    from reversecore_mcp.core.extension_registry import get_extension_registry

    _ext_registry = get_extension_registry()
    _ext_registry.discover_all()
    ext_summary = _ext_registry.list_extensions()
    if ext_summary["r2"] or ext_summary["ghidra"]:
        logger.info(
            "✅ Extension plugins active — R2: %s | Ghidra: %s",
            ext_summary["r2"] or "none",
            ext_summary["ghidra"] or "none",
        )
    else:
        logger.info(
            "ℹ️  No extension plugins registered (add via REVERSECORE_PLUGIN_DIRS or entry_points)"
        )

    # Start cleanup task
    cleanup_task = asyncio.create_task(_cleanup_old_files())

    # Start embedded task queue worker if queue is enabled
    from arq.worker import Worker

    from reversecore_mcp.core.task_queue import WorkerSettings, get_arq_pool

    pool = await get_arq_pool()
    worker = None
    worker_task = None
    if pool is not None:
        try:
            worker = Worker(
                functions=WorkerSettings.functions,  # type: ignore[arg-type]
                redis_pool=pool,
                handle_signals=False,
            )
            worker_task = asyncio.create_task(worker.async_run())
            logger.info("✅ Embedded ARQ task queue worker started successfully.")
        except Exception as e:
            logger.warning(f"⚠️ Failed to start embedded task queue worker: {e}")

    # ============================================================================
    # SERVER RUNNING (yield control)
    # ============================================================================
    yield

    # ============================================================================
    # SHUTDOWN
    # ============================================================================
    logger.info("🛑 Reversecore MCP Server shutting down...")

    # Close task queue worker and pools
    if worker is not None:
        try:
            await worker.close()
            logger.info("Embedded ARQ worker stopped.")
        except Exception as e:
            logger.debug(f"Error stopping ARQ worker: {e}")

    if worker_task is not None:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass

    from reversecore_mcp.core.task_queue import close_arq_pool

    try:
        await close_arq_pool()
    except Exception as e:
        logger.debug(f"Error closing ARQ pool: {e}")

    from reversecore_mcp.core.analysis_cache import close_redis

    try:
        await close_redis()
    except Exception as e:
        logger.debug(f"Error closing Redis: {e}")

    # Stop Resource Manager
    try:
        await resource_manager.stop()
    except Exception as e:
        logger.debug(f"Error stopping Resource Manager: {e}")

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
        # Stop and cleanup plugins explicitly
        for plugin in plugins:
            if hasattr(plugin, "cleanup"):
                try:
                    await plugin.cleanup()
                except Exception as e:
                    logger.debug(f"Error during {plugin.name} cleanup: {e}")

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

            # Only scan tmp folder - never touch user's analysis files in workspace root
            # This prevents accidental deletion of important binary files
            targets = [workspace / "tmp", workspace / "uploads"]

            for target_dir in targets:
                if not target_dir.exists():
                    continue

                for p in target_dir.rglob("*"):
                    # Use a single stat() call: S_ISREG checks for regular file,
                    # avoiding a separate is_file() syscall followed by stat().
                    try:
                        st = p.stat()
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    # Check mtime
                    if now - st.st_mtime > retention_seconds:
                        # Only delete files that are clearly temporary or uploaded
                        # This is a safety measure to avoid deleting user's important files
                        # Match UUID-prefixed uploads (8 hex chars followed by underscore)
                        is_uuid_upload = bool(re.match(r"^[0-9a-f]{8}_", p.name))
                        # Match temp files (.tmp suffix or .r2_* prefix for radare2)
                        is_temp = p.suffix == ".tmp" or p.name.startswith(".r2_")

                        if is_uuid_upload or is_temp:
                            is_in_use = False
                            try:
                                for plugin in plugins:
                                    if plugin.name == "radare2_mcp_tools":
                                        file_to_session = getattr(plugin, "_file_to_session", None)
                                        if (
                                            isinstance(file_to_session, dict)
                                            and str(p) in file_to_session
                                        ):
                                            is_in_use = True
                                            break
                            except Exception as e:
                                logger.debug(f"Error checking plugin sessions: {e}")

                            if is_in_use:
                                try:
                                    import os

                                    os.utime(
                                        p, None
                                    )  # Update mtime to prevent repeated cleanup warnings
                                except Exception:
                                    pass
                                continue

                            try:
                                p.unlink()
                                invalidate_path_cache()
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


# Initialize the FastMCP server with lifespan management
mcp = FastMCP(name="Reversecore_MCP", lifespan=server_lifespan)

# Register plugins dynamically
import os  # noqa: E402

from reversecore_mcp.core.loader import PluginLoader  # noqa: E402

# Initialize plugin loader
loader = PluginLoader()

# Discover and load plugins from the tools directory
# We assume tools are in the 'reversecore_mcp/tools' package
tools_dir = Path(__file__).resolve().parent / "tools"

plugins = loader.discover_plugins(str(tools_dir), "reversecore_mcp.tools")

# Register each plugin with the MCP server
for plugin in plugins:
    try:
        plugin.register(mcp)
        logger.info(f"Registered plugin: {plugin.name}")
    except Exception as e:
        logger.error(f"Failed to register plugin {plugin.name}: {e}")

# Register extension plugin tools (dynamically contributed by R2/Ghidra extensions)
# Note: discover_all() runs at server startup (lifespan), but we pre-call here
# so tools are available before the first request.
try:
    from reversecore_mcp.core.extension_registry import (
        get_extension_registry as _get_ext_reg,
    )

    _ext_reg = _get_ext_reg()
    _ext_reg.discover_all()  # idempotent — safe to call before lifespan too
    for _ext_tool in _ext_reg.get_all_extension_tools():
        try:
            mcp.tool()(_ext_tool)
            logger.info(f"Registered extension tool: {_ext_tool.__name__}")
        except Exception as _tool_err:
            logger.error(f"Failed to register extension tool {_ext_tool}: {_tool_err}")
except Exception as _ext_err:
    logger.warning(f"⚠️ Extension tool registration skipped: {_ext_err}")


# Register prompts
from reversecore_mcp import prompts  # noqa: E402

prompts.register_prompts(mcp)

# Register resources (reversecore:// URIs)
from reversecore_mcp import resources  # noqa: E402

resources.register_resources(mcp)

# Report tools are dynamically registered via ReportToolsPlugin in loader.py

# Register task queue get_job_result tool
from reversecore_mcp.core.task_queue import get_job_result  # noqa: E402

mcp.tool()(get_job_result)
logger.info("Registered get_job_result tool")


# ============================================================================
# Security & Authentication Middleware
# ============================================================================
from reversecore_mcp.web.auth import APIKeyAuthMiddleware  # noqa: E402
from reversecore_mcp.web.middleware import (  # noqa: E402
    LoopbackOnlyMiddleware,
    SecurityHeadersMiddleware,
)


def main():
    """Run the MCP server."""
    # Get transport mode from settings (default: stdio)
    settings = get_config()

    # Validate paths at startup
    try:
        settings.validate_paths(strict=False)
        logger.info("Path validation successful")
    except ValueError as e:
        logger.error(f"Path validation failed: {e}")
        raise

    transport = settings.mcp_transport.lower()

    if transport in ("http", "sse", "streamable-http"):
        # HTTP transport mode for network-based AI agents
        import uvicorn
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware

        from reversecore_mcp.web.endpoints import router as web_router

        # Setup authentication (if MCP_API_KEY is set)
        api_key = settings.api_key
        host = settings.host
        use_loopback_guard = False

        # Safe Bind Address Fallback (P0)
        if not api_key:
            if host != "127.0.0.1" and host != "localhost":
                if Path("/.dockerenv").exists():
                    logger.warning(
                        f"⚠️ Container binding to '{host}' without an API key. "
                        "Only public health endpoints and loopback clients will be allowed."
                    )
                    use_loopback_guard = True
                else:
                    logger.warning(
                        f"⚠️ Safety warning: Binding to external interface '{host}' without an API key is unsafe. "
                        "Overriding host binding to 127.0.0.1 (loopback) to prevent unauthorized access."
                    )
                    host = "127.0.0.1"

        mcp_app = mcp.http_app(transport="sse")

        # Wrap initialization in FastAPI lifespan
        @asynccontextmanager
        async def app_lifespan(app: FastAPI):
            async with mcp._lifespan_manager():
                yield

        app = FastAPI(
            title="Reversecore_MCP",
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
            lifespan=app_lifespan,
        )

        # Container health probes may be external, but all other unauthenticated
        # traffic must still originate from the container loopback interface.
        if use_loopback_guard:
            app.add_middleware(LoopbackOnlyMiddleware)

        # Enforce API Key globally if set (including on mounted sub-apps)
        if api_key:
            app.add_middleware(APIKeyAuthMiddleware, api_key=api_key)

        # Enforce Security Headers outermost so all responses (including 401/403 auth errors) carry headers
        app.add_middleware(SecurityHeadersMiddleware)

        app.mount("/mcp", mcp_app)
        app.include_router(web_router)

        # Add CORS middleware with restricted origins when API Key is set
        allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
        allowed_origins_env = os.getenv("ALLOWED_ORIGINS")
        if allowed_origins_env:
            allowed_origins = allowed_origins_env.split(",")
        elif not api_key:
            allowed_origins = ["*"]

        allow_creds = "*" not in allowed_origins

        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=allow_creds,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Mount dashboard
        try:
            from reversecore_mcp.dashboard import get_router, get_static_files

            app.include_router(get_router())
            app.mount("/dashboard/static", get_static_files(), name="dashboard_static")
            logger.info("📊 Dashboard available at /dashboard/")
        except ImportError as e:
            logger.warning(f"Dashboard not available: {e}")

        # Optional: apply rate limiting if slowapi is available
        try:
            from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore
            from slowapi.errors import RateLimitExceeded  # type: ignore
            from slowapi.middleware import SlowAPIMiddleware  # type: ignore
            from slowapi.util import get_remote_address  # type: ignore

            class SafeSlowAPIMiddleware:
                def __init__(self, app_arg):
                    self.slowapi_middleware = SlowAPIMiddleware(app_arg)
                    self.app = app_arg

                async def __call__(self, scope, receive, send):
                    path = scope.get("path", "")
                    if scope["type"] == "http" and (
                        path == "/mcp/sse" or path == "/mcp/sse/" or path.startswith("/mcp/sse")
                    ):
                        await self.app(scope, receive, send)
                    else:
                        await self.slowapi_middleware(scope, receive, send)

            rate_limit = settings.rate_limit
            limiter = Limiter(key_func=get_remote_address, default_limits=[f"{rate_limit}/minute"])
            app.state.limiter = limiter
            app.add_middleware(SafeSlowAPIMiddleware)
            app.add_exception_handler(
                RateLimitExceeded,
                _rate_limit_exceeded_handler,  # type: ignore[arg-type]
            )
            logger.info(f"Rate limiting enabled: {rate_limit}/minute")
        except ImportError:
            _strict = os.getenv("REVERSECORE_RATE_LIMIT_STRICT", "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            if _strict:
                raise RuntimeError(
                    "REVERSECORE_RATE_LIMIT_STRICT=true but slowapi is not installed. "
                    "Install it with: pip install 'reversecore-mcp[http]'"
                )
            logger.warning(
                "slowapi not installed: Rate limiting is DISABLED. "
                "Set REVERSECORE_RATE_LIMIT_STRICT=true to treat this as a fatal error, "
                "or install with: pip install 'reversecore-mcp[http]'"
            )
        except Exception as e:
            logger.warning(f"Failed to setup rate limiting: {e}")

        # Run uvicorn with the FastMCP HTTP app
        uvicorn.run(app, host=host, port=settings.port, workers=1)
    else:
        # Stdio transport mode for local AI clients (default)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
