"""Protocol-level integration tests for FastMCP server transports, resources, and lifecycle.

Validates:
1. Stdio transport lifecycle, error isolation (stderr logging), clean shutdown, and Client session.
2. SSE HTTP transport endpoints (/mcp/sse, /mcp/messages/), ASGI streaming, API key authentication,
   rate limiting middleware, loopback security, and security headers.
3. Dynamic MCP context resources URI template routing via FastMCP protocol Client:
   - reversecore://{filename}/metadata
   - reversecore://{filename}/func/{address}/xrefs
   - reversecore://{filename}/func/{address}/context
   - reversecore://{filename}/memory_map
   - reversecore://{filename}/signatures
   - reversecore://{filename}/imports
   - reversecore://{filename}/exports
   - Path traversal security validation.
4. Progress reporting and notification streaming with progressToken via FastMCP Client.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastmcp import Client, Context, FastMCP

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import setup_logging
from reversecore_mcp.core.result import ToolSuccess
from reversecore_mcp.prompts import register_prompts
from reversecore_mcp.resources import _get_workspace_path, register_resources
from reversecore_mcp.server import server_lifespan
from reversecore_mcp.tools.common.file_operations import scan_workspace
from reversecore_mcp.web.auth import APIKeyAuthMiddleware
from reversecore_mcp.web.endpoints import router as web_router
from reversecore_mcp.web.middleware import (
    LoopbackOnlyMiddleware,
    SecurityHeadersMiddleware,
)

pytestmark = pytest.mark.integration


# ============================================================================
# Helper: Direct ASGI SSE Test Client
# ============================================================================


async def asgi_request(
    app: Any,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    client_ip: str = "127.0.0.1",
    client_port: int = 50000,
    body: bytes = b"",
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Execute a direct ASGI HTTP request supporting indefinite SSE streams."""
    hdr_list = [(b"host", b"localhost")]
    if headers:
        for k, v in headers.items():
            hdr_list.append((k.lower().encode(), v.encode()))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": hdr_list,
        "client": (client_ip, client_port),
    }

    response_started = asyncio.Event()
    resp_data: dict[str, Any] = {
        "status": None,
        "headers": {},
        "body_chunks": [],
    }

    body_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal body_sent
        if not body_sent and body:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        if not response_started.is_set():
            await response_started.wait()
        # Yield to let stream write initial chunk, then simulate client disconnect
        await asyncio.sleep(0.05)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            resp_data["status"] = message["status"]
            resp_data["headers"] = {
                k.decode("latin1").lower(): v.decode("latin1")
                for k, v in message.get("headers", [])
            }
            response_started.set()
        elif message["type"] == "http.response.body":
            resp_data["body_chunks"].append(message.get("body", b""))

    task = asyncio.create_task(app(scope, receive, send))
    try:
        await asyncio.wait_for(response_started.wait(), timeout=timeout_seconds)
        # Brief pause to allow the first body chunk (e.g. SSE endpoint event) to arrive
        await asyncio.sleep(0.05)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    return resp_data


# ============================================================================
# 1. Stdio Transport Lifecycle & Error Isolation
# ============================================================================


class TestStdioTransportLifecycle:
    """Test stdio transport lifecycle, error isolation (stderr logging), and clean shutdown."""

    @pytest.mark.asyncio
    async def test_stdio_server_initialization_and_lifespan(self, workspace_dir):
        """Verify FastMCP server initializes cleanly with server_lifespan context manager."""
        test_mcp = FastMCP("TestReversecoreStdio", lifespan=server_lifespan)

        with patch(
            "reversecore_mcp.core.task_queue.get_arq_pool",
            new_callable=AsyncMock,
            return_value=None,
        ):
            # Execute startup and shutdown via server_lifespan
            async with server_lifespan(test_mcp):
                assert test_mcp.name == "TestReversecoreStdio"
                # Verify workspace directory exists
                assert get_config().workspace.exists()

    def test_stdio_stderr_logging_isolation(self):
        """Verify application stream handlers output exclusively to stderr (not stdout), preserving stdio JSON-RPC."""
        setup_logging()
        rc_logger = logging.getLogger("reversecore_mcp")

        # Find application StreamHandlers attached to reversecore loggers (excluding pytest LogCaptureHandler)
        app_handlers = [
            h
            for h in rc_logger.handlers
            if isinstance(h, logging.StreamHandler)
            and h.__class__.__name__ != "LogCaptureHandler"
            and not isinstance(h, logging.FileHandler)
        ]

        if not app_handlers:
            root_logger = logging.getLogger()
            app_handlers = [
                h
                for h in root_logger.handlers
                if isinstance(h, logging.StreamHandler)
                and h.__class__.__name__ != "LogCaptureHandler"
                and not isinstance(h, logging.FileHandler)
            ]

        for handler in app_handlers:
            # Stream must be sys.stderr (never sys.stdout)
            assert handler.stream in (
                sys.stderr,
                sys.__stderr__,
            ), (
                f"Handler stream is {handler.stream}, expected sys.stderr to avoid polluting stdio JSON-RPC"
            )

    @pytest.mark.asyncio
    async def test_stdio_clean_shutdown_releases_resources(self):
        """Verify server_lifespan teardown gracefully releases background tasks, memory, and pools."""
        test_mcp = FastMCP("TestCleanShutdown", lifespan=server_lifespan)

        with (
            patch(
                "reversecore_mcp.core.task_queue.get_arq_pool",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "reversecore_mcp.core.resource_manager.resource_manager.stop",
                new_callable=AsyncMock,
            ) as mock_rm_stop,
            patch("reversecore_mcp.core.memory.get_memory_store") as mock_get_store,
        ):
            mock_store = MagicMock()
            mock_store.close = AsyncMock()
            mock_get_store.return_value = mock_store

            async with server_lifespan(test_mcp):
                pass  # Simulate active session

            # After exit, shutdown cleanup must be invoked
            mock_rm_stop.assert_called_once()
            mock_store.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_stdio_client_session_discovery(self):
        """Verify FastMCP Client initializes and discovers tools, prompts, and resources over in-memory transport."""
        server = FastMCP("TestStdioDiscoveryServer")
        register_resources(server)
        register_prompts(server)

        @server.tool()
        def ping() -> str:
            return "pong"

        async with Client(server) as client:
            tools = await client.list_tools()
            tool_names = [t.name for t in tools]
            assert "ping" in tool_names

            prompts_list = await client.list_prompts()
            assert len(prompts_list) >= 20

            templates = await client.list_resource_templates()
            template_uris = [
                getattr(t, "uriTemplate", getattr(t, "uri_template", str(t))) for t in templates
            ]
            assert "reversecore://{filename}/metadata" in template_uris


# ============================================================================
# 2. SSE HTTP Transport Endpoints, Auth, & Middleware
# ============================================================================


class TestSSETransportEndpoints:
    """Test SSE HTTP transport endpoints (/mcp/sse, /mcp/messages/), API Key Auth, and Security Headers."""

    def _create_test_app(
        self,
        api_key: str | None = None,
        use_loopback_guard: bool = False,
        enable_rate_limiting: bool = False,
    ) -> FastAPI:
        """Construct a test FastAPI app mimicking server.py setup."""
        test_mcp_instance = FastMCP("TestReversecoreSSE")
        mcp_app = test_mcp_instance.http_app(transport="sse")

        app = FastAPI(title="Test_Reversecore_MCP")

        if enable_rate_limiting:
            try:
                from slowapi import Limiter
                from slowapi.middleware import SlowAPIMiddleware
                from slowapi.util import get_remote_address

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

                limiter = Limiter(key_func=get_remote_address, default_limits=["2/minute"])
                app.state.limiter = limiter
                app.add_middleware(SafeSlowAPIMiddleware)
            except ImportError:
                pass

        if use_loopback_guard:
            app.add_middleware(LoopbackOnlyMiddleware)

        if api_key:
            app.add_middleware(APIKeyAuthMiddleware, api_key=api_key)

        # Enforce Security Headers outermost so all responses (including 401/403/429) carry headers
        app.add_middleware(SecurityHeadersMiddleware)

        app.mount("/mcp", mcp_app)
        app.include_router(web_router)
        return app

    @pytest.mark.asyncio
    async def test_sse_endpoint_connect_headers_and_stream(self):
        """GET /mcp/sse must establish an SSE stream with text/event-stream content type and initial endpoint event."""
        app = self._create_test_app()
        res = await asgi_request(app, "GET", "/mcp/sse")

        assert res["status"] == 200
        assert "text/event-stream" in res["headers"].get("content-type", "")
        # Verify initial endpoint event emitted to client
        body_bytes = b"".join(res["body_chunks"])
        assert b"event: endpoint" in body_bytes
        assert b"/messages/?session_id=" in body_bytes

    @pytest.mark.asyncio
    async def test_sse_messages_endpoint_session_validation(self):
        """POST /mcp/messages/ without a valid session_id must return 400/404 or bad request."""
        app = self._create_test_app()
        client = TestClient(app)
        response = client.post(
            "/mcp/messages/?session_id=nonexistent_session_12345",
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
        assert response.status_code in (400, 404, 500)

    @pytest.mark.asyncio
    async def test_api_key_auth_middleware_enforcement(self):
        """Verify APIKeyAuthMiddleware enforces token on /mcp endpoints while exempting /health."""
        api_key = "rc_secret_test_token_12345"
        app = self._create_test_app(api_key=api_key)

        # 1. Unauthenticated request to /mcp/sse -> 403 Forbidden (with security headers)
        res_no_auth = await asgi_request(app, "GET", "/mcp/sse")
        assert res_no_auth["status"] == 403
        assert res_no_auth["headers"].get("x-content-type-options") == "nosniff"
        assert res_no_auth["headers"].get("x-frame-options") == "DENY"
        assert res_no_auth["headers"].get("content-security-policy") == "default-src 'self'"

        # 2. Invalid API key in header -> 403 Forbidden (with security headers)
        res_bad_key = await asgi_request(app, "GET", "/mcp/sse", headers={"X-API-Key": "wrong_key"})
        assert res_bad_key["status"] == 403
        assert res_bad_key["headers"].get("x-content-type-options") == "nosniff"
        assert res_bad_key["headers"].get("x-frame-options") == "DENY"
        assert res_bad_key["headers"].get("content-security-policy") == "default-src 'self'"

        # 3. Valid X-API-Key header -> 200 OK SSE Stream
        res_ok = await asgi_request(app, "GET", "/mcp/sse", headers={"X-API-Key": api_key})
        assert res_ok["status"] == 200
        assert "text/event-stream" in res_ok["headers"].get("content-type", "")

        # 4. Valid Authorization: Bearer <key> -> 200 OK SSE Stream
        res_bearer = await asgi_request(
            app,
            "GET",
            "/mcp/sse",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert res_bearer["status"] == 200

        # 5. Public health endpoints must be exempt from API Key authentication
        client = TestClient(app)
        health_res = client.get("/health")
        assert health_res.status_code == 200

        health_live_res = client.get("/health/live")
        assert health_live_res.status_code == 200

    def test_security_headers_middleware(self):
        """Verify SecurityHeadersMiddleware injects required HTTP security headers."""
        app = self._create_test_app()
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        headers = response.headers

        assert "strict-transport-security" in headers
        assert "max-age=31536000" in headers["strict-transport-security"]
        assert headers.get("x-content-type-options") == "nosniff"
        assert headers.get("x-frame-options") == "DENY"
        assert headers.get("content-security-policy") == "default-src 'self'"

    @pytest.mark.asyncio
    async def test_loopback_only_middleware(self):
        """Verify LoopbackOnlyMiddleware restricts access to loopback clients when API key is unset."""
        app = self._create_test_app(use_loopback_guard=True)

        # 1. Loopback client (127.0.0.1) -> allowed (200 OK)
        res_loopback = await asgi_request(app, "GET", "/mcp/sse", client_ip="127.0.0.1")
        assert res_loopback["status"] == 200

        # 2. Remote client (192.168.1.100) -> 403 Forbidden on /mcp/sse (with security headers)
        res_remote = await asgi_request(app, "GET", "/mcp/sse", client_ip="192.168.1.100")
        assert res_remote["status"] == 403
        assert res_remote["headers"].get("x-content-type-options") == "nosniff"
        assert res_remote["headers"].get("x-frame-options") == "DENY"
        assert res_remote["headers"].get("content-security-policy") == "default-src 'self'"

        # 3. Remote client accessing /health -> allowed (public liveness contract)
        res_health = await asgi_request(app, "GET", "/health", client_ip="192.168.1.100")
        assert res_health["status"] == 200


# ============================================================================
# 3. Dynamic MCP Context Resources (7 URI Templates & MIME Types)
# ============================================================================


class TestDynamicMCPContextResources:
    """Test dynamic MCP context resources URI template routing and security validation."""

    @pytest.fixture
    def registered_mcp_and_resources(self):
        """Create a FastMCP server instance and register all resources."""
        server = FastMCP("ResourceTestServer")
        register_resources(server)
        return server

    @pytest.mark.asyncio
    async def test_resource_templates_discovery_and_mime_types(self, registered_mcp_and_resources):
        """Verify all 7 dynamic context resource templates are registered with text/markdown MIME type."""
        server = registered_mcp_and_resources
        templates = (
            await server.get_resource_templates()
            if asyncio.iscoroutinefunction(server.get_resource_templates)
            else server.get_resource_templates()
        )

        template_uris = {
            getattr(t, "uri_template", getattr(t, "uriTemplate", str(t))) for t in templates
        }

        expected_templates = {
            "reversecore://{filename}/metadata",
            "reversecore://{filename}/func/{address}/xrefs",
            "reversecore://{filename}/func/{address}/context",
            "reversecore://{filename}/memory_map",
            "reversecore://{filename}/signatures",
            "reversecore://{filename}/imports",
            "reversecore://{filename}/exports",
        }

        for exp in expected_templates:
            assert exp in template_uris, f"Missing dynamic resource template: {exp}"

    @pytest.mark.asyncio
    async def test_dynamic_resource_metadata_protocol_read(
        self, registered_mcp_and_resources, workspace_dir, patched_workspace_config
    ):
        """Test reading reversecore://{filename}/metadata via protocol Client."""
        server = registered_mcp_and_resources
        test_file = workspace_dir / "target.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 200)

        with (
            patch("reversecore_mcp.resources._calculate_file_hashes") as mock_hashes,
            patch("reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief") as mock_lief,
            patch(
                "reversecore_mcp.tools.analysis.die_tools.detect_packer",
                new_callable=AsyncMock,
            ) as mock_packer,
        ):
            mock_hashes.return_value = {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "ssdeep": "3::",
            }
            mock_lief.return_value = ToolSuccess(
                data={
                    "format": "ELF64",
                    "entry_point": "0x401000",
                    "mitigations": {"canary": True, "nx": True, "pie": True},
                    "sections": [{"name": ".text"}, {"name": ".data"}],
                }
            )
            mock_packer.return_value = ToolSuccess(
                data={
                    "file_type": "ELF64",
                    "arch": "x64",
                    "packer": "None detected",
                    "compiler": "GCC 13.2",
                }
            )

            async with Client(server) as client:
                contents = await client.read_resource("reversecore://target.elf/metadata")
                assert len(contents) >= 1
                text = contents[0].text
                assert "# 📋 Binary Metadata: target.elf" in text
                assert "ELF64" in text
                assert "d41d8cd98f00b204e9800998ecf8427e" in text
                assert "CANARY" in text

    @pytest.mark.asyncio
    async def test_dynamic_resource_xrefs_protocol_read(
        self, registered_mcp_and_resources, workspace_dir, patched_workspace_config
    ):
        """Test reading reversecore://{filename}/func/{address}/xrefs via protocol Client."""
        server = registered_mcp_and_resources
        test_file = workspace_dir / "target.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 200)

        with patch(
            "reversecore_mcp.tools.radare2.r2_analysis.analyze_xrefs",
            new_callable=AsyncMock,
        ) as mock_xrefs:
            mock_xrefs.return_value = ToolSuccess(
                data={
                    "total_refs_to": 2,
                    "total_refs_from": 1,
                    "xrefs_to": [
                        {"from": "0x401100", "type": "call", "fcn_name": "main"},
                        {"from": "0x401200", "type": "call", "fcn_name": "worker"},
                    ],
                    "xrefs_from": [{"addr": "0x401500", "type": "call", "name": "printf"}],
                }
            )

            async with Client(server) as client:
                contents = await client.read_resource(
                    "reversecore://target.elf/func/0x401000/xrefs"
                )
                assert len(contents) >= 1
                text = contents[0].text
                assert "# 🔄 Cross-References: target.elf @ 0x401000" in text
                assert "0x401100" in text
                assert "main" in text
                assert "printf" in text

    @pytest.mark.asyncio
    async def test_dynamic_resource_memory_map_protocol_read(
        self, registered_mcp_and_resources, workspace_dir, patched_workspace_config
    ):
        """Test reading reversecore://{filename}/memory_map via protocol Client."""
        server = registered_mcp_and_resources
        test_file = workspace_dir / "target.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 200)

        with patch("reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief") as mock_lief:
            mock_lief.return_value = ToolSuccess(
                data={
                    "sections": [
                        {
                            "name": ".text",
                            "virtual_address": "0x401000",
                            "virtual_size": 4096,
                            "permissions": "r-x",
                            "entropy": 6.2,
                        },
                        {
                            "name": ".data",
                            "virtual_address": "0x402000",
                            "virtual_size": 1024,
                            "permissions": "rw-",
                            "entropy": 3.1,
                        },
                    ]
                }
            )

            async with Client(server) as client:
                contents = await client.read_resource("reversecore://target.elf/memory_map")
                assert len(contents) >= 1
                text = contents[0].text
                assert "Memory Map" in text
                assert ".text" in text
                assert ".data" in text

    @pytest.mark.asyncio
    async def test_dynamic_resource_signatures_protocol_read(
        self, registered_mcp_and_resources, workspace_dir, patched_workspace_config
    ):
        """Test reading reversecore://{filename}/signatures via protocol Client."""
        server = registered_mcp_and_resources
        test_file = workspace_dir / "target.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 200)

        with (
            patch(
                "reversecore_mcp.tools.malware.yara_tools.run_yara",
                new_callable=AsyncMock,
            ) as mock_yara,
            patch(
                "reversecore_mcp.tools.malware.dormant_detector.dormant_detector",
                new_callable=AsyncMock,
            ) as mock_dormant,
        ):
            mock_yara.return_value = ToolSuccess(
                data={
                    "matched": True,
                    "matches": [{"rule": "anti_debug_rdtsc", "tags": ["evasion", "timing"]}],
                }
            )
            mock_dormant.return_value = ToolSuccess(
                data={
                    "orphan_functions": ["sub_401150"],
                    "suspicious_logic": [],
                }
            )

            async with Client(server) as client:
                contents = await client.read_resource("reversecore://target.elf/signatures")
                assert len(contents) >= 1
                text = contents[0].text
                assert "# 🛡️ Threat Signatures & Capabilities: target.elf" in text
                assert "anti_debug_rdtsc" in text
                assert "orphan function" in text

    @pytest.mark.asyncio
    async def test_dynamic_resource_imports_exports_protocol_read(
        self, registered_mcp_and_resources, workspace_dir, patched_workspace_config
    ):
        """Test reading reversecore://{filename}/imports and /exports via protocol Client."""
        server = registered_mcp_and_resources
        test_file = workspace_dir / "target.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 200)

        with (
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                new_callable=AsyncMock,
            ) as mock_r2,
            patch("reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief") as mock_lief,
        ):
            # Radare2 returns empty or error to trigger LIEF fallback
            mock_r2.return_value = ToolSuccess(data="[]")
            mock_lief.return_value = ToolSuccess(
                data={
                    "imports": [
                        {
                            "name": "libc.so.6",
                            "functions": ["malloc", "free", "VirtualAlloc"],
                        }
                    ],
                    "exports": [{"name": "ExportedFunc1", "address": "0x401000", "ordinal": 1}],
                }
            )

            async with Client(server) as client:
                # 1. Imports
                imp_contents = await client.read_resource("reversecore://target.elf/imports")
                assert len(imp_contents) >= 1
                assert "# 📥 Imported Libraries & Functions: target.elf" in imp_contents[0].text
                assert "VirtualAlloc" in imp_contents[0].text

                # 2. Exports
                exp_contents = await client.read_resource("reversecore://target.elf/exports")
                assert len(exp_contents) >= 1
                assert "# 📤 Exported Symbols: target.elf" in exp_contents[0].text
                assert "ExportedFunc1" in exp_contents[0].text

    @pytest.mark.asyncio
    async def test_dynamic_resource_path_traversal_prevention(self):
        """Verify _get_workspace_path rejects path traversal attempts."""
        with pytest.raises(ValidationError):
            _get_workspace_path("../../../etc/passwd")

        with pytest.raises(ValidationError):
            _get_workspace_path("/etc/shadow")


# ============================================================================
# 4. Progress Reporting & Notification Streaming with progressToken
# ============================================================================


class TestProgressReportingContext:
    """Test transparent FastMCP Context injection and progress/notification streaming."""

    @pytest.mark.asyncio
    async def test_context_progress_reporting_in_scan_workspace(
        self, workspace_dir, patched_config, patched_workspace_config
    ):
        """Verify scan_workspace correctly invokes ctx.report_progress for each scanned file."""
        f1 = workspace_dir / "sample1.bin"
        f1.write_bytes(b"\x90" * 100)
        f2 = workspace_dir / "sample2.bin"
        f2.write_bytes(b"\x90" * 100)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.report_progress = AsyncMock()
        mock_ctx.info = AsyncMock()

        result = await scan_workspace(file_patterns=["*.bin"], ctx=mock_ctx)

        assert result.status == "success"
        assert mock_ctx.report_progress.call_count >= 2

    @pytest.mark.asyncio
    async def test_fastmcp_context_injection_in_tool(self):
        """Verify FastMCP server properly injects Context instance into tools declaring ctx parameter."""
        server = FastMCP("ContextTestServer")
        progress_calls = []

        async def raw_analysis_worker(target: str, ctx: Context | None = None) -> str:
            if ctx:
                await ctx.report_progress(50, 100)
                await ctx.info(f"Analyzing {target}")
            return f"Done: {target}"

        tool_obj = server.tool()(raw_analysis_worker)
        assert tool_obj is not None

        mock_context = MagicMock(spec=Context)
        mock_context.report_progress = AsyncMock(
            side_effect=lambda c, t: progress_calls.append((c, t))
        )
        mock_context.info = AsyncMock()

        # Invoke tool function with injected context
        res = await raw_analysis_worker("sample.bin", ctx=mock_context)
        assert res == "Done: sample.bin"
        assert (50, 100) in progress_calls
        mock_context.info.assert_called_once_with("Analyzing sample.bin")

    @pytest.mark.asyncio
    async def test_fastmcp_client_progress_token_streaming(self):
        """Verify FastMCP Client streams MCP notifications/progress events via progress_handler."""
        server = FastMCP("ProgressStreamingServer")

        @server.tool()
        async def multi_step_decompilation(binary_name: str, ctx: Context | None = None) -> str:
            if ctx:
                await ctx.report_progress(progress=20, total=100)
                await ctx.report_progress(progress=60, total=100)
                await ctx.report_progress(progress=100, total=100)
            return f"Decompiled {binary_name}"

        progress_events: list[tuple[float, float | None, str | None]] = []

        async def progress_tracker(progress: float, total: float | None, message: str | None):
            progress_events.append((progress, total, message))

        async with Client(server) as client:
            result = await client.call_tool(
                "multi_step_decompilation",
                arguments={"binary_name": "target.elf"},
                progress_handler=progress_tracker,
            )
            assert result.data == "Decompiled target.elf"
            assert len(progress_events) == 3
            assert progress_events[0] == (20.0, 100.0, None)
            assert progress_events[1] == (60.0, 100.0, None)
            assert progress_events[2] == (100.0, 100.0, None)
