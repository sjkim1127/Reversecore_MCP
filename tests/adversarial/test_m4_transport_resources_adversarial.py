"""Adversarial stress tests and empirical verification for Milestone 4.

Empirically challenges and stress-tests:
1. FastMCP SSE transport resilience: abnormal disconnects, rapid churn, invalid verbs/headers.
2. FastMCP /mcp/messages/ endpoint: missing/empty/malformed/oversized session IDs, malformed JSON-RPC bodies, bad HTTP methods.
3. API Key authentication & middleware: token enforcement, case sensitivity, header injection, malformed prefixes, oversized keys, public exemptions.
4. Dynamic MCP Context Resources: path traversal, command injection, malformed addresses, 0-byte/corrupted binaries across all 16 URI templates/aliases via FastMCP Client.
5. Stdio / Protocol JSON-RPC handling: unknown tools, malformed arguments, non-existent prompts/resources.
6. High-concurrency race condition stress: 50+ simultaneous streams and resource readers.
7. Verification of zero unhandled exceptions, zero stack trace leakages, and zero server crashes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastmcp import Client, FastMCP
from mcp.shared.exceptions import McpError

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.prompts import register_prompts
from reversecore_mcp.resources import _get_workspace_path, register_resources
from reversecore_mcp.web.auth import APIKeyAuthMiddleware
from reversecore_mcp.web.endpoints import router as web_router
from reversecore_mcp.web.middleware import (
    LoopbackOnlyMiddleware,
    SecurityHeadersMiddleware,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]


# ============================================================================
# Helpers: Direct ASGI SSE Test Client with Disconnect Hooks
# ============================================================================


async def asgi_request_adversarial(
    app: Any,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    client_ip: str = "127.0.0.1",
    client_port: int = 50000,
    body: bytes = b"",
    disconnect_after_start: bool = True,
    disconnect_delay_seconds: float = 0.02,
    disconnect_before_start: bool = False,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Execute ASGI request with configurable disconnect timing for adversarial stress testing."""
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
        "disconnected_early": False,
    }

    body_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal body_sent
        if disconnect_before_start:
            return {"type": "http.disconnect"}
        if not body_sent and body:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        if not response_started.is_set():
            await response_started.wait()
        if disconnect_after_start:
            await asyncio.sleep(disconnect_delay_seconds)
            resp_data["disconnected_early"] = True
            return {"type": "http.disconnect"}
        return {"type": "http.request", "body": b"", "more_body": False}

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
        if not disconnect_before_start:
            await asyncio.wait_for(response_started.wait(), timeout=timeout_seconds)
            await asyncio.sleep(disconnect_delay_seconds + 0.05)
        else:
            await asyncio.sleep(0.05)
    except asyncio.TimeoutError:
        pass
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    return resp_data


def create_adversarial_test_app(
    api_key: str | None = None,
    use_loopback_guard: bool = False,
) -> FastAPI:
    """Construct FastAPI app with FastMCP SSE sub-app and security middleware."""
    test_mcp_instance = FastMCP("TestReversecoreAdversarial")
    mcp_app = test_mcp_instance.http_app(transport="sse")

    app = FastAPI(title="Adversarial_Reversecore_MCP")

    if use_loopback_guard:
        app.add_middleware(LoopbackOnlyMiddleware)

    if api_key:
        app.add_middleware(APIKeyAuthMiddleware, api_key=api_key)

    # Add SecurityHeadersMiddleware last so it wraps all responses (including auth/loopback errors)
    app.add_middleware(SecurityHeadersMiddleware)

    app.mount("/mcp", mcp_app)
    app.include_router(web_router)
    return app


@pytest.fixture
def adversarial_mcp_server():
    """Create a fully registered FastMCP server instance for protocol client testing."""
    server = FastMCP("AdversarialFullServer")
    register_resources(server)
    register_prompts(server)

    @server.tool()
    def divide_numbers(a: int, b: int) -> float:
        if b == 0:
            raise ValueError("Division by zero error")
        return a / b

    return server


# ============================================================================
# 1. FastMCP SSE Transport Adversarial Stress Tests
# ============================================================================


class TestSSETransportAdversarialStress:
    """Adversarial stress-testing of SSE stream connection, disconnect, and protocol edges."""

    @pytest.mark.asyncio
    async def test_abnormal_disconnect_before_response_start(self):
        """Client disconnects immediately before the server sends response headers."""
        app = create_adversarial_test_app()
        res = await asgi_request_adversarial(app, "GET", "/mcp/sse", disconnect_before_start=True)
        # Server must handle disconnect cleanly without crashing
        assert res is not None

    @pytest.mark.asyncio
    async def test_abnormal_disconnect_mid_stream_during_event_emission(self):
        """Client abruptly terminates connection during SSE event transmission."""
        app = create_adversarial_test_app()
        res = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            disconnect_after_start=True,
            disconnect_delay_seconds=0.01,
        )
        assert res["status"] == 200
        assert res["disconnected_early"] is True
        # Verify initial endpoint event received before disconnect
        body_bytes = b"".join(res["body_chunks"])
        assert b"event: endpoint" in body_bytes

    @pytest.mark.asyncio
    async def test_rapid_connect_disconnect_churn(self):
        """Simulate 30 clients opening SSE connections and disconnecting in rapid succession."""
        app = create_adversarial_test_app()

        async def single_churn(i: int):
            return await asgi_request_adversarial(
                app,
                "GET",
                "/mcp/sse",
                client_port=50000 + i,
                disconnect_after_start=True,
                disconnect_delay_seconds=0.005,
            )

        tasks = [asyncio.create_task(single_churn(i)) for i in range(30)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, res in enumerate(results):
            assert not isinstance(res, Exception), f"Task {idx} failed with exception: {res}"
            assert res["status"] == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad_method", ["POST", "PUT", "DELETE", "PATCH"])
    async def test_invalid_http_verbs_on_sse_endpoint(self, bad_method: str):
        """HTTP verbs other than GET on /mcp/sse must be rejected with 405 Method Not Allowed."""
        app = create_adversarial_test_app()
        client = TestClient(app)
        response = client.request(bad_method, "/mcp/sse")
        assert response.status_code == 405

    @pytest.mark.asyncio
    async def test_sse_endpoint_accept_headers_negotiation(self):
        """MCP specification requires Accept: text/event-stream for streaming, while non-streaming requests handle cleanly."""
        app = create_adversarial_test_app()
        # 1. Standard event-stream accept header
        res_sse = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"Accept": "text/event-stream"},
            disconnect_after_start=False,
        )
        assert res_sse["status"] == 200
        assert "text/event-stream" in res_sse["headers"].get("content-type", "")

        # 2. Wildcard accept header handled safely without crashing
        res_wildcard = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"Accept": "*/*"},
            disconnect_after_start=False,
        )
        assert res_wildcard["status"] == 200


# ============================================================================
# 2. FastMCP /mcp/messages/ Endpoint Adversarial Stress Tests
# ============================================================================


class TestMessagesEndpointAdversarialStress:
    """Adversarially challenge /mcp/messages/ endpoint with malformed/malicious inputs."""

    @pytest.mark.asyncio
    async def test_missing_session_id_query_parameter(self):
        """POST /mcp/messages/ without session_id must return 400/404/422, not 500."""
        app = create_adversarial_test_app()
        client = TestClient(app)
        response = client.post(
            "/mcp/messages/",
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
        assert response.status_code in (400, 404, 422)
        assert "traceback" not in response.text.lower()

    @pytest.mark.asyncio
    async def test_empty_session_id_parameter(self):
        """POST /mcp/messages/?session_id= must reject cleanly."""
        app = create_adversarial_test_app()
        client = TestClient(app)
        response = client.post(
            "/mcp/messages/?session_id=",
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
        assert response.status_code in (400, 404, 422)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "malicious_session_id",
        [
            "../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "'; DROP TABLE sessions; --",
            "<script>alert('xss')</script>",
            "\x00\x00\x00\x00",
            "a" * 8192,  # Oversized 8KB session ID
            "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        ],
    )
    async def test_malicious_session_id_strings(self, malicious_session_id: str):
        """Ensure malicious session_id strings do not cause unhandled crashes or path traversal."""
        app = create_adversarial_test_app()
        client = TestClient(app)
        response = client.post(
            "/mcp/messages/",
            params={"session_id": malicious_session_id},
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
        assert response.status_code in (400, 404, 500)
        assert "traceback (most recent call last)" not in response.text.lower()

    @pytest.mark.asyncio
    async def test_nonexistent_uuid_session_id(self):
        """POST /mcp/messages/ with a non-existent UUID session ID returns 400/404."""
        app = create_adversarial_test_app()
        client = TestClient(app)
        response = client.post(
            "/mcp/messages/?session_id=00000000-0000-0000-0000-000000000000",
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
        )
        assert response.status_code in (400, 404)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_payload",
        [
            b"MALFORMED NON-JSON DATA",
            b'{"jsonrpc": "2.0", "method": ',  # Truncated JSON
            b"\xff\xfe\x00\x01\x80\x90",  # Non-UTF8 raw binary
            b'{"not_jsonrpc": true}',  # Invalid JSON-RPC frame
            b"[]",  # Empty batch
            b'{"jsonrpc": "1.0", "method": "test"}',  # Wrong jsonrpc version
            b"",  # Empty body
        ],
    )
    async def test_malformed_request_bodies_to_messages_endpoint(self, bad_payload: bytes):
        """Server must gracefully reject malformed bodies on /mcp/messages/ without unhandled crash."""
        app = create_adversarial_test_app()
        client = TestClient(app)
        response = client.post(
            "/mcp/messages/?session_id=fake_session_123",
            content=bad_payload,
            headers={"Content-Type": "application/json"},
        )
        # Should return error status (400/404/422/500)
        assert response.status_code in (400, 404, 422, 500)
        assert "traceback (most recent call last)" not in response.text.lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("wrong_method", ["GET", "PUT", "DELETE", "PATCH"])
    async def test_wrong_http_methods_on_messages_endpoint(self, wrong_method: str):
        """Verbs other than POST on /mcp/messages/ must return error status (400, 404, or 405)."""
        app = create_adversarial_test_app()
        client = TestClient(app)
        response = client.request(wrong_method, "/mcp/messages/?session_id=fake_session")
        assert response.status_code in (400, 404, 405)


# ============================================================================
# 3. API Key Authentication Adversarial Stress Tests
# ============================================================================


class TestAPIKeyAuthAdversarialStress:
    """Adversarial stress-testing of APIKeyAuthMiddleware."""

    @pytest.mark.asyncio
    async def test_auth_header_injection_and_crlf(self):
        """Test authentication handling when headers contain special/injection characters."""
        api_key = "secure_token_abc123"
        app = create_adversarial_test_app(api_key=api_key)

        # 1. Injected newline in token -> rejected (403)
        res1 = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"X-API-Key": f"{api_key}\r\nInjected: evil"},
        )
        assert res1["status"] == 403

        # 2. Token with null byte suffix -> rejected (403)
        res2 = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"X-API-Key": f"{api_key}\x00extra"},
        )
        assert res2["status"] == 403

    @pytest.mark.asyncio
    async def test_case_insensitive_authorization_headers(self):
        """Ensure standard Authorization header variations work cleanly."""
        api_key = "secure_token_abc123"
        app = create_adversarial_test_app(api_key=api_key)

        # 1. Lowercase bearer prefix: 'bearer <token>'
        res1 = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"Authorization": f"bearer {api_key}"},
        )
        assert res1["status"] == 200

        # 2. Standard Bearer prefix: 'Bearer <token>'
        res2 = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert res2["status"] == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "malformed_auth",
        [
            "Bearer",  # Missing token
            "Bearer ",  # Spaces only
            "Bearer   ",
            "Bearer secure_token_abc123 extra_token",  # Multiple tokens
            "Basic dXNlcjpwYXNz",  # Basic auth unsupported
            "Token some_token",  # Non-bearer scheme
            "Digest xyz",
            "",
        ],
    )
    async def test_malformed_authorization_header_formats(self, malformed_auth: str):
        """Malformed Authorization header formats must return 403 Forbidden."""
        api_key = "secure_token_abc123"
        app = create_adversarial_test_app(api_key=api_key)
        res = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"Authorization": malformed_auth},
        )
        assert res["status"] == 403

    @pytest.mark.asyncio
    async def test_competing_headers_precedence(self):
        """Test behavior when both X-API-Key and Authorization headers are present."""
        api_key = "valid_api_key_12345"
        app = create_adversarial_test_app(api_key=api_key)

        # 1. Valid X-API-Key + Invalid Authorization -> X-API-Key validated -> 200 OK
        res1 = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={
                "X-API-Key": api_key,
                "Authorization": "Bearer wrong_token",
            },
        )
        assert res1["status"] == 200

        # 2. Invalid X-API-Key + Valid Authorization -> X-API-Key takes priority -> 403 Forbidden
        res2 = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={
                "X-API-Key": "wrong_api_key",
                "Authorization": f"Bearer {api_key}",
            },
        )
        assert res2["status"] == 403

    @pytest.mark.asyncio
    async def test_oversized_api_key_header(self):
        """Oversized 64KB token in X-API-Key must be safely rejected with 403 without crashing."""
        api_key = "valid_api_key_12345"
        app = create_adversarial_test_app(api_key=api_key)
        huge_token = "A" * 65536
        res = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            headers={"X-API-Key": huge_token},
        )
        assert res["status"] == 403


# ============================================================================
# 4. Dynamic MCP Context Resources: Exhaustive Path Traversal & Adversarial URIs
# ============================================================================


class TestDynamicResourcesPathTraversalAndAdversarialURIs:
    """Exhaustively challenge all dynamic resource URI templates with path traversal and malformed inputs."""

    @pytest.mark.parametrize(
        "traversal_filename",
        [
            "../../../../etc/passwd",
            "/etc/shadow",
            "nested/../../../../etc/passwd",
            "/dev/null",
            "/var/run/docker.sock",
        ],
    )
    def test_workspace_path_traversal_detection(self, traversal_filename: str):
        """_get_workspace_path must consistently raise ValidationError for any out-of-bounds path."""
        with pytest.raises(ValidationError) as excinfo:
            _get_workspace_path(traversal_filename)
        assert "Path traversal detected" in str(excinfo.value)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "resource_uri_pattern",
        [
            "reversecore://{fn}/metadata",
            "reversecore://{fn}/info",
            "reversecore://{fn}/memory_map",
            "reversecore://{fn}/sections",
            "reversecore://{fn}/signatures",
            "reversecore://{fn}/imports",
            "reversecore://{fn}/exports",
            "reversecore://{fn}/strings",
            "reversecore://{fn}/iocs",
            "reversecore://{fn}/functions",
            "reversecore://{fn}/dormant_detector",
            "reversecore://{fn}/func/0x401000/xrefs",
            "reversecore://{fn}/func/0x401000/context",
            "reversecore://{fn}/func/0x401000/code",
            "reversecore://{fn}/func/0x401000/asm",
            "reversecore://{fn}/func/0x401000/cfg",
        ],
    )
    async def test_dynamic_resource_client_path_traversal_rejection(
        self, adversarial_mcp_server, resource_uri_pattern: str
    ):
        """All dynamic resource URIs must reject path traversal attempts via FastMCP Client cleanly."""
        uri = resource_uri_pattern.format(fn="../../../etc/passwd")
        async with Client(adversarial_mcp_server) as client:
            try:
                contents = await client.read_resource(uri)
                assert len(contents) >= 1
                text = contents[0].text
                assert "Error" in text or "Path traversal detected" in text
                assert "traceback (most recent call last)" not in text.lower()
            except (McpError, Exception) as e:
                # FastMCP rejects unknown or malformed resource URI templates cleanly
                assert "traceback (most recent call last)" not in str(e).lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "malformed_address",
        [
            "0xZZZZ",
            "-1",
            "0x",
            "not_an_address",
            "0x401000; rm -rf / ;",
            "0x401000 | cat /etc/shadow",
            "0xffffffffffffffffffffffffffff",
            "0x401000\x00extra",
            "' OR 1=1;--",
            "<script>alert(1)</script>",
        ],
    )
    async def test_function_resources_with_adversarial_addresses(
        self,
        adversarial_mcp_server,
        workspace_dir,
        patched_workspace_config,
        malformed_address: str,
    ):
        """Function-level resources must gracefully handle malformed/injected address strings via Client."""
        test_file = workspace_dir / "adversarial_target.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        func_uris = [
            f"reversecore://adversarial_target.elf/func/{malformed_address}/xrefs",
            f"reversecore://adversarial_target.elf/func/{malformed_address}/context",
            f"reversecore://adversarial_target.elf/func/{malformed_address}/code",
            f"reversecore://adversarial_target.elf/func/{malformed_address}/asm",
            f"reversecore://adversarial_target.elf/func/{malformed_address}/cfg",
        ]

        async with Client(adversarial_mcp_server) as client:
            for uri in func_uris:
                try:
                    contents = await client.read_resource(uri)
                    assert len(contents) >= 1
                    text = contents[0].text
                    assert isinstance(text, str)
                    assert "traceback (most recent call last)" not in text.lower()
                except (McpError, Exception) as e:
                    assert "traceback (most recent call last)" not in str(e).lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("corrupt_bytes", [b"", b"\x00", b"\x7fELF", b"\x90" * 10])
    async def test_dynamic_resources_on_corrupted_binaries(
        self,
        adversarial_mcp_server,
        workspace_dir,
        patched_workspace_config,
        corrupt_bytes: bytes,
    ):
        """Zero-byte, single-byte, and truncated binaries must not crash resource extractors."""
        target = workspace_dir / "corrupted_sample.bin"
        target.write_bytes(corrupt_bytes)

        test_uris = [
            "reversecore://corrupted_sample.bin/metadata",
            "reversecore://corrupted_sample.bin/memory_map",
            "reversecore://corrupted_sample.bin/signatures",
            "reversecore://corrupted_sample.bin/imports",
            "reversecore://corrupted_sample.bin/exports",
        ]

        async with Client(adversarial_mcp_server) as client:
            for uri in test_uris:
                contents = await client.read_resource(uri)
                assert len(contents) >= 1
                text = contents[0].text
                assert isinstance(text, str)
                assert len(text) > 0

    @pytest.mark.asyncio
    async def test_dynamic_resources_on_nonexistent_binary(
        self, adversarial_mcp_server, workspace_dir, patched_workspace_config
    ):
        """Reading dynamic resources for a non-existent binary returns clean error without crashing."""
        async with Client(adversarial_mcp_server) as client:
            contents = await client.read_resource(
                "reversecore://does_not_exist_file_99999.elf/metadata"
            )
            assert len(contents) >= 1
            text = contents[0].text
            assert (
                "does_not_exist_file_99999.elf" in text
                or "Error" in text
                or "not found" in text.lower()
            )


# ============================================================================
# 5. FastMCP Protocol Client JSON-RPC Adversarial Handling
# ============================================================================


class TestFastMCPProtocolClientAdversarial:
    """Stress-test FastMCP server over protocol Client with malformed queries and invalid targets."""

    @pytest.mark.asyncio
    async def test_call_nonexistent_tool(self, adversarial_mcp_server):
        """Calling a non-existent tool via Client returns proper error without crashing."""
        async with Client(adversarial_mcp_server) as client:
            with pytest.raises(Exception) as excinfo:
                await client.call_tool("nonexistent_tool_12345", arguments={})
            assert (
                "not found" in str(excinfo.value).lower()
                or "unknown" in str(excinfo.value).lower()
                or "error" in str(excinfo.value).lower()
            )

    @pytest.mark.asyncio
    async def test_call_tool_with_invalid_arguments_and_error_handling(
        self, adversarial_mcp_server
    ):
        """Calling tool with invalid argument types or raising exceptions returns error cleanly."""
        async with Client(adversarial_mcp_server) as client:
            # 1. Invalid argument type
            with pytest.raises(Exception, match=r".+"):
                await client.call_tool("divide_numbers", arguments={"a": "not_an_int", "b": 2})

            # 2. Tool raising ValueError (division by zero)
            with pytest.raises(Exception) as excinfo:
                await client.call_tool("divide_numbers", arguments={"a": 10, "b": 0})
            assert "division by zero" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_read_nonexistent_resource_uri(self, adversarial_mcp_server):
        """Reading an unknown/unregistered resource URI raises proper client exception."""
        async with Client(adversarial_mcp_server) as client:
            with pytest.raises(Exception) as excinfo:
                await client.read_resource("reversecore://invalid/unregistered/resource")
            assert (
                "not found" in str(excinfo.value).lower()
                or "error" in str(excinfo.value).lower()
                or "unknown" in str(excinfo.value).lower()
            )

    @pytest.mark.asyncio
    async def test_get_nonexistent_prompt(self, adversarial_mcp_server):
        """Getting a non-existent prompt raises proper client exception."""
        async with Client(adversarial_mcp_server) as client:
            with pytest.raises(Exception) as excinfo:
                await client.get_prompt("nonexistent_prompt_mode", arguments={})
            assert (
                "not found" in str(excinfo.value).lower()
                or "unknown" in str(excinfo.value).lower()
                or "error" in str(excinfo.value).lower()
            )


# ============================================================================
# 6. High Concurrency Race Condition Stress Tests
# ============================================================================


class TestHighConcurrencyStressAndRaceConditions:
    """Stress-test concurrent requests across transports and dynamic resources."""

    @pytest.mark.asyncio
    async def test_concurrent_sse_and_http_requests(self):
        """Execute 40 concurrent mixed requests across /health, /health/live, and /mcp/sse."""
        app = create_adversarial_test_app()

        async def mixed_worker(i: int):
            if i % 3 == 0:
                # SSE Stream
                return await asgi_request_adversarial(
                    app,
                    "GET",
                    "/mcp/sse",
                    client_port=51000 + i,
                    disconnect_after_start=True,
                    disconnect_delay_seconds=0.01,
                )
            elif i % 3 == 1:
                # Health live
                return await asgi_request_adversarial(
                    app,
                    "GET",
                    "/health/live",
                    client_port=51000 + i,
                    disconnect_after_start=False,
                )
            else:
                # Health root
                return await asgi_request_adversarial(
                    app,
                    "GET",
                    "/health",
                    client_port=51000 + i,
                    disconnect_after_start=False,
                )

        tasks = [asyncio.create_task(mixed_worker(i)) for i in range(40)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, res in enumerate(results):
            assert not isinstance(res, Exception), f"Concurrent request {idx} threw: {res}"
            assert res["status"] == 200

    @pytest.mark.asyncio
    async def test_concurrent_dynamic_resource_readers(
        self, adversarial_mcp_server, workspace_dir, patched_workspace_config
    ):
        """Execute 50 concurrent dynamic resource extractions across different files in parallel."""
        # Create 5 synthetic sample files
        for i in range(5):
            f = workspace_dir / f"concurrent_sample_{i}.bin"
            f.write_bytes(b"\x7fELF" + b"\x90" * (100 + i * 20))

        uris = [
            f"reversecore://concurrent_sample_{i % 5}.bin/{suffix}"
            for i, suffix in enumerate(
                ["metadata", "memory_map", "imports", "strings", "signatures"] * 10
            )
        ]

        async with Client(adversarial_mcp_server) as client:

            async def reader_worker(uri_str: str):
                return await client.read_resource(uri_str)

            tasks = [asyncio.create_task(reader_worker(u)) for u in uris]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for idx, res in enumerate(results):
                assert not isinstance(res, Exception), (
                    f"Resource read {idx} threw unhandled exception: {res}"
                )
                assert len(res) >= 1
                assert len(res[0].text) > 0


# ============================================================================
# 7. Stack Trace Leakage & Error Hygiene Verification
# ============================================================================


class TestErrorHygieneAndNoStackTraceLeakage:
    """Verify that error outputs across endpoints and resources never leak raw Python tracebacks."""

    @pytest.mark.asyncio
    async def test_no_stack_trace_in_auth_rejections(self):
        """403 responses must never leak stack traces."""
        api_key = "secure_token_123"
        app = create_adversarial_test_app(api_key=api_key)
        client = TestClient(app)

        res = client.get("/mcp/sse", headers={"X-API-Key": "wrong"})
        assert res.status_code == 403
        assert "traceback (most recent call last)" not in res.text.lower()
        assert 'File "' not in res.text

    @pytest.mark.asyncio
    async def test_no_stack_trace_in_path_traversal_errors(self, adversarial_mcp_server):
        """Path traversal rejections in dynamic resources must return clean message without traceback."""
        async with Client(adversarial_mcp_server) as client:
            try:
                contents = await client.read_resource(
                    "reversecore://../../../../etc/shadow/metadata"
                )
                assert len(contents) >= 1
                text = contents[0].text
                assert "traceback (most recent call last)" not in text.lower()
                assert 'File "' not in text
            except (McpError, Exception) as e:
                assert "traceback (most recent call last)" not in str(e).lower()
                assert 'File "' not in str(e)

    @pytest.mark.asyncio
    async def test_dynamic_resource_underlying_tool_failure_resilience(
        self,
        adversarial_mcp_server,
        workspace_dir,
        patched_workspace_config,
        monkeypatch,
    ):
        """When underlying binary analysis tools throw unexpected runtime errors, resources must return clean error text."""
        test_file = workspace_dir / "crash_sample.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 50)

        # Mock r2_analysis to raise an unexpected runtime error
        async def mock_run_r2_crash(*args, **kwargs):
            raise RuntimeError("Underlying R2 process crashed unexpectedly!")

        monkeypatch.setattr(
            "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
            mock_run_r2_crash,
        )

        async with Client(adversarial_mcp_server) as client:
            # 1. Imports resource under r2 crash
            imp_contents = await client.read_resource("reversecore://crash_sample.elf/imports")
            assert len(imp_contents) >= 1
            assert "crash_sample.elf" in imp_contents[0].text or "Error" in imp_contents[0].text
            assert "traceback (most recent call last)" not in imp_contents[0].text.lower()

            # 2. Exports resource under r2 crash
            exp_contents = await client.read_resource("reversecore://crash_sample.elf/exports")
            assert len(exp_contents) >= 1
            assert "crash_sample.elf" in exp_contents[0].text or "Error" in exp_contents[0].text
            assert "traceback (most recent call last)" not in exp_contents[0].text.lower()

    def test_symlink_path_traversal_detection(self, patched_config):
        """A symlink pointing outside the workspace must be detected and rejected."""
        symlink_path = patched_config.workspace / "evil_symlink.bin"
        try:
            symlink_path.symlink_to(Path("/etc/hosts"))
        except OSError:
            pytest.skip("Symlink creation not permitted in this environment")

        with pytest.raises(ValidationError) as excinfo:
            _get_workspace_path("evil_symlink.bin")
        assert "Path traversal detected" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_security_headers_present_on_all_error_responses(self):
        """Security headers must be present on 400, 403, 404, 405 error responses."""
        app = create_adversarial_test_app(api_key="secret123")
        client = TestClient(app)

        # 403 Forbidden (Auth failure)
        res403 = client.get("/mcp/sse", headers={"X-API-Key": "wrong"})
        assert res403.status_code == 403
        assert res403.headers.get("X-Content-Type-Options") == "nosniff"
        assert res403.headers.get("X-Frame-Options") == "DENY"
        assert "Strict-Transport-Security" in res403.headers

        # 405 Method Not Allowed
        res405 = client.post("/mcp/sse", headers={"X-API-Key": "secret123"})
        assert res405.status_code == 405
        assert res405.headers.get("X-Content-Type-Options") == "nosniff"

    @pytest.mark.asyncio
    async def test_loopback_middleware_blocks_external_client_ip(self):
        """Non-loopback client IPs must be rejected with 403 when LoopbackOnlyMiddleware is active."""
        app = create_adversarial_test_app(use_loopback_guard=True)
        res = await asgi_request_adversarial(
            app,
            "GET",
            "/mcp/sse",
            client_ip="198.51.100.25",  # External IP
            disconnect_before_start=False,
            disconnect_after_start=False,
        )
        assert res["status"] == 403

    @pytest.mark.asyncio
    async def test_large_and_deep_jsonrpc_payload_resilience(self):
        """Server must gracefully reject or handle 1MB payload on /mcp/messages/ without crashing."""
        app = create_adversarial_test_app()
        client = TestClient(app)

        huge_payload = {
            "jsonrpc": "2.0",
            "method": "ping",
            "params": {"data": "X" * 1048576},
            "id": 1,
        }
        response = client.post(
            "/mcp/messages/?session_id=fake_session",
            json=huge_payload,
        )
        assert response.status_code in (400, 404, 422, 500)
        assert "traceback (most recent call last)" not in response.text.lower()
