"""Milestone 1 Empirical Adversarial Test Suite.

Verifies:
1. Path traversal attacks against `_get_workspace_path` and dynamic resource URIs.
2. FastMCP Tool JSON schema parameter suppression for Context (`ctx`).
3. Dynamic and static resource MIME types and boundary enforcement.
"""

from __future__ import annotations

import urllib.parse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import Context

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.resources import _get_workspace_path
from reversecore_mcp.server import mcp
from reversecore_mcp.tools.common.file_operations import scan_workspace

pytestmark = pytest.mark.security


class TestGetWorkspacePathAdversarialTraversal:
    """Adversarial stress-testing of _get_workspace_path against path traversal vectors."""

    @pytest.fixture
    def workspace(self, tmp_path):
        """Mock workspace directory."""
        ws = (tmp_path / "workspace").resolve()
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    def test_relative_path_traversal_blocked(self, workspace):
        """Test classic relative traversal strings are blocked with ValidationError."""
        malicious_traversals = [
            "../",
            "../../",
            "../../etc/passwd",
            "../../../etc/shadow",
            "../../../../var/log/system.log",
            "../../../../../../../../../../../../etc/passwd",
            "subdir/../../etc/passwd",
            "./../../etc/passwd",
            "foo/bar/../../../etc/passwd",
            "foo/../../../../etc/passwd",
            "a/b/c/../../../../etc/passwd",
        ]

        with patch("reversecore_mcp.resources.get_config") as mock_cfg:
            mock_cfg.return_value.workspace = workspace

            for payload in malicious_traversals:
                with pytest.raises(ValidationError) as exc_info:
                    _get_workspace_path(payload)
                assert "Path traversal detected" in str(exc_info.value)
                assert str(workspace) in str(exc_info.value)

    def test_absolute_path_traversal_blocked(self, workspace):
        """Test absolute paths outside workspace are strictly blocked."""
        outside_absolute_paths = [
            "/etc/passwd",
            "/var/log/system.log",
            "/tmp/secret.txt",
            "/root/.ssh/id_rsa",
            "/Users/some_user/documents",
            str(workspace.parent / "outside_file.txt"),
        ]

        with patch("reversecore_mcp.resources.get_config") as mock_cfg:
            mock_cfg.return_value.workspace = workspace

            for path_str in outside_absolute_paths:
                with pytest.raises(ValidationError) as exc_info:
                    _get_workspace_path(path_str)
                assert "Path traversal detected" in str(exc_info.value)

    def test_sibling_directory_prefix_collision_blocked(self, workspace):
        """Test sibling directory path with common prefix is not tricked by naive string matching."""
        # e.g., workspace = /tmp/workspace -> sibling = /tmp/workspace_fake/secret.txt
        sibling_path = str(workspace) + "_fake/secret.txt"
        sibling_path_2 = str(workspace) + "2/secret.txt"

        with patch("reversecore_mcp.resources.get_config") as mock_cfg:
            mock_cfg.return_value.workspace = workspace

            for sibling in [sibling_path, sibling_path_2]:
                with pytest.raises(ValidationError) as exc_info:
                    _get_workspace_path(sibling)
                assert "Path traversal detected" in str(exc_info.value)

    def test_url_encoded_path_traversal_blocked_when_decoded(self, workspace):
        """Test URL-encoded path traversals when unquoted are strictly caught."""
        encoded_payloads = [
            "..%2f..%2fetc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252fetc/passwd",
        ]

        with patch("reversecore_mcp.resources.get_config") as mock_cfg:
            mock_cfg.return_value.workspace = workspace

            for encoded in encoded_payloads:
                decoded = urllib.parse.unquote(encoded)
                if "%" in decoded:
                    decoded = urllib.parse.unquote(decoded)  # Double-decode check
                with pytest.raises(ValidationError) as exc_info:
                    _get_workspace_path(decoded)
                assert "Path traversal detected" in str(exc_info.value)

    def test_valid_paths_inside_workspace_allowed(self, workspace):
        """Test legitimate files and subdirectories within workspace succeed."""
        valid_cases = [
            ("sample.exe", workspace / "sample.exe"),
            ("subdir/binary.bin", workspace / "subdir" / "binary.bin"),
            (
                "nested/deep/dir/target.elf",
                workspace / "nested" / "deep" / "dir" / "target.elf",
            ),
            ("subdir/../sample.exe", workspace / "sample.exe"),
            (str(workspace / "direct.dll"), workspace / "direct.dll"),
            (".", workspace),
        ]

        with patch("reversecore_mcp.resources.get_config") as mock_cfg:
            mock_cfg.return_value.workspace = workspace

            for input_path, expected_path in valid_cases:
                resolved = _get_workspace_path(input_path)
                assert resolved == str(expected_path.resolve())


class TestFastMCPToolSchemaCtxSuppression:
    """Empirical verification that FastMCP tool inputSchema suppresses `ctx` parameter."""

    @pytest.mark.asyncio
    async def test_scan_workspace_schema_suppresses_ctx(self):
        """Verify `ctx` is not present in parameters or inputSchema for scan_workspace."""
        tool = await mcp.get_tool("scan_workspace")
        assert tool is not None, "scan_workspace must be registered on server.mcp"

        # 1. Inspect FastMCP tool parameters dictionary
        params = tool.parameters
        assert isinstance(params, dict)
        properties = params.get("properties", {})
        required = params.get("required", [])

        assert "ctx" not in properties, (
            f"ctx leaked into parameters properties: {properties.keys()}"
        )
        assert "ctx" not in required, f"ctx leaked into parameters required: {required}"

        # 2. Verify declared user-facing arguments are intact
        assert "file_patterns" in properties
        assert "timeout" in properties
        assert properties["timeout"].get("default") == 600

        # 3. Inspect MCP wire-level tool model
        mcp_tool = tool.to_mcp_tool()
        assert mcp_tool.name == "scan_workspace"
        input_schema = mcp_tool.inputSchema
        assert "ctx" not in input_schema.get("properties", {})
        assert "ctx" not in input_schema.get("required", [])

    @pytest.mark.asyncio
    async def test_scan_workspace_executes_with_and_without_context(self, tmp_path):
        """Verify scan_workspace executes cleanly with FastMCP Context injected and when ctx is None."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_cfg:
            mock_cfg.return_value.workspace = tmp_path

            # Execution with explicit mock Context
            mock_ctx = MagicMock(spec=Context)
            mock_ctx.report_progress = AsyncMock()

            res_with_ctx = await scan_workspace(file_patterns=["*.bin"], timeout=10, ctx=mock_ctx)
            assert res_with_ctx.status == "success"
            assert mock_ctx.report_progress.await_count >= 1

            # Execution without Context (direct invocation default)
            res_without_ctx = await scan_workspace(file_patterns=["*.bin"], timeout=10, ctx=None)
            assert res_without_ctx.status == "success"


class TestDynamicResourceAdversarialRead:
    """Adversarial testing of dynamic resource endpoints via FastMCP resource manager."""

    @pytest.mark.asyncio
    async def test_dynamic_resource_traversal_payloads(self):
        """Test calling dynamic resources with traversal payloads returns error and never exposes host files."""
        traversal_uris = [
            "reversecore://../strings",
            "reversecore://..%2f..%2fetc%2fpasswd/strings",
            "reversecore://%2e%2e%2f%2e%2e%2fetc%2fpasswd/strings",
            "reversecore://..%2f..%2fetc%2fpasswd/iocs",
            "reversecore://..%2f..%2fetc%2fpasswd/func/0x1000/code",
            "reversecore://..%2f..%2fetc%2fpasswd/func/0x1000/asm",
        ]

        for uri in traversal_uris:
            res = await mcp._resource_manager.read_resource(uri)
            res_str = str(res)
            # Must return error and not leak /etc/passwd contents (root:x:0:0)
            assert "root:x:0:0" not in res_str
            assert "Error" in res_str or "Path traversal detected" in res_str


class TestResourceMimeTypesMetadata:
    """Verify that registered resources specify appropriate MIME types."""

    def test_registered_resource_mime_types(self):
        """Verify static resources and templates have defined MIME types."""
        # Check static resources
        static_resources = mcp._resource_manager._resources
        expected_static_mimes = {
            "reversecore://guide": "text/markdown",
            "reversecore://guide/structures": "text/markdown",
            "reversecore://tools": "text/markdown",
            "reversecore://logs": "text/plain",
        }

        for uri, expected_mime in expected_static_mimes.items():
            res = static_resources.get(uri)
            assert res is not None, f"Static resource {uri} must be registered"
            assert res.mime_type == expected_mime, (
                f"{uri} mime_type expected {expected_mime}, got {res.mime_type}"
            )

        # Check resource templates
        templates = mcp._resource_manager._templates.values()
        template_uris = {t.uri_template: t.mime_type for t in templates}

        expected_template_mimes = {
            "reversecore://{filename}/strings": "text/markdown",
            "reversecore://{filename}/iocs": "text/markdown",
            "reversecore://{filename}/func/{address}/code": "text/markdown",
            "reversecore://{filename}/func/{address}/asm": "text/markdown",
        }

        for uri_temp, expected_mime in expected_template_mimes.items():
            assert uri_temp in template_uris, f"Template {uri_temp} must be registered"
            assert template_uris[uri_temp] == expected_mime, (
                f"Template {uri_temp} mime_type expected {expected_mime}, got {template_uris[uri_temp]}"
            )
