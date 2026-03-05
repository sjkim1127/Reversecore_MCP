"""
Integration tests: MCP server tool listing and tool invocation via protocol.

Verifies that the FastMCP server actually exposes tools and executes them
when requested through the MCP layer (list_tools / call_tool), not just
when Python functions are called directly.

Uses a minimal in-process FastMCP instance that registers the same tool
functions as the real server (list_workspace, run_file) so we test the
MCP tool-call path without running the full server lifespan (resource
manager, memory store, etc.), which can block or be slow in CI.
"""

import pytest


def _make_minimal_mcp():
    """Build a minimal FastMCP with a few real tools (no lifespan)."""
    from fastmcp import FastMCP

    from reversecore_mcp.tools.common.file_operations import list_workspace, run_file

    mcp = FastMCP(name="Reversecore_MCP_test", lifespan=None)
    mcp.tool(list_workspace)
    mcp.tool(run_file)
    return mcp


class TestMCPToolListing:
    """Test that the MCP layer exposes tools via tools/list."""

    @pytest.mark.asyncio
    async def test_list_tools_returns_tools(self, patched_workspace_config):
        """Server must expose at least one tool (e.g. list_workspace)."""
        from fastmcp.client import Client

        mcp = _make_minimal_mcp()
        async with Client(transport=mcp) as client:
            tools = await client.list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0, "MCP server should expose at least one tool"
        names = [t.name for t in tools]
        assert "list_workspace" in names, f"Expected list_workspace in {names}"

    @pytest.mark.asyncio
    async def test_list_tools_includes_registered_tools(self, patched_workspace_config):
        """Registered tools (list_workspace, run_file) must be listed."""
        from fastmcp.client import Client

        mcp = _make_minimal_mcp()
        async with Client(transport=mcp) as client:
            tools = await client.list_tools()
        names = [t.name for t in tools]
        assert "list_workspace" in names
        assert "run_file" in names


class TestMCPToolCall:
    """Test that the MCP layer executes tools via tools/call."""

    @pytest.mark.asyncio
    async def test_call_list_workspace_success(self, patched_workspace_config):
        """list_workspace via MCP must succeed and return workspace info."""
        from fastmcp.client import Client

        mcp = _make_minimal_mcp()
        async with Client(transport=mcp) as client:
            result = await client.call_tool("list_workspace", {})

        # MCP layer should treat this as a non-error and return some payload,
        # but the exact shape of result.data may vary across fastmcp versions
        # (dict vs. Pydantic model), so we only assert on high-level signals.
        assert result.is_error is False, getattr(result, "message", str(result))
        assert result.data is not None or (hasattr(result, "content") and bool(result.content))

    @pytest.mark.asyncio
    async def test_call_run_file_via_mcp(self, patched_workspace_config, sample_binary_path):
        """run_file via MCP must run the tool and return file type info (or TOOL_NOT_FOUND if missing)."""
        import shutil

        from fastmcp.client import Client

        if not shutil.which("file"):
            pytest.skip("'file' command not available on this system")
        mcp = _make_minimal_mcp()
        async with Client(transport=mcp) as client:
            result = await client.call_tool(
                "run_file",
                {"file_path": str(sample_binary_path)},
            )

        # As above, just verify MCP successfully routed the call and returned data.
        assert result.is_error is False, getattr(result, "message", str(result))
        assert result.data is not None or (hasattr(result, "content") and bool(result.content))
