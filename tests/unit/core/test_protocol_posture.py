"""Unit tests for MCP protocol capabilities posture and modern handshake behavior."""

import pytest

from reversecore_mcp import server


class TestProtocolPosture:
    """Validate server protocol capabilities against MCP specifications."""

    def test_logging_capability_is_suppressed(self):
        """Verify deprecated MCP logging capability is suppressed from server capabilities."""
        mcp = server.mcp
        assert hasattr(mcp, "_mcp_server"), "FastMCP instance should wrap an MCP server"

        caps = mcp._mcp_server.get_capabilities(
            notification_options=mcp._mcp_server.notification_options,
            experimental_capabilities={},
        )
        assert caps.logging is None, (
            "Deprecated MCP logging capability must be None per Issue #347 protocol posture audit"
        )

    def test_essential_capabilities_preserved(self):
        """Verify tools, resources, and prompts capabilities are preserved."""
        mcp = server.mcp
        caps = mcp._mcp_server.get_capabilities(
            notification_options=mcp._mcp_server.notification_options,
            experimental_capabilities={},
        )
        assert caps.tools is not None, "tools capability must be present"
        assert caps.resources is not None, "resources capability must be present"
        assert caps.prompts is not None, "prompts capability must be present"

    @pytest.mark.asyncio
    async def test_tool_count_and_availability(self):
        """Verify full suite of 156 tools is available on live FastMCP server."""
        tools = await server.mcp.list_tools()
        tools_list = tools if isinstance(tools, list) else list(tools.values())
        assert len(tools_list) == 163, f"Expected 163 tools, found {len(tools_list)}"

        tool_names = {t.name for t in tools_list}
        assert "run_capa" in tool_names
        assert "run_capa_quick" in tool_names
        assert "detect_packer" in tool_names
        assert "detect_packer_deep" in tool_names
        assert "export_analysis_cache" in tool_names
        assert "import_analysis_cache" in tool_names
        assert "verify_string_references" in tool_names
        assert "retrieve_truncated_output" in tool_names
        assert "batch_execute" in tool_names
        assert "transaction_begin" in tool_names
        assert "transaction_commit" in tool_names
        assert "transaction_rollback" in tool_names
        assert "transaction_status" in tool_names
        assert "transaction_undo" in tool_names
        assert "transaction_redo" in tool_names
        assert "recommend_analysis_plan" in tool_names
