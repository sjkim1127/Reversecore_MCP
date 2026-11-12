"""Unit tests for Tiered Tools & Multi-Agent mode (reversecore_mcp.core.tiered)."""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from reversecore_mcp.core.result import ToolSuccess
from reversecore_mcp.core.tiered import (
    TIER1_CORE_TOOLS,
    TIER2_ROUTER_TOOLS,
    TIERED_TOOL_NAMES,
    AgentRegistry,
    DeobfuscationAgent,
    DiffAnalystAgent,
    ForensicsAgent,
    MalwareSpecialistAgent,
    SourceAuditorAgent,
    SymbolicEngineAgent,
    VulnerabilityHunterAgent,
    call_expert_agent,
    execute_domain_tool,
    search_tools,
    setup_tiered_mode,
)


@pytest.fixture
def mock_mcp() -> FastMCP:
    """Create a test FastMCP server with dummy core and niche tools."""
    app = FastMCP("test_mcp")

    # Register Tier-1 dummy tools
    for name in TIER1_CORE_TOOLS:

        def _make_tool(tool_name: str):
            async def _dummy(file_path: str = "") -> dict:
                return {"tool": tool_name, "file_path": file_path, "ok": True}

            _dummy.__name__ = tool_name
            return _dummy

        app.tool(name=name)(_make_tool(name))

    # Register dummy niche tools
    @app.tool(name="build_rop_chain", description="Build ROP exploit chain.")
    async def _dummy_rop(file_path: str) -> dict:
        return {"gadgets": ["pop rax", "ret"], "ok": True}

    @app.tool(name="pcap_analyze", description="Analyze PCAP network dump.")
    async def _dummy_pcap(pcap_path: str) -> dict:
        return {"packets": 100, "ok": True}

    @app.tool(name="vulnerability_hunter", description="Hunt vulnerabilities.")
    async def _dummy_vuln(file_path: str) -> dict:
        return {"vulnerabilities": ["buffer_overflow"], "ok": True}

    return app


def test_tiered_tool_definitions():
    """Verify tier 1 and tier 2 tool configurations."""
    assert len(TIER1_CORE_TOOLS) == 15
    assert len(TIER2_ROUTER_TOOLS) == 3
    assert len(TIERED_TOOL_NAMES) == 18
    assert "run_file" in TIER1_CORE_TOOLS
    assert "Radare2_open_file" in TIER1_CORE_TOOLS
    assert "Radare2_decompile_function" in TIER1_CORE_TOOLS
    assert "call_expert_agent" in TIER2_ROUTER_TOOLS
    assert "search_tools" in TIER2_ROUTER_TOOLS
    assert "execute_domain_tool" in TIER2_ROUTER_TOOLS


def test_agent_registry():
    """Verify domain agent registry registration and alias resolution."""
    registry = AgentRegistry()
    agents = registry.list_agents()
    agent_names = [a["name"] for a in agents]

    assert "vulnerability_hunter" in agent_names
    assert "forensics" in agent_names
    assert "malware_analyst" in agent_names
    assert "deobfuscator" in agent_names
    assert "symbolic_engine" in agent_names
    assert "diff_analyst" in agent_names
    assert "source_auditor" in agent_names

    # Test alias resolution
    assert isinstance(registry.get_agent("vuln"), VulnerabilityHunterAgent)
    assert isinstance(registry.get_agent("cve"), VulnerabilityHunterAgent)
    assert isinstance(registry.get_agent("dfir"), ForensicsAgent)
    assert isinstance(registry.get_agent("memory"), ForensicsAgent)
    assert isinstance(registry.get_agent("threat"), MalwareSpecialistAgent)
    assert isinstance(registry.get_agent("unpack"), DeobfuscationAgent)
    assert isinstance(registry.get_agent("angr"), SymbolicEngineAgent)
    assert isinstance(registry.get_agent("patch"), DiffAnalystAgent)
    assert isinstance(registry.get_agent("sast"), SourceAuditorAgent)
    assert registry.get_agent("unknown_agent") is None


@pytest.mark.asyncio
async def test_search_tools(mock_mcp: FastMCP):
    """Test searching tools across registered catalog."""
    # Search for ROP
    res = await search_tools(mock_mcp, query="rop")
    assert isinstance(res, ToolSuccess)
    data = res.data
    assert data["total_matches"] >= 1
    tool_names = [t["name"] for t in data["tools"]]
    assert "build_rop_chain" in tool_names

    # Search for PCAP with domain filter
    res_pcap = await search_tools(mock_mcp, query="pcap", domain="forensics")
    assert isinstance(res_pcap, ToolSuccess)
    assert res_pcap.data["total_matches"] >= 1
    assert res_pcap.data["tools"][0]["name"] == "pcap_analyze"

    # Search non-existent
    res_none = await search_tools(mock_mcp, query="nonexistent_xyz_tool")
    assert isinstance(res_none, ToolSuccess)
    assert res_none.data["total_matches"] == 0


@pytest.mark.asyncio
async def test_execute_domain_tool(mock_mcp: FastMCP):
    """Test dynamic router tool execution."""
    # Execute valid tool
    res = await execute_domain_tool(mock_mcp, "run_file", {"file_path": "test.bin"})
    assert isinstance(res, ToolSuccess)
    assert res.data["tool"] == "run_file"

    # Execute with invalid name -> close match hint
    res_err = await execute_domain_tool(mock_mcp, "pcap_analys")
    assert res_err.status == "error"
    assert "Did you mean: pcap_analyze" in str(res_err.message)

    # Empty name
    res_empty = await execute_domain_tool(mock_mcp, "")
    assert res_empty.status == "error"


@pytest.mark.asyncio
async def test_call_expert_agent(mock_mcp: FastMCP):
    """Test dispatching task to expert sub-agents."""
    # Unknown agent
    res_unknown = await call_expert_agent(mock_mcp, "alien_agent", "do stuff", "sample.bin")
    assert res_unknown.status == "error"
    assert "Available agents" in str(res_unknown.message)

    # Vulnerability Hunter Agent
    res_vuln = await call_expert_agent(
        mock_mcp, "vulnerability_hunter", "Find ROP gadgets", "sample.bin"
    )
    assert isinstance(res_vuln, ToolSuccess)
    data = res_vuln.data
    assert data["agent"] == "vulnerability_hunter"
    assert "vulnerability_hunter" in data["tools_invoked"]
    assert "build_rop_chain" in data["tools_invoked"]


@pytest.mark.asyncio
async def test_setup_tiered_mode(mock_mcp: FastMCP):
    """Test setup_tiered_mode activation and list_tools filtering."""
    # 1. Full mode: list_tools remains un-filtered
    setup_tiered_mode(mock_mcp, profile="full")
    all_tools = await mock_mcp.list_tools()
    assert len(all_tools) >= 15  # All tools visible

    # 2. Tiered mode: list_tools is filtered to exactly TIERED_TOOL_NAMES
    setup_tiered_mode(mock_mcp, profile="tiered")
    tiered_tools = await mock_mcp.list_tools()
    assert len(tiered_tools) == 18
    tiered_names = {t.name for t in tiered_tools}
    assert tiered_names == TIERED_TOOL_NAMES

    # Non-tiered tool (e.g. build_rop_chain) is hidden from list_tools
    assert "build_rop_chain" not in tiered_names

    # But it CAN still be called directly via call_tool!
    call_res = await mock_mcp.call_tool("build_rop_chain", {"file_path": "sample.bin"})
    assert call_res is not None
