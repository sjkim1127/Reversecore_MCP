"""Unit tests for recommend_analysis_plan MCP tool."""

from __future__ import annotations

import pytest

from reversecore_mcp.tools.common.planning_tools import recommend_analysis_plan


@pytest.mark.asyncio
class TestRecommendAnalysisPlanTool:
    """Tests for recommend_analysis_plan MCP tool."""

    async def test_default_recommendation(self):
        """Test default call produces valid plan with NextToolHint."""
        res = await recommend_analysis_plan()
        assert res.status == "success"
        assert res.data is not None

        payload = res.data
        assert payload["objective"] == "malware_triage"
        assert payload["depth"] == "standard"
        assert len(payload["primary_steps"]) >= 6
        assert len(payload["conditional_branches"]) > 0
        assert len(payload["stop_conditions"]) > 0

        # Check recommended next tool hint
        assert res.recommended_next_tools is not None
        assert len(res.recommended_next_tools) == 1
        hint = res.recommended_next_tools[0]
        assert hint["tool"] == payload["primary_steps"][0]["tool"]
        assert hint["priority"] == 1

    async def test_explicit_vulnerability_research_deep(self):
        """Test deep vulnerability research plan."""
        res = await recommend_analysis_plan(
            target_file="vulnerable.elf",
            objective="vulnerability_research",
            depth="deep",
            sample_format="elf",
            architecture="x86_64",
        )
        assert res.status == "success"
        payload = res.data
        assert payload["objective"] == "vulnerability_research"
        assert payload["depth"] == "deep"
        assert payload["sample_format"] == "elf"
        assert payload["estimated_budget_seconds"] >= 300

        tools = [s["tool"] for s in payload["primary_steps"]]
        assert "run_file" in tools
        assert "vulnerability_hunter" in tools
        assert "r2_decompile" in tools

    async def test_pcap_forensics_plan(self):
        """Test PCAP network analysis plan."""
        res = await recommend_analysis_plan(
            target_file="malicious.pcap",
            objective="incident_reconstruction",
            depth="quick",
        )
        assert res.status == "success"
        payload = res.data
        assert payload["sample_format"] == "pcap"
        assert payload["depth"] == "quick"

        tools = [s["tool"] for s in payload["primary_steps"]]
        assert "pcap_analyze" in tools
        assert "extract_iocs" in tools

    async def test_time_budget_override(self):
        """Test time budget dynamically dictates depth tier."""
        res_quick = await recommend_analysis_plan(
            time_budget_seconds=30,
        )
        payload_quick = res_quick.data
        assert payload_quick["depth"] == "quick"

        res_deep = await recommend_analysis_plan(
            time_budget_seconds=500,
        )
        payload_deep = res_deep.data
        assert payload_deep["depth"] == "deep"
