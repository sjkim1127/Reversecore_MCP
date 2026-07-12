"""Tests for structured evidence guidance in security prompts."""

from reversecore_mcp.prompts import register_prompts
from reversecore_mcp.prompts.cve_research import patch_diff_auto_mode
from reversecore_mcp.prompts.security import patch_analysis_mode, source_code_audit_mode


def test_patch_analysis_mode_mentions_structured_patch_evidence():
    prompt = patch_analysis_mode("old.bin", "new.bin")

    assert "structured_signals" in prompt
    assert "RCMCP-PATCH-LOWER-BOUND-ADDED" in prompt
    assert "out_of_bounds_access" in prompt
    assert "structured_findings" in prompt


def test_source_code_audit_mode_mentions_structured_sast_evidence():
    prompt = source_code_audit_mode()

    assert "structured_findings" in prompt
    assert "RCMCP-SAST-C-012" in prompt
    assert "guard_status" in prompt
    assert "verification_status" in prompt


def test_patch_diff_auto_mode_mentions_merging_sast_and_patch_evidence():
    prompt = patch_diff_auto_mode("old.bin", "new.bin")

    assert "structured_signals" in prompt
    assert "structured_findings" in prompt
    assert "RCMCP-SAST-C-012" in prompt
    assert "RCMCP-PATCH-LOWER-BOUND-ADDED" in prompt


def test_required_smoke_prompts_are_registered():
    from fastmcp import FastMCP

    required_prompt_names = {
        "full_analysis_mode",
        "malware_analysis_mode",
        "vulnerability_hunter_mode",
        "firmware_analysis_mode",
        "server_health_check_mode",
        "server_tool_catalog_mode",
        "report_generation_mode",
        "autonomous_vuln_hunt_mode",
    }
    mcp = FastMCP("prompt-test")
    register_prompts(mcp)
    # FastMCP 2.x exposes registered prompts as a name-to-prompt mapping.
    prompt_names = set(mcp.get_prompts())

    assert required_prompt_names <= prompt_names
