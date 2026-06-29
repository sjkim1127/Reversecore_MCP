"""Prompts package for Reversecore MCP Tools."""

from fastmcp import FastMCP

from reversecore_mcp.prompts.cve_research import (
    cve_discovery_pipeline_mode,
    fuzzing_mode,
    heap_exploit_mode,
    patch_diff_auto_mode,
    taint_analysis_mode,
)
from reversecore_mcp.prompts.game import game_analysis_mode
from reversecore_mcp.prompts.malware import (
    apt_hunting_mode,
    basic_analysis_mode,
    c2_extraction_mode,
    code_similarity_mode,
    full_analysis_mode,
    malware_analysis_mode,
    malware_defense_mode,
    ransomware_triage_mode,
    unpacking_mode,
)
from reversecore_mcp.prompts.report import report_generation_mode
from reversecore_mcp.prompts.security import (
    autonomous_vuln_hunt_mode,
    crypto_analysis_mode,
    firmware_analysis_mode,
    patch_analysis_mode,
    vulnerability_research_mode,
)
from reversecore_mcp.prompts.server_health import (
    server_health_check_mode,
    server_tool_catalog_mode,
)


def register_prompts(mcp: FastMCP):
    """
    Registers analysis scenarios (prompts) to the server.

    This function aggregates prompts from various modules and registers them
    with the FastMCP server instance.
    """
    # Malware Analysis Prompts
    mcp.prompt("full_analysis_mode")(full_analysis_mode)
    mcp.prompt("malware_analysis_mode")(malware_analysis_mode)
    mcp.prompt("basic_analysis_mode")(basic_analysis_mode)
    mcp.prompt("apt_hunting_mode")(apt_hunting_mode)
    mcp.prompt("malware_defense_mode")(malware_defense_mode)

    # NEW: Specialized Malware Prompts
    mcp.prompt("unpacking_mode")(unpacking_mode)
    mcp.prompt("c2_extraction_mode")(c2_extraction_mode)
    mcp.prompt("ransomware_triage_mode")(ransomware_triage_mode)
    mcp.prompt("code_similarity_mode")(code_similarity_mode)

    # Security Research Prompts
    mcp.prompt("patch_analysis_mode")(patch_analysis_mode)
    mcp.prompt("crypto_analysis_mode")(crypto_analysis_mode)
    mcp.prompt("firmware_analysis_mode")(firmware_analysis_mode)
    mcp.prompt("vulnerability_research_mode")(vulnerability_research_mode)
    mcp.prompt("autonomous_vuln_hunt_mode")(autonomous_vuln_hunt_mode)

    # CVE Research & Exploit Development Prompts
    mcp.prompt("taint_analysis_mode")(taint_analysis_mode)
    mcp.prompt("heap_exploit_mode")(heap_exploit_mode)
    mcp.prompt("fuzzing_mode")(fuzzing_mode)
    mcp.prompt("patch_diff_auto_mode")(patch_diff_auto_mode)
    mcp.prompt("cve_discovery_pipeline_mode")(cve_discovery_pipeline_mode)

    # Game Analysis Prompts
    mcp.prompt("game_analysis_mode")(game_analysis_mode)

    # Report Generation Prompts
    mcp.prompt("report_generation_mode")(report_generation_mode)

    # Server Inspection Prompts
    mcp.prompt("server_health_check_mode")(server_health_check_mode)
    mcp.prompt("server_tool_catalog_mode")(server_tool_catalog_mode)
