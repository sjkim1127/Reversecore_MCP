"""Prompts package for Reversecore MCP Tools."""

from fastmcp import FastMCP

from reversecore_mcp.prompts.game import game_analysis_mode
from reversecore_mcp.prompts.malware import (
    apt_hunting_mode,
    basic_analysis_mode,
    full_analysis_mode,
    malware_analysis_mode,
    vulnerability_hunter_mode,
)
from reversecore_mcp.prompts.report import report_generation_mode
from reversecore_mcp.prompts.security import (
    crypto_analysis_mode,
    firmware_analysis_mode,
    patch_analysis_mode,
    vulnerability_research_mode,
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
    mcp.prompt("vulnerability_hunter_mode")(vulnerability_hunter_mode)

    # Security Research Prompts
    mcp.prompt("patch_analysis_mode")(patch_analysis_mode)
    mcp.prompt("crypto_analysis_mode")(crypto_analysis_mode)
    mcp.prompt("firmware_analysis_mode")(firmware_analysis_mode)
    mcp.prompt("vulnerability_research_mode")(vulnerability_research_mode)

    # Game Analysis Prompts
    mcp.prompt("game_analysis_mode")(game_analysis_mode)

    # Report Generation Prompts
    mcp.prompt("report_generation_mode")(report_generation_mode)
