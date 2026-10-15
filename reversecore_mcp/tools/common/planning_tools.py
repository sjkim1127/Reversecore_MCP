"""MCP tools for goal-aware tool recommendations and adaptive analysis plans.

Allows AI agents to obtain structured, depth-tiered execution workflows (quick,
standard, deep) composed strictly of existing Reversecore MCP tools, optimized
for sample format, target architecture, analysis objective, and profile.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.planner import (
    AnalysisObjective,
    DepthTier,
    SampleFormat,
    generate_analysis_plan,
)
from reversecore_mcp.core.result import ToolResult, success


@log_execution(tool_name="recommend_analysis_plan")
@handle_tool_errors
async def recommend_analysis_plan(
    target_file: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional path to target binary, capture, or source sample in workspace (e.g. 'sample.exe', 'dump.raw').",
        ),
    ] = None,
    objective: Annotated[
        str,
        Field(
            default="malware_triage",
            description=(
                "Analysis objective: static_triage, malware_triage, vulnerability_research, "
                "unpacking_deobfuscation, incident_reconstruction, patch_review, forensics."
            ),
        ),
    ] = "malware_triage",
    depth: Annotated[
        str,
        Field(
            default="standard",
            description="Analysis depth tier: quick (fingerprinting/fast triage), standard (balanced workflow), deep (broader emulation/deobfuscation/fuzzing).",
        ),
    ] = "standard",
    sample_format: Annotated[
        str | None,
        Field(
            default=None,
            description="Explicit binary or data format (pe, elf, macho, pcap, memory, disk, source, generic). Auto-detected if target_file is provided.",
        ),
    ] = None,
    architecture: Annotated[
        str | None,
        Field(
            default=None,
            description="Target architecture if known (e.g. 'x86', 'x86_64', 'arm', 'arm64', 'mips'). Defaults to 'x86_64'.",
        ),
    ] = None,
    profile: Annotated[
        str | None,
        Field(
            default=None,
            description="Active or requested MCP tool profile: full, static, malware, forensics, vuln-research.",
        ),
    ] = None,
    time_budget_seconds: Annotated[
        int | None,
        Field(
            default=None,
            description="Optional time or resource budget in seconds (e.g. 30 for quick, 120 for standard, 300+ for deep).",
        ),
    ] = None,
) -> ToolResult:
    """Recommend a goal-aware, depth-tiered analysis plan composed of existing MCP tools.

    Given a file, objective, and depth tier, evaluates tool availability, active
    profile constraints, and external dependencies to synthesize a sequential
    tool pipeline with conditional branches, stop conditions, and rationales.

    Args:
        target_file: Path to sample in workspace.
        objective: Goal of the analysis.
        depth: Analysis depth tier ('quick', 'standard', 'deep').
        sample_format: Optional explicit format override.
        architecture: Target CPU architecture.
        profile: Active profile filter.
        time_budget_seconds: Optional execution budget.

    Returns:
        ToolResult with machine-readable AnalysisPlan and recommended next tool hint.
    """
    plan = generate_analysis_plan(
        target_file=target_file,
        file_format=sample_format,
        architecture=architecture,
        objective=objective,
        depth=depth,
        profile=profile,
        time_budget_seconds=time_budget_seconds,
    )

    plan_dict = plan.model_dump()

    # Formulate next-tool hint from first step if available
    hints = []
    if plan.primary_steps:
        first_step = plan.primary_steps[0]
        hints.append(
            {
                "tool": first_step.tool,
                "reason": f"Plan step 1: {first_step.purpose}",
                "confidence": "high",
                "suggested_args": first_step.parameters,
                "priority": 1,
            }
        )

    return success(plan_dict, hints=hints)


__all__ = [
    "recommend_analysis_plan",
    "AnalysisObjective",
    "DepthTier",
    "SampleFormat",
]
