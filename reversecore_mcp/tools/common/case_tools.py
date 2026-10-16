"""MCP tools for machine-readable analysis case state management across agent sessions.

Provides state persistence, phase tracking (intake -> triage -> hypothesis_generation ->
deep_analysis -> verification -> reporting -> completed), hash-bound sample validation,
active hypotheses, next target priority queues, blockers, and artifact references.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from reversecore_mcp.core.case_state import (
    CaseState,
    get_case_state_manager,
)
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import (
    CaseNotFoundError,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.next_tool_hints import NextToolHint
from reversecore_mcp.core.result import ToolResult, failure, success

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Tool Implementations
# ---------------------------------------------------------------------------


@log_execution(tool_name="create_case_state")
@handle_tool_errors
async def create_case_state(
    sample_path: Annotated[
        str,
        Field(
            description="Path to target binary or artifact in workspace to bind this case to.",
        ),
    ],
    case_name: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional descriptive case name (e.g. 'lockbit_v3_loader', 'incident_2026_host01').",
        ),
    ] = None,
    initial_phase: Annotated[
        str,
        Field(
            default="intake",
            description="Initial analysis phase: intake, triage, hypothesis_generation, deep_analysis, verification, reporting, completed.",
        ),
    ] = "intake",
    session_id: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional linked memory or reporting session UUID.",
        ),
    ] = None,
    hypotheses: Annotated[
        list[dict[str, Any]] | None,
        Field(
            default=None,
            description="Optional initial hypotheses list (each with title, category, evidence_level, rationale).",
        ),
    ] = None,
    targets: Annotated[
        list[dict[str, Any]] | None,
        Field(
            default=None,
            description="Optional initial inspection targets (each with target, kind, priority, reason, expected_next_step).",
        ),
    ] = None,
) -> ToolResult:
    """Create a persistent machine-readable analysis case bound to sample SHA-256 integrity."""
    manager = get_case_state_manager()
    case = await manager.create_case(
        sample_path=sample_path,
        case_name=case_name,
        initial_phase=initial_phase,
        session_id=session_id,
    )

    if hypotheses:
        for h in hypotheses:
            if isinstance(h, dict) and "title" in h:
                case.add_hypothesis(
                    title=h["title"],
                    category=h.get("category", "general"),
                    evidence_level=h.get("evidence_level", "possible"),
                    evidence_refs=h.get("evidence_refs"),
                    rationale=h.get("rationale", ""),
                )

    if targets:
        for t in targets:
            if isinstance(t, dict) and "target" in t:
                case.add_target(
                    target=t["target"],
                    kind=t.get("kind", "function"),
                    priority=t.get("priority", "medium"),
                    reason=t.get("reason", ""),
                    evidence_refs=t.get("evidence_refs"),
                    expected_next_step=t.get("expected_next_step", ""),
                    blockers=t.get("blockers"),
                )

    if hypotheses or targets:
        await manager.save_case(case)

    # Adaptive follow-up hint
    recommended_hints: list[NextToolHint] = [
        {
            "tool": "recommend_analysis_plan",
            "reason": f"Generate a goal-aware execution plan for sample '{case.sample.name}'.",
            "confidence": "high",
            "suggested_args": {"target_file": case.sample.path, "depth": "standard"},
            "priority": 1,
        }
    ]

    return success(
        {
            "case": case.to_summary_dict(),
            "case_id": case.case_id,
            "phase": case.phase,
            "sample_hash": case.sample.sha256,
        },
        hints=recommended_hints,
    )


@log_execution(tool_name="get_case_state")
@handle_tool_errors
async def get_case_state(
    case_id: Annotated[
        str | None,
        Field(
            default=None,
            description="Unique case ID (e.g. 'case_sample.exe_a1b2c3'). Required if sample_path not given.",
        ),
    ] = None,
    sample_path: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional sample path to look up latest case bound to this file's SHA-256.",
        ),
    ] = None,
    full_details: Annotated[
        bool,
        Field(
            default=False,
            description="If True, returns complete history including all steps; if False, returns compact summary.",
        ),
    ] = False,
) -> ToolResult:
    """Retrieve persistent analysis case state by ID or sample path."""
    manager = get_case_state_manager()
    case: CaseState | None = None

    if case_id:
        case = await manager.get_case(case_id)
    elif sample_path:
        from pathlib import Path

        from reversecore_mcp.core.analysis_cache import calculate_file_sha256
        from reversecore_mcp.core.security import validate_file_path

        path_obj: Path | None = None
        try:
            safe_path = validate_file_path(sample_path)
            path_obj = Path(safe_path)
        except Exception:
            p = Path(sample_path)
            if p.exists() and p.is_file():
                path_obj = p

        if path_obj and path_obj.exists() and path_obj.is_file():
            sha256 = calculate_file_sha256(path_obj)
            case = await manager.get_case_by_sample_hash(sha256)
    else:
        return failure(
            "INVALID_ARGUMENTS",
            "Either 'case_id' or 'sample_path' must be provided.",
            recovery_hint="Specify a valid case_id or provide sample_path to look up existing cases.",
        )

    if not case:
        identifier = case_id or sample_path or "unknown"
        raise CaseNotFoundError(identifier)

    result_data = case.to_dict() if full_details else case.to_summary_dict()
    return success(
        {
            "case": result_data,
            "case_id": case.case_id,
            "phase": case.phase,
        }
    )


@log_execution(tool_name="update_case_state")
@handle_tool_errors
async def update_case_state(
    case_id: Annotated[
        str,
        Field(description="Unique ID of the analysis case to update."),
    ],
    phase: Annotated[
        str | None,
        Field(
            default=None,
            description="New analysis phase: intake, triage, hypothesis_generation, deep_analysis, verification, reporting, completed.",
        ),
    ] = None,
    force_phase: Annotated[
        bool,
        Field(
            default=False,
            description="If True, allows stepping backward in phase progression or resetting phases.",
        ),
    ] = False,
    add_step: Annotated[
        dict[str, Any] | None,
        Field(
            default=None,
            description="Record a completed operation (step_id, tool_name, summary, output_summary).",
        ),
    ] = None,
    add_hypothesis: Annotated[
        dict[str, Any] | None,
        Field(
            default=None,
            description="Add a new hypothesis (title, category, evidence_level, evidence_refs, rationale).",
        ),
    ] = None,
    update_hypothesis: Annotated[
        dict[str, Any] | None,
        Field(
            default=None,
            description="Update an existing hypothesis (hyp_id, status, evidence_refs, contradictions, rationale, evidence_level).",
        ),
    ] = None,
    add_target: Annotated[
        dict[str, Any] | None,
        Field(
            default=None,
            description="Add or update an inspection target (target, kind, priority, reason, expected_next_step, blockers).",
        ),
    ] = None,
    update_target: Annotated[
        dict[str, Any] | None,
        Field(
            default=None,
            description="Update target status (target_id_or_name, status, reason).",
        ),
    ] = None,
    add_blocker: Annotated[
        dict[str, Any] | None,
        Field(
            default=None,
            description="Add a blocking condition (target, reason, blocked_by, suggested_resolution).",
        ),
    ] = None,
    resolve_blocker: Annotated[
        str | None,
        Field(
            default=None,
            description="Target name to clear blocking status for.",
        ),
    ] = None,
    add_artifact: Annotated[
        dict[str, Any] | None,
        Field(
            default=None,
            description="Attach an artifact reference (name, artifact_type, path, uri, sha256, metadata).",
        ),
    ] = None,
) -> ToolResult:
    """Incrementally update case state, phase, hypotheses, targets, blockers, or artifacts."""
    manager = get_case_state_manager()
    case = await manager.get_case(case_id)
    if not case:
        raise CaseNotFoundError(case_id)

    # 1. Phase transition
    if phase:
        case.transition_phase(phase, force=force_phase)

    # 2. Record step
    if add_step and isinstance(add_step, dict):
        case.record_step(
            step_id=add_step.get("step_id", f"step_{len(case.completed_steps) + 1}"),
            tool_name=add_step.get("tool_name", "unknown"),
            summary=add_step.get("summary", ""),
            phase=add_step.get("phase"),
            output_summary=add_step.get("output_summary"),
        )

    # 3. Add hypothesis
    if add_hypothesis and isinstance(add_hypothesis, dict):
        case.add_hypothesis(
            title=add_hypothesis.get("title", "Untitled hypothesis"),
            category=add_hypothesis.get("category", "general"),
            evidence_level=add_hypothesis.get("evidence_level", "possible"),
            evidence_refs=add_hypothesis.get("evidence_refs"),
            rationale=add_hypothesis.get("rationale", ""),
            hyp_id=add_hypothesis.get("hyp_id"),
        )

    # 4. Update hypothesis
    if update_hypothesis and isinstance(update_hypothesis, dict):
        hyp_id = update_hypothesis.get("hyp_id")
        if hyp_id:
            case.update_hypothesis(
                hyp_id=hyp_id,
                status=update_hypothesis.get("status"),
                evidence_refs=update_hypothesis.get("evidence_refs"),
                contradictions=update_hypothesis.get("contradictions"),
                rationale=update_hypothesis.get("rationale"),
                evidence_level=update_hypothesis.get("evidence_level"),
            )

    # 5. Add target
    if add_target and isinstance(add_target, dict):
        case.add_target(
            target=add_target.get("target", "unknown"),
            kind=add_target.get("kind", "function"),
            priority=add_target.get("priority", "medium"),
            reason=add_target.get("reason", ""),
            evidence_refs=add_target.get("evidence_refs"),
            expected_next_step=add_target.get("expected_next_step", ""),
            blockers=add_target.get("blockers"),
            target_id=add_target.get("target_id"),
        )

    # 6. Update target
    if update_target and isinstance(update_target, dict):
        target_name = update_target.get("target_id_or_name") or update_target.get("target")
        status = update_target.get("status")
        if target_name and status:
            case.update_target_status(
                target_id_or_name=target_name,
                status=status,
                reason=update_target.get("reason"),
            )

    # 7. Add blocker
    if add_blocker and isinstance(add_blocker, dict):
        case.add_blocker(
            target=add_blocker.get("target", "unknown"),
            reason=add_blocker.get("reason", "Blocked"),
            blocked_by=add_blocker.get("blocked_by"),
            suggested_resolution=add_blocker.get("suggested_resolution", ""),
        )

    # 8. Resolve blocker
    if resolve_blocker:
        case.resolve_blocker(resolve_blocker)

    # 9. Add artifact
    if add_artifact and isinstance(add_artifact, dict):
        case.add_artifact(
            name=add_artifact.get("name", "artifact"),
            artifact_type=add_artifact.get("artifact_type", "report"),
            path=add_artifact.get("path"),
            uri=add_artifact.get("uri"),
            sha256=add_artifact.get("sha256"),
            metadata=add_artifact.get("metadata"),
        )

    await manager.save_case(case)
    return success(
        {
            "case": case.to_summary_dict(),
            "case_id": case.case_id,
            "phase": case.phase,
        }
    )


@log_execution(tool_name="resume_case_state")
@handle_tool_errors
async def resume_case_state(
    case_id: Annotated[
        str,
        Field(description="Unique ID of the analysis case to resume."),
    ],
    sample_path: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional sample path to verify against case's bound SHA-256.",
        ),
    ] = None,
    verify_hash: Annotated[
        bool,
        Field(
            default=True,
            description="If True, verifies that sample file on disk matches stored SHA-256.",
        ),
    ] = True,
) -> ToolResult:
    """Resume an existing analysis case with hash verification and actionable guidance."""
    manager = get_case_state_manager()
    resume_payload = await manager.resume_case(
        case_id=case_id,
        sample_path=sample_path,
        verify_hash=verify_hash,
    )

    # Generate recommended next tool hints based on top target
    recommended_hints: list[NextToolHint] = []
    top_target = resume_payload.get("top_target")
    if top_target:
        target_name = top_target.get("target", "")
        next_step = (top_target.get("expected_next_step") or "").lower()
        target_file = resume_payload["sample"]["path"]

        tool_hint = "r2_decompile"
        suggested_args: dict[str, Any] = {"file_path": target_file, "function_name": target_name}
        if "disasm" in next_step:
            tool_hint = "r2_disassemble"
        elif "taint" in next_step:
            tool_hint = "taint_trace"
            suggested_args = {"file_path": target_file, "source_api": target_name}

        recommended_hints.append(
            {
                "tool": tool_hint,
                "reason": f"Inspect top priority target '{target_name}': {top_target.get('reason') or 'deep inspection'}",
                "confidence": "high",
                "suggested_args": suggested_args,
                "priority": 1,
            }
        )

    return success(
        {
            "resumption": resume_payload,
            "case_id": resume_payload["case_id"],
            "phase": resume_payload["phase"],
        },
        hints=recommended_hints,
    )


@log_execution(tool_name="list_case_states")
@handle_tool_errors
async def list_case_states(
    phase: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional phase filter (intake, triage, hypothesis_generation, deep_analysis, verification, reporting, completed).",
        ),
    ] = None,
    limit: Annotated[
        int,
        Field(default=50, ge=1, le=200, description="Maximum number of cases to return."),
    ] = 50,
) -> ToolResult:
    """List persistent analysis cases."""
    manager = get_case_state_manager()
    cases = await manager.list_cases(phase=phase, limit=limit)
    return success(
        {
            "cases": cases,
            "total_count": len(cases),
        }
    )
