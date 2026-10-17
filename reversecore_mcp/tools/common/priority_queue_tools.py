"""MCP tools for evidence-driven analysis priority queue management in agent workflows.

Provides ranked next-analysis planning, automated triage ingestion, priority target tracking,
and blocker resolution to externalize investigation state and prevent agents from rediscovering
priorities repeatedly.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import Field

from reversecore_mcp.core.case_state import (
    TargetPriority,
    TargetStatus,
    get_case_state_manager,
)
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import (
    CaseNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.next_tool_hints import NextToolHint
from reversecore_mcp.core.result import ToolResult, success

logger = get_logger(__name__)


@log_execution(tool_name="plan_next_analysis_targets")
@handle_tool_errors
async def plan_next_analysis_targets(
    case_id: Annotated[
        str,
        Field(
            description="Unique identifier of the analysis case state (e.g. 'case_a1b2c3d4').",
        ),
    ],
    limit: Annotated[
        int,
        Field(
            default=5,
            ge=1,
            le=25,
            description="Maximum number of ranked targets to include in the plan (1 to 25).",
        ),
    ] = 5,
    include_blocked: Annotated[
        bool,
        Field(
            default=False,
            description="If True, includes targets with unresolved blockers in the ranking.",
        ),
    ] = False,
    min_priority: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional minimum priority tier filter ('critical', 'high', 'medium', 'low').",
        ),
    ] = None,
) -> ToolResult:
    """Generate an evidence-ranked next-analysis plan for an active case.

    Ranks inspection targets deterministically based on evidence references, priority level,
    active hypotheses, and blocker readiness. Provides concrete recommended tools and next steps.
    """
    manager = get_case_state_manager()
    plan_data = await manager.plan_next_analysis(
        case_id=case_id,
        limit=limit,
        include_blocked=include_blocked,
        min_priority=min_priority,
    )

    hints: list[NextToolHint] = []
    plan_targets = plan_data.get("plan_targets", [])
    if plan_targets:
        top_tgt = plan_targets[0]
        rec_tools = top_tgt.get("recommended_tools", [])
        if rec_tools:
            primary_tool = rec_tools[0]
            hints.append(
                NextToolHint(
                    tool=primary_tool,
                    reason=f"Inspect top-ranked target '{top_tgt.get('target')}' ({top_tgt.get('priority')} priority)",
                    priority=1,
                )
            )
        hints.append(
            NextToolHint(
                tool="update_priority_target",
                reason=f"Update status of '{top_tgt.get('target')}' to active/completed upon inspection",
                priority=2,
            )
        )
    else:
        hints.append(
            NextToolHint(
                tool="populate_case_queue_from_triage",
                reason="Queue has no ready pending targets; ingest findings from triage to generate new leads",
                priority=1,
            )
        )

    return success(
        plan_data,
        hints=hints,
    )


@log_execution(tool_name="populate_case_queue_from_triage")
@handle_tool_errors
async def populate_case_queue_from_triage(
    case_id: Annotated[
        str,
        Field(
            description="Unique identifier of the analysis case state (e.g. 'case_a1b2c3d4').",
        ),
    ],
    triage_data: Annotated[
        dict[str, Any] | str,
        Field(
            description="Triage findings dictionary or JSON string (imports, strings, anti_analysis, diff, injections, network, sections).",
        ),
    ],
    max_items: Annotated[
        int,
        Field(
            default=15,
            ge=1,
            le=50,
            description="Maximum number of priority targets to extract and add to the queue.",
        ),
    ] = 15,
) -> ToolResult:
    """Extract prioritized inspection leads from triage results and populate the case queue.

    Parses suspicious APIs, high-entropy sections, anti-analysis checks, diff changes,
    and network/memory IOCs into prioritized targets with rationale and evidence links.
    Skips targets that are already completed.
    """
    parsed_triage: dict[str, Any]
    if isinstance(triage_data, str):
        try:
            parsed_triage = json.loads(triage_data)
        except Exception as e:
            raise ValidationError(f"Invalid JSON string provided for triage_data: {e}") from e
    elif isinstance(triage_data, dict):
        parsed_triage = triage_data
    else:
        raise ValidationError(
            f"triage_data must be dict or JSON string, got {type(triage_data).__name__}"
        )

    manager = get_case_state_manager()
    result_data = await manager.populate_queue_from_triage(
        case_id=case_id,
        triage_data=parsed_triage,
        max_items=max_items,
    )

    hints = [
        NextToolHint(
            tool="plan_next_analysis_targets",
            reason="Review ranked next-analysis plan based on newly populated triage targets",
            priority=1,
        ),
        NextToolHint(
            tool="get_case_state",
            reason="Inspect current case state and updated targets queue",
            priority=2,
        ),
    ]

    return success(
        result_data,
        hints=hints,
    )


@log_execution(tool_name="add_priority_target")
@handle_tool_errors
async def add_priority_target(
    case_id: Annotated[
        str,
        Field(
            description="Unique identifier of the analysis case state.",
        ),
    ],
    target: Annotated[
        str,
        Field(
            description="Target symbol, address, function, artifact, or subsystem to inspect (e.g. 'sym.decrypt_config', '0x1400010a0').",
        ),
    ],
    kind: Annotated[
        str,
        Field(
            default="function",
            description="Kind of target: 'function', 'import', 'string', 'diff', 'patch', 'memory', 'pcap', 'section', 'hypothesis', 'cve'.",
        ),
    ] = "function",
    priority: Annotated[
        str,
        Field(
            default="high",
            description="Priority tier: 'critical', 'high', 'medium', 'low'.",
        ),
    ] = "high",
    reason: Annotated[
        str,
        Field(
            default="",
            description="Evidence-based rationale explaining why this target should be inspected next.",
        ),
    ] = "",
    expected_next_step: Annotated[
        str,
        Field(
            default="",
            description="Prescribed next analysis technique (e.g. 'decompile + xrefs + taint', 'simulate in ESIL').",
        ),
    ] = "",
    evidence_refs: Annotated[
        list[str] | None,
        Field(
            default=None,
            description="Evidence reference identifiers supporting this target (e.g. ['import:VirtualAllocEx', 'string:https://c2.onion']).",
        ),
    ] = None,
    blockers: Annotated[
        list[str] | None,
        Field(
            default=None,
            description="Prerequisite targets or actions that must be completed before inspecting this target.",
        ),
    ] = None,
) -> ToolResult:
    """Manually add an evidence-driven analysis target to the active case queue."""
    manager = get_case_state_manager()
    case = await manager.get_case(case_id)
    if not case:
        raise CaseNotFoundError(case_id)

    tgt = case.add_target(
        target=target,
        kind=kind,
        priority=priority,
        reason=reason,
        evidence_refs=evidence_refs,
        expected_next_step=expected_next_step,
        blockers=blockers,
    )

    if blockers:
        for b in blockers:
            case.add_blocker(
                target=target,
                reason=f"Waiting for prerequisite blocker '{b}'",
                blocked_by=[b],
            )

    await manager.save_case(case)

    return success(
        {
            "case_id": case.case_id,
            "target": tgt.to_dict(),
            "total_targets": len(case.next_targets),
        },
        hints=[
            NextToolHint(
                tool="plan_next_analysis_targets",
                reason="View updated priority plan with newly added target",
                priority=1,
            )
        ],
    )


@log_execution(tool_name="update_priority_target")
@handle_tool_errors
async def update_priority_target(
    case_id: Annotated[
        str,
        Field(
            description="Unique identifier of the analysis case state.",
        ),
    ],
    target: Annotated[
        str,
        Field(
            description="Target ID (e.g. 'tgt_1234abcd') or target identifier (e.g. 'sym.decrypt_config').",
        ),
    ],
    status: Annotated[
        str,
        Field(
            description="New lifecycle status: 'pending', 'active', 'completed', 'deferred', 'blocked', 'rejected'.",
        ),
    ],
    priority: Annotated[
        str | None,
        Field(
            default=None,
            description="Optional updated priority tier: 'critical', 'high', 'medium', 'low'.",
        ),
    ] = None,
    findings: Annotated[
        list[str] | None,
        Field(
            default=None,
            description="List of analysis findings or conclusions uncovered during inspection of this target.",
        ),
    ] = None,
    reason: Annotated[
        str | None,
        Field(
            default=None,
            description="Rationale for status update or completion summary notes.",
        ),
    ] = None,
) -> ToolResult:
    """Update a target's lifecycle status, unblock dependent targets on completion, and record findings."""
    norm_status = status.lower()
    valid_statuses = {s.value for s in TargetStatus}
    if norm_status not in valid_statuses:
        raise ValidationError(
            f"Invalid target status '{status}'. Valid statuses: {sorted(valid_statuses)}"
        )

    if priority:
        valid_priorities = {p.value for p in TargetPriority}
        if priority.lower() not in valid_priorities:
            raise ValidationError(
                f"Invalid target priority '{priority}'. Valid priorities: {sorted(valid_priorities)}"
            )

    manager = get_case_state_manager()
    result_data = await manager.update_priority_target(
        case_id=case_id,
        target_id_or_name=target,
        status=norm_status,
        priority=priority,
        findings=findings,
        reason=reason,
    )

    hints: list[NextToolHint] = [
        NextToolHint(
            tool="plan_next_analysis_targets",
            reason="Generate updated analysis plan following target status change",
            priority=1,
        ),
    ]

    unblocked = result_data.get("unblocked_targets", [])
    if unblocked:
        hints.insert(
            0,
            NextToolHint(
                tool="plan_next_analysis_targets",
                reason=f"Target completion unblocked {len(unblocked)} dependent target(s): {', '.join(unblocked[:3])}",
                priority=1,
            ),
        )

    return success(
        result_data,
        hints=hints,
    )


@log_execution(tool_name="resolve_target_blocker")
@handle_tool_errors
async def resolve_target_blocker(
    case_id: Annotated[
        str,
        Field(
            description="Unique identifier of the analysis case state.",
        ),
    ],
    target: Annotated[
        str,
        Field(
            description="Target identifier whose blocking dependency has been resolved.",
        ),
    ],
    resolution_note: Annotated[
        str,
        Field(
            default="",
            description="Explanation of how the blocking condition was satisfied or bypassed.",
        ),
    ] = "",
) -> ToolResult:
    """Resolve an explicit blocking dependency for a target, transitioning it to pending status."""
    manager = get_case_state_manager()
    case = await manager.get_case(case_id)
    if not case:
        raise CaseNotFoundError(case_id)

    resolved = case.resolve_blocker(target)

    # Also check if target in next_targets had matching blocker
    unblocked_target = None
    for t in case.next_targets:
        if t.target == target or t.id == target:
            t.status = TargetStatus.PENDING.value
            t.blockers = []
            if resolution_note:
                t.reason = f"{t.reason} | Blocker resolved: {resolution_note}"
            t.updated_at = case.last_updated
            unblocked_target = t
            break

    await manager.save_case(case)

    return success(
        {
            "case_id": case.case_id,
            "target": target,
            "resolved": resolved,
            "unblocked": unblocked_target is not None,
            "status": unblocked_target.status if unblocked_target else "not_found",
            "resolution_note": resolution_note,
        },
        hints=[
            NextToolHint(
                tool="plan_next_analysis_targets",
                reason="View updated analysis plan with now-unblocked target",
                priority=1,
            )
        ],
    )
