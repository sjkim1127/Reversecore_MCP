"""Retained Evidence View Inspection Tool for Reversecore_MCP.

Provides ``inspect_analysis_view`` so AI agents can paginate and filter
cached analysis outputs (disassembly instructions, decompiled lines, strings,
Go/Rust symbols, Electron ASAR files, and Unity IL2CPP metadata) produced
by summary-first tool invocations.
"""

from __future__ import annotations

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.evidence_cache import get_evidence_cache
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success


@log_execution(tool_name="inspect_analysis_view")
@track_metrics("inspect_analysis_view")
@handle_tool_errors
async def inspect_analysis_view(
    evidence_id: str,
    facet: str | None = None,
    offset: int = 0,
    limit: int = 50,
    filter_query: str | None = None,
) -> ToolResult:
    """Paginate and filter a retained analysis result by its ``evidence_id``.

    When a tool is called with ``detail="summary"``, it caches the complete output
    in the session EvidenceCache and returns an ``evidence_id`` (e.g. ``ev_8f3a92b1c4d0``).
    Use ``inspect_analysis_view`` to inspect specific pages or filter items without
    flooding the LLM context window. Pass ``evidence_id="list"`` to view all
    retained evidence handles in the current session.

    Args:
        evidence_id: Retained evidence identifier (e.g. 'ev_8f3a92b1c4d0'), or 'list'
            to enumerate all cached evidence records in the session.
        facet: Optional facet name to inspect (e.g. 'instructions', 'lines', 'strings',
            'functions', 'files', 'packages', 'literals'). Defaults to primary facet.
        offset: Zero-based starting item index for pagination (default: 0).
        limit: Maximum number of items to return per page (default: 50, max: 500).
        filter_query: Optional case-insensitive substring filter applied before slicing.

    Returns:
        ToolResult containing the paginated slice, total item counts, available facets,
        and ``next_offset`` for subsequent pages.
    """
    cache = get_evidence_cache()
    clean_id = (evidence_id or "").strip()

    if not clean_id:
        return failure(
            "VALIDATION_ERROR",
            "evidence_id is required (pass 'list' to see retained evidence handles).",
        )

    if clean_id.lower() == "list":
        records = cache.list_records(limit=max(1, min(limit, 100)))
        return success(
            data={
                "status": "success",
                "total_retained": len(records),
                "records": records,
            },
            message=f"Found {len(records)} retained evidence record(s) in session cache.",
        )

    view = cache.query_view(
        evidence_id=clean_id,
        facet=facet,
        offset=offset,
        limit=limit,
        filter_query=filter_query,
    )

    if view is None:
        recent = [r["evidence_id"] for r in cache.list_records(limit=5)]
        hint_msg = (
            f"Available recent evidence_ids: {', '.join(recent)}"
            if recent
            else "No evidence records are currently cached. Run an analysis tool with detail='summary' first."
        )
        return failure(
            "EVIDENCE_NOT_FOUND",
            f"Evidence record '{clean_id}' was not found or has expired from the LRU cache.",
            hint=hint_msg,
        )

    return success(
        data=view,
        message=(
            f"Retrieved {view['returned_items']}/{view['total_items']} items from "
            f"{clean_id} (facet='{view['selected_facet']}', offset={view['offset']})."
        ),
    )
