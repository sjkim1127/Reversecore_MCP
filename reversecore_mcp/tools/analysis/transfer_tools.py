"""Cross-binary function identity and annotation transfer tools.

Provides MCP tools to:
- Establish architecture compatibility and match functions across binary revisions
- Propagate analyst annotations, bookmarks, types, structures, and findings safely
- Keep changed functions as historical context requiring re-verification
- Never auto-promote ambiguous 1-to-many or many-to-one matches
- Review and verify/reject suggested transfers
"""

from __future__ import annotations

import asyncio

from reversecore_mcp.core.annotation_transfer import (
    CrossBinaryTransferEngine,
    compute_file_sha256,
)
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import (
    PaginationMeta,
    ToolResult,
    failure,
    success,
)
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.radare2.r2_db import (
    _validate_annotation_pagination,
    apply_transferred_annotation_sync,
    list_transferred_annotations_sync,
)

logger = get_logger(__name__)
DEFAULT_TIMEOUT = get_config().default_tool_timeout


@log_execution(tool_name="match_functions_across_binaries")
@track_metrics("match_functions_across_binaries")
@handle_tool_errors
async def match_functions_across_binaries(
    file_path_a: str,
    file_path_b: str,
    min_confidence: float = 0.6,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Match functions across two binary files using identity signals and CFG metrics.

    Identifies exact, strong, probable, and ambiguous function pairings between
    two versions or variants of a binary. Rebased or renumbered functions with
    identical code or CFG structure are paired reliably.

    Args:
        file_path_a: Path to the original or reference binary file.
        file_path_b: Path to the target, revision, or variant binary file.
        min_confidence: Minimum similarity score (0.0 - 1.0) for candidate matching.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with architecture compatibility, function matches, and state classifications.
    """
    if min_confidence < 0.0 or min_confidence > 1.0:
        return failure("VALIDATION_ERROR", "min_confidence must be between 0.0 and 1.0.")

    path_a = validate_file_path(file_path_a)
    path_b = validate_file_path(file_path_b)

    engine = CrossBinaryTransferEngine(timeout=timeout)

    # 1. Architecture compatibility check
    arch_info = await engine.check_architecture_compatibility(path_a, path_b)
    if not arch_info["compatible"]:
        return failure(
            "COMPATIBILITY_ERROR",
            "Incompatible binary architectures for function matching.",
            details=arch_info["reasons"],
        )

    # 2. Extract function fingerprints
    funcs_a, funcs_b = await asyncio.gather(
        engine.extract_functions(path_a),
        engine.extract_functions(path_b),
    )

    if not funcs_a or not funcs_b:
        return failure(
            "EXTRACTION_ERROR",
            "Failed to extract functions from one or both binaries.",
            details={
                "binary_a_function_count": len(funcs_a),
                "binary_b_function_count": len(funcs_b),
            },
        )

    # 3. Radiff2 graphdiff (if available)
    radiff_diffs = await engine._run_radiff2_graphdiff(path_a, path_b)

    # 4. Deterministic function matching
    matches = engine.match_functions(funcs_a, funcs_b, radiff_diffs, min_confidence=min_confidence)

    exact_count = sum(1 for m in matches if m.match_state.value == "exact")
    strong_count = sum(1 for m in matches if m.match_state.value == "strong_match")
    probable_count = sum(1 for m in matches if m.match_state.value == "probable")
    ambiguous_count = sum(1 for m in matches if m.match_state.value == "ambiguous")
    unmatched_count = sum(1 for m in matches if m.match_state.value == "unmatched")

    return success(
        {
            "binary_a": str(path_a),
            "binary_b": str(path_b),
            "total_source_functions": len(funcs_a),
            "total_target_functions": len(funcs_b),
            "summary": {
                "exact": exact_count,
                "strong_match": strong_count,
                "probable": probable_count,
                "ambiguous": ambiguous_count,
                "unmatched": unmatched_count,
            },
            "matches": [m.to_dict() for m in matches],
        }
    )


@log_execution(tool_name="transfer_annotations_across_binaries")
@track_metrics("transfer_annotations_across_binaries")
@handle_tool_errors
async def transfer_annotations_across_binaries(
    source_path: str,
    target_path: str,
    auto_apply_exact: bool = False,
    case_id: str | None = None,
    min_confidence: float = 0.6,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Transfer analyst annotations, bookmarks, types, structures, and findings across binaries.

    Propagates knowledge from an analyzed source binary to a new revision or variant.
    Exact matches may be auto-applied if requested; all other matches are exposed as
    suggested context with full provenance so changed logic requires re-verification.
    Ambiguous matches remain unresolved and are never auto-applied.

    Args:
        source_path: Path to the analyzed source binary with existing annotations.
        target_path: Path to the destination binary revision.
        auto_apply_exact: Whether to automatically activate exact (100% identical) matches.
        case_id: Optional persistent investigation case ID to propagate case findings.
        min_confidence: Minimum match confidence (default: 0.6).
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult summarizing transferred items, suggested context, and unresolved ambiguities.
    """
    path_src = validate_file_path(source_path)
    path_tgt = validate_file_path(target_path)

    engine = CrossBinaryTransferEngine(timeout=timeout)
    transfer_res = await engine.execute_transfer(
        source_path=path_src,
        target_path=path_tgt,
        auto_apply_exact=auto_apply_exact,
        case_id=case_id,
        min_confidence=min_confidence,
    )

    if transfer_res.get("status") == "error":
        return failure(
            "TRANSFER_ERROR",
            transfer_res.get("error", "Transfer failed"),
            details=transfer_res,
        )

    return success(transfer_res)


@log_execution(tool_name="review_transferred_annotations")
@track_metrics("review_transferred_annotations")
@handle_tool_errors
async def review_transferred_annotations(
    file_path: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> ToolResult:
    """List transferred annotations, bookmarks, and findings for a binary.

    Exposes transferred knowledge as suggested or verified context with complete
    source provenance, match confidence, and historical context.

    Args:
        file_path: Path to the target binary file.
        status: Optional filter by status ('suggested', 'verified', 'rejected', 'unresolved').
        limit: Number of items to return (1-500).
        offset: Offset for pagination.

    Returns:
        ToolResult with paginated transferred annotations.
    """
    pagination_error = _validate_annotation_pagination(limit, offset)
    if pagination_error is not None:
        return pagination_error

    validated = validate_file_path(file_path)
    bh = compute_file_sha256(validated)

    items, total_items = await asyncio.to_thread(
        list_transferred_annotations_sync, bh, status, limit, offset
    )

    has_more = offset + len(items) < total_items
    next_offset = offset + len(items) if has_more else None

    return success(
        {
            "binary_hash": bh,
            "transferred_annotations": items,
            "count": len(items),
        },
        pagination=PaginationMeta(
            has_more=has_more,
            next_cursor=str(next_offset) if next_offset is not None else None,
            total_items=total_items,
            page=(offset // limit) + 1,
            page_size=limit,
            truncated=has_more,
        ),
    )


@log_execution(tool_name="apply_transferred_annotation")
@track_metrics("apply_transferred_annotation")
@handle_tool_errors
async def apply_transferred_annotation(
    transfer_id: int,
    verified: bool = True,
) -> ToolResult:
    """Accept or reject a suggested transferred annotation.

    When verified=True, the suggested annotation is promoted to active status and
    installed into the target binary's persistent bookmark, structure, or type store.
    When verified=False, the transfer is marked rejected.

    Args:
        transfer_id: Unique database ID of the transferred annotation record.
        verified: True to accept and verify the annotation; False to reject it.

    Returns:
        ToolResult with the updated transfer record and confirmation of active installation.
    """
    if not isinstance(transfer_id, int) or isinstance(transfer_id, bool) or transfer_id < 1:
        return failure("VALIDATION_ERROR", "transfer_id must be a positive integer.")

    updated = await asyncio.to_thread(apply_transferred_annotation_sync, transfer_id, verified)

    if not updated:
        return failure("NOT_FOUND", f"Transferred annotation record #{transfer_id} not found.")

    return success(
        {
            "transfer_id": transfer_id,
            "status": updated["status"],
            "item_type": updated["item_type"],
            "target_address": updated["target_address"],
            "applied": verified,
            "annotation": updated,
        }
    )
