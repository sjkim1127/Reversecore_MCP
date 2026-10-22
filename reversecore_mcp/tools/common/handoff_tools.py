"""MCP tools for portable analyst handoff bundles.

``export_handoff_bundle`` packages case state, memory session, annotations and
artifact references (by hash) into one verifiable JSON file;
``import_handoff_bundle`` verifies integrity and sample binding before attaching
anything to the receiving workspace.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.handoff_bundle import (
    HandoffBundleError,
    SampleHashMismatchInBundle,
    build_bundle,
    import_bundle,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

MAX_BUNDLE_BYTES = 50 * 1024 * 1024


@log_execution(tool_name="export_handoff_bundle")
@track_metrics("export_handoff_bundle")
@handle_tool_errors
async def export_handoff_bundle(
    sample_path: Annotated[
        str,
        Field(description="Workspace path of the sample the investigation is about.", min_length=1),
    ],
    case_id: Annotated[
        str | None,
        Field(description="Case to include. Defaults to the latest case bound to the sample hash."),
    ] = None,
    session_id: Annotated[
        str | None,
        Field(description="Memory session to include. Defaults to the case's linked session."),
    ] = None,
    artifact_paths: Annotated[
        list[str] | None,
        Field(
            description="Workspace files (reports, YARA/Sigma rules, dumps) to reference by "
            "SHA-256. Files are referenced, never embedded."
        ),
    ] = None,
    include_annotations: Annotated[
        bool, Field(description="Include bookmarks, structures and types for the sample.")
    ] = True,
    output_name: Annotated[
        str | None,
        Field(
            description="Output filename only (default '<sample>_<hash8>.rchandoff.json'). "
            "Written inside the workspace."
        ),
    ] = None,
) -> ToolResult:
    """Export a portable analyst handoff bundle for a sample.

    The bundle records sample identity, scope and tool provenance, what is
    established vs. unresolved, relevant annotations, and integrity digests for
    every section and artifact reference.

    Args:
        sample_path: Workspace path of the sample.
        case_id: Optional case ID to include.
        session_id: Optional memory session ID to include.
        artifact_paths: Optional workspace artifacts to reference by hash.
        include_annotations: Whether to include annotation DB entries.
        output_name: Optional output filename (workspace only).

    Returns:
        ToolResult with the bundle path, digest and per-section counts.
    """
    try:
        bundle = await build_bundle(
            sample_path,
            case_id=case_id,
            session_id=session_id,
            artifact_paths=artifact_paths,
            include_annotations=include_annotations,
        )
    except HandoffBundleError as exc:
        return failure(
            "HANDOFF_EXPORT_ERROR",
            str(exc),
            recovery_hint="Check the sample path and that case_id belongs to this sample.",
            retryable=False,
        )

    sample_hash = bundle["manifest"]["sample"]["sha256"]
    if output_name:
        name = Path(output_name).name
        if not name or name in (".", ".."):
            return failure(
                "INVALID_PARAMETER",
                "output_name must be a plain filename",
                recovery_hint="Use e.g. 'case1.rchandoff.json'.",
                retryable=False,
            )
    else:
        name = f"{Path(sample_path).name}_{sample_hash[:8]}.rchandoff.json"

    workspace = get_config().workspace.resolve()
    out = (workspace / name).resolve()
    try:
        out.relative_to(workspace)
    except ValueError:
        return failure(
            "SECURITY_ERROR",
            "Output path escapes the workspace",
            recovery_hint="Use a plain filename.",
            retryable=False,
        )
    try:
        out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    except OSError as exc:
        return failure(
            "HANDOFF_EXPORT_ERROR",
            f"Failed to write bundle: {exc}",
            recovery_hint="Check workspace permissions and free space.",
            retryable=True,
        )

    sections = bundle["manifest"]["sections"]
    return success(
        {
            "bundle_path": str(out),
            "bundle_sha256": bundle["bundle_sha256"],
            "sample_sha256": sample_hash,
            "sections": {k: v["count"] for k, v in sections.items()},
            "artifacts": [
                {"path": a.get("path"), "status": a.get("status")}
                for a in bundle["manifest"]["artifacts"]
            ],
            "summary": {
                "established": len(bundle["sections"]["handoff_summary"]["established"]),
                "unresolved": len(bundle["sections"]["handoff_summary"]["unresolved"]),
                "next_checks": len(bundle["sections"]["handoff_summary"]["next_checks"]),
            },
        }
    )


@log_execution(tool_name="import_handoff_bundle")
@track_metrics("import_handoff_bundle")
@handle_tool_errors
async def import_handoff_bundle(
    bundle_path: Annotated[
        str,
        Field(description="Workspace path of the .rchandoff.json bundle.", min_length=1),
    ],
    target_file_path: Annotated[
        str | None,
        Field(
            description="Local sample whose SHA-256 must match the bundle. Strongly recommended: "
            "a mismatch aborts before anything is attached."
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        Field(description="Verify and report what would be imported without writing anything."),
    ] = False,
) -> ToolResult:
    """Verify and import an analyst handoff bundle.

    Integrity digests are checked first, then the sample hash, and only then is
    state written. Existing local cases and annotations are never overwritten:
    an already-known case is imported under a new ID and conflicting annotations
    are reported and left as-is. Missing optional artifacts are reported without
    affecting the rest of the import.

    Args:
        bundle_path: Workspace path of the bundle file.
        target_file_path: Optional local sample to verify against the bundle hash.
        dry_run: If True, nothing is written.

    Returns:
        ToolResult with per-section outcomes, artifact verification, warnings and
        the established/unresolved summary for the receiving analyst.
    """
    path = Path(validate_file_path(bundle_path))
    if not path.is_file():
        return failure(
            "HANDOFF_IMPORT_ERROR",
            f"Bundle not found: {bundle_path}",
            recovery_hint="Use list_workspace to locate the bundle.",
            retryable=False,
        )
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        return failure(
            "HANDOFF_IMPORT_ERROR",
            f"Bundle exceeds {MAX_BUNDLE_BYTES} bytes",
            recovery_hint="Handoff bundles reference artifacts; do not embed large data.",
            retryable=False,
        )
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return failure(
            "HANDOFF_IMPORT_ERROR",
            f"Failed to parse bundle: {exc}",
            recovery_hint="Provide a bundle produced by export_handoff_bundle.",
            retryable=False,
        )

    try:
        report = await import_bundle(bundle, target_file=target_file_path, dry_run=dry_run)
    except SampleHashMismatchInBundle as exc:
        return failure(
            "SAMPLE_HASH_MISMATCH",
            str(exc),
            recovery_hint="Provide the exact sample the bundle was exported for.",
            retryable=False,
        )
    except HandoffBundleError as exc:
        return failure(
            "HANDOFF_IMPORT_INVALID",
            str(exc),
            recovery_hint="The bundle is malformed or was altered; request a fresh export.",
            retryable=False,
        )
    return success(report)
