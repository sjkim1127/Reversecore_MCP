"""Portable analyst handoff bundle: export, integrity verification and import.

A handoff bundle packages the state another analyst (or MCP client) needs to
resume an investigation without repeating discovery work. It is composed from
existing Reversecore stores rather than introducing a collaboration database:

* ``CaseState`` (phase, hypotheses with evidence levels, targets, blockers)
* memory sessions and their memories (findings / notes)
* the SQLite annotation DB (bookmarks, structures, types)
* references (path + SHA-256) to generated workspace artifacts

Design rules:

* **References over copies** - artifacts are referenced by hash, never embedded.
* **Integrity first** - every section carries a SHA-256 digest and the bundle a
  digest over manifest + sections; nothing is written when verification fails.
* **Hash binding** - a sample hash mismatch is surfaced before any state is
  attached to the wrong sample.
* **Receiver wins** - existing annotations/cases are never overwritten; conflicts
  are reported and imported cases receive a fresh ID.
* **Provenance preserved** - evidence levels and statuses are carried verbatim.
"""

from __future__ import annotations

import asyncio
import hashlib
import json as _stdjson
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reversecore_mcp import __version__
from reversecore_mcp.core.analysis_cache import calculate_file_sha256
from reversecore_mcp.core.case_state import (
    CaseState,
    HypothesisStatus,
    get_case_state_manager,
)
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

BUNDLE_FORMAT = "rchandoff"
BUNDLE_VERSION = 1
SECTION_NAMES = ("case_state", "memory_session", "annotations", "handoff_summary")


class HandoffBundleError(Exception):
    """Raised when a bundle is malformed or fails integrity verification."""


class SampleHashMismatchInBundle(HandoffBundleError):
    """Raised when the bundle's sample hash differs from the provided local sample."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_digest(obj: Any) -> str:
    """Return a stable SHA-256 over the canonical JSON form of ``obj``."""
    encoded = _stdjson.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _section_count(name: str, data: Any) -> int:
    if data is None:
        return 0
    if name == "annotations":
        return sum(len(data.get(k, [])) for k in ("bookmarks", "structures", "types"))
    if name == "memory_session":
        return len(data.get("memories", []))
    if name == "handoff_summary":
        return len(data.get("established", [])) + len(data.get("unresolved", []))
    return 1


def build_handoff_summary(case: CaseState | None) -> dict[str, Any]:
    """Split case state into established work and unresolved questions.

    Verified hypotheses and completed steps count as *established*; active or
    inconclusive hypotheses, pending targets and blockers are *unresolved*.
    Evidence levels are preserved so the receiver can judge confidence.
    """
    if case is None:
        return {"established": [], "unresolved": [], "next_checks": [], "blocked": []}

    established: list[dict[str, Any]] = [
        {
            "kind": "hypothesis",
            "id": h.id,
            "title": h.title,
            "evidence_level": h.evidence_level,
            "evidence_refs": list(h.evidence_refs),
        }
        for h in case.active_hypotheses
        if h.status == HypothesisStatus.VERIFIED.value
    ]
    established.extend(
        {
            "kind": "completed_step",
            "id": s.step_id,
            "tool": s.tool_name,
            "phase": s.phase,
            "summary": s.summary,
        }
        for s in case.completed_steps
    )
    unresolved = [
        {
            "kind": "hypothesis",
            "id": h.id,
            "title": h.title,
            "status": h.status,
            "evidence_level": h.evidence_level,
            "contradictions": list(h.contradictions),
        }
        for h in case.active_hypotheses
        if h.status in (HypothesisStatus.ACTIVE.value, HypothesisStatus.INCONCLUSIVE.value)
    ]
    next_checks = [
        {
            "target": t.target,
            "kind": t.kind,
            "priority": t.priority,
            "reason": t.reason,
            "expected_next_step": t.expected_next_step,
        }
        for t in case.get_sorted_targets()
    ]
    return {
        "established": established,
        "unresolved": unresolved,
        "next_checks": next_checks,
        "blocked": [b.to_dict() for b in case.blocked],
    }


def _describe_artifact(path_str: str) -> dict[str, Any]:
    """Build a reference entry (never embeds content) for a workspace artifact."""
    workspace = get_config().workspace.resolve()
    try:
        safe = Path(validate_file_path(str(path_str))).resolve()
    except Exception as exc:
        return {"path": str(path_str), "status": "skipped", "reason": f"invalid path: {exc}"}
    try:
        rel = safe.relative_to(workspace).as_posix()
    except ValueError:
        rel = safe.name
    if not safe.is_file():
        return {"path": rel, "status": "missing_at_export", "sha256": None}
    return {
        "path": rel,
        "name": safe.name,
        "sha256": calculate_file_sha256(safe),
        "size_bytes": safe.stat().st_size,
        "status": "referenced",
    }


async def build_bundle(
    sample_path: str,
    case_id: str | None = None,
    session_id: str | None = None,
    artifact_paths: list[str] | None = None,
    include_annotations: bool = True,
) -> dict[str, Any]:
    """Assemble a handoff bundle for a sample from existing Reversecore stores.

    Args:
        sample_path: Workspace path of the sample the investigation is about.
        case_id: Optional case to include. If omitted, the latest case bound to
            the sample hash is used when one exists.
        session_id: Optional memory session to include (defaults to the case's
            linked session).
        artifact_paths: Optional workspace files (reports, rules, dumps) to
            reference by hash.
        include_annotations: Include bookmarks/structures/types for the sample.

    Returns:
        The bundle dict (not yet written to disk).

    Raises:
        HandoffBundleError: If the sample cannot be hashed or a requested case is
            bound to a different sample.
    """
    from reversecore_mcp.tools.radare2.r2_db import export_annotations_sync

    sample = Path(validate_file_path(str(sample_path)))
    sample_hash = await asyncio.to_thread(calculate_file_sha256, sample)
    if not sample_hash:
        raise HandoffBundleError(f"Could not hash sample: {sample_path}")

    manager = get_case_state_manager()
    case: CaseState | None
    if case_id:
        case = await manager.get_case(case_id)
        if case is None:
            raise HandoffBundleError(f"Case not found: {case_id}")
        if case.sample.sha256 != sample_hash:
            raise HandoffBundleError(
                f"Case {case_id} is bound to {case.sample.sha256[:12]}..., "
                f"but the sample hashes to {sample_hash[:12]}...; refusing to export."
            )
    else:
        case = await manager.get_case_by_sample_hash(sample_hash)

    memory_section: dict[str, Any] | None = None
    effective_session = session_id or (case.session_id if case else None)
    if effective_session:
        store = manager.memory_store
        await store.initialize()
        session_row = await store.get_session(effective_session)
        if session_row is not None:
            memory_section = {
                "session": session_row,
                "memories": await store.get_session_memories(effective_session),
            }

    annotations: dict[str, Any] | None = None
    if include_annotations:
        annotations = await asyncio.to_thread(export_annotations_sync, sample_hash)

    artifacts = [_describe_artifact(p) for p in (artifact_paths or [])]

    sections: dict[str, Any] = {
        "case_state": case.to_dict() if case else None,
        "memory_session": memory_section,
        "annotations": annotations,
        "handoff_summary": build_handoff_summary(case),
    }
    manifest: dict[str, Any] = {
        "sample": {
            "sha256": sample_hash,
            "name": sample.name,
            "size_bytes": sample.stat().st_size,
            "format": case.sample.format if case else None,
        },
        "scope": {
            "case_id": case.case_id if case else None,
            "session_id": effective_session,
            "phase": case.phase if case else None,
        },
        "environment": {
            "reversecore_version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "sections": {
            name: {
                "sha256": canonical_digest(sections[name]),
                "count": _section_count(name, sections[name]),
            }
            for name in SECTION_NAMES
        },
        "artifacts": artifacts,
    }
    return {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "created_at": _utc_now_iso(),
        "manifest": manifest,
        "sections": sections,
        "bundle_sha256": canonical_digest({"manifest": manifest, "sections": sections}),
    }


def verify_bundle(bundle: Any) -> dict[str, Any]:
    """Verify structure and integrity digests of a bundle.

    Returns:
        ``{"valid": bool, "problems": [...]}``; never raises on bad content.
    """
    problems: list[str] = []
    if not isinstance(bundle, dict):
        return {"valid": False, "problems": ["bundle is not a JSON object"]}
    if bundle.get("format") != BUNDLE_FORMAT:
        problems.append(f"unexpected format {bundle.get('format')!r}, expected {BUNDLE_FORMAT!r}")
    version = bundle.get("version")
    if not isinstance(version, int) or version > BUNDLE_VERSION:
        problems.append(f"unsupported bundle version {version!r} (supported <= {BUNDLE_VERSION})")
    manifest = bundle.get("manifest")
    sections = bundle.get("sections")
    if not isinstance(manifest, dict) or not isinstance(sections, dict):
        problems.append("manifest or sections missing")
        return {"valid": False, "problems": problems}
    if not isinstance(manifest.get("sample"), dict) or not manifest["sample"].get("sha256"):
        problems.append("manifest.sample.sha256 missing")

    declared = manifest.get("sections", {})
    for name in SECTION_NAMES:
        if name not in sections or name not in declared:
            problems.append(f"section {name!r} missing")
            continue
        if canonical_digest(sections[name]) != declared[name].get("sha256"):
            problems.append(f"section {name!r} digest mismatch (content altered or corrupted)")
    if canonical_digest({"manifest": manifest, "sections": sections}) != bundle.get(
        "bundle_sha256"
    ):
        problems.append("bundle_sha256 mismatch (bundle altered or corrupted)")
    return {"valid": not problems, "problems": problems}


def _verify_artifacts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Check each referenced artifact against the receiving workspace."""
    workspace = get_config().workspace.resolve()
    report: list[dict[str, Any]] = []
    for art in manifest.get("artifacts", []):
        entry = {"path": art.get("path"), "expected_sha256": art.get("sha256")}
        if art.get("status") != "referenced" or not art.get("sha256"):
            report.append({**entry, "status": f"not_available ({art.get('status')})"})
            continue
        candidate = (workspace / str(art["path"])).resolve()
        try:
            candidate.relative_to(workspace)
        except ValueError:
            report.append({**entry, "status": "rejected_path_escape"})
            continue
        if not candidate.is_file():
            report.append({**entry, "status": "missing"})
        elif calculate_file_sha256(candidate) != art["sha256"]:
            report.append({**entry, "status": "hash_mismatch"})
        else:
            report.append({**entry, "status": "verified"})
    return report


async def import_bundle(
    bundle: dict[str, Any],
    target_file: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Verify and import a handoff bundle into the local Reversecore stores.

    Order of operations guarantees nothing is attached before checks pass:
    integrity verification, then sample hash verification, then (unless
    ``dry_run``) case, memory session and annotation import.

    Args:
        bundle: Parsed bundle dict.
        target_file: Optional local sample whose SHA-256 must match the bundle.
        dry_run: Validate and report what would happen without writing.

    Returns:
        Import report with per-section outcomes, conflicts and artifact status.

    Raises:
        HandoffBundleError: Malformed or tampered bundle.
        SampleHashMismatchInBundle: ``target_file`` does not match the bundle.
    """
    from reversecore_mcp.tools.radare2.r2_db import import_annotations_sync

    check = verify_bundle(bundle)
    if not check["valid"]:
        raise HandoffBundleError("Integrity verification failed: " + "; ".join(check["problems"]))

    manifest = bundle["manifest"]
    sections = bundle["sections"]
    bundle_hash = bundle["bundle_sha256"]
    sample_hash = manifest["sample"]["sha256"]

    target_verified = False
    if target_file is not None:
        local = Path(validate_file_path(str(target_file), read_only=True))
        local_hash = await asyncio.to_thread(calculate_file_sha256, local)
        if local_hash != sample_hash:
            raise SampleHashMismatchInBundle(
                f"Sample hash mismatch: bundle is for {sample_hash}, "
                f"{local.name} hashes to {local_hash}. Nothing was imported."
            )
        target_verified = True

    report: dict[str, Any] = {
        "bundle_sha256": bundle_hash,
        "sample_sha256": sample_hash,
        "target_hash_verified": target_verified,
        "dry_run": dry_run,
        "integrity": "verified",
        "case_state": {"status": "absent"},
        "memory_session": {"status": "absent"},
        "annotations": {"status": "absent"},
        "artifacts": _verify_artifacts(manifest),
        "warnings": [],
        "summary": sections["handoff_summary"],
    }
    if not target_verified:
        report["warnings"].append(
            "No target_file provided: sample hash was not verified against a local binary. "
            "Imported state is keyed to the bundle's sample hash only."
        )
    missing = [a for a in report["artifacts"] if a["status"] not in ("verified",)]
    if missing:
        report["warnings"].append(
            f"{len(missing)} referenced artifact(s) not verified locally; "
            "the rest of the handoff was imported normally."
        )

    manager = get_case_state_manager()
    new_session_id: str | None = None

    # --- memory session (imported first so the case can link to the new ID) ---
    mem = sections.get("memory_session")
    if mem:
        report["memory_session"] = {
            "status": "would_import" if dry_run else "imported",
            "memories": len(mem.get("memories", [])),
        }
        if not dry_run:
            store = manager.memory_store
            await store.initialize()
            src = mem["session"]
            new_session_id = await store.create_session(
                name=f"{src.get('name', 'handoff')} (handoff)",
                binary_name=src.get("binary_name"),
                binary_hash=src.get("binary_hash") or sample_hash,
            )
            for m in mem.get("memories", []):
                await store.save_memory(
                    session_id=new_session_id,
                    memory_type=m.get("memory_type", "context"),
                    content=m.get("content", ""),
                    category=m.get("category"),
                    user_prompt=m.get("user_prompt"),
                    importance=int(m.get("importance", 5)),
                )
            await store.update_session(
                new_session_id, status=src.get("status"), summary=src.get("summary")
            )
            report["memory_session"]["session_id"] = new_session_id

    # --- case state ---
    case_dict = sections.get("case_state")
    if case_dict:
        original_id = case_dict["case_id"]
        existing = await manager.get_case(original_id)
        new_id = original_id
        if existing is not None:
            new_id = f"{original_id}_imported_{uuid.uuid4().hex[:6]}"
            report["warnings"].append(
                f"Case {original_id} already exists locally; imported as {new_id} "
                "(existing case left untouched)."
            )
        report["case_state"] = {
            "status": "would_import" if dry_run else "imported",
            "original_case_id": original_id,
            "case_id": new_id,
            "phase": case_dict.get("phase"),
        }
        if not dry_run:
            imported = CaseState.from_dict({**case_dict, "case_id": new_id})
            imported.session_id = new_session_id or imported.session_id
            imported.metadata = {
                **imported.metadata,
                "handoff": {
                    "source_bundle_sha256": bundle_hash,
                    "original_case_id": original_id,
                    "imported_at": _utc_now_iso(),
                    "exported_with": manifest.get("environment", {}),
                },
            }
            await manager.save_case(imported)

    # --- annotations ---
    ann = sections.get("annotations")
    if ann:
        if dry_run:
            report["annotations"] = {
                "status": "would_import",
                "bookmarks": len(ann.get("bookmarks", [])),
                "structures": len(ann.get("structures", [])),
                "types": len(ann.get("types", [])),
            }
        else:
            outcome = await asyncio.to_thread(
                import_annotations_sync,
                sample_hash,
                ann.get("bookmarks", []),
                ann.get("structures", []),
                ann.get("types", []),
            )
            report["annotations"] = {"status": "imported", **outcome}
            if outcome["conflicts"]:
                report["warnings"].append(
                    f"{len(outcome['conflicts'])} annotation conflict(s): existing local "
                    "entries were kept."
                )

    return report
