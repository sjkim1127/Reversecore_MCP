"""Machine-readable analysis case state management across agent sessions.

Persists compact, structured investigation state (phases, active hypotheses,
next inspection targets, blocked dependencies, and referenced artifacts) bound
to sample SHA-256 integrity checks, enabling agents to survive context compaction
and restart without context loss.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.analysis_cache import calculate_file_sha256
from reversecore_mcp.core.exceptions import (
    CaseNotFoundError,
    CaseStateError,
    InvalidPhaseTransitionError,
    SampleHashMismatchError,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.memory import MemoryStore, get_memory_store
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Enums and Constants
# ---------------------------------------------------------------------------


class AnalysisPhase(str, Enum):
    """Investigation phases in standard reverse engineering workflows."""

    INTAKE = "intake"
    TRIAGE = "triage"
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    DEEP_ANALYSIS = "deep_analysis"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    COMPLETED = "completed"


PHASE_ORDER: list[str] = [
    AnalysisPhase.INTAKE.value,
    AnalysisPhase.TRIAGE.value,
    AnalysisPhase.HYPOTHESIS_GENERATION.value,
    AnalysisPhase.DEEP_ANALYSIS.value,
    AnalysisPhase.VERIFICATION.value,
    AnalysisPhase.REPORTING.value,
    AnalysisPhase.COMPLETED.value,
]


class HypothesisStatus(str, Enum):
    """Status lifecycle for investigation hypotheses."""

    ACTIVE = "active"
    VERIFIED = "verified"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class TargetStatus(str, Enum):
    """Status of specific analysis inspection targets."""

    PENDING = "pending"
    ACTIVE = "active"
    BLOCKED = "blocked"
    DEFERRED = "deferred"
    COMPLETED = "completed"
    REJECTED = "rejected"


class TargetPriority(str, Enum):
    """Priority levels for analysis targets."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


PRIORITY_RANK: dict[str, int] = {
    TargetPriority.CRITICAL.value: 0,
    TargetPriority.HIGH.value: 1,
    TargetPriority.MEDIUM.value: 2,
    TargetPriority.LOW.value: 3,
}


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class SampleMetadata:
    """Bound sample identity and file metadata."""

    path: str
    sha256: str
    name: str | None = None
    format: str | None = None
    size_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SampleMetadata:
        return cls(
            path=data["path"],
            sha256=data["sha256"],
            name=data.get("name"),
            format=data.get("format"),
            size_bytes=data.get("size_bytes"),
        )


@dataclass
class AnalysisHypothesis:
    """Hypothesis about sample behavior, capabilities, or attribution."""

    id: str
    title: str
    category: str = "general"
    status: str = HypothesisStatus.ACTIVE.value
    evidence_level: str = "possible"
    evidence_refs: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    rationale: str = ""
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisHypothesis:
        return cls(
            id=data["id"],
            title=data["title"],
            category=data.get("category", "general"),
            status=data.get("status", HypothesisStatus.ACTIVE.value),
            evidence_level=data.get("evidence_level", "possible"),
            evidence_refs=list(data.get("evidence_refs", [])),
            contradictions=list(data.get("contradictions", [])),
            rationale=data.get("rationale", ""),
            created_at=data.get("created_at", _utc_now_iso()),
            updated_at=data.get("updated_at", _utc_now_iso()),
        )


@dataclass
class AnalysisTarget:
    """A prioritized target function, address, artifact, or subsystem to inspect next."""

    id: str
    target: str
    kind: str = "function"  # function, string, section, network, memory, hypothesis
    priority: str = TargetPriority.MEDIUM.value
    reason: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    expected_next_step: str = ""
    blockers: list[str] = field(default_factory=list)
    status: str = TargetStatus.PENDING.value
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisTarget:
        return cls(
            id=data["id"],
            target=data["target"],
            kind=data.get("kind", "function"),
            priority=data.get("priority", TargetPriority.MEDIUM.value),
            reason=data.get("reason", ""),
            evidence_refs=list(data.get("evidence_refs", [])),
            expected_next_step=data.get("expected_next_step", ""),
            blockers=list(data.get("blockers", [])),
            status=data.get("status", TargetStatus.PENDING.value),
            created_at=data.get("created_at", _utc_now_iso()),
            updated_at=data.get("updated_at", _utc_now_iso()),
        )


@dataclass
class CompletedStep:
    """A recorded analysis operation completed during the case."""

    step_id: str
    tool_name: str
    phase: str
    summary: str
    completed_at: str = field(default_factory=_utc_now_iso)
    output_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompletedStep:
        return cls(
            step_id=data["step_id"],
            tool_name=data["tool_name"],
            phase=data["phase"],
            summary=data["summary"],
            completed_at=data.get("completed_at", _utc_now_iso()),
            output_summary=dict(data.get("output_summary", {})),
        )


@dataclass
class BlockedDependency:
    """An analysis item currently blocked waiting on prerequisites or external inputs."""

    target: str
    reason: str
    blocked_by: list[str] = field(default_factory=list)
    suggested_resolution: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BlockedDependency:
        return cls(
            target=data["target"],
            reason=data["reason"],
            blocked_by=list(data.get("blocked_by", [])),
            suggested_resolution=data.get("suggested_resolution", ""),
        )


@dataclass
class ArtifactRef:
    """A lightweight reference to an analysis artifact without duplicating raw bulk data."""

    name: str
    artifact_type: str  # report, dump, pcap, cfg, yara_rule, disasm, annotation_db
    path: str | None = None
    uri: str | None = None
    sha256: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArtifactRef:
        return cls(
            name=data["name"],
            artifact_type=data["artifact_type"],
            path=data.get("path"),
            uri=data.get("uri"),
            sha256=data.get("sha256"),
            metadata=dict(data.get("metadata", {})),
        )


# ---------------------------------------------------------------------------
# Core CaseState Aggregate
# ---------------------------------------------------------------------------


@dataclass
class CaseState:
    """Persistent machine-readable case state container."""

    case_id: str
    sample: SampleMetadata
    phase: str = AnalysisPhase.INTAKE.value
    completed_phases: list[str] = field(default_factory=list)
    completed_steps: list[CompletedStep] = field(default_factory=list)
    active_hypotheses: list[AnalysisHypothesis] = field(default_factory=list)
    next_targets: list[AnalysisTarget] = field(default_factory=list)
    blocked: list[BlockedDependency] = field(default_factory=list)
    artifacts: list[ArtifactRef] = field(default_factory=list)
    session_id: str | None = None
    created_at: str = field(default_factory=_utc_now_iso)
    last_updated: str = field(default_factory=_utc_now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)

    # -----------------------------------------------------------------------
    # Phase Progression & Lifecycle
    # -----------------------------------------------------------------------

    def transition_phase(self, new_phase: str | AnalysisPhase, force: bool = False) -> None:
        """Transition case to a new analysis phase.

        Args:
            new_phase: Target phase name or enum.
            force: If True, allow backward transitions or phase resets.

        Raises:
            InvalidPhaseTransitionError: If moving backward without force=True.
        """
        target = new_phase.value if isinstance(new_phase, AnalysisPhase) else str(new_phase).lower()
        if target not in PHASE_ORDER:
            raise InvalidPhaseTransitionError(
                self.phase,
                target,
                f"Unknown phase '{target}'. Valid phases are: {', '.join(PHASE_ORDER)}",
            )

        if target == self.phase:
            return

        current_idx = PHASE_ORDER.index(self.phase) if self.phase in PHASE_ORDER else 0
        target_idx = PHASE_ORDER.index(target)

        if target_idx < current_idx and not force:
            raise InvalidPhaseTransitionError(
                self.phase,
                target,
                f"Backward phase transition requires force_phase=True. Current phase is '{self.phase}'.",
            )

        # Mark current and skipped intermediate phases as completed
        if current_idx < target_idx:
            for p in PHASE_ORDER[current_idx:target_idx]:
                if p not in self.completed_phases:
                    self.completed_phases.append(p)

        self.phase = target
        self.last_updated = _utc_now_iso()

    def is_phase_completed(self, phase: str | AnalysisPhase) -> bool:
        """Check if a specific phase has already been completed."""
        p_str = phase.value if isinstance(phase, AnalysisPhase) else str(phase).lower()
        return p_str in self.completed_phases

    def can_skip_phase(self, phase: str | AnalysisPhase, force: bool = False) -> bool:
        """Determine whether a phase can be skipped without re-running."""
        if force:
            return False
        return self.is_phase_completed(phase)

    # -----------------------------------------------------------------------
    # Step Tracking
    # -----------------------------------------------------------------------

    def record_step(
        self,
        step_id: str,
        tool_name: str,
        summary: str,
        phase: str | None = None,
        output_summary: dict[str, Any] | None = None,
    ) -> CompletedStep:
        """Record a completed tool invocation or analysis milestone."""
        target_phase = phase or self.phase
        step = CompletedStep(
            step_id=step_id,
            tool_name=tool_name,
            phase=target_phase,
            summary=summary,
            completed_at=_utc_now_iso(),
            output_summary=output_summary or {},
        )
        self.completed_steps.append(step)
        self.last_updated = _utc_now_iso()
        return step

    # -----------------------------------------------------------------------
    # Hypotheses Operations
    # -----------------------------------------------------------------------

    def add_hypothesis(
        self,
        title: str,
        category: str = "general",
        evidence_level: str = "possible",
        evidence_refs: list[str] | None = None,
        rationale: str = "",
        hyp_id: str | None = None,
    ) -> AnalysisHypothesis:
        """Add a new hypothesis to the case."""
        h_id = hyp_id or f"hyp_{uuid.uuid4().hex[:8]}"
        hyp = AnalysisHypothesis(
            id=h_id,
            title=title,
            category=category,
            status=HypothesisStatus.ACTIVE.value,
            evidence_level=evidence_level,
            evidence_refs=evidence_refs or [],
            contradictions=[],
            rationale=rationale,
            created_at=_utc_now_iso(),
            updated_at=_utc_now_iso(),
        )
        self.active_hypotheses.append(hyp)
        self.last_updated = _utc_now_iso()
        return hyp

    def update_hypothesis(
        self,
        hyp_id: str,
        status: str | None = None,
        evidence_refs: list[str] | None = None,
        contradictions: list[str] | None = None,
        rationale: str | None = None,
        evidence_level: str | None = None,
    ) -> AnalysisHypothesis | None:
        """Update an existing hypothesis incrementally."""
        for hyp in self.active_hypotheses:
            if hyp.id == hyp_id:
                if status is not None:
                    hyp.status = status.lower()
                if evidence_refs:
                    for ref in evidence_refs:
                        if ref not in hyp.evidence_refs:
                            hyp.evidence_refs.append(ref)
                if contradictions:
                    for c in contradictions:
                        if c not in hyp.contradictions:
                            hyp.contradictions.append(c)
                if rationale is not None:
                    hyp.rationale = rationale
                if evidence_level is not None:
                    hyp.evidence_level = evidence_level
                hyp.updated_at = _utc_now_iso()
                self.last_updated = _utc_now_iso()
                return hyp
        return None

    def resolve_hypothesis(
        self,
        hyp_id: str,
        verified: bool,
        rationale: str = "",
        evidence_refs: list[str] | None = None,
    ) -> AnalysisHypothesis | None:
        """Mark a hypothesis as verified or refuted."""
        new_status = HypothesisStatus.VERIFIED.value if verified else HypothesisStatus.REFUTED.value
        new_level = "observed" if verified else "possible"
        return self.update_hypothesis(
            hyp_id=hyp_id,
            status=new_status,
            evidence_refs=evidence_refs,
            rationale=rationale,
            evidence_level=new_level,
        )

    # -----------------------------------------------------------------------
    # Next Target Operations (Priority Queue)
    # -----------------------------------------------------------------------

    def add_target(
        self,
        target: str,
        kind: str = "function",
        priority: str = TargetPriority.MEDIUM.value,
        reason: str = "",
        evidence_refs: list[str] | None = None,
        expected_next_step: str = "",
        blockers: list[str] | None = None,
        target_id: str | None = None,
    ) -> AnalysisTarget:
        """Add or update an analysis inspection target."""
        # Check if target already exists by name
        for existing in self.next_targets:
            if existing.target == target and existing.status in (
                TargetStatus.PENDING.value,
                TargetStatus.ACTIVE.value,
                TargetStatus.BLOCKED.value,
            ):
                existing.priority = priority.lower()
                if reason:
                    existing.reason = reason
                if evidence_refs:
                    for ref in evidence_refs:
                        if ref not in existing.evidence_refs:
                            existing.evidence_refs.append(ref)
                if expected_next_step:
                    existing.expected_next_step = expected_next_step
                if blockers:
                    for b in blockers:
                        if b not in existing.blockers:
                            existing.blockers.append(b)
                existing.updated_at = _utc_now_iso()
                self.last_updated = _utc_now_iso()
                return existing

        t_id = target_id or f"tgt_{uuid.uuid4().hex[:8]}"
        initial_status = (
            TargetStatus.BLOCKED.value
            if (blockers and len(blockers) > 0)
            else TargetStatus.PENDING.value
        )
        tgt = AnalysisTarget(
            id=t_id,
            target=target,
            kind=kind,
            priority=priority.lower(),
            reason=reason,
            evidence_refs=evidence_refs or [],
            expected_next_step=expected_next_step,
            blockers=blockers or [],
            status=initial_status,
            created_at=_utc_now_iso(),
            updated_at=_utc_now_iso(),
        )
        self.next_targets.append(tgt)
        self.last_updated = _utc_now_iso()
        return tgt

    def update_target_status(
        self,
        target_id_or_name: str,
        status: str,
        reason: str | None = None,
    ) -> AnalysisTarget | None:
        """Update target status (e.g. pending -> active -> completed)."""
        st = status.lower()
        for tgt in self.next_targets:
            if tgt.id == target_id_or_name or tgt.target == target_id_or_name:
                tgt.status = st
                if reason:
                    tgt.reason = f"{tgt.reason} (Update: {reason})" if tgt.reason else reason
                tgt.updated_at = _utc_now_iso()
                self.last_updated = _utc_now_iso()
                return tgt
        return None

    def get_sorted_targets(self, include_completed: bool = False) -> list[AnalysisTarget]:
        """Return next targets ordered deterministically by priority and creation time."""
        from reversecore_mcp.core.priority_queue import AnalysisPriorityQueue

        ranked = AnalysisPriorityQueue.rank_targets(
            self.next_targets,
            case=self,
            include_completed=include_completed,
            include_blocked=True,
        )
        return [r.target for r in ranked]

    # -----------------------------------------------------------------------
    # Blocker Operations
    # -----------------------------------------------------------------------

    def add_blocker(
        self,
        target: str,
        reason: str,
        blocked_by: list[str] | None = None,
        suggested_resolution: str = "",
    ) -> BlockedDependency:
        """Record an explicit blocking condition."""
        for b in self.blocked:
            if b.target == target:
                b.reason = reason
                b.blocked_by = blocked_by or b.blocked_by
                b.suggested_resolution = suggested_resolution or b.suggested_resolution
                self.last_updated = _utc_now_iso()
                return b

        blocker = BlockedDependency(
            target=target,
            reason=reason,
            blocked_by=blocked_by or [],
            suggested_resolution=suggested_resolution,
        )
        self.blocked.append(blocker)

        # Also reflect in target status if target exists
        for tgt in self.next_targets:
            if tgt.target == target and tgt.status == TargetStatus.PENDING.value:
                tgt.status = TargetStatus.BLOCKED.value
                tgt.blockers = list(set(tgt.blockers + (blocked_by or [reason])))

        self.last_updated = _utc_now_iso()
        return blocker

    def resolve_blocker(self, target: str) -> bool:
        """Clear a blocking condition for a target."""
        initial_len = len(self.blocked)
        self.blocked = [b for b in self.blocked if b.target != target]
        resolved = len(self.blocked) < initial_len

        # Unblock target if no other blockers exist
        for tgt in self.next_targets:
            if tgt.target == target and tgt.status == TargetStatus.BLOCKED.value:
                tgt.status = TargetStatus.PENDING.value
                tgt.blockers = []

        if resolved:
            self.last_updated = _utc_now_iso()
        return resolved

    # -----------------------------------------------------------------------
    # Artifact Operations
    # -----------------------------------------------------------------------

    def add_artifact(
        self,
        name: str,
        artifact_type: str,
        path: str | None = None,
        uri: str | None = None,
        sha256: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        """Attach a lightweight artifact reference to the case."""
        for art in self.artifacts:
            if art.name == name:
                art.artifact_type = artifact_type
                art.path = path or art.path
                art.uri = uri or art.uri
                art.sha256 = sha256 or art.sha256
                if metadata:
                    art.metadata.update(metadata)
                self.last_updated = _utc_now_iso()
                return art

        art_ref = ArtifactRef(
            name=name,
            artifact_type=artifact_type,
            path=path,
            uri=uri,
            sha256=sha256,
            metadata=metadata or {},
        )
        self.artifacts.append(art_ref)
        self.last_updated = _utc_now_iso()
        return art_ref

    # -----------------------------------------------------------------------
    # Serialization and Summaries
    # -----------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Convert entire case state to serializable dict."""
        return {
            "case_id": self.case_id,
            "sample": self.sample.to_dict(),
            "phase": self.phase,
            "completed_phases": self.completed_phases,
            "completed_steps": [s.to_dict() for s in self.completed_steps],
            "active_hypotheses": [h.to_dict() for h in self.active_hypotheses],
            "next_targets": [t.to_dict() for t in self.next_targets],
            "blocked": [b.to_dict() for b in self.blocked],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "session_id": self.session_id,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CaseState:
        """Reconstruct CaseState from serialized dict."""
        return cls(
            case_id=data["case_id"],
            sample=SampleMetadata.from_dict(data["sample"]),
            phase=data.get("phase", AnalysisPhase.INTAKE.value),
            completed_phases=list(data.get("completed_phases", [])),
            completed_steps=[CompletedStep.from_dict(s) for s in data.get("completed_steps", [])],
            active_hypotheses=[
                AnalysisHypothesis.from_dict(h) for h in data.get("active_hypotheses", [])
            ],
            next_targets=[AnalysisTarget.from_dict(t) for t in data.get("next_targets", [])],
            blocked=[BlockedDependency.from_dict(b) for b in data.get("blocked", [])],
            artifacts=[ArtifactRef.from_dict(a) for a in data.get("artifacts", [])],
            session_id=data.get("session_id"),
            created_at=data.get("created_at", _utc_now_iso()),
            last_updated=data.get("last_updated", _utc_now_iso()),
            metadata=dict(data.get("metadata", {})),
        )

    def to_summary_dict(self) -> dict[str, Any]:
        """Compact machine-readable summary suitable for LLM context injection."""
        pending_targets = self.get_sorted_targets()
        return {
            "case_id": self.case_id,
            "phase": self.phase,
            "sample": {
                "path": self.sample.path,
                "sha256": self.sample.sha256,
                "name": self.sample.name,
                "format": self.sample.format,
            },
            "completed_phases": self.completed_phases,
            "counts": {
                "completed_steps": len(self.completed_steps),
                "active_hypotheses": sum(
                    1 for h in self.active_hypotheses if h.status == HypothesisStatus.ACTIVE.value
                ),
                "verified_hypotheses": sum(
                    1 for h in self.active_hypotheses if h.status == HypothesisStatus.VERIFIED.value
                ),
                "pending_targets": len(pending_targets),
                "blocked": len(self.blocked),
                "artifacts": len(self.artifacts),
            },
            "active_hypotheses": [
                h.to_dict()
                for h in self.active_hypotheses
                if h.status == HypothesisStatus.ACTIVE.value
            ],
            "next_targets": [t.to_dict() for t in pending_targets[:5]],
            "blocked": [b.to_dict() for b in self.blocked],
            "last_updated": self.last_updated,
        }


# ---------------------------------------------------------------------------
# CaseStateManager Engine
# ---------------------------------------------------------------------------


class CaseStateManager:
    """Coordinates case state persistence, integrity validation, and lifecycle."""

    def __init__(self, memory_store: MemoryStore | None = None) -> None:
        self.memory_store = memory_store or get_memory_store()

    async def _ensure_store(self) -> None:
        """Ensure memory store database is initialized."""
        await self.memory_store.initialize()

    async def create_case(
        self,
        sample_path: str,
        case_name: str | None = None,
        initial_phase: str = AnalysisPhase.INTAKE.value,
        session_id: str | None = None,
        explicit_sha256: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CaseState:
        """Create and persist a new analysis case bound to sample SHA-256.

        Args:
            sample_path: Path to sample file (validated within workspace).
            case_name: Optional human-readable case name.
            initial_phase: Initial analysis phase (default: intake).
            session_id: Optional linked memory/report session ID.
            explicit_sha256: Optional precomputed hash.
            metadata: Optional case metadata.

        Returns:
            Newly created CaseState.
        """
        await self._ensure_store()

        # Validate file path and calculate hash
        validated_path = sample_path
        sha256 = explicit_sha256
        file_size = None
        file_name = Path(sample_path).name

        path_obj: Path | None = None
        try:
            safe_path = validate_file_path(sample_path)
            validated_path = str(safe_path)
            path_obj = Path(safe_path)
        except Exception:
            p = Path(sample_path)
            if p.exists() and p.is_file():
                path_obj = p
                validated_path = str(p)

        if path_obj and path_obj.exists() and path_obj.is_file():
            if not sha256:
                sha256 = calculate_file_sha256(path_obj)
            file_size = path_obj.stat().st_size
            file_name = path_obj.name

        if not sha256:
            # Fall back to synthetic hash based on path if file not on disk yet
            sha256 = hashlib.sha256(sample_path.encode()).hexdigest()

        # Generate unique case ID
        name_prefix = case_name.strip().replace(" ", "_") if case_name else file_name
        case_id = f"case_{name_prefix}_{uuid.uuid4().hex[:6]}"

        sample_meta = SampleMetadata(
            path=validated_path,
            sha256=sha256,
            name=file_name,
            size_bytes=file_size,
        )

        init_phase = initial_phase.lower()
        if init_phase not in PHASE_ORDER:
            init_phase = AnalysisPhase.INTAKE.value

        case = CaseState(
            case_id=case_id,
            sample=sample_meta,
            phase=init_phase,
            session_id=session_id,
            metadata=metadata or {},
        )

        await self.save_case(case)
        logger.info(
            f"Created case state '{case_id}' for sample '{validated_path}' ({sha256[:8]}...)"
        )
        return case

    async def get_case(self, case_id: str) -> CaseState | None:
        """Retrieve case state by ID."""
        await self._ensure_store()
        row = await self.memory_store.get_case_state(case_id)
        if not row:
            return None
        state_dict = json.loads(row["state_json"])
        return CaseState.from_dict(state_dict)

    async def get_case_by_sample_hash(self, sample_hash: str) -> CaseState | None:
        """Retrieve latest case state bound to a sample SHA-256."""
        await self._ensure_store()
        row = await self.memory_store.get_case_state_by_hash(sample_hash)
        if not row:
            return None
        state_dict = json.loads(row["state_json"])
        return CaseState.from_dict(state_dict)

    async def save_case(self, case: CaseState) -> None:
        """Persist case state to storage."""
        await self._ensure_store()
        case.last_updated = _utc_now_iso()
        state_json = json.dumps(case.to_dict())
        await self.memory_store.save_case_state(
            case_id=case.case_id,
            sample_hash=case.sample.sha256,
            phase=case.phase,
            state_json=state_json,
            sample_path=case.sample.path,
            session_id=case.session_id,
        )

    async def resume_case(
        self,
        case_id: str,
        sample_path: str | None = None,
        verify_hash: bool = True,
    ) -> dict[str, Any]:
        """Resume an existing case with integrity verification and next action guidance.

        Args:
            case_id: Case ID to resume.
            sample_path: Optional path to binary file to verify against case's bound hash.
            verify_hash: Whether to strictly enforce sample SHA-256 matching.

        Returns:
            Dict containing resumption summary and actionable next tool guidance.

        Raises:
            CaseNotFoundError: If case does not exist.
            SampleHashMismatchError: If sample file SHA-256 differs from case.
        """
        case = await self.get_case(case_id)
        if not case:
            raise CaseNotFoundError(case_id)

        target_file = sample_path or case.sample.path

        # Verify sample hash binding if requested and file is available
        if verify_hash and target_file:
            path_obj: Path | None = None
            try:
                safe_path = validate_file_path(target_file)
                path_obj = Path(safe_path)
            except Exception:
                p = Path(target_file)
                if p.exists() and p.is_file():
                    path_obj = p

            if path_obj and path_obj.exists() and path_obj.is_file():
                actual_hash = calculate_file_sha256(path_obj)
                if actual_hash != case.sample.sha256:
                    raise SampleHashMismatchError(
                        case_id=case.case_id,
                        expected_hash=case.sample.sha256,
                        actual_hash=actual_hash,
                        sample_path=str(path_obj),
                    )

        # Produce actionable resumption summary
        sorted_targets = case.get_sorted_targets()
        top_target = sorted_targets[0] if sorted_targets else None
        active_hyp = [
            h for h in case.active_hypotheses if h.status == HypothesisStatus.ACTIVE.value
        ]

        # Generate contextual guidance for the agent
        guidance = (
            f"Resumed analysis case '{case.case_id}' in phase '{case.phase}'. "
            f"{len(case.completed_steps)} prior operations recorded across completed phases: {case.completed_phases}. "
        )
        if top_target:
            guidance += (
                f"Next prioritized target is '{top_target.target}' ({top_target.priority} priority, "
                f"reason: {top_target.reason or 'unspecified'}). Recommended step: '{top_target.expected_next_step or 'inspect'}'. "
            )
        if active_hyp:
            guidance += f"{len(active_hyp)} active hypotheses require verification."

        return {
            "resumed": True,
            "case_id": case.case_id,
            "phase": case.phase,
            "completed_phases": case.completed_phases,
            "sample": case.sample.to_dict(),
            "guidance": guidance,
            "top_target": top_target.to_dict() if top_target else None,
            "active_hypotheses": [h.to_dict() for h in active_hyp],
            "next_targets": [t.to_dict() for t in sorted_targets[:10]],
            "blocked": [b.to_dict() for b in case.blocked],
            "artifacts_count": len(case.artifacts),
            "last_updated": case.last_updated,
        }

    async def plan_next_analysis(
        self,
        case_id: str,
        limit: int = 5,
        include_blocked: bool = False,
        min_priority: str | None = None,
    ) -> dict[str, Any]:
        """Generate a ranked next-analysis plan for an analysis case.

        Args:
            case_id: Case identifier.
            limit: Maximum number of targets to return in plan.
            include_blocked: Whether to include targets with unresolved blockers.
            min_priority: Optional filter by minimum priority tier.

        Returns:
            Dictionary containing ranked plan, summary statistics, and next steps.
        """
        case = await self.get_case(case_id)
        if not case:
            raise CaseNotFoundError(case_id)

        from reversecore_mcp.core.priority_queue import AnalysisPriorityQueue

        ranked_targets = AnalysisPriorityQueue.rank_targets(
            case.next_targets,
            case=case,
            include_completed=False,
            include_blocked=include_blocked,
            min_priority=min_priority,
            limit=limit,
        )

        all_ranked = AnalysisPriorityQueue.rank_targets(
            case.next_targets,
            case=case,
            include_completed=True,
            include_blocked=True,
        )

        status_counts: dict[str, int] = {}
        for t in case.next_targets:
            status_counts[t.status] = status_counts.get(t.status, 0) + 1

        ready_count = sum(1 for r in all_ranked if r.is_ready)
        blocked_count = sum(
            1
            for r in all_ranked
            if not r.is_ready
            and r.target.status != TargetStatus.COMPLETED.value
            and r.target.status != TargetStatus.REJECTED.value
        )

        top_guidance = (
            f"Generated plan with {len(ranked_targets)} actionable targets for phase '{case.phase}'. "
            f"Top priority target: '{ranked_targets[0].target.target}' ({ranked_targets[0].target.priority}) - {ranked_targets[0].target.reason}"
            if ranked_targets
            else "No pending targets in priority queue. Triage or analyst input needed."
        )

        return {
            "case_id": case.case_id,
            "phase": case.phase,
            "sample_path": case.sample.path,
            "plan_targets": [r.to_dict() for r in ranked_targets],
            "total_targets": len(case.next_targets),
            "ready_targets_count": ready_count,
            "blocked_targets_count": blocked_count,
            "status_counts": status_counts,
            "active_hypotheses_count": len(
                [h for h in case.active_hypotheses if h.status == HypothesisStatus.ACTIVE.value]
            ),
            "guidance": top_guidance,
        }

    async def populate_queue_from_triage(
        self,
        case_id: str,
        triage_data: dict[str, Any],
        max_items: int = 15,
    ) -> dict[str, Any]:
        """Extract prioritized leads from triage results and populate the case queue.

        Args:
            case_id: Case identifier.
            triage_data: Triage output dictionary.
            max_items: Maximum items to extract.

        Returns:
            Dictionary containing added targets and queue metrics.
        """
        case = await self.get_case(case_id)
        if not case:
            raise CaseNotFoundError(case_id)

        from reversecore_mcp.core.priority_queue import AnalysisPriorityQueue

        new_targets = AnalysisPriorityQueue.extract_targets_from_triage(
            triage_data=triage_data,
            case=case,
            max_items=max_items,
        )

        for nt in new_targets:
            case.next_targets.append(nt)

        if new_targets:
            case.last_updated = _utc_now_iso()
            await self.save_case(case)

        return {
            "case_id": case.case_id,
            "added_count": len(new_targets),
            "added_targets": [t.to_dict() for t in new_targets],
            "total_queue_size": len(case.next_targets),
        }

    async def update_priority_target(
        self,
        case_id: str,
        target_id_or_name: str,
        status: str,
        priority: str | None = None,
        findings: list[str] | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Update a target's lifecycle status, resolve blockers, and record findings.

        Args:
            case_id: Case identifier.
            target_id_or_name: Target ID or target identifier.
            status: New status (pending, active, completed, deferred, blocked, rejected).
            priority: Optional updated priority level.
            findings: Optional list of findings uncovered.
            reason: Optional update rationale.

        Returns:
            Dictionary with updated target, unblocked targets, and case metrics.
        """
        case = await self.get_case(case_id)
        if not case:
            raise CaseNotFoundError(case_id)

        from reversecore_mcp.core.priority_queue import AnalysisPriorityQueue

        norm_status = status.lower()
        unblocked_targets: list[str] = []
        updated_target: AnalysisTarget | None = None

        if norm_status == TargetStatus.COMPLETED.value:
            updated_target, unblocked_targets = AnalysisPriorityQueue.resolve_target_completion(
                case=case,
                target_id_or_name=target_id_or_name,
                findings=findings,
                reason=reason,
            )
        else:
            for t in case.next_targets:
                if t.id == target_id_or_name or t.target == target_id_or_name:
                    t.status = norm_status
                    if priority:
                        t.priority = priority.lower()
                    if reason:
                        t.reason = f"{t.reason} | {reason}" if t.reason else reason
                    t.updated_at = _utc_now_iso()
                    case.last_updated = _utc_now_iso()
                    updated_target = t
                    break

        if not updated_target:
            raise CaseStateError(f"Target '{target_id_or_name}' not found in case '{case_id}'")

        await self.save_case(case)

        return {
            "case_id": case.case_id,
            "target": updated_target.to_dict(),
            "unblocked_targets": unblocked_targets,
            "total_targets": len(case.next_targets),
            "last_updated": case.last_updated,
        }

    async def list_cases(
        self,
        phase: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List stored analysis cases."""
        await self._ensure_store()
        return await self.memory_store.list_case_states(phase=phase, limit=limit, offset=offset)

    async def delete_case(self, case_id: str) -> bool:
        """Delete an analysis case by ID."""
        await self._ensure_store()
        return await self.memory_store.delete_case_state(case_id)


# Singleton instance
_case_state_manager: CaseStateManager | None = None


def get_case_state_manager() -> CaseStateManager:
    """Get the global CaseStateManager instance."""
    global _case_state_manager
    if _case_state_manager is None:
        _case_state_manager = CaseStateManager()
    return _case_state_manager
