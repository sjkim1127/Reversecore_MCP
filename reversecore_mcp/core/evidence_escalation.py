"""Evidence-escalation workflow engine for verifying suspicious static findings.

Composes static analysis, structural cross-references, data-flow taint tracing,
symbolic constraint solving, and dynamic/ESIL emulation into a disciplined,
evidence-governed hypothesis escalation pipeline.

Invariants (Issue #316):
1. "Reachable" is not automatically reported as "tainted" or "exploitable".
2. Unsupported verification steps leave the finding inconclusive rather than
   silently upgrading confidence.
3. Contradictory evidence is preserved in the final result and downgrades/refutes
   the hypothesis.
4. False-positive findings are downgraded or refuted after verification.
5. Every confidence and evidence level transition is traceable to concrete tool output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from reversecore_mcp.core.case_state import HypothesisStatus
from reversecore_mcp.core.evidence import (
    EvidenceLevel,
    EvidenceOrigin,
    Finding,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class VerificationStageType(str, Enum):
    """Stages of hypothesis verification in increasing order of verification strength."""

    STATIC_OBSERVATION = "static_observation"
    STRUCTURAL_REACHABILITY = "structural_reachability"
    DATAFLOW_TAINT = "dataflow_taint"
    SYMBOLIC_CONSTRAINT = "symbolic_constraint"
    EMULATION_RUNTIME = "emulation_runtime"

    @property
    def display_name(self) -> str:
        return {
            "static_observation": "1. Static Observation",
            "structural_reachability": "2. Structural Control-Flow Reachability",
            "dataflow_taint": "3. Data-Flow Taint Verification",
            "symbolic_constraint": "4. Symbolic Path & Constraint Solving",
            "emulation_runtime": "5. Emulated Runtime Execution",
        }[self.value]

    @property
    def default_origin(self) -> EvidenceOrigin:
        return {
            "static_observation": EvidenceOrigin.ARTIFACT,
            "structural_reachability": EvidenceOrigin.STRUCTURAL,
            "dataflow_taint": EvidenceOrigin.CAPABILITY,
            "symbolic_constraint": EvidenceOrigin.CAPABILITY,
            "emulation_runtime": EvidenceOrigin.RUNTIME,
        }[self.value]


class StageOutcome(str, Enum):
    """Outcome of a single verification step."""

    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"


@dataclass
class VerificationStageRecord:
    """Record of an executed verification stage with concrete tool outputs."""

    stage: VerificationStageType
    tool_name: str
    outcome: StageOutcome
    summary: str
    tool_evidence: dict[str, Any] = field(default_factory=dict)
    contradictions: list[str] = field(default_factory=list)
    concrete_inputs: dict[str, Any] | None = None
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "stage_name": self.stage.display_name,
            "tool_name": self.tool_name,
            "outcome": self.outcome.value,
            "summary": self.summary,
            "tool_evidence": self.tool_evidence,
            "contradictions": list(self.contradictions),
            "concrete_inputs": self.concrete_inputs,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationStageRecord:
        stage_val = data.get("stage", VerificationStageType.STATIC_OBSERVATION.value)
        outcome_val = data.get("outcome", StageOutcome.INCONCLUSIVE.value)
        return cls(
            stage=VerificationStageType(stage_val),
            tool_name=data.get("tool_name", "unknown_tool"),
            outcome=StageOutcome(outcome_val),
            summary=data.get("summary", ""),
            tool_evidence=dict(data.get("tool_evidence", {})),
            contradictions=list(data.get("contradictions", [])),
            concrete_inputs=data.get("concrete_inputs"),
            timestamp=data.get("timestamp", _utc_now_iso()),
        )


@dataclass
class HypothesisEscalationRecord:
    """End-to-end evidence escalation record for verifying suspicious static claims.

    Maintains traceability from the initial static suspicion through structural,
    taint, symbolic, and emulation verification stages.
    """

    hypothesis_id: str
    title: str
    category: str
    initial_claim: str
    target_function: str | None = None
    target_address: str | None = None
    stages: list[VerificationStageRecord] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    evidence_level: EvidenceLevel = EvidenceLevel.POSSIBLE
    status: HypothesisStatus = HypothesisStatus.ACTIVE
    is_reachable: bool | None = None
    is_tainted: bool | None = None
    is_exploitable: bool | None = None
    concrete_trigger: dict[str, Any] | None = None
    confidence_score: float = 0.35
    transition_history: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def add_stage(
        self,
        stage: VerificationStageType | str,
        tool_name: str,
        outcome: StageOutcome | str,
        summary: str,
        tool_evidence: dict[str, Any] | None = None,
        contradictions: list[str] | None = None,
        concrete_inputs: dict[str, Any] | None = None,
    ) -> VerificationStageRecord:
        """Record a verification stage outcome and re-evaluate escalation."""
        if isinstance(stage, str):
            stage = VerificationStageType(stage)
        if isinstance(outcome, str):
            outcome = StageOutcome(outcome)

        rec = VerificationStageRecord(
            stage=stage,
            tool_name=tool_name,
            outcome=outcome,
            summary=summary,
            tool_evidence=tool_evidence or {},
            contradictions=list(contradictions or []),
            concrete_inputs=concrete_inputs,
        )
        self.stages.append(rec)
        if contradictions:
            for c in contradictions:
                if c not in self.contradictions:
                    self.contradictions.append(c)

        if concrete_inputs:
            self.concrete_trigger = concrete_inputs

        self.recalculate_escalation(rec)
        self.updated_at = _utc_now_iso()
        return rec

    def recalculate_escalation(self, latest_record: VerificationStageRecord | None = None) -> None:
        """Apply strict evidence escalation rules across all recorded stages.

        Enforces:
        - Reachable does NOT imply tainted or exploitable.
        - Unsupported/Inconclusive steps freeze evidence level without promotion.
        - Contradictions downgrade or refute hypothesis.
        - Runtime confirmation required for OBSERVED level.
        """
        # Track stage outcomes
        supported_stages: set[VerificationStageType] = set()
        contradicted_stages: set[VerificationStageType] = set()
        unsupported_stages: set[VerificationStageType] = set()

        for st in self.stages:
            if st.outcome == StageOutcome.SUPPORTED:
                supported_stages.add(st.stage)
            elif st.outcome == StageOutcome.CONTRADICTED:
                contradicted_stages.add(st.stage)
            elif st.outcome in (StageOutcome.UNSUPPORTED, StageOutcome.INCONCLUSIVE):
                unsupported_stages.add(st.stage)

        prev_level = self.evidence_level
        prev_status = self.status

        # 1. Check for contradictions first (False Positive handling)
        if contradicted_stages:
            self.status = HypothesisStatus.REFUTED
            self.evidence_level = EvidenceLevel.POSSIBLE
            self.confidence_score = 0.10
            # Explicitly mark unreachability / unexploitability if contradicted
            if VerificationStageType.STRUCTURAL_REACHABILITY in contradicted_stages:
                self.is_reachable = False
                self.is_exploitable = False
            if VerificationStageType.DATAFLOW_TAINT in contradicted_stages:
                self.is_tainted = False
                self.is_exploitable = False
            if VerificationStageType.SYMBOLIC_CONSTRAINT in contradicted_stages:
                self.is_exploitable = False
            if VerificationStageType.EMULATION_RUNTIME in contradicted_stages:
                self.is_exploitable = False

            transition_note = (
                f"Contradicted at {', '.join(s.value for s in contradicted_stages)}: "
                f"status changed from {prev_status.value} to REFUTED (confidence: {self.confidence_score:.2f})."
            )
            if not self.transition_history or self.transition_history[-1] != transition_note:
                self.transition_history.append(transition_note)
            return

        # 2. Check reachability
        if VerificationStageType.STRUCTURAL_REACHABILITY in supported_stages:
            self.is_reachable = True
        elif VerificationStageType.STRUCTURAL_REACHABILITY in unsupported_stages:
            self.is_reachable = None

        # 3. Check taint (Rule: Reachable is NOT automatically tainted or exploitable)
        if VerificationStageType.DATAFLOW_TAINT in supported_stages:
            self.is_tainted = True
        elif VerificationStageType.DATAFLOW_TAINT in unsupported_stages:
            self.is_tainted = None

        # 4. Check concrete input recovery
        if VerificationStageType.SYMBOLIC_CONSTRAINT in supported_stages:
            if self.concrete_trigger is None and latest_record and latest_record.concrete_inputs:
                self.concrete_trigger = latest_record.concrete_inputs

        # 5. Evaluate evidence level promotion
        # - RUNTIME stage supported -> OBSERVED (and VERIFIED status)
        if VerificationStageType.EMULATION_RUNTIME in supported_stages:
            self.evidence_level = EvidenceLevel.OBSERVED
            self.status = HypothesisStatus.VERIFIED
            self.confidence_score = 0.95
            if self.is_tainted is True and self.concrete_trigger:
                self.is_exploitable = True
        # - SYMBOLIC_CONSTRAINT or DATAFLOW_TAINT supported -> INFERRED
        elif (
            VerificationStageType.SYMBOLIC_CONSTRAINT in supported_stages
            or VerificationStageType.DATAFLOW_TAINT in supported_stages
        ):
            self.evidence_level = EvidenceLevel.INFERRED
            self.status = HypothesisStatus.ACTIVE
            self.confidence_score = 0.80 if self.concrete_trigger else 0.70
            self.is_exploitable = None  # Requires concrete runtime confirmation
        # - STRUCTURAL_REACHABILITY supported alone -> INFERRED (Structural only, not exploitable)
        elif VerificationStageType.STRUCTURAL_REACHABILITY in supported_stages:
            self.evidence_level = EvidenceLevel.INFERRED
            self.status = HypothesisStatus.ACTIVE
            self.confidence_score = 0.55
            self.is_tainted = None
            self.is_exploitable = None
        # - Unsupported or inconclusive only
        elif unsupported_stages:
            self.evidence_level = EvidenceLevel.POSSIBLE
            self.status = HypothesisStatus.INCONCLUSIVE
            self.confidence_score = 0.35
            self.is_exploitable = None
        else:
            self.evidence_level = EvidenceLevel.POSSIBLE
            self.status = HypothesisStatus.ACTIVE
            self.confidence_score = 0.35
            self.is_exploitable = None

        if prev_level != self.evidence_level or prev_status != self.status:
            step_name = latest_record.stage.value if latest_record else "eval"
            transition_note = (
                f"Stage '{step_name}' completed ({latest_record.outcome.value if latest_record else 'init'}): "
                f"Level [{prev_level.value.upper()} -> {self.evidence_level.value.upper()}], "
                f"Status [{prev_status.value} -> {self.status.value}], "
                f"Confidence [{self.confidence_score:.2f}]."
            )
            self.transition_history.append(transition_note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "category": self.category,
            "initial_claim": self.initial_claim,
            "target_function": self.target_function,
            "target_address": self.target_address,
            "evidence_level": self.evidence_level.value,
            "status": self.status.value,
            "is_reachable": self.is_reachable,
            "is_tainted": self.is_tainted,
            "is_exploitable": self.is_exploitable,
            "concrete_trigger": self.concrete_trigger,
            "confidence_score": round(self.confidence_score, 2),
            "contradictions": list(self.contradictions),
            "transition_history": list(self.transition_history),
            "stages": [s.to_dict() for s in self.stages],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HypothesisEscalationRecord:
        record = cls(
            hypothesis_id=data["hypothesis_id"],
            title=data["title"],
            category=data.get("category", "vulnerability"),
            initial_claim=data.get("initial_claim", ""),
            target_function=data.get("target_function"),
            target_address=data.get("target_address"),
            evidence_level=EvidenceLevel(data.get("evidence_level", EvidenceLevel.POSSIBLE.value)),
            status=HypothesisStatus(data.get("status", HypothesisStatus.ACTIVE.value)),
            is_reachable=data.get("is_reachable"),
            is_tainted=data.get("is_tainted"),
            is_exploitable=data.get("is_exploitable"),
            concrete_trigger=data.get("concrete_trigger"),
            confidence_score=float(data.get("confidence_score", 0.35)),
            contradictions=list(data.get("contradictions", [])),
            transition_history=list(data.get("transition_history", [])),
            created_at=data.get("created_at", _utc_now_iso()),
            updated_at=data.get("updated_at", _utc_now_iso()),
        )
        for s in data.get("stages", []):
            record.stages.append(VerificationStageRecord.from_dict(s))
        return record

    def to_finding(self) -> Finding:
        """Convert into a canonical Finding object with evidence items."""
        finding = Finding(
            title=f"Verified Hypothesis: {self.title}"
            if self.status == HypothesisStatus.VERIFIED
            else self.title,
            description=f"{self.initial_claim}\n\nStatus: {self.status.value.upper()}.\nConfidence: {self.confidence_score:.0%}.",
            level=self.evidence_level,
            category=self.category,
        )
        for s in self.stages:
            loc = self.target_address or self.target_function or "unknown"
            finding.add_evidence(
                source=s.tool_name,
                location=loc,
                description=f"[{s.stage.value}] ({s.outcome.value}) {s.summary}",
                origin=s.stage.default_origin,
            )
        return finding

    def format_markdown(self) -> str:
        """Format a comprehensive analyst verification dossier."""
        status_badge = {
            HypothesisStatus.VERIFIED: "✅ VERIFIED",
            HypothesisStatus.REFUTED: "❌ REFUTED (FALSE POSITIVE)",
            HypothesisStatus.INCONCLUSIVE: "⚠️ INCONCLUSIVE",
            HypothesisStatus.ACTIVE: "🔄 ACTIVE",
        }[self.status]

        lines = [
            f"## {self.evidence_level.symbol} [{self.evidence_level.value.upper()}] {self.title}",
            "",
            f"**Hypothesis ID**: `{self.hypothesis_id}`  ",
            f"**Status**: **{status_badge}**  ",
            f"**Category**: `{self.category}`  ",
            f"**Confidence**: `{self.confidence_score:.0%}`  ",
            f"**Target**: `{self.target_function or 'N/A'}` @ `{self.target_address or 'N/A'}`  ",
            "",
            "### Initial Hypothesis Statement",
            f"> {self.initial_claim}",
            "",
            "### Verification State",
            f"- **Control-Flow Reachable**: `{self.is_reachable}`",
            f"- **Data-Flow Tainted**: `{self.is_tainted}`",
            f"- **Confirmed Exploitable**: `{self.is_exploitable}`",
            "",
        ]

        if self.concrete_trigger:
            lines.append("### Concrete Input Trigger")
            lines.append("```json")
            import json

            lines.append(json.dumps(self.concrete_trigger, indent=2))
            lines.append("```")
            lines.append("")

        if self.contradictions:
            lines.append("### ⚠️ Contradictory Evidence")
            for c in self.contradictions:
                lines.append(f"- ❌ {c}")
            lines.append("")

        lines.append("### Verification Stages Performed")
        lines.append("| # | Stage | Tool | Outcome | Summary |")
        lines.append("|---|---|---|---|---|")
        for i, st in enumerate(self.stages, 1):
            outcome_icon = {
                StageOutcome.SUPPORTED: "✅ Supported",
                StageOutcome.CONTRADICTED: "❌ Contradicted",
                StageOutcome.INCONCLUSIVE: "⚠️ Inconclusive",
                StageOutcome.UNSUPPORTED: "⏹️ Unsupported",
            }[st.outcome]
            lines.append(
                f"| {i} | {st.stage.display_name} | `{st.tool_name}` | {outcome_icon} | {st.summary} |"
            )

        lines.append("")
        lines.append("### Evidence Transition History")
        for h in self.transition_history:
            lines.append(f"- {h}")

        return "\n".join(lines)


def create_initial_hypothesis(
    hypothesis_id: str,
    title: str,
    initial_claim: str,
    category: str = "vulnerability",
    target_function: str | None = None,
    target_address: str | None = None,
    source_tool: str = "static_analysis",
    source_evidence: dict[str, Any] | None = None,
) -> HypothesisEscalationRecord:
    """Create a new hypothesis escalation record from an initial static suspicion."""
    rec = HypothesisEscalationRecord(
        hypothesis_id=hypothesis_id,
        title=title,
        category=category,
        initial_claim=initial_claim,
        target_function=target_function,
        target_address=target_address,
    )
    rec.add_stage(
        stage=VerificationStageType.STATIC_OBSERVATION,
        tool_name=source_tool,
        outcome=StageOutcome.SUPPORTED,
        summary=f"Initial suspicion recorded: {initial_claim}",
        tool_evidence=source_evidence or {},
    )
    return rec
