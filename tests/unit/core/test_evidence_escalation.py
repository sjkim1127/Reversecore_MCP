"""Unit tests for the evidence-escalation workflow engine (Issue #316)."""

import json
from pathlib import Path

import pytest

from reversecore_mcp.core.case_state import HypothesisStatus
from reversecore_mcp.core.evidence import EvidenceLevel
from reversecore_mcp.core.evidence_escalation import (
    HypothesisEscalationRecord,
    StageOutcome,
    VerificationStageType,
    create_initial_hypothesis,
)
from reversecore_mcp.prompts.evidence_escalation import evidence_escalation_mode


def test_initial_hypothesis_creation():
    rec = create_initial_hypothesis(
        hypothesis_id="hyp-test-01",
        title="Suspicious command execution",
        initial_claim="Function sub_401000 may call system() based on string match",
        category="malware",
        target_function="sub_401000",
        target_address="0x00401000",
        source_tool="Radare2_list_strings",
    )

    assert rec.hypothesis_id == "hyp-test-01"
    assert rec.status == HypothesisStatus.ACTIVE
    assert rec.evidence_level == EvidenceLevel.POSSIBLE
    assert rec.confidence_score == pytest.approx(0.35, abs=0.05)
    assert rec.is_reachable is None
    assert rec.is_tainted is None
    assert rec.is_exploitable is None
    assert len(rec.stages) == 1
    assert rec.stages[0].stage == VerificationStageType.STATIC_OBSERVATION


def test_reachability_does_not_imply_tainted_or_exploitable():
    """Acceptance criterion 1: 'Reachable' is not automatically reported as 'tainted' or 'exploitable'."""
    rec = create_initial_hypothesis(
        hypothesis_id="hyp-reach-01",
        title="Check reachability",
        initial_claim="Suspect function sub_402000",
        target_function="sub_402000",
    )

    rec.add_stage(
        stage=VerificationStageType.STRUCTURAL_REACHABILITY,
        tool_name="Radare2_xrefs_to",
        outcome=StageOutcome.SUPPORTED,
        summary="Found xref path from main to sub_402000",
        tool_evidence={"caller": "main", "call_offset": "0x401015"},
    )

    assert rec.is_reachable is True
    # MUST NOT be marked tainted or exploitable
    assert rec.is_tainted is None
    assert rec.is_exploitable is None
    assert rec.evidence_level == EvidenceLevel.INFERRED
    assert rec.status == HypothesisStatus.ACTIVE
    assert rec.confidence_score < 0.65


def test_unsupported_verification_step_leaves_finding_inconclusive():
    """Acceptance criterion 2: Unsupported verification steps leave the finding inconclusive rather than silently upgrading confidence."""
    rec = create_initial_hypothesis(
        hypothesis_id="hyp-unsupported-01",
        title="Unsupported architecture check",
        initial_claim="Suspect path in MIPS binary",
        target_function="sub_800010",
    )

    prev_confidence = rec.confidence_score
    prev_level = rec.evidence_level

    # Stage encounters unsupported solver / architecture
    rec.add_stage(
        stage=VerificationStageType.SYMBOLIC_CONSTRAINT,
        tool_name="verify_path_and_get_args",
        outcome=StageOutcome.UNSUPPORTED,
        summary="Symbolic execution does not support binary architecture: mips32",
        tool_evidence={"arch": "mips32", "error": "unsupported_arch"},
    )

    assert rec.status == HypothesisStatus.INCONCLUSIVE
    assert rec.evidence_level == prev_level  # Did NOT upgrade to INFERRED or OBSERVED
    assert rec.confidence_score <= prev_confidence  # Confidence did NOT increase
    assert rec.is_exploitable is None


def test_contradictory_evidence_retained_and_refutes_hypothesis():
    """Acceptance criteria 3 & 4: Contradictory evidence is retained and downgrades/refutes hypothesis."""
    rec = create_initial_hypothesis(
        hypothesis_id="hyp-contradict-01",
        title="Suspected backdoor",
        initial_claim="Hidden command execution in dead_func",
        target_function="dead_func",
    )

    rec.add_stage(
        stage=VerificationStageType.STRUCTURAL_REACHABILITY,
        tool_name="Radare2_xrefs_to",
        outcome=StageOutcome.CONTRADICTED,
        summary="0 incoming xrefs found; dead code omitted from entrypoints",
        contradictions=["Function is completely unreferenced dead code"],
    )

    assert rec.status == HypothesisStatus.REFUTED
    assert "Function is completely unreferenced dead code" in rec.contradictions
    assert rec.is_reachable is False
    assert rec.is_exploitable is False
    assert rec.confidence_score <= 0.15


def test_full_escalation_lifecycle_to_verified_observed():
    """Full progression from static observation to confirmed observed finding."""
    rec = create_initial_hypothesis(
        hypothesis_id="hyp-full-01",
        title="Dormant backdoor execution",
        initial_claim="sub_401340 executes system() when magic token equals 0x5339",
        target_function="sub_401340",
    )

    # 1. Structural reachability
    rec.add_stage(
        stage=VerificationStageType.STRUCTURAL_REACHABILITY,
        tool_name="Radare2_xrefs_to",
        outcome=StageOutcome.SUPPORTED,
        summary="Caller path found: main -> dispatch -> sub_401340",
    )
    assert rec.is_reachable is True
    assert rec.evidence_level == EvidenceLevel.INFERRED

    # 2. Taint analysis
    rec.add_stage(
        stage=VerificationStageType.DATAFLOW_TAINT,
        tool_name="taint_trace",
        outcome=StageOutcome.SUPPORTED,
        summary="Dataflow from recv() to sub_401340",
    )
    assert rec.is_tainted is True
    assert rec.is_exploitable is None  # Not yet proven exploitable

    # 3. Symbolic constraint solving
    rec.add_stage(
        stage=VerificationStageType.SYMBOLIC_CONSTRAINT,
        tool_name="verify_path_and_get_args",
        outcome=StageOutcome.SUPPORTED,
        summary="SAT: Solved token == 0x5339",
        concrete_inputs={"token": "0x5339"},
    )
    assert rec.concrete_trigger == {"token": "0x5339"}

    # 4. Runtime emulation
    rec.add_stage(
        stage=VerificationStageType.EMULATION_RUNTIME,
        tool_name="dormant_detector",
        outcome=StageOutcome.SUPPORTED,
        summary="ESIL emulation reached system() sink at 0x401385 with eax=0x5339",
    )

    assert rec.status == HypothesisStatus.VERIFIED
    assert rec.evidence_level == EvidenceLevel.OBSERVED
    assert rec.is_exploitable is True
    assert rec.confidence_score >= 0.90
    assert len(rec.transition_history) >= 2


def test_positive_fixture_verification():
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "evidence_escalation"
        / "positive_fixture.json"
    )
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)

    rec = create_initial_hypothesis(
        hypothesis_id=data["hypothesis_id"],
        title=data["title"],
        initial_claim=data["initial_claim"],
        category=data["category"],
        target_function=data["target_function"],
        target_address=data["target_address"],
    )

    for step in data["steps"]:
        if step["stage"] == "static_observation":
            continue
        rec.add_stage(
            stage=step["stage"],
            tool_name=step["tool_name"],
            outcome=step["outcome"],
            summary=step["summary"],
            tool_evidence=step.get("tool_evidence"),
            concrete_inputs=step.get("concrete_inputs"),
        )

    assert rec.status.value == data["expected_final_status"]
    assert rec.evidence_level.value == data["expected_final_evidence_level"]
    assert rec.is_reachable == data["expected_is_reachable"]
    assert rec.is_tainted == data["expected_is_tainted"]
    assert rec.is_exploitable == data["expected_is_exploitable"]


def test_false_positive_fixture_downgrades_and_refutes():
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "evidence_escalation"
        / "false_positive_fixture.json"
    )
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)

    rec = create_initial_hypothesis(
        hypothesis_id=data["hypothesis_id"],
        title=data["title"],
        initial_claim=data["initial_claim"],
        category=data["category"],
        target_function=data["target_function"],
        target_address=data["target_address"],
    )

    for step in data["steps"]:
        if step["stage"] == "static_observation":
            continue
        rec.add_stage(
            stage=step["stage"],
            tool_name=step["tool_name"],
            outcome=step["outcome"],
            summary=step["summary"],
            tool_evidence=step.get("tool_evidence"),
            contradictions=step.get("contradictions"),
        )

    assert rec.status.value == data["expected_final_status"]
    assert rec.evidence_level.value == data["expected_final_evidence_level"]
    assert rec.is_reachable == data["expected_is_reachable"]
    assert rec.is_exploitable == data["expected_is_exploitable"]
    assert len(rec.contradictions) >= 2


def test_serialization_and_finding_conversion():
    rec = create_initial_hypothesis(
        hypothesis_id="hyp-ser-01",
        title="Serialization test",
        initial_claim="Testing conversion methods",
        target_function="sub_401000",
    )
    rec.add_stage(
        stage=VerificationStageType.STRUCTURAL_REACHABILITY,
        tool_name="Radare2_xrefs_to",
        outcome=StageOutcome.SUPPORTED,
        summary="Caller found",
    )

    # To/From dict
    d = rec.to_dict()
    restored = HypothesisEscalationRecord.from_dict(d)
    assert restored.hypothesis_id == rec.hypothesis_id
    assert restored.status == rec.status
    assert len(restored.stages) == len(rec.stages)

    # To Finding
    finding = rec.to_finding()
    assert finding.title == rec.title
    assert finding.level == rec.evidence_level
    assert len(finding.evidence) == len(rec.stages)

    # Format Markdown
    md = rec.format_markdown()
    assert "Verification Stages Performed" in md
    assert "Radare2_xrefs_to" in md


def test_guided_prompt_generation():
    prompt = evidence_escalation_mode(
        target_file="malware.bin",
        hypothesis="sub_401230 is a dormant backdoor",
        target_function="sub_401230",
    )
    assert "malware.bin" in prompt
    assert "sub_401230" in prompt
    assert "Reachable" in prompt
    assert "taint_trace" in prompt
    assert "verify_path_and_get_args" in prompt
    assert "dormant_detector" in prompt
