"""Unit tests for AnalysisPriorityQueue engine."""

from __future__ import annotations

import pytest

from reversecore_mcp.core.case_state import (
    AnalysisTarget,
    CaseState,
    SampleMetadata,
    TargetPriority,
    TargetStatus,
)
from reversecore_mcp.core.priority_queue import (
    AnalysisPriorityQueue,
)


@pytest.fixture
def sample_case() -> CaseState:
    """Fixture providing a mock CaseState for priority queue testing."""
    sample = SampleMetadata(
        path="/app/workspace/sample.exe",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    case = CaseState(
        case_id="case_test_queue",
        sample=sample,
        phase="triage",
    )
    case.add_hypothesis(
        title="Sample communicates with C2 server over HTTPS",
        category="network",
        evidence_level="possible",
        evidence_refs=["import:InternetOpenA"],
        rationale="Import table contains WinINet functions",
    )
    return case


@pytest.mark.unit
def test_priority_queue_scoring_weights(sample_case: CaseState):
    """Verify base priority scores and status modifiers."""
    crit_target = AnalysisTarget(
        id="t1",
        target="sym.inject_shellcode",
        kind="function",
        priority=TargetPriority.CRITICAL.value,
        reason="Process injection routine detected",
        status=TargetStatus.ACTIVE.value,
    )
    med_target = AnalysisTarget(
        id="t2",
        target="sym.parse_args",
        kind="function",
        priority=TargetPriority.MEDIUM.value,
        reason="Normal command line parsing",
        status=TargetStatus.PENDING.value,
    )

    score1, breakdown1, is_ready1, _ = AnalysisPriorityQueue.calculate_target_score(
        crit_target, case=sample_case
    )
    score2, breakdown2, is_ready2, _ = AnalysisPriorityQueue.calculate_target_score(
        med_target, case=sample_case
    )

    assert score1 > score2
    assert breakdown1["base_priority"] == 1000.0
    assert breakdown1["status_adjustment"] == 120.0
    assert "process_injection_primitive" in breakdown1
    assert is_ready1 is True

    assert breakdown2["base_priority"] == 500.0
    assert breakdown2["status_adjustment"] == 0.0
    assert is_ready2 is True


@pytest.mark.unit
def test_priority_queue_hypothesis_boost(sample_case: CaseState):
    """Verify target aligned with active hypothesis receives boost."""
    aligned_target = AnalysisTarget(
        id="t_c2",
        target="InternetOpenA",
        kind="import",
        priority=TargetPriority.HIGH.value,
        reason="WinINet import used for C2 beaconing",
        status=TargetStatus.PENDING.value,
    )
    score, breakdown, _, _ = AnalysisPriorityQueue.calculate_target_score(
        aligned_target, case=sample_case
    )

    assert "hypothesis_alignment" in breakdown
    assert breakdown["hypothesis_alignment"] == 120.0


@pytest.mark.unit
def test_priority_queue_blocker_penalty_and_readiness(sample_case: CaseState):
    """Verify unresolved blockers reduce score and set is_ready to False."""
    blocked_target = AnalysisTarget(
        id="t_blocked",
        target="sym.decrypt_payload",
        kind="function",
        priority=TargetPriority.HIGH.value,
        reason="AES payload decryption",
        blockers=["sym.extract_aes_key"],
        status=TargetStatus.BLOCKED.value,
    )
    score, breakdown, is_ready, blockers = AnalysisPriorityQueue.calculate_target_score(
        blocked_target, case=sample_case
    )

    assert is_ready is False
    assert "sym.extract_aes_key" in blockers
    assert "unresolved_blockers_penalty" in breakdown
    assert breakdown["unresolved_blockers_penalty"] == -150.0


@pytest.mark.unit
def test_priority_queue_deterministic_ranking(sample_case: CaseState):
    """Verify deterministic ranking: ready items first, then score descending, then FIFO."""
    t1 = AnalysisTarget(
        id="t1",
        target="sym.unpacker",
        kind="function",
        priority=TargetPriority.HIGH.value,
        reason="Unpacker routine",
        created_at="2026-10-16T10:00:00Z",
    )
    t2 = AnalysisTarget(
        id="t2",
        target="sym.c2_handler",
        kind="function",
        priority=TargetPriority.HIGH.value,
        reason="C2 beaconing routine",
        created_at="2026-10-16T10:05:00Z",
    )
    t3_blocked = AnalysisTarget(
        id="t3",
        target="sym.critical_payload",
        kind="function",
        priority=TargetPriority.CRITICAL.value,
        reason="Critical payload",
        blockers=["sym.unpacker"],
        status=TargetStatus.BLOCKED.value,
        created_at="2026-10-16T09:00:00Z",
    )

    ranked = AnalysisPriorityQueue.rank_targets([t1, t2, t3_blocked], case=sample_case)

    # Ready items must precede blocked items despite t3 having CRITICAL base priority
    assert ranked[0].is_ready is True
    assert ranked[1].is_ready is True
    assert ranked[2].is_ready is False
    assert ranked[2].target.id == "t3"

    # t2 has C2 keyword boost, so it scores higher than t1
    assert ranked[0].target.id == "t2"
    assert ranked[1].target.id == "t1"


@pytest.mark.unit
def test_priority_queue_extract_targets_from_triage():
    """Verify automated extraction of suspicious APIs, sections, and diffs from triage."""
    triage_data = {
        "imports": [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CryptDecrypt",
            "IsDebuggerPresent",
            "GetCurrentProcess",
        ],
        "anti_analysis": [
            {"description": "PEB BeingDebugged check at 0x140001050", "address": "0x140001050"}
        ],
        "diff": ["sym.modified_protocol_handler"],
        "sections": [
            {"name": ".rsrc", "entropy": 7.85},
            {"name": ".text", "entropy": 6.20},
        ],
        "strings": ["https://evil-c2-domain.test/endpoint"],
    }

    targets = AnalysisPriorityQueue.extract_targets_from_triage(triage_data)
    target_names = {t.target for t in targets}

    assert "VirtualAllocEx" in target_names
    assert "WriteProcessMemory" in target_names
    assert "CryptDecrypt" in target_names
    assert "IsDebuggerPresent" in target_names
    assert "0x140001050" in target_names
    assert "sym.modified_protocol_handler" in target_names
    assert ".rsrc" in target_names
    assert ".text" not in target_names  # Entropy below threshold 7.0
    assert "https://evil-c2-domain.test/endpoint" in target_names

    # Check process injection has critical priority
    inj_target = next(t for t in targets if t.target == "VirtualAllocEx")
    assert inj_target.priority == TargetPriority.CRITICAL.value
    assert inj_target.kind == "import"


@pytest.mark.unit
def test_priority_queue_extract_triage_deduplication(sample_case: CaseState):
    """Verify extract_targets_from_triage does not re-add existing or completed targets."""
    sample_case.add_target(
        target="VirtualAllocEx",
        kind="import",
        priority=TargetPriority.CRITICAL.value,
        reason="Already in queue",
    )
    completed_tgt = sample_case.add_target(
        target="CryptDecrypt",
        kind="import",
        priority=TargetPriority.HIGH.value,
        reason="Already analyzed",
    )
    completed_tgt.status = TargetStatus.COMPLETED.value

    triage_data = {"imports": ["VirtualAllocEx", "CryptDecrypt", "InternetOpenA"]}

    new_targets = AnalysisPriorityQueue.extract_targets_from_triage(triage_data, case=sample_case)

    new_names = {t.target for t in new_targets}
    assert "InternetOpenA" in new_names
    assert "VirtualAllocEx" not in new_names
    assert "CryptDecrypt" not in new_names


@pytest.mark.unit
def test_priority_queue_resolve_target_completion(sample_case: CaseState):
    """Verify completing a blocker target automatically unblocks dependent targets."""
    t_key = sample_case.add_target(
        target="sym.extract_aes_key",
        kind="function",
        priority=TargetPriority.HIGH.value,
        reason="Extract AES decryption key",
    )
    t_payload = sample_case.add_target(
        target="sym.decrypt_payload",
        kind="function",
        priority=TargetPriority.CRITICAL.value,
        reason="Decrypt embedded payload",
        blockers=["sym.extract_aes_key"],
    )
    sample_case.add_blocker(
        target="sym.decrypt_payload",
        reason="Waiting for AES key",
        blocked_by=["sym.extract_aes_key"],
    )

    assert t_payload.status == TargetStatus.BLOCKED.value

    completed, unblocked = AnalysisPriorityQueue.resolve_target_completion(
        case=sample_case,
        target_id_or_name=t_key.id,
        findings=["Found AES-256-CBC key: 0x01020304..."],
        reason="Extracted key from .rdata section",
    )

    assert completed is not None
    assert completed.status == TargetStatus.COMPLETED.value
    assert "sym.decrypt_payload" in unblocked
    assert t_payload.status == TargetStatus.PENDING.value
    assert len(t_payload.blockers) == 0
    assert len(sample_case.blocked) == 0
    assert len(sample_case.completed_steps) == 1
