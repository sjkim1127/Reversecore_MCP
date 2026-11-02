"""Unit tests for release-to-release security regression review engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reversecore_mcp.core.memory import MemoryStore
from reversecore_mcp.core.security_regression import (
    FindingCategory,
    RegressionFinding,
    RegressionFindingStatus,
    RegressionSeverity,
    RegressionVerdict,
    SecurityRegressionReview,
    build_regression_review,
    transfer_session_findings_for_regression,
)
from reversecore_mcp.prompts.regression_review import security_regression_mode

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "security_regression"


def load_fixture(filename: str) -> RegressionFinding:
    path = FIXTURES_DIR / filename
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return RegressionFinding.from_dict(data)


@pytest.fixture
def fixed_vuln_finding() -> RegressionFinding:
    return load_fixture("fixed_vulnerability.json")


@pytest.fixture
def introduced_risk_finding() -> RegressionFinding:
    return load_fixture("introduced_risk.json")


@pytest.fixture
def benign_refactor_finding() -> RegressionFinding:
    return load_fixture("benign_refactor.json")


@pytest.mark.unit
def test_benign_refactor_does_not_escalate_to_regression(
    benign_refactor_finding: RegressionFinding,
):
    """AC1 & AC3: Benign code-motion/refactor does not produce a high-confidence security regression."""
    assert benign_refactor_finding.security_relevant is False
    assert benign_refactor_finding.category == FindingCategory.BENIGN_REFACTOR
    assert benign_refactor_finding.severity == RegressionSeverity.INFORMATIONAL
    assert benign_refactor_finding.confidence_score <= 0.3

    review = build_regression_review(
        review_id="rev_benign_01",
        old_binary_name="v1.bin",
        old_binary_hash="1111222233334444",
        new_binary_name="v2.bin",
        new_binary_hash="5555666677778888",
        findings=[benign_refactor_finding],
    )

    # Must be classified as BENIGN_REFACTOR, NEVER HIGH_RISK_REGRESSION
    assert review.verdict == RegressionVerdict.BENIGN_REFACTOR
    assert len(review.introduced_findings) == 0

    md = review.format_markdown()
    assert "BENIGN REFACTOR" in md
    assert "Compiler Inlining" in md


@pytest.mark.unit
def test_deliberately_introduced_dangerous_sink_surfaced_and_localized(
    introduced_risk_finding: RegressionFinding,
):
    """AC2 & AC4: Introduced dangerous sink is surfaced, localized with exact address, and triggers high risk."""
    assert introduced_risk_finding.status == RegressionFindingStatus.INTRODUCED
    assert introduced_risk_finding.category == FindingCategory.DANGEROUS_SINK
    assert introduced_risk_finding.severity == RegressionSeverity.CRITICAL
    assert introduced_risk_finding.security_relevant is True

    # Exact location citation
    new_loc = introduced_risk_finding.new_location
    assert new_loc is not None
    assert new_loc.function_name == "handle_debug_command"
    assert new_loc.address == "0x405800"
    assert introduced_risk_finding.provenance_tool == "taint_trace"

    review = build_regression_review(
        review_id="rev_danger_01",
        old_binary_name="v1.bin",
        old_binary_hash="aaaa1111",
        new_binary_name="v2.bin",
        new_binary_hash="bbbb2222",
        findings=[introduced_risk_finding],
    )

    # Must trigger HIGH_RISK_REGRESSION
    assert review.verdict == RegressionVerdict.HIGH_RISK_REGRESSION
    assert len(review.introduced_findings) == 1

    md = review.format_markdown()
    assert "HIGH RISK REGRESSION" in md
    assert "handle_debug_command@0x405800" in md
    assert "taint_trace" in md


@pytest.mark.unit
def test_fixed_vulnerability_promotes_security_improved(
    fixed_vuln_finding: RegressionFinding,
):
    """Remediated vulnerability results in SECURITY_IMPROVED verdict."""
    assert fixed_vuln_finding.status == RegressionFindingStatus.REMOVED
    assert fixed_vuln_finding.category == FindingCategory.VULNERABILITY_FIX
    assert fixed_vuln_finding.security_relevant is True
    assert fixed_vuln_finding.provenance_tool == "explain_patch"

    # Both old and new locations cited
    assert fixed_vuln_finding.old_location.address == "0x401240"
    assert fixed_vuln_finding.new_location.address == "0x401310"

    review = build_regression_review(
        review_id="rev_improved_01",
        old_binary_name="v1.bin",
        old_binary_hash="1234",
        new_binary_name="v2.bin",
        new_binary_hash="5678",
        findings=[fixed_vuln_finding],
    )

    assert review.verdict == RegressionVerdict.SECURITY_IMPROVED
    assert len(review.removed_findings) == 1


@pytest.mark.asyncio
async def test_transfer_session_findings_and_memory_reuse(tmp_path: Path):
    """Verify carrying forward analyst findings across memory sessions."""
    db_path = tmp_path / "regression_memory.db"
    store = MemoryStore(db_path=db_path)
    await store.initialize()

    # Create v1 session and save prior vulnerability finding
    sess1_id = await store.create_session(
        name="release_v1_session",
        binary_name="server_v1.bin",
        binary_hash="hash_v1",
    )
    await store.save_memory(
        session_id=sess1_id,
        memory_type="finding",
        content="Format string bug in log_client_ip",
        category="vulnerability_sink",
        importance=8,
    )

    # Create v2 session
    sess2_id = await store.create_session(
        name="release_v2_session",
        binary_name="server_v2.bin",
        binary_hash="hash_v2",
    )

    # Transfer findings
    transferred = await transfer_session_findings_for_regression(
        store=store,
        old_session_id=sess1_id,
        new_session_id=sess2_id,
        matched_functions={"log_client_ip": "log_client_ip_v2"},
    )

    assert len(transferred) == 1
    t = transferred[0]
    assert t.status == RegressionFindingStatus.UNCHANGED_BUT_RELEVANT
    assert "Format string bug" in t.title
    assert t.security_relevant is True

    # Verify memory was persisted in v2 session
    v2_memories = await store.get_session_memories(sess2_id)
    assert len(v2_memories) == 1
    assert "Carried from" in v2_memories[0]["content"]


@pytest.mark.unit
def test_serialization_roundtrip_review(
    fixed_vuln_finding: RegressionFinding,
    introduced_risk_finding: RegressionFinding,
    benign_refactor_finding: RegressionFinding,
):
    """Verify JSON serialization and deserialization roundtrip."""
    review = build_regression_review(
        review_id="rev_comprehensive",
        old_binary_name="app_v1.elf",
        old_binary_hash="11223344",
        new_binary_name="app_v2.elf",
        new_binary_hash="55667788",
        findings=[
            fixed_vuln_finding,
            introduced_risk_finding,
            benign_refactor_finding,
        ],
        summary_notes="Multi-finding comprehensive test.",
    )

    review_dict = review.to_dict()
    restored = SecurityRegressionReview.from_dict(review_dict)

    assert restored.review_id == "rev_comprehensive"
    assert restored.verdict == RegressionVerdict.HIGH_RISK_REGRESSION
    assert len(restored.findings) == 3
    assert len(restored.introduced_findings) == 1
    assert len(restored.removed_findings) == 1
    assert len(restored.changed_findings) == 1


@pytest.mark.unit
def test_security_regression_mode_prompt_generation():
    """Verify guided prompt renders with all necessary SOP steps and invariants."""
    prompt = security_regression_mode(
        old_binary="firmware_1.0.bin",
        new_binary="firmware_2.0.bin",
        target_function="handle_packet",
    )

    assert "firmware_1.0.bin" in prompt
    assert "firmware_2.0.bin" in prompt
    assert "handle_packet" in prompt
    assert "diff_binaries" in prompt
    assert "analyze_variant_changes" in prompt
    assert "explain_patch" in prompt
    assert "taint_trace" in prompt
    assert "BENIGN_REFACTOR" in prompt
    assert "HIGH_RISK_REGRESSION" in prompt
