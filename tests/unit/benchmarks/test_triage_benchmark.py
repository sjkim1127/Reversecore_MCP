"""Unit tests for Layer 1 Meta-tool Triage Benchmark Runner."""

from __future__ import annotations

import pytest

from reversecore_mcp.benchmarks.models import (
    TriageGroundTruth,
    TriageScorecardSummary,
    TriageTargetResult,
)
from reversecore_mcp.benchmarks.triage_benchmark import TriageBenchmarkRunner


@pytest.mark.unit
@pytest.mark.asyncio
async def test_triage_benchmark_mock_mode() -> None:
    """Test TriageBenchmarkRunner in offline mock mode."""
    target = TriageGroundTruth(
        target_id="test_pe",
        target_file="sample.exe",
        category="binary",
        expected_format="PE",
        expected_arch="x86_64",
        expected_mitigations={"nx": True, "pie": True},
        expected_dangerous_apis=["strcpy"],
        expected_cwe_candidates=["CWE-120"],
        expected_risk_level="HIGH",
    )

    runner = TriageBenchmarkRunner(mock_mode=True)
    res = await runner.evaluate_target(target)

    assert isinstance(res, TriageTargetResult)
    assert res.target_id == "test_pe"
    assert res.status == "SUCCESS"
    assert res.format_matched is True
    assert res.arch_matched is True
    assert res.mitigations_accuracy_pct == 100.0
    assert res.dangerous_apis_recall_pct == 100.0
    assert res.cwe_matched is True
    assert res.risk_level_matched is True
    assert res.estimated_tokens > 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_triage_benchmark_suite_execution() -> None:
    """Test TriageBenchmarkRunner running a suite of targets."""
    targets = [
        TriageGroundTruth(
            target_id="target_1",
            target_file="test1.bin",
            expected_format="ELF",
            expected_arch="x86_64",
            expected_risk_level="LOW",
        ),
        TriageGroundTruth(
            target_id="target_2",
            target_file="test2.bin",
            expected_format="PE",
            expected_arch="x86",
            expected_risk_level="CRITICAL",
        ),
    ]

    runner = TriageBenchmarkRunner(mock_mode=True)
    summary = await runner.run_suite(targets)

    assert isinstance(summary, TriageScorecardSummary)
    assert summary.total_targets == 2
    assert summary.success_count == 2
    assert summary.triage_accuracy_pct == 100.0
    assert summary.risk_concordance_rate_pct == 100.0
    assert len(summary.target_results) == 2

    # JSON serialization
    json_out = summary.to_json()
    assert "target_1" in json_out
    assert "target_2" in json_out


@pytest.mark.unit
@pytest.mark.asyncio
async def test_triage_benchmark_timeout_handling() -> None:
    """Test TriageBenchmarkRunner timeout containment."""
    target = TriageGroundTruth(
        target_id="timeout_target",
        target_file="/nonexistent/path/to/binary",
        category="binary",
    )

    runner = TriageBenchmarkRunner(mock_mode=False, timeout_seconds=0)
    # File does not exist, so in mock_mode=False with missing file it falls back to mock or returns status
    res = await runner.evaluate_target(target)
    assert res.target_id == "timeout_target"
