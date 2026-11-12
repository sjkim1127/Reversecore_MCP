"""Unit tests for Dynamic Execution Sandbox Benchmark Runner."""

from __future__ import annotations

import pytest

from reversecore_mcp.benchmarks.dynamic_benchmark import DynamicSandboxBenchmarkRunner
from reversecore_mcp.benchmarks.models import (
    DynamicSandboxGroundTruth,
    DynamicSandboxScorecardSummary,
    DynamicSandboxTargetResult,
)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_dynamic_benchmark_mock_mode() -> None:
    """Test DynamicSandboxBenchmarkRunner in mock mode."""
    target = DynamicSandboxGroundTruth(
        target_id="mock_test",
        binary_path="/bin/echo",
        args=["hello"],
        expected_syscalls=["execve", "write"],
        expected_network_beacons=["1.2.3.4"],
        anti_debug_present=True,
        expected_bypass_success=True,
        expected_seccomp_blocked=False,
    )

    runner = DynamicSandboxBenchmarkRunner(mock_mode=True)
    res = await runner.evaluate_target(target)

    assert isinstance(res, DynamicSandboxTargetResult)
    assert res.target_id == "mock_test"
    assert res.status == "SUCCESS"
    assert res.syscall_coverage_pct == 100.0
    assert res.anti_debug_bypassed is True
    assert res.network_detection_rate_pct == 100.0
    assert res.seccomp_containment_verified is True


@pytest.mark.unit
@pytest.mark.asyncio
async def test_dynamic_benchmark_suite_execution() -> None:
    """Test DynamicSandboxBenchmarkRunner running a suite of targets."""
    targets = [
        DynamicSandboxGroundTruth(
            target_id="t1",
            binary_path="/bin/echo",
            expected_syscalls=["execve"],
        ),
        DynamicSandboxGroundTruth(
            target_id="t2",
            binary_path="/bin/ls",
            expected_syscalls=["execve", "openat"],
        ),
    ]

    runner = DynamicSandboxBenchmarkRunner(mock_mode=True)
    summary = await runner.run_suite(targets)

    assert isinstance(summary, DynamicSandboxScorecardSummary)
    assert summary.total_targets == 2
    assert summary.success_count == 2
    assert summary.avg_syscall_coverage_pct == 100.0
    assert summary.containment_enforcement_rate_pct == 100.0
    assert len(summary.target_results) == 2

    json_str = summary.to_json()
    assert "t1" in json_str
    assert "t2" in json_str
