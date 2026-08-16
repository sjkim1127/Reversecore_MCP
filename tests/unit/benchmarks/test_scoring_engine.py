"""Unit tests for ScoringEngine in reversecore_mcp.benchmarks.scoring."""

from __future__ import annotations

import pytest

from reversecore_mcp.benchmarks.models import (
    CVSSGroundTruth,
    FixturePaths,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.scoring import ScoringEngine


@pytest.fixture
def sample_target() -> TargetGroundTruth:
    """Fixture returning a standard TargetGroundTruth instance."""
    return TargetGroundTruth(
        target_id="test_heap_uaf",
        target_name="Test Heap Use After Free",
        category="parser",
        real_world_library="libtest",
        target_version="1.0.0",
        cve_reference="CVE-2026-0001",
        vulnerability_class="use_after_free",
        cwe_id="CWE-416",
        cwe_name="Use After Free",
        faulting_symbol="test_free_func",
        source_file="test.c",
        source_line=100,
        expected_memory_access_type="FREE",
        expected_access_size=8,
        cvss=CVSSGroundTruth(
            base_score_min=8.0,
            base_score_max=9.0,
            expected_score=8.8,
            severity="HIGH",
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            tolerated_vectors=[],
        ),
        fixtures=FixturePaths(
            vulnerable_source="vulnerable.c",
            patched_source="patched.c",
            patch_diff="patch.diff",
            harness_c="harness.c",
            asan_crash_log="asan.log",
            valid_seed_corpus="seeds",
            raw_crash_poc="poc.bin",
            minimized_poc="poc_min.bin",
        ),
        raw_poc_size_bytes=100,
        minimized_poc_target_bytes=20,
        expected_minimization_ratio_min=0.8,
        dictionary_tokens=["TOKEN1", "TOKEN2"],
        max_time_to_crash_seconds=30,
    )


class TestScoringEngine:
    """Comprehensive test suite for ScoringEngine mathematical calculations."""

    def test_single_target_true_positive_exact_match(
        self, sample_target: TargetGroundTruth
    ) -> None:
        """Test single target true positive evaluation with exact CWE and CVSS match."""
        engine = ScoringEngine(cvss_tolerance=0.5)
        tool_output = {
            "target_function": "test_free_func",
            "cwe_id": "CWE-416",
            "cvss_v31_score": 8.8,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 2000, "crashes_detected": 1},
            "minimized_input_size_bytes": 20,
        }

        res = engine.evaluate_target(
            ground_truth=sample_target,
            tool_output=tool_output,
            elapsed_time=2.0,
            is_error=False,
        )

        assert res.target_id == "test_heap_uaf"
        assert res.status == "DISCOVERED"
        assert res.is_true_positive is True
        assert res.time_to_crash_seconds == 2.0
        assert res.total_executions == 2000
        assert res.throughput_execs_per_sec == 1000.0  # 2000 / 2.0
        assert res.original_poc_size_bytes == 100
        assert res.minimized_poc_size_bytes == 20
        assert res.poc_reduction_percentage == 80.0  # (100 - 20) / 100 * 100
        assert res.cwe_exact_match is True
        assert res.cwe_hierarchical_match is True
        assert res.cwe_match_score == 1.0
        assert res.ground_truth_cvss == 8.8
        assert res.predicted_cvss == 8.8
        assert res.cvss_delta == 0.0
        assert res.cvss_tolerance_passed is True
        assert res.severity_match is True
        assert res.faulting_symbol == "test_free_func"
        assert res.error_message is None

    def test_single_target_hierarchical_cwe_match(self, sample_target: TargetGroundTruth) -> None:
        """Test hierarchical CWE match (parent/child score = 0.75)."""
        engine = ScoringEngine(cvss_tolerance=1.0)
        # CWE-416 (UAF) parent is CWE-672 (Operation on Resource after Expiration or Release)
        tool_output = {
            "cwe_id": "CWE-672",
            "cvss_v31_score": 8.5,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 500, "crashes_detected": 1},
            "minimized_input_size_bytes": 40,
        }

        res = engine.evaluate_target(
            ground_truth=sample_target,
            tool_output=tool_output,
            elapsed_time=1.5,
        )

        assert res.status == "DISCOVERED"
        assert res.is_true_positive is True
        assert res.cwe_exact_match is False
        assert res.cwe_hierarchical_match is True
        assert res.cwe_match_score == 0.75
        assert res.cvss_delta == 0.3  # |8.5 - 8.8|
        assert res.cvss_tolerance_passed is True
        assert res.poc_reduction_percentage == 60.0

    def test_single_target_triaged_crashes_extraction(
        self, sample_target: TargetGroundTruth
    ) -> None:
        """Test extraction from nested triaged_crashes when top-level fields are omitted."""
        engine = ScoringEngine()
        tool_output = {
            "fuzzing_stats": {"executions": 1000, "crashes_detected": 1},
            "triaged_crashes": [
                {
                    "cwe_id": "CWE-416",
                    "faulting_function": "test_free_func",
                    "cvss": {
                        "cvss_v31_score": 8.8,
                        "severity": "HIGH",
                    },
                }
            ],
            "minimized_input_size_bytes": 20,
        }

        res = engine.evaluate_target(
            ground_truth=sample_target,
            tool_output=tool_output,
            elapsed_time=1.0,
        )

        assert res.is_true_positive is True
        assert res.cwe_exact_match is True
        assert res.predicted_cvss == 8.8
        assert res.predicted_severity == "HIGH"
        assert res.severity_match is True
        assert res.faulting_symbol == "test_free_func"

    def test_single_target_error_handling(self, sample_target: TargetGroundTruth) -> None:
        """Test evaluation when tool run resulted in an unhandled error."""
        engine = ScoringEngine()
        res = engine.evaluate_target(
            ground_truth=sample_target,
            tool_output=None,
            elapsed_time=3.5,
            is_error=True,
            error_msg="Compilation failure: symbol not found",
        )

        assert res.status == "ERROR"
        assert res.is_true_positive is False
        assert res.time_to_crash_seconds == 3.5
        assert res.total_executions == 0
        assert res.throughput_execs_per_sec == 0.0
        assert res.poc_reduction_percentage == 0.0
        assert res.cwe_exact_match is False
        assert res.cwe_match_score == 0.0
        assert res.cvss_tolerance_passed is False
        assert res.severity_match is False
        assert res.error_message == "Compilation failure: symbol not found"

    def test_single_target_missed_handling(self, sample_target: TargetGroundTruth) -> None:
        """Test evaluation when tool ran successfully but found no crash or CWE."""
        engine = ScoringEngine()
        tool_output = {
            "fuzzing_stats": {"executions": 5000, "crashes_detected": 0},
            "triaged_crashes": [],
        }

        res = engine.evaluate_target(
            ground_truth=sample_target,
            tool_output=tool_output,
            elapsed_time=5.0,
            is_error=False,
        )

        assert res.status == "MISSED"
        assert res.is_true_positive is False
        assert res.time_to_crash_seconds == 5.0
        assert res.throughput_execs_per_sec == 1000.0  # 5000 / 5.0

    def test_poc_reduction_edge_cases(self, sample_target: TargetGroundTruth) -> None:
        """Test PoC byte reduction under 0 raw bytes and expanded minimized bytes."""
        engine = ScoringEngine()

        # Minimized larger than original -> 0.0%
        tool_output_expanded = {
            "cwe_id": "CWE-416",
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
            "minimized_input_size_bytes": 150,  # larger than raw 100
        }
        res_exp = engine.evaluate_target(sample_target, tool_output_expanded, elapsed_time=1.0)
        assert res_exp.poc_reduction_percentage == 0.0

        # Zero raw bytes in ground truth -> 0.0%
        zero_target = sample_target.model_copy(update={"raw_poc_size_bytes": 0})
        res_zero = engine.evaluate_target(zero_target, tool_output_expanded, elapsed_time=1.0)
        assert res_zero.poc_reduction_percentage == 0.0

    def test_zero_elapsed_time_throughput(self, sample_target: TargetGroundTruth) -> None:
        """Test zero division guard when elapsed time is 0.0s."""
        engine = ScoringEngine()
        tool_output = {
            "cwe_id": "CWE-416",
            "fuzzing_stats": {"executions": 500, "crashes_detected": 1},
        }
        res = engine.evaluate_target(sample_target, tool_output, elapsed_time=0.0)
        assert res.throughput_execs_per_sec == 0.0

    def test_aggregate_scorecard_empty_list(self) -> None:
        """Test aggregate scorecard on empty list returns clean 0.0 values."""
        engine = ScoringEngine()
        scorecard = engine.aggregate_scorecard([], total_duration=0.0)

        assert scorecard.total_targets == 0
        assert scorecard.discovered_count == 0
        assert scorecard.missed_count == 0
        assert scorecard.error_count == 0
        assert scorecard.discovery_rate_tpr_pct == 0.0
        assert scorecard.mean_time_to_crash_seconds == 0.0
        assert scorecard.avg_throughput_exec_per_sec == 0.0
        assert scorecard.avg_poc_reduction_pct == 0.0
        assert scorecard.cwe_exact_match_rate_pct == 0.0
        assert scorecard.cwe_hierarchical_match_rate_pct == 0.0
        assert scorecard.cvss_mean_absolute_error == 0.0
        assert scorecard.cvss_tolerance_match_rate_pct == 0.0
        assert scorecard.severity_concordance_rate_pct == 0.0
        assert scorecard.class_breakdown == {}
        assert scorecard.target_results == []

    def test_aggregate_scorecard_multi_targets(self, sample_target: TargetGroundTruth) -> None:
        """Test full scorecard aggregation across multiple target results."""
        engine = ScoringEngine(cvss_tolerance=0.5)

        target2 = sample_target.model_copy(
            update={
                "target_id": "target_overflow",
                "vulnerability_class": "heap_buffer_overflow",
                "cwe_id": "CWE-122",
            }
        )

        res1 = engine.evaluate_target(
            ground_truth=sample_target,
            tool_output={
                "cwe_id": "CWE-416",
                "cvss_v31_score": 8.8,
                "cvss_severity": "HIGH",
                "fuzzing_stats": {"executions": 2000, "crashes_detected": 1},
                "minimized_input_size_bytes": 20,
            },
            elapsed_time=2.0,
        )

        res2 = engine.evaluate_target(
            ground_truth=target2,
            tool_output={
                "cwe_id": "CWE-122",
                "cvss_v31_score": 8.6,
                "cvss_severity": "HIGH",
                "fuzzing_stats": {"executions": 4000, "crashes_detected": 1},
                "minimized_input_size_bytes": 50,
            },
            elapsed_time=4.0,
        )

        res3 = engine.evaluate_target(
            ground_truth=sample_target,
            tool_output=None,
            elapsed_time=1.0,
            is_error=True,
            error_msg="Crash in fuzzer",
        )

        scorecard = engine.aggregate_scorecard([res1, res2, res3], total_duration=7.0)

        assert scorecard.total_targets == 3
        assert scorecard.discovered_count == 2
        assert scorecard.missed_count == 0
        assert scorecard.error_count == 1
        assert scorecard.discovery_rate_tpr_pct == 66.7  # 2 / 3 * 100
        assert scorecard.mean_time_to_crash_seconds == 3.0  # (2.0 + 4.0) / 2
        # Throughputs: res1=1000.0, res2=1000.0, res3=0.0 -> avg = 2000.0 / 3 = 666.7
        assert scorecard.avg_throughput_exec_per_sec == 666.7
        # PoC reductions: res1=80.0%, res2=50.0% -> avg = 65.0%
        assert scorecard.avg_poc_reduction_pct == 65.0
        assert scorecard.cwe_exact_match_rate_pct == 100.0
        assert scorecard.cwe_hierarchical_match_rate_pct == 100.0
        # CVSS MAE: res1 delta=0.0, res2 delta=0.2 -> avg = 0.1
        assert scorecard.cvss_mean_absolute_error == 0.1
        assert scorecard.cvss_tolerance_match_rate_pct == 100.0
        assert scorecard.severity_concordance_rate_pct == 100.0

        # Class breakdown verification
        assert "use_after_free" in scorecard.class_breakdown
        assert "heap_buffer_overflow" in scorecard.class_breakdown
        uaf_stats = scorecard.class_breakdown["use_after_free"]
        assert uaf_stats["total"] == 2
        assert uaf_stats["discovered"] == 1
        assert uaf_stats["missed"] == 1
        assert uaf_stats["tpr_pct"] == 50.0
        assert uaf_stats["avg_ttc_s"] == 2.0
        assert uaf_stats["avg_reduction_pct"] == 80.0
