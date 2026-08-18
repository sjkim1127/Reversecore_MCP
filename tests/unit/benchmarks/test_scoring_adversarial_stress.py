"""Adversarial and Empirical Stress Test Suite for ScoringEngine and CWE Taxonomy.

Exhaustively stresses:
1. Empty collections and zero-division safety across all metrics.
2. Single-target and multi-target aggregations under extreme distributions.
3. Negative, zero, sub-millisecond, and extreme execution times.
4. PoC bytes reduction under 0 baseline bytes, negative reduction, expansions, and bad types.
5. Exact vs hierarchical CWE matching across deep hierarchies, multi-parent DAG nodes,
   and unmapped/corrupted CWE identifiers.
6. CVSS delta calculations: perfect matches, extreme divergence, tolerances, and corrupt inputs.
7. Qualitative severity concordance: matching, adjacent, discordant, and fallback extractions.
8. Vulnerability class stratification breakdown under missing, mixed, and single classes.
9. Floating-point precision, rounding stability, and zero-division guards.
10. Malformed, corrupted, and hostile tool output payloads.
11. Scale and high-volume performance stress (1,000+ targets).
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from reversecore_mcp.benchmarks.models import (
    CVSSGroundTruth,
    FixturePaths,
    TargetEvaluationResult,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.scoring import ScoringEngine


@pytest.fixture
def base_target() -> TargetGroundTruth:
    """Fixture returning a standard base TargetGroundTruth instance."""
    return TargetGroundTruth(
        target_id="test_target_base",
        target_name="Base Test Target",
        category="parser",
        real_world_library="libtest",
        target_version="1.0.0",
        cve_reference="CVE-2026-0001",
        vulnerability_class="heap_buffer_overflow",
        cwe_id="CWE-122",
        cwe_name="Heap-based Buffer Overflow",
        faulting_symbol="test_fault_func",
        source_file="test.c",
        source_line=42,
        expected_memory_access_type="WRITE_OOB",
        expected_access_size=4,
        cvss=CVSSGroundTruth(
            base_score_min=7.0,
            base_score_max=9.0,
            expected_score=8.8,
            severity="HIGH",
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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
        dictionary_tokens=["TOK1", "TOK2"],
        max_time_to_crash_seconds=30,
    )


# ============================================================================
# 1. Empty Input Collections & Zero-Division Safety
# ============================================================================


class TestEmptyAndZeroDivisionSafety:
    """Stress-test ScoringEngine against empty inputs and division-by-zero vectors."""

    def test_aggregate_scorecard_empty_list_all_durations(self) -> None:
        """Verify aggregate_scorecard on empty list cleanly returns all 0.0 values."""
        engine = ScoringEngine()
        for duration in [0.0, -10.5, 1e9, 0.0001]:
            summary = engine.aggregate_scorecard([], total_duration=duration)
            assert summary.total_targets == 0
            assert summary.discovered_count == 0
            assert summary.missed_count == 0
            assert summary.error_count == 0
            assert summary.discovery_rate_tpr_pct == 0.0
            assert summary.mean_time_to_crash_seconds == 0.0
            assert summary.avg_throughput_exec_per_sec == 0.0
            assert summary.avg_poc_reduction_pct == 0.0
            assert summary.cwe_exact_match_rate_pct == 0.0
            assert summary.cwe_hierarchical_match_rate_pct == 0.0
            assert summary.cvss_mean_absolute_error == 0.0
            assert summary.cvss_tolerance_match_rate_pct == 0.0
            assert summary.severity_concordance_rate_pct == 0.0
            assert summary.class_breakdown == {}
            assert summary.target_results == []
            assert summary.total_duration_seconds == round(max(0.0, float(duration)), 2)

    def test_evaluate_target_none_tool_output(self, base_target: TargetGroundTruth) -> None:
        """Verify evaluate_target handles None tool_output gracefully."""
        engine = ScoringEngine()
        res = engine.evaluate_target(base_target, tool_output=None, elapsed_time=1.5)
        assert res.status == "MISSED"
        assert res.is_true_positive is False
        assert res.time_to_crash_seconds == 1.5
        assert res.total_executions == 0
        assert res.throughput_execs_per_sec == 0.0
        assert res.poc_reduction_percentage == 0.0
        assert res.cwe_exact_match is False
        assert res.cwe_hierarchical_match is False
        assert res.cwe_match_score == 0.0
        assert res.ground_truth_cvss == 8.8
        assert res.predicted_cvss == 0.0
        assert res.cvss_delta == 8.8
        assert res.cvss_tolerance_passed is False
        assert res.predicted_severity == "NONE"
        assert res.severity_match is False
        assert res.error_message is None

    def test_evaluate_target_empty_dict_tool_output(self, base_target: TargetGroundTruth) -> None:
        """Verify evaluate_target handles empty dict tool_output as MISSED."""
        engine = ScoringEngine()
        res = engine.evaluate_target(base_target, tool_output={}, elapsed_time=2.0)
        assert res.status == "MISSED"
        assert res.is_true_positive is False
        assert res.throughput_execs_per_sec == 0.0

    def test_evaluate_target_is_error_flag(self, base_target: TargetGroundTruth) -> None:
        """Verify evaluate_target with is_error=True marks status as ERROR."""
        engine = ScoringEngine()
        res = engine.evaluate_target(
            base_target,
            tool_output={"cwe_id": "CWE-122"},
            elapsed_time=3.0,
            is_error=True,
            error_msg="Subprocess killed by SIGKILL",
        )
        assert res.status == "ERROR"
        assert res.is_true_positive is False
        assert res.error_message == "Subprocess killed by SIGKILL"
        assert res.predicted_cwe == "UNKNOWN"

    def test_aggregate_all_missed_zero_tpr(self, base_target: TargetGroundTruth) -> None:
        """Verify aggregation when all targets are missed (0 TP, no ZeroDivisionError)."""
        engine = ScoringEngine()
        results = [
            engine.evaluate_target(base_target, tool_output={}, elapsed_time=1.0),
            engine.evaluate_target(base_target, tool_output={}, elapsed_time=2.0),
        ]
        summary = engine.aggregate_scorecard(results, total_duration=3.0)
        assert summary.total_targets == 2
        assert summary.discovered_count == 0
        assert summary.missed_count == 2
        assert summary.error_count == 0
        assert summary.discovery_rate_tpr_pct == 0.0
        assert summary.mean_time_to_crash_seconds == 0.0
        assert summary.avg_poc_reduction_pct == 0.0
        assert summary.cwe_exact_match_rate_pct == 0.0
        assert summary.cwe_hierarchical_match_rate_pct == 0.0
        assert summary.cvss_mean_absolute_error == 0.0
        assert summary.cvss_tolerance_match_rate_pct == 0.0
        assert summary.severity_concordance_rate_pct == 0.0

    def test_aggregate_all_errors_and_timeouts(self, base_target: TargetGroundTruth) -> None:
        """Verify aggregation when all targets are ERROR or TIMEOUT."""
        engine = ScoringEngine()
        res_err = engine.evaluate_target(
            base_target, None, elapsed_time=1.0, is_error=True, error_msg="Crash"
        )
        res_timeout = TargetEvaluationResult(
            target_id="t_to",
            target_name="Timeout Target",
            vulnerability_class="heap_buffer_overflow",
            status="TIMEOUT",
            is_true_positive=False,
            time_to_crash_seconds=30.0,
            total_executions=0,
            throughput_execs_per_sec=0.0,
            original_poc_size_bytes=100,
            minimized_poc_size_bytes=100,
            poc_reduction_percentage=0.0,
            ground_truth_cwe="CWE-122",
            predicted_cwe="UNKNOWN",
            cwe_exact_match=False,
            cwe_hierarchical_match=False,
            cwe_match_score=0.0,
            ground_truth_cvss=8.8,
            predicted_cvss=0.0,
            cvss_delta=8.8,
            cvss_tolerance_passed=False,
            predicted_severity="NONE",
            ground_truth_severity="HIGH",
            severity_match=False,
            faulting_symbol="none",
            error_message="Execution timed out after 30s",
        )
        summary = engine.aggregate_scorecard([res_err, res_timeout], total_duration=31.0)
        assert summary.total_targets == 2
        assert summary.discovered_count == 0
        assert summary.error_count == 2
        assert summary.discovery_rate_tpr_pct == 0.0


# ============================================================================
# 2. Execution Times, Throughput & Extreme Values
# ============================================================================


class TestExecutionTimeAndThroughput:
    """Stress-test time boundaries, negative times, and throughput calculations."""

    @pytest.mark.parametrize(
        "elapsed,executions,expected_time,expected_throughput",
        [
            (
                0.0,
                1000,
                0.001,
                0.0,
            ),  # elapsed <= 0 -> throughput 0.0, safe_elapsed 0.001
            (-5.0, 500, 0.001, 0.0),  # negative elapsed -> throughput 0.0
            (-1e-6, 100, 0.001, 0.0),  # negative microsecond
            (0.0001, 1000, 0.001, 1000000.0),  # positive sub-millisecond
            (0.5, 1000, 0.5, 2000.0),  # standard fast run
            (2.0, 0, 2.0, 0.0),  # 0 executions -> throughput 0.0
            (
                1e9,
                1000,
                1e9,
                0.0,
            ),  # 1 billion seconds -> throughput round(1000/1e9, 1) = 0.0
            (0.001, 10**6, 0.001, 10**9),  # 1M execs in 1ms -> 1B exec/s
        ],
    )
    def test_elapsed_time_and_throughput_boundaries(
        self,
        base_target: TargetGroundTruth,
        elapsed: float,
        executions: int,
        expected_time: float,
        expected_throughput: float,
    ) -> None:
        """Verify throughput and time calculations across boundary values."""
        engine = ScoringEngine()
        tool_output = {
            "cwe_id": "CWE-122",
            "fuzzing_stats": {"executions": executions, "crashes_detected": 1},
        }
        res = engine.evaluate_target(base_target, tool_output, elapsed_time=elapsed)
        assert res.time_to_crash_seconds == expected_time
        assert res.throughput_execs_per_sec == expected_throughput

    def test_corrupted_fuzzing_stats_types(self, base_target: TargetGroundTruth) -> None:
        """Verify graceful handling when fuzzing_stats contains corrupted data types."""
        engine = ScoringEngine()
        bad_fuzz_stats = [
            "not_a_dict",
            None,
            12345,
            {"executions": "many", "crashes_detected": "yes"},
            {"executions": None, "crashes_detected": None},
            {"executions": -100, "crashes_detected": 1},
        ]
        for bad_stat in bad_fuzz_stats:
            tool_output = {
                "cwe_id": "CWE-122",
                "fuzzing_stats": bad_stat,
            }
            res = engine.evaluate_target(base_target, tool_output, elapsed_time=1.0)
            assert isinstance(res.total_executions, int)
            assert isinstance(res.throughput_execs_per_sec, float)
            assert not math.isnan(res.throughput_execs_per_sec)


# ============================================================================
# 3. PoC Byte Reduction Edge Cases
# ============================================================================


class TestPoCByteReduction:
    """Stress-test PoC minimization ratio calculation under adversarial conditions."""

    @pytest.mark.parametrize(
        "raw_size,min_size,expected_red_pct",
        [
            (100, 20, 80.0),  # Standard 80% reduction
            (100, 0, 100.0),  # 100% reduction to 0 bytes
            (100, 100, 0.0),  # 0% reduction (identical size)
            (100, 150, 0.0),  # Expansion (minimized > raw) -> 0.0%
            (100, -10, 100.0),  # Negative min size clamped to 0 -> 100.0%
            (0, 0, 0.0),  # 0 raw bytes -> 0.0% (no zero-division)
            (0, 50, 0.0),  # 0 raw bytes with positive min -> 0.0%
            (3, 1, 66.7),  # Rounding (2/3 * 100 = 66.666... -> 66.7)
            (7, 3, 57.1),  # Rounding (4/7 * 100 = 57.142... -> 57.1)
            (10**8, 10**6, 99.0),  # Large payload minimization
        ],
    )
    def test_poc_reduction_calculations(
        self,
        base_target: TargetGroundTruth,
        raw_size: int,
        min_size: int,
        expected_red_pct: float,
    ) -> None:
        """Verify PoC byte reduction percentages against all mathematical edge cases."""
        engine = ScoringEngine()
        target = base_target.model_copy(update={"raw_poc_size_bytes": raw_size})
        tool_output = {
            "cwe_id": "CWE-122",
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
            "minimized_input_size_bytes": min_size,
        }
        res = engine.evaluate_target(target, tool_output, elapsed_time=1.0)
        assert res.poc_reduction_percentage == expected_red_pct

    def test_poc_reduction_field_fallbacks_and_corrupt_types(
        self, base_target: TargetGroundTruth
    ) -> None:
        """Verify minimized_poc_size_bytes fallback and bad type resilience."""
        engine = ScoringEngine()

        # Fallback to 'minimized_poc_size_bytes' key
        tool_out_fallback = {
            "cwe_id": "CWE-122",
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
            "minimized_poc_size_bytes": 50,
        }
        res_fb = engine.evaluate_target(base_target, tool_out_fallback, elapsed_time=1.0)
        assert res_fb.minimized_poc_size_bytes == 50
        assert res_fb.poc_reduction_percentage == 50.0

        # Corrupted non-integer types
        for bad_min in ["fifty", None, [], {}, float("nan")]:
            tool_out_bad = {
                "cwe_id": "CWE-122",
                "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
                "minimized_input_size_bytes": bad_min,
            }
            res_bad = engine.evaluate_target(base_target, tool_out_bad, elapsed_time=1.0)
            assert res_bad.minimized_poc_size_bytes == base_target.raw_poc_size_bytes
            assert res_bad.poc_reduction_percentage == 0.0


# ============================================================================
# 4. CWE Hierarchical Taxonomic Matching
# ============================================================================


class TestCWETaxonomyScoring:
    """Stress-test CWE exact and hierarchical match logic across the taxonomy DAG."""

    @pytest.mark.parametrize(
        "gt_cwe,pred_cwe,expected_score,expected_exact,expected_hier",
        [
            # Exact Matches
            ("CWE-122", "CWE-122", 1.0, True, True),
            ("CWE-416", "cwe416", 1.0, True, True),
            ("CWE-190", "190", 1.0, True, True),
            ("CWE-787", "CWE_787", 1.0, True, True),
            # Direct Parent / Child (0.75)
            (
                "CWE-122",
                "CWE-787",
                0.75,
                False,
                True,
            ),  # Heap Overflow -> Out-of-bounds Write
            (
                "CWE-787",
                "CWE-122",
                0.75,
                False,
                True,
            ),  # Out-of-bounds Write -> Heap Overflow
            (
                "CWE-121",
                "CWE-787",
                0.75,
                False,
                True,
            ),  # Stack Overflow -> Out-of-bounds Write
            ("CWE-125", "CWE-119", 0.75, False, True),  # OOB Read -> Buffer Bounds
            ("CWE-126", "CWE-125", 0.75, False, True),  # Buffer Over-read -> OOB Read
            ("CWE-416", "CWE-672", 0.75, False, True),  # UAF -> Expired Resource
            (
                "CWE-415",
                "CWE-672",
                0.75,
                False,
                True,
            ),  # Double Free -> Expired Resource
            ("CWE-415", "CWE-761", 0.75, False, True),  # Double Free -> Free Non-Heap
            (
                "CWE-190",
                "CWE-682",
                0.75,
                False,
                True,
            ),  # Integer Overflow -> Calculation Error
            ("CWE-79", "CWE-707", 0.75, False, True),  # XSS -> Neutralization
            # Multi-Hop Ancestors (0.50)
            ("CWE-122", "CWE-119", 0.50, False, True),  # CWE-122 -> CWE-787 -> CWE-119
            (
                "CWE-122",
                "CWE-664",
                0.50,
                False,
                True,
            ),  # CWE-122 -> ... -> CWE-664 (Root)
            ("CWE-126", "CWE-119", 0.50, False, True),  # CWE-126 -> CWE-125 -> CWE-119
            ("CWE-126", "CWE-664", 0.50, False, True),  # CWE-126 -> ... -> CWE-664
            ("CWE-416", "CWE-664", 0.50, False, True),  # CWE-416 -> CWE-672 -> CWE-664
            # Siblings / Shared Ancestor (0.50)
            (
                "CWE-122",
                "CWE-121",
                0.50,
                False,
                True,
            ),  # Heap Overflow vs Stack Overflow
            (
                "CWE-122",
                "CWE-125",
                0.50,
                False,
                True,
            ),  # OOB Write vs OOB Read (via CWE-119)
            (
                "CWE-416",
                "CWE-415",
                0.50,
                False,
                True,
            ),  # UAF vs Double Free (via CWE-672)
            ("CWE-190", "CWE-191", 0.50, False, True),  # Int Overflow vs Int Underflow
            # Completely Unrelated Weaknesses (0.0)
            ("CWE-122", "CWE-79", 0.0, False, False),  # Memory corruption vs XSS
            ("CWE-416", "CWE-190", 0.0, False, False),  # UAF vs Integer Overflow
            ("CWE-476", "CWE-89", 0.0, False, False),  # NULL deref vs SQL Injection
            ("CWE-122", "CWE-9999", 0.0, False, False),  # Memory vs Non-existent CWE
            # Unknown / Malformed Inputs (0.0)
            ("CWE-122", "UNKNOWN", 0.0, False, False),
            ("CWE-122", "", 0.0, False, False),
            ("CWE-122", None, 0.0, False, False),
            ("CWE-122", "INVALID_CWE", 0.0, False, False),
        ],
    )
    def test_cwe_taxonomic_evaluation_cases(
        self,
        base_target: TargetGroundTruth,
        gt_cwe: str,
        pred_cwe: Any,
        expected_score: float,
        expected_exact: bool,
        expected_hier: bool,
    ) -> None:
        """Verify CWE exact and hierarchical matching across extensive pairwise combinations."""
        engine = ScoringEngine()
        target = base_target.model_copy(update={"cwe_id": gt_cwe})
        tool_output = {
            "cwe_id": pred_cwe,
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
        }
        res = engine.evaluate_target(target, tool_output, elapsed_time=1.0)
        assert res.cwe_match_score == expected_score
        assert res.cwe_exact_match is expected_exact
        assert res.cwe_hierarchical_match is expected_hier

    def test_cwe_extraction_from_triaged_crashes(self, base_target: TargetGroundTruth) -> None:
        """Verify CWE is extracted from triaged_crashes when top-level cwe_id is missing."""
        engine = ScoringEngine()
        tool_output = {
            "triaged_crashes": [{"cwe_id": "CWE-787"}],
            "fuzzing_stats": {"executions": 500, "crashes_detected": 1},
        }
        res = engine.evaluate_target(base_target, tool_output, elapsed_time=1.0)
        assert res.predicted_cwe == "CWE-787"
        assert res.cwe_exact_match is False
        assert res.cwe_hierarchical_match is True
        assert res.cwe_match_score == 0.75


# ============================================================================
# 5. CVSS Delta, Tolerance & MAE Calculations
# ============================================================================


class TestCVSSScoringAndTolerance:
    """Stress-test CVSS difference calculations, tolerance boundaries, and MAE."""

    @pytest.mark.parametrize(
        "gt_score,pred_score,tolerance,expected_delta,expected_passed",
        [
            (8.8, 8.8, 0.5, 0.0, True),  # Perfect match
            (8.8, 8.5, 0.5, 0.3, True),  # Within tolerance
            (8.8, 9.3, 0.5, 0.5, True),  # Exact upper boundary
            (8.8, 8.3, 0.5, 0.5, True),  # Exact lower boundary
            (8.8, 9.31, 0.5, 0.51, False),  # Outside upper boundary
            (8.8, 8.29, 0.5, 0.51, False),  # Outside lower boundary
            (10.0, 0.0, 0.5, 10.0, False),  # Maximum divergence
            (
                10.0,
                0.0,
                10.0,
                10.0,
                False,
            ),  # Pred 0.0 fails even with max tol if GT > 0
            (0.0, 0.0, 0.5, 0.0, True),  # GT 0.0 and Pred 0.0 passes
            (5.555, 5.551, 0.01, 0.0, True),  # Precision delta rounded to 2 decimals
            (7.5, 7.8, 0.2, 0.3, False),  # Stricter tolerance
            (7.5, 8.5, 1.0, 1.0, True),  # Wider tolerance
        ],
    )
    def test_cvss_delta_and_tolerance_boundaries(
        self,
        base_target: TargetGroundTruth,
        gt_score: float,
        pred_score: float,
        tolerance: float,
        expected_delta: float,
        expected_passed: bool,
    ) -> None:
        """Verify CVSS delta computation and tolerance checking."""
        engine = ScoringEngine(cvss_tolerance=tolerance)
        cvss_gt = base_target.cvss.model_copy(update={"expected_score": gt_score})
        target = base_target.model_copy(update={"cvss": cvss_gt})
        tool_output = {
            "cwe_id": "CWE-122",
            "cvss_v31_score": pred_score,
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
        }
        res = engine.evaluate_target(target, tool_output, elapsed_time=1.0)
        assert res.ground_truth_cvss == gt_score
        assert res.predicted_cvss == pred_score
        assert res.cvss_delta == expected_delta
        assert res.cvss_tolerance_passed is expected_passed

    def test_cvss_corrupted_inputs_and_fallbacks(self, base_target: TargetGroundTruth) -> None:
        """Verify CVSS evaluation handles corrupted strings, nested structures, and None."""
        engine = ScoringEngine()

        # Triaged crashes fallback
        tool_out_triaged = {
            "cwe_id": "CWE-122",
            "triaged_crashes": [{"cvss": {"cvss_v31_score": 8.8}}],
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
        }
        res_tri = engine.evaluate_target(base_target, tool_out_triaged, elapsed_time=1.0)
        assert res_tri.predicted_cvss == 8.8
        assert res_tri.cvss_delta == 0.0
        assert res_tri.cvss_tolerance_passed is True

        # Malformed non-numeric values
        for bad_val in ["critical", "N/A", None, [], {}]:
            tool_out_bad = {
                "cwe_id": "CWE-122",
                "cvss_v31_score": bad_val,
                "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
            }
            res_bad = engine.evaluate_target(base_target, tool_out_bad, elapsed_time=1.0)
            assert res_bad.predicted_cvss == 0.0
            assert res_bad.cvss_delta == 8.8
            assert res_bad.cvss_tolerance_passed is False

    def test_cvss_mae_aggregation_multiple_targets(self, base_target: TargetGroundTruth) -> None:
        """Verify Mean Absolute Error (MAE) and tolerance rate over multiple targets."""
        engine = ScoringEngine(cvss_tolerance=0.5)

        # 3 True Positives: delta 0.2, delta 0.4, delta 0.9 -> MAE = (0.2 + 0.4 + 0.9) / 3 = 0.5
        # Tolerance passes: delta 0.2 (yes), delta 0.4 (yes), delta 0.9 (no) -> 2/3 = 66.7%
        res1 = engine.evaluate_target(
            base_target,
            {
                "cwe_id": "CWE-122",
                "cvss_v31_score": 8.6,
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )
        res2 = engine.evaluate_target(
            base_target,
            {
                "cwe_id": "CWE-122",
                "cvss_v31_score": 9.2,
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )
        res3 = engine.evaluate_target(
            base_target,
            {
                "cwe_id": "CWE-122",
                "cvss_v31_score": 7.9,
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )

        summary = engine.aggregate_scorecard([res1, res2, res3], total_duration=3.0)
        assert summary.cvss_mean_absolute_error == 0.5
        assert summary.cvss_tolerance_match_rate_pct == 66.7


# ============================================================================
# 6. Severity Concordance
# ============================================================================


class TestSeverityConcordance:
    """Stress-test qualitative severity matching and concordance rate calculations."""

    @pytest.mark.parametrize(
        "gt_sev,pred_sev,expected_match",
        [
            ("HIGH", "HIGH", True),
            ("HIGH", "high", True),  # Case insensitive
            ("MEDIUM", "Medium", True),
            ("CRITICAL", "critical", True),
            ("LOW", "LOW", True),
            ("HIGH", "MEDIUM", False),  # Discordant
            ("CRITICAL", "LOW", False),  # Completely discordant
            ("HIGH", "UNKNOWN", False),
            ("HIGH", "NONE", False),
            ("HIGH", "", False),
            ("HIGH", None, False),
        ],
    )
    def test_severity_concordance_cases(
        self,
        base_target: TargetGroundTruth,
        gt_sev: str,
        pred_sev: Any,
        expected_match: bool,
    ) -> None:
        """Verify severity concordance across exact, casing, and discordant pairings."""
        engine = ScoringEngine()
        cvss_gt = base_target.cvss.model_copy(update={"severity": gt_sev})
        target = base_target.model_copy(update={"cvss": cvss_gt})
        tool_output = {
            "cwe_id": "CWE-122",
            "cvss_severity": pred_sev,
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
        }
        res = engine.evaluate_target(target, tool_output, elapsed_time=1.0)
        assert res.severity_match is expected_match

    def test_severity_extraction_from_nested_triaged_crashes(
        self, base_target: TargetGroundTruth
    ) -> None:
        """Verify severity extracted from triaged_crashes[0].cvss.severity."""
        engine = ScoringEngine()
        tool_output = {
            "cwe_id": "CWE-122",
            "triaged_crashes": [{"cvss": {"severity": "HIGH"}}],
            "fuzzing_stats": {"executions": 100, "crashes_detected": 1},
        }
        res = engine.evaluate_target(base_target, tool_output, elapsed_time=1.0)
        assert res.predicted_severity == "HIGH"
        assert res.severity_match is True


# ============================================================================
# 7. Vulnerability Class Stratification
# ============================================================================


class TestVulnerabilityClassStratification:
    """Stress-test vulnerability class breakdown aggregation across diverse class distributions."""

    def test_single_class_all_discovered(self, base_target: TargetGroundTruth) -> None:
        """Verify class breakdown when all targets belong to a single class and are discovered."""
        engine = ScoringEngine()
        results = [
            engine.evaluate_target(
                base_target,
                {
                    "cwe_id": "CWE-122",
                    "fuzzing_stats": {"executions": 1000, "crashes_detected": 1},
                    "minimized_input_size_bytes": 20,
                },
                elapsed_time=2.0,
            ),
            engine.evaluate_target(
                base_target,
                {
                    "cwe_id": "CWE-122",
                    "fuzzing_stats": {"executions": 2000, "crashes_detected": 1},
                    "minimized_input_size_bytes": 40,
                },
                elapsed_time=4.0,
            ),
        ]
        summary = engine.aggregate_scorecard(results, total_duration=6.0)
        assert len(summary.class_breakdown) == 1
        stats = summary.class_breakdown["heap_buffer_overflow"]
        assert stats["total"] == 2
        assert stats["discovered"] == 2
        assert stats["missed"] == 0
        assert stats["tpr_pct"] == 100.0
        assert stats["avg_ttc_s"] == 3.0  # (2.0 + 4.0) / 2
        assert stats["avg_reduction_pct"] == 70.0  # (80.0 + 60.0) / 2

    def test_mixed_classes_with_zero_and_partial_discoveries(
        self, base_target: TargetGroundTruth
    ) -> None:
        """Verify multiple vulnerability classes with mixed discovery rates."""
        engine = ScoringEngine()

        t_uaf = base_target.model_copy(
            update={"target_id": "t_uaf", "vulnerability_class": "use_after_free"}
        )
        t_oob = base_target.model_copy(
            update={"target_id": "t_oob", "vulnerability_class": "oob_read"}
        )
        t_int = base_target.model_copy(
            update={"target_id": "t_int", "vulnerability_class": "integer_overflow"}
        )

        # UAF: 1 TP, 1 Missed (50% TPR)
        r_uaf1 = engine.evaluate_target(
            t_uaf,
            {
                "cwe_id": "CWE-416",
                "fuzzing_stats": {"crashes_detected": 1},
                "minimized_input_size_bytes": 50,
            },
            elapsed_time=2.0,
        )
        r_uaf2 = engine.evaluate_target(t_uaf, tool_output={}, elapsed_time=5.0)

        # OOB: 2 TP (100% TPR)
        r_oob1 = engine.evaluate_target(
            t_oob,
            {
                "cwe_id": "CWE-125",
                "fuzzing_stats": {"crashes_detected": 1},
                "minimized_input_size_bytes": 10,
            },
            elapsed_time=1.0,
        )
        r_oob2 = engine.evaluate_target(
            t_oob,
            {
                "cwe_id": "CWE-125",
                "fuzzing_stats": {"crashes_detected": 1},
                "minimized_input_size_bytes": 30,
            },
            elapsed_time=3.0,
        )

        # Integer: 1 Error (0% TPR)
        r_int1 = engine.evaluate_target(t_int, None, is_error=True, elapsed_time=1.0)

        summary = engine.aggregate_scorecard(
            [r_uaf1, r_uaf2, r_oob1, r_oob2, r_int1], total_duration=12.0
        )

        assert summary.total_targets == 5
        assert summary.discovered_count == 3
        assert summary.discovery_rate_tpr_pct == 60.0  # 3 / 5 * 100

        breakdown = summary.class_breakdown
        assert len(breakdown) == 3

        # Check UAF stats: 1 TP (elapsed 2.0, red 50.0%)
        assert breakdown["use_after_free"]["total"] == 2
        assert breakdown["use_after_free"]["discovered"] == 1
        assert breakdown["use_after_free"]["missed"] == 1
        assert breakdown["use_after_free"]["tpr_pct"] == 50.0
        assert breakdown["use_after_free"]["avg_ttc_s"] == 2.0
        assert breakdown["use_after_free"]["avg_reduction_pct"] == 50.0

        # Check OOB stats: 2 TP (elapsed 1.0 & 3.0 -> avg 2.0, red 90.0% & 70.0% -> avg 80.0%)
        assert breakdown["oob_read"]["total"] == 2
        assert breakdown["oob_read"]["discovered"] == 2
        assert breakdown["oob_read"]["missed"] == 0
        assert breakdown["oob_read"]["tpr_pct"] == 100.0
        assert breakdown["oob_read"]["avg_ttc_s"] == 2.0
        assert breakdown["oob_read"]["avg_reduction_pct"] == 80.0

        # Check Integer stats: 0 TP
        assert breakdown["integer_overflow"]["total"] == 1
        assert breakdown["integer_overflow"]["discovered"] == 0
        assert breakdown["integer_overflow"]["missed"] == 1
        assert breakdown["integer_overflow"]["tpr_pct"] == 0.0
        assert breakdown["integer_overflow"]["avg_ttc_s"] == 0.0
        assert breakdown["integer_overflow"]["avg_reduction_pct"] == 0.0


# ============================================================================
# 8. High Volume Scale & Performance Stress
# ============================================================================


class TestHighVolumePerformanceStress:
    """Stress-test ScoringEngine at high volume (1,000+ target evaluations)."""

    def test_aggregate_1000_targets_performance_and_stability(
        self, base_target: TargetGroundTruth
    ) -> None:
        """Evaluate and aggregate 1,000 diverse targets without degradation or precision loss."""
        import time

        engine = ScoringEngine()
        results: list[TargetEvaluationResult] = []

        t0 = time.perf_counter()
        for i in range(1000):
            status_mod = i % 4
            vc = f"class_{i % 5}"
            target = base_target.model_copy(
                update={"target_id": f"t_{i}", "vulnerability_class": vc}
            )

            if status_mod == 0:
                # Discovered (Exact CWE)
                res = engine.evaluate_target(
                    target,
                    {
                        "cwe_id": "CWE-122",
                        "cvss_v31_score": 8.8,
                        "cvss_severity": "HIGH",
                        "fuzzing_stats": {
                            "executions": 1000 + i,
                            "crashes_detected": 1,
                        },
                        "minimized_input_size_bytes": 20,
                    },
                    elapsed_time=1.0 + (i % 10),
                )
            elif status_mod == 1:
                # Discovered (Hierarchical CWE)
                res = engine.evaluate_target(
                    target,
                    {
                        "cwe_id": "CWE-787",
                        "cvss_v31_score": 8.5,
                        "cvss_severity": "HIGH",
                        "fuzzing_stats": {"executions": 500, "crashes_detected": 1},
                        "minimized_input_size_bytes": 50,
                    },
                    elapsed_time=2.0,
                )
            elif status_mod == 2:
                # Missed
                res = engine.evaluate_target(target, tool_output={}, elapsed_time=5.0)
            else:
                # Error
                res = engine.evaluate_target(
                    target, None, is_error=True, error_msg="Crash", elapsed_time=1.0
                )

            results.append(res)

        eval_duration = time.perf_counter() - t0

        t1 = time.perf_counter()
        summary = engine.aggregate_scorecard(results, total_duration=100.0)
        agg_duration = time.perf_counter() - t1

        # Performance checks: 1,000 evaluations + aggregation under 250ms total
        assert eval_duration < 1.0, f"Target evaluations too slow: {eval_duration:.3f}s"
        assert agg_duration < 0.2, f"Scorecard aggregation too slow: {agg_duration:.3f}s"

        # Correctness checks
        assert summary.total_targets == 1000
        assert summary.discovered_count == 500  # status_mod 0 and 1
        assert summary.missed_count == 250  # status_mod 2
        assert summary.error_count == 250  # status_mod 3
        assert summary.discovery_rate_tpr_pct == 50.0
        assert len(summary.class_breakdown) == 5

        # All ratio metrics must be bounded within [0.0, 100.0]
        assert 0.0 <= summary.discovery_rate_tpr_pct <= 100.0
        assert 0.0 <= summary.cwe_exact_match_rate_pct <= 100.0
        assert 0.0 <= summary.cwe_hierarchical_match_rate_pct <= 100.0
        assert 0.0 <= summary.cvss_tolerance_match_rate_pct <= 100.0
        assert 0.0 <= summary.severity_concordance_rate_pct <= 100.0
        assert 0.0 <= summary.avg_poc_reduction_pct <= 100.0


# ============================================================================
# 9. Faulting Symbol Cascading Resolution
# ============================================================================


class TestFaultingSymbolResolution:
    """Stress-test cascading extraction priority of faulting_symbol."""

    def test_symbol_priority_cascade(self, base_target: TargetGroundTruth) -> None:
        """Verify priority order: target_function > faulting_symbol > triaged.faulting_function > ground_truth."""
        engine = ScoringEngine()

        # 1. target_function has highest priority
        out1 = {
            "cwe_id": "CWE-122",
            "target_function": "func_target",
            "faulting_symbol": "func_sym",
            "triaged_crashes": [{"faulting_function": "func_triaged"}],
        }
        res1 = engine.evaluate_target(base_target, out1, elapsed_time=1.0)
        assert res1.faulting_symbol == "func_target"

        # 2. faulting_symbol has second priority
        out2 = {
            "cwe_id": "CWE-122",
            "faulting_symbol": "func_sym",
            "triaged_crashes": [{"faulting_function": "func_triaged"}],
        }
        res2 = engine.evaluate_target(base_target, out2, elapsed_time=1.0)
        assert res2.faulting_symbol == "func_sym"

        # 3. triaged_crashes has third priority
        out3 = {
            "cwe_id": "CWE-122",
            "triaged_crashes": [{"faulting_function": "func_triaged"}],
        }
        res3 = engine.evaluate_target(base_target, out3, elapsed_time=1.0)
        assert res3.faulting_symbol == "func_triaged"

        # 4. Falls back to ground_truth.faulting_symbol
        out4 = {"cwe_id": "CWE-122"}
        res4 = engine.evaluate_target(base_target, out4, elapsed_time=1.0)
        assert res4.faulting_symbol == base_target.faulting_symbol
