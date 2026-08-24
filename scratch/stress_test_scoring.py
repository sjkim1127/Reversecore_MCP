#!/usr/bin/env python3
"""Comprehensive Adversarial & Boundary Stress Testing Harness for ScoringEngine.

Tests:
1. Empty result lists [], single target, 10,000 targets (performance & correctness).
2. 0-byte PoCs, expanded PoCs (minimized > raw), negative byte sizes, float/string sizes.
3. 0 elapsed time, negative elapsed time, huge elapsed time (1e6s), microsecond elapsed time.
4. CVSS extremes (-5.0, 0.0, 10.0, 15.0, None, NaN, Inf, non-numeric strings, tolerance limits).
5. Unknown / invalid CWE strings ("CWE-999999", "'; DROP TABLE", "", None, aliases, casing, numbers).
6. Mixed outcome batches (all TP, all Missed, all Error, all Timeout, complex multi-class mixtures).
7. Malformed tool_output dictionary schemas (missing keys, nested non-dicts, unexpected types).
8. Data models & JSON serialization roundtrip robustness.
"""

from __future__ import annotations

import sys
import time
from typing import Any

from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    CVSSGroundTruth,
    FixturePaths,
    TargetEvaluationResult,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.scoring import ScoringEngine


def create_base_ground_truth(
    target_id: str = "target_001",
    vuln_class: str = "heap_buffer_overflow",
    cwe_id: str = "CWE-122",
    cvss_score: float = 8.5,
    severity: str = "HIGH",
    raw_poc_size: int = 100,
) -> TargetGroundTruth:
    """Helper to instantiate a valid TargetGroundTruth."""
    return TargetGroundTruth(
        target_id=target_id,
        target_name=f"Target {target_id}",
        category="parsers",
        real_world_library="libstress",
        target_version="1.0",
        cve_reference="CVE-2026-9999",
        vulnerability_class=vuln_class,
        cwe_id=cwe_id,
        cwe_name="Test Weakness",
        faulting_symbol="stress_vuln_func",
        source_file="stress.c",
        source_line=42,
        expected_memory_access_type="WRITE_OOB",
        expected_access_size=4,
        cvss=CVSSGroundTruth(
            base_score_min=7.0,
            base_score_max=9.0,
            expected_score=cvss_score,
            severity=severity,  # type: ignore[arg-type]
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        fixtures=FixturePaths(
            vulnerable_source="vuln.c",
            patched_source="patch.c",
            patch_diff="p.diff",
            harness_c="h.c",
            asan_crash_log="a.log",
            valid_seed_corpus="s/",
            raw_crash_poc="r.bin",
            minimized_poc="m.bin",
        ),
        raw_poc_size_bytes=raw_poc_size,
        minimized_poc_target_bytes=20,
        expected_minimization_ratio_min=0.5,
    )


def run_all_stress_tests() -> dict[str, Any]:
    engine = ScoringEngine(cvss_tolerance=0.5)
    summary: dict[str, Any] = {
        "passed": 0,
        "failed": 0,
        "anomalies": [],
        "tests": [],
    }

    def record_pass(test_id: str, desc: str, detail: str = ""):
        summary["passed"] += 1
        summary["tests"].append({"id": test_id, "desc": desc, "status": "PASS", "detail": detail})
        print(f"[PASS] {test_id}: {desc} -> {detail}")

    def record_fail(test_id: str, desc: str, err: str):
        summary["failed"] += 1
        summary["tests"].append({"id": test_id, "desc": desc, "status": "FAIL", "error": err})
        print(f"[FAIL] {test_id}: {desc} -> {err}", file=sys.stderr)

    def record_anomaly(test_id: str, desc: str, detail: str):
        summary["anomalies"].append({"id": test_id, "desc": desc, "detail": detail})
        print(f"[ANOMALY] {test_id}: {desc} -> {detail}")

    # =========================================================================
    # DIMENSION 1: Result List Scales & Boundaries ([], Single, 10,000)
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 1: Result List Scales & Boundaries")
    print("=" * 70)

    # 1.1 Empty Result List
    try:
        sc_empty = engine.aggregate_scorecard([], total_duration=0.0)
        assert sc_empty.total_targets == 0
        assert sc_empty.discovered_count == 0
        assert sc_empty.missed_count == 0
        assert sc_empty.error_count == 0
        assert sc_empty.discovery_rate_tpr_pct == 0.0
        assert sc_empty.mean_time_to_crash_seconds == 0.0
        assert sc_empty.avg_throughput_exec_per_sec == 0.0
        assert sc_empty.avg_poc_reduction_pct == 0.0
        assert sc_empty.cwe_exact_match_rate_pct == 0.0
        assert sc_empty.cwe_hierarchical_match_rate_pct == 0.0
        assert sc_empty.cvss_mean_absolute_error == 0.0
        assert sc_empty.cvss_tolerance_match_rate_pct == 0.0
        assert sc_empty.severity_concordance_rate_pct == 0.0
        assert sc_empty.class_breakdown == {}
        assert sc_empty.target_results == []
        assert sc_empty.total_duration_seconds == 0.0
        record_pass(
            "D1.1",
            "Empty result list aggregation",
            "ZeroDivisionError fully guarded, clean default values",
        )
    except Exception as e:
        record_fail("D1.1", "Empty result list aggregation", str(e))

    # 1.2 Single Target Evaluation & Aggregation
    try:
        gt = create_base_ground_truth(target_id="single_01")
        tool_out = {
            "cwe_id": "CWE-122",
            "cvss_v31_score": 8.5,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 1500, "crashes_detected": 1},
            "minimized_input_size_bytes": 25,
            "target_function": "stress_vuln_func",
        }
        res_single = engine.evaluate_target(gt, tool_out, elapsed_time=1.5)
        assert res_single.is_true_positive is True
        assert res_single.status == "DISCOVERED"
        assert res_single.throughput_execs_per_sec == 1000.0  # 1500 / 1.5
        assert res_single.poc_reduction_percentage == 75.0  # (100 - 25)/100

        sc_single = engine.aggregate_scorecard([res_single], total_duration=1.5)
        assert sc_single.total_targets == 1
        assert sc_single.discovered_count == 1
        assert sc_single.discovery_rate_tpr_pct == 100.0
        assert sc_single.mean_time_to_crash_seconds == 1.5
        assert sc_single.avg_throughput_exec_per_sec == 1000.0
        assert sc_single.avg_poc_reduction_pct == 75.0
        assert sc_single.cwe_exact_match_rate_pct == 100.0
        assert sc_single.cvss_mean_absolute_error == 0.0
        assert sc_single.class_breakdown["heap_buffer_overflow"]["total"] == 1
        assert sc_single.class_breakdown["heap_buffer_overflow"]["tpr_pct"] == 100.0
        record_pass(
            "D1.2",
            "Single target evaluation and scorecard aggregation",
            "Perfect single target metric propagation",
        )
    except Exception as e:
        record_fail("D1.2", "Single target evaluation and aggregation", str(e))

    # 1.3 10,000 Targets Scale & Performance Stress Test
    try:
        t0 = time.perf_counter()
        classes = [
            "heap_overflow",
            "use_after_free",
            "double_free",
            "integer_overflow",
            "null_deref",
        ]
        large_suite: list[TargetEvaluationResult] = []

        for i in range(10000):
            vc = classes[i % len(classes)]
            is_tp = i % 4 != 0  # 75% TPR
            is_err = i % 20 == 0  # 5% Error
            status = "ERROR" if is_err else ("DISCOVERED" if is_tp else "MISSED")
            actual_tp = status == "DISCOVERED"

            res = TargetEvaluationResult(
                target_id=f"t_{i:05d}",
                target_name=f"Target {i}",
                vulnerability_class=vc,
                status=status,
                is_true_positive=actual_tp,
                time_to_crash_seconds=float((i % 30) + 0.5),
                total_executions=(i % 500) * 10,
                throughput_execs_per_sec=float((i % 200) * 5),
                original_poc_size_bytes=100,
                minimized_poc_size_bytes=30 if actual_tp else 100,
                poc_reduction_percentage=70.0 if actual_tp else 0.0,
                ground_truth_cwe="CWE-122",
                predicted_cwe="CWE-122" if actual_tp else "UNKNOWN",
                cwe_exact_match=actual_tp,
                cwe_hierarchical_match=actual_tp,
                cwe_match_score=1.0 if actual_tp else 0.0,
                ground_truth_cvss=8.5,
                predicted_cvss=8.5 if actual_tp else 0.0,
                cvss_delta=0.0 if actual_tp else 8.5,
                cvss_tolerance_passed=actual_tp,
                predicted_severity="HIGH" if actual_tp else "NONE",
                ground_truth_severity="HIGH",
                severity_match=actual_tp,
                faulting_symbol="func",
                error_message="timeout" if is_err else None,
                details={},
            )
            large_suite.append(res)

        sc_10k = engine.aggregate_scorecard(large_suite, total_duration=500.0)
        t1 = time.perf_counter()
        elapsed_sec = t1 - t0

        assert sc_10k.total_targets == 10000
        assert sc_10k.discovered_count == sum(1 for r in large_suite if r.is_true_positive)
        assert sc_10k.error_count == sum(1 for r in large_suite if r.status in ("ERROR", "TIMEOUT"))
        assert sc_10k.missed_count == sum(1 for r in large_suite if r.status == "MISSED")
        assert len(sc_10k.class_breakdown) == 5
        assert elapsed_sec < 0.5, f"10k aggregation took too long: {elapsed_sec:.4f}s"
        record_pass(
            "D1.3",
            "10,000 targets aggregation scale test",
            f"Aggregated 10,000 targets in {elapsed_sec:.4f}s (well below 0.5s requirement)",
        )
    except Exception as e:
        record_fail("D1.3", "10,000 targets scale test", str(e))

    # =========================================================================
    # DIMENSION 2: PoC Byte Size Edge Cases & Calculations
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 2: PoC Byte Size Edge Cases & Calculations")
    print("=" * 70)

    # 2.1 0-byte ground truth PoC (simulated via mock or duck-typing)
    try:

        class MockZeroPoCTarget:
            target_id = "zero_poc_target"
            target_name = "Zero PoC Target"
            vulnerability_class = "uncontrolled_recursion"
            cwe_id = "CWE-674"
            faulting_symbol = "recurse"
            cvss_v31_score = 7.5
            cvss_severity = "HIGH"
            raw_poc_size_bytes = 0

        res_zero = engine.evaluate_target(
            MockZeroPoCTarget(),  # type: ignore[arg-type]
            tool_output={
                "cwe_id": "CWE-674",
                "minimized_input_size_bytes": 0,
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )
        assert res_zero.original_poc_size_bytes == 0
        assert res_zero.minimized_poc_size_bytes == 0
        assert res_zero.poc_reduction_percentage == 0.0
        record_pass("D2.1", "0-byte raw PoC", "Handled with 0 division guard, reduction=0.0%")
    except Exception as e:
        record_fail("D2.1", "0-byte raw PoC", str(e))

    # 2.2 Expanded PoC (minimized > raw)
    try:
        gt = create_base_ground_truth(raw_poc_size=100)
        res_exp = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "minimized_input_size_bytes": 500,
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )
        assert res_exp.original_poc_size_bytes == 100
        assert res_exp.minimized_poc_size_bytes == 500
        assert res_exp.poc_reduction_percentage == 0.0
        record_pass("D2.2", "Expanded PoC (minimized > raw)", "Reduction clamped to 0.0%")
    except Exception as e:
        record_fail("D2.2", "Expanded PoC", str(e))

    # 2.3 Equal PoC size (minimized == raw)
    try:
        gt = create_base_ground_truth(raw_poc_size=100)
        res_eq = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "minimized_input_size_bytes": 100,
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )
        assert res_eq.poc_reduction_percentage == 0.0
        record_pass("D2.3", "Equal PoC size (minimized == raw)", "Reduction is 0.0%")
    except Exception as e:
        record_fail("D2.3", "Equal PoC size", str(e))

    # 2.4 Negative Minimized PoC size & String values
    try:
        gt = create_base_ground_truth(raw_poc_size=100)
        res_neg = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "minimized_input_size_bytes": -20,
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )
        # safe_min = max(0, -20) = 0 -> (100 - 0) / 100 = 100.0%
        assert res_neg.poc_reduction_percentage == 100.0
        assert res_neg.minimized_poc_size_bytes == -20

        res_str = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "minimized_input_size_bytes": "not_an_int",
                "fuzzing_stats": {"crashes_detected": 1},
            },
            elapsed_time=1.0,
        )
        assert res_str.minimized_poc_size_bytes == 100
        assert res_str.poc_reduction_percentage == 0.0
        record_pass(
            "D2.4", "Negative & invalid string minimized PoC size", "Handled safely without crash"
        )
    except Exception as e:
        record_fail("D2.4", "Negative & invalid string minimized PoC size", str(e))

    # =========================================================================
    # DIMENSION 3: Elapsed Time Edge Cases & Throughput
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 3: Elapsed Time Edge Cases & Throughput")
    print("=" * 70)

    # 3.1 Zero elapsed time
    try:
        gt = create_base_ground_truth()
        res_zero_t = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "fuzzing_stats": {"executions": 5000, "crashes_detected": 1},
            },
            elapsed_time=0.0,
        )
        assert res_zero_t.time_to_crash_seconds == 0.001
        assert res_zero_t.throughput_execs_per_sec == 0.0
        record_pass(
            "D3.1",
            "0.0 elapsed time",
            "Safe elapsed=0.001s, throughput=0.0 (guarded against 0 elapsed)",
        )
    except Exception as e:
        record_fail("D3.1", "0.0 elapsed time", str(e))

    # 3.2 Negative elapsed time
    try:
        res_neg_t = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "fuzzing_stats": {"executions": 5000, "crashes_detected": 1},
            },
            elapsed_time=-100.0,
        )
        assert res_neg_t.time_to_crash_seconds == 0.001
        assert res_neg_t.throughput_execs_per_sec == 0.0
        record_pass("D3.2", "Negative elapsed time (-100.0s)", "Clamped to 0.001s, throughput=0.0")
    except Exception as e:
        record_fail("D3.2", "Negative elapsed time", str(e))

    # 3.3 Microsecond elapsed time (0.0001s)
    try:
        res_micro = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "fuzzing_stats": {"executions": 10, "crashes_detected": 1},
            },
            elapsed_time=0.0001,
        )
        assert res_micro.time_to_crash_seconds == 0.001
        assert res_micro.throughput_execs_per_sec == 10000.0  # 10 / 0.001
        record_pass(
            "D3.3", "Microsecond elapsed time (0.0001s)", "Handled with rounding precision 0.001s"
        )
    except Exception as e:
        record_fail("D3.3", "Microsecond elapsed time", str(e))

    # 3.4 Huge elapsed time (1e6s)
    try:
        res_huge = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "fuzzing_stats": {"executions": 1000, "crashes_detected": 1},
            },
            elapsed_time=1_000_000.0,
        )
        assert res_huge.time_to_crash_seconds == 1_000_000.0
        assert res_huge.throughput_execs_per_sec == 0.0
        record_pass(
            "D3.4", "Huge elapsed time (1,000,000s)", "Time preserved, throughput rounded to 0.0"
        )
    except Exception as e:
        record_fail("D3.4", "Huge elapsed time", str(e))

    # =========================================================================
    # DIMENSION 4: CVSS Extremes & Invalid Inputs
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 4: CVSS Extremes & Invalid Inputs")
    print("=" * 70)

    cvss_test_matrix = [
        ("Negative CVSS (-5.0)", -5.0, 8.5, 13.5, False),
        ("Zero CVSS (0.0)", 0.0, 8.5, 8.5, False),
        ("Exact CVSS (8.5)", 8.5, 8.5, 0.0, True),
        ("CVSS within upper tolerance (8.9 vs 8.5, tol=0.5)", 8.9, 8.5, 0.4, True),
        ("CVSS beyond upper tolerance (9.1 vs 8.5, tol=0.5)", 9.1, 8.5, 0.6, False),
        ("CVSS within lower tolerance (8.1 vs 8.5, tol=0.5)", 8.1, 8.5, 0.4, True),
        ("CVSS beyond lower tolerance (7.9 vs 8.5, tol=0.5)", 7.9, 8.5, 0.6, False),
        ("CVSS 10.0 (Max standard)", 10.0, 8.5, 1.5, False),
        ("CVSS 15.0 (Out of range)", 15.0, 8.5, 6.5, False),
        ("CVSS None", None, 8.5, 8.5, False),
        ("CVSS non-numeric string ('invalid')", "invalid", 8.5, 8.5, False),
        ("CVSS numeric string ('8.8')", "8.8", 8.5, 0.3, True),
        ("CVSS NaN", float("nan"), 8.5, None, False),
        ("CVSS Inf", float("inf"), 8.5, None, False),
        ("Ground truth CVSS 0.0 vs Predicted 0.0", 0.0, 0.0, 0.0, True),
    ]

    for label, pred_v, gt_v, exp_delta, exp_pass in cvss_test_matrix:
        try:
            gt_inst = create_base_ground_truth(cvss_score=gt_v)
            res = engine.evaluate_target(
                gt_inst,
                tool_output={
                    "cwe_id": "CWE-122",
                    "cvss_v31_score": pred_v,
                    "fuzzing_stats": {"crashes_detected": 1},
                },
                elapsed_time=1.0,
            )
            if exp_delta is not None:
                assert res.cvss_delta == exp_delta, (
                    f"Expected delta={exp_delta}, got {res.cvss_delta}"
                )
            assert res.cvss_tolerance_passed == exp_pass, (
                f"Expected passed={exp_pass}, got {res.cvss_tolerance_passed}"
            )
            record_pass(
                f"D4: {label}",
                "CVSS evaluated correctly",
                f"pred={pred_v}, delta={res.cvss_delta}, passed={res.cvss_tolerance_passed}",
            )
        except Exception as e:
            record_fail(f"D4: {label}", "CVSS evaluation", str(e))

    # =========================================================================
    # DIMENSION 5: Unknown / Invalid CWE Strings & Taxonomy Stress
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 5: CWE Strings & Taxonomy Hierarchy")
    print("=" * 70)

    cwe_test_matrix = [
        # (pred_cwe, gt_cwe, expected_score, expected_hierarchical, expected_normalized)
        ("CWE-999999 (Non-existent CWE)", "CWE-999999", "CWE-122", 0.0, False, "CWE-999999"),
        (
            "SQL Injection string in CWE",
            "'; DROP TABLE users; --",
            "CWE-122",
            0.0,
            False,
            "'; DROP TABLE USERS; --",
        ),
        ("Empty string CWE", "", "CWE-122", 0.0, False, "UNKNOWN"),
        ("None CWE", None, "CWE-122", 0.0, False, "UNKNOWN"),
        ("Whitespace CWE ('   cwe_122   ')", "   cwe_122   ", "CWE-122", 1.0, True, "CWE-122"),
        ("Raw number CWE ('122')", "122", "CWE-122", 1.0, True, "CWE-122"),
        ("Compact CWE ('cwe122')", "cwe122", "CWE-122", 1.0, True, "CWE-122"),
        (
            "Direct Parent CWE (CWE-787 is parent of CWE-122)",
            "CWE-787",
            "CWE-122",
            0.75,
            True,
            "CWE-787",
        ),
        (
            "Ancestor CWE (CWE-119 is ancestor of CWE-122)",
            "CWE-119",
            "CWE-122",
            0.50,
            True,
            "CWE-119",
        ),
        (
            "Shared Root Ancestor (CWE-416 and CWE-122 share CWE-664)",
            "CWE-416",
            "CWE-122",
            0.50,
            True,
            "CWE-416",
        ),
        (
            "Completely Unrelated (CWE-89 SQLi vs CWE-122 Heap OOB)",
            "CWE-89",
            "CWE-122",
            0.0,
            False,
            "CWE-89",
        ),
        ("Unrelated (CWE-79 XSS vs CWE-416 UAF)", "CWE-79", "CWE-416", 0.0, False, "CWE-79"),
    ]

    for label, pred_cwe, gt_cwe, exp_score, exp_hier, exp_norm in cwe_test_matrix:
        try:
            gt_inst = create_base_ground_truth(cwe_id=gt_cwe)
            res = engine.evaluate_target(
                gt_inst,
                tool_output={"cwe_id": pred_cwe, "fuzzing_stats": {"crashes_detected": 1}},
                elapsed_time=1.0,
            )
            assert res.predicted_cwe == exp_norm, (
                f"Expected norm={exp_norm}, got {res.predicted_cwe}"
            )
            assert res.cwe_match_score == exp_score, (
                f"Expected score={exp_score}, got {res.cwe_match_score}"
            )
            assert res.cwe_hierarchical_match == exp_hier, (
                f"Expected hier={exp_hier}, got {res.cwe_hierarchical_match}"
            )
            record_pass(
                f"D5: {label}",
                "CWE taxonomy evaluated correctly",
                f"norm={res.predicted_cwe}, score={res.cwe_match_score}, hier={res.cwe_hierarchical_match}",
            )
        except Exception as e:
            record_fail(f"D5: {label}", "CWE taxonomy evaluation", str(e))

    # =========================================================================
    # DIMENSION 6: Mixed Outcome Batches & Vulnerability Class Stratification
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 6: Mixed Outcome Batches & Stratification")
    print("=" * 70)

    gt_base = create_base_ground_truth()

    # 6.1 All True Positive Batch
    try:
        all_tp = [
            engine.evaluate_target(
                gt_base,
                tool_output={
                    "cwe_id": "CWE-122",
                    "cvss_v31_score": 8.5,
                    "cvss_severity": "HIGH",
                    "fuzzing_stats": {"executions": 200, "crashes_detected": 1},
                },
                elapsed_time=2.0,
            )
            for _ in range(50)
        ]
        sc_all_tp = engine.aggregate_scorecard(all_tp, total_duration=100.0)
        assert sc_all_tp.total_targets == 50
        assert sc_all_tp.discovered_count == 50
        assert sc_all_tp.missed_count == 0
        assert sc_all_tp.error_count == 0
        assert sc_all_tp.discovery_rate_tpr_pct == 100.0
        assert sc_all_tp.mean_time_to_crash_seconds == 2.0
        assert sc_all_tp.avg_throughput_exec_per_sec == 100.0
        record_pass(
            "D6.1", "All True Positive batch (50/50)", "TPR=100%, discovered=50, missed=0, error=0"
        )
    except Exception as e:
        record_fail("D6.1", "All True Positive batch", str(e))

    # 6.2 All Missed Batch
    try:
        all_missed = [
            engine.evaluate_target(
                gt_base,
                tool_output={"fuzzing_stats": {"executions": 500, "crashes_detected": 0}},
                elapsed_time=5.0,
            )
            for _ in range(50)
        ]
        sc_all_missed = engine.aggregate_scorecard(all_missed, total_duration=250.0)
        assert sc_all_missed.total_targets == 50
        assert sc_all_missed.discovered_count == 0
        assert sc_all_missed.missed_count == 50
        assert sc_all_missed.error_count == 0
        assert sc_all_missed.discovery_rate_tpr_pct == 0.0
        assert sc_all_missed.mean_time_to_crash_seconds == 0.0  # guarded for 0 TPs
        assert sc_all_missed.avg_poc_reduction_pct == 0.0
        assert sc_all_missed.avg_throughput_exec_per_sec == 100.0  # 500/5.0
        record_pass(
            "D6.2",
            "All Missed batch (50/50)",
            "TPR=0%, discovered=0, missed=50, throughput preserved",
        )
    except Exception as e:
        record_fail("D6.2", "All Missed batch", str(e))

    # 6.3 All Error Batch
    try:
        all_error = [
            engine.evaluate_target(
                gt_base,
                tool_output=None,
                elapsed_time=0.5,
                is_error=True,
                error_msg="Compilation timeout: clang exceeded 120s",
            )
            for _ in range(50)
        ]
        sc_all_error = engine.aggregate_scorecard(all_error, total_duration=25.0)
        assert sc_all_error.total_targets == 50
        assert sc_all_error.discovered_count == 0
        assert sc_all_error.missed_count == 0
        assert sc_all_error.error_count == 50
        assert sc_all_error.discovery_rate_tpr_pct == 0.0
        assert sc_all_error.mean_time_to_crash_seconds == 0.0
        assert sc_all_error.avg_throughput_exec_per_sec == 0.0
        record_pass("D6.3", "All Error batch (50/50)", "TPR=0%, error=50, missed=0, discovered=0")
    except Exception as e:
        record_fail("D6.3", "All Error batch", str(e))

    # 6.4 Complex Multi-Class Mixed Outcomes (TP, Missed, Error, Timeout)
    try:
        vuln_classes = [
            "heap_buffer_overflow",
            "use_after_free",
            "integer_overflow",
            "null_pointer_dereference",
            "double_free",
            "format_string",
        ]
        mixed_results: list[TargetEvaluationResult] = []

        # 240 targets: 40 per class
        for i in range(240):
            vc = vuln_classes[i % len(vuln_classes)]
            gt_i = create_base_ground_truth(target_id=f"mix_{i:03d}", vuln_class=vc)
            mode = i % 4
            if mode == 0:
                # Discovered (TP)
                r = engine.evaluate_target(
                    gt_i,
                    tool_output={
                        "cwe_id": "CWE-122",
                        "cvss_v31_score": 8.5,
                        "cvss_severity": "HIGH",
                        "fuzzing_stats": {"executions": 1000, "crashes_detected": 1},
                        "minimized_input_size_bytes": 20,
                    },
                    elapsed_time=2.0,
                )
            elif mode == 1:
                # Missed (Clean execution, no crashes)
                r = engine.evaluate_target(
                    gt_i,
                    tool_output={"fuzzing_stats": {"executions": 2000, "crashes_detected": 0}},
                    elapsed_time=4.0,
                )
            elif mode == 2:
                # Error
                r = engine.evaluate_target(
                    gt_i,
                    tool_output=None,
                    elapsed_time=1.0,
                    is_error=True,
                    error_msg="LLVM sanitizer crash in harness",
                )
            else:
                # Empty output -> Missed
                r = engine.evaluate_target(gt_i, {}, elapsed_time=3.0)

            mixed_results.append(r)

        sc_mix = engine.aggregate_scorecard(mixed_results, total_duration=600.0)
        assert sc_mix.total_targets == 240
        assert sc_mix.discovered_count == 60  # 240 / 4
        assert sc_mix.error_count == 60  # 240 / 4
        assert sc_mix.missed_count == 120  # mode 1 (60) + mode 3 (60)
        assert sc_mix.discovery_rate_tpr_pct == 25.0  # 60 / 240
        assert len(sc_mix.class_breakdown) == 6

        for vc in vuln_classes:
            st = sc_mix.class_breakdown[vc]
            assert st["total"] == 40
            assert st["discovered"] == 10
            assert st["missed"] == 20
            assert st["tpr_pct"] == 25.0
            assert st["avg_ttc_s"] == 2.0
            assert st["avg_reduction_pct"] == 80.0

        record_pass(
            "D6.4",
            "Complex Multi-Class Mixed Outcomes (240 targets, 6 classes)",
            "Precise class stratification arithmetic verified",
        )
    except Exception as e:
        record_fail("D6.4", "Complex Multi-Class Mixed Outcomes", str(e))

    # =========================================================================
    # DIMENSION 7: Pathological & Malformed Tool Outputs
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 7: Pathological & Malformed Tool Outputs")
    print("=" * 70)

    gt_std = create_base_ground_truth()

    pathological_cases = [
        ("None tool_output", None),
        ("Empty dict tool_output", {}),
        ("fuzzing_stats is None", {"fuzzing_stats": None}),
        ("fuzzing_stats is a string", {"fuzzing_stats": "non_dict_string"}),
        (
            "fuzzing_stats executions is invalid string",
            {"fuzzing_stats": {"executions": "invalid_num"}},
        ),
        ("fuzzing_stats executions is negative", {"fuzzing_stats": {"executions": -500}}),
        ("triaged_crashes is string", {"triaged_crashes": "invalid_triaged"}),
        ("triaged_crashes is empty list", {"triaged_crashes": []}),
        ("triaged_crashes contains non-dict items", {"triaged_crashes": [123, "abc", None]}),
        ("triaged_crashes cvss is non-dict", {"triaged_crashes": [{"cvss": "bad_cvss"}]}),
        (
            "triaged_crashes cvss score is invalid string",
            {"triaged_crashes": [{"cvss": {"cvss_v31_score": "bad_float"}}]},
        ),
        ("minimized_input_size_bytes is object", {"minimized_input_size_bytes": object()}),
        ("Deep nested unexpected metadata", {"unknown_key": {"sub": [1, 2, 3]}}),
    ]

    for label, bad_out in pathological_cases:
        try:
            res = engine.evaluate_target(gt_std, bad_out, elapsed_time=1.0)  # type: ignore[arg-type]
            assert isinstance(res, TargetEvaluationResult)
            record_pass(
                f"D7: {label}",
                "Handled safely without crash",
                f"status={res.status}, is_tp={res.is_true_positive}",
            )
        except Exception as e:
            record_fail(f"D7: {label}", "Failed to handle safely", str(e))

    # Test potential bug: fuzzing_stats.crashes_detected with non-int string or None
    print("\n--- Testing Specific Vulnerability in crashes_detected parsing ---")
    crashes_detected_cases = [
        ("crashes_detected is string '5'", {"fuzzing_stats": {"crashes_detected": "5"}}, True),
        (
            "crashes_detected is string 'invalid_str'",
            {"fuzzing_stats": {"crashes_detected": "invalid_str"}},
            False,
        ),
        ("crashes_detected is None", {"fuzzing_stats": {"crashes_detected": None}}, False),
        ("crashes_detected is float 2.5", {"fuzzing_stats": {"crashes_detected": 2.5}}, True),
    ]

    for lbl, payload, _should_survive_without_bug in crashes_detected_cases:
        try:
            res = engine.evaluate_target(gt_std, payload, elapsed_time=1.0)
            record_pass(
                f"D7-CrashDet: {lbl}", "Evaluated without exception", f"status={res.status}"
            )
        except (ValueError, TypeError) as e:
            record_anomaly(
                f"D7-CrashDet: {lbl}",
                "Unhandled ValueError/TypeError in crashes_detected",
                f"Exception: {type(e).__name__}: {e}",
            )

    # =========================================================================
    # DIMENSION 8: Data Models & Serialization Roundtrips
    # =========================================================================
    print("\n" + "=" * 70)
    print("DIMENSION 8: Data Models & Serialization Roundtrips")
    print("=" * 70)

    try:
        gt = create_base_ground_truth()
        res = engine.evaluate_target(
            gt,
            tool_output={
                "cwe_id": "CWE-122",
                "cvss_v31_score": 8.5,
                "cvss_severity": "HIGH",
                "fuzzing_stats": {"executions": 2500, "crashes_detected": 1},
                "minimized_input_size_bytes": 10,
            },
            elapsed_time=2.5,
        )

        # TargetEvaluationResult JSON roundtrip
        res_json = res.to_json(indent=2)
        res_recovered = TargetEvaluationResult.from_json(res_json)
        assert res_recovered.target_id == res.target_id
        assert res_recovered.status == res.status
        assert res_recovered.is_true_positive == res.is_true_positive
        assert res_recovered.throughput_execs_per_sec == res.throughput_execs_per_sec
        assert res_recovered.poc_reduction_percentage == res.poc_reduction_percentage

        # BenchmarkScorecardSummary JSON roundtrip
        sc = engine.aggregate_scorecard([res], total_duration=2.5)
        sc_json = sc.to_json(indent=2)
        sc_recovered = BenchmarkScorecardSummary.from_json(sc_json)
        assert sc_recovered.total_targets == sc.total_targets
        assert sc_recovered.discovered_count == sc.discovered_count
        assert sc_recovered.discovery_rate_tpr_pct == sc.discovery_rate_tpr_pct
        assert len(sc_recovered.target_results) == 1
        assert sc_recovered.target_results[0].target_id == res.target_id

        # TargetGroundTruth JSON roundtrip
        gt_json = gt.to_json(indent=2)
        gt_recovered = TargetGroundTruth.from_json(gt_json)
        assert gt_recovered.target_id == gt.target_id
        assert gt_recovered.cwe_id == gt.cwe_id
        assert gt_recovered.cvss.expected_score == gt.cvss.expected_score

        record_pass(
            "D8.1",
            "Pydantic & Dataclass JSON Serialization Roundtrips",
            "TargetGroundTruth, TargetEvaluationResult, and BenchmarkScorecardSummary roundtrips verified",
        )
    except Exception as e:
        record_fail("D8.1", "Serialization Roundtrips", str(e))

    # Summary
    print("\n" + "=" * 70)
    print(
        f"STRESS TEST SUITE COMPLETE: {summary['passed']} PASSED, {summary['failed']} FAILED, {len(summary['anomalies'])} ANOMALIES"
    )
    print("=" * 70)

    return summary


if __name__ == "__main__":
    res = run_all_stress_tests()
    if res["failed"] > 0:
        sys.exit(1)
    sys.exit(0)
