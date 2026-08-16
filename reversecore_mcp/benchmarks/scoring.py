"""Scoring Engine for CVE Benchmark Evaluation.

Provides mathematical scoring, precision metrics, True Positive Rate (TPR),
Time-to-Crash (TTC), Fuzzing Throughput (Exec/s), PoC Minimization % Reduction,
CWE Exact and Hierarchical Taxonomic Matches, CVSS v3.1 Delta / MAE / Tolerance
Match, Qualitative Severity Concordance, and Vulnerability Class Stratification
with strict zero-division safeguards.
"""

from __future__ import annotations

from typing import Any

from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    TargetEvaluationResult,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.taxonomy import (
    calculate_cwe_taxonomic_score,
    normalize_cwe_id,
)


class ScoringEngine:
    """Mathematical scoring and evaluation engine for benchmark targets and test suites.

    Computes discovery rates, execution efficiencies, payload minimization rates,
    and ground-truth concordance scores.
    """

    def __init__(self, cvss_tolerance: float = 0.5) -> None:
        """Initialize scoring engine with configurable CVSS score tolerance.

        Args:
            cvss_tolerance: Maximum allowable absolute difference between predicted
                           and ground truth CVSS base score for a tolerance pass.
                           Defaults to 0.5.
        """
        self.cvss_tolerance = float(cvss_tolerance)

    def evaluate_target(
        self,
        ground_truth: TargetGroundTruth,
        tool_output: dict[str, Any] | None = None,
        elapsed_time: float = 0.0,
        is_error: bool = False,
        error_msg: str | None = None,
        options: Any = None,
    ) -> TargetEvaluationResult:
        """Evaluate an individual target tool execution against ground-truth metadata.

        Args:
            ground_truth: Ground-truth target definition and expected ratings.
            tool_output: Raw or structured output dictionary from CVE discovery tools.
            elapsed_time: Execution duration in seconds.
            is_error: Whether the tool execution resulted in an unhandled exception or timeout.
            error_msg: Optional error or diagnostic message.
            options: Optional execution options.

        Returns:
            TargetEvaluationResult containing all evaluated metrics.
        """
        safe_elapsed = round(max(0.001, float(elapsed_time)), 3)
        gt_cwe = normalize_cwe_id(ground_truth.cwe_id)
        gt_cvss = float(
            ground_truth.cvss.expected_score
            if hasattr(ground_truth, "cvss") and hasattr(ground_truth.cvss, "expected_score")
            else getattr(ground_truth, "cvss_v31_score", 0.0)
        )
        gt_severity = str(
            ground_truth.cvss.severity
            if hasattr(ground_truth, "cvss") and hasattr(ground_truth.cvss, "severity")
            else getattr(ground_truth, "cvss_severity", "UNKNOWN")
        ).upper()
        raw_poc_size = max(0, int(getattr(ground_truth, "raw_poc_size_bytes", 0)))

        # Error or empty tool output handling
        if is_error or not tool_output:
            status = "ERROR" if is_error else "MISSED"

            return TargetEvaluationResult(
                target_id=ground_truth.target_id,
                target_name=ground_truth.target_name,
                vulnerability_class=ground_truth.vulnerability_class,
                status=status,
                is_true_positive=False,
                time_to_crash_seconds=safe_elapsed,
                total_executions=0,
                throughput_execs_per_sec=0.0,
                original_poc_size_bytes=raw_poc_size,
                minimized_poc_size_bytes=raw_poc_size,
                poc_reduction_percentage=0.0,
                ground_truth_cwe=gt_cwe,
                predicted_cwe="UNKNOWN",
                cwe_exact_match=False,
                cwe_hierarchical_match=False,
                cwe_match_score=0.0,
                ground_truth_cvss=gt_cvss,
                predicted_cvss=0.0,
                cvss_delta=gt_cvss,
                cvss_tolerance_passed=False,
                predicted_severity="NONE",
                ground_truth_severity=gt_severity,
                severity_match=False,
                faulting_symbol=str(ground_truth.faulting_symbol or "none"),
                error_message=error_msg,
                details=tool_output or {},
            )

        # Extract crash triage details
        triaged_list = tool_output.get("triaged_crashes", [])
        triaged: dict[str, Any] = (
            triaged_list[0]
            if isinstance(triaged_list, list)
            and len(triaged_list) > 0
            and isinstance(triaged_list[0], dict)
            else {}
        )

        fuzz_stats = tool_output.get("fuzzing_stats", {})
        if isinstance(fuzz_stats, dict):
            try:
                crashes_detected = int(fuzz_stats.get("crashes_detected", 0) or 0)
            except (ValueError, TypeError):
                crashes_detected = 0
        else:
            crashes_detected = 0

        # True positive evaluation
        is_tp = bool(crashes_detected > 0 or tool_output.get("cwe_id") or triaged.get("cwe_id"))

        # CWE Taxonomy evaluation
        raw_pred_cwe = tool_output.get("cwe_id") or triaged.get("cwe_id")
        pred_cwe = normalize_cwe_id(raw_pred_cwe) if raw_pred_cwe else "UNKNOWN"
        cwe_score, is_hierarchical = calculate_cwe_taxonomic_score(pred_cwe, gt_cwe)
        is_exact = bool(pred_cwe == gt_cwe and pred_cwe not in ("", "UNKNOWN"))

        # CVSS scoring evaluation
        raw_pred_cvss = tool_output.get("cvss_v31_score")
        if raw_pred_cvss is None and isinstance(triaged.get("cvss"), dict):
            raw_pred_cvss = triaged["cvss"].get("cvss_v31_score")
        try:
            pred_cvss = float(raw_pred_cvss) if raw_pred_cvss is not None else 0.0
        except (ValueError, TypeError):
            pred_cvss = 0.0

        cvss_delta = round(abs(pred_cvss - gt_cvss), 2)
        cvss_passed = bool(
            cvss_delta <= self.cvss_tolerance and (pred_cvss > 0.0 or gt_cvss == 0.0)
        )

        # Severity qualitative concordance
        raw_pred_sev = tool_output.get("cvss_severity")
        if not raw_pred_sev and isinstance(triaged.get("cvss"), dict):
            raw_pred_sev = triaged["cvss"].get("severity")
        pred_sev = str(raw_pred_sev).upper() if raw_pred_sev else "UNKNOWN"
        sev_match = bool(pred_sev == gt_severity and pred_sev not in ("UNKNOWN", "NONE", ""))

        # PoC Minimization byte reduction %
        min_poc_size = raw_poc_size
        raw_min = tool_output.get(
            "minimized_input_size_bytes",
            tool_output.get("minimized_poc_size_bytes"),
        )
        if raw_min is not None:
            try:
                min_poc_size = int(raw_min)
            except (ValueError, TypeError):
                min_poc_size = raw_poc_size

        if raw_poc_size > 0 and min_poc_size < raw_poc_size:
            safe_min = max(0, min_poc_size)
            poc_red_pct = round(((raw_poc_size - safe_min) / raw_poc_size) * 100.0, 1)
        else:
            poc_red_pct = 0.0

        # Throughput computation
        total_execs = 0
        if isinstance(fuzz_stats, dict):
            try:
                total_execs = int(fuzz_stats.get("executions", 0))
            except (ValueError, TypeError):
                total_execs = 0

        throughput = (
            round(total_execs / max(0.001, safe_elapsed), 1)
            if float(elapsed_time) > 0 and total_execs > 0
            else 0.0
        )

        faulting_sym = (
            tool_output.get("target_function")
            or tool_output.get("faulting_symbol")
            or triaged.get("faulting_function")
            or ground_truth.faulting_symbol
            or "none"
        )

        return TargetEvaluationResult(
            target_id=ground_truth.target_id,
            target_name=ground_truth.target_name,
            vulnerability_class=ground_truth.vulnerability_class,
            status="DISCOVERED" if is_tp else "MISSED",
            is_true_positive=is_tp,
            time_to_crash_seconds=safe_elapsed,
            total_executions=total_execs,
            throughput_execs_per_sec=throughput,
            original_poc_size_bytes=raw_poc_size,
            minimized_poc_size_bytes=min_poc_size,
            poc_reduction_percentage=poc_red_pct,
            ground_truth_cwe=gt_cwe,
            predicted_cwe=pred_cwe,
            cwe_exact_match=is_exact,
            cwe_hierarchical_match=is_hierarchical,
            cwe_match_score=cwe_score,
            ground_truth_cvss=gt_cvss,
            predicted_cvss=pred_cvss,
            cvss_delta=cvss_delta,
            cvss_tolerance_passed=cvss_passed,
            predicted_severity=pred_sev,
            ground_truth_severity=gt_severity,
            severity_match=sev_match,
            faulting_symbol=str(faulting_sym),
            error_message=error_msg,
            details=tool_output,
        )

    def aggregate_scorecard(
        self,
        results: list[TargetEvaluationResult],
        total_duration: float = 0.0,
        options: Any = None,
    ) -> BenchmarkScorecardSummary:
        """Aggregate per-target evaluation results into a global scorecard summary.

        Computes discovery rate, execution throughput, average PoC reduction,
        CWE exact/hierarchical accuracy, CVSS MAE, tolerance pass rates, and class
        stratifications with strict zero-division guards.

        Args:
            results: List of individual TargetEvaluationResult objects.
            total_duration: Total execution wall-clock time for the suite in seconds.
            options: Optional execution options.

        Returns:
            BenchmarkScorecardSummary containing aggregated performance metrics.
        """
        total = len(results)
        if total == 0:
            return BenchmarkScorecardSummary(
                total_duration_seconds=round(max(0.0, float(total_duration)), 2)
            )

        tp_results = [r for r in results if r.is_true_positive]
        tp_count = len(tp_results)
        missed_count = sum(1 for r in results if r.status == "MISSED")
        error_count = sum(1 for r in results if r.status in ("ERROR", "TIMEOUT"))

        tpr_pct = round((tp_count / total) * 100.0, 1)

        mean_ttc = (
            round(sum(r.time_to_crash_seconds for r in tp_results) / tp_count, 3)
            if tp_count > 0
            else 0.0
        )
        avg_throughput = (
            round(sum(r.throughput_execs_per_sec for r in results) / total, 1) if total > 0 else 0.0
        )
        avg_poc_red = (
            round(
                sum(r.poc_reduction_percentage for r in tp_results) / tp_count,
                1,
            )
            if tp_count > 0
            else 0.0
        )

        cwe_exact_pct = (
            round(
                (sum(1 for r in tp_results if r.cwe_exact_match) / tp_count) * 100.0,
                1,
            )
            if tp_count > 0
            else 0.0
        )
        cwe_hier_pct = (
            round(
                (sum(r.cwe_match_score for r in tp_results) / tp_count) * 100.0,
                1,
            )
            if tp_count > 0
            else 0.0
        )

        cvss_mae = (
            round(sum(r.cvss_delta for r in tp_results) / tp_count, 2) if tp_count > 0 else 0.0
        )
        cvss_tol_pct = (
            round(
                (sum(1 for r in tp_results if r.cvss_tolerance_passed) / tp_count) * 100.0,
                1,
            )
            if tp_count > 0
            else 0.0
        )
        sev_concordance_pct = (
            round(
                (sum(1 for r in tp_results if r.severity_match) / tp_count) * 100.0,
                1,
            )
            if tp_count > 0
            else 0.0
        )

        # Vulnerability class stratification breakdown
        breakdown: dict[str, dict[str, Any]] = {}
        for r in results:
            vc = r.vulnerability_class
            if vc not in breakdown:
                breakdown[vc] = {
                    "total": 0,
                    "discovered": 0,
                    "missed": 0,
                    "tpr_pct": 0.0,
                    "avg_ttc_s": 0.0,
                    "avg_reduction_pct": 0.0,
                }
            breakdown[vc]["total"] += 1
            if r.is_true_positive:
                breakdown[vc]["discovered"] += 1
            else:
                breakdown[vc]["missed"] += 1

        for vc, stats in breakdown.items():
            class_tp = [r for r in results if r.vulnerability_class == vc and r.is_true_positive]
            stats["tpr_pct"] = (
                round((stats["discovered"] / stats["total"]) * 100.0, 1)
                if stats["total"] > 0
                else 0.0
            )
            stats["avg_ttc_s"] = (
                round(
                    sum(r.time_to_crash_seconds for r in class_tp) / len(class_tp),
                    3,
                )
                if len(class_tp) > 0
                else 0.0
            )
            stats["avg_reduction_pct"] = (
                round(
                    sum(r.poc_reduction_percentage for r in class_tp) / len(class_tp),
                    1,
                )
                if len(class_tp) > 0
                else 0.0
            )

        return BenchmarkScorecardSummary(
            total_targets=total,
            discovered_count=tp_count,
            missed_count=missed_count,
            error_count=error_count,
            discovery_rate_tpr_pct=tpr_pct,
            mean_time_to_crash_seconds=mean_ttc,
            avg_throughput_exec_per_sec=avg_throughput,
            avg_poc_reduction_pct=avg_poc_red,
            cwe_exact_match_rate_pct=cwe_exact_pct,
            cwe_hierarchical_match_rate_pct=cwe_hier_pct,
            cvss_mean_absolute_error=cvss_mae,
            cvss_tolerance_match_rate_pct=cvss_tol_pct,
            severity_concordance_rate_pct=sev_concordance_pct,
            class_breakdown=breakdown,
            target_results=results,
            total_duration_seconds=round(max(0.0, float(total_duration)), 2),
        )
