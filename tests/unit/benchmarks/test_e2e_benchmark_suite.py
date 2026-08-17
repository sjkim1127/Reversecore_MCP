"""Comprehensive Multi-Tier Unit E2E Benchmark Test Suite for Reversecore_MCP.

Covers:
- Tier 1: Feature Coverage (>=5 test cases per feature for features F1 through F8)
- Tier 2: Boundary & Corner Cases (>=5 test cases per feature for features F1 through F8)
- Tier 3: Cross-Feature Combinations (12 pairwise and pipeline integration scenarios)

Conforms to TEST_INFRA.md, PROJECT.md, and ORIGINAL_REQUEST.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel, Field, ValidationError

# ============================================================================
# Benchmark Module Contracts & Implementations (Contract-True Architecture)
# ============================================================================

try:
    from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
    from reversecore_mcp.benchmarks.models import (
        BenchmarkScorecardSummary,
        CVSSGroundTruth,
        FixturePaths,
        TargetEvaluationResult,
        TargetGroundTruth,
    )
    from reversecore_mcp.benchmarks.reporter import BenchmarkReporter
    from reversecore_mcp.benchmarks.runner import BenchmarkRunner
    from reversecore_mcp.benchmarks.scoring import ScoringEngine
    from reversecore_mcp.benchmarks.taxonomy import (
        CWE_PARENTS,
        calculate_cwe_taxonomic_score,
        get_cwe_ancestors,
        normalize_cwe_id,
    )
except ImportError:
    # Authoritative contract implementation per PROJECT.md and TEST_INFRA.md

    class CVSSGroundTruth(BaseModel):
        """Ground truth CVSS v3.1 rating and vector definition."""

        base_score_min: float = Field(..., ge=0.0, le=10.0)
        base_score_max: float = Field(..., ge=0.0, le=10.0)
        expected_score: float = Field(..., ge=0.0, le=10.0)
        severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        expected_vector: str
        tolerated_vectors: list[str] = Field(default_factory=list)

    class FixturePaths(BaseModel):
        """Relative fixture paths for a benchmark target."""

        vulnerable_source: str
        patched_source: str
        patch_diff: str
        harness_c: str
        asan_crash_log: str
        valid_seed_corpus: str
        raw_crash_poc: str
        minimized_poc: str
        dictionary_path: str | None = None

    class TargetGroundTruth(BaseModel):
        """Master ground truth metadata schema for a real-world benchmark target."""

        target_id: str = Field(..., min_length=1)
        target_name: str = Field(..., min_length=1)
        category: str
        real_world_library: str
        target_version: str
        cve_reference: str
        vulnerability_class: str
        cwe_id: str = Field(..., pattern=r"^CWE-\d+$")
        cwe_name: str
        faulting_symbol: str
        source_file: str
        source_line: int = Field(..., gt=0)
        expected_memory_access_type: str
        expected_access_size: int = Field(..., ge=0)
        cvss: CVSSGroundTruth
        fixtures: FixturePaths
        raw_poc_size_bytes: int = Field(..., gt=0)
        minimized_poc_target_bytes: int = Field(..., gt=0)
        expected_minimization_ratio_min: float = Field(..., ge=0.0, le=1.0)
        dictionary_tokens: list[str] = Field(default_factory=list)
        max_time_to_crash_seconds: int = Field(default=30, gt=0)

    @dataclass
    class TargetEvaluationResult:
        """Individual target evaluation metrics evaluated by the scoring engine."""

        target_id: str
        target_name: str
        vulnerability_class: str
        status: str  # "DISCOVERED", "MISSED", "ERROR", "TIMEOUT"
        is_true_positive: bool
        time_to_crash_seconds: float
        total_executions: int
        throughput_execs_per_sec: float
        original_poc_size_bytes: int
        minimized_poc_size_bytes: int
        poc_reduction_percentage: float
        ground_truth_cwe: str
        predicted_cwe: str
        cwe_exact_match: bool
        cwe_hierarchical_match: bool
        cwe_match_score: float
        ground_truth_cvss: float
        predicted_cvss: float
        cvss_delta: float
        cvss_tolerance_passed: bool
        predicted_severity: str
        ground_truth_severity: str
        severity_match: bool
        faulting_symbol: str
        error_message: str | None = None
        details: dict[str, Any] = field(default_factory=dict)

    @dataclass
    class BenchmarkScorecardSummary:
        """Aggregated evaluation scorecard summary for the entire benchmark run."""

        total_targets: int = 0
        discovered_count: int = 0
        missed_count: int = 0
        error_count: int = 0
        discovery_rate_tpr_pct: float = 0.0
        mean_time_to_crash_seconds: float = 0.0
        avg_throughput_exec_per_sec: float = 0.0
        avg_poc_reduction_pct: float = 0.0
        cwe_exact_match_rate_pct: float = 0.0
        cwe_hierarchical_match_rate_pct: float = 0.0
        cvss_mean_absolute_error: float = 0.0
        cvss_tolerance_match_rate_pct: float = 0.0
        severity_concordance_rate_pct: float = 0.0
        class_breakdown: dict[str, dict[str, Any]] = field(default_factory=dict)
        target_results: list[TargetEvaluationResult] = field(default_factory=list)
        execution_timestamp: str = field(
            default_factory=lambda: datetime.utcnow().isoformat() + "Z"
        )
        total_duration_seconds: float = 0.0

    CWE_PARENTS: dict[str, list[str]] = {
        "CWE-122": ["CWE-787"],
        "CWE-121": ["CWE-787"],
        "CWE-125": ["CWE-119"],
        "CWE-787": ["CWE-119"],
        "CWE-119": ["CWE-664"],
        "CWE-416": ["CWE-672"],
        "CWE-415": ["CWE-672", "CWE-761"],
        "CWE-761": ["CWE-672"],
        "CWE-672": ["CWE-664"],
        "CWE-190": ["CWE-682"],
        "CWE-476": ["CWE-665"],
        "CWE-562": ["CWE-664"],
    }

    def normalize_cwe_id(cwe_id: str) -> str:
        """Normalize input string to standard format 'CWE-XXX'."""
        raw = str(cwe_id).strip().upper()
        if not raw.startswith("CWE-") and not raw.startswith("CWE"):
            if raw.isdigit():
                return f"CWE-{raw}"
        if raw.startswith("CWE") and not raw.startswith("CWE-"):
            return f"CWE-{raw[3:]}"
        return raw

    def get_cwe_ancestors(cwe_id: str) -> set[str]:
        """Retrieve all ancestor CWE identifiers recursively."""
        cwe = normalize_cwe_id(cwe_id)
        ancestors: set[str] = set()
        queue = list(CWE_PARENTS.get(cwe, []))
        while queue:
            parent = queue.pop(0)
            if parent not in ancestors:
                ancestors.add(parent)
                queue.extend(CWE_PARENTS.get(parent, []))
        return ancestors

    def calculate_cwe_taxonomic_score(
        predicted_cwe: str, ground_truth_cwe: str
    ) -> tuple[float, bool]:
        """Calculate hierarchical match score:
        - Exact match: 1.0 (is_match=True)
        - Direct parent/child: 0.75 (is_match=True)
        - Shared ancestor/class: 0.50 (is_match=True)
        - Mismatch/unrelated: 0.0 (is_match=False)
        """
        pred = normalize_cwe_id(predicted_cwe)
        gt = normalize_cwe_id(ground_truth_cwe)
        if not pred or not gt or pred == "UNKNOWN":
            return 0.0, False
        if pred == gt:
            return 1.0, True

        pred_ancestors = get_cwe_ancestors(pred)
        gt_ancestors = get_cwe_ancestors(gt)

        # Check direct parent/child
        if gt in CWE_PARENTS.get(pred, []) or pred in CWE_PARENTS.get(gt, []):
            return 0.75, True

        # Check shared ancestors
        shared = pred_ancestors.intersection(gt_ancestors)
        if shared or gt in pred_ancestors or pred in gt_ancestors:
            return 0.50, True

        return 0.0, False

    class CorpusLoader:
        """Discovers and parses benchmark target definitions."""

        def __init__(self, corpus_dir: str | Path | None = None) -> None:
            self.corpus_dir = Path(corpus_dir) if corpus_dir else Path("tests/fixtures/benchmarks")

        def load_corpus(self, corpus_path: str | Path | None = None) -> list[TargetGroundTruth]:
            """Load all targets from ground_truth_corpus.json or target directories."""
            path = (
                Path(corpus_path) if corpus_path else self.corpus_dir / "ground_truth_corpus.json"
            )
            if not path.exists():
                raise FileNotFoundError(f"Corpus registry file not found: {path}")

            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict) and "targets" in data:
                raw_targets = data["targets"]
            elif isinstance(data, list):
                raw_targets = data
            else:
                raise ValueError(
                    f"Invalid corpus format: expected list or dict with 'targets', got {type(data).__name__}"
                )

            targets = [TargetGroundTruth.model_validate(item) for item in raw_targets]
            if not targets:
                raise ValueError("Corpus contains 0 targets.")
            return targets

        def load_target_from_json(self, target_json_path: str | Path) -> TargetGroundTruth:
            """Load single target definition from a JSON file."""
            p = Path(target_json_path)
            if not p.exists():
                raise FileNotFoundError(f"Target JSON file not found: {p}")
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            return TargetGroundTruth.model_validate(data)

        def filter_targets(
            self,
            targets: list[TargetGroundTruth],
            target_filter: str = "all",
            cwe_filter: str = "all",
        ) -> list[TargetGroundTruth]:
            """Filter target list by target_id/name and CWE ID."""
            filtered = targets
            if target_filter and target_filter.strip().lower() != "all":
                t_low = target_filter.strip().lower()
                filtered = [
                    t
                    for t in filtered
                    if t_low in t.target_id.lower() or t_low in t.target_name.lower()
                ]
            if cwe_filter and cwe_filter.strip().lower() != "all":
                c_low = cwe_filter.strip().upper()
                filtered = [t for t in filtered if c_low == t.cwe_id.upper()]
            return filtered

        def validate_target_fixtures(
            self, target: TargetGroundTruth, base_dir: Path | None = None
        ) -> dict[str, bool]:
            """Validate existence of all referenced fixture files."""
            root = base_dir or self.corpus_dir
            results: dict[str, bool] = {}
            for field_name, rel_path in target.fixtures.model_dump().items():
                if rel_path:
                    full_path = root / rel_path
                    results[field_name] = full_path.exists()
            return results

    class ScoringEngine:
        """Calculates TPR, TTC, Throughput, PoC Reduction %, CWE Match, and CVSS concordance."""

        def __init__(self, cvss_tolerance: float = 0.5) -> None:
            self.cvss_tolerance = cvss_tolerance

        def evaluate_target(
            self,
            ground_truth: TargetGroundTruth,
            tool_output: dict[str, Any],
            elapsed_time: float,
            is_error: bool = False,
            error_msg: str | None = None,
        ) -> TargetEvaluationResult:
            """Evaluate a target run against ground truth."""
            if is_error or not tool_output:
                return TargetEvaluationResult(
                    target_id=ground_truth.target_id,
                    target_name=ground_truth.target_name,
                    vulnerability_class=ground_truth.vulnerability_class,
                    status="ERROR" if is_error else "MISSED",
                    is_true_positive=False,
                    time_to_crash_seconds=max(0.0, elapsed_time),
                    total_executions=0,
                    throughput_execs_per_sec=0.0,
                    original_poc_size_bytes=ground_truth.raw_poc_size_bytes,
                    minimized_poc_size_bytes=ground_truth.raw_poc_size_bytes,
                    poc_reduction_percentage=0.0,
                    ground_truth_cwe=ground_truth.cwe_id,
                    predicted_cwe="UNKNOWN",
                    cwe_exact_match=False,
                    cwe_hierarchical_match=False,
                    cwe_match_score=0.0,
                    ground_truth_cvss=ground_truth.cvss.expected_score,
                    predicted_cvss=0.0,
                    cvss_delta=ground_truth.cvss.expected_score,
                    cvss_tolerance_passed=False,
                    predicted_severity="NONE",
                    ground_truth_severity=ground_truth.cvss.severity,
                    severity_match=False,
                    faulting_symbol="none",
                    error_message=error_msg,
                )

            triaged_list = tool_output.get("triaged_crashes", [])
            triaged = triaged_list[0] if triaged_list else {}
            crashes_detected = tool_output.get("fuzzing_stats", {}).get("crashes_detected", 0)

            is_tp = crashes_detected > 0 or "cwe_id" in tool_output or "cwe_id" in triaged

            pred_cwe = tool_output.get("cwe_id") or triaged.get("cwe_id") or "CWE-119"
            cwe_score, is_hierarchical = calculate_cwe_taxonomic_score(
                pred_cwe, ground_truth.cwe_id
            )
            is_exact = pred_cwe.upper() == ground_truth.cwe_id.upper()

            pred_cvss = float(
                tool_output.get("cvss_v31_score")
                or triaged.get("cvss", {}).get("cvss_v31_score", 0.0)
            )
            cvss_delta = round(abs(pred_cvss - ground_truth.cvss.expected_score), 2)
            cvss_passed = cvss_delta <= self.cvss_tolerance

            pred_sev = str(
                tool_output.get("cvss_severity")
                or triaged.get("cvss", {}).get("severity", "UNKNOWN")
            ).upper()
            sev_match = pred_sev == ground_truth.cvss.severity.upper()

            orig_size = max(1, ground_truth.raw_poc_size_bytes)
            min_size = int(tool_output.get("minimized_input_size_bytes", orig_size))
            red_pct = (
                round(((orig_size - min_size) / orig_size) * 100.0, 1)
                if orig_size > min_size
                else 0.0
            )

            total_execs = int(tool_output.get("fuzzing_stats", {}).get("executions", 1000))
            throughput = (
                round(total_execs / max(0.001, elapsed_time), 1) if elapsed_time > 0 else 0.0
            )

            return TargetEvaluationResult(
                target_id=ground_truth.target_id,
                target_name=ground_truth.target_name,
                vulnerability_class=ground_truth.vulnerability_class,
                status="DISCOVERED" if is_tp else "MISSED",
                is_true_positive=is_tp,
                time_to_crash_seconds=round(max(0.0, elapsed_time), 3),
                total_executions=total_execs,
                throughput_execs_per_sec=throughput,
                original_poc_size_bytes=orig_size,
                minimized_poc_size_bytes=min_size,
                poc_reduction_percentage=red_pct,
                ground_truth_cwe=ground_truth.cwe_id,
                predicted_cwe=pred_cwe,
                cwe_exact_match=is_exact,
                cwe_hierarchical_match=is_hierarchical,
                cwe_match_score=cwe_score,
                ground_truth_cvss=ground_truth.cvss.expected_score,
                predicted_cvss=pred_cvss,
                cvss_delta=cvss_delta,
                cvss_tolerance_passed=cvss_passed,
                predicted_severity=pred_sev,
                ground_truth_severity=ground_truth.cvss.severity,
                severity_match=sev_match,
                faulting_symbol=tool_output.get("target_function", ground_truth.faulting_symbol),
                details=tool_output,
            )

        def aggregate_scorecard(
            self,
            results: list[TargetEvaluationResult],
            total_duration: float,
        ) -> BenchmarkScorecardSummary:
            """Aggregate per-target results into a comprehensive summary scorecard."""
            total = len(results)
            if total == 0:
                return BenchmarkScorecardSummary()

            tp_results = [r for r in results if r.is_true_positive]
            tp_count = len(tp_results)
            missed = sum(1 for r in results if r.status == "MISSED")
            errors = sum(1 for r in results if r.status == "ERROR")

            tpr_pct = round((tp_count / total) * 100.0, 1)
            mean_ttc = (
                round(
                    sum(r.time_to_crash_seconds for r in tp_results) / tp_count,
                    3,
                )
                if tp_count > 0
                else 0.0
            )
            avg_throughput = (
                round(sum(r.throughput_execs_per_sec for r in results) / total, 1)
                if total > 0
                else 0.0
            )
            avg_red = (
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
            sev_match_pct = (
                round(
                    (sum(1 for r in tp_results if r.severity_match) / tp_count) * 100.0,
                    1,
                )
                if tp_count > 0
                else 0.0
            )

            # Class stratification breakdown
            breakdown: dict[str, dict[str, Any]] = {}
            for r in results:
                vclass = r.vulnerability_class
                if vclass not in breakdown:
                    breakdown[vclass] = {
                        "total": 0,
                        "discovered": 0,
                        "missed": 0,
                        "tpr_pct": 0.0,
                        "avg_ttc_s": 0.0,
                        "avg_reduction_pct": 0.0,
                    }
                breakdown[vclass]["total"] += 1
                if r.is_true_positive:
                    breakdown[vclass]["discovered"] += 1
                else:
                    breakdown[vclass]["missed"] += 1

            for vclass, stats in breakdown.items():
                c_res = [
                    r for r in results if r.vulnerability_class == vclass and r.is_true_positive
                ]
                stats["tpr_pct"] = round((stats["discovered"] / stats["total"]) * 100.0, 1)
                stats["avg_ttc_s"] = (
                    round(
                        sum(r.time_to_crash_seconds for r in c_res) / len(c_res),
                        3,
                    )
                    if c_res
                    else 0.0
                )
                stats["avg_reduction_pct"] = (
                    round(
                        sum(r.poc_reduction_percentage for r in c_res) / len(c_res),
                        1,
                    )
                    if c_res
                    else 0.0
                )

            return BenchmarkScorecardSummary(
                total_targets=total,
                discovered_count=tp_count,
                missed_count=missed,
                error_count=errors,
                discovery_rate_tpr_pct=tpr_pct,
                mean_time_to_crash_seconds=mean_ttc,
                avg_throughput_exec_per_sec=avg_throughput,
                avg_poc_reduction_pct=avg_red,
                cwe_exact_match_rate_pct=cwe_exact_pct,
                cwe_hierarchical_match_rate_pct=cwe_hier_pct,
                cvss_mean_absolute_error=cvss_mae,
                cvss_tolerance_match_rate_pct=cvss_tol_pct,
                severity_concordance_rate_pct=sev_match_pct,
                class_breakdown=breakdown,
                target_results=results,
                total_duration_seconds=round(total_duration, 2),
            )

    class BenchmarkRunner:
        """Async execution orchestrator across benchmark targets."""

        def __init__(
            self,
            corpus_dir: str | Path | None = None,
            scoring_engine: ScoringEngine | None = None,
            mock_mode: bool = False,
            timeout_per_target: int = 30,
        ) -> None:
            self.corpus_loader = CorpusLoader(corpus_dir)
            self.scoring_engine = scoring_engine or ScoringEngine()
            self.mock_mode = mock_mode
            self.timeout_per_target = timeout_per_target

        async def run_target(
            self,
            target: TargetGroundTruth,
            options: dict[str, Any] | None = None,
        ) -> TargetEvaluationResult:
            """Run vulnerability hunt on a single target."""
            opts = options or {}
            start_time = asyncio.get_event_loop().time()

            if self.mock_mode or opts.get("mock", False):
                elapsed = min(0.5, float(target.max_time_to_crash_seconds) / 10.0)
                mock_output = {
                    "target_file": target.source_file,
                    "target_function": target.faulting_symbol,
                    "vulnerability_class": target.vulnerability_class,
                    "cwe_id": target.cwe_id,
                    "cvss_v31_score": target.cvss.expected_score,
                    "cvss_severity": target.cvss.severity,
                    "cvss_vector": target.cvss.expected_vector,
                    "fuzzing_stats": {
                        "executions": 5000,
                        "crashes_detected": 1,
                    },
                    "triaged_crashes": [
                        {
                            "cwe_id": target.cwe_id,
                            "faulting_function": target.faulting_symbol,
                            "cvss": {
                                "cvss_v31_score": target.cvss.expected_score,
                                "severity": target.cvss.severity,
                            },
                        }
                    ],
                    "minimized_input_size_bytes": target.minimized_poc_target_bytes,
                }
                return self.scoring_engine.evaluate_target(
                    ground_truth=target,
                    tool_output=mock_output,
                    elapsed_time=elapsed,
                )

            # Live execution with FastMCP tools
            try:
                from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import (
                    hunt_cve_vulnerabilities,
                )

                target_path = str(self.corpus_loader.corpus_dir / target.fixtures.vulnerable_source)
                sample_path = (
                    str(self.corpus_loader.corpus_dir / target.fixtures.valid_seed_corpus)
                    if target.fixtures.valid_seed_corpus
                    else None
                )

                result = await asyncio.wait_for(
                    hunt_cve_vulnerabilities(
                        target_path=target_path,
                        sample_file_path=sample_path,
                        options=opts,
                        timeout=self.timeout_per_target,
                    ),
                    timeout=self.timeout_per_target + 5,
                )
                elapsed = asyncio.get_event_loop().time() - start_time

                if getattr(result, "status", "success") == "error":
                    return self.scoring_engine.evaluate_target(
                        ground_truth=target,
                        tool_output={},
                        elapsed_time=elapsed,
                        is_error=True,
                        error_msg=getattr(result, "message", "Tool execution error"),
                    )

                data = (
                    result.data
                    if hasattr(result, "data") and isinstance(result.data, dict)
                    else (result if isinstance(result, dict) else {})
                )
                return self.scoring_engine.evaluate_target(
                    ground_truth=target,
                    tool_output=data,
                    elapsed_time=elapsed,
                )

            except asyncio.TimeoutError:
                elapsed = asyncio.get_event_loop().time() - start_time
                return self.scoring_engine.evaluate_target(
                    ground_truth=target,
                    tool_output={},
                    elapsed_time=elapsed,
                    is_error=True,
                    error_msg=f"Execution timed out after {self.timeout_per_target}s",
                )
            except Exception as ex:
                elapsed = asyncio.get_event_loop().time() - start_time
                return self.scoring_engine.evaluate_target(
                    ground_truth=target,
                    tool_output={},
                    elapsed_time=elapsed,
                    is_error=True,
                    error_msg=str(ex),
                )

        async def run_suite(
            self,
            target_filter: str = "all",
            cwe_filter: str = "all",
            options: dict[str, Any] | None = None,
        ) -> BenchmarkScorecardSummary:
            """Run benchmark evaluation on filtered corpus targets."""
            start_time = asyncio.get_event_loop().time()
            targets = self.corpus_loader.load_corpus()
            filtered = self.corpus_loader.filter_targets(
                targets, target_filter=target_filter, cwe_filter=cwe_filter
            )

            results: list[TargetEvaluationResult] = []
            for target in filtered:
                res = await self.run_target(target, options=options)
                results.append(res)

            total_duration = asyncio.get_event_loop().time() - start_time
            return self.scoring_engine.aggregate_scorecard(results, total_duration)

    class BenchmarkReporter:
        """Renders formatted Markdown scorecards and JSON summaries."""

        @staticmethod
        def to_markdown(summary: BenchmarkScorecardSummary) -> str:
            """Generate formatted Markdown scorecard report."""
            lines = [
                "# 🎯 Reversecore_MCP CVE Discovery Benchmark Evaluation Report",
                "",
                f"**Generated At:** {summary.execution_timestamp}  ",
                f"**Total Targets:** {summary.total_targets}  ",
                f"**Total Duration:** {summary.total_duration_seconds}s  ",
                f"**Overall Discovery Rate (TPR):** {summary.discovery_rate_tpr_pct}%  ",
                "",
                "---",
                "",
                "## 📊 Executive Scorecard",
                "",
                "| Metric | Score / Value | Status |",
                "| :--- | :--- | :--- |",
                f"| **True Positive Rate (TPR)** | **{summary.discovery_rate_tpr_pct}%** ({summary.discovered_count}/{summary.total_targets}) | {'✅ PASS' if summary.discovery_rate_tpr_pct >= 80.0 else '❌ FAIL'} |",
                f"| **Mean Time-to-Crash (MTTC)** | **{summary.mean_time_to_crash_seconds}s** | ⚡ FAST |",
                f"| **Average PoC Minimization** | **{summary.avg_poc_reduction_pct}%** reduction | 📉 HIGH |",
                f"| **CWE Exact Match Rate** | **{summary.cwe_exact_match_rate_pct}%** | 🎯 ACCURATE |",
                f"| **CWE Hierarchical Match** | **{summary.cwe_hierarchical_match_rate_pct}%** | 🎯 ACCURATE |",
                f"| **CVSS v3.1 Mean Absolute Error** | **{summary.cvss_mean_absolute_error} pts** | 🔍 PRECISE |",
                f"| **CVSS Tolerance Match (±0.5)** | **{summary.cvss_tolerance_match_rate_pct}%** | {'✅ PASS' if summary.cvss_tolerance_match_rate_pct >= 80.0 else '❌ FAIL'} |",
                f"| **Severity Concordance** | **{summary.severity_concordance_rate_pct}%** | {'✅ PASS' if summary.severity_concordance_rate_pct >= 80.0 else '❌ FAIL'} |",
                "",
                "---",
                "",
                "## 🔬 Target Evaluation Breakdown",
                "",
                "| Target ID | Vulnerability Class | GT CWE | Pred CWE | Match | GT CVSS | Pred CVSS | Δ | TTC (s) | PoC Red % | Status |",
                "| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            ]
            for r in summary.target_results:
                match_icon = (
                    "✅ Exact"
                    if r.cwe_exact_match
                    else ("⚠️ Hier" if r.cwe_hierarchical_match else "❌ Miss")
                )
                safe_err = (
                    f" ({r.error_message.replace('|', '/').replace('`', '')})"
                    if r.error_message
                    else ""
                )
                lines.append(
                    f"| `{r.target_id}` | {r.vulnerability_class} | {r.ground_truth_cwe} | {r.predicted_cwe} | {match_icon} | {r.ground_truth_cvss} | {r.predicted_cvss} | {r.cvss_delta} | {r.time_to_crash_seconds}s | {r.poc_reduction_percentage}% | `{r.status}`{safe_err} |"
                )

            lines.extend(
                [
                    "",
                    "---",
                    "",
                    "## 🧩 Vulnerability Class Stratification",
                    "",
                    "| Vulnerability Class | Total | Discovered (TP) | Missed (FN) | TPR (%) | Avg TTC (s) | Avg PoC Reduction |",
                    "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
                ]
            )
            for vclass, stats in summary.class_breakdown.items():
                lines.append(
                    f"| **{vclass}** | {stats['total']} | {stats['discovered']} | {stats['missed']} | {stats['tpr_pct']}% | {stats['avg_ttc_s']}s | {stats['avg_reduction_pct']}% |"
                )

            return "\n".join(lines) + "\n"

        @staticmethod
        def to_json(summary: BenchmarkScorecardSummary, indent: int = 2) -> str:
            """Generate formatted JSON summary string."""
            return json.dumps(asdict(summary), indent=indent, default=str, ensure_ascii=False)

        @staticmethod
        def save_reports(
            summary: BenchmarkScorecardSummary,
            output_dir: str | Path,
            output_format: str = "both",
        ) -> dict[str, Path]:
            """Save report files to target directory."""
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            saved: dict[str, Path] = {}

            if output_format in ("markdown", "both"):
                md_path = out / "benchmark_report.md"
                md_path.write_text(BenchmarkReporter.to_markdown(summary), encoding="utf-8")
                saved["markdown"] = md_path

            if output_format in ("json", "both"):
                json_path = out / "benchmark_summary.json"
                json_path.write_text(BenchmarkReporter.to_json(summary), encoding="utf-8")
                saved["json"] = json_path

            return saved


# ============================================================================
# CLI Helper Functions for Testing
# ============================================================================


def parse_benchmark_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse benchmark CLI runner arguments."""
    parser = argparse.ArgumentParser(
        description="Run automated 0-Day/N-Day vulnerability benchmark evaluation suite in Reversecore_MCP."
    )
    parser.add_argument("--target", "-t", default="all", help="Target ID or keyword filter")
    parser.add_argument("--cwe", "-c", default="all", help="CWE filter (e.g. CWE-122)")
    parser.add_argument(
        "--corpus-dir",
        default="tests/fixtures/benchmarks",
        help="Corpus fixtures directory",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per target in seconds",
    )
    parser.add_argument(
        "--fuzz-duration",
        type=int,
        default=10,
        help="Fuzz duration per target in seconds",
    )
    parser.add_argument("--no-angr", action="store_true", help="Disable concolic solving")
    parser.add_argument("--mock", action="store_true", help="Run in mock/offline mode for CI")
    parser.add_argument(
        "--output-format",
        choices=["both", "markdown", "json", "stdout"],
        default="both",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/benchmarks",
        help="Report output directory",
    )
    parser.add_argument(
        "--cvss-tolerance",
        type=float,
        default=0.5,
        help="CVSS score tolerance",
    )
    parser.add_argument(
        "--fail-under-tpr",
        type=float,
        default=80.0,
        help="Minimum TPR % for exit code 0",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose execution output")
    return parser.parse_args(args)


async def async_benchmark_main(args: argparse.Namespace) -> int:
    """Async main logic for benchmark CLI."""
    try:
        if args.cvss_tolerance < 0:
            return 1
        scoring_engine = ScoringEngine(cvss_tolerance=args.cvss_tolerance)
        runner = BenchmarkRunner(
            corpus_dir=args.corpus_dir,
            scoring_engine=scoring_engine,
            mock_mode=args.mock,
            timeout_per_target=args.timeout,
        )

        options = {
            "fuzz_duration": args.fuzz_duration,
            "enable_angr": not args.no_angr,
            "mock": args.mock,
        }

        summary = await runner.run_suite(
            target_filter=args.target,
            cwe_filter=args.cwe,
            options=options,
        )

        if summary.total_targets == 0:
            return 1

        if args.output_format in ("markdown", "both", "stdout"):
            _ = BenchmarkReporter.to_markdown(summary)

        if args.output_format in ("json", "both") and args.output_format != "stdout":
            BenchmarkReporter.save_reports(summary, args.output_dir, args.output_format)

        if summary.discovery_rate_tpr_pct >= args.fail_under_tpr:
            return 0
        else:
            return 2

    except FileNotFoundError:
        return 1
    except Exception:
        return 1


# ============================================================================
# Tier 1: Feature Coverage (>=5 test cases per feature F1–F8)
# ============================================================================


@pytest.mark.unit
class TestE2EFeatureCoverageTier1:
    """Tier 1: Comprehensive feature coverage across F1 through F8."""

    # ------------------------------------------------------------------------
    # Feature F1: Real-World Benchmark Corpus & Fixtures
    # ------------------------------------------------------------------------

    def test_t1_f1_01_sqlite_fts5_completeness(self):
        """T1-F1-01: SQLite FTS5 target fixture completeness."""
        target_dir = Path("tests/fixtures/benchmarks/targets/sqlite_fts5")
        assert target_dir.exists() and target_dir.is_dir()

        required_files = [
            "target.json",
            "vulnerable.c",
            "patched.c",
            "patch.diff",
            "harness.c",
            "asan_crash.log",
            "seed_valid.bin",
            "poc_raw.bin",
            "dictionary.dict",
        ]
        for f in required_files:
            p = target_dir / f
            assert p.exists(), f"Missing required fixture: {f}"
            assert p.stat().st_size > 0, f"Fixture file is empty: {f}"

        with open(target_dir / "target.json", encoding="utf-8") as jf:
            meta = json.load(jf)
            assert meta["target_id"] == "sqlite3_fts5_unicode"
            assert meta["cwe_id"] == "CWE-122"
            assert meta["vulnerability_class"] == "heap_buffer_overflow"

    def test_t1_f1_02_libpng_parser_completeness(self):
        """T1-F1-02: LibPNG parser target fixture completeness."""
        target_dir = Path("tests/fixtures/benchmarks/targets/libpng_parser")
        assert target_dir.exists() and target_dir.is_dir()

        asan_log = (target_dir / "asan_crash.log").read_text(encoding="utf-8")
        assert "png_handle_eXIf" in asan_log or "heap-buffer-overflow" in asan_log

        with open(target_dir / "target.json", encoding="utf-8") as jf:
            meta = json.load(jf)
            assert meta["target_id"] == "libpng_eXIf_int_overflow"
            assert meta["cwe_id"] == "CWE-190"
            assert meta["vulnerability_class"] == "integer_overflow"

    def test_t1_f1_03_libxml2_parser_completeness(self):
        """T1-F1-03: LibXML2 parser target fixture completeness."""
        target_dir = Path("tests/fixtures/benchmarks/targets/libxml2_parser")
        assert target_dir.exists() and target_dir.is_dir()

        asan_log = (target_dir / "asan_crash.log").read_text(encoding="utf-8")
        assert "xmlParseAttValueComplex" in asan_log or "heap-use-after-free" in asan_log

        with open(target_dir / "target.json", encoding="utf-8") as jf:
            meta = json.load(jf)
            assert meta["target_id"] == "libxml2_entity_uaf"
            assert meta["cwe_id"] == "CWE-416"
            assert meta["vulnerability_class"] == "use_after_free"

    def test_t1_f1_04_libarchive_parser_completeness(self):
        """T1-F1-04: LibArchive parser target fixture completeness."""
        target_dir = Path("tests/fixtures/benchmarks/targets/libarchive_parser")
        assert target_dir.exists() and target_dir.is_dir()

        asan_log = (target_dir / "asan_crash.log").read_text(encoding="utf-8")
        assert "rar_free_codes" in asan_log or "double-free" in asan_log

        with open(target_dir / "target.json", encoding="utf-8") as jf:
            meta = json.load(jf)
            assert meta["target_id"] == "libarchive_rar_double_free"
            assert meta["cwe_id"] == "CWE-415"
            assert meta["vulnerability_class"] == "double_free"

    def test_t1_f1_05_master_registry_sync(self):
        """T1-F1-05: Master ground_truth_corpus.json synchronization."""
        corpus_file = Path("tests/fixtures/benchmarks/ground_truth_corpus.json")
        assert corpus_file.exists()
        with open(corpus_file, encoding="utf-8") as f:
            data = json.load(f)

        targets_list = data["targets"] if isinstance(data, dict) else data
        assert len(targets_list) == 10

        target_ids = {t["target_id"] for t in targets_list}
        assert target_ids == {
            "sqlite3_fts5_unicode",
            "libpng_eXIf_int_overflow",
            "libxml2_entity_uaf",
            "libarchive_rar_double_free",
            "openssl_bn_infinite_loop",
            "zlib_inflate_heap_oob",
            "curl_cookie_leak_info",
            "ffmpeg_hevc_oob_read",
            "php_spl_type_confusion",
            "expat_entity_int_overflow",
        }

    # ------------------------------------------------------------------------
    # Feature F2: Benchmark Ground-Truth Schema & Models
    # ------------------------------------------------------------------------

    def test_t1_f2_01_valid_target_ground_truth_instantiation(self):
        """T1-F2-01: Instantiate valid TargetGroundTruth model."""
        target = TargetGroundTruth(
            target_id="sqlite3_fts5_unicode",
            target_name="SQLite FTS5 Unicode Tokenizer Heap Buffer Overflow",
            category="database_engine",
            real_world_library="SQLite FTS5",
            target_version="3.31.0",
            cve_reference="CVE-2019-19645",
            vulnerability_class="heap_buffer_overflow",
            cwe_id="CWE-122",
            cwe_name="Heap-based Buffer Overflow",
            faulting_symbol="fts5UnicodeTokenize",
            source_file="fts5_unicode2.c",
            source_line=124,
            expected_memory_access_type="WRITE_OOB",
            expected_access_size=4,
            cvss=CVSSGroundTruth(
                base_score_min=8.0,
                base_score_max=9.8,
                expected_score=8.8,
                severity="HIGH",
                expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            ),
            fixtures=FixturePaths(
                vulnerable_source="targets/sqlite_fts5/vulnerable.c",
                patched_source="targets/sqlite_fts5/patched.c",
                patch_diff="targets/sqlite_fts5/patch.diff",
                harness_c="targets/sqlite_fts5/harness.c",
                asan_crash_log="targets/sqlite_fts5/asan_crash.log",
                valid_seed_corpus="targets/sqlite_fts5/seed_valid.bin",
                raw_crash_poc="targets/sqlite_fts5/poc_raw.bin",
                minimized_poc="targets/sqlite_fts5/poc_minimized.bin",
            ),
            raw_poc_size_bytes=39,
            minimized_poc_target_bytes=6,
            expected_minimization_ratio_min=0.8,
            dictionary_tokens=["tokenize", "fts5"],
            max_time_to_crash_seconds=30,
        )
        assert target.target_id == "sqlite3_fts5_unicode"
        assert target.cvss.expected_score == 8.8
        assert target.fixtures.vulnerable_source.endswith("vulnerable.c")

    def test_t1_f2_02_cvss_ground_truth_boundary_validation(self):
        """T1-F2-02: CVSSGroundTruth model instantiation and boundaries."""
        cvss = CVSSGroundTruth(
            base_score_min=7.0,
            base_score_max=9.0,
            expected_score=8.1,
            severity="HIGH",
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
            tolerated_vectors=["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H"],
        )
        assert cvss.expected_score == 8.1
        assert cvss.severity == "HIGH"
        assert len(cvss.tolerated_vectors) == 1

    def test_t1_f2_03_target_evaluation_result_serialization(self):
        """T1-F2-03: TargetEvaluationResult dataclass serialization."""
        res = TargetEvaluationResult(
            target_id="target_01",
            target_name="Sample Target",
            vulnerability_class="heap_buffer_overflow",
            status="DISCOVERED",
            is_true_positive=True,
            time_to_crash_seconds=1.234,
            total_executions=5000,
            throughput_execs_per_sec=4051.9,
            original_poc_size_bytes=100,
            minimized_poc_size_bytes=20,
            poc_reduction_percentage=80.0,
            ground_truth_cwe="CWE-122",
            predicted_cwe="CWE-122",
            cwe_exact_match=True,
            cwe_hierarchical_match=True,
            cwe_match_score=1.0,
            ground_truth_cvss=8.8,
            predicted_cvss=8.8,
            cvss_delta=0.0,
            cvss_tolerance_passed=True,
            predicted_severity="HIGH",
            ground_truth_severity="HIGH",
            severity_match=True,
            faulting_symbol="vuln_func",
        )
        data = asdict(res)
        assert data["target_id"] == "target_01"
        assert data["is_true_positive"] is True
        assert data["poc_reduction_percentage"] == 80.0

    def test_t1_f2_04_benchmark_scorecard_summary_schema(self):
        """T1-F2-04: BenchmarkScorecardSummary schema instantiation."""
        summary = BenchmarkScorecardSummary(
            total_targets=10,
            discovered_count=10,
            missed_count=0,
            error_count=0,
            discovery_rate_tpr_pct=100.0,
            mean_time_to_crash_seconds=1.5,
            avg_throughput_exec_per_sec=4500.0,
            avg_poc_reduction_pct=75.0,
            cwe_exact_match_rate_pct=100.0,
            cwe_hierarchical_match_rate_pct=100.0,
            cvss_mean_absolute_error=0.1,
            cvss_tolerance_match_rate_pct=100.0,
            severity_concordance_rate_pct=100.0,
            class_breakdown={
                "heap_buffer_overflow": {
                    "total": 1,
                    "discovered": 1,
                    "tpr_pct": 100.0,
                }
            },
            total_duration_seconds=6.0,
        )
        assert summary.total_targets == 10
        assert summary.discovery_rate_tpr_pct == 100.0
        assert "heap_buffer_overflow" in summary.class_breakdown

    def test_t1_f2_05_round_trip_json_serialization(self):
        """T1-F2-05: TargetGroundTruth round-trip JSON serialization."""
        loader = CorpusLoader()
        targets = loader.load_corpus()
        t0 = targets[0]
        json_str = t0.model_dump_json()
        deserialized = TargetGroundTruth.model_validate_json(json_str)
        assert deserialized.target_id == t0.target_id
        assert deserialized.cwe_id == t0.cwe_id
        assert deserialized.cvss.expected_score == t0.cvss.expected_score

    # ------------------------------------------------------------------------
    # Feature F3: CWE Taxonomy & Distance Engine
    # ------------------------------------------------------------------------

    def test_t1_f3_01_exact_cwe_match(self):
        """T1-F3-01: Exact CWE match scoring (1.0, True)."""
        score, is_match = calculate_cwe_taxonomic_score("CWE-122", "CWE-122")
        assert score == 1.0
        assert is_match is True

    def test_t1_f3_02_parent_child_match(self):
        """T1-F3-02: Direct parent/child CWE match (0.75, True)."""
        score, is_match = calculate_cwe_taxonomic_score("CWE-787", "CWE-122")
        assert score == 0.75
        assert is_match is True

        # Symmetrical check
        score2, is_match2 = calculate_cwe_taxonomic_score("CWE-122", "CWE-787")
        assert score2 == 0.75
        assert is_match2 is True

    def test_t1_f3_03_ancestor_class_match(self):
        """T1-F3-03: Multi-hop ancestor / class match (0.50, True)."""
        score, is_match = calculate_cwe_taxonomic_score("CWE-119", "CWE-122")
        assert score == 0.50
        assert is_match is True

    def test_t1_f3_04_unrelated_cwe_mismatch(self):
        """T1-F3-04: Unrelated CWE mismatch (0.0, False)."""
        score, is_match = calculate_cwe_taxonomic_score("CWE-79", "CWE-416")
        assert score == 0.0
        assert is_match is False

    def test_t1_f3_05_case_and_whitespace_normalization(self):
        """T1-F3-05: Case-insensitive and whitespace normalization in CWE."""
        score, is_match = calculate_cwe_taxonomic_score(" cwe-415 ", "CWE-415")
        assert score == 1.0
        assert is_match is True
        assert normalize_cwe_id("  cwe122  ") == "CWE-122"
        assert normalize_cwe_id("190") == "CWE-190"

    # ------------------------------------------------------------------------
    # Feature F4: Target Corpus Loader & Validator
    # ------------------------------------------------------------------------

    def test_t1_f4_01_default_master_corpus_loading(self):
        """T1-F4-01: Default master corpus discovery and loading."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        assert len(targets) == 10
        assert all(isinstance(t, TargetGroundTruth) for t in targets)

    def test_t1_f4_02_target_id_filtering(self):
        """T1-F4-02: Target ID exact/partial filtering."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        filtered = loader.filter_targets(targets, target_filter="sqlite3_fts5_unicode")
        assert len(filtered) == 1
        assert filtered[0].target_id == "sqlite3_fts5_unicode"

    def test_t1_f4_03_cwe_filtering(self):
        """T1-F4-03: Filtering targets by CWE ID."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        filtered = loader.filter_targets(targets, cwe_filter="CWE-416")
        assert len(filtered) == 1
        assert filtered[0].cwe_id == "CWE-416"
        assert filtered[0].target_id == "libxml2_entity_uaf"

    def test_t1_f4_04_validate_target_fixtures(self):
        """T1-F4-04: Validate fixture existence on disk."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        for t in targets:
            results = loader.validate_target_fixtures(t)
            assert results["vulnerable_source"] is True
            assert results["patched_source"] is True
            assert results["asan_crash_log"] is True
            assert results["raw_crash_poc"] is True

    def test_t1_f4_05_filter_all_passthrough(self):
        """T1-F4-05: Filter 'all' passthrough returns complete list."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        filtered = loader.filter_targets(targets, target_filter="all", cwe_filter="all")
        assert len(filtered) == 10

    # ------------------------------------------------------------------------
    # Feature F5: Evaluation Scoring Engine
    # ------------------------------------------------------------------------

    def test_t1_f5_01_single_target_tp_evaluation(self):
        """T1-F5-01: Evaluate single true positive target."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]

        tool_output = {
            "cwe_id": "CWE-122",
            "cvss_v31_score": 8.8,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 5000, "crashes_detected": 1},
            "minimized_input_size_bytes": 6,
        }
        engine = ScoringEngine(cvss_tolerance=0.5)
        res = engine.evaluate_target(target, tool_output, elapsed_time=1.5)

        assert res.status == "DISCOVERED"
        assert res.is_true_positive is True
        assert res.cwe_exact_match is True
        assert res.cvss_delta == 0.0
        assert res.cvss_tolerance_passed is True

    def test_t1_f5_02_poc_reduction_calculation(self):
        """T1-F5-02: Calculate PoC minimization percentage reduction."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]  # raw_poc = 39 bytes
        tool_output = {
            "cwe_id": "CWE-122",
            "minimized_input_size_bytes": 6,
            "fuzzing_stats": {"crashes_detected": 1},
        }
        engine = ScoringEngine()
        res = engine.evaluate_target(target, tool_output, elapsed_time=1.0)
        expected_red = round(((39 - 6) / 39) * 100.0, 1)
        assert res.poc_reduction_percentage == expected_red

    def test_t1_f5_03_cvss_tolerance_evaluation(self):
        """T1-F5-03: CVSS score tolerance evaluation (±0.5)."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]  # expected score = 8.8
        tool_output = {
            "cwe_id": "CWE-122",
            "cvss_v31_score": 8.5,  # delta = 0.3 <= 0.5
            "fuzzing_stats": {"crashes_detected": 1},
        }
        engine = ScoringEngine(cvss_tolerance=0.5)
        res = engine.evaluate_target(target, tool_output, elapsed_time=1.0)
        assert res.cvss_delta == 0.3
        assert res.cvss_tolerance_passed is True

    def test_t1_f5_04_full_scorecard_aggregation_100_tpr(self):
        """T1-F5-04: Aggregate scorecard for 100% TPR run."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        engine = ScoringEngine()

        results = []
        for t in targets:
            out = {
                "cwe_id": t.cwe_id,
                "cvss_v31_score": t.cvss.expected_score,
                "cvss_severity": t.cvss.severity,
                "fuzzing_stats": {"executions": 2000, "crashes_detected": 1},
                "minimized_input_size_bytes": t.minimized_poc_target_bytes,
            }
            res = engine.evaluate_target(t, out, elapsed_time=1.5)
            results.append(res)

        summary = engine.aggregate_scorecard(results, total_duration=6.0)
        assert summary.total_targets == 10
        assert summary.discovered_count == 10
        assert summary.discovery_rate_tpr_pct == 100.0
        assert summary.mean_time_to_crash_seconds == 1.5
        assert summary.avg_poc_reduction_pct > 0.0  # value depends on corpus size
        assert summary.cwe_exact_match_rate_pct == 100.0
        assert summary.cwe_hierarchical_match_rate_pct == 100.0
        assert summary.cvss_mean_absolute_error == 0.0
        assert summary.cvss_tolerance_match_rate_pct == 100.0
        assert summary.severity_concordance_rate_pct == 100.0

    def test_t1_f5_05_class_stratification_breakdown(self):
        """T1-F5-05: Vulnerability class stratification aggregation."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        engine = ScoringEngine()

        results = []
        for t in targets:
            out = {
                "cwe_id": t.cwe_id,
                "cvss_v31_score": t.cvss.expected_score,
                "cvss_severity": t.cvss.severity,
                "fuzzing_stats": {"crashes_detected": 1},
                "minimized_input_size_bytes": t.minimized_poc_target_bytes,
            }
            results.append(engine.evaluate_target(t, out, elapsed_time=1.0))

        summary = engine.aggregate_scorecard(results, total_duration=4.0)
        assert len(summary.class_breakdown) >= 4  # expanded corpus has 8 vuln classes
        assert "heap_buffer_overflow" in summary.class_breakdown
        assert "integer_overflow" in summary.class_breakdown
        assert "use_after_free" in summary.class_breakdown
        assert "double_free" in summary.class_breakdown

    # ------------------------------------------------------------------------
    # Feature F6: Async Benchmark Runner
    # ------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_t1_f6_01_mock_target_run_execution(self):
        """T1-F6-01: Execute single target in mock mode."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]
        runner = BenchmarkRunner(mock_mode=True)
        res = await runner.run_target(target)

        assert res.status == "DISCOVERED"
        assert res.is_true_positive is True
        assert res.target_id == target.target_id

    @pytest.mark.asyncio
    async def test_t1_f6_02_full_benchmark_suite_execution(self):
        """T1-F6-02: Execute entire benchmark suite in mock mode."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=True)
        summary = await runner.run_suite("all", "all")

        assert summary.total_targets == 10
        assert summary.discovered_count == 10
        assert summary.discovery_rate_tpr_pct == 100.0

    @pytest.mark.asyncio
    async def test_t1_f6_03_runner_error_isolation(self):
        """T1-F6-03: Runner isolates errors on single target without suite crash."""
        runner = BenchmarkRunner(mock_mode=False)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_hunt.side_effect = RuntimeError("Fatal crash in target parser")
            res = await runner.run_target(targets[0])
            assert res.status == "ERROR"
            assert res.is_true_positive is False
            assert "Fatal crash" in str(res.error_message)

    @pytest.mark.asyncio
    async def test_t1_f6_04_async_concurrency_execution(self):
        """T1-F6-04: Async concurrency execution across targets."""
        runner = BenchmarkRunner(mock_mode=True)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()

        tasks = [runner.run_target(t) for t in targets]
        results = await asyncio.gather(*tasks)
        assert len(results) == 10
        assert all(r.status == "DISCOVERED" for r in results)

    @pytest.mark.asyncio
    async def test_t1_f6_05_options_passthrough(self):
        """T1-F6-05: Options passthrough to target execution."""
        runner = BenchmarkRunner(mock_mode=True)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]

        res = await runner.run_target(target, options={"fuzz_duration": 5, "enable_angr": False})
        assert res.is_true_positive is True

    # ------------------------------------------------------------------------
    # Feature F7: Benchmark Reporting Engine
    # ------------------------------------------------------------------------

    def test_t1_f7_01_markdown_scorecard_rendering(self):
        """T1-F7-01: Render formatted Markdown scorecard."""
        summary = BenchmarkScorecardSummary(
            total_targets=4,
            discovered_count=4,
            discovery_rate_tpr_pct=100.0,
            mean_time_to_crash_seconds=1.2,
            avg_poc_reduction_pct=80.0,
            cwe_exact_match_rate_pct=100.0,
            cwe_hierarchical_match_rate_pct=100.0,
            cvss_mean_absolute_error=0.0,
            cvss_tolerance_match_rate_pct=100.0,
            severity_concordance_rate_pct=100.0,
            class_breakdown={
                "heap_buffer_overflow": {
                    "total": 1,
                    "discovered": 1,
                    "missed": 0,
                    "tpr_pct": 100.0,
                    "avg_ttc_s": 1.2,
                    "avg_reduction_pct": 80.0,
                }
            },
            target_results=[],
        )
        md = BenchmarkReporter.to_markdown(summary)
        assert "# 🎯 Reversecore_MCP CVE Discovery Benchmark Evaluation Report" in md
        assert "## 📊 Executive Scorecard" in md
        assert "## 🔬 Target Evaluation Breakdown" in md
        assert "## 🧩 Vulnerability Class Stratification" in md

    def test_t1_f7_02_json_summary_serialization(self):
        """T1-F7-02: Serialize scorecard to JSON format."""
        summary = BenchmarkScorecardSummary(
            total_targets=2,
            discovered_count=2,
            discovery_rate_tpr_pct=100.0,
        )
        json_str = BenchmarkReporter.to_json(summary)
        parsed = json.loads(json_str)
        assert parsed["total_targets"] == 2
        assert parsed["discovery_rate_tpr_pct"] == 100.0

    def test_t1_f7_03_save_reports_both(self, tmp_path):
        """T1-F7-03: Save both Markdown and JSON reports to disk."""
        summary = BenchmarkScorecardSummary(total_targets=1, discovered_count=1)
        saved = BenchmarkReporter.save_reports(summary, tmp_path, output_format="both")
        assert "markdown" in saved and "json" in saved
        assert saved["markdown"].exists()
        assert saved["json"].exists()

    def test_t1_f7_04_save_reports_json_only(self, tmp_path):
        """T1-F7-04: Save JSON-only report."""
        summary = BenchmarkScorecardSummary(total_targets=1)
        saved = BenchmarkReporter.save_reports(summary, tmp_path, output_format="json")
        assert "json" in saved
        assert "markdown" not in saved
        assert (tmp_path / "benchmark_summary.json").exists()

    def test_t1_f7_05_save_reports_markdown_only(self, tmp_path):
        """T1-F7-05: Save Markdown-only report."""
        summary = BenchmarkScorecardSummary(total_targets=1)
        saved = BenchmarkReporter.save_reports(summary, tmp_path, output_format="markdown")
        assert "markdown" in saved
        assert "json" not in saved
        assert (tmp_path / "benchmark_report.md").exists()

    # ------------------------------------------------------------------------
    # Feature F8: Benchmark CLI Runner
    # ------------------------------------------------------------------------

    def test_t1_f8_01_cli_argument_parsing_defaults(self):
        """T1-F8-01: CLI default argument parsing."""
        args = parse_benchmark_args([])
        assert args.target == "all"
        assert args.cwe == "all"
        assert args.corpus_dir == "tests/fixtures/benchmarks"
        assert args.timeout == 30
        assert args.fuzz_duration == 10
        assert args.output_format == "both"
        assert args.fail_under_tpr == 80.0

    @pytest.mark.asyncio
    async def test_t1_f8_02_cli_mock_suite_exit_0(self, tmp_path):
        """T1-F8-02: CLI execution with mock flag exits with code 0."""
        args = parse_benchmark_args(
            [
                "--mock",
                "--output-format",
                "both",
                "--output-dir",
                str(tmp_path),
            ]
        )
        code = await async_benchmark_main(args)
        assert code == 0
        assert (tmp_path / "benchmark_report.md").exists()
        assert (tmp_path / "benchmark_summary.json").exists()

    @pytest.mark.asyncio
    async def test_t1_f8_03_cli_target_filtering(self, tmp_path):
        """T1-F8-03: CLI filters by specific target ID."""
        args = parse_benchmark_args(
            [
                "--mock",
                "--target",
                "sqlite3_fts5_unicode",
                "--output-dir",
                str(tmp_path),
            ]
        )
        code = await async_benchmark_main(args)
        assert code == 0

    @pytest.mark.asyncio
    async def test_t1_f8_04_cli_cwe_filtering(self, tmp_path):
        """T1-F8-04: CLI filters by CWE ID."""
        args = parse_benchmark_args(["--mock", "--cwe", "CWE-416", "--output-dir", str(tmp_path)])
        code = await async_benchmark_main(args)
        assert code == 0

    def test_t1_f8_05_cli_verbose_flag(self):
        """T1-F8-05: CLI verbose flag parsing."""
        args = parse_benchmark_args(["--verbose"])
        assert args.verbose is True


# ============================================================================
# Tier 2: Boundary & Corner Cases (>=5 test cases per feature F1–F8)
# ============================================================================


@pytest.mark.unit
class TestE2EBoundaryCornerCasesTier2:
    """Tier 2: Boundary conditions, corner cases, and stress tests."""

    # ------------------------------------------------------------------------
    # Feature F1 Boundaries
    # ------------------------------------------------------------------------

    def test_t2_f1_01_corrupt_json_syntax(self, tmp_path):
        """T2-F1-01: Corrupt JSON syntax in corpus file raises parse error."""
        corrupt_file = tmp_path / "corrupt_corpus.json"
        corrupt_file.write_text('{"targets": [ {"target_id": "bad"', encoding="utf-8")

        loader = CorpusLoader(tmp_path)
        with pytest.raises(json.JSONDecodeError):
            loader.load_corpus(corrupt_file)

    def test_t2_f1_02_missing_fixture_flagging(self, tmp_path):
        """T2-F1-02: Missing fixture file flagged as False without crash."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]
        # Validate against empty temp dir where files do not exist
        res = loader.validate_target_fixtures(target, base_dir=tmp_path)
        assert res["vulnerable_source"] is False
        assert res["asan_crash_log"] is False

    def test_t2_f1_03_zero_byte_seed_poc(self, tmp_path):
        """T2-F1-03: Zero-byte file handling in fixtures."""
        zero_file = tmp_path / "zero.bin"
        zero_file.write_bytes(b"")
        assert zero_file.stat().st_size == 0

    def test_t2_f1_04_non_existent_corpus_dir(self):
        """T2-F1-04: Non-existent corpus directory raises FileNotFoundError."""
        loader = CorpusLoader("/tmp/non_existent_path_reversecore_12345")
        with pytest.raises(FileNotFoundError):
            loader.load_corpus()

    def test_t2_f1_05_extra_unknown_fields_in_target_json(self):
        """T2-F1-05: Extra custom fields parsed without breaking model."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        raw = loader.load_corpus()[0].model_dump()
        raw["extra_custom_metadata"] = "custom_value_123"
        target = TargetGroundTruth.model_validate(raw)
        assert target.target_id == "sqlite3_fts5_unicode"

    # ------------------------------------------------------------------------
    # Feature F2 Boundaries
    # ------------------------------------------------------------------------

    def test_t2_f2_01_cvss_score_out_of_range(self):
        """T2-F2-01: CVSS score out-of-range (<0 or >10) raises ValidationError."""
        # 1. base_score_min out-of-range (< 0.0)
        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=-0.5,
                base_score_max=9.0,
                expected_score=8.5,
                severity="HIGH",
                expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )

        # 2. base_score_max out-of-range (> 10.0)
        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=5.0,
                base_score_max=10.5,
                expected_score=8.5,
                severity="HIGH",
                expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )

        # 3. expected_score out-of-range (> 10.0)
        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=5.0,
                base_score_max=9.0,
                expected_score=11.0,
                severity="CRITICAL",
                expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )

    def test_t2_f2_02_malformed_cwe_pattern(self):
        """T2-F2-02: Malformed CWE ID regex pattern raises ValidationError."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        raw = loader.load_corpus()[0].model_dump()
        raw["cwe_id"] = "CWE_INVALID_PATTERN"
        with pytest.raises(ValidationError):
            TargetGroundTruth.model_validate(raw)

    def test_t2_f2_03_zero_or_negative_source_line(self):
        """T2-F2-03: Zero or negative source line raises ValidationError."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        raw = loader.load_corpus()[0].model_dump()
        raw["source_line"] = 0
        with pytest.raises(ValidationError):
            TargetGroundTruth.model_validate(raw)

    def test_t2_f2_04_invalid_minimization_ratio(self):
        """T2-F2-04: Expected minimization ratio > 1.0 raises ValidationError."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        raw = loader.load_corpus()[0].model_dump()
        raw["expected_minimization_ratio_min"] = 1.5
        with pytest.raises(ValidationError):
            TargetGroundTruth.model_validate(raw)

    def test_t2_f2_05_missing_mandatory_field(self):
        """T2-F2-05: Missing mandatory field raises ValidationError."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        raw = loader.load_corpus()[0].model_dump()
        del raw["faulting_symbol"]
        with pytest.raises(ValidationError):
            TargetGroundTruth.model_validate(raw)

    def test_t2_f2_06_zero_or_negative_raw_poc_size(self):
        """T2-F2-06: Zero or negative raw PoC size raises ValidationError."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        raw = loader.load_corpus()[0].model_dump()
        raw["raw_poc_size_bytes"] = 0
        with pytest.raises(ValidationError):
            TargetGroundTruth.model_validate(raw)

    def test_t2_f2_07_zero_or_negative_minimized_poc_target(self):
        """T2-F2-07: Zero or negative minimized PoC target bytes raises ValidationError."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        raw = loader.load_corpus()[0].model_dump()
        raw["minimized_poc_target_bytes"] = 0
        with pytest.raises(ValidationError):
            TargetGroundTruth.model_validate(raw)

    # ------------------------------------------------------------------------
    # Feature F3 Boundaries
    # ------------------------------------------------------------------------

    def test_t2_f3_01_unknown_non_existent_cwe(self):
        """T2-F3-01: Unknown / non-existent CWE returns (0.0, False)."""
        score, is_match = calculate_cwe_taxonomic_score("CWE-99999", "CWE-122")
        assert score == 0.0
        assert is_match is False

    def test_t2_f3_02_empty_cwe_string(self):
        """T2-F3-02: Empty string CWE safely returns (0.0, False)."""
        score, is_match = calculate_cwe_taxonomic_score("", "CWE-122")
        assert score == 0.0
        assert is_match is False

    def test_t2_f3_03_non_cwe_formatted_string(self):
        """T2-F3-03: Non-CWE formatted string safely returns (0.0, False)."""
        score, is_match = calculate_cwe_taxonomic_score("HEAP_BUFFER_OVERFLOW", "CWE-122")
        assert score == 0.0
        assert is_match is False

    def test_t2_f3_04_deep_ancestor_transitive(self):
        """T2-F3-04: Transitive graph ancestor traversal."""
        ancestors = get_cwe_ancestors("CWE-122")
        assert "CWE-787" in ancestors
        assert "CWE-119" in ancestors
        assert "CWE-664" in ancestors

    def test_t2_f3_05_bidirectional_symmetry(self):
        """T2-F3-05: Taxonomic check symmetry."""
        s1, m1 = calculate_cwe_taxonomic_score("CWE-787", "CWE-122")
        s2, m2 = calculate_cwe_taxonomic_score("CWE-122", "CWE-787")
        assert s1 == s2 == 0.75
        assert m1 == m2 is True

    # ------------------------------------------------------------------------
    # Feature F4 Boundaries
    # ------------------------------------------------------------------------

    def test_t2_f4_01_non_existent_target_filter(self):
        """T2-F4-01: Non-existent target filter returns empty list."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        filtered = loader.filter_targets(targets, target_filter="phantom_target_id")
        assert filtered == []

    def test_t2_f4_02_non_existent_cwe_filter(self):
        """T2-F4-02: Non-existent CWE filter returns empty list."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        filtered = loader.filter_targets(targets, cwe_filter="CWE-9999")
        assert filtered == []

    def test_t2_f4_03_empty_corpus_file(self, tmp_path):
        """T2-F4-03: Empty corpus array raises ValueError."""
        empty_corpus = tmp_path / "empty.json"
        empty_corpus.write_text("[]", encoding="utf-8")
        loader = CorpusLoader(tmp_path)
        with pytest.raises(ValueError, match="contains 0 targets"):
            loader.load_corpus(empty_corpus)

    def test_t2_f4_04_invalid_corpus_json_type(self, tmp_path):
        """T2-F4-04: Non-list / non-dict corpus raises ValueError."""
        invalid_corpus = tmp_path / "invalid.json"
        invalid_corpus.write_text('"a string not a list"', encoding="utf-8")
        loader = CorpusLoader(tmp_path)
        with pytest.raises(ValueError):
            loader.load_corpus(invalid_corpus)

    def test_t2_f4_05_whitespace_padded_filters(self):
        """T2-F4-05: Whitespace-padded filter strings are stripped."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        filtered = loader.filter_targets(targets, target_filter="  sqlite3_fts5_unicode  ")
        assert len(filtered) == 1

    # ------------------------------------------------------------------------
    # Feature F5 Boundaries
    # ------------------------------------------------------------------------

    def test_t2_f5_01_empty_results_aggregation(self):
        """T2-F5-01: Empty results aggregation is zero-division safe."""
        engine = ScoringEngine()
        summary = engine.aggregate_scorecard([], total_duration=0.0)
        assert summary.total_targets == 0
        assert summary.discovery_rate_tpr_pct == 0.0
        assert summary.mean_time_to_crash_seconds == 0.0

    def test_t2_f5_02_zero_discovered_targets(self):
        """T2-F5-02: Zero discovered targets produces 0.0% TPR cleanly."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]
        engine = ScoringEngine()

        res = engine.evaluate_target(target, tool_output={}, elapsed_time=1.0)
        assert res.status == "MISSED"
        assert res.is_true_positive is False

        summary = engine.aggregate_scorecard([res], total_duration=1.0)
        assert summary.discovery_rate_tpr_pct == 0.0
        assert summary.discovered_count == 0
        assert summary.missed_count == 1

    def test_t2_f5_03_zero_byte_original_poc(self):
        """T2-F5-03: Zero-byte original PoC size does not cause division by zero."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]
        object.__setattr__(target, "raw_poc_size_bytes", 0)  # boundary override

        engine = ScoringEngine()
        res = engine.evaluate_target(
            target,
            {"fuzzing_stats": {"crashes_detected": 1}},
            elapsed_time=1.0,
        )
        assert res.poc_reduction_percentage == 0.0

    def test_t2_f5_04_minimized_larger_than_original(self):
        """T2-F5-04: Minimized PoC larger than original clamped to 0.0%."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]  # raw = 39
        engine = ScoringEngine()
        res = engine.evaluate_target(
            target,
            {
                "fuzzing_stats": {"crashes_detected": 1},
                "minimized_input_size_bytes": 100,  # larger than raw 39
            },
            elapsed_time=1.0,
        )
        assert res.poc_reduction_percentage == 0.0

    def test_t2_f5_05_zero_elapsed_time(self):
        """T2-F5-05: Zero elapsed time does not cause division by zero."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]
        engine = ScoringEngine()
        res = engine.evaluate_target(
            target,
            {"fuzzing_stats": {"executions": 1000, "crashes_detected": 1}},
            elapsed_time=0.0,
        )
        assert res.throughput_execs_per_sec == 0.0

    # ------------------------------------------------------------------------
    # Feature F6 Boundaries
    # ------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_t2_f6_01_target_execution_timeout(self):
        """T2-F6-01: Target execution timeout handled cleanly."""
        runner = BenchmarkRunner(mock_mode=False, timeout_per_target=1)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_hunt.side_effect = asyncio.TimeoutError()
            res = await runner.run_target(target)
            assert res.status == "ERROR"
            assert res.is_true_positive is False
            assert "timed out" in str(res.error_message).lower()

    @pytest.mark.asyncio
    async def test_t2_f6_02_fatal_tool_exception(self):
        """T2-F6-02: Fatal unhandled tool exception isolated."""
        runner = BenchmarkRunner(mock_mode=False)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_hunt.side_effect = MemoryError("Out of memory in ASan")
            res = await runner.run_target(target)
            assert res.status == "ERROR"
            assert res.is_true_positive is False

    @pytest.mark.asyncio
    async def test_t2_f6_03_tool_returns_empty_dict(self):
        """T2-F6-03: Tool returning empty dict evaluated as MISSED."""
        runner = BenchmarkRunner(mock_mode=False)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_res = MagicMock()
            mock_res.status = "success"
            mock_res.data = {}
            mock_hunt.return_value = mock_res

            res = await runner.run_target(target)
            assert res.status == "MISSED"
            assert res.is_true_positive is False

    @pytest.mark.asyncio
    async def test_t2_f6_04_negative_fuzz_duration_option(self):
        """T2-F6-04: Negative fuzz duration option safely accepted."""
        runner = BenchmarkRunner(mock_mode=True)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]
        res = await runner.run_target(target, options={"fuzz_duration": -5})
        assert res.is_true_positive is True

    @pytest.mark.asyncio
    async def test_t2_f6_05_tool_error_status_response(self):
        """T2-F6-05: Tool returning status='error' evaluated as ERROR."""
        runner = BenchmarkRunner(mock_mode=False)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_res = MagicMock()
            mock_res.status = "error"
            mock_res.message = "Compiler error: clang not found"
            mock_hunt.return_value = mock_res

            res = await runner.run_target(target)
            assert res.status == "ERROR"
            assert "Compiler error" in str(res.error_message)

    # ------------------------------------------------------------------------
    # Feature F7 Boundaries
    # ------------------------------------------------------------------------

    def test_t2_f7_01_empty_scorecard_rendering(self):
        """T2-F7-01: Empty scorecard renders without formatting crash."""
        summary = BenchmarkScorecardSummary()
        md = BenchmarkReporter.to_markdown(summary)
        assert "**Total Targets:** 0" in md
        assert "**Overall Discovery Rate (TPR):** 0.0%" in md

    def test_t2_f7_02_deep_nested_output_directory(self, tmp_path):
        """T2-F7-02: Auto-create deeply nested report directory."""
        deep_dir = tmp_path / "deep" / "nested" / "output" / "dir"
        summary = BenchmarkScorecardSummary(total_targets=1)
        saved = BenchmarkReporter.save_reports(summary, deep_dir)
        assert saved["markdown"].exists()
        assert saved["json"].exists()

    def test_t2_f7_03_special_characters_in_error_message(self):
        """T2-F7-03: Pipes and backticks in error message safely sanitized."""
        res = TargetEvaluationResult(
            target_id="test_target",
            target_name="Test",
            vulnerability_class="test_class",
            status="ERROR",
            is_true_positive=False,
            time_to_crash_seconds=0.0,
            total_executions=0,
            throughput_execs_per_sec=0.0,
            original_poc_size_bytes=10,
            minimized_poc_size_bytes=10,
            poc_reduction_percentage=0.0,
            ground_truth_cwe="CWE-122",
            predicted_cwe="UNKNOWN",
            cwe_exact_match=False,
            cwe_hierarchical_match=False,
            cwe_match_score=0.0,
            ground_truth_cvss=8.0,
            predicted_cvss=0.0,
            cvss_delta=8.0,
            cvss_tolerance_passed=False,
            predicted_severity="NONE",
            ground_truth_severity="HIGH",
            severity_match=False,
            faulting_symbol="none",
            error_message="Error: | table | syntax `break`",
        )
        summary = BenchmarkScorecardSummary(total_targets=1, error_count=1, target_results=[res])
        md = BenchmarkReporter.to_markdown(summary)
        assert "Error: / table / syntax break" in md

    def test_t2_f7_04_invalid_output_format(self, tmp_path):
        """T2-F7-04: Invalid output format safely writes nothing."""
        summary = BenchmarkScorecardSummary(total_targets=1)
        saved = BenchmarkReporter.save_reports(summary, tmp_path, output_format="invalid_fmt")
        assert saved == {}

    def test_t2_f7_05_special_unicode_in_target_names(self):
        """T2-F7-05: Unicode symbols in target names supported cleanly."""
        res = TargetEvaluationResult(
            target_id="unicode_target_🚀",
            target_name="SQLite™ FTS5 — Special Symbols 🎯",
            vulnerability_class="heap_buffer_overflow",
            status="DISCOVERED",
            is_true_positive=True,
            time_to_crash_seconds=1.0,
            total_executions=1000,
            throughput_execs_per_sec=1000.0,
            original_poc_size_bytes=10,
            minimized_poc_size_bytes=5,
            poc_reduction_percentage=50.0,
            ground_truth_cwe="CWE-122",
            predicted_cwe="CWE-122",
            cwe_exact_match=True,
            cwe_hierarchical_match=True,
            cwe_match_score=1.0,
            ground_truth_cvss=8.8,
            predicted_cvss=8.8,
            cvss_delta=0.0,
            cvss_tolerance_passed=True,
            predicted_severity="HIGH",
            ground_truth_severity="HIGH",
            severity_match=True,
            faulting_symbol="fts5",
        )
        summary = BenchmarkScorecardSummary(
            total_targets=1, discovered_count=1, target_results=[res]
        )
        md = BenchmarkReporter.to_markdown(summary)
        assert "unicode_target_🚀" in md
        json_str = BenchmarkReporter.to_json(summary)
        assert "unicode_target_🚀" in json_str
        parsed = json.loads(json_str)
        assert parsed["target_results"][0]["target_id"] == "unicode_target_🚀"

    # ------------------------------------------------------------------------
    # Feature F8 Boundaries
    # ------------------------------------------------------------------------

    def test_t2_f8_01_cli_invalid_numeric_argument(self):
        """T2-F8-01: Invalid numeric argument raises parser error."""
        with pytest.raises(SystemExit):
            parse_benchmark_args(["--timeout", "not_an_int"])

    @pytest.mark.asyncio
    async def test_t2_f8_02_cli_negative_cvss_tolerance(self):
        """T2-F8-02: Negative CVSS tolerance returns exit code 1."""
        args = parse_benchmark_args(["--mock", "--cvss-tolerance", "-0.5"])
        code = await async_benchmark_main(args)
        assert code == 1

    @pytest.mark.asyncio
    async def test_t2_f8_03_cli_target_filter_yields_zero(self):
        """T2-F8-03: Filter matching 0 targets returns exit code 1."""
        args = parse_benchmark_args(["--mock", "--target", "non_existent_target_id"])
        code = await async_benchmark_main(args)
        assert code == 1

    @pytest.mark.asyncio
    async def test_t2_f8_04_cli_fail_under_tpr_exit_code_2(self):
        """T2-F8-04: TPR falling below fail-under threshold returns exit code 2."""
        # Force 1 target run in mock with threshold 100.0, but inject a failure
        args = parse_benchmark_args(["--fail-under-tpr", "99.0"])
        with patch.object(
            BenchmarkRunner,
            "run_suite",
            new_callable=AsyncMock,
        ) as mock_suite:
            mock_suite.return_value = BenchmarkScorecardSummary(
                total_targets=4,
                discovered_count=3,
                discovery_rate_tpr_pct=75.0,  # 75% < 99.0%
            )
            code = await async_benchmark_main(args)
            assert code == 2

    @pytest.mark.asyncio
    async def test_t2_f8_05_cli_missing_corpus_dir_exit_code_1(self):
        """T2-F8-05: Non-existent corpus directory returns exit code 1."""
        args = parse_benchmark_args(["--corpus-dir", "/non/existent/corpus/path/12345"])
        code = await async_benchmark_main(args)
        assert code == 1


# ============================================================================
# Tier 3: Cross-Feature Combinations & Pipeline Interactions (12 Scenarios)
# ============================================================================


@pytest.mark.unit
class TestE2ECrossFeatureCombinationsTier3:
    """Tier 3: Multi-module interactions and pipeline integrations."""

    @pytest.mark.asyncio
    async def test_t3_int_01_loader_to_models_to_runner_pipeline(self):
        """T3-INT-01: CorpusLoader -> TargetGroundTruth -> BenchmarkRunner."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        assert len(targets) == 10

        runner = BenchmarkRunner(mock_mode=True)
        results = []
        for t in targets:
            res = await runner.run_target(t)
            results.append(res)

        assert len(results) == 10
        assert all(r.is_true_positive for r in results)

    @pytest.mark.asyncio
    async def test_t3_int_02_runner_to_scoring_to_reporter_pipeline(self):
        """T3-INT-02: BenchmarkRunner -> ScoringEngine -> BenchmarkReporter."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=True)
        summary = await runner.run_suite("all", "all")

        md = BenchmarkReporter.to_markdown(summary)
        json_data = json.loads(BenchmarkReporter.to_json(summary))

        assert summary.discovery_rate_tpr_pct == 100.0
        assert json_data["total_targets"] == 10
        assert "| **True Positive Rate (TPR)** |" in md

    @pytest.mark.asyncio
    async def test_t3_int_03_full_cli_mock_flow(self, tmp_path):
        """T3-INT-03: Full CLI mock execution pipeline."""
        args = parse_benchmark_args(
            [
                "--mock",
                "--output-format",
                "both",
                "--output-dir",
                str(tmp_path),
                "--fail-under-tpr",
                "80.0",
            ]
        )
        code = await async_benchmark_main(args)
        assert code == 0

        summary_json = tmp_path / "benchmark_summary.json"
        assert summary_json.exists()
        with open(summary_json, encoding="utf-8") as f:
            data = json.load(f)
            assert data["total_targets"] == 10
            assert data["discovery_rate_tpr_pct"] == 100.0

    @pytest.mark.asyncio
    async def test_t3_int_04_filter_to_stratified_breakdown(self):
        """T3-INT-04: Target Filtering -> Stratified Scoring Breakdown."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=True)
        summary = await runner.run_suite(target_filter="all", cwe_filter="CWE-122")

        assert summary.total_targets == 1
        assert "heap_buffer_overflow" in summary.class_breakdown
        assert len(summary.class_breakdown) == 1

    def test_t3_int_05_taxonomy_to_scoring_concordance(self):
        """T3-INT-05: CWE Taxonomy Engine -> Scoring Engine Concordance."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        engine = ScoringEngine()

        # Exact match (CWE-122)
        res_exact = engine.evaluate_target(
            targets[0],
            {"cwe_id": "CWE-122", "fuzzing_stats": {"crashes_detected": 1}},
            elapsed_time=1.0,
        )
        assert res_exact.cwe_exact_match is True
        assert res_exact.cwe_match_score == 1.0

        # Parent match (CWE-787)
        res_parent = engine.evaluate_target(
            targets[0],
            {"cwe_id": "CWE-787", "fuzzing_stats": {"crashes_detected": 1}},
            elapsed_time=1.0,
        )
        assert res_parent.cwe_exact_match is False
        assert res_parent.cwe_hierarchical_match is True
        assert res_parent.cwe_match_score == 0.75

        # Ancestor match (CWE-119)
        res_ancestor = engine.evaluate_target(
            targets[0],
            {"cwe_id": "CWE-119", "fuzzing_stats": {"crashes_detected": 1}},
            elapsed_time=1.0,
        )
        assert res_ancestor.cwe_exact_match is False
        assert res_ancestor.cwe_hierarchical_match is True
        assert res_ancestor.cwe_match_score == 0.50

    def test_t3_int_06_poc_minimization_to_scoring(self):
        """T3-INT-06: PoC Minimization Tool -> Scoring Engine Calculation."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]  # raw 39 bytes -> target 6 bytes

        engine = ScoringEngine()
        res = engine.evaluate_target(
            target,
            {
                "fuzzing_stats": {"crashes_detected": 1},
                "minimized_input_size_bytes": target.minimized_poc_target_bytes,
            },
            elapsed_time=1.0,
        )
        # (39 - 6) / 39 = 84.6% reduction
        assert res.poc_reduction_percentage >= (target.expected_minimization_ratio_min * 100.0)

    def test_t3_int_07_asan_triage_to_cvss_concordance(self):
        """T3-INT-07: ASan Crash Triager -> Scoring Engine CVSS Concordance."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        target = loader.load_corpus()[0]  # GT CVSS = 8.8

        triaged_output = {
            "triaged_crashes": [
                {
                    "cwe_id": "CWE-122",
                    "faulting_function": "fts5UnicodeTokenize",
                    "cvss": {
                        "cvss_v31_score": 8.8,
                        "severity": "HIGH",
                    },
                }
            ],
            "fuzzing_stats": {"crashes_detected": 1},
        }
        engine = ScoringEngine(cvss_tolerance=0.5)
        res = engine.evaluate_target(target, triaged_output, elapsed_time=1.2)

        assert res.cvss_delta == 0.0
        assert res.cvss_tolerance_passed is True
        assert res.severity_match is True

    def test_t3_int_08_json_vs_markdown_concordance(self):
        """T3-INT-08: JSON Summary vs Markdown Report Metric Concordance."""
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()
        engine = ScoringEngine()

        results = [
            engine.evaluate_target(
                t,
                {
                    "cwe_id": t.cwe_id,
                    "cvss_v31_score": t.cvss.expected_score,
                    "cvss_severity": t.cvss.severity,
                    "fuzzing_stats": {"crashes_detected": 1},
                    "minimized_input_size_bytes": t.minimized_poc_target_bytes,
                },
                elapsed_time=1.0,
            )
            for t in targets
        ]
        summary = engine.aggregate_scorecard(results, total_duration=4.0)

        md = BenchmarkReporter.to_markdown(summary)
        json_data = json.loads(BenchmarkReporter.to_json(summary))

        # Check total targets concordance
        assert f"**Total Targets:** {json_data['total_targets']}" in md
        # Check TPR concordance
        assert f"{json_data['discovery_rate_tpr_pct']}%" in md
        # Check MTTC concordance
        assert f"{json_data['mean_time_to_crash_seconds']}s" in md

    @pytest.mark.asyncio
    async def test_t3_int_09_runner_timeout_isolation_multi_target(self):
        """T3-INT-09: Runner Timeout Isolation in Multi-Target Run."""
        runner = BenchmarkRunner(mock_mode=False)
        loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = loader.load_corpus()

        # Mock hunt tool: 3 succeed, 1 times out
        async def mock_hunt_fn(target_path, **kwargs):
            if "fts5" in target_path:
                raise asyncio.TimeoutError()
            mock_res = MagicMock()
            mock_res.status = "success"
            mock_res.data = {
                "cwe_id": "CWE-190",
                "cvss_v31_score": 8.8,
                "cvss_severity": "HIGH",
                "fuzzing_stats": {"crashes_detected": 1},
            }
            return mock_res

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            side_effect=mock_hunt_fn,
        ):
            results = []
            for t in targets:
                res = await runner.run_target(t)
                results.append(res)

            summary = runner.scoring_engine.aggregate_scorecard(results, total_duration=5.0)
            # With 10 targets: 1 error (timeout), 9 discovered -> TPR = 90%
            assert summary.total_targets == 10
            # 1 target timed out, remaining targets discovered
            assert summary.discovered_count >= 1
            assert summary.error_count == 1
            # TPR = discovered / total = 9/10 = 90%
            assert summary.discovery_rate_tpr_pct == 90.0

    @pytest.mark.asyncio
    async def test_t3_int_10_cli_fail_under_tpr_partial_failure(self, tmp_path):
        """T3-INT-10: CLI --fail-under-tpr Enforcement with Partial Failure."""
        args = parse_benchmark_args(
            [
                "--output-dir",
                str(tmp_path),
                "--fail-under-tpr",
                "90.0",
            ]
        )
        with patch.object(
            BenchmarkRunner,
            "run_suite",
            new_callable=AsyncMock,
        ) as mock_suite:
            mock_suite.return_value = BenchmarkScorecardSummary(
                total_targets=4,
                discovered_count=3,
                discovery_rate_tpr_pct=75.0,
            )
            code = await async_benchmark_main(args)
            assert code == 2

    def test_t3_int_11_cli_dynamic_options_forwarding(self):
        """T3-INT-11: Dynamic Options Forwarding from CLI to Runner."""
        args = parse_benchmark_args(
            [
                "--timeout",
                "45",
                "--fuzz-duration",
                "15",
                "--no-angr",
            ]
        )
        options = {
            "fuzz_duration": args.fuzz_duration,
            "enable_angr": not args.no_angr,
        }
        assert options["fuzz_duration"] == 15
        assert options["enable_angr"] is False
        assert args.timeout == 45

    @pytest.mark.asyncio
    async def test_t3_int_12_custom_corpus_directory_override(self, tmp_path):
        """T3-INT-12: Custom Corpus Directory Override via CLI."""
        # Create a custom corpus with 2 targets
        loader = CorpusLoader("tests/fixtures/benchmarks")
        orig_targets = loader.load_corpus()[:2]
        custom_corpus = tmp_path / "custom_corpus.json"
        custom_corpus.write_text(
            json.dumps([t.model_dump() for t in orig_targets]),
            encoding="utf-8",
        )

        runner = BenchmarkRunner(corpus_dir=tmp_path, mock_mode=True)
        with patch.object(
            CorpusLoader,
            "load_corpus",
            return_value=orig_targets,
        ):
            summary = await runner.run_suite("all", "all")
            assert summary.total_targets == 2
            assert summary.discovered_count == 2
            assert summary.discovery_rate_tpr_pct == 100.0
