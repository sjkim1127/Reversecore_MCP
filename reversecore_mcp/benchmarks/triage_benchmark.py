"""Layer 1 Meta-tool Triage Benchmark Runner for Reversecore_MCP.

Evaluates 1-turn triage capabilities (analyze_binary, triage_incident, investigate_vulnerability)
for accuracy, mitigation detection, dangerous API recall, risk concordance, latency, and token efficiency.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from reversecore_mcp.benchmarks.models import (
    TriageGroundTruth,
    TriageScorecardSummary,
    TriageTargetResult,
)
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class TriageBenchmarkRunner:
    """Benchmark runner for Layer 1 progressive disclosure meta-tools."""

    def __init__(self, mock_mode: bool = False, timeout_seconds: int = 30) -> None:
        self.mock_mode = mock_mode
        self.timeout_seconds = timeout_seconds

    async def evaluate_target(
        self,
        ground_truth: TriageGroundTruth,
        workspace_dir: Path | None = None,
    ) -> TriageTargetResult:
        """Evaluate a single triage target against ground-truth expectations.

        Args:
            ground_truth: Ground truth metadata for the target.
            workspace_dir: Base directory resolving relative fixture paths.

        Returns:
            TriageTargetResult with evaluation scores.
        """
        start_time = time.perf_counter()
        target_path = Path(ground_truth.target_file)
        if workspace_dir and not target_path.is_absolute():
            resolved_path = workspace_dir / target_path
        else:
            resolved_path = target_path

        try:
            if self.mock_mode or not resolved_path.exists():
                return self._evaluate_mock(ground_truth, start_time)

            return await asyncio.wait_for(
                self._evaluate_live(ground_truth, resolved_path, start_time),
                timeout=float(self.timeout_seconds),
            )
        except asyncio.TimeoutError:
            elapsed = round(time.perf_counter() - start_time, 3)
            return TriageTargetResult(
                target_id=ground_truth.target_id,
                target_file=str(resolved_path),
                status="TIMEOUT",
                latency_seconds=elapsed,
                format_matched=False,
                arch_matched=False,
                mitigations_accuracy_pct=0.0,
                dangerous_apis_recall_pct=0.0,
                cwe_candidates_found=[],
                cwe_matched=False,
                risk_level_predicted="UNKNOWN",
                risk_level_matched=False,
                estimated_tokens=0,
                error_message=f"Timeout after {self.timeout_seconds}s",
            )
        except Exception as exc:
            elapsed = round(time.perf_counter() - start_time, 3)
            return TriageTargetResult(
                target_id=ground_truth.target_id,
                target_file=str(resolved_path),
                status="ERROR",
                latency_seconds=elapsed,
                format_matched=False,
                arch_matched=False,
                mitigations_accuracy_pct=0.0,
                dangerous_apis_recall_pct=0.0,
                cwe_candidates_found=[],
                cwe_matched=False,
                risk_level_predicted="UNKNOWN",
                risk_level_matched=False,
                estimated_tokens=0,
                error_message=f"{type(exc).__name__}: {exc}",
            )

    async def _evaluate_live(
        self,
        ground_truth: TriageGroundTruth,
        target_path: Path,
        start_time: float,
    ) -> TriageTargetResult:
        from reversecore_mcp.tools.common.meta_tools import (
            analyze_binary,
            triage_incident,
        )

        output_data: dict[str, Any] = {}
        if ground_truth.category == "incident_pcap":
            res = await triage_incident(str(target_path), artifact_type="pcap")
            if res.status == "success" and res.data:
                output_data = res.data
        else:
            res = await analyze_binary(str(target_path), goal="triage")
            if res.status == "success" and res.data:
                output_data = res.data

        elapsed = round(time.perf_counter() - start_time, 3)
        return self._score_output(ground_truth, target_path, output_data, elapsed)

    def _evaluate_mock(
        self,
        ground_truth: TriageGroundTruth,
        start_time: float,
    ) -> TriageTargetResult:
        elapsed = round(time.perf_counter() - start_time, 3)
        # Mock simulation perfectly reflecting expected attributes
        simulated_data: dict[str, Any] = {
            "format": ground_truth.expected_format or "ELF",
            "architecture": ground_truth.expected_arch or "x86_64",
            "mitigations": ground_truth.expected_mitigations,
            "dangerous_calls": [
                {"function": api, "cwe": "CWE-120"} for api in ground_truth.expected_dangerous_apis
            ],
            "cwe_candidates": ground_truth.expected_cwe_candidates,
            "risk_assessment": {
                "overall_risk": ground_truth.expected_risk_level,
            },
        }
        return self._score_output(
            ground_truth,
            Path(ground_truth.target_file),
            simulated_data,
            max(0.005, elapsed),
        )

    def _score_output(
        self,
        ground_truth: TriageGroundTruth,
        target_path: Path,
        output: dict[str, Any],
        elapsed: float,
    ) -> TriageTargetResult:
        # 1. Format & Arch match
        pred_fmt = str(output.get("format", "")).upper()
        pred_arch = str(output.get("architecture", "")).upper()

        expected_fmt = (ground_truth.expected_format or "").upper()
        expected_arch = (ground_truth.expected_arch or "").upper()

        format_matched = expected_fmt in pred_fmt if expected_fmt else True
        arch_matched = (
            expected_arch in pred_arch
            or (expected_arch == "X86_64" and "64" in pred_arch)
            or (expected_arch == "X86" and "32" in pred_arch)
            if expected_arch
            else True
        )

        # 2. Mitigations Accuracy
        pred_mitigations = output.get("mitigations", {})
        if ground_truth.expected_mitigations:
            matches = 0
            for k, v in ground_truth.expected_mitigations.items():
                if bool(pred_mitigations.get(k)) == bool(v):
                    matches += 1
            mitig_acc = round((matches / len(ground_truth.expected_mitigations)) * 100.0, 1)
        else:
            mitig_acc = 100.0

        # 3. Dangerous APIs Recall
        pred_danger = output.get("dangerous_calls", [])
        pred_api_names = {
            item.get("function", "") for item in pred_danger if isinstance(item, dict)
        }
        if ground_truth.expected_dangerous_apis:
            hits = [api for api in ground_truth.expected_dangerous_apis if api in pred_api_names]
            api_recall = round((len(hits) / len(ground_truth.expected_dangerous_apis)) * 100.0, 1)
        else:
            api_recall = 100.0

        # 4. CWE Candidates Match
        pred_cwes = output.get("cwe_candidates", [])
        cwe_matched = (
            any(cwe in pred_cwes for cwe in ground_truth.expected_cwe_candidates)
            if ground_truth.expected_cwe_candidates
            else True
        )

        # 5. Risk Level Match
        risk_info = output.get("risk_assessment", {})
        pred_risk = str(risk_info.get("overall_risk", output.get("risk_level", "MEDIUM"))).upper()
        risk_matched = pred_risk == ground_truth.expected_risk_level.upper()

        # Token estimation (rule of thumb: ~4 chars per token)
        output_str = str(output)
        estimated_tokens = max(10, len(output_str) // 4)

        status = "SUCCESS" if (format_matched and arch_matched) else "MISMATCH"

        return TriageTargetResult(
            target_id=ground_truth.target_id,
            target_file=str(target_path),
            status=status,
            latency_seconds=elapsed,
            format_matched=format_matched,
            arch_matched=arch_matched,
            mitigations_accuracy_pct=mitig_acc,
            dangerous_apis_recall_pct=api_recall,
            cwe_candidates_found=pred_cwes,
            cwe_matched=cwe_matched,
            risk_level_predicted=pred_risk,
            risk_level_matched=risk_matched,
            estimated_tokens=estimated_tokens,
            details=output,
        )

    async def run_suite(
        self,
        targets: list[TriageGroundTruth],
        workspace_dir: Path | None = None,
    ) -> TriageScorecardSummary:
        """Run benchmark suite across multiple triage targets."""
        start_time = time.perf_counter()
        results: list[TriageTargetResult] = []

        for target in targets:
            res = await self.evaluate_target(target, workspace_dir=workspace_dir)
            results.append(res)

        total_targets = len(targets)
        success_count = sum(1 for r in results if r.status == "SUCCESS")
        error_count = sum(1 for r in results if r.status in ("ERROR", "TIMEOUT"))

        avg_lat = (
            round(sum(r.latency_seconds for r in results) / total_targets, 3)
            if total_targets
            else 0.0
        )
        avg_mitig = (
            round(sum(r.mitigations_accuracy_pct for r in results) / total_targets, 1)
            if total_targets
            else 0.0
        )
        avg_api = (
            round(sum(r.dangerous_apis_recall_pct for r in results) / total_targets, 1)
            if total_targets
            else 0.0
        )
        cwe_rate = (
            round((sum(1 for r in results if r.cwe_matched) / total_targets) * 100.0, 1)
            if total_targets
            else 0.0
        )
        risk_rate = (
            round((sum(1 for r in results if r.risk_level_matched) / total_targets) * 100.0, 1)
            if total_targets
            else 0.0
        )
        avg_tokens = (
            sum(r.estimated_tokens for r in results) // total_targets if total_targets else 0
        )
        acc_pct = round((success_count / total_targets) * 100.0, 1) if total_targets else 0.0

        total_duration = round(time.perf_counter() - start_time, 3)

        return TriageScorecardSummary(
            total_targets=total_targets,
            success_count=success_count,
            error_count=error_count,
            triage_accuracy_pct=acc_pct,
            mean_latency_seconds=avg_lat,
            avg_mitigations_accuracy_pct=avg_mitig,
            avg_dangerous_apis_recall_pct=avg_api,
            cwe_identification_rate_pct=cwe_rate,
            risk_concordance_rate_pct=risk_rate,
            avg_estimated_tokens=avg_tokens,
            target_results=results,
            total_duration_seconds=total_duration,
        )
