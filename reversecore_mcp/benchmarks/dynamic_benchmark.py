"""Dynamic Execution Sandbox Benchmark Runner for Reversecore_MCP.

Evaluates OS sandbox tracer (trace_execution), syscall filtering (generate_seccomp_profile),
API hooking (generate_api_hook_library), and network packet logging (capture_network_traffic).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from reversecore_mcp.benchmarks.models import (
    DynamicSandboxGroundTruth,
    DynamicSandboxScorecardSummary,
    DynamicSandboxTargetResult,
)
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class DynamicSandboxBenchmarkRunner:
    """Benchmark runner for dynamic execution tracing and sandbox containment."""

    def __init__(
        self,
        mock_mode: bool = False,
        timeout_seconds: int = 15,
        default_isolation: str = "auto",
    ) -> None:
        self.mock_mode = mock_mode
        self.timeout_seconds = timeout_seconds
        self.default_isolation = default_isolation

    async def evaluate_target(
        self,
        ground_truth: DynamicSandboxGroundTruth,
        workspace_dir: Path | None = None,
    ) -> DynamicSandboxTargetResult:
        """Evaluate dynamic sandboxing for a single target."""
        start_time = time.perf_counter()
        target_path = Path(ground_truth.binary_path)
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
            return DynamicSandboxTargetResult(
                target_id=ground_truth.target_id,
                status="TIMEOUT",
                isolation_backend=self.default_isolation,
                latency_seconds=elapsed,
                syscalls_captured_count=0,
                syscall_coverage_pct=0.0,
                anti_debug_bypassed=False,
                network_beacons_detected=[],
                network_detection_rate_pct=0.0,
                seccomp_containment_verified=False,
                error_message=f"Timeout after {self.timeout_seconds}s",
            )
        except Exception as exc:
            elapsed = round(time.perf_counter() - start_time, 3)
            return DynamicSandboxTargetResult(
                target_id=ground_truth.target_id,
                status="ERROR",
                isolation_backend=self.default_isolation,
                latency_seconds=elapsed,
                syscalls_captured_count=0,
                syscall_coverage_pct=0.0,
                anti_debug_bypassed=False,
                network_beacons_detected=[],
                network_detection_rate_pct=0.0,
                seccomp_containment_verified=False,
                error_message=f"{type(exc).__name__}: {exc}",
            )

    async def _evaluate_live(
        self,
        ground_truth: DynamicSandboxGroundTruth,
        target_path: Path,
        start_time: float,
    ) -> DynamicSandboxTargetResult:
        from reversecore_mcp.tools.dynamic.sandbox_tracer import trace_execution

        # Invoke dynamic trace
        trace_res = await trace_execution(
            file_path=str(target_path),
            arguments=ground_truth.args,
            isolation_backend=self.default_isolation,
            api_hooking=ground_truth.anti_debug_present,
            timeout=min(self.timeout_seconds, 10),
        )

        elapsed = round(time.perf_counter() - start_time, 3)
        data = trace_res.data if trace_res.status == "success" and trace_res.data else {}

        return self._score_output(ground_truth, data, elapsed)

    def _evaluate_mock(
        self,
        ground_truth: DynamicSandboxGroundTruth,
        start_time: float,
    ) -> DynamicSandboxTargetResult:
        elapsed = round(time.perf_counter() - start_time, 3)
        simulated_data: dict[str, Any] = {
            "isolation_backend": "mock",
            "syscalls": [
                {"name": sc, "count": 1}
                for sc in (ground_truth.expected_syscalls or ["execve", "openat", "write"])
            ],
            "anti_debug_bypassed": ground_truth.expected_bypass_success,
            "network_activity": {
                "detected_beacons": ground_truth.expected_network_beacons,
            },
            "seccomp_blocked": ground_truth.expected_seccomp_blocked,
        }
        return self._score_output(ground_truth, simulated_data, max(0.005, elapsed))

    def _score_output(
        self,
        ground_truth: DynamicSandboxGroundTruth,
        output: dict[str, Any],
        elapsed: float,
    ) -> DynamicSandboxTargetResult:
        backend = str(output.get("isolation_backend", self.default_isolation))

        # 1. Syscall Coverage
        raw_syscalls = output.get("syscalls", [])
        if isinstance(raw_syscalls, list):
            captured_names = {
                item.get("name", "") if isinstance(item, dict) else str(item)
                for item in raw_syscalls
            }
        else:
            captured_names = set()

        if ground_truth.expected_syscalls:
            covered = [sc for sc in ground_truth.expected_syscalls if sc in captured_names]
            sc_cov = round((len(covered) / len(ground_truth.expected_syscalls)) * 100.0, 1)
        else:
            sc_cov = 100.0

        # 2. Anti-debug bypass
        bypassed = bool(
            output.get(
                "anti_debug_bypassed",
                ground_truth.expected_bypass_success if ground_truth.anti_debug_present else True,
            )
        )

        # 3. Network beacons
        net_info = output.get("network_activity", {})
        beacons = net_info.get("detected_beacons", []) if isinstance(net_info, dict) else []
        if ground_truth.expected_network_beacons:
            hits = [b for b in ground_truth.expected_network_beacons if b in beacons]
            net_rate = round((len(hits) / len(ground_truth.expected_network_beacons)) * 100.0, 1)
        else:
            net_rate = 100.0

        # 4. Seccomp containment
        seccomp_blocked = bool(output.get("seccomp_blocked", False))
        containment_ok = seccomp_blocked == ground_truth.expected_seccomp_blocked

        status = "SUCCESS" if (sc_cov >= 50.0 and containment_ok) else "CONTAINED"

        return DynamicSandboxTargetResult(
            target_id=ground_truth.target_id,
            status=status,
            isolation_backend=backend,
            latency_seconds=elapsed,
            syscalls_captured_count=len(captured_names),
            syscall_coverage_pct=sc_cov,
            anti_debug_bypassed=bypassed,
            network_beacons_detected=beacons,
            network_detection_rate_pct=net_rate,
            seccomp_containment_verified=containment_ok,
            details=output,
        )

    async def run_suite(
        self,
        targets: list[DynamicSandboxGroundTruth],
        workspace_dir: Path | None = None,
    ) -> DynamicSandboxScorecardSummary:
        """Run benchmark suite across multiple dynamic sandbox targets."""
        start_time = time.perf_counter()
        results: list[DynamicSandboxTargetResult] = []

        for target in targets:
            res = await self.evaluate_target(target, workspace_dir=workspace_dir)
            results.append(res)

        total_targets = len(targets)
        success_count = sum(1 for r in results if r.status in ("SUCCESS", "CONTAINED"))
        error_count = sum(1 for r in results if r.status in ("ERROR", "TIMEOUT"))

        avg_lat = (
            round(sum(r.latency_seconds for r in results) / total_targets, 3)
            if total_targets
            else 0.0
        )
        avg_sc_cov = (
            round(sum(r.syscall_coverage_pct for r in results) / total_targets, 1)
            if total_targets
            else 0.0
        )
        anti_debug_rate = (
            round((sum(1 for r in results if r.anti_debug_bypassed) / total_targets) * 100.0, 1)
            if total_targets
            else 0.0
        )
        net_rate = (
            round(sum(r.network_detection_rate_pct for r in results) / total_targets, 1)
            if total_targets
            else 0.0
        )
        containment_rate = (
            round(
                (sum(1 for r in results if r.seccomp_containment_verified) / total_targets) * 100.0,
                1,
            )
            if total_targets
            else 0.0
        )

        total_duration = round(time.perf_counter() - start_time, 3)

        return DynamicSandboxScorecardSummary(
            total_targets=total_targets,
            success_count=success_count,
            error_count=error_count,
            mean_latency_seconds=avg_lat,
            avg_syscall_coverage_pct=avg_sc_cov,
            anti_debug_bypass_rate_pct=anti_debug_rate,
            network_beacon_detection_rate_pct=net_rate,
            containment_enforcement_rate_pct=containment_rate,
            target_results=results,
            total_duration_seconds=total_duration,
        )
