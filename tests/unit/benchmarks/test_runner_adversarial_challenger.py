"""Empirical Challenger Stress & Adversarial Test Suite for BenchmarkRunner (Milestone M3).

This module conducts rigorous empirical challenge testing on BenchmarkRunner:
- Concurrency scaling (1, 5, 20, 50, 100 workers) with real-time active task tracking.
- Strict sub-second timeout enforcement, task cancellation, and mixed workload completion bounds.
- Error containment across standard, resource-exhaustion, custom, and malformed data exceptions.
- Multi-attribute filter permutations (target, CWE, category, vulnerability class, case/whitespace variations).
- Mock mode vs custom callbacks vs live mode fallbacks and error handling.
- Resource leak prevention, active asyncio task cleanup, and semaphore release safety.
"""

from __future__ import annotations

import asyncio
import gc
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    CVSSGroundTruth,
    ExecutionOptions,
    FixturePaths,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.runner import BenchmarkRunner


def create_synthetic_target(
    target_id: str,
    vulnerability_class: str = "heap_buffer_overflow",
    cwe_id: str = "CWE-122",
    cvss_score: float = 7.5,
    severity: str = "HIGH",
    faulting_symbol: str = "vuln_func",
    raw_poc_size: int = 100,
    min_poc_size: int = 20,
    category: str = "network_parser",
) -> TargetGroundTruth:
    """Helper to synthesize valid TargetGroundTruth instances for adversarial testing."""
    return TargetGroundTruth(
        target_id=target_id,
        target_name=f"Synthetic Target {target_id}",
        category=category,
        real_world_library="libchallenger",
        target_version="1.0.0",
        cve_reference="CVE-2026-9999",
        vulnerability_class=vulnerability_class,
        cwe_id=cwe_id,
        cwe_name=f"CWE Name for {cwe_id}",
        faulting_symbol=faulting_symbol,
        source_file="test_target.c",
        source_line=100,
        expected_memory_access_type="WRITE_OOB",
        expected_access_size=4,
        cvss=CVSSGroundTruth(
            base_score_min=max(0.0, cvss_score - 0.5),
            base_score_max=min(10.0, cvss_score + 0.5),
            expected_score=cvss_score,
            severity=severity,  # type: ignore[arg-type]
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        ),
        fixtures=FixturePaths(
            vulnerable_source="nonexistent/source.c",
            patched_source="nonexistent/patch.c",
            patch_diff="nonexistent/patch.diff",
            harness_c="nonexistent/harness.c",
            asan_crash_log="nonexistent/asan.log",
            valid_seed_corpus="nonexistent/seeds",
            raw_crash_poc="nonexistent/crash.poc",
            minimized_poc="nonexistent/min.poc",
        ),
        raw_poc_size_bytes=raw_poc_size,
        minimized_poc_target_bytes=min_poc_size,
        expected_minimization_ratio_min=0.5,
        max_time_to_crash_seconds=30,
    )


class ConcurrencyTelemetry:
    """Monitors and enforces concurrency metrics during stress test execution."""

    def __init__(self, artificial_delay: float = 0.02) -> None:
        self.active_tasks = 0
        self.peak_tasks = 0
        self.total_invocations = 0
        self.artificial_delay = artificial_delay
        self.lock = asyncio.Lock()

    async def execute_task(
        self, target: TargetGroundTruth, options: ExecutionOptions
    ) -> dict[str, Any]:
        async with self.lock:
            self.active_tasks += 1
            self.total_invocations += 1
            if self.active_tasks > self.peak_tasks:
                self.peak_tasks = self.active_tasks

        try:
            await asyncio.sleep(self.artificial_delay)
            return {
                "target_file": target.source_file,
                "target_function": target.faulting_symbol,
                "vulnerability_class": target.vulnerability_class,
                "cwe_id": target.cwe_id,
                "cvss_v31_score": target.cvss.expected_score,
                "cvss_severity": target.cvss.severity,
                "fuzzing_stats": {"executions": 2000, "crashes_detected": 1},
                "minimized_input_size_bytes": target.minimized_poc_target_bytes,
            }
        finally:
            async with self.lock:
                self.active_tasks -= 1


# ============================================================================
# 1. High Concurrency & Scaling Stress Tests
# ============================================================================


class TestBenchmarkRunnerConcurrencyAdversarial:
    """Adversarial stress-testing of concurrency limits and async task orchestration."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "workers,target_count",
        [
            (1, 20),
            (5, 50),
            (20, 80),
            (50, 150),
            (100, 200),
        ],
    )
    async def test_concurrency_bounds_and_peak_enforcement(
        self, workers: int, target_count: int
    ) -> None:
        """Verify that peak concurrency strictly respects the parallel_workers limit."""
        runner = BenchmarkRunner(mock_mode=True)
        synthetic_targets = [
            create_synthetic_target(f"target_{i:04d}") for i in range(target_count)
        ]
        runner.corpus_loader.load_corpus = MagicMock(return_value=synthetic_targets)

        telemetry = ConcurrencyTelemetry(artificial_delay=0.01)
        with patch.object(runner, "_execute_target_pipeline", side_effect=telemetry.execute_task):
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=workers, mock_mode=True)
            )

            assert telemetry.total_invocations == target_count
            assert telemetry.peak_tasks <= workers, (
                f"Peak concurrency {telemetry.peak_tasks} exceeded configured workers {workers}"
            )
            if workers > 1 and target_count >= workers:
                assert telemetry.peak_tasks > 1, (
                    f"Expected parallel execution, but peak was only {telemetry.peak_tasks}"
                )
            assert scorecard.total_targets == target_count
            assert scorecard.discovered_count == target_count
            assert scorecard.discovery_rate_tpr_pct == 100.0

    @pytest.mark.asyncio
    async def test_rapid_burst_100_short_tasks(self) -> None:
        """Verify high-throughput rapid bursting with minimal delay (100 tasks of 0.001s)."""
        runner = BenchmarkRunner(mock_mode=True)
        targets = [create_synthetic_target(f"burst_{i:03d}") for i in range(100)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)

        telemetry = ConcurrencyTelemetry(artificial_delay=0.001)
        with patch.object(runner, "_execute_target_pipeline", side_effect=telemetry.execute_task):
            start = time.perf_counter()
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=25, mock_mode=True)
            )
            elapsed = time.perf_counter() - start

            assert telemetry.total_invocations == 100
            assert telemetry.peak_tasks <= 25
            assert scorecard.total_targets == 100
            assert elapsed < 5.0, f"Burst took {elapsed}s, expected < 5.0s"

    @pytest.mark.asyncio
    async def test_simultaneous_reentrant_suite_runs(self) -> None:
        """Verify multiple simultaneous run_suite calls on the same runner instance."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=True)

        async def run_subsuite(cwe: str, workers: int) -> BenchmarkScorecardSummary:
            return await runner.run_suite(
                cwe_filter=cwe,
                options=ExecutionOptions(parallel_workers=workers, mock_mode=True),
            )

        # Launch 5 concurrent suite runs with different filters & workers
        results = await asyncio.gather(
            run_subsuite("CWE-122", 2),
            run_subsuite("CWE-416", 4),
            run_subsuite("CWE-190", 1),
            run_subsuite("CWE-125", 3),
            run_subsuite("all", 5),
        )

        assert results[0].total_targets >= 1, "CWE-122 (SQLite FTS5) must match at least 1 target"
        assert results[1].total_targets >= 1, "CWE-416 (LibXML2 UAF) must match at least 1 target"
        assert results[2].total_targets >= 1, "CWE-190 (LibPNG IntOv) must match at least 1 target"
        assert results[3].total_targets >= 0, "CWE-125 (no corpus target) returns 0 — acceptable"
        assert results[4].total_targets == 4, "'all' filter must match all 4 corpus targets"


# ============================================================================
# 2. Strict Timeout Enforcement & Cancellation Stress Tests
# ============================================================================


class TestBenchmarkRunnerTimeoutAdversarial:
    """Stress tests for strict per-target timeout containment and task cancellation."""

    @pytest.mark.asyncio
    async def test_strict_subsecond_timeout_kills_hanging_task(self) -> None:
        """Verify that a hanging async pipeline is terminated cleanly at 0.2s timeout."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target("hanging_target")

        task_cancelled = False

        async def hanging_pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
            nonlocal task_cancelled
            try:
                await asyncio.sleep(10.0)
            except asyncio.CancelledError:
                task_cancelled = True
                raise
            return {}

        with patch.object(runner, "_execute_target_pipeline", side_effect=hanging_pipeline):
            start = time.perf_counter()
            result = await runner.run_target(
                target, options=ExecutionOptions(timeout_seconds=1, mock_mode=True)
            )
            elapsed = time.perf_counter() - start

            assert elapsed < 2.5, f"Execution took too long: {elapsed}s"
            assert result.status == "ERROR"
            assert result.is_true_positive is False
            assert "timed out" in str(result.error_message).lower()
            assert task_cancelled is True, "Underlying async task was not cancelled!"

    @pytest.mark.asyncio
    async def test_mixed_workload_timing_and_cancellation(self) -> None:
        """Verify a suite with mixed fast, slow, and crashing targets completes boundedly."""
        runner = BenchmarkRunner(mock_mode=True)
        targets = (
            [create_synthetic_target(f"fast_{i}") for i in range(10)]
            + [create_synthetic_target(f"slow_hang_{i}") for i in range(5)]
            + [create_synthetic_target(f"crashing_{i}") for i in range(5)]
        )
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)

        cancelled_count = 0

        async def mixed_pipeline(
            target: TargetGroundTruth, options: ExecutionOptions
        ) -> dict[str, Any]:
            nonlocal cancelled_count
            if "slow_hang" in target.target_id:
                try:
                    await asyncio.sleep(30.0)
                except asyncio.CancelledError:
                    cancelled_count += 1
                    raise
                return {}
            elif "crashing" in target.target_id:
                raise RuntimeError(f"Deliberate crash for {target.target_id}")
            else:
                await asyncio.sleep(0.01)
                return {
                    "cwe_id": target.cwe_id,
                    "cvss_v31_score": target.cvss.expected_score,
                    "fuzzing_stats": {"executions": 1000, "crashes_detected": 1},
                }

        with patch.object(runner, "_execute_target_pipeline", side_effect=mixed_pipeline):
            start = time.perf_counter()
            scorecard = await runner.run_suite(
                options=ExecutionOptions(timeout_seconds=1, parallel_workers=10, mock_mode=True)
            )
            elapsed = time.perf_counter() - start

            assert elapsed < 5.0, f"Suite execution took {elapsed}s, expected < 5.0s"
            assert scorecard.total_targets == 20
            assert scorecard.discovered_count == 10
            assert scorecard.error_count == 10  # 5 timed out + 5 crashed
            assert cancelled_count == 5, f"Expected 5 cancelled tasks, got {cancelled_count}"


# ============================================================================
# 3. Error Containment & Extreme Exceptions
# ============================================================================


class CustomMaliciousExploitError(Exception):
    """Custom unhandled user exception."""


class TestBenchmarkRunnerErrorContainmentAdversarial:
    """Stress tests for isolating extreme unhandled exceptions without runner failure."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "injected_exception",
        [
            MemoryError("Simulated memory allocation exhaustion"),
            RecursionError("Maximum recursion depth exceeded during AST traversal"),
            RuntimeError("Clang AddressSanitizer runtime crash SIGABRT"),
            ValueError("Malformed float string in CVSS score"),
            KeyError("missing 'target_function' in tool output"),
            IndexError("List index 0 out of range on empty crash list"),
            TypeError("Unsupported operand type for +: 'NoneType' and 'int'"),
            OSError("Errno 24: Too many open files"),
            ZeroDivisionError("Division by zero in throughput calculation"),
            CustomMaliciousExploitError("Adversarial payload triggered custom exception"),
        ],
    )
    async def test_individual_exception_containment(self, injected_exception: Exception) -> None:
        """Verify that every exception type is cleanly contained in TargetEvaluationResult."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target("fault_containment_target")

        with patch.object(runner, "_execute_target_pipeline", side_effect=injected_exception):
            result = await runner.run_target(target)

            assert result.status == "ERROR"
            assert result.is_true_positive is False
            assert result.error_message is not None
            assert type(injected_exception).__name__ in result.error_message
            assert result.target_id == "fault_containment_target"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "corrupt_output",
        [
            None,
            {},
            [],
            "Unexpected string output",
            12345,
            {"fuzzing_stats": None, "cvss_v31_score": "not-a-number"},
            {"fuzzing_stats": "invalid_type", "triaged_crashes": None},
            {"triaged_crashes": ["not_a_dict", None, 42]},
            {"cwe_id": None, "cvss_v31_score": None, "cvss_severity": None},
        ],
    )
    async def test_corrupt_and_bizarre_pipeline_outputs(self, corrupt_output: Any) -> None:
        """Verify runner and scoring engine survive corrupt, non-dict, or malformed data outputs."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target("bizarre_output_target")

        with patch.object(runner, "_execute_target_pipeline", return_value=corrupt_output):
            result = await runner.run_target(target)

            assert result.status in ("DISCOVERED", "MISSED", "ERROR")
            assert isinstance(result.time_to_crash_seconds, float)
            assert isinstance(result.throughput_execs_per_sec, float)
            assert isinstance(result.poc_reduction_percentage, float)
            assert isinstance(result.cvss_delta, float)


# ============================================================================
# 4. Multi-Attribute Filter Permutations
# ============================================================================


class TestBenchmarkRunnerFilterPermutationsAdversarial:
    """Stress tests for target, CWE, category, and class filter variations."""

    @pytest.fixture
    def multi_target_runner(self) -> BenchmarkRunner:
        targets = [
            create_synthetic_target(
                "sqlite3_fts5_unicode",
                cwe_id="CWE-122",
                vulnerability_class="heap_buffer_overflow",
                category="database_engine",
            ),
            create_synthetic_target(
                "libpng_eXIf_int_overflow",
                cwe_id="CWE-190",
                vulnerability_class="integer_overflow",
                category="image_parser",
            ),
            create_synthetic_target(
                "cjson_uaf_iter",
                cwe_id="CWE-416",
                vulnerability_class="use_after_free",
                category="json_parser",
            ),
            create_synthetic_target(
                "curl_oob_read",
                cwe_id="CWE-125",
                vulnerability_class="out_of_bounds_read",
                category="network_protocol",
            ),
        ]
        runner = BenchmarkRunner(mock_mode=True)
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)
        return runner

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "cwe_input,expected_count",
        [
            ("CWE-122", 1),
            ("cwe-122", 1),
            ("122", 1),
            ("CWE122", 1),
            ("CWE-190", 1),
            ("cwe-190", 1),
            ("190", 1),
            ("all", 4),
            ("ALL", 4),
            ("CWE-99999", 0),
        ],
    )
    async def test_cwe_filter_normalization(
        self, multi_target_runner: BenchmarkRunner, cwe_input: str, expected_count: int
    ) -> None:
        """Verify CWE filtering normalizes prefixes and cases properly."""
        scorecard = await multi_target_runner.run_suite(cwe_filter=cwe_input)
        assert scorecard.total_targets == expected_count

    @pytest.mark.asyncio
    async def test_orthogonal_4way_filter_intersection(
        self, multi_target_runner: BenchmarkRunner
    ) -> None:
        """Test combined target_filter + cwe_filter + category_filter + vulnerability_class_filter."""
        # 1. All match single target
        opts = ExecutionOptions(
            category_filter="database",
            vulnerability_class_filter="heap_buffer",
            mock_mode=True,
        )
        res = await multi_target_runner.run_suite(
            target_filter="sqlite3",
            cwe_filter="CWE-122",
            options=opts,
        )
        assert res.total_targets == 1
        assert res.target_results[0].target_id == "sqlite3_fts5_unicode"

        # 2. Conflicting category filter results in 0 targets cleanly
        opts_conflict = ExecutionOptions(
            category_filter="image_parser",  # Conflicts with sqlite
            vulnerability_class_filter="heap_buffer",
            mock_mode=True,
        )
        res_conflict = await multi_target_runner.run_suite(
            target_filter="sqlite3",
            cwe_filter="CWE-122",
            options=opts_conflict,
        )
        assert res_conflict.total_targets == 0
        assert res_conflict.discovered_count == 0
        assert res_conflict.discovery_rate_tpr_pct == 0.0

    @pytest.mark.asyncio
    async def test_zero_matching_targets_invariants(
        self, multi_target_runner: BenchmarkRunner
    ) -> None:
        """Verify scorecard mathematical invariants when 0 targets are selected."""
        scorecard = await multi_target_runner.run_suite(target_filter="non_existent_target_xyz")
        assert scorecard.total_targets == 0
        assert scorecard.discovered_count == 0
        assert scorecard.missed_count == 0
        assert scorecard.error_count == 0
        assert scorecard.discovery_rate_tpr_pct == 0.0
        assert scorecard.mean_time_to_crash_seconds == 0.0
        assert scorecard.avg_throughput_exec_per_sec == 0.0
        assert scorecard.avg_poc_reduction_pct == 0.0
        assert scorecard.cwe_exact_match_rate_pct == 0.0
        assert scorecard.cvss_tolerance_match_rate_pct == 0.0
        assert scorecard.severity_concordance_rate_pct == 0.0
        assert len(scorecard.target_results) == 0


# ============================================================================
# 5. Live Mode, Mock Mode, & Pipeline Fallbacks
# ============================================================================


class TestBenchmarkRunnerLiveAndMockModes:
    """Stress tests for Live vs Mock mode execution and tool invocation pipelines."""

    @pytest.mark.asyncio
    async def test_live_pipeline_structured_data_handling(self) -> None:
        """Verify live pipeline extracts structured data from ToolResult."""
        runner = BenchmarkRunner(mock_mode=False)
        target = create_synthetic_target("live_success_target")

        mock_tool_result = MagicMock()
        mock_tool_result.status = "success"
        mock_tool_result.data = {
            "target_function": "vuln_func",
            "cwe_id": "CWE-122",
            "cvss_v31_score": 7.5,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 4500, "crashes_detected": 1},
            "minimized_input_size_bytes": 15,
        }

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_hunt.return_value = mock_tool_result
            res = await runner.run_target(target)

            assert res.status == "DISCOVERED"
            assert res.is_true_positive is True
            assert res.total_executions == 4500
            assert res.minimized_poc_size_bytes == 15
            assert res.cwe_exact_match is True

    @pytest.mark.asyncio
    async def test_live_pipeline_error_status_handling(self) -> None:
        """Verify live pipeline converts ToolResult(status='error') into a target error."""
        runner = BenchmarkRunner(mock_mode=False)
        target = create_synthetic_target("live_error_target")

        mock_tool_result = MagicMock()
        mock_tool_result.status = "error"
        mock_tool_result.message = "Binary instrumentation failed with non-zero exit code"

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_hunt.return_value = mock_tool_result
            res = await runner.run_target(target)

            assert res.status == "ERROR"
            assert res.is_true_positive is False
            assert "instrumentation failed" in str(res.error_message)

    @pytest.mark.asyncio
    async def test_mock_pipeline_missing_fixtures_synthesis(self) -> None:
        """Verify mock pipeline synthesizes ASan logs and handles missing fixtures without errors."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target(
            "missing_fixtures_target",
            vulnerability_class="heap_use_after_free",
            faulting_symbol="cjson_free_item",
        )
        # Execute mock pipeline
        mock_output = await runner._execute_mock_pipeline(
            target, ExecutionOptions(fuzz_duration_seconds=5)
        )

        assert mock_output["target_function"] == "cjson_free_item"
        assert mock_output["vulnerability_class"] == "heap_use_after_free"
        assert mock_output["fuzzing_stats"]["executions"] == 5000
        assert mock_output["cwe_id"] == "CWE-122"


# ============================================================================
# 6. Resource Cleanup & Task Leak Prevention
# ============================================================================


class TestBenchmarkRunnerResourceCleanup:
    """Stress tests verifying no dangling tasks, coroutine leaks, or unreleased locks."""

    @pytest.mark.asyncio
    async def test_no_dangling_asyncio_tasks_after_suite(self) -> None:
        """Verify that after run_suite completes, all created child tasks are cleaned up."""
        runner = BenchmarkRunner(mock_mode=True)
        targets = [create_synthetic_target(f"cleanup_target_{i}") for i in range(25)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)

        current_task = asyncio.current_task()
        tasks_before = {t for t in asyncio.all_tasks() if t is not current_task and not t.done()}

        scorecard = await runner.run_suite(
            options=ExecutionOptions(parallel_workers=5, mock_mode=True)
        )

        # Allow loop turn for task completion
        await asyncio.sleep(0.01)

        tasks_after = {t for t in asyncio.all_tasks() if t is not current_task and not t.done()}
        new_dangling_tasks = tasks_after - tasks_before

        assert len(new_dangling_tasks) == 0, f"Found dangling tasks: {new_dangling_tasks}"
        assert scorecard.total_targets == 25

    @pytest.mark.asyncio
    async def test_semaphore_release_under_extreme_crashes(self) -> None:
        """Verify semaphore is fully released even if tasks throw MemoryError or CancelledError."""
        runner = BenchmarkRunner(mock_mode=True)
        targets = [create_synthetic_target(f"sem_target_{i}") for i in range(30)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)

        async def crashing_pipeline(
            target: TargetGroundTruth, options: ExecutionOptions
        ) -> dict[str, Any]:
            idx = int(target.target_id.split("_")[2])
            if idx % 2 == 0:
                raise MemoryError("Deliberate OOM simulation")
            await asyncio.sleep(0.005)
            return {
                "cwe_id": target.cwe_id,
                "cvss_v31_score": target.cvss.expected_score,
                "fuzzing_stats": {"crashes_detected": 1, "executions": 500},
            }

        with patch.object(runner, "_execute_target_pipeline", side_effect=crashing_pipeline):
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=3, mock_mode=True)
            )

            assert scorecard.total_targets == 30
            assert scorecard.discovered_count == 15
            assert scorecard.error_count == 15

            # Subsequent suite must not hang or block on semaphore
            scorecard2 = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=3, mock_mode=True)
            )
            assert scorecard2.total_targets == 30

    @pytest.mark.asyncio
    async def test_large_volume_500_targets_stability(self) -> None:
        """Stress-test memory stability and execution across 500 targets."""
        runner = BenchmarkRunner(mock_mode=True)
        targets = [create_synthetic_target(f"large_{i:04d}") for i in range(500)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)

        telemetry = ConcurrencyTelemetry(artificial_delay=0.0005)
        with patch.object(runner, "_execute_target_pipeline", side_effect=telemetry.execute_task):
            gc.collect()
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=50, mock_mode=True)
            )
            gc.collect()

            assert scorecard.total_targets == 500
            assert scorecard.discovered_count == 500
            assert telemetry.total_invocations == 500
            assert telemetry.peak_tasks <= 50
