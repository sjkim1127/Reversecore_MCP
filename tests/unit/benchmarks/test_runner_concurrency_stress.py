"""Adversarial stress and concurrency test suite for BenchmarkRunner.

Tests:
1. Concurrency limit enforcement (parallel_workers=1, 10, 50, and 500-target load) with active task telemetry.
2. Timeout containment & enforcement (sub-second, slow mock/live, mixed suites).
3. Fault containment under injected crashes (RuntimeError, MemoryError, KeyError, malformed data, corrupt fixtures).
4. Filter permutation stress (non-existent, empty, whitespace, wildcard, mixed valid/invalid, CWE normalizations).
5. Re-entrancy and race-condition safety under simultaneous suite runs.
6. Options normalization and validation bounds.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from reversecore_mcp.benchmarks.models import (
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
) -> TargetGroundTruth:
    """Helper to generate valid synthetic TargetGroundTruth models."""
    return TargetGroundTruth(
        target_id=target_id,
        target_name=f"Synthetic Target {target_id}",
        category="testing_harness",
        real_world_library="libtest",
        target_version="1.0.0",
        cve_reference="CVE-2026-0001",
        vulnerability_class=vulnerability_class,
        cwe_id=cwe_id,
        cwe_name=f"Name for {cwe_id}",
        faulting_symbol=faulting_symbol,
        source_file="test_target.c",
        source_line=42,
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


class ConcurrencyTracker:
    """Tracks active concurrent async executions and peak concurrency."""

    def __init__(self, delay: float = 0.02) -> None:
        self.active_count = 0
        self.peak_count = 0
        self.total_invocations = 0
        self.delay = delay
        self.lock = asyncio.Lock()

    async def execute_task(
        self, target: TargetGroundTruth, options: ExecutionOptions
    ) -> dict[str, Any]:
        async with self.lock:
            self.active_count += 1
            self.total_invocations += 1
            if self.active_count > self.peak_count:
                self.peak_count = self.active_count

        try:
            await asyncio.sleep(self.delay)
            return {
                "target_file": target.source_file,
                "target_function": target.faulting_symbol,
                "vulnerability_class": target.vulnerability_class,
                "cwe_id": target.cwe_id,
                "cvss_v31_score": target.cvss.expected_score,
                "cvss_severity": target.cvss.severity,
                "fuzzing_stats": {"executions": 1000, "crashes_detected": 1},
                "minimized_input_size_bytes": target.minimized_poc_target_bytes,
            }
        finally:
            async with self.lock:
                self.active_count -= 1


class TestBenchmarkRunnerConcurrencyStress:
    """Stress tests for runner async concurrency bounds and task orchestration."""

    @pytest.mark.asyncio
    async def test_concurrency_workers_1_strict_serial(self) -> None:
        """Verify that parallel_workers=1 strictly enforces single-task serialization."""
        runner = BenchmarkRunner(mock_mode=True)
        synthetic_targets = [create_synthetic_target(f"target_{i:02d}") for i in range(15)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=synthetic_targets)

        tracker = ConcurrencyTracker(delay=0.01)
        with patch.object(runner, "_execute_target_pipeline", side_effect=tracker.execute_task):
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=1, mock_mode=True)
            )

            assert tracker.total_invocations == 15
            assert tracker.peak_count == 1, (
                f"Peak concurrency exceeded limit 1: got {tracker.peak_count}"
            )
            assert scorecard.total_targets == 15
            assert scorecard.discovered_count == 15
            assert scorecard.discovery_rate_tpr_pct == 100.0

    @pytest.mark.asyncio
    async def test_concurrency_workers_10_bounded(self) -> None:
        """Verify that parallel_workers=10 runs concurrently but never exceeds 10."""
        runner = BenchmarkRunner(mock_mode=True)
        synthetic_targets = [create_synthetic_target(f"target_{i:02d}") for i in range(35)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=synthetic_targets)

        tracker = ConcurrencyTracker(delay=0.03)
        with patch.object(runner, "_execute_target_pipeline", side_effect=tracker.execute_task):
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=10, mock_mode=True)
            )

            assert tracker.total_invocations == 35
            assert 1 < tracker.peak_count <= 10, (
                f"Peak concurrency was {tracker.peak_count}, expected <= 10 and > 1"
            )
            assert scorecard.total_targets == 35
            assert scorecard.discovered_count == 35

    @pytest.mark.asyncio
    async def test_concurrency_workers_50_heavy_load(self) -> None:
        """Verify that parallel_workers=50 scales up under 100-target load without exceeding 50."""
        runner = BenchmarkRunner(mock_mode=True)
        synthetic_targets = [create_synthetic_target(f"target_{i:03d}") for i in range(100)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=synthetic_targets)

        tracker = ConcurrencyTracker(delay=0.02)
        with patch.object(runner, "_execute_target_pipeline", side_effect=tracker.execute_task):
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=50, mock_mode=True)
            )

            assert tracker.total_invocations == 100
            assert 1 < tracker.peak_count <= 50, (
                f"Peak concurrency was {tracker.peak_count}, expected <= 50"
            )
            assert scorecard.total_targets == 100
            assert scorecard.discovered_count == 100

    @pytest.mark.asyncio
    async def test_concurrency_validation_rejects_zero_or_negative_workers(self) -> None:
        """Verify ExecutionOptions schema validation rejects parallel_workers < 1."""
        runner = BenchmarkRunner(mock_mode=True)

        with pytest.raises(ValidationError):
            runner._normalize_options({"parallel_workers": 0})

        with pytest.raises(ValidationError):
            runner._normalize_options({"parallel_workers": -5})

    @pytest.mark.asyncio
    async def test_concurrent_reentrant_suite_runs(self) -> None:
        """Verify that multiple simultaneous run_suite calls on the same runner do not corrupt state."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=True)

        async def run_one(cwe: str) -> Any:
            return await runner.run_suite(
                cwe_filter=cwe, options={"parallel_workers": 2, "mock": True}
            )

        # Run 4 suites concurrently on the same runner instance
        results = await asyncio.gather(
            run_one("CWE-122"),
            run_one("CWE-416"),
            run_one("CWE-190"),
            run_one("all"),
        )

        assert results[0].total_targets >= 1
        assert results[1].total_targets >= 1
        assert results[2].total_targets >= 1
        assert results[3].total_targets == 10


class TestBenchmarkRunnerTimeoutStress:
    """Stress tests for execution timeout enforcement and containment."""

    @pytest.mark.asyncio
    async def test_subsecond_target_timeout_containment(self) -> None:
        """Verify that a hanging target execution is cleanly terminated at sub-second timeout."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target("slow_target")

        async def hanging_pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
            await asyncio.sleep(5.0)
            return {}

        with patch.object(runner, "_execute_target_pipeline", side_effect=hanging_pipeline):
            start = time.perf_counter()
            result = await runner.run_target(
                target, options=ExecutionOptions(timeout_seconds=1, mock_mode=True)
            )
            duration = time.perf_counter() - start

            assert duration < 2.0, f"Execution took too long ({duration}s), timeout not enforced"
            assert result.status == "ERROR"
            assert result.is_true_positive is False
            assert "timed out" in str(result.error_message).lower()
            assert result.target_id == "slow_target"

    @pytest.mark.asyncio
    async def test_mixed_fast_and_slow_targets_in_suite(self) -> None:
        """Verify suite finishes in bounded time with mixed fast and timed-out targets."""
        runner = BenchmarkRunner(mock_mode=True)
        targets = [
            create_synthetic_target("fast_1"),
            create_synthetic_target("slow_1"),
            create_synthetic_target("fast_2"),
            create_synthetic_target("slow_2"),
            create_synthetic_target("fast_3"),
        ]
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)

        async def mixed_pipeline(
            target: TargetGroundTruth, options: ExecutionOptions
        ) -> dict[str, Any]:
            if "slow" in target.target_id:
                await asyncio.sleep(10.0)
                return {}
            await asyncio.sleep(0.01)
            return {
                "cwe_id": target.cwe_id,
                "cvss_v31_score": target.cvss.expected_score,
                "fuzzing_stats": {"crashes_detected": 1, "executions": 500},
            }

        with patch.object(runner, "_execute_target_pipeline", side_effect=mixed_pipeline):
            start = time.perf_counter()
            scorecard = await runner.run_suite(
                options=ExecutionOptions(timeout_seconds=1, parallel_workers=5, mock_mode=True)
            )
            total_duration = time.perf_counter() - start

            assert total_duration < 3.0, f"Suite took {total_duration}s, should be < 3.0s"
            assert scorecard.total_targets == 5
            assert scorecard.discovered_count == 3
            assert scorecard.error_count == 2
            assert scorecard.discovery_rate_tpr_pct == 60.0


class TestBenchmarkRunnerFaultContainment:
    """Stress tests for fault isolation under diverse injected exceptions."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "injected_exception",
        [
            RuntimeError("Clang ASan compilation failed with SIGSEGV"),
            MemoryError("Concolic execution exceeded 8GB limit"),
            KeyError("missing 'cwe_id' key in tool dictionary"),
            ValueError("Invalid integer literal for fuzzing throughput"),
            OSError("Too many open files in system descriptor table"),
            TypeError("NoneType object has no attribute 'items'"),
            ZeroDivisionError("division by zero in custom metric calculator"),
        ],
    )
    async def test_exception_isolation_per_target(self, injected_exception: Exception) -> None:
        """Verify that individual exceptions do not crash run_target or abort execution."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target("fault_target")

        with patch.object(runner, "_execute_target_pipeline", side_effect=injected_exception):
            result = await runner.run_target(target)

            assert result.status == "ERROR"
            assert result.is_true_positive is False
            assert result.error_message is not None
            assert type(injected_exception).__name__ in result.error_message

    @pytest.mark.asyncio
    async def test_suite_resilience_under_intermittent_crashes(self) -> None:
        """Verify run_suite completes and isolates faults across a mixed healthy/crashing batch."""
        runner = BenchmarkRunner(mock_mode=True)
        targets = [create_synthetic_target(f"target_{i}") for i in range(10)]
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)

        async def flaky_pipeline(
            target: TargetGroundTruth, options: ExecutionOptions
        ) -> dict[str, Any]:
            idx = int(target.target_id.split("_")[1])
            if idx % 3 == 0:
                raise RuntimeError(f"Simulated pipeline crash for {target.target_id}")
            return {
                "cwe_id": target.cwe_id,
                "cvss_v31_score": target.cvss.expected_score,
                "fuzzing_stats": {"crashes_detected": 1, "executions": 1000},
            }

        with patch.object(runner, "_execute_target_pipeline", side_effect=flaky_pipeline):
            scorecard = await runner.run_suite(
                options=ExecutionOptions(parallel_workers=4, mock_mode=True)
            )

            # Indexes 0, 3, 6, 9 (4 targets) should fail; 1, 2, 4, 5, 7, 8 (6 targets) should succeed
            assert scorecard.total_targets == 10
            assert scorecard.discovered_count == 6
            assert scorecard.error_count == 4
            assert scorecard.discovery_rate_tpr_pct == 60.0

    @pytest.mark.asyncio
    async def test_resilience_to_non_dict_and_corrupt_outputs(self) -> None:
        """Verify scoring handles malformed tool outputs (None, empty, corrupt types) without crashing."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target("corrupt_output_target")

        async def corrupt_pipeline(*args: Any, **kwargs: Any) -> Any:
            return {
                "fuzzing_stats": "not_a_dict",
                "cvss_v31_score": "not_a_float",
                "minimized_input_size_bytes": "invalid",
            }

        with patch.object(runner, "_execute_target_pipeline", side_effect=corrupt_pipeline):
            result = await runner.run_target(target)
            assert result.status in ("DISCOVERED", "MISSED", "ERROR")
            assert isinstance(result.poc_reduction_percentage, float)
            assert isinstance(result.throughput_execs_per_sec, float)

    @pytest.mark.asyncio
    async def test_missing_fixture_fallback_synthesis(self) -> None:
        """Verify that targets referencing missing fixture files synthesize ASan logs gracefully."""
        runner = BenchmarkRunner(mock_mode=True)
        target = create_synthetic_target("missing_fixtures_target")
        # Run mock pipeline which reads asan log and poc sizes
        output = await runner._execute_mock_pipeline(target, ExecutionOptions())
        assert output["vulnerability_class"] == "heap_buffer_overflow"
        assert output["target_function"] == "vuln_func"
        assert output["original_input_size_bytes"] == 100
        assert output["minimized_input_size_bytes"] == 20


class TestBenchmarkRunnerFilterStress:
    """Stress tests for target, CWE, category, and class filter variations."""

    @pytest.fixture
    def corpus_runner(self) -> BenchmarkRunner:
        targets = [
            create_synthetic_target(
                "sqlite3_fts5_unicode", cwe_id="CWE-122", vulnerability_class="heap_buffer_overflow"
            ),
            create_synthetic_target(
                "libpng_eXIf_int_overflow", cwe_id="CWE-190", vulnerability_class="integer_overflow"
            ),
            create_synthetic_target(
                "cjson_uaf_iter", cwe_id="CWE-416", vulnerability_class="use_after_free"
            ),
            create_synthetic_target(
                "curl_oob_read", cwe_id="CWE-125", vulnerability_class="out_of_bounds_read"
            ),
            # 6 additional targets added during corpus expansion
            create_synthetic_target(
                "openssl_bn_infinite_loop", cwe_id="CWE-835", vulnerability_class="infinite_loop"
            ),
            create_synthetic_target(
                "zlib_inflate_heap_oob",
                cwe_id="CWE-787",
                vulnerability_class="heap_buffer_overflow",
            ),
            create_synthetic_target(
                "curl_cookie_leak_info",
                cwe_id="CWE-200",
                vulnerability_class="information_exposure",
            ),
            create_synthetic_target(
                "ffmpeg_hevc_oob_read", cwe_id="CWE-125", vulnerability_class="out_of_bounds_read"
            ),
            create_synthetic_target(
                "php_spl_type_confusion", cwe_id="CWE-763", vulnerability_class="type_confusion"
            ),
            create_synthetic_target(
                "expat_entity_int_overflow",
                cwe_id="CWE-190",
                vulnerability_class="integer_overflow",
            ),
        ]
        runner = BenchmarkRunner(mock_mode=True)
        runner.corpus_loader.load_corpus = MagicMock(return_value=targets)
        return runner

    @pytest.mark.asyncio
    async def test_non_existent_filters(self, corpus_runner: BenchmarkRunner) -> None:
        """Test non-existent string and list filters return 0 targets cleanly."""
        res1 = await corpus_runner.run_suite(target_filter="non_existent_xyz")
        assert res1.total_targets == 0
        assert res1.discovered_count == 0

        res2 = await corpus_runner.run_suite(target_filter=["fake_1", "fake_2"])
        assert res2.total_targets == 0

        res3 = await corpus_runner.run_suite(cwe_filter="CWE-99999")
        assert res3.total_targets == 0

        res4 = await corpus_runner.run_suite(cwe_filter=["CWE-88888", "CWE-77777"])
        assert res4.total_targets == 0

    @pytest.mark.asyncio
    async def test_empty_filters(self, corpus_runner: BenchmarkRunner) -> None:
        """Test that empty string and empty lists return all targets."""
        res_empty_str = await corpus_runner.run_suite(target_filter="", cwe_filter="")
        assert res_empty_str.total_targets == 10

        res_empty_list = await corpus_runner.run_suite(target_filter=[], cwe_filter=[])
        assert res_empty_list.total_targets == 10

        res_ws_list = await corpus_runner.run_suite(
            target_filter=["", "   "], cwe_filter=["", "   "]
        )
        assert res_ws_list.total_targets == 10

    @pytest.mark.asyncio
    async def test_wildcard_and_case_insensitive_filters(
        self, corpus_runner: BenchmarkRunner
    ) -> None:
        """Test wildcard 'ALL' in various casings and case-insensitive substring filters."""
        res_all_upper = await corpus_runner.run_suite(target_filter="ALL", cwe_filter="ALL")
        assert res_all_upper.total_targets == 10

        res_sub = await corpus_runner.run_suite(target_filter="SQLITE")
        assert res_sub.total_targets == 1
        assert res_sub.target_results[0].target_id == "sqlite3_fts5_unicode"

        res_cwe = await corpus_runner.run_suite(cwe_filter="cwe-122")
        assert res_cwe.total_targets == 1
        assert res_cwe.target_results[0].ground_truth_cwe == "CWE-122"

        res_cwe_num = await corpus_runner.run_suite(cwe_filter="122")
        assert res_cwe_num.total_targets == 1

    @pytest.mark.asyncio
    async def test_mixed_valid_and_invalid_target_list(
        self, corpus_runner: BenchmarkRunner
    ) -> None:
        """Test target list containing mixed valid and invalid IDs."""
        res = await corpus_runner.run_suite(
            target_filter=["sqlite3_fts5_unicode", "non_existent_target", "curl_oob_read", ""]
        )
        assert res.total_targets == 2
        matched_ids = {r.target_id for r in res.target_results}
        assert matched_ids == {"sqlite3_fts5_unicode", "curl_oob_read"}

    @pytest.mark.asyncio
    async def test_execution_options_category_and_class_filters(
        self, corpus_runner: BenchmarkRunner
    ) -> None:
        """Test filtering via ExecutionOptions category and vulnerability class fields."""
        opts = ExecutionOptions(
            vulnerability_class_filter="use_after_free",
            mock_mode=True,
        )
        res = await corpus_runner.run_suite(options=opts)
        assert res.total_targets == 1
        assert res.target_results[0].target_id == "cjson_uaf_iter"

        # Non-matching vulnerability class
        opts_nomatch = ExecutionOptions(
            vulnerability_class_filter="race_condition_oob",
            mock_mode=True,
        )
        res_nomatch = await corpus_runner.run_suite(options=opts_nomatch)
        assert res_nomatch.total_targets == 0


class TestBenchmarkRunnerOptionsNormalization:
    """Stress tests for options normalization, tolerance propagation, and types."""

    def test_normalize_options_with_none(self) -> None:
        runner = BenchmarkRunner(mock_mode=True, timeout_per_target=45)
        opts = runner._normalize_options(None)
        assert opts.mock_mode is True
        assert opts.timeout_seconds == 45

    def test_normalize_options_with_dict_aliases(self) -> None:
        runner = BenchmarkRunner(mock_mode=False, timeout_per_target=30)
        opts = runner._normalize_options(
            {
                "mock": True,
                "timeout": 20,
                "fuzz_duration": 5,
                "parallel_workers": 4,
            }
        )
        assert opts.mock_mode is True
        assert opts.timeout_seconds == 20
        assert opts.fuzz_duration_seconds == 5
        assert opts.parallel_workers == 4

    def test_normalize_options_invalid_type_raises_type_error(self) -> None:
        runner = BenchmarkRunner()
        with pytest.raises(TypeError):
            runner._normalize_options(["invalid_list"])  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_scoring_engine_tolerance_updated_from_options(self) -> None:
        runner = BenchmarkRunner(mock_mode=True)
        assert runner.scoring_engine.cvss_tolerance == 0.5

        # Execute with custom tolerance
        await runner.run_suite(
            "all",
            options=ExecutionOptions(cvss_tolerance=1.5, mock_mode=True),
        )
        assert runner.scoring_engine.cvss_tolerance == 1.5
