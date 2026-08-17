"""Unit tests for BenchmarkRunner in reversecore_mcp.benchmarks.runner."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.benchmarks.models import ExecutionOptions
from reversecore_mcp.benchmarks.runner import BenchmarkRunner


@pytest.fixture
def runner_mock() -> BenchmarkRunner:
    """Fixture returning a mock-mode BenchmarkRunner instance."""
    return BenchmarkRunner(
        corpus_dir="tests/fixtures/benchmarks",
        mock_mode=True,
    )


class TestBenchmarkRunner:
    """Comprehensive test suite for BenchmarkRunner async orchestration."""

    @pytest.mark.asyncio
    async def test_run_target_mock_mode(self, runner_mock: BenchmarkRunner) -> None:
        """Test single target execution in offline mock mode."""
        targets = runner_mock.corpus_loader.load_corpus()
        target = targets[0]

        result = await runner_mock.run_target(target)

        assert result.status == "DISCOVERED"
        assert result.is_true_positive is True
        assert result.target_id == target.target_id
        assert result.ground_truth_cwe == target.cwe_id
        assert result.cwe_exact_match is True
        assert result.cvss_tolerance_passed is True

    @pytest.mark.asyncio
    async def test_run_suite_mock_mode_all(self, runner_mock: BenchmarkRunner) -> None:
        """Test full benchmark suite execution across all targets in mock mode."""
        scorecard = await runner_mock.run_suite("all", "all")

        # Corpus now contains 10 targets after expansion
        assert scorecard.total_targets == 10
        assert scorecard.discovered_count == 10
        assert scorecard.discovery_rate_tpr_pct == 100.0
        assert scorecard.cwe_exact_match_rate_pct == 100.0
        assert scorecard.cvss_tolerance_match_rate_pct == 100.0
        assert len(scorecard.target_results) == 10

    @pytest.mark.asyncio
    async def test_run_suite_with_target_filter(self, runner_mock: BenchmarkRunner) -> None:
        """Test suite filtering by target ID."""
        scorecard = await runner_mock.run_suite(target_filter="sqlite3_fts5_unicode")

        assert scorecard.total_targets == 1
        assert scorecard.target_results[0].target_id == "sqlite3_fts5_unicode"

    @pytest.mark.asyncio
    async def test_run_suite_with_cwe_filter(self, runner_mock: BenchmarkRunner) -> None:
        """Test suite filtering by CWE ID."""
        scorecard = await runner_mock.run_suite(cwe_filter="CWE-122")

        # CWE-122 targets in the expanded corpus: sqlite3_fts5_unicode only
        assert scorecard.total_targets == 1
        assert scorecard.target_results[0].ground_truth_cwe == "CWE-122"

    @pytest.mark.asyncio
    async def test_run_suite_with_target_list_filter(self, runner_mock: BenchmarkRunner) -> None:
        """Test suite filtering by list of target IDs."""
        scorecard = await runner_mock.run_suite(
            target_filter=[
                "sqlite3_fts5_unicode",
                "libpng_eXIf_int_overflow",
            ]
        )

        assert scorecard.total_targets == 2
        target_ids = {r.target_id for r in scorecard.target_results}
        assert "sqlite3_fts5_unicode" in target_ids
        assert "libpng_eXIf_int_overflow" in target_ids

    @pytest.mark.asyncio
    async def test_run_suite_no_matching_targets(self, runner_mock: BenchmarkRunner) -> None:
        """Test suite behavior when filters match 0 targets."""
        scorecard = await runner_mock.run_suite(target_filter="non_existent_target_xyz")

        assert scorecard.total_targets == 0
        assert scorecard.discovered_count == 0
        assert scorecard.discovery_rate_tpr_pct == 0.0

    @pytest.mark.asyncio
    async def test_live_mode_success_execution(self) -> None:
        """Test live mode execution when hunt_cve_vulnerabilities succeeds."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=False)
        target = runner.corpus_loader.load_corpus()[0]

        mock_tool_result = MagicMock()
        mock_tool_result.status = "success"
        mock_tool_result.data = {
            "target_function": target.faulting_symbol,
            "cwe_id": target.cwe_id,
            "cvss_v31_score": 8.8,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 3000, "crashes_detected": 1},
            "minimized_input_size_bytes": 10,
        }

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_hunt.return_value = mock_tool_result
            res = await runner.run_target(target)

            assert res.status == "DISCOVERED"
            assert res.is_true_positive is True
            assert res.total_executions == 3000

    @pytest.mark.asyncio
    async def test_live_mode_error_containment(self) -> None:
        """Test that unhandled exception in live tool is caught cleanly."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=False)
        target = runner.corpus_loader.load_corpus()[0]

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
        ) as mock_hunt:
            mock_hunt.side_effect = RuntimeError("Clang compilation failed")
            res = await runner.run_target(target)

            assert res.status == "ERROR"
            assert res.is_true_positive is False
            assert "Clang compilation failed" in str(res.error_message)

    @pytest.mark.asyncio
    async def test_live_mode_timeout_containment(self) -> None:
        """Test timeout containment during long-running live execution."""
        runner = BenchmarkRunner(
            corpus_dir="tests/fixtures/benchmarks",
            mock_mode=False,
            timeout_per_target=1,
        )
        target = runner.corpus_loader.load_corpus()[0]

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
    async def test_parallel_concurrency_execution(self, runner_mock: BenchmarkRunner) -> None:
        """Test suite execution with parallel workers concurrency."""
        options = ExecutionOptions(mock_mode=True, parallel_workers=2)
        scorecard = await runner_mock.run_suite(options=options)

        # Corpus now contains 10 targets after expansion
        assert scorecard.total_targets == 10
        assert scorecard.discovered_count == 10

    @pytest.mark.asyncio
    async def test_options_normalization_dict(self, runner_mock: BenchmarkRunner) -> None:
        """Test options passed as raw dict."""
        target = runner_mock.corpus_loader.load_corpus()[0]
        res = await runner_mock.run_target(
            target, options={"mock": True, "timeout": 15, "fuzz_duration": 2}
        )

        assert res.status == "DISCOVERED"
        assert res.is_true_positive is True
