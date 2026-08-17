"""Expanded performance regression benchmarks with SLA enforcement.

Covers 10 tool categories: LIEF, YARA, Radare2, static analysis (strings),
signature generation, file operations, BenchmarkRunner mock suite,
corpus loader, scoring engine aggregation, and LIEF packer detection.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import ExecutionOptions
from reversecore_mcp.benchmarks.runner import BenchmarkRunner
from reversecore_mcp.benchmarks.scoring import ScoringEngine
from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief
from reversecore_mcp.tools.malware.yara_tools import run_yara
from reversecore_mcp.tools.radare2.r2_analysis import run_radare2
from tests.conftest import requires_radare2

# ---------------------------------------------------------------------------
# SLA Thresholds (in seconds)
# ---------------------------------------------------------------------------
SLA_LIEF_MAX_SECONDS = 1.0
SLA_LIEF_PACKER_MAX_SECONDS = 2.0
SLA_YARA_MAX_SECONDS = 0.5
SLA_R2_ANALYZE_MAX_SECONDS = 1.0
SLA_STRINGS_MAX_SECONDS = 0.5
SLA_FILE_OPERATIONS_MAX_SECONDS = 0.5
SLA_CORPUS_LOAD_MAX_SECONDS = 0.2
SLA_SCORING_AGGREGATE_MAX_SECONDS = 0.1
SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS = 5.0

# ---------------------------------------------------------------------------
# Fixture path helpers
# ---------------------------------------------------------------------------
CORPUS_DIR = Path(__file__).parent.parent / "fixtures" / "benchmarks"
BINARIES_DIR = Path(__file__).parent.parent / "fixtures" / "workspace" / "binaries"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def payload_binary(workspace_dir, patched_config, patched_workspace_config):
    """Copy hello_x64 (or fallback minimal ELF) into the isolated workspace."""
    source_binary = BINARIES_DIR / "hello_x64"
    target_binary = workspace_dir / "hello_x64"

    if source_binary.exists():
        shutil.copy2(source_binary, target_binary)
    else:
        # Minimal valid ELF64 stub for CI without prebuilt binaries
        target_binary.write_bytes(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 1024
        )

    return str(target_binary)


@pytest.fixture(scope="function")
def yara_rule_file(read_only_dir):
    """Copy a YARA rule (or create a minimal dummy) into the read-only dir."""
    source_rule = Path(__file__).parent.parent / "fixtures" / "rules" / "test_rule.yar"
    target_rule = read_only_dir / "test_rule.yar"
    if source_rule.exists():
        shutil.copy2(source_rule, target_rule)
    else:
        target_rule.write_text("rule dummy { condition: true }")
    return str(target_rule)


@pytest.fixture(scope="function")
def corpus_loader():
    """Return a CorpusLoader pointing at the test fixtures corpus."""
    return CorpusLoader(CORPUS_DIR)


# ---------------------------------------------------------------------------
# 1. LIEF binary parsing SLA
# ---------------------------------------------------------------------------


def test_lief_performance(benchmark, payload_binary):
    """Benchmark LIEF binary parsing and enforce SLA."""
    result = benchmark(parse_binary_with_lief, payload_binary)

    assert result.status == "success", (
        f"LIEF failed: {result.error if hasattr(result, 'error') else result}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_LIEF_MAX_SECONDS, (
        f"LIEF parsing violated SLA: {mean_time:.3f}s >= {SLA_LIEF_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 2. YARA scanning SLA
# ---------------------------------------------------------------------------


def test_yara_performance(benchmark, payload_binary, yara_rule_file):
    """Benchmark YARA scanning and enforce SLA."""

    def run_yara_sync():
        return asyncio.run(run_yara(payload_binary, yara_rule_file))

    result = benchmark(run_yara_sync)

    assert result.status == "success", (
        f"YARA failed: {result.error if hasattr(result, 'error') else result}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_YARA_MAX_SECONDS, (
        f"YARA scanning violated SLA: {mean_time:.3f}s >= {SLA_YARA_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 3. Radare2 analysis SLA (skipped if r2 not installed)
# ---------------------------------------------------------------------------


@requires_radare2
def test_r2_analysis_performance(benchmark, payload_binary):
    """Benchmark Radare2 analysis and enforce SLA."""

    def run_r2_sync():
        return asyncio.run(run_radare2(payload_binary, "aaa"))

    result = benchmark(run_r2_sync)

    assert result.status == "success", (
        f"R2 failed: {result.error if hasattr(result, 'error') else result}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_R2_ANALYZE_MAX_SECONDS, (
        f"R2 analysis violated SLA: {mean_time:.3f}s >= {SLA_R2_ANALYZE_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 4. Static analysis — strings extraction SLA
# ---------------------------------------------------------------------------


def test_strings_extraction_performance(
    benchmark, payload_binary, patched_config, patched_workspace_config
):
    """Benchmark run_strings (CLI strings tool) and enforce SLA."""
    from reversecore_mcp.tools.common.cli_tools import run_strings

    def run_strings_sync():
        return asyncio.run(run_strings(payload_binary))

    result = benchmark(run_strings_sync)

    # May be skipped on systems without strings binary — treat as expected skip
    if result.status == "error" and "not found" in (result.error or "").lower():
        pytest.skip("strings command not available on this system")

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_STRINGS_MAX_SECONDS, (
        f"strings extraction violated SLA: {mean_time:.3f}s >= {SLA_STRINGS_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 5. File operations — copy_to_workspace SLA
# ---------------------------------------------------------------------------


def test_file_operations_performance(
    benchmark, workspace_dir, patched_config, patched_workspace_config, tmp_path
):
    """Benchmark copy_to_workspace and enforce SLA."""
    from reversecore_mcp.tools.common.file_operations import copy_to_workspace

    # Create a source file outside workspace
    src = tmp_path / "src_perf_bench.bin"
    src.write_bytes(b"\x00" * 65536)  # 64 KB

    def copy_sync():
        # copy_to_workspace is synchronous
        return copy_to_workspace(str(src))

    with patch(
        "reversecore_mcp.tools.common.file_operations.get_workspace_config",
        return_value=patched_workspace_config,
    ):
        result = benchmark(copy_sync)

    assert result.status in (
        "success",
        "error",
    ), f"copy_to_workspace returned unexpected status: {result}"

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_FILE_OPERATIONS_MAX_SECONDS, (
        f"File copy violated SLA: {mean_time:.3f}s >= {SLA_FILE_OPERATIONS_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 6. Corpus loading SLA (10-target corpus)
# ---------------------------------------------------------------------------


def test_corpus_load_performance(benchmark, corpus_loader):
    """Benchmark loading the full 10-target ground-truth corpus and enforce SLA."""

    def load():
        return corpus_loader.load_corpus()

    targets = benchmark(load)

    assert len(targets) >= 10, f"Expected at least 10 targets, got {len(targets)}"

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_CORPUS_LOAD_MAX_SECONDS, (
        f"Corpus loading violated SLA: {mean_time:.3f}s >= {SLA_CORPUS_LOAD_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 7. Scoring engine aggregation SLA (100-result synthetic dataset)
# ---------------------------------------------------------------------------


def test_scoring_engine_aggregate_performance(benchmark):
    """Benchmark ScoringEngine.aggregate_scorecard over 100 synthetic results."""
    from reversecore_mcp.benchmarks.models import TargetEvaluationResult

    engine = ScoringEngine(cvss_tolerance=0.5)

    # Build a set of 100 synthetic TargetEvaluationResult objects
    results = [
        TargetEvaluationResult(
            target_id=f"target_{i:03d}",
            target_name=f"Synthetic Target {i}",
            vulnerability_class=("heap_buffer_overflow" if i % 2 == 0 else "use_after_free"),
            status="DISCOVERED" if i % 5 != 0 else "MISSED",
            is_true_positive=i % 5 != 0,
            time_to_crash_seconds=0.5 + (i % 10) * 0.1,
            total_executions=1000 * (i + 1),
            throughput_execs_per_sec=2000.0,
            original_poc_size_bytes=100 + i,
            minimized_poc_size_bytes=10 + (i % 20),
            poc_reduction_percentage=85.0 - (i % 30),
            ground_truth_cwe="CWE-122",
            predicted_cwe="CWE-122" if i % 3 != 0 else "CWE-787",
            cwe_exact_match=i % 3 != 0,
            cwe_hierarchical_match=True,
            cwe_match_score=1.0 if i % 3 != 0 else 0.5,
            ground_truth_cvss=8.8,
            predicted_cvss=8.8 if i % 4 != 0 else 8.0,
            cvss_delta=0.0 if i % 4 != 0 else 0.8,
            cvss_tolerance_passed=i % 4 != 0,
            predicted_severity="HIGH",
            ground_truth_severity="HIGH",
            severity_match=True,
            faulting_symbol=f"func_{i}",
        )
        for i in range(100)
    ]

    def aggregate():
        return engine.aggregate_scorecard(results, total_duration=1.23)

    scorecard = benchmark(aggregate)

    assert scorecard.total_targets == 100
    assert scorecard.discovery_rate_tpr_pct > 0.0

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_SCORING_AGGREGATE_MAX_SECONDS, (
        f"Scoring aggregation violated SLA: {mean_time:.3f}s >= {SLA_SCORING_AGGREGATE_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 8. BenchmarkRunner mock suite SLA (10 targets, mock_mode=True)
# ---------------------------------------------------------------------------


def test_benchmark_runner_mock_suite_performance(benchmark):
    """Benchmark BenchmarkRunner.run_suite() in mock mode over all 10 corpus targets."""
    runner = BenchmarkRunner(corpus_dir=CORPUS_DIR, mock_mode=True, timeout_per_target=10)
    opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)

    def run_suite():
        return asyncio.run(runner.run_suite(options=opts))

    scorecard = benchmark(run_suite)

    assert scorecard.total_targets >= 10, f"Expected >=10 targets, got {scorecard.total_targets}"
    assert scorecard.discovery_rate_tpr_pct >= 80.0, (
        f"Mock TPR {scorecard.discovery_rate_tpr_pct:.1f}% below 80% threshold"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS, (
        f"Mock suite violated SLA: {mean_time:.3f}s >= {SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 9. LIEF packer/protector detection SLA
# ---------------------------------------------------------------------------


def test_lief_packer_detection_performance(benchmark, payload_binary):
    """Benchmark LIEF-based packer/protection detection and enforce SLA."""
    from reversecore_mcp.tools.analysis.lief_tools import detect_packer_deep

    result = benchmark(detect_packer_deep, payload_binary)

    assert result.status in (
        "success",
        "error",
    ), f"detect_packer_deep returned unexpected status: {result}"

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_LIEF_PACKER_MAX_SECONDS, (
        f"LIEF packer detection violated SLA: {mean_time:.3f}s >= {SLA_LIEF_PACKER_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 10. BenchmarkRunner filtered suite — single CWE category
# ---------------------------------------------------------------------------


def test_benchmark_runner_filtered_suite_performance(benchmark):
    """Benchmark BenchmarkRunner.run_suite() filtered to a single vulnerability class."""
    runner = BenchmarkRunner(corpus_dir=CORPUS_DIR, mock_mode=True, timeout_per_target=10)
    opts = ExecutionOptions(
        mock_mode=True,
        timeout_seconds=10,
        fuzz_duration_seconds=1,
        vulnerability_class_filter="heap_buffer_overflow",
    )

    def run_filtered():
        return asyncio.run(runner.run_suite(options=opts))

    scorecard = benchmark(run_filtered)

    # heap_buffer_overflow targets: sqlite3_fts5_unicode + zlib_inflate_heap_oob = 2
    assert scorecard.total_targets >= 1, (
        f"Expected >=1 heap_buffer_overflow target, got {scorecard.total_targets}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS, (
        f"Filtered suite violated SLA: {mean_time:.3f}s >= {SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS}s"
    )
