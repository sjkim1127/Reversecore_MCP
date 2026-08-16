"""
End-to-End Real-World Application Integration Benchmark Test Suite (Tier 4).

Validates the full automated 0-Day/N-Day vulnerability benchmark evaluation pipeline
across 4 real-world C/C++ targets (SQLite FTS5, LibPNG, LibXML2, LibArchive),
programmatic runner/reporter execution, CLI runner execution with mock mode,
adversarial threshold enforcement (exit codes 0/1/2), and report artifact generation.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.result import failure, success
from reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline import (
    generate_cve_advisory_markdown,
)

try:
    from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
    from reversecore_mcp.benchmarks.models import (
        BenchmarkScorecardSummary,
        TargetEvaluationResult,
        TargetGroundTruth,
    )
    from reversecore_mcp.benchmarks.reporter import BenchmarkReporter
    from reversecore_mcp.benchmarks.runner import BenchmarkRunner
    from reversecore_mcp.benchmarks.scoring import ScoringEngine
    from reversecore_mcp.benchmarks.taxonomy import calculate_cwe_taxonomic_score

    BENCHMARKS_AVAILABLE = True
except ImportError:
    BENCHMARKS_AVAILABLE = False
    CorpusLoader = Any  # type: ignore[misc, assignment]
    BenchmarkScorecardSummary = Any  # type: ignore[misc, assignment]
    TargetEvaluationResult = Any  # type: ignore[misc, assignment]
    TargetGroundTruth = Any  # type: ignore[misc, assignment]
    BenchmarkReporter = Any  # type: ignore[misc, assignment]
    BenchmarkRunner = Any  # type: ignore[misc, assignment]
    ScoringEngine = Any  # type: ignore[misc, assignment]
    calculate_cwe_taxonomic_score = Any  # type: ignore[misc, assignment]

try:
    from scripts.run_cve_benchmark import async_main, parse_args

    CLI_AVAILABLE = True
except ImportError:
    CLI_AVAILABLE = False
    async_main = None  # type: ignore[assignment]
    parse_args = None  # type: ignore[assignment]


pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

CORPUS_JSON_PATH = (
    Path(__file__).parents[2] / "tests" / "fixtures" / "benchmarks" / "ground_truth_corpus.json"
)
CORPUS_DIR_PATH = Path(__file__).parents[2] / "tests" / "fixtures" / "benchmarks"
CLI_SCRIPT_PATH = Path(__file__).parents[2] / "scripts" / "run_cve_benchmark.py"


@pytest.fixture
def corpus_loader() -> CorpusLoader:
    """Provide a configured CorpusLoader instance."""
    if not BENCHMARKS_AVAILABLE:
        pytest.skip("reversecore_mcp.benchmarks module is not available")
    return CorpusLoader(corpus_dir=CORPUS_DIR_PATH)


@pytest.fixture
def scoring_engine() -> ScoringEngine:
    """Provide a configured ScoringEngine instance."""
    if not BENCHMARKS_AVAILABLE:
        pytest.skip("reversecore_mcp.benchmarks module is not available")
    return ScoringEngine(cvss_tolerance=0.5)


@pytest.fixture
def mock_benchmark_runner(scoring_engine: ScoringEngine) -> BenchmarkRunner:
    """Provide a BenchmarkRunner in mock mode."""
    if not BENCHMARKS_AVAILABLE:
        pytest.skip("reversecore_mcp.benchmarks module is not available")
    return BenchmarkRunner(
        corpus_dir=CORPUS_DIR_PATH,
        scoring_engine=scoring_engine,
        mock_mode=True,
        timeout_per_target=30,
    )


# ==============================================================================
# Scenario 1: SQLite FTS5 Unicode Tokenizer (CVE-2019-19645, CWE-122)
# ==============================================================================


class TestSQLiteFTS5BenchmarkE2E:
    """T4-E2E-01: Real-World Benchmark E2E on SQLite FTS5 Unicode Tokenizer."""

    def test_t4_e2e_01_sqlite_fts5_ground_truth_and_fixtures(self, corpus_loader: CorpusLoader):
        """Verify SQLite FTS5 target schema, metadata, and all fixture files on disk."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "sqlite_fts5" / "target.json"
        )
        assert target.target_id == "sqlite3_fts5_unicode"
        assert target.cve_reference == "CVE-2019-19645"
        assert target.cwe_id == "CWE-122"
        assert target.vulnerability_class == "heap_buffer_overflow"
        assert target.faulting_symbol == "fts5UnicodeTokenize"
        assert target.source_file == "fts5_unicode2.c"
        assert target.source_line == 124
        assert target.expected_memory_access_type == "WRITE_OOB"
        assert target.cvss.expected_score == 8.8
        assert target.cvss.severity == "HIGH"
        assert target.raw_poc_size_bytes == 39
        assert target.minimized_poc_target_bytes == 6
        assert target.expected_minimization_ratio_min >= 0.8

        # Test taxonomic score calculation
        score, is_match = calculate_cwe_taxonomic_score("CWE-122", target.cwe_id)
        assert score == 1.0
        assert is_match is True

        fixtures_status = corpus_loader.validate_target_fixtures(target, base_dir=CORPUS_DIR_PATH)
        for fixture_name, exists in fixtures_status.items():
            assert exists is True, f"Missing fixture file for {fixture_name}"

    async def test_t4_e2e_01_sqlite_fts5_mock_benchmark_pipeline(
        self, corpus_loader: CorpusLoader, mock_benchmark_runner: BenchmarkRunner
    ):
        """Execute mock benchmark pipeline for SQLite FTS5 target and assert scoring concordance."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "sqlite_fts5" / "target.json"
        )
        result: TargetEvaluationResult = await mock_benchmark_runner.run_target(target)

        assert result.status == "DISCOVERED"
        assert result.is_true_positive is True
        assert result.predicted_cwe == "CWE-122"
        assert result.cwe_exact_match is True
        assert result.cwe_hierarchical_match is True
        assert result.cwe_match_score == 1.0
        assert result.predicted_cvss == 8.8
        assert result.cvss_delta == 0.0
        assert result.cvss_tolerance_passed is True
        assert result.predicted_severity == "HIGH"
        assert result.severity_match is True
        assert result.faulting_symbol == "fts5UnicodeTokenize"
        assert result.original_poc_size_bytes == 39
        assert result.minimized_poc_size_bytes == 6
        assert result.poc_reduction_percentage >= 80.0
        assert result.time_to_crash_seconds > 0.0
        assert result.total_executions > 0

    async def test_t4_e2e_01_sqlite_fts5_live_cve_hunter_integration(
        self, corpus_loader: CorpusLoader, scoring_engine: ScoringEngine
    ):
        """Execute live tool integration path with mocked CVE hunter tool."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "sqlite_fts5" / "target.json"
        )
        runner = BenchmarkRunner(
            corpus_dir=CORPUS_DIR_PATH,
            scoring_engine=scoring_engine,
            mock_mode=False,
            timeout_per_target=10,
        )

        mock_tool_output = {
            "target_file": target.source_file,
            "target_function": target.faulting_symbol,
            "cwe_id": "CWE-122",
            "cvss_v31_score": 8.8,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 8500, "crashes_detected": 1},
            "minimized_input_size_bytes": 6,
        }

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
            return_value=success(mock_tool_output),
        ):
            result = await runner.run_target(target)
            assert result.status == "DISCOVERED"
            assert result.is_true_positive is True
            assert result.predicted_cwe == "CWE-122"
            assert result.cwe_exact_match is True
            assert result.cvss_tolerance_passed is True
            assert result.poc_reduction_percentage >= 80.0

    def test_t4_e2e_01_sqlite_fts5_vendor_advisory_generation(self):
        """Verify security advisory draft formatting for SQLite FTS5."""
        triage = {
            "cwe_id": "CWE-122",
            "cwe_name": "Heap-based Buffer Overflow",
            "cvss": {
                "cvss_v31_score": 8.8,
                "severity": "HIGH",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            },
            "faulting_function": "fts5UnicodeTokenize",
            "faulting_source_location": "fts5_unicode2.c:124",
            "bug_type": "heap-buffer-overflow",
            "access_type": "WRITE",
            "access_size": 4,
            "crash_callstack": [
                {
                    "frame": 0,
                    "address": "0x5555555",
                    "symbol": "fts5UnicodeTokenize",
                    "source_file": "fts5_unicode2.c",
                    "line": 124,
                }
            ],
        }
        advisory = generate_cve_advisory_markdown(
            target_name="SQLite FTS5",
            triage=triage,
            poc_script="import sys\npayload = b'\\xff\\xfe' * 3",
            c_harness="#include <stdio.h>\nint main() { return 0; }",
        )
        assert "# Security Advisory: Heap-based Buffer Overflow" in advisory
        assert "fts5UnicodeTokenize" in advisory
        assert "CWE-122" in advisory
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" in advisory
        assert "import sys" in advisory


# ==============================================================================
# Scenario 2: LibPNG EXIF Parser (CVE-2018-13785, CWE-190/122)
# ==============================================================================


class TestLibPNGParserBenchmarkE2E:
    """T4-E2E-02: Real-World Benchmark E2E on LibPNG EXIF Parser."""

    def test_t4_e2e_02_libpng_ground_truth_and_fixtures(self, corpus_loader: CorpusLoader):
        """Verify LibPNG EXIF parser target schema, metadata, and fixtures."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libpng_parser" / "target.json"
        )
        assert target.target_id == "libpng_eXIf_int_overflow"
        assert target.cve_reference == "CVE-2018-13785"
        assert target.cwe_id == "CWE-190"
        assert target.vulnerability_class == "integer_overflow"
        assert target.faulting_symbol == "png_handle_eXIf"
        assert target.source_file == "pngrutil.c"
        assert target.cvss.expected_score == 8.8
        assert target.cvss.severity == "HIGH"
        assert target.raw_poc_size_bytes == 69
        assert target.minimized_poc_target_bytes == 16
        assert target.expected_minimization_ratio_min >= 0.7

        fixtures_status = corpus_loader.validate_target_fixtures(target, base_dir=CORPUS_DIR_PATH)
        for fixture_name, exists in fixtures_status.items():
            assert exists is True, f"Missing fixture file for {fixture_name}"

    async def test_t4_e2e_02_libpng_mock_benchmark_pipeline(
        self, corpus_loader: CorpusLoader, mock_benchmark_runner: BenchmarkRunner
    ):
        """Execute mock benchmark pipeline for LibPNG target and assert metrics."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libpng_parser" / "target.json"
        )
        result: TargetEvaluationResult = await mock_benchmark_runner.run_target(target)

        assert result.status == "DISCOVERED"
        assert result.is_true_positive is True
        assert result.predicted_cwe == "CWE-190"
        assert result.cwe_exact_match is True
        assert result.predicted_cvss == 8.8
        assert result.cvss_delta == 0.0
        assert result.cvss_tolerance_passed is True
        assert result.original_poc_size_bytes == 69
        assert result.minimized_poc_size_bytes == 16
        assert result.poc_reduction_percentage >= 70.0

    async def test_t4_e2e_02_libpng_live_cve_hunter_integration(
        self, corpus_loader: CorpusLoader, scoring_engine: ScoringEngine
    ):
        """Execute live tool integration path for LibPNG."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libpng_parser" / "target.json"
        )
        runner = BenchmarkRunner(
            corpus_dir=CORPUS_DIR_PATH,
            scoring_engine=scoring_engine,
            mock_mode=False,
            timeout_per_target=10,
        )

        mock_tool_output = {
            "target_file": target.source_file,
            "target_function": target.faulting_symbol,
            "cwe_id": "CWE-190",
            "cvss_v31_score": 8.8,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 6200, "crashes_detected": 1},
            "minimized_input_size_bytes": 16,
        }

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
            return_value=success(mock_tool_output),
        ):
            result = await runner.run_target(target)
            assert result.status == "DISCOVERED"
            assert result.is_true_positive is True
            assert result.cwe_exact_match is True
            assert result.poc_reduction_percentage >= 70.0


# ==============================================================================
# Scenario 3: LibXML2 Entity Expansion (CVE-2022-2309, CWE-416)
# ==============================================================================


class TestLibXML2ParserBenchmarkE2E:
    """T4-E2E-03: Real-World Benchmark E2E on LibXML2 Entity Expansion Engine."""

    def test_t4_e2e_03_libxml2_ground_truth_and_fixtures(self, corpus_loader: CorpusLoader):
        """Verify LibXML2 target schema, metadata, and fixtures."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libxml2_parser" / "target.json"
        )
        assert target.target_id == "libxml2_entity_uaf"
        assert target.cve_reference == "CVE-2022-2309"
        assert target.cwe_id == "CWE-416"
        assert target.vulnerability_class == "use_after_free"
        assert target.faulting_symbol == "xmlParseAttValueComplex"
        assert target.source_file == "parser.c"
        assert target.cvss.expected_score == 8.8
        assert target.cvss.severity == "HIGH"
        assert target.raw_poc_size_bytes == 115
        assert target.minimized_poc_target_bytes == 59
        assert target.expected_minimization_ratio_min >= 0.45

        fixtures_status = corpus_loader.validate_target_fixtures(target, base_dir=CORPUS_DIR_PATH)
        for fixture_name, exists in fixtures_status.items():
            assert exists is True, f"Missing fixture file for {fixture_name}"

    async def test_t4_e2e_03_libxml2_mock_benchmark_pipeline(
        self, corpus_loader: CorpusLoader, mock_benchmark_runner: BenchmarkRunner
    ):
        """Execute mock benchmark pipeline for LibXML2 target and assert metrics."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libxml2_parser" / "target.json"
        )
        result: TargetEvaluationResult = await mock_benchmark_runner.run_target(target)

        assert result.status == "DISCOVERED"
        assert result.is_true_positive is True
        assert result.predicted_cwe == "CWE-416"
        assert result.cwe_exact_match is True
        assert result.predicted_cvss == 8.8
        assert result.cvss_delta == 0.0
        assert result.cvss_tolerance_passed is True
        assert result.original_poc_size_bytes == 115
        assert result.minimized_poc_size_bytes == 59
        assert result.poc_reduction_percentage >= 45.0

    async def test_t4_e2e_03_libxml2_live_cve_hunter_integration(
        self, corpus_loader: CorpusLoader, scoring_engine: ScoringEngine
    ):
        """Execute live tool integration path for LibXML2."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libxml2_parser" / "target.json"
        )
        runner = BenchmarkRunner(
            corpus_dir=CORPUS_DIR_PATH,
            scoring_engine=scoring_engine,
            mock_mode=False,
            timeout_per_target=10,
        )

        mock_tool_output = {
            "target_file": target.source_file,
            "target_function": target.faulting_symbol,
            "cwe_id": "CWE-416",
            "cvss_v31_score": 8.8,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 4500, "crashes_detected": 1},
            "minimized_input_size_bytes": 59,
        }

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
            return_value=success(mock_tool_output),
        ):
            result = await runner.run_target(target)
            assert result.status == "DISCOVERED"
            assert result.is_true_positive is True
            assert result.cwe_exact_match is True
            assert result.poc_reduction_percentage >= 45.0


# ==============================================================================
# Scenario 4: LibArchive Header Parser (CVE-2019-18408, CWE-415)
# ==============================================================================


class TestLibArchiveParserBenchmarkE2E:
    """T4-E2E-04: Real-World Benchmark E2E on LibArchive Header Parser."""

    def test_t4_e2e_04_libarchive_ground_truth_and_fixtures(self, corpus_loader: CorpusLoader):
        """Verify LibArchive target schema, metadata, and fixtures."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libarchive_parser" / "target.json"
        )
        assert target.target_id == "libarchive_rar_double_free"
        assert target.cve_reference == "CVE-2019-18408"
        assert target.cwe_id == "CWE-415"
        assert target.vulnerability_class == "double_free"
        assert target.faulting_symbol == "rar_free_codes"
        assert target.source_file == "archive_read_support_format_rar.c"
        assert target.cvss.expected_score == 8.1
        assert target.cvss.severity == "HIGH"
        assert target.raw_poc_size_bytes == 68
        assert target.minimized_poc_target_bytes == 12
        assert target.expected_minimization_ratio_min >= 0.75

        fixtures_status = corpus_loader.validate_target_fixtures(target, base_dir=CORPUS_DIR_PATH)
        for fixture_name, exists in fixtures_status.items():
            assert exists is True, f"Missing fixture file for {fixture_name}"

    async def test_t4_e2e_04_libarchive_mock_benchmark_pipeline(
        self, corpus_loader: CorpusLoader, mock_benchmark_runner: BenchmarkRunner
    ):
        """Execute mock benchmark pipeline for LibArchive target and assert metrics."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libarchive_parser" / "target.json"
        )
        result: TargetEvaluationResult = await mock_benchmark_runner.run_target(target)

        assert result.status == "DISCOVERED"
        assert result.is_true_positive is True
        assert result.predicted_cwe == "CWE-415"
        assert result.cwe_exact_match is True
        assert result.predicted_cvss == 8.1
        assert result.cvss_delta == 0.0
        assert result.cvss_tolerance_passed is True
        assert result.original_poc_size_bytes == 68
        assert result.minimized_poc_size_bytes == 12
        assert result.poc_reduction_percentage >= 75.0

    async def test_t4_e2e_04_libarchive_live_cve_hunter_integration(
        self, corpus_loader: CorpusLoader, scoring_engine: ScoringEngine
    ):
        """Execute live tool integration path for LibArchive."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "libarchive_parser" / "target.json"
        )
        runner = BenchmarkRunner(
            corpus_dir=CORPUS_DIR_PATH,
            scoring_engine=scoring_engine,
            mock_mode=False,
            timeout_per_target=10,
        )

        mock_tool_output = {
            "target_file": target.source_file,
            "target_function": target.faulting_symbol,
            "cwe_id": "CWE-415",
            "cvss_v31_score": 8.1,
            "cvss_severity": "HIGH",
            "fuzzing_stats": {"executions": 7100, "crashes_detected": 1},
            "minimized_input_size_bytes": 12,
        }

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
            return_value=success(mock_tool_output),
        ):
            result = await runner.run_target(target)
            assert result.status == "DISCOVERED"
            assert result.is_true_positive is True
            assert result.cwe_exact_match is True
            assert result.poc_reduction_percentage >= 75.0


# ==============================================================================
# Scenario 5: Full Multi-Target Benchmark Suite Run
# ==============================================================================


class TestMultiTargetSuiteBenchmarkE2E:
    """T4-E2E-05: Full Multi-Target Benchmark Suite Run (100% TPR, class breakdowns)."""

    async def test_t4_e2e_05_full_multitarget_benchmark_suite_execution(
        self, mock_benchmark_runner: BenchmarkRunner
    ):
        """Execute full benchmark suite across all 4 targets simultaneously."""
        summary: BenchmarkScorecardSummary = await mock_benchmark_runner.run_suite(
            target_filter="all", cwe_filter="all"
        )

        assert summary.total_targets == 4
        assert summary.discovered_count == 4
        assert summary.missed_count == 0
        assert summary.error_count == 0
        assert summary.discovery_rate_tpr_pct == 100.0
        assert summary.mean_time_to_crash_seconds < 5.0
        assert summary.avg_poc_reduction_pct > 70.0
        assert summary.cwe_exact_match_rate_pct == 100.0
        assert summary.cwe_hierarchical_match_rate_pct == 100.0
        assert summary.cvss_mean_absolute_error <= 0.20
        assert summary.cvss_tolerance_match_rate_pct == 100.0
        assert summary.severity_concordance_rate_pct == 100.0

        # Assert all 4 target IDs are present in individual results
        target_ids = {r.target_id for r in summary.target_results}
        expected_ids = {
            "sqlite3_fts5_unicode",
            "libpng_eXIf_int_overflow",
            "libxml2_entity_uaf",
            "libarchive_rar_double_free",
        }
        assert target_ids == expected_ids

    async def test_t4_e2e_05_class_stratification_completeness(
        self, mock_benchmark_runner: BenchmarkRunner
    ):
        """Verify vulnerability class stratification breakdown covers all 4 bug classes."""
        summary: BenchmarkScorecardSummary = await mock_benchmark_runner.run_suite(
            target_filter="all", cwe_filter="all"
        )
        breakdown = summary.class_breakdown

        assert "heap_buffer_overflow" in breakdown
        assert "integer_overflow" in breakdown
        assert "use_after_free" in breakdown
        assert "double_free" in breakdown

        for vclass, stats in breakdown.items():
            assert stats["total"] >= 1, f"Class {vclass} has 0 total targets"
            assert stats["discovered"] >= 1, f"Class {vclass} has 0 discovered targets"
            assert stats["missed"] == 0, f"Class {vclass} has missed targets"
            assert stats["tpr_pct"] == 100.0, f"Class {vclass} TPR < 100%"
            assert stats["avg_reduction_pct"] > 0.0, f"Class {vclass} avg reduction is 0%"

    async def test_t4_e2e_05_filtered_suite_execution_by_cwe(
        self, mock_benchmark_runner: BenchmarkRunner
    ):
        """Verify filtered suite run for specific CWE ID."""
        summary_uaf = await mock_benchmark_runner.run_suite(cwe_filter="CWE-416")
        assert summary_uaf.total_targets == 1
        assert summary_uaf.target_results[0].target_id == "libxml2_entity_uaf"
        assert summary_uaf.discovery_rate_tpr_pct == 100.0

        summary_df = await mock_benchmark_runner.run_suite(cwe_filter="CWE-415")
        assert summary_df.total_targets == 1
        assert summary_df.target_results[0].target_id == "libarchive_rar_double_free"
        assert summary_df.discovery_rate_tpr_pct == 100.0

    async def test_t4_e2e_05_filtered_suite_execution_by_target_id(
        self, mock_benchmark_runner: BenchmarkRunner
    ):
        """Verify filtered suite run for specific target ID/keyword."""
        summary_sqlite = await mock_benchmark_runner.run_suite(target_filter="sqlite3_fts5_unicode")
        assert summary_sqlite.total_targets == 1
        assert summary_sqlite.target_results[0].target_id == "sqlite3_fts5_unicode"
        assert summary_sqlite.discovery_rate_tpr_pct == 100.0


# ==============================================================================
# Scenario 6: CI/CD Continuous Evaluation Mode
# ==============================================================================


class TestCICDContinuousEvaluationModeE2E:
    """T4-E2E-06: CI/CD Continuous Evaluation Mode (mock mode, zero leaks, JSON summary artifact)."""

    def test_t4_e2e_06_cli_subprocess_mock_execution_success(self, tmp_path: Path):
        """Execute CLI script via subprocess in mock mode and verify output artifacts and exit code 0."""
        if not CLI_SCRIPT_PATH.exists():
            pytest.skip("scripts/run_cve_benchmark.py is not yet created")

        output_dir = tmp_path / "ci_artifacts"
        cmd = [
            sys.executable,
            str(CLI_SCRIPT_PATH),
            "--mock",
            "--output-format",
            "both",
            "--output-dir",
            str(output_dir),
            "--corpus-dir",
            str(CORPUS_DIR_PATH),
            "--verbose",
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert proc.returncode == 0, f"CLI exited with {proc.returncode}. Stderr: {proc.stderr}"
        assert "# 🎯 Reversecore_MCP CVE Discovery Benchmark Evaluation Report" in proc.stdout
        assert "True Positive Rate (TPR)" in proc.stdout

        summary_file = output_dir / "benchmark_summary.json"
        report_file = output_dir / "benchmark_report.md"

        assert summary_file.exists(), "benchmark_summary.json not generated"
        assert report_file.exists(), "benchmark_report.md not generated"
        assert summary_file.stat().st_size > 0
        assert report_file.stat().st_size > 0

    def test_t4_e2e_06_cli_json_artifact_schema_validation(self, tmp_path: Path):
        """Verify generated benchmark_summary.json schema conforms to standard evaluation structure."""
        if not CLI_SCRIPT_PATH.exists():
            pytest.skip("scripts/run_cve_benchmark.py is not yet created")

        output_dir = tmp_path / "schema_artifacts"
        cmd = [
            sys.executable,
            str(CLI_SCRIPT_PATH),
            "--mock",
            "--output-format",
            "json",
            "--output-dir",
            str(output_dir),
            "--corpus-dir",
            str(CORPUS_DIR_PATH),
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0

        summary_file = output_dir / "benchmark_summary.json"
        assert summary_file.exists()

        data = json.loads(summary_file.read_text(encoding="utf-8"))
        assert data["total_targets"] == 4
        assert data["discovered_count"] == 4
        assert data["missed_count"] == 0
        assert data["error_count"] == 0
        assert data["discovery_rate_tpr_pct"] == 100.0
        assert isinstance(data["class_breakdown"], dict)
        assert isinstance(data["target_results"], list)
        assert len(data["target_results"]) == 4

        # Validate target_result fields in JSON
        for r in data["target_results"]:
            assert "target_id" in r
            assert "is_true_positive" in r
            assert "cwe_exact_match" in r
            assert "cvss_tolerance_passed" in r
            assert "poc_reduction_percentage" in r

    def test_t4_e2e_06_cli_process_stability_and_no_leaks(self):
        """Verify CLI finishes cleanly without hanging, orphaned processes, or abnormal termination."""
        if not CLI_SCRIPT_PATH.exists():
            pytest.skip("scripts/run_cve_benchmark.py is not yet created")

        cmd = [
            sys.executable,
            str(CLI_SCRIPT_PATH),
            "--mock",
            "--output-format",
            "stdout",
            "--corpus-dir",
            str(CORPUS_DIR_PATH),
        ]

        # Fast execution expected under 10 seconds in mock mode
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0
        assert "✅ PASS" in proc.stdout


# ==============================================================================
# Scenario 7: Adversarial Threshold Enforcement (Exit Codes 0 / 1 / 2)
# ==============================================================================


class TestAdversarialThresholdEnforcementE2E:
    """T4-E2E-07: Adversarial Threshold Enforcement (Exit code 0 on pass, exit code 1 on error, exit code 2 on threshold failure)."""

    def test_t4_e2e_07_exit_code_0_on_threshold_pass(self, tmp_path: Path):
        """Verify exit code 0 when TPR meets or exceeds --fail-under-tpr."""
        if not CLI_SCRIPT_PATH.exists():
            pytest.skip("scripts/run_cve_benchmark.py is not yet created")

        cmd = [
            sys.executable,
            str(CLI_SCRIPT_PATH),
            "--mock",
            "--fail-under-tpr",
            "80.0",
            "--corpus-dir",
            str(CORPUS_DIR_PATH),
            "--output-dir",
            str(tmp_path),
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0

    def test_t4_e2e_07_exit_code_2_on_threshold_failure(self, tmp_path: Path):
        """Verify exit code 2 when TPR fails to meet --fail-under-tpr (e.g. 101.0%)."""
        if not CLI_SCRIPT_PATH.exists():
            pytest.skip("scripts/run_cve_benchmark.py is not yet created")

        cmd = [
            sys.executable,
            str(CLI_SCRIPT_PATH),
            "--mock",
            "--fail-under-tpr",
            "101.0",
            "--corpus-dir",
            str(CORPUS_DIR_PATH),
            "--output-dir",
            str(tmp_path),
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 2, (
            f"Expected exit code 2 on threshold failure, got {proc.returncode}"
        )
        assert (
            "threshold failure" in proc.stderr.lower() or "threshold failure" in proc.stdout.lower()
        )

    def test_t4_e2e_07_exit_code_1_on_nonexistent_corpus_dir(self, tmp_path: Path):
        """Verify exit code 1 on fatal error (e.g. non-existent corpus directory)."""
        if not CLI_SCRIPT_PATH.exists():
            pytest.skip("scripts/run_cve_benchmark.py is not yet created")

        cmd = [
            sys.executable,
            str(CLI_SCRIPT_PATH),
            "--mock",
            "--corpus-dir",
            str(tmp_path / "non_existent_corpus_dir_12345"),
            "--output-dir",
            str(tmp_path),
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 1, f"Expected exit code 1 on corpus error, got {proc.returncode}"
        assert "corpus error" in proc.stderr.lower() or "error" in proc.stderr.lower()

    async def test_t4_e2e_07_programmatic_async_main_exit_codes(self, tmp_path: Path):
        """Test async_main directly under different argument configurations."""
        if not CLI_AVAILABLE:
            pytest.skip("scripts.run_cve_benchmark is not available")

        # Test Exit 0
        args_pass = parse_args(
            [
                "--mock",
                "--corpus-dir",
                str(CORPUS_DIR_PATH),
                "--output-dir",
                str(tmp_path / "async_pass"),
                "--fail-under-tpr",
                "80.0",
            ]
        )
        code_pass = await async_main(args_pass)
        assert code_pass == 0

        # Test Exit 2 (Threshold Failure)
        args_fail = parse_args(
            [
                "--mock",
                "--corpus-dir",
                str(CORPUS_DIR_PATH),
                "--output-dir",
                str(tmp_path / "async_fail"),
                "--fail-under-tpr",
                "101.0",
            ]
        )
        code_fail = await async_main(args_fail)
        assert code_fail == 2

        # Test Exit 1 (Corpus Error)
        args_err = parse_args(
            [
                "--mock",
                "--corpus-dir",
                str(tmp_path / "non_existent"),
                "--output-dir",
                str(tmp_path / "async_err"),
            ]
        )
        code_err = await async_main(args_err)
        assert code_err == 1


# ==============================================================================
# Scenario 8: Full Artifact & Vendor Advisory Export
# ==============================================================================


class TestArtifactAndVendorAdvisoryExportE2E:
    """T4-E2E-08: Full Artifact & Vendor Advisory Export (Markdown GFM table formatting, JSON Schema conformance)."""

    async def test_t4_e2e_08_markdown_scorecard_gfm_tables(
        self, mock_benchmark_runner: BenchmarkRunner
    ):
        """Verify generated Markdown scorecard contains standard GFM table structures and headers."""
        summary: BenchmarkScorecardSummary = await mock_benchmark_runner.run_suite()
        md = BenchmarkReporter.to_markdown(summary)

        # Verify Executive Scorecard table
        assert "# 🎯 Reversecore_MCP CVE Discovery Benchmark Evaluation Report" in md
        assert "## 📊 Executive Scorecard" in md
        assert "| Metric | Score / Value | Status |" in md
        assert "| :--- | :--- | :--- |" in md
        assert "| **True Positive Rate (TPR)** |" in md
        assert "| **Mean Time-to-Crash (MTTC)** |" in md
        assert "| **Average PoC Minimization** |" in md
        assert "| **CWE Exact Match Rate** |" in md
        assert "| **CVSS v3.1 Mean Absolute Error** |" in md

        # Verify Target Breakdown table
        assert "## 🔬 Target Evaluation Breakdown" in md
        assert (
            "| Target ID | Vulnerability Class | GT CWE | Pred CWE | Match | GT CVSS | Pred CVSS | Δ | TTC (s) | PoC Red % | Status |"
            in md
        )
        assert "`sqlite3_fts5_unicode`" in md
        assert "`libpng_eXIf_int_overflow`" in md
        assert "`libxml2_entity_uaf`" in md
        assert "`libarchive_rar_double_free`" in md

        # Verify Vulnerability Class Stratification table
        assert "## 🧩 Vulnerability Class Stratification" in md
        assert (
            "| Vulnerability Class | Total | Discovered (TP) | Missed (FN) | TPR (%) | Avg TTC (s) | Avg PoC Reduction |"
            in md
        )
        assert "| **heap_buffer_overflow** |" in md
        assert "| **integer_overflow** |" in md
        assert "| **use_after_free** |" in md
        assert "| **double_free** |" in md

    async def test_t4_e2e_08_json_summary_serialization(
        self, mock_benchmark_runner: BenchmarkRunner
    ):
        """Verify BenchmarkReporter.to_json generates parseable, structured JSON."""
        summary: BenchmarkScorecardSummary = await mock_benchmark_runner.run_suite()
        json_str = BenchmarkReporter.to_json(summary, indent=2)

        data = json.loads(json_str)
        assert data["total_targets"] == 4
        assert data["discovered_count"] == 4
        assert data["discovery_rate_tpr_pct"] == 100.0
        assert len(data["target_results"]) == 4

    async def test_t4_e2e_08_reporter_save_reports_formats(
        self, mock_benchmark_runner: BenchmarkRunner, tmp_path: Path
    ):
        """Verify save_reports correctly generates markdown, json, or both formats in nested directories."""
        summary: BenchmarkScorecardSummary = await mock_benchmark_runner.run_suite()

        # Test both
        out_both = tmp_path / "deep" / "nested" / "both"
        saved_both = BenchmarkReporter.save_reports(summary, out_both, output_format="both")
        assert "markdown" in saved_both
        assert "json" in saved_both
        assert saved_both["markdown"].exists()
        assert saved_both["json"].exists()

        # Test markdown only
        out_md = tmp_path / "md_only"
        saved_md = BenchmarkReporter.save_reports(summary, out_md, output_format="markdown")
        assert "markdown" in saved_md
        assert "json" not in saved_md
        assert saved_md["markdown"].exists()
        assert not (out_md / "benchmark_summary.json").exists()

        # Test json only
        out_json = tmp_path / "json_only"
        saved_json = BenchmarkReporter.save_reports(summary, out_json, output_format="json")
        assert "json" in saved_json
        assert "markdown" not in saved_json
        assert saved_json["json"].exists()
        assert not (out_json / "benchmark_report.md").exists()

    def test_t4_e2e_08_vendor_advisory_markdown_reproducers(self):
        """Verify complete vendor advisory markdown generation with standalone reproducers."""
        triage = {
            "cwe_id": "CWE-416",
            "cwe_name": "Use After Free",
            "cvss": {
                "cvss_v31_score": 8.8,
                "severity": "HIGH",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            },
            "faulting_function": "xmlParseAttValueComplex",
            "faulting_source_location": "parser.c:3890",
            "bug_type": "heap-use-after-free",
            "access_type": "UAF_WRITE",
            "access_size": 8,
            "crash_callstack": [
                {
                    "frame": 0,
                    "address": "0x401234",
                    "symbol": "xmlParseAttValueComplex",
                    "source_file": "parser.c",
                    "line": 3890,
                }
            ],
            "exploitability_assessment": "Heap memory corruption leading to remote code execution.",
        }
        py_poc = "import subprocess\nsubprocess.run(['./libxml2_parser', 'poc.bin'])"
        c_poc = "#include <libxml/parser.h>\nint main() { return 0; }"

        advisory = generate_cve_advisory_markdown(
            target_name="LibXML2 Entity Expansion",
            triage=triage,
            poc_script=py_poc,
            c_harness=c_poc,
        )

        assert "xmlParseAttValueComplex" in advisory
        assert "CWE-416" in advisory
        assert "heap-use-after-free" in advisory
        assert "import subprocess" in advisory
        assert "#include <libxml/parser.h>" in advisory


# ==============================================================================
# Live Tool Resilience & Error Handling Tests
# ==============================================================================


class TestLiveToolResilienceAndTimeoutE2E:
    """Resilience and fault containment integration tests for live CVE hunting execution."""

    async def test_live_tool_error_containment(
        self, corpus_loader: CorpusLoader, scoring_engine: ScoringEngine
    ):
        """Verify runner isolates tool error without crashing the suite."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "sqlite_fts5" / "target.json"
        )
        runner = BenchmarkRunner(
            corpus_dir=CORPUS_DIR_PATH,
            scoring_engine=scoring_engine,
            mock_mode=False,
            timeout_per_target=5,
        )

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            new_callable=AsyncMock,
            return_value=failure("RCMCP-E001", "Simulated clang build error: header not found"),
        ):
            result: TargetEvaluationResult = await runner.run_target(target)
            assert result.status == "ERROR"
            assert result.is_true_positive is False
            assert result.error_message is not None and "clang" in result.error_message

    async def test_live_tool_timeout_containment(
        self, corpus_loader: CorpusLoader, scoring_engine: ScoringEngine
    ):
        """Verify runner isolates asyncio.TimeoutError without hanging."""
        target: TargetGroundTruth = corpus_loader.load_target_from_json(
            CORPUS_DIR_PATH / "targets" / "sqlite_fts5" / "target.json"
        )
        runner = BenchmarkRunner(
            corpus_dir=CORPUS_DIR_PATH,
            scoring_engine=scoring_engine,
            mock_mode=False,
            timeout_per_target=1,
        )

        async def _hang(*args: Any, **kwargs: Any) -> Any:
            await asyncio.sleep(10)
            return success({})

        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_vulnerabilities",
            side_effect=_hang,
        ):
            result: TargetEvaluationResult = await runner.run_target(target)
            assert result.status == "ERROR"
            assert result.is_true_positive is False
            assert result.error_message is not None and "timed out" in result.error_message.lower()
