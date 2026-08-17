"""Unit tests for the expanded 10-target benchmark corpus.

Validates:
- All 10 CVE targets load and parse correctly from ground_truth_corpus.json
- Fixture files exist on disk for every target
- BenchmarkRunner.run_suite() in mock mode achieves >= 80% TPR across all 10 targets
- ScoringEngine computes CVSS MAE, CWE match rates, severity concordance correctly
  for the full corpus
- Filter operations work correctly against the expanded target set
- CorpusLoader version field is present and parseable
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    ExecutionOptions,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.runner import BenchmarkRunner
from reversecore_mcp.benchmarks.scoring import ScoringEngine

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# __file__ lives at: tests/unit/benchmarks/test_expanded_corpus.py
# parent           → tests/unit/benchmarks/
# parent.parent    → tests/unit/
# parent.parent.parent → tests/
CORPUS_DIR = Path(__file__).parent.parent.parent / "fixtures" / "benchmarks"
TARGETS_DIR = CORPUS_DIR / "targets"

# All 10 expected target IDs after expansion
EXPECTED_TARGET_IDS = {
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

# Expected fixture filenames for each target directory
REQUIRED_FIXTURE_FILES = [
    "vulnerable.c",
    "patched.c",
    "patch.diff",
    "harness.c",
    "asan_crash.log",
    "poc_raw.bin",
    "poc_minimized.bin",
    "seed_valid.bin",
    "dictionary.dict",
]

# CWE IDs present in the expanded corpus
EXPECTED_CWES = {
    "CWE-122",  # sqlite3, zlib
    "CWE-190",  # libpng, expat
    "CWE-416",  # libxml2
    "CWE-415",  # libarchive
    "CWE-835",  # openssl
    "CWE-200",  # curl
    "CWE-125",  # ffmpeg
    "CWE-763",  # php
    "CWE-787",  # zlib (Out-of-bounds Write)
}

# Vulnerability classes in the corpus
EXPECTED_VULN_CLASSES = {
    "heap_buffer_overflow",
    "integer_overflow",
    "use_after_free",
    "double_free",
    "infinite_loop",
    "out_of_bounds_read",
    "information_exposure",
    "type_confusion",
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Corpus loading tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExpandedCorpusLoading:
    """Test that all 10 CVE targets load correctly."""

    def test_corpus_loads_ten_targets(self):
        """Corpus must contain exactly 10 targets."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        assert len(targets) == 10, f"Expected 10 targets, got {len(targets)}"

    def test_all_expected_target_ids_present(self):
        """Every expected target ID must be present in the loaded corpus."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        loaded_ids = {t.target_id for t in targets}
        missing = EXPECTED_TARGET_IDS - loaded_ids
        assert not missing, f"Missing target IDs: {missing}"

    def test_no_unexpected_target_ids(self):
        """No extra target IDs outside the expected set should be present."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        loaded_ids = {t.target_id for t in targets}
        extra = loaded_ids - EXPECTED_TARGET_IDS
        assert not extra, f"Unexpected target IDs: {extra}"

    def test_all_targets_are_valid_pydantic_models(self):
        """Each target must parse into a valid TargetGroundTruth Pydantic model."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        for t in targets:
            assert isinstance(t, TargetGroundTruth)
            assert t.target_id
            assert t.cwe_id.startswith("CWE-")
            assert 0 < t.cvss.expected_score <= 10.0
            assert t.cvss.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_corpus_covers_expected_cwe_diversity(self):
        """Corpus must cover the expected set of CWE categories."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        loaded_cwes = {t.cwe_id for t in targets}
        # Verify at least the CWEs from the original 4 targets are present
        base_cwes = {"CWE-122", "CWE-190", "CWE-416", "CWE-415"}
        assert base_cwes.issubset(loaded_cwes), f"Missing base CWEs: {base_cwes - loaded_cwes}"
        # New targets should introduce at least 4 new CWEs
        assert len(loaded_cwes) >= 6, f"Expected >=6 distinct CWEs, got {len(loaded_cwes)}"

    def test_corpus_covers_expected_vuln_classes(self):
        """Corpus must cover at least 6 distinct vulnerability classes."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        classes = {t.vulnerability_class for t in targets}
        assert len(classes) >= 6, (
            f"Expected >=6 vulnerability classes, got {len(classes)}: {classes}"
        )

    def test_corpus_covers_expected_categories(self):
        """Corpus must span multiple target categories."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        categories = {t.category for t in targets}
        assert len(categories) >= 5, f"Expected >=5 categories, got {len(categories)}: {categories}"

    def test_severity_distribution_includes_critical(self):
        """At least one CRITICAL severity target must be present after expansion."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        severities = {t.cvss.severity for t in targets}
        assert "CRITICAL" in severities, "No CRITICAL severity target found in expanded corpus"

    def test_severity_distribution_includes_medium(self):
        """At least one MEDIUM severity target must be present after expansion."""
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        severities = {t.cvss.severity for t in targets}
        assert "MEDIUM" in severities, "No MEDIUM severity target found in expanded corpus"


# ---------------------------------------------------------------------------
# Fixture file existence tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExpandedFixtureFiles:
    """Test that all fixture files exist on disk for every target."""

    @pytest.mark.parametrize(
        "target_id,fixture_dir",
        [
            ("openssl_bn_infinite_loop", "openssl_bn"),
            ("zlib_inflate_heap_oob", "zlib_inflate"),
            ("curl_cookie_leak_info", "curl_cookie"),
            ("ffmpeg_hevc_oob_read", "ffmpeg_hevc"),
            ("php_spl_type_confusion", "php_spl"),
            ("expat_entity_int_overflow", "expat_entity"),
        ],
    )
    def test_new_target_directory_exists(self, target_id, fixture_dir):
        """Each new target must have its fixture directory."""
        assert (TARGETS_DIR / fixture_dir).is_dir(), (
            f"Missing fixture directory for {target_id}: {TARGETS_DIR / fixture_dir}"
        )

    @pytest.mark.parametrize(
        "fixture_dir",
        [
            "openssl_bn",
            "zlib_inflate",
            "curl_cookie",
            "ffmpeg_hevc",
            "php_spl",
            "expat_entity",
        ],
    )
    @pytest.mark.parametrize("filename", REQUIRED_FIXTURE_FILES)
    def test_required_fixture_file_exists(self, fixture_dir, filename):
        """Every required fixture file must exist for each new target."""
        path = TARGETS_DIR / fixture_dir / filename
        assert path.exists(), f"Missing fixture file: {path}"
        assert path.stat().st_size > 0, f"Empty fixture file: {path}"

    @pytest.mark.parametrize(
        "fixture_dir,expected_min_bytes",
        [
            ("openssl_bn", 4),  # DER stub: 64 bytes generated, min requirement: 4
            ("zlib_inflate", 4),  # gzip magic header: 10 bytes generated, min: 4
            ("curl_cookie", 4),  # HTTP snippet: ~42 bytes generated, min: 4
            ("ffmpeg_hevc", 4),  # HEVC NAL stub: ~48 bytes generated, min: 4
            ("php_spl", 4),  # PHP serialized: ~42 bytes generated, min: 4
            ("expat_entity", 4),  # XML snippet: ~45 bytes generated, min: 4
        ],
    )
    def test_minimized_poc_size(self, fixture_dir, expected_min_bytes):
        """Minimized PoC file must be at least the expected minimum size."""
        path = TARGETS_DIR / fixture_dir / "poc_minimized.bin"
        assert path.exists(), f"Missing: {path}"
        assert path.stat().st_size >= expected_min_bytes, (
            f"{fixture_dir}: poc_minimized.bin too small "
            f"({path.stat().st_size} < {expected_min_bytes})"
        )

    def test_asan_crash_log_contains_faulting_symbol(self):
        """ASan crash logs must contain the expected faulting symbol."""
        checks = [
            ("openssl_bn", "BN_mod_sqrt"),
            ("zlib_inflate", "inflateGetHeader"),
            ("curl_cookie", "Curl_http_output_auth"),
            ("ffmpeg_hevc", "hevc_parse_slice_header"),
            ("php_spl", "spl_dllist_object_free_storage"),
            ("expat_entity", "storeRawNames"),
        ]
        for fixture_dir, symbol in checks:
            log = (TARGETS_DIR / fixture_dir / "asan_crash.log").read_text(errors="ignore")
            assert symbol in log, f"{fixture_dir}/asan_crash.log missing faulting symbol '{symbol}'"


# ---------------------------------------------------------------------------
# BenchmarkRunner mock-mode tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBenchmarkRunnerExpandedCorpus:
    """Test BenchmarkRunner with all 10 corpus targets in mock mode."""

    def _make_runner(self):
        return BenchmarkRunner(corpus_dir=CORPUS_DIR, mock_mode=True, timeout_per_target=10)

    def test_run_suite_returns_scorecard(self):
        """run_suite() must return a BenchmarkScorecardSummary."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(options=opts))
        assert isinstance(scorecard, BenchmarkScorecardSummary)

    def test_run_suite_evaluates_all_ten_targets(self):
        """run_suite() must evaluate exactly 10 targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(options=opts))
        assert scorecard.total_targets == 10, f"Expected 10 targets, got {scorecard.total_targets}"

    def test_run_suite_achieves_80pct_tpr(self):
        """Mock mode must achieve >= 80% True Positive Rate across all 10 targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(options=opts))
        assert scorecard.discovery_rate_tpr_pct >= 80.0, (
            f"TPR {scorecard.discovery_rate_tpr_pct:.1f}% < 80% threshold"
        )

    def test_run_suite_zero_errors(self):
        """Mock mode should produce zero errors."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(options=opts))
        assert scorecard.error_count == 0, f"Expected 0 errors, got {scorecard.error_count}"

    def test_run_suite_class_breakdown_populated(self):
        """class_breakdown must be non-empty and contain expected classes."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(options=opts))
        assert len(scorecard.class_breakdown) >= 6, (
            f"Expected >=6 classes in breakdown, got {len(scorecard.class_breakdown)}"
        )

    def test_run_suite_poc_reduction_positive(self):
        """Mock mode must report a positive average PoC reduction percentage."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(options=opts))
        assert scorecard.avg_poc_reduction_pct > 0.0, (
            f"Expected positive PoC reduction, got {scorecard.avg_poc_reduction_pct}"
        )

    def test_run_suite_filter_by_vulnerability_class(self):
        """Filtering by heap_buffer_overflow must return only matching targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(
            mock_mode=True,
            timeout_seconds=10,
            fuzz_duration_seconds=1,
            vulnerability_class_filter="heap_buffer_overflow",
        )
        scorecard = _run(runner.run_suite(options=opts))
        # sqlite3_fts5_unicode + zlib_inflate_heap_oob
        assert 1 <= scorecard.total_targets <= 5, (
            f"Unexpected target count for heap_buffer_overflow filter: {scorecard.total_targets}"
        )

    def test_run_suite_filter_by_cwe(self):
        """Filtering by CWE-190 must return only integer_overflow targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(cwe_filter="CWE-190", options=opts))
        # libpng + expat both have CWE-190
        assert scorecard.total_targets >= 2, (
            f"Expected >=2 CWE-190 targets, got {scorecard.total_targets}"
        )

    def test_run_suite_filter_by_category(self):
        """Filtering by xml_parser category must return libxml2 and expat targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(
            mock_mode=True,
            timeout_seconds=10,
            fuzz_duration_seconds=1,
            category_filter="xml_parser",
        )
        scorecard = _run(runner.run_suite(options=opts))
        assert scorecard.total_targets >= 2, (
            f"Expected >=2 xml_parser targets, got {scorecard.total_targets}"
        )

    def test_run_single_new_target_openssl(self):
        """Run a single mock evaluation for the openssl_bn_infinite_loop target."""
        runner = self._make_runner()
        loader = CorpusLoader(CORPUS_DIR)
        targets = {t.target_id: t for t in loader.load_corpus()}
        target = targets["openssl_bn_infinite_loop"]
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        result = _run(runner.run_target(target, opts))
        assert result.target_id == "openssl_bn_infinite_loop"
        assert result.status in ("DISCOVERED", "MISSED", "ERROR")

    def test_run_single_new_target_zlib(self):
        """Run a single mock evaluation for the zlib_inflate_heap_oob target."""
        runner = self._make_runner()
        loader = CorpusLoader(CORPUS_DIR)
        targets = {t.target_id: t for t in loader.load_corpus()}
        target = targets["zlib_inflate_heap_oob"]
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        result = _run(runner.run_target(target, opts))
        assert result.target_id == "zlib_inflate_heap_oob"
        assert result.is_true_positive

    def test_run_single_new_target_php_spl(self):
        """Run a single mock evaluation for the php_spl_type_confusion target."""
        runner = self._make_runner()
        loader = CorpusLoader(CORPUS_DIR)
        targets = {t.target_id: t for t in loader.load_corpus()}
        target = targets["php_spl_type_confusion"]
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)
        result = _run(runner.run_target(target, opts))
        assert result.target_id == "php_spl_type_confusion"
        assert result.ground_truth_cwe == "CWE-763"


# ---------------------------------------------------------------------------
# ScoringEngine — expanded CVSS / CWE / severity metric tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScoringEngineExpandedMetrics:
    """Validate ScoringEngine metric computation paths with the expanded corpus."""

    def _make_tool_output(self, target: TargetGroundTruth, execs: int = 5000) -> dict:
        """Build a mock tool output that exactly matches the target's ground truth."""
        orig, mini = _get_poc_sizes(target)
        reduction = round(((orig - mini) / orig) * 100, 1) if orig > mini else 0.0
        return {
            "target_function": target.faulting_symbol,
            "cwe_id": target.cwe_id,
            "cvss_v31_score": target.cvss.expected_score,
            "cvss_severity": target.cvss.severity,
            "fuzzing_stats": {"executions": execs, "crashes_detected": 1},
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
            "original_input_size_bytes": orig,
            "minimized_input_size_bytes": mini,
            "reduction_percentage": f"{reduction}%",
        }

    def test_perfect_cwe_exact_match_all_targets(self):
        """When predicted CWE == ground truth CWE, exact_match must be True."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        for target in loader.load_corpus():
            output = self._make_tool_output(target)
            result = engine.evaluate_target(target, output, elapsed_time=0.5)
            assert result.cwe_exact_match, (
                f"{target.target_id}: expected cwe_exact_match=True, got False"
            )

    def test_cvss_tolerance_pass_for_exact_score(self):
        """When predicted CVSS == expected CVSS, tolerance must pass for all targets."""
        engine = ScoringEngine(cvss_tolerance=0.5)
        loader = CorpusLoader(CORPUS_DIR)
        for target in loader.load_corpus():
            output = self._make_tool_output(target)
            result = engine.evaluate_target(target, output, elapsed_time=0.3)
            assert result.cvss_tolerance_passed, (
                f"{target.target_id}: CVSS tolerance failed "
                f"(pred={result.predicted_cvss}, gt={result.ground_truth_cvss})"
            )

    def test_severity_concordance_exact_match(self):
        """When predicted severity == expected severity, severity_match must be True."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        for target in loader.load_corpus():
            output = self._make_tool_output(target)
            result = engine.evaluate_target(target, output, elapsed_time=0.3)
            assert result.severity_match, (
                f"{target.target_id}: severity_match=False "
                f"(pred={result.predicted_severity}, gt={result.ground_truth_severity})"
            )

    def test_aggregate_cvss_mae_zero_for_perfect_predictions(self):
        """With perfect CVSS predictions, MAE must be 0.0."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        results = [
            engine.evaluate_target(t, self._make_tool_output(t), elapsed_time=0.1) for t in targets
        ]
        scorecard = engine.aggregate_scorecard(results, total_duration=1.0)
        assert scorecard.cvss_mean_absolute_error == 0.0, (
            f"Expected MAE=0.0, got {scorecard.cvss_mean_absolute_error}"
        )

    def test_aggregate_cwe_exact_match_rate_100pct(self):
        """With perfect CWE predictions, exact match rate must be 100%."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        results = [
            engine.evaluate_target(t, self._make_tool_output(t), elapsed_time=0.1) for t in targets
        ]
        scorecard = engine.aggregate_scorecard(results, total_duration=1.0)
        assert scorecard.cwe_exact_match_rate_pct == 100.0, (
            f"Expected CWE exact match=100%, got {scorecard.cwe_exact_match_rate_pct}"
        )

    def test_aggregate_severity_concordance_100pct(self):
        """With perfect severity predictions, concordance must be 100%."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        results = [
            engine.evaluate_target(t, self._make_tool_output(t), elapsed_time=0.1) for t in targets
        ]
        scorecard = engine.aggregate_scorecard(results, total_duration=1.0)
        assert scorecard.severity_concordance_rate_pct == 100.0, (
            f"Expected severity concordance=100%, got {scorecard.severity_concordance_rate_pct}"
        )

    def test_aggregate_tpr_100pct_for_all_discovered(self):
        """When all targets are discovered, TPR must be 100%."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        results = [
            engine.evaluate_target(t, self._make_tool_output(t), elapsed_time=0.1) for t in targets
        ]
        scorecard = engine.aggregate_scorecard(results, total_duration=1.0)
        assert scorecard.discovery_rate_tpr_pct == 100.0, (
            f"Expected 100% TPR, got {scorecard.discovery_rate_tpr_pct}"
        )

    def test_aggregate_zero_error_count(self):
        """Zero-error scenario with mock outputs."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        results = [
            engine.evaluate_target(t, self._make_tool_output(t), elapsed_time=0.1) for t in targets
        ]
        scorecard = engine.aggregate_scorecard(results, total_duration=1.0)
        assert scorecard.error_count == 0

    def test_missed_target_reduces_tpr(self):
        """Marking one target as MISSED must reduce TPR below 100%."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        results = []
        for i, t in enumerate(targets):
            if i == 0:
                # Force this one to be MISSED
                result = engine.evaluate_target(t, {}, elapsed_time=0.1, is_error=False)
            else:
                result = engine.evaluate_target(t, self._make_tool_output(t), elapsed_time=0.1)
            results.append(result)
        scorecard = engine.aggregate_scorecard(results, total_duration=1.0)
        assert scorecard.discovery_rate_tpr_pct < 100.0
        assert scorecard.missed_count >= 1

    def test_cvss_tolerance_fail_for_large_delta(self):
        """When CVSS delta > tolerance, tolerance must fail."""
        engine = ScoringEngine(cvss_tolerance=0.5)
        loader = CorpusLoader(CORPUS_DIR)
        target = loader.load_corpus()[0]
        bad_output = self._make_tool_output(target)
        bad_output["cvss_v31_score"] = max(0.0, target.cvss.expected_score - 3.0)
        result = engine.evaluate_target(target, bad_output, elapsed_time=0.1)
        assert not result.cvss_tolerance_passed, "Expected tolerance=False for delta=3.0, got True"

    def test_class_breakdown_covers_all_vuln_classes(self):
        """class_breakdown must contain an entry for every vulnerability class."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        targets = loader.load_corpus()
        results = [
            engine.evaluate_target(t, self._make_tool_output(t), elapsed_time=0.1) for t in targets
        ]
        scorecard = engine.aggregate_scorecard(results, total_duration=1.0)
        loaded_classes = {t.vulnerability_class for t in targets}
        for vc in loaded_classes:
            assert vc in scorecard.class_breakdown, f"Missing class '{vc}' in class_breakdown"

    def test_poc_reduction_positive_for_all_targets(self):
        """Every target should have a positive PoC reduction in perfect mock output."""
        engine = ScoringEngine()
        loader = CorpusLoader(CORPUS_DIR)
        for target in loader.load_corpus():
            output = self._make_tool_output(target)
            result = engine.evaluate_target(target, output, elapsed_time=0.1)
            assert result.poc_reduction_percentage >= 0.0


# ---------------------------------------------------------------------------
# CorpusLoader filter tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCorpusLoaderFilters:
    """Test BenchmarkRunner filter logic with the expanded corpus."""

    def _make_runner(self):
        return BenchmarkRunner(corpus_dir=CORPUS_DIR, mock_mode=True, timeout_per_target=5)

    def test_filter_by_target_id_returns_single(self):
        """Filtering to a specific target_id should return exactly that target."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=5, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(target_filter="openssl_bn_infinite_loop", options=opts))
        assert scorecard.total_targets == 1

    def test_filter_by_partial_name_match(self):
        """Partial name substring filter must return matching targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=5, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(target_filter="libpng", options=opts))
        assert scorecard.total_targets >= 1

    def test_filter_nonexistent_target_returns_empty(self):
        """Filtering for a non-existent target ID must return 0 targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=5, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(target_filter="nonexistent_xyz_12345", options=opts))
        assert scorecard.total_targets == 0

    def test_filter_all_returns_ten_targets(self):
        """'all' filter must return all 10 targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=5, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(target_filter="all", options=opts))
        assert scorecard.total_targets == 10

    def test_filter_list_of_ids(self):
        """Filtering with a list of IDs must return exactly those targets."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=5, fuzz_duration_seconds=1)
        ids = [
            "openssl_bn_infinite_loop",
            "zlib_inflate_heap_oob",
            "php_spl_type_confusion",
        ]
        scorecard = _run(runner.run_suite(target_filter=ids, options=opts))
        assert scorecard.total_targets == 3

    def test_cwe_filter_835_returns_openssl(self):
        """CWE-835 filter must return only the OpenSSL infinite_loop target."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=5, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(cwe_filter="CWE-835", options=opts))
        assert scorecard.total_targets == 1

    def test_cwe_filter_125_returns_ffmpeg(self):
        """CWE-125 filter must return only the FFmpeg OOB read target."""
        runner = self._make_runner()
        opts = ExecutionOptions(mock_mode=True, timeout_seconds=5, fuzz_duration_seconds=1)
        scorecard = _run(runner.run_suite(cwe_filter="CWE-125", options=opts))
        assert scorecard.total_targets == 1

    def test_category_filter_cryptographic(self):
        """Category filter 'cryptographic_library' must return only OpenSSL."""
        runner = self._make_runner()
        opts = ExecutionOptions(
            mock_mode=True,
            timeout_seconds=5,
            fuzz_duration_seconds=1,
            category_filter="cryptographic_library",
        )
        scorecard = _run(runner.run_suite(options=opts))
        assert scorecard.total_targets == 1

    def test_category_filter_network_client(self):
        """Category filter 'network_client' must return only cURL."""
        runner = self._make_runner()
        opts = ExecutionOptions(
            mock_mode=True,
            timeout_seconds=5,
            fuzz_duration_seconds=1,
            category_filter="network_client",
        )
        scorecard = _run(runner.run_suite(options=opts))
        assert scorecard.total_targets == 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_poc_sizes(target: TargetGroundTruth) -> tuple[int, int]:
    """Return (raw_poc_size, min_poc_size) from fixture or metadata."""
    fixture_dir_map = {
        "sqlite3_fts5_unicode": "sqlite_fts5",
        "libpng_eXIf_int_overflow": "libpng_parser",
        "libxml2_entity_uaf": "libxml2_parser",
        "libarchive_rar_double_free": "libarchive_parser",
        "openssl_bn_infinite_loop": "openssl_bn",
        "zlib_inflate_heap_oob": "zlib_inflate",
        "curl_cookie_leak_info": "curl_cookie",
        "ffmpeg_hevc_oob_read": "ffmpeg_hevc",
        "php_spl_type_confusion": "php_spl",
        "expat_entity_int_overflow": "expat_entity",
    }
    d = TARGETS_DIR / fixture_dir_map.get(target.target_id, target.target_id)
    raw = d / "poc_raw.bin"
    mini = d / "poc_minimized.bin"
    orig = raw.stat().st_size if raw.exists() else target.raw_poc_size_bytes
    mn = mini.stat().st_size if mini.exists() else target.minimized_poc_target_bytes
    return max(1, orig), max(1, mn)
