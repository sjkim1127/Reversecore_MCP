"""Comprehensive Unit Tests for Benchmark Models, CWE Taxonomy, and CorpusLoader.

Verifies:
- Data models (TargetGroundTruth, CVSSGroundTruth, FixturePaths, TargetEvaluationResult,
  BenchmarkScorecardSummary, ExecutionOptions) serialization, deserialization, validation.
- CWE taxonomy normalization, DAG parent/child/ancestor traversal, and scoring engine concordance.
- CorpusLoader master corpus parsing, single target JSON loading, multi-dimensional filtering,
  fixture verification, and error handling.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    CVSSGroundTruth,
    ExecutionOptions,
    FixturePaths,
    GroundTruthMetadata,
    TargetEvaluationResult,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.taxonomy import (
    calculate_cwe_taxonomic_score,
    get_cwe_ancestors,
    get_cwe_children,
    get_cwe_descendants,
    get_cwe_parents,
    normalize_cwe_id,
)

FIXTURES_DIR = Path(__file__).parents[2] / "tests" / "fixtures" / "benchmarks"
CORPUS_JSON_PATH = FIXTURES_DIR / "ground_truth_corpus.json"


# ============================================================================
# 1. Benchmark Data Models Tests
# ============================================================================


class TestBenchmarkDataModels:
    """Test suite for Benchmark Pydantic and dataclass models."""

    def test_cvss_ground_truth_valid(self):
        """Test valid CVSSGroundTruth instantiation and field access."""
        cvss = CVSSGroundTruth(
            base_score_min=8.0,
            base_score_max=9.8,
            expected_score=8.8,
            severity="HIGH",
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            tolerated_vectors=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
        )
        assert cvss.base_score_min == 8.0
        assert cvss.base_score_max == 9.8
        assert cvss.expected_score == 8.8
        assert cvss.severity == "HIGH"
        assert cvss.expected_vector.startswith("CVSS:3.1")
        assert len(cvss.tolerated_vectors) == 1

    def test_cvss_ground_truth_invalid_bounds(self):
        """Test CVSSGroundTruth validation fails when score out of range [0.0, 10.0]."""
        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=-1.0,
                base_score_max=9.0,
                expected_score=8.0,
                severity="HIGH",
                expected_vector="CVSS:3.1/...",
            )

        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=8.0,
                base_score_max=11.0,
                expected_score=8.0,
                severity="HIGH",
                expected_vector="CVSS:3.1/...",
            )

        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=8.0,
                base_score_max=7.0,  # max < min
                expected_score=8.0,
                severity="HIGH",
                expected_vector="CVSS:3.1/...",
            )

    def test_cvss_ground_truth_invalid_severity(self):
        """Test CVSSGroundTruth validation fails with invalid severity literal."""
        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=8.0,
                base_score_max=9.0,
                expected_score=8.5,
                severity="SUPER_CRITICAL",  # type: ignore[arg-type]
                expected_vector="CVSS:3.1/...",
            )

    def test_fixture_paths_valid_and_extra_fields(self):
        """Test FixturePaths instantiation and custom field handling."""
        fixtures = FixturePaths(
            vulnerable_source="targets/test/vulnerable.c",
            patched_source="targets/test/patched.c",
            patch_diff="targets/test/patch.diff",
            harness_c="targets/test/harness.c",
            asan_crash_log="targets/test/asan_crash.log",
            valid_seed_corpus="targets/test/seed.bin",
            raw_crash_poc="targets/test/poc_raw.bin",
            minimized_poc="targets/test/poc_min.bin",
            dictionary_path="targets/test/dict.dict",
            extra_field="extra_data",
        )
        assert fixtures.vulnerable_source == "targets/test/vulnerable.c"
        assert fixtures.dictionary_path == "targets/test/dict.dict"
        assert fixtures.minimized_poc == "targets/test/poc_min.bin"

    def test_target_ground_truth_full_instantiation(self):
        """Test full TargetGroundTruth instantiation with all fields."""
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
                dictionary_path="targets/sqlite_fts5/dictionary.dict",
            ),
            raw_poc_size_bytes=39,
            minimized_poc_target_bytes=6,
            expected_minimization_ratio_min=0.8,
            dictionary_tokens=["tokenize", "unicode61", "fts5"],
            max_time_to_crash_seconds=30,
        )
        assert target.target_id == "sqlite3_fts5_unicode"
        assert target.cwe_id == "CWE-122"
        assert target.expected_access_size == 4
        assert len(target.dictionary_tokens) == 3

    def test_target_ground_truth_validation_failures(self):
        """Test TargetGroundTruth validation constraints."""
        valid_cvss = CVSSGroundTruth(
            base_score_min=8.0,
            base_score_max=9.8,
            expected_score=8.8,
            severity="HIGH",
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        )
        valid_fixtures = FixturePaths(
            vulnerable_source="targets/sqlite_fts5/vulnerable.c",
            patched_source="targets/sqlite_fts5/patched.c",
            patch_diff="targets/sqlite_fts5/patch.diff",
            harness_c="targets/sqlite_fts5/harness.c",
            asan_crash_log="targets/sqlite_fts5/asan_crash.log",
            valid_seed_corpus="targets/sqlite_fts5/seed_valid.bin",
            raw_crash_poc="targets/sqlite_fts5/poc_raw.bin",
            minimized_poc="targets/sqlite_fts5/poc_minimized.bin",
        )

        # Invalid CWE regex (e.g. missing CWE- prefix)
        with pytest.raises(ValidationError):
            TargetGroundTruth(
                target_id="t1",
                target_name="T1",
                category="test",
                real_world_library="lib",
                target_version="1.0",
                cve_reference="CVE-2020-0001",
                vulnerability_class="heap_overflow",
                cwe_id="122",  # invalid pattern
                cwe_name="Heap Overflow",
                faulting_symbol="sym",
                source_file="src.c",
                source_line=10,
                expected_memory_access_type="WRITE_OOB",
                expected_access_size=4,
                cvss=valid_cvss,
                fixtures=valid_fixtures,
                raw_poc_size_bytes=100,
                minimized_poc_target_bytes=20,
                expected_minimization_ratio_min=0.5,
            )

        # Invalid source_line <= 0
        with pytest.raises(ValidationError):
            TargetGroundTruth(
                target_id="t1",
                target_name="T1",
                category="test",
                real_world_library="lib",
                target_version="1.0",
                cve_reference="CVE-2020-0001",
                vulnerability_class="heap_overflow",
                cwe_id="CWE-122",
                cwe_name="Heap Overflow",
                faulting_symbol="sym",
                source_file="src.c",
                source_line=0,  # line <= 0
                expected_memory_access_type="WRITE_OOB",
                expected_access_size=4,
                cvss=valid_cvss,
                fixtures=valid_fixtures,
                raw_poc_size_bytes=100,
                minimized_poc_target_bytes=20,
                expected_minimization_ratio_min=0.5,
            )

        # Invalid expected_minimization_ratio_min > 1.0
        with pytest.raises(ValidationError):
            TargetGroundTruth(
                target_id="t1",
                target_name="T1",
                category="test",
                real_world_library="lib",
                target_version="1.0",
                cve_reference="CVE-2020-0001",
                vulnerability_class="heap_overflow",
                cwe_id="CWE-122",
                cwe_name="Heap Overflow",
                faulting_symbol="sym",
                source_file="src.c",
                source_line=10,
                expected_memory_access_type="WRITE_OOB",
                expected_access_size=4,
                cvss=valid_cvss,
                fixtures=valid_fixtures,
                raw_poc_size_bytes=100,
                minimized_poc_target_bytes=20,
                expected_minimization_ratio_min=1.5,  # > 1.0
            )

    def test_target_ground_truth_serialization_round_trip(self):
        """Test TargetGroundTruth to_dict, to_json, from_dict, from_json."""
        target = TargetGroundTruth(
            target_id="test_target",
            target_name="Test Target",
            category="image_parser",
            real_world_library="LibTest",
            target_version="1.0.0",
            cve_reference="CVE-2021-9999",
            vulnerability_class="use_after_free",
            cwe_id="CWE-416",
            cwe_name="Use After Free",
            faulting_symbol="free_item",
            source_file="test.c",
            source_line=42,
            expected_memory_access_type="UAF_READ",
            expected_access_size=8,
            cvss=CVSSGroundTruth(
                base_score_min=7.0,
                base_score_max=9.0,
                expected_score=8.1,
                severity="HIGH",
                expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",
            ),
            fixtures=FixturePaths(
                vulnerable_source="vuln.c",
                patched_source="patch.c",
                patch_diff="diff.diff",
                harness_c="harness.c",
                asan_crash_log="asan.log",
                valid_seed_corpus="seed.bin",
                raw_crash_poc="poc.bin",
                minimized_poc="poc_min.bin",
            ),
            raw_poc_size_bytes=120,
            minimized_poc_target_bytes=30,
            expected_minimization_ratio_min=0.75,
        )

        d = target.to_dict()
        assert isinstance(d, dict)
        assert d["target_id"] == "test_target"

        from_d = TargetGroundTruth.from_dict(d)
        assert from_d.target_id == target.target_id
        assert from_d.cvss.expected_score == target.cvss.expected_score

        json_str = target.to_json(indent=2)
        assert "test_target" in json_str

        from_j = TargetGroundTruth.from_json(json_str)
        assert from_j.target_id == target.target_id

    def test_target_evaluation_result_dataclass_methods(self):
        """Test TargetEvaluationResult dataclass methods and serialization."""
        result = TargetEvaluationResult(
            target_id="target_x",
            target_name="Target X",
            vulnerability_class="integer_overflow",
            status="DISCOVERED",
            is_true_positive=True,
            time_to_crash_seconds=1.45,
            total_executions=3500,
            throughput_execs_per_sec=2413.8,
            original_poc_size_bytes=100,
            minimized_poc_size_bytes=25,
            poc_reduction_percentage=75.0,
            ground_truth_cwe="CWE-190",
            predicted_cwe="CWE-190",
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
            faulting_symbol="overflow_fn",
            error_message=None,
            details={"notes": "all clear"},
        )

        d = result.to_dict()
        assert d["target_id"] == "target_x"
        assert d["is_true_positive"] is True

        deserialized = TargetEvaluationResult.from_dict(d)
        assert deserialized.target_id == result.target_id
        assert deserialized.poc_reduction_percentage == 75.0

        json_s = result.to_json()
        from_json_res = TargetEvaluationResult.from_json(json_s)
        assert from_json_res.target_name == "Target X"

    def test_benchmark_scorecard_summary_methods(self):
        """Test BenchmarkScorecardSummary dataclass methods and nested parsing."""
        res1 = TargetEvaluationResult(
            target_id="t1",
            target_name="Target 1",
            vulnerability_class="heap_buffer_overflow",
            status="DISCOVERED",
            is_true_positive=True,
            time_to_crash_seconds=1.2,
            total_executions=4000,
            throughput_execs_per_sec=3333.3,
            original_poc_size_bytes=68,
            minimized_poc_size_bytes=6,
            poc_reduction_percentage=91.1,
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
            faulting_symbol="tokenize",
        )

        summary = BenchmarkScorecardSummary(
            total_targets=1,
            discovered_count=1,
            missed_count=0,
            error_count=0,
            discovery_rate_tpr_pct=100.0,
            mean_time_to_crash_seconds=1.2,
            avg_throughput_exec_per_sec=3333.3,
            avg_poc_reduction_pct=91.1,
            cwe_exact_match_rate_pct=100.0,
            cwe_hierarchical_match_rate_pct=100.0,
            cvss_mean_absolute_error=0.0,
            cvss_tolerance_match_rate_pct=100.0,
            severity_concordance_rate_pct=100.0,
            class_breakdown={"heap_buffer_overflow": {"total": 1, "discovered": 1}},
            target_results=[res1],
            total_duration_seconds=1.5,
        )

        d = summary.to_dict()
        assert d["total_targets"] == 1
        assert len(d["target_results"]) == 1

        deserialized = BenchmarkScorecardSummary.from_dict(d)
        assert deserialized.total_targets == 1
        assert isinstance(deserialized.target_results[0], TargetEvaluationResult)
        assert deserialized.target_results[0].target_id == "t1"

        json_str = summary.to_json()
        from_j = BenchmarkScorecardSummary.from_json(json_str)
        assert from_j.discovery_rate_tpr_pct == 100.0

    def test_execution_options(self):
        """Test ExecutionOptions model defaults and custom settings."""
        opts = ExecutionOptions()
        assert opts.targets_filter == "all"
        assert opts.cwe_filter == "all"
        assert opts.timeout_seconds == 30
        assert opts.parallel_workers == 1
        assert opts.mock_mode is False

        custom = ExecutionOptions(
            targets_filter="sqlite3",
            cwe_filter="CWE-122",
            timeout_seconds=60,
            mock_mode=True,
            fail_under_tpr=90.0,
        )
        assert custom.targets_filter == "sqlite3"
        assert custom.mock_mode is True
        assert custom.fail_under_tpr == 90.0

        d = custom.to_dict()
        assert d["timeout_seconds"] == 60
        reconstructed = ExecutionOptions.from_dict(d)
        assert reconstructed.targets_filter == "sqlite3"

    def test_ground_truth_metadata_alias(self):
        """Test GroundTruthMetadata is an alias for TargetGroundTruth."""
        assert GroundTruthMetadata is TargetGroundTruth


# ============================================================================
# 2. CWE Taxonomy & Distance Engine Tests
# ============================================================================


class TestCWETaxonomy:
    """Test suite for CWE hierarchy DAG, normalization, and distance scoring."""

    def test_normalize_cwe_id_variants(self):
        """Test normalization handles various string variations."""
        assert normalize_cwe_id("CWE-122") == "CWE-122"
        assert normalize_cwe_id("cwe-122") == "CWE-122"
        assert normalize_cwe_id("  cwe-415  ") == "CWE-415"
        assert normalize_cwe_id("cwe190") == "CWE-190"
        assert normalize_cwe_id("CWE_190") == "CWE-190"
        assert normalize_cwe_id("416") == "CWE-416"
        assert normalize_cwe_id("122") == "CWE-122"
        assert normalize_cwe_id("") == ""
        assert normalize_cwe_id("   ") == ""
        assert normalize_cwe_id(None) == ""
        assert normalize_cwe_id("UNKNOWN") == "UNKNOWN"
        assert normalize_cwe_id("HEAP_BUFFER_OVERFLOW") == "HEAP_BUFFER_OVERFLOW"

    def test_cwe_parent_child_lookup(self):
        """Test parent and child query functions."""
        assert get_cwe_parents("CWE-122") == ["CWE-787"]
        assert "CWE-672" in get_cwe_parents("CWE-415")
        assert "CWE-761" in get_cwe_parents("CWE-415")
        assert get_cwe_parents("CWE-99999") == []

        children_787 = get_cwe_children("CWE-787")
        assert "CWE-122" in children_787
        assert "CWE-121" in children_787

    def test_cwe_ancestor_and_descendant_traversal(self):
        """Test recursive ancestor and descendant traversal in DAG."""
        ancestors_122 = get_cwe_ancestors("CWE-122")
        assert "CWE-787" in ancestors_122
        assert "CWE-119" in ancestors_122
        assert "CWE-664" in ancestors_122

        descendants_119 = get_cwe_descendants("CWE-119")
        assert "CWE-122" in descendants_119
        assert "CWE-121" in descendants_119
        assert "CWE-125" in descendants_119
        assert "CWE-787" in descendants_119

    def test_exact_cwe_scoring(self):
        """Test exact match scoring returns 1.0 and True."""
        score, is_match = calculate_cwe_taxonomic_score("CWE-122", "CWE-122")
        assert score == 1.0
        assert is_match is True

        score, is_match = calculate_cwe_taxonomic_score("cwe-416", "CWE-416")
        assert score == 1.0
        assert is_match is True

    def test_parent_child_cwe_scoring(self):
        """Test parent/child relationship scoring returns 0.75 and True."""
        # Child vs Parent
        score, is_match = calculate_cwe_taxonomic_score("CWE-122", "CWE-787")
        assert score == 0.75
        assert is_match is True

        # Parent vs Child (symmetric)
        score, is_match = calculate_cwe_taxonomic_score("CWE-787", "CWE-122")
        assert score == 0.75
        assert is_match is True

        # UAF vs Expired Resource
        score, is_match = calculate_cwe_taxonomic_score("CWE-416", "CWE-672")
        assert score == 0.75
        assert is_match is True

        # Integer Overflow vs Calculation Error
        score, is_match = calculate_cwe_taxonomic_score("CWE-190", "CWE-682")
        assert score == 0.75
        assert is_match is True

    def test_ancestor_and_sibling_class_cwe_scoring(self):
        """Test multi-hop ancestor and shared class scoring returns 0.50 and True."""
        # Multi-hop ancestor: CWE-122 (Heap OOBW) vs CWE-119 (Buffer Bounds)
        score, is_match = calculate_cwe_taxonomic_score("CWE-122", "CWE-119")
        assert score == 0.50
        assert is_match is True

        # Sibling classes: CWE-122 (Heap OOBW) vs CWE-121 (Stack OOBW)
        score, is_match = calculate_cwe_taxonomic_score("CWE-122", "CWE-121")
        assert score == 0.50
        assert is_match is True

        # Sibling classes: CWE-125 (OOBR) vs CWE-122 (OOBW)
        score, is_match = calculate_cwe_taxonomic_score("CWE-125", "CWE-122")
        assert score == 0.50
        assert is_match is True

        # Sibling classes: CWE-415 (Double Free) vs CWE-416 (UAF)
        score, is_match = calculate_cwe_taxonomic_score("CWE-415", "CWE-416")
        assert score == 0.50
        assert is_match is True

    def test_unrelated_cwe_scoring(self):
        """Test unrelated CWE categories return 0.0 and False."""
        score, is_match = calculate_cwe_taxonomic_score("CWE-79", "CWE-122")  # XSS vs Heap OOB
        assert score == 0.0
        assert is_match is False

        score, is_match = calculate_cwe_taxonomic_score("CWE-89", "CWE-416")  # SQLi vs UAF
        assert score == 0.0
        assert is_match is False

    def test_invalid_and_unknown_cwe_scoring(self):
        """Test non-existent, empty, and UNKNOWN CWE strings safely return 0.0 and False."""
        assert calculate_cwe_taxonomic_score("", "CWE-122") == (0.0, False)
        assert calculate_cwe_taxonomic_score(None, "CWE-122") == (0.0, False)
        assert calculate_cwe_taxonomic_score("UNKNOWN", "CWE-122") == (0.0, False)
        assert calculate_cwe_taxonomic_score("CWE-99999", "CWE-122") == (0.0, False)
        assert calculate_cwe_taxonomic_score("HEAP_BUFFER_OVERFLOW", "CWE-122") == (
            0.0,
            False,
        )

    def test_taxonomic_scoring_symmetry(self):
        """Verify calculate_cwe_taxonomic_score is strictly symmetrical."""
        pairs = [
            ("CWE-122", "CWE-787"),
            ("CWE-122", "CWE-119"),
            ("CWE-122", "CWE-121"),
            ("CWE-415", "CWE-416"),
            ("CWE-190", "CWE-682"),
            ("CWE-79", "CWE-416"),
        ]
        for cwe_a, cwe_b in pairs:
            s_ab, m_ab = calculate_cwe_taxonomic_score(cwe_a, cwe_b)
            s_ba, m_ba = calculate_cwe_taxonomic_score(cwe_b, cwe_a)
            assert s_ab == s_ba, f"Asymmetry in score for ({cwe_a}, {cwe_b})"
            assert m_ab == m_ba, f"Asymmetry in match flag for ({cwe_a}, {cwe_b})"


# ============================================================================
# 3. CorpusLoader Tests
# ============================================================================


class TestCorpusLoader:
    """Test suite for CorpusLoader target discovery, parsing, filtering, and validation."""

    def test_load_master_corpus(self):
        """Test loading master corpus from default fixtures path."""
        loader = CorpusLoader(FIXTURES_DIR)
        targets = loader.load_corpus()
        assert len(targets) == 10

        target_ids = {t.target_id for t in targets}
        expected_ids = {
            "sqlite3_fts5_unicode",
            "libpng_eXIf_int_overflow",
            "libxml2_entity_uaf",
            "libarchive_rar_double_free",
            # 6 targets added in corpus expansion
            "openssl_bn_infinite_loop",
            "zlib_inflate_heap_oob",
            "curl_cookie_leak_info",
            "ffmpeg_hevc_oob_read",
            "php_spl_type_confusion",
            "expat_entity_int_overflow",
        }
        assert target_ids == expected_ids

    def test_load_target_from_json(self):
        """Test loading single target.json file."""
        loader = CorpusLoader(FIXTURES_DIR)
        target_path = FIXTURES_DIR / "targets" / "sqlite_fts5" / "target.json"
        target = loader.load_target_from_json(target_path)
        assert target.target_id == "sqlite3_fts5_unicode"
        assert target.faulting_symbol == "fts5UnicodeTokenize"
        assert target.cwe_id == "CWE-122"

    def test_filter_targets_by_target_id(self):
        """Test filtering targets by target identifier or substring."""
        loader = CorpusLoader(FIXTURES_DIR)
        targets = loader.load_corpus()

        # Exact ID
        res = loader.filter_targets(targets, target_filter="sqlite3_fts5_unicode")
        assert len(res) == 1
        assert res[0].target_id == "sqlite3_fts5_unicode"

        # Substring in name
        res = loader.filter_targets(targets, target_filter="LibPNG")
        assert len(res) == 1
        assert res[0].target_id == "libpng_eXIf_int_overflow"

        # Non-existent ID
        res = loader.filter_targets(targets, target_filter="non_existent_target")
        assert len(res) == 0

    def test_filter_targets_by_cwe(self):
        """Test filtering targets by CWE ID."""
        loader = CorpusLoader(FIXTURES_DIR)
        targets = loader.load_corpus()

        res_416 = loader.filter_targets(targets, cwe_filter="CWE-416")
        assert len(res_416) == 1
        assert res_416[0].target_id == "libxml2_entity_uaf"

        # Normalized query without prefix — CWE-190 now has 2 targets: libpng + expat
        res_190 = loader.filter_targets(targets, cwe_filter="190")
        assert len(res_190) == 2
        res_190_ids = {t.target_id for t in res_190}
        assert "libpng_eXIf_int_overflow" in res_190_ids
        assert "expat_entity_int_overflow" in res_190_ids

        # Non-matching CWE
        res_none = loader.filter_targets(targets, cwe_filter="CWE-79")
        assert len(res_none) == 0

    def test_filter_targets_by_category_and_vuln_class(self):
        """Test filtering targets by category and vulnerability class."""
        loader = CorpusLoader(FIXTURES_DIR)
        targets = loader.load_corpus()

        res_cat = loader.filter_targets(targets, category_filter="archive_parser")
        assert len(res_cat) == 1
        assert res_cat[0].target_id == "libarchive_rar_double_free"

        res_vc = loader.filter_targets(targets, vulnerability_class_filter="double_free")
        assert len(res_vc) == 1
        assert res_vc[0].target_id == "libarchive_rar_double_free"

    def test_filter_targets_all_passthrough(self):
        """Test filter 'all' returns the complete list unchanged."""
        loader = CorpusLoader(FIXTURES_DIR)
        targets = loader.load_corpus()
        res = loader.filter_targets(
            targets,
            target_filter="all",
            cwe_filter="all",
            category_filter="all",
            vulnerability_class_filter="all",
        )
        assert len(res) == len(targets)

    def test_validate_target_fixtures_real_corpus(self):
        """Test fixture validation passes for all actual targets in benchmark fixtures."""
        loader = CorpusLoader(FIXTURES_DIR)
        targets = loader.load_corpus()
        for t in targets:
            status = loader.validate_target_fixtures(t)
            for fixture_key, exists in status.items():
                assert exists is True, f"Missing fixture '{fixture_key}' for target '{t.target_id}'"

    def test_validate_target_fixtures_missing_dir(self, tmp_path):
        """Test fixture validation correctly flags missing files in empty directory."""
        loader = CorpusLoader(FIXTURES_DIR)
        target = loader.load_corpus()[0]
        status = loader.validate_target_fixtures(target, base_dir=tmp_path)
        assert status["vulnerable_source"] is False
        assert status["patched_source"] is False
        assert status["asan_crash_log"] is False

    def test_validate_corpus_integrity(self):
        """Test validate_corpus_integrity on full master fixture corpus."""
        loader = CorpusLoader(FIXTURES_DIR)
        summary = loader.validate_corpus_integrity()
        assert summary["valid"] is True
        assert summary["total_targets"] == 10
        assert len(summary["target_details"]) == 10

    def test_load_target_from_json_error(self, tmp_path):
        """Test load_target_from_json raises FileNotFoundError when file does not exist."""
        loader = CorpusLoader(FIXTURES_DIR)
        with pytest.raises(FileNotFoundError):
            loader.load_target_from_json(tmp_path / "phantom_target.json")

    def test_validate_corpus_integrity_with_missing_fixtures(self, tmp_path):
        """Test validate_corpus_integrity correctly returns valid=False when fixtures are missing."""
        loader = CorpusLoader(FIXTURES_DIR)
        summary = loader.validate_corpus_integrity(base_dir=tmp_path)
        assert summary["valid"] is False
        assert summary["total_targets"] == 10
        assert any(d["all_fixtures_present"] is False for d in summary["target_details"])

    def test_load_corpus_error_handling(self, tmp_path):
        """Test load_corpus error handling on non-existent, corrupt, empty files."""
        loader = CorpusLoader(tmp_path)

        # FileNotFoundError
        with pytest.raises(FileNotFoundError):
            loader.load_corpus(tmp_path / "does_not_exist.json")

        # JSONDecodeError on syntax corruption
        corrupt_file = tmp_path / "corrupt.json"
        corrupt_file.write_text('{"targets": [ {"target_id": "incomplete"', encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            loader.load_corpus(corrupt_file)

        # ValueError on empty array
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("[]", encoding="utf-8")
        with pytest.raises(ValueError, match="contains 0 targets"):
            loader.load_corpus(empty_file)

        # ValueError on invalid top-level type
        invalid_type_file = tmp_path / "invalid_type.json"
        invalid_type_file.write_text('"just a string"', encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid corpus format"):
            loader.load_corpus(invalid_type_file)
