"""Adversarial and Stress Test Suite for Benchmark Models, Taxonomy, and CorpusLoader.

Rigorously stress-tests:
- Model validation constraints, type coercion, boundaries, out-of-range floats, NaNs, infinities,
  negative line numbers, empty strings, missing fields, and dataclass serialization/deserialization.
- CWE taxonomy normalization with bizarre inputs, cycle freedom across the DAG,
  multihop graph traversal, multi-parent nodes, and pairwise taxonomic score symmetry.
- CorpusLoader handling of non-existent files, corrupted JSON, missing attributes,
  unexpected formats, regex special characters in filters, and partial fixture files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    CVSSGroundTruth,
    ExecutionOptions,
    FixturePaths,
    TargetEvaluationResult,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.taxonomy import (
    CWE_PARENTS,
    calculate_cwe_taxonomic_score,
    get_cwe_ancestors,
    get_cwe_descendants,
    get_cwe_parents,
    normalize_cwe_id,
)

FIXTURES_DIR = Path(__file__).parents[2] / "tests" / "fixtures" / "benchmarks"


# ============================================================================
# 1. Adversarial Model Stress Tests
# ============================================================================


class TestAdversarialModels:
    """Stress-test data models with boundary, invalid, and extreme inputs."""

    @pytest.mark.parametrize(
        "min_score,max_score,expected_score,should_fail",
        [
            (-0.001, 5.0, 5.0, True),  # Negative min
            (0.0, 10.001, 5.0, True),  # Max > 10.0
            (0.0, 5.0, -0.1, True),  # Expected < 0.0
            (0.0, 5.0, 10.1, True),  # Expected > 10.0
            (8.0, 7.99, 8.0, True),  # Max < Min
            (0.0, 0.0, 0.0, False),  # Boundary 0.0
            (10.0, 10.0, 10.0, False),  # Boundary 10.0
            (0.00001, 9.99999, 5.555, False),  # Precision
        ],
    )
    def test_cvss_score_boundaries(
        self,
        min_score: float,
        max_score: float,
        expected_score: float,
        should_fail: bool,
    ):
        """Test CVSSGroundTruth score boundary conditions."""
        if should_fail:
            with pytest.raises(ValidationError):
                CVSSGroundTruth(
                    base_score_min=min_score,
                    base_score_max=max_score,
                    expected_score=expected_score,
                    severity="HIGH",
                    expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                )
        else:
            cvss = CVSSGroundTruth(
                base_score_min=min_score,
                base_score_max=max_score,
                expected_score=expected_score,
                severity="HIGH",
                expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
            assert cvss.base_score_min == min_score
            assert cvss.base_score_max == max_score

    @pytest.mark.parametrize(
        "bad_float",
        [float("nan"), float("inf"), float("-inf")],
    )
    def test_cvss_nan_and_inf_rejection(self, bad_float: float):
        """Test CVSSGroundTruth rejects NaN and Infinities."""
        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=bad_float,
                base_score_max=9.0,
                expected_score=8.0,
                severity="HIGH",
                expected_vector="CVSS:3.1/...",
            )

    @pytest.mark.parametrize(
        "invalid_severity",
        ["", "high", "High", "CRIT", "INFORMATIONAL", "NONE", "VERY_HIGH", None],
    )
    def test_cvss_invalid_severities(self, invalid_severity: Any):
        """Test CVSSGroundTruth rejects invalid severity literal values."""
        with pytest.raises(ValidationError):
            CVSSGroundTruth(
                base_score_min=5.0,
                base_score_max=8.0,
                expected_score=6.5,
                severity=invalid_severity,
                expected_vector="CVSS:3.1/...",
            )

    @pytest.mark.parametrize(
        "invalid_field,value",
        [
            ("vulnerable_source", ""),
            ("patched_source", ""),
            ("patch_diff", ""),
            ("harness_c", ""),
            ("asan_crash_log", ""),
            ("valid_seed_corpus", ""),
            ("raw_crash_poc", ""),
            ("minimized_poc", ""),
            ("vulnerable_source", None),
        ],
    )
    def test_fixture_paths_empty_or_null_rejection(self, invalid_field: str, value: Any):
        """Test FixturePaths rejects empty strings or None for mandatory paths."""
        valid_kwargs = {
            "vulnerable_source": "vuln.c",
            "patched_source": "patch.c",
            "patch_diff": "patch.diff",
            "harness_c": "harness.c",
            "asan_crash_log": "asan.log",
            "valid_seed_corpus": "seed.bin",
            "raw_crash_poc": "poc_raw.bin",
            "minimized_poc": "poc_min.bin",
            "dictionary_path": None,
        }
        valid_kwargs[invalid_field] = value
        with pytest.raises(ValidationError):
            FixturePaths(**valid_kwargs)

    @pytest.mark.parametrize(
        "field_name,invalid_val",
        [
            ("target_id", ""),
            ("target_name", ""),
            ("category", ""),
            ("real_world_library", ""),
            ("target_version", ""),
            ("cve_reference", ""),
            ("vulnerability_class", ""),
            ("cwe_id", "cwe-122"),  # Must match ^CWE-\d+$ (uppercase, hyphen, digits)
            ("cwe_id", "122"),
            ("cwe_id", "CWE_122"),
            ("cwe_id", "CWE-"),
            ("cwe_id", "CWE-abc"),
            ("cwe_name", ""),
            ("faulting_symbol", ""),
            ("source_file", ""),
            ("source_line", 0),
            ("source_line", -1),
            ("source_line", -9999),
            ("expected_memory_access_type", ""),
            ("expected_access_size", -1),
            ("raw_poc_size_bytes", 0),
            ("raw_poc_size_bytes", -10),
            ("minimized_poc_target_bytes", 0),
            ("minimized_poc_target_bytes", -5),
            ("expected_minimization_ratio_min", -0.01),
            ("expected_minimization_ratio_min", 1.0001),
            ("max_time_to_crash_seconds", 0),
            ("max_time_to_crash_seconds", -30),
        ],
    )
    def test_target_ground_truth_invalid_fields(self, field_name: str, invalid_val: Any):
        """Test TargetGroundTruth strictly rejects malformed field inputs."""
        base_valid: dict[str, Any] = {
            "target_id": "test_target",
            "target_name": "Test Target Name",
            "category": "parser",
            "real_world_library": "libtest",
            "target_version": "1.0.0",
            "cve_reference": "CVE-2026-0001",
            "vulnerability_class": "heap_buffer_overflow",
            "cwe_id": "CWE-122",
            "cwe_name": "Heap-based Buffer Overflow",
            "faulting_symbol": "test_func",
            "source_file": "test.c",
            "source_line": 100,
            "expected_memory_access_type": "WRITE_OOB",
            "expected_access_size": 4,
            "cvss": CVSSGroundTruth(
                base_score_min=5.0,
                base_score_max=8.0,
                expected_score=6.5,
                severity="MEDIUM",
                expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            ),
            "fixtures": FixturePaths(
                vulnerable_source="vuln.c",
                patched_source="patch.c",
                patch_diff="patch.diff",
                harness_c="harness.c",
                asan_crash_log="asan.log",
                valid_seed_corpus="seed.bin",
                raw_crash_poc="poc_raw.bin",
                minimized_poc="poc_min.bin",
            ),
            "raw_poc_size_bytes": 100,
            "minimized_poc_target_bytes": 20,
            "expected_minimization_ratio_min": 0.8,
            "dictionary_tokens": ["token1"],
            "max_time_to_crash_seconds": 30,
        }
        base_valid[field_name] = invalid_val
        with pytest.raises(ValidationError):
            TargetGroundTruth(**base_valid)

    def test_target_evaluation_result_from_dict_and_json_robustness(self):
        """Test TargetEvaluationResult handles extraneous fields and corrupted JSON."""
        valid_dict = {
            "target_id": "t1",
            "target_name": "Target 1",
            "vulnerability_class": "heap_buffer_overflow",
            "status": "DISCOVERED",
            "is_true_positive": True,
            "time_to_crash_seconds": 0.5,
            "total_executions": 1000,
            "throughput_execs_per_sec": 2000.0,
            "original_poc_size_bytes": 50,
            "minimized_poc_size_bytes": 10,
            "poc_reduction_percentage": 80.0,
            "ground_truth_cwe": "CWE-122",
            "predicted_cwe": "CWE-122",
            "cwe_exact_match": True,
            "cwe_hierarchical_match": True,
            "cwe_match_score": 1.0,
            "ground_truth_cvss": 8.8,
            "predicted_cvss": 8.8,
            "cvss_delta": 0.0,
            "cvss_tolerance_passed": True,
            "predicted_severity": "HIGH",
            "ground_truth_severity": "HIGH",
            "severity_match": True,
            "faulting_symbol": "sym",
            "error_message": None,
            "details": {},
            "unrecognized_future_field": "extra_val",
        }
        res = TargetEvaluationResult.from_dict(valid_dict)
        assert res.target_id == "t1"
        assert not hasattr(res, "unrecognized_future_field")

        with pytest.raises(json.JSONDecodeError):
            TargetEvaluationResult.from_json("CORRUPTED_JSON{")

        with pytest.raises(TypeError):
            TargetEvaluationResult.from_dict({"target_id": "missing_required"})

    def test_benchmark_scorecard_summary_from_json_nested_robustness(self):
        """Test BenchmarkScorecardSummary deserialization with raw JSON dicts in target_results."""
        raw_json_data = {
            "total_targets": 1,
            "discovered_count": 1,
            "missed_count": 0,
            "error_count": 0,
            "discovery_rate_tpr_pct": 100.0,
            "mean_time_to_crash_seconds": 1.0,
            "avg_throughput_exec_per_sec": 1000.0,
            "avg_poc_reduction_pct": 50.0,
            "cwe_exact_match_rate_pct": 100.0,
            "cwe_hierarchical_match_rate_pct": 100.0,
            "cvss_mean_absolute_error": 0.0,
            "cvss_tolerance_match_rate_pct": 100.0,
            "severity_concordance_rate_pct": 100.0,
            "class_breakdown": {},
            "target_results": [
                {
                    "target_id": "t_nested",
                    "target_name": "Target Nested",
                    "vulnerability_class": "uaf",
                    "status": "DISCOVERED",
                    "is_true_positive": True,
                    "time_to_crash_seconds": 1.0,
                    "total_executions": 500,
                    "throughput_execs_per_sec": 500.0,
                    "original_poc_size_bytes": 100,
                    "minimized_poc_size_bytes": 50,
                    "poc_reduction_percentage": 50.0,
                    "ground_truth_cwe": "CWE-416",
                    "predicted_cwe": "CWE-416",
                    "cwe_exact_match": True,
                    "cwe_hierarchical_match": True,
                    "cwe_match_score": 1.0,
                    "ground_truth_cvss": 7.5,
                    "predicted_cvss": 7.5,
                    "cvss_delta": 0.0,
                    "cvss_tolerance_passed": True,
                    "predicted_severity": "HIGH",
                    "ground_truth_severity": "HIGH",
                    "severity_match": True,
                    "faulting_symbol": "free_sym",
                }
            ],
            "total_duration_seconds": 2.0,
            "extra_ignored_key": 12345,
        }
        json_str = json.dumps(raw_json_data)
        summary = BenchmarkScorecardSummary.from_json(json_str)
        assert summary.total_targets == 1
        assert len(summary.target_results) == 1
        assert isinstance(summary.target_results[0], TargetEvaluationResult)
        assert summary.target_results[0].target_id == "t_nested"

    @pytest.mark.parametrize(
        "field_name,invalid_val",
        [
            ("timeout_seconds", 0),
            ("timeout_seconds", -5),
            ("fuzz_duration_seconds", -1),
            ("parallel_workers", 0),
            ("parallel_workers", -1),
            ("cvss_tolerance", -0.1),
            ("cvss_tolerance", 10.1),
            ("fail_under_tpr", -1.0),
            ("fail_under_tpr", 100.1),
        ],
    )
    def test_execution_options_invalid_bounds(self, field_name: str, invalid_val: Any):
        """Test ExecutionOptions rejects invalid boundary inputs."""
        kwargs = {field_name: invalid_val}
        with pytest.raises(ValidationError):
            ExecutionOptions(**kwargs)


# ============================================================================
# 2. Adversarial CWE Taxonomy Stress Tests
# ============================================================================


class TestAdversarialCWETaxonomy:
    """Stress-test CWE normalization, DAG structure, cycle freedom, and symmetry."""

    @pytest.mark.parametrize(
        "raw_input,expected_norm",
        [
            (" \t\r\n CWE-122 \n ", "CWE-122"),
            ("cwe122", "CWE-122"),
            ("CWE_122", "CWE-122"),
            ("122", "CWE-122"),
            ("cwe-416", "CWE-416"),
            ("CWE-0122", "CWE-0122"),
            ("0", "CWE-0"),
            ("cwe0", "CWE-0"),
            ("CWE_0", "CWE-0"),
            ("", ""),
            ("   ", ""),
            (None, ""),
            ("UNKNOWN", "UNKNOWN"),
            ("unknown", "UNKNOWN"),
            ("CWE", "CWE"),
            ("CWE-", "CWE-"),
            ("CWE_", "CWE-"),
            ("cwe_", "CWE-"),
            ("CWE-ABC", "CWE-ABC"),
            ("INVALID_TYPE", "INVALID_TYPE"),
        ],
    )
    def test_normalize_cwe_id_bizarre_strings(self, raw_input: Any, expected_norm: str):
        """Test normalize_cwe_id against bizarre and malformed string variations."""
        assert normalize_cwe_id(raw_input) == expected_norm

    def test_cwe_dag_acyclicity_and_reachability(self):
        """Exhaustively verify that the CWE taxonomy graph has NO cycles and is a valid DAG."""
        for cwe in CWE_PARENTS:
            ancestors = get_cwe_ancestors(cwe)
            assert cwe not in ancestors, (
                f"Cycle detected in CWE taxonomy! Node '{cwe}' is its own ancestor."
            )

            descendants = get_cwe_descendants(cwe)
            assert cwe not in descendants, (
                f"Cycle detected in CWE taxonomy! Node '{cwe}' is its own descendant."
            )

            assert ancestors.isdisjoint(descendants), (
                f"Intersection between ancestors and descendants for '{cwe}'."
            )

    def test_pairwise_taxonomic_score_strict_symmetry(self):
        """Exhaustively verify pairwise symmetry score(A, B) == score(B, A) across all taxonomy nodes."""
        all_cwes = list(CWE_PARENTS.keys()) + [
            "CWE-9999",
            "UNKNOWN",
            "",
            "cwe-122",
            "190",
            "CWE_416",
        ]
        for a in all_cwes:
            for b in all_cwes:
                score_ab, match_ab = calculate_cwe_taxonomic_score(a, b)
                score_ba, match_ba = calculate_cwe_taxonomic_score(b, a)

                assert score_ab == score_ba, f"Asymmetric score for ({a}, {b})"
                assert match_ab == match_ba, f"Asymmetric match boolean for ({a}, {b})"
                assert 0.0 <= score_ab <= 1.0, f"Score out of bounds for ({a}, {b})"

                norm_a = normalize_cwe_id(a)
                norm_b = normalize_cwe_id(b)
                if (
                    norm_a
                    and norm_b
                    and norm_a == norm_b
                    and norm_a.startswith("CWE-")
                    and norm_a[4:].isdigit()
                ):
                    assert score_ab == 1.0, (
                        f"Expected exact match 1.0 for normalized identical ({a}, {b})"
                    )
                    assert match_ab is True

    def test_multiparent_cwe_scoring(self):
        """Test CWEs with multiple parents (e.g. CWE-415 has CWE-672 and CWE-761)."""
        parents_415 = get_cwe_parents("CWE-415")
        assert "CWE-672" in parents_415
        assert "CWE-761" in parents_415

        # Direct parent matches
        assert calculate_cwe_taxonomic_score("CWE-415", "CWE-672") == (0.75, True)
        assert calculate_cwe_taxonomic_score("CWE-415", "CWE-761") == (0.75, True)

        # Ancestor match via either parent
        assert calculate_cwe_taxonomic_score("CWE-415", "CWE-664") == (0.50, True)

    def test_multihop_descendant_and_ancestor_traversal(self):
        """Test deep multi-hop traversal in the taxonomy DAG."""
        # CWE-126 -> CWE-125 -> CWE-119 -> CWE-664
        ancestors_126 = get_cwe_ancestors("CWE-126")
        assert {"CWE-125", "CWE-119", "CWE-664"}.issubset(ancestors_126)

        descendants_664 = get_cwe_descendants("CWE-664")
        assert {
            "CWE-119",
            "CWE-787",
            "CWE-122",
            "CWE-121",
            "CWE-416",
            "CWE-415",
        }.issubset(descendants_664)


# ============================================================================
# 3. Adversarial CorpusLoader Stress Tests
# ============================================================================


class TestAdversarialCorpusLoader:
    """Stress-test CorpusLoader against corrupted files, bad paths, and edge filtering."""

    def test_load_corpus_invalid_paths(self, tmp_path: Path):
        """Test CorpusLoader raises FileNotFoundError for nonexistent paths."""
        loader = CorpusLoader(tmp_path / "non_existent_dir")
        with pytest.raises(FileNotFoundError):
            loader.load_corpus()

    def test_load_corpus_malformed_structures(self, tmp_path: Path):
        """Test CorpusLoader raises appropriate exceptions for malformed JSON structures."""
        loader = CorpusLoader(tmp_path)

        # Non-dict and non-list top-level (e.g. integer or boolean)
        f_int = tmp_path / "int.json"
        f_int.write_text("12345", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid corpus format"):
            loader.load_corpus(f_int)

        # Dictionary without 'targets' key
        f_bad_dict = tmp_path / "bad_dict.json"
        f_bad_dict.write_text('{"other_key": [1, 2, 3]}', encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid corpus format"):
            loader.load_corpus(f_bad_dict)

        # Dictionary with empty 'targets' array
        f_empty_targets = tmp_path / "empty_targets.json"
        f_empty_targets.write_text('{"targets": []}', encoding="utf-8")
        with pytest.raises(ValueError, match="contains 0 targets"):
            loader.load_corpus(f_empty_targets)

        # Targets with invalid elements (Pydantic ValidationError)
        f_invalid_elements = tmp_path / "invalid_elements.json"
        f_invalid_elements.write_text('{"targets": [{"target_id": "only_id"}]}', encoding="utf-8")
        with pytest.raises(ValidationError):
            loader.load_corpus(f_invalid_elements)

    def test_filter_targets_adversarial_queries(self):
        """Test filter_targets handles regex characters, whitespace, and special characters."""
        loader = CorpusLoader(FIXTURES_DIR)
        targets = loader.load_corpus()

        # Regex metacharacters should not crash or trigger regex syntax errors
        res = loader.filter_targets(targets, target_filter=".*+?^${}()|[]\\")
        assert len(res) == 0

        res_cwe = loader.filter_targets(targets, cwe_filter=".*")
        assert len(res_cwe) == 0

        # Whitespace and weird casing
        res_ws = loader.filter_targets(targets, target_filter="   \t\n  ")
        assert len(res_ws) == len(targets)  # Whitespace alone is ignored like 'all'

        res_case = loader.filter_targets(targets, vulnerability_class_filter="HEAP_BUFFER_OVERFLOW")
        # Expanded corpus has 2 heap_buffer_overflow targets: sqlite3_fts5_unicode + zlib_inflate_heap_oob
        assert len(res_case) == 2
        res_case_ids = {t.target_id for t in res_case}
        assert "sqlite3_fts5_unicode" in res_case_ids
        assert "zlib_inflate_heap_oob" in res_case_ids

        # None / empty list of targets
        assert loader.filter_targets([], target_filter="sqlite") == []

    def test_validate_target_fixtures_with_optional_dict_none(self, tmp_path: Path):
        """Test validate_target_fixtures when dictionary_path is None."""
        loader = CorpusLoader(tmp_path)
        valid_cvss = CVSSGroundTruth(
            base_score_min=5.0,
            base_score_max=8.0,
            expected_score=6.5,
            severity="MEDIUM",
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )
        fixtures = FixturePaths(
            vulnerable_source="vuln.c",
            patched_source="patch.c",
            patch_diff="patch.diff",
            harness_c="harness.c",
            asan_crash_log="asan.log",
            valid_seed_corpus="seed.bin",
            raw_crash_poc="poc_raw.bin",
            minimized_poc="poc_min.bin",
            dictionary_path=None,  # Optional None
        )
        target = TargetGroundTruth(
            target_id="test_opt",
            target_name="Test Optional",
            category="parser",
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
            fixtures=fixtures,
            raw_poc_size_bytes=100,
            minimized_poc_target_bytes=20,
            expected_minimization_ratio_min=0.5,
        )
        status = loader.validate_target_fixtures(target, base_dir=tmp_path)
        assert "dictionary_path" not in status or status.get("dictionary_path") is None

    def test_validate_corpus_integrity_empty_list(self):
        """Test validate_corpus_integrity handles empty targets list gracefully."""
        loader = CorpusLoader(FIXTURES_DIR)
        summary = loader.validate_corpus_integrity(targets=[])
        assert summary["valid"] is True
        assert summary["total_targets"] == 0
        assert summary["target_details"] == []
