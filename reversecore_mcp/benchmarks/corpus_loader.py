"""Benchmark Target Corpus Discovery, Loading, and Validation Engine.

Provides the `CorpusLoader` utility to load real-world benchmark targets from
master ground-truth registries or individual target directories, filter by
attributes (target_id, cwe_id, category, vulnerability_class), and validate
the physical presence and integrity of all fixture files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reversecore_mcp.benchmarks.models import TargetGroundTruth
from reversecore_mcp.benchmarks.taxonomy import normalize_cwe_id


class CorpusLoader:
    """Discovers, parses, filters, and validates benchmark target definitions."""

    def __init__(self, corpus_dir: str | Path | None = None) -> None:
        """Initialize CorpusLoader with root directory for benchmark fixtures.

        Args:
            corpus_dir: Root directory containing ground_truth_corpus.json and targets/.
                       Defaults to 'tests/fixtures/benchmarks'.
        """
        self.corpus_dir = Path(corpus_dir) if corpus_dir else Path("tests/fixtures/benchmarks")

    def load_corpus(self, corpus_path: str | Path | None = None) -> list[TargetGroundTruth]:
        """Load all targets from ground_truth_corpus.json or target directory.

        Args:
            corpus_path: Specific JSON file path or None to use default.

        Returns:
            List of validated TargetGroundTruth instances.

        Raises:
            FileNotFoundError: If the registry file or directory does not exist.
            json.JSONDecodeError: If the JSON syntax is corrupt.
            ValueError: If the corpus is empty or has an invalid structure.
        """
        path = Path(corpus_path) if corpus_path else self.corpus_dir / "ground_truth_corpus.json"
        if not path.exists():
            raise FileNotFoundError(f"Corpus registry file not found: {path}")

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict) and "targets" in data:
            raw_targets = data["targets"]
        elif isinstance(data, list):
            raw_targets = data
        else:
            raise ValueError(
                f"Invalid corpus format: expected list or dict with 'targets', got {type(data).__name__}"
            )

        if not isinstance(raw_targets, list) or len(raw_targets) == 0:
            raise ValueError("Corpus contains 0 targets.")

        targets = [TargetGroundTruth.model_validate(item) for item in raw_targets]
        return targets

    def load_target_from_json(self, target_json_path: str | Path) -> TargetGroundTruth:
        """Load single target definition from a JSON file.

        Args:
            target_json_path: Path to target.json file.

        Returns:
            Validated TargetGroundTruth instance.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        p = Path(target_json_path)
        if not p.exists():
            raise FileNotFoundError(f"Target JSON file not found: {p}")
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return TargetGroundTruth.model_validate(data)

    def filter_targets(
        self,
        targets: list[TargetGroundTruth],
        target_filter: str = "all",
        cwe_filter: str = "all",
        category_filter: str = "all",
        vulnerability_class_filter: str = "all",
    ) -> list[TargetGroundTruth]:
        """Filter target list by target identifier/name, CWE ID, category, or vulnerability class.

        Args:
            targets: List of TargetGroundTruth objects to filter.
            target_filter: Substring match against target_id or target_name, or 'all'.
            cwe_filter: Exact or normalized match against cwe_id, or 'all'.
            category_filter: Substring match against category, or 'all'.
            vulnerability_class_filter: Substring match against vulnerability_class, or 'all'.

        Returns:
            Filtered list of TargetGroundTruth instances.
        """
        filtered = list(targets)

        # Target ID / Name filter
        if target_filter and target_filter.strip().lower() != "all":
            t_low = target_filter.strip().lower()
            filtered = [
                t
                for t in filtered
                if t_low in t.target_id.lower() or t_low in t.target_name.lower()
            ]

        # CWE ID filter
        if cwe_filter and cwe_filter.strip().lower() != "all":
            c_norm = normalize_cwe_id(cwe_filter)
            filtered = [t for t in filtered if normalize_cwe_id(t.cwe_id) == c_norm]

        # Category filter
        if category_filter and category_filter.strip().lower() != "all":
            cat_low = category_filter.strip().lower()
            filtered = [t for t in filtered if cat_low in t.category.lower()]

        # Vulnerability Class filter
        if vulnerability_class_filter and vulnerability_class_filter.strip().lower() != "all":
            vc_low = vulnerability_class_filter.strip().lower()
            filtered = [t for t in filtered if vc_low in t.vulnerability_class.lower()]

        return filtered

    def validate_target_fixtures(
        self, target: TargetGroundTruth, base_dir: Path | None = None
    ) -> dict[str, bool]:
        """Validate physical presence of all referenced fixture files on disk.

        Args:
            target: TargetGroundTruth instance to check.
            base_dir: Root directory for relative fixture paths (defaults to self.corpus_dir).

        Returns:
            Dictionary mapping fixture field name to existence boolean (True/False).
        """
        root = Path(base_dir) if base_dir else self.corpus_dir
        results: dict[str, bool] = {}
        for field_name, rel_path in target.fixtures.model_dump().items():
            if rel_path:
                full_path = root / rel_path
                results[field_name] = full_path.exists()
        return results

    def validate_corpus_integrity(
        self,
        targets: list[TargetGroundTruth] | None = None,
        base_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Validate comprehensive fixture presence and non-zero sizes across the corpus.

        Args:
            targets: Optional preloaded list of targets, or loads from self.corpus_dir.
            base_dir: Root directory for fixtures.

        Returns:
            Summary dictionary with validation results and per-target details.
        """
        target_list = targets if targets is not None else self.load_corpus()
        root = Path(base_dir) if base_dir else self.corpus_dir

        all_valid = True
        details = []

        for t in target_list:
            fixture_status = self.validate_target_fixtures(t, base_dir=root)
            all_fixtures_present = all(fixture_status.values())
            if not all_fixtures_present:
                all_valid = False

            details.append(
                {
                    "target_id": t.target_id,
                    "target_name": t.target_name,
                    "cwe_id": t.cwe_id,
                    "all_fixtures_present": all_fixtures_present,
                    "fixtures": fixture_status,
                }
            )

        return {
            "valid": all_valid,
            "total_targets": len(target_list),
            "target_details": details,
        }
