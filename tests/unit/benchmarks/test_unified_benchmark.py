"""Unit tests for Unified Multi-Domain Benchmark Reporting and CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    DynamicSandboxScorecardSummary,
    EngineComparisonSummary,
    TriageScorecardSummary,
    UnifiedBenchmarkScorecardSummary,
)
from reversecore_mcp.benchmarks.reporter import (
    UnifiedBenchmarkReporter,
)


@pytest.mark.unit
def test_corpus_loader_extended_methods(tmp_path: Path) -> None:
    """Test CorpusLoader load_triage_corpus and load_dynamic_corpus methods."""
    loader = CorpusLoader(corpus_dir=Path("tests/fixtures/benchmarks"))
    triage_targets = loader.load_triage_corpus()
    assert len(triage_targets) >= 3

    dynamic_targets = loader.load_dynamic_corpus()
    assert len(dynamic_targets) >= 3


@pytest.mark.unit
def test_unified_benchmark_reporter_markdown(tmp_path: Path) -> None:
    """Test UnifiedBenchmarkReporter generation of markdown and json reports."""
    summary = UnifiedBenchmarkScorecardSummary(
        cve_summary=BenchmarkScorecardSummary(
            total_targets=1,
            discovered_count=1,
            discovery_rate_tpr_pct=100.0,
            cwe_exact_match_rate_pct=100.0,
            cvss_tolerance_match_rate_pct=100.0,
        ),
        triage_summary=TriageScorecardSummary(
            total_targets=1,
            success_count=1,
            triage_accuracy_pct=100.0,
            mean_latency_seconds=0.01,
        ),
        dynamic_summary=DynamicSandboxScorecardSummary(
            total_targets=1,
            success_count=1,
            avg_syscall_coverage_pct=100.0,
            containment_enforcement_rate_pct=100.0,
        ),
        engine_summary=EngineComparisonSummary(
            total_targets=1,
            engines_evaluated=["radare2", "fission"],
            engine_metrics={
                "radare2": {"successful_analyses": 1, "avg_latency_seconds": 0.05},
                "fission": {"successful_analyses": 1, "avg_latency_seconds": 0.01},
            },
        ),
        total_duration_seconds=1.23,
    )

    md = UnifiedBenchmarkReporter.to_markdown(summary)
    assert "Multi-Domain Benchmark Overview" in md
    assert "Layer 1 Meta-Tool Triage Evaluation" in md
    assert "Dynamic Execution Sandbox & Tracing" in md
    assert "Multi-Engine Comparative Evaluation" in md
    assert "radare2" in md
    assert "fission" in md

    # JSON export
    json_str = UnifiedBenchmarkReporter.to_json(summary)
    assert '"triage_accuracy_pct": 100.0' in json_str
    assert '"fission"' in json_str

    # Save reports
    saved = UnifiedBenchmarkReporter.save_reports(summary, tmp_path, output_format="both")
    assert "markdown" in saved
    assert "json" in saved
    assert saved["markdown"].exists()
    assert saved["json"].exists()
