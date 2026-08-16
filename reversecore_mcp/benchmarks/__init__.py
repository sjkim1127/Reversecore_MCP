"""Reversecore_MCP Benchmark Suite Package.

Provides data models, CWE taxonomy DAG, corpus loading, mathematical evaluation scoring,
async benchmark runner, and report generators for automated 0-Day/N-Day vulnerability testing.
"""

from __future__ import annotations

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
from reversecore_mcp.benchmarks.reporter import BenchmarkReporter
from reversecore_mcp.benchmarks.runner import BenchmarkRunner
from reversecore_mcp.benchmarks.scoring import ScoringEngine
from reversecore_mcp.benchmarks.taxonomy import (
    CWE_NAMES,
    CWE_PARENTS,
    calculate_cwe_taxonomic_score,
    get_cwe_ancestors,
    get_cwe_children,
    get_cwe_descendants,
    get_cwe_parents,
    normalize_cwe_id,
)

# Canonical Aliases
TargetDef = TargetGroundTruth
GroundTruth = TargetGroundTruth
BenchmarkOptions = ExecutionOptions
BenchmarkScorecard = BenchmarkScorecardSummary

__all__ = [
    "BenchmarkOptions",
    "BenchmarkReporter",
    "BenchmarkRunner",
    "BenchmarkScorecard",
    "BenchmarkScorecardSummary",
    "CVSSGroundTruth",
    "CWE_NAMES",
    "CWE_PARENTS",
    "CorpusLoader",
    "ExecutionOptions",
    "FixturePaths",
    "GroundTruth",
    "GroundTruthMetadata",
    "ScoringEngine",
    "TargetDef",
    "TargetEvaluationResult",
    "TargetGroundTruth",
    "calculate_cwe_taxonomic_score",
    "get_cwe_ancestors",
    "get_cwe_children",
    "get_cwe_descendants",
    "get_cwe_parents",
    "normalize_cwe_id",
]
