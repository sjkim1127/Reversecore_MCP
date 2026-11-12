"""Reversecore_MCP Benchmark Suite Package.

Provides data models, CWE taxonomy DAG, corpus loading, mathematical evaluation scoring,
async benchmark runner, and report generators for automated 0-Day/N-Day vulnerability testing,
1-turn triage benchmarking, dynamic execution sandboxing, and multi-engine comparative evaluation.
"""

from __future__ import annotations

from reversecore_mcp.benchmarks.capabilities import (
    CapabilityDetector,
    ToolchainCapabilities,
    detect_capabilities,
)
from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.dynamic_benchmark import DynamicSandboxBenchmarkRunner
from reversecore_mcp.benchmarks.engine_adapter import (
    EngineBenchmarkAdapter,
    EngineBenchmarkRunner,
    FissionEngineAdapter,
    MockEngineAdapter,
    Radare2EngineAdapter,
)
from reversecore_mcp.benchmarks.models import (
    BenchmarkScorecardSummary,
    CVSSGroundTruth,
    DynamicSandboxGroundTruth,
    DynamicSandboxScorecardSummary,
    DynamicSandboxTargetResult,
    EngineAnalysisResult,
    EngineComparisonSummary,
    ExecutionOptions,
    FixturePaths,
    GroundTruthMetadata,
    TargetEvaluationResult,
    TargetGroundTruth,
    TriageGroundTruth,
    TriageScorecardSummary,
    TriageTargetResult,
    UnifiedBenchmarkScorecardSummary,
)
from reversecore_mcp.benchmarks.reporter import (
    BenchmarkReporter,
    UnifiedBenchmarkReporter,
)
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
from reversecore_mcp.benchmarks.triage_benchmark import TriageBenchmarkRunner

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
    "CapabilityDetector",
    "CorpusLoader",
    "DynamicSandboxBenchmarkRunner",
    "DynamicSandboxGroundTruth",
    "DynamicSandboxScorecardSummary",
    "DynamicSandboxTargetResult",
    "EngineAnalysisResult",
    "EngineBenchmarkAdapter",
    "EngineBenchmarkRunner",
    "EngineComparisonSummary",
    "ExecutionOptions",
    "FissionEngineAdapter",
    "FixturePaths",
    "GroundTruth",
    "GroundTruthMetadata",
    "MockEngineAdapter",
    "Radare2EngineAdapter",
    "ScoringEngine",
    "TargetDef",
    "TargetEvaluationResult",
    "TargetGroundTruth",
    "ToolchainCapabilities",
    "TriageBenchmarkRunner",
    "TriageGroundTruth",
    "TriageScorecardSummary",
    "TriageTargetResult",
    "UnifiedBenchmarkReporter",
    "UnifiedBenchmarkScorecardSummary",
    "calculate_cwe_taxonomic_score",
    "detect_capabilities",
    "get_cwe_ancestors",
    "get_cwe_children",
    "get_cwe_descendants",
    "get_cwe_parents",
    "normalize_cwe_id",
]
