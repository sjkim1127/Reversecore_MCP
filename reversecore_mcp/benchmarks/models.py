"""Data models for Reversecore_MCP Benchmark Testbed.

This module defines Pydantic V2 and dataclass models representing ground-truth metadata,
CVSS scoring targets, fixture locations, target evaluation outcomes, scorecard summaries,
and benchmark execution options.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from reversecore_mcp.core import json_utils as json


class CVSSGroundTruth(BaseModel):
    """Ground truth CVSS v3.1 rating, score bounds, and vector definition."""

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    base_score_min: float = Field(
        ..., ge=0.0, le=10.0, description="Minimum acceptable CVSS v3.1 base score"
    )
    base_score_max: float = Field(
        ..., ge=0.0, le=10.0, description="Maximum acceptable CVSS v3.1 base score"
    )
    expected_score: float = Field(
        ..., ge=0.0, le=10.0, description="Canonical CVSS v3.1 base score"
    )
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        ..., description="Canonical CVSS severity rating"
    )
    expected_vector: str = Field(..., min_length=1, description="Canonical CVSS v3.1 vector string")
    tolerated_vectors: list[str] = Field(
        default_factory=list, description="Alternative acceptable vector strings"
    )

    @field_validator("base_score_max")
    @classmethod
    def validate_score_range(cls, v: float, info: Any) -> float:
        """Ensure base_score_max is not less than base_score_min when provided."""
        min_score = info.data.get("base_score_min")
        if min_score is not None and v < min_score:
            raise ValueError(
                f"base_score_max ({v}) cannot be less than base_score_min ({min_score})"
            )
        return v


class FixturePaths(BaseModel):
    """Relative fixture paths for a benchmark target on the filesystem."""

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    vulnerable_source: str = Field(
        ..., min_length=1, description="Relative path to vulnerable C/C++ source file"
    )
    patched_source: str = Field(
        ..., min_length=1, description="Relative path to patched C/C++ source file"
    )
    patch_diff: str = Field(
        ..., min_length=1, description="Relative path to unified diff file (.diff)"
    )
    harness_c: str = Field(
        ..., min_length=1, description="Relative path to LibFuzzer/AFL harness (.c/.cc)"
    )
    asan_crash_log: str = Field(
        ..., min_length=1, description="Relative path to recorded ASan crash log (.log)"
    )
    valid_seed_corpus: str = Field(
        ..., min_length=1, description="Relative path to valid seed directory or file"
    )
    raw_crash_poc: str = Field(
        ..., min_length=1, description="Relative path to unminimized crash trigger file"
    )
    minimized_poc: str = Field(
        ..., min_length=1, description="Relative path to gold-standard minimized PoC"
    )
    dictionary_path: str | None = Field(
        default=None, description="Relative path to AFL/LibFuzzer dictionary (.dict)"
    )


class TargetGroundTruth(BaseModel):
    """Master ground truth metadata schema for a real-world benchmark target."""

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    target_id: str = Field(..., min_length=1, description="Unique target identifier")
    target_name: str = Field(..., min_length=1, description="Human-readable target name")
    category: str = Field(
        ...,
        min_length=1,
        description="Target category (e.g. database_engine, image_parser)",
    )
    real_world_library: str = Field(
        ..., min_length=1, description="Target library or software package"
    )
    target_version: str = Field(..., min_length=1, description="Vulnerable version string")
    cve_reference: str = Field(..., min_length=1, description="Associated CVE reference")
    vulnerability_class: str = Field(
        ...,
        min_length=1,
        description="Vulnerability class (e.g. heap_buffer_overflow, use_after_free)",
    )
    cwe_id: str = Field(
        ..., pattern=r"^CWE-\d+$", description="Primary CWE identifier (e.g. CWE-122)"
    )
    cwe_name: str = Field(..., min_length=1, description="Canonical CWE name")
    faulting_symbol: str = Field(
        ..., min_length=1, description="Function or symbol where corruption triggers"
    )
    source_file: str = Field(..., min_length=1, description="Faulting source filename")
    source_line: int = Field(..., gt=0, description="Faulting line number (>0)")
    expected_memory_access_type: str = Field(
        ...,
        min_length=1,
        description="Expected memory access type (e.g. WRITE_OOB, UAF_READ)",
    )
    expected_access_size: int = Field(
        ..., ge=0, description="Memory access size in bytes (0 for free/double-free)"
    )
    cvss: CVSSGroundTruth = Field(..., description="Ground truth CVSS ratings")
    fixtures: FixturePaths = Field(..., description="Fixture file relative paths")
    raw_poc_size_bytes: int = Field(..., gt=0, description="Original crash payload size in bytes")
    minimized_poc_target_bytes: int = Field(
        ..., gt=0, description="Target minimized payload size in bytes"
    )
    expected_minimization_ratio_min: float = Field(
        ..., ge=0.0, le=1.0, description="Minimum expected byte reduction ratio"
    )
    dictionary_tokens: list[str] = Field(
        default_factory=list, description="Fuzzer dictionary tokens"
    )
    max_time_to_crash_seconds: int = Field(
        default=30, gt=0, description="Maximum expected time-to-crash in seconds"
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize target ground truth to a dictionary."""
        return self.model_dump()

    def to_json(self, indent: int | None = None) -> str:
        """Serialize target ground truth to a JSON string."""
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetGroundTruth:
        """Deserialize target ground truth from a dictionary."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> TargetGroundTruth:
        """Deserialize target ground truth from a JSON string."""
        return cls.model_validate_json(json_str)


# Alias for backwards and cross-module compatibility
GroundTruthMetadata = TargetGroundTruth


@dataclass
class TargetEvaluationResult:
    """Individual target evaluation metrics evaluated by the scoring engine."""

    target_id: str
    target_name: str
    vulnerability_class: str
    status: str  # "DISCOVERED", "MISSED", "ERROR", "TIMEOUT"
    is_true_positive: bool
    time_to_crash_seconds: float
    total_executions: int
    throughput_execs_per_sec: float
    original_poc_size_bytes: int
    minimized_poc_size_bytes: int
    poc_reduction_percentage: float
    ground_truth_cwe: str
    predicted_cwe: str
    cwe_exact_match: bool
    cwe_hierarchical_match: bool
    cwe_match_score: float
    ground_truth_cvss: float
    predicted_cvss: float
    cvss_delta: float
    cvss_tolerance_passed: bool
    predicted_severity: str
    ground_truth_severity: str
    severity_match: bool
    faulting_symbol: str
    error_message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize result to a dictionary."""
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        """Serialize result to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetEvaluationResult:
        """Deserialize result from a dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    @classmethod
    def from_json(cls, json_str: str) -> TargetEvaluationResult:
        """Deserialize result from a JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class BenchmarkScorecardSummary:
    """Aggregated evaluation scorecard summary for the entire benchmark run."""

    total_targets: int = 0
    discovered_count: int = 0
    missed_count: int = 0
    error_count: int = 0
    discovery_rate_tpr_pct: float = 0.0
    mean_time_to_crash_seconds: float = 0.0
    avg_throughput_exec_per_sec: float = 0.0
    avg_poc_reduction_pct: float = 0.0
    cwe_exact_match_rate_pct: float = 0.0
    cwe_hierarchical_match_rate_pct: float = 0.0
    cvss_mean_absolute_error: float = 0.0
    cvss_tolerance_match_rate_pct: float = 0.0
    severity_concordance_rate_pct: float = 0.0
    class_breakdown: dict[str, dict[str, Any]] = field(default_factory=dict)
    target_results: list[TargetEvaluationResult] = field(default_factory=list)
    execution_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize scorecard summary to a dictionary."""
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        """Serialize scorecard summary to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkScorecardSummary:
        """Deserialize scorecard summary from a dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        if "target_results" in filtered and isinstance(filtered["target_results"], list):
            filtered["target_results"] = [
                (TargetEvaluationResult.from_dict(item) if isinstance(item, dict) else item)
                for item in filtered["target_results"]
            ]
        return cls(**filtered)

    @classmethod
    def from_json(cls, json_str: str) -> BenchmarkScorecardSummary:
        """Deserialize scorecard summary from a JSON string."""
        return cls.from_dict(json.loads(json_str))


class ExecutionOptions(BaseModel):
    """Configuration options for benchmark test execution."""

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    targets_filter: str = Field(
        default="all", description="Target ID or name filter substring or 'all'"
    )
    cwe_filter: str = Field(default="all", description="CWE ID filter or 'all'")
    category_filter: str = Field(default="all", description="Category filter or 'all'")
    vulnerability_class_filter: str = Field(
        default="all", description="Vulnerability class filter or 'all'"
    )
    timeout_seconds: int = Field(default=30, gt=0, description="Per-target timeout in seconds")
    fuzz_duration_seconds: int = Field(
        default=10, ge=0, description="Fuzzing campaign duration per target in seconds"
    )
    parallel_workers: int = Field(
        default=1, ge=1, description="Number of parallel execution workers"
    )
    r2_decompiler_mode: str = Field(
        default="r2ghidra",
        description="Decompiler engine mode ('r2ghidra', 'r2dec', etc.)",
    )
    output_dir: str = Field(
        default="artifacts/benchmarks",
        description="Output destination directory for reports",
    )
    output_format: str = Field(
        default="both",
        description="Report output format ('json', 'markdown', 'both', 'stdout')",
    )
    cvss_tolerance: float = Field(
        default=0.5,
        ge=0.0,
        le=10.0,
        description="Absolute tolerance delta for CVSS scoring",
    )
    fail_under_tpr: float = Field(
        default=80.0,
        ge=0.0,
        le=100.0,
        description="Minimum TPR required for successful exit",
    )
    mock_mode: bool = Field(
        default=False,
        description="Run with mock providers without external binary dependencies",
    )
    auto_fallback: bool = Field(
        default=True,
        description="Automatically fallback to mock fixtures if live toolchains are absent or fail",
    )
    clang_path: str | None = Field(
        default=None,
        description="Custom path to Clang compiler",
    )
    enable_angr: bool = Field(default=True, description="Enable angr concolic execution")
    verbose: bool = Field(default=False, description="Enable verbose logging")

    def to_dict(self) -> dict[str, Any]:
        """Serialize options to a dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionOptions:
        """Deserialize options from a dictionary."""
        return cls.model_validate(data)
