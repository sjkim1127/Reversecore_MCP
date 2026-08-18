# Project: Reversecore_MCP Local Benchmark Suite Hardening

## Architecture
Reversecore_MCP benchmark framework provides automated evaluation for vulnerability discovery, dynamic ASan crash triage, CVSS scoring, and PoC minimization across 10 real-world CVE targets.

```
                    ┌──────────────────────────────────────────────┐
                    │               BenchmarkRunner                │
                    │   (reversecore_mcp/benchmarks/runner.py)     │
                    └──────────────────────┬───────────────────────┘
                                           │
                        [Capability & Options Evaluation]
                                           │
                  ┌────────────────────────┴────────────────────────┐
                  ▼                                                 ▼
   ┌──────────────────────────────┐                 ┌──────────────────────────────┐
   │    Live Dynamic Pipeline     │                 │   Deterministic Mock Pipeline│
   │   - ToolchainCapabilities    │                 │   - ground_truth_corpus.json │
   │   - LiveTargetCompilerRunner │                 │   - fixture asan_crash.log   │
   │   - Clang ASan Compilation   │                 │   - fixture raw/min PoCs     │
   │   - Real Crash Reproduction  │                 │   - Zero external dependency │
   │   - triage_asan_log()        │                 │                              │
   │   - Delta-debug Minimization │                 │                              │
   └──────────────┬───────────────┘                 └──────────────┬───────────────┘
                  │                                                │
                  └────────────────────────┬───────────────────────┘
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │                ScoringEngine                 │
                    │   - Exact & Taxonomic CWE (DAG Distance)     │
                    │   - CVSS v3.1 Delta & Tolerance Score        │
                    │   - Time-to-Crash (TTC) & Throughput         │
                    │   - PoC Minimization Byte Reduction %        │
                    └──────────────────────────────────────────────┘
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | `ToolchainCapabilities` & Probing | Safe, cached probing of `clang`, ASan/UBSan, LibFuzzer, Docker, AFL++ with timeout containment | M1 | R2 / Survey 2 |
| F2 | Config & CLI Option Precedence | Support for `--mock`, `--mock-mode`, `--live`, `--clang-path`, `REVERSECORE_MOCK_MODE`, and settings hierarchy | M1 | R2 / Survey 2 |
| F3 | Live Target Compilation | Dynamic compilation of C target harnesses (`vulnerable.c` + `harness.c` + driver) with `-fsanitize=address,undefined` | M2 | R1 / Survey 1,3 |
| F4 | Live Crash Reproduction & ASan Triage | Subprocess execution of compiled target with PoC input, capturing ASan traces and parsing with `triage_asan_log` | M2 | R1, R3 / Survey 3 |
| F5 | Monotonic TTC Measurement | High-resolution wall-clock Time-To-Crash measurement using `time.perf_counter()` | M2 | R3 / Survey 3 |
| F6 | Live PoC Minimization & Ratio Verification | Delta-debugging minimization against live binary and calculation of byte reduction percentage | M2 | R3 / Survey 3 |
| F7 | Graceful Hybrid Fallback Engine | Clean fallback to mock fixture evaluation when compiler is absent, disabled, or target compilation fails | M1, M2 | R2 / Survey 1,2 |
| F8 | Integration Suite Sync & 10-Target Consistency | Update test assertions to 10 targets, ensure 100% test pass rate across unit and integration tests | M2, M3 | Survey 1,2 |
| F9 | Opaque-Box E2E Testing Suite (Tiers 1-4) | Comprehensive test suite covering features F1-F8, boundary conditions, cross-feature combinations, and CLI scenarios | M3 | R1, R2, R3 |
| F10 | Adversarial Coverage & Forensic Audit (Tier 5) | Adversarial stress testing, edge-case validation, and independent forensic integrity verification | M4 | Quality Gate |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1: Toolchain Auto-Detection & Config | `capabilities.py`, `config.py`, `models.py`, `scripts/run_cve_benchmark.py`, `tests/unit/benchmarks/test_capabilities.py` | none | DONE |
| 2 | M2: Dynamic Compilation, Live Execution & Fallback | `compiler_runner.py`, `runner.py`, integration test fixes, live crash reproduction | M1 | DONE |
| 3 | M3: E2E Testing Suite | Multi-tier test suite (`TEST_INFRA.md`, `TEST_READY.md`, tests) | M2 | DONE |
| 4 | M4: Adversarial Hardening & Forensic Audit | Adversarial tests, code formatting, gate check, forensic audit | M3 | DONE |

## Interface Contracts

### `capabilities.py` ↔ `runner.py` / `config.py`
- `detect_capabilities(force_refresh: bool = False, clang_path_override: str | None = None) -> ToolchainCapabilities`
- `ToolchainCapabilities`:
  * `clang_available: bool`
  * `clang_path: Path | None`
  * `clang_version: str | None`
  * `asan_supported: bool`
  * `ubsan_supported: bool`
  * `libfuzzer_supported: bool`
  * `live_fuzzing_ready: bool` (property: `clang_available and asan_supported`)
  * `full_libfuzzer_ready: bool` (property: `live_fuzzing_ready and libfuzzer_supported`)

### `compiler_runner.py` ↔ `runner.py`
- `class LiveTargetCompilerRunner`:
  * `async compile_target(target: TargetGroundTruth, clang_path: Path | None = None, work_dir: Path | None = None) -> Path | None`
  * `async execute_live_target(target: TargetGroundTruth, compiled_bin: Path, poc_payload: bytes, timeout_seconds: float) -> tuple[int, str, float]` (returns `(returncode, stderr, elapsed_ttc)`)
  * `async run_live_poc_minimization(target: TargetGroundTruth, compiled_bin: Path, raw_poc: bytes) -> tuple[bytes, float]` (returns `(minimized_bytes, reduction_ratio)`)

### `runner.py` ↔ `ScoringEngine`
- `BenchmarkRunner.run_target(target_id: str, options: ExecutionOptions | None = None) -> TargetEvaluationResult`
- Returns validated `TargetEvaluationResult` containing CWE prediction, CVSS score, TTC, PoC reduction ratio, status (`DISCOVERED`).

## Code Layout
- `reversecore_mcp/benchmarks/capabilities.py`: Toolchain detection & capability probing
- `reversecore_mcp/benchmarks/compiler_runner.py`: Dynamic C compilation, ASan execution, and live minimization
- `reversecore_mcp/benchmarks/runner.py`: Orchestrator linking capabilities, compiler runner, and mock pipeline
- `reversecore_mcp/benchmarks/models.py`: Pydantic data models & `ExecutionOptions`
- `reversecore_mcp/core/config.py`: Centralized configuration settings
- `scripts/run_cve_benchmark.py`: CLI benchmark runner
- `tests/unit/benchmarks/`: Unit test suite
- `tests/integration/`: Integration test suite
- `TEST_INFRA.md`: Comprehensive test infrastructure documentation
- `TEST_READY.md`: Quick-start test execution and readiness guide
