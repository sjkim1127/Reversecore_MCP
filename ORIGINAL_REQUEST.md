# Original User Request

## Initial Request — 2026-08-18T00:47:50Z

Strengthen and harden the local benchmark suite for Reversecore_MCP by enhancing live dynamic fuzzing, Clang/ASan instrumented execution, crash reproduction, and automated PoC minimization pipelines alongside robust mock test harnesses with hybrid auto-detection.

Working directory: `/Users/sjkim1127/Reversecore_MCP`
Integrity mode: development

## Requirements

### R1. Live Dynamic Execution & Fuzzing Pipeline Integration
Enhance the live execution runner in the benchmark framework (`BenchmarkRunner`) to support real Clang ASan/UBSan compilation, LibFuzzer/AFL++ execution, and dynamic crash detection against ground-truth target harnesses.

### R2. Capability Auto-Detection & Graceful Fallback
Implement an automated capability detector that verifies whether required toolchains (`clang`, `libFuzzer`, ASan runtime) are present on the host/Docker environment. When available, execute live fuzzing/crash triage; when unavailable, cleanly fallback to deterministic mock/fixture evaluation without crashing or failing tests.

### R3. Dynamic Crash Reproduction & PoC Minimization Verification
Verify that live executions properly capture ASan stack traces, extract faulting symbols, calculate Time-To-Crash (TTC), verify memory access violations, and measure PoC minimization ratios.

## Acceptance Criteria

### Live & Hybrid Execution Verification
- [ ] Automated toolchain detection accurately identifies local compiler capabilities (`clang`, sanitizers).
- [ ] At least one real C target (e.g., `sqlite3_fts5_unicode` or `expat_entity_int_overflow`) successfully compiles with ASan and reproduces a genuine crash/memory violation when Clang is available.
- [ ] Graceful fallback operates seamlessly without test failures when toolchains are absent or disabled (`--mock-mode`).

### Test Suite & Performance Integrity
- [ ] Full existing test suite (`pytest tests/unit/ tests/integration/`) maintains 100% pass rate with zero regressions across all 10 CVE targets.
- [ ] All code quality standards (`ruff check`, `black --target-version py312`) pass without warnings or format issues.
