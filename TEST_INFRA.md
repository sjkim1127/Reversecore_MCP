# TEST_INFRA — Reversecore_MCP Benchmark & Testing Infrastructure

## 1. Overview & Test Philosophy

Reversecore_MCP's automated vulnerability benchmark framework evaluates AI-assisted reverse engineering and vulnerability triage tools against real-world 0-day/N-day software vulnerabilities. The testing infrastructure is engineered using an **opaque-box, requirement-driven methodology** to guarantee evaluation rigor, deterministic repeatability, safety containment, and zero reliance on fragile implementation details.

### Core Testing Principles

1. **Opaque-Box Evaluation (Requirement-Driven)**
   All tests interface strictly with public contracts, schemas, and CLI entry points (`BenchmarkRunner`, `CapabilityDetector`, `LiveTargetCompilerRunner`, `ScoringEngine`, `CorpusLoader`, `BenchmarkReporter`, and `scripts/run_cve_benchmark.py`). Internal state is evaluated solely through observable outputs, exit codes, generated reports, and structured evaluation scorecards.

2. **Category-Partition & Domain Equivalence Partitioning**
   Input domains and environmental parameters are partitioned into disjoint equivalence classes:
   - **Environment State**: Toolchain fully available (Clang + ASan + LibFuzzer), compiler partially available (Clang without sanitizer runtime), non-executable compiler, hanging compiler process, total toolchain absence.
   - **Execution Modes**: Explicit mock mode (`--mock`, `mock_mode=True`), explicit live mode (`--live`), automatic auto-detection mode.
   - **Target Composition**: Self-contained targets (standalone C source + harness) vs. external-dependency targets (requiring system headers).
   - **Fallback Configuration**: Permissive fallback (`auto_fallback=True`) vs. strict failure enforcement (`auto_fallback=False` / `--no-fallback`).

3. **Boundary Value Analysis (BVA)**
   Edge and extreme boundary conditions are systematically tested across all interfaces:
   - **Payload Sizing**: 0-byte empty PoCs, 1-byte minimal non-crashing inputs, exact threshold inputs, 11MB+ oversized payloads exceeding memory boundaries.
   - **CVSS Scoring Range**: Lower limit (`0.0`), upper limit (`10.0`), exact boundaries, tolerance delta boundaries (`±0.5` points).
   - **Taxonomic Distances**: Exact match (1.0), direct parent/child (0.75), multi-hop ancestor (0.50), completely unrelated CWE (0.0).
   - **Timeout Thresholds**: Subprocess execution timeouts (0.1s, 1.0s, 3.0s containment), probe script timeouts (3.0s hard ceiling).

4. **Pairwise & Orthogonal Combinatorial Testing**
   Combinations of orthogonal execution parameters are exercised to detect interaction defects:
   - Mode (`--mock` vs. `--live`) $\times$ Fallback (`auto_fallback=True` vs. `auto_fallback=False`) $\times$ Output format (`stdout`, `markdown`, `json`, `both`).
   - Compiler Overrides (valid custom path, invalid path, unexecutable file, directory) $\times$ Target Filter (single target, CWE class, all).

5. **Workload & Stress Testing**
   - High-concurrency multithreaded capability detection (50+ simultaneous worker threads) validating memoization cache safety and eliminating race conditions.
   - Delta-debugging minimization under tight iteration bounds ($N=2, 5, 30$).
   - Long-running infinite loop containment via monotonic high-resolution timeouts.

---

## 2. Feature Inventory & Coverage Mapping (Tiers 1–4)

| Feature # | Feature Name | Description | Source / Milestone | Tier 1 (Unit) | Tier 2 (Boundary) | Tier 3 (Cross) | Tier 4 (Scenario) |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **F1** | `ToolchainCapabilities` & Safe Probing | Active sandboxed probing of Clang, ASan/UBSan, LibFuzzer, Docker, and angr with 3s timeout containment. | R2 / M1 | ✅ | ✅ | ✅ | ✅ |
| **F2** | Config & CLI Option Precedence | Multi-tier precedence resolution across CLI flags (`--mock`, `--live`, `--clang-path`), environment variables (`REVERSECORE_MOCK_MODE`), and config defaults. | R2 / M1 | ✅ | ✅ | ✅ | ✅ |
| **F3** | Live Dynamic Target Compilation | Compilation of C target sources (`vulnerable.c` + `harness.c` + standalone driver) with `-fsanitize=address,undefined -g -O1`. | R1 / M2 | ✅ | ✅ | ✅ | ✅ |
| **F4** | Live Crash Reproduction & ASan Triage | Subprocess execution under ASan monitoring, extracting SIGABRT/SIGSEGV, crash stack traces, and parsing structured CWE/CVSS via `triage_asan_log`. | R1, R3 / M2 | ✅ | ✅ | ✅ | ✅ |
| **F5** | Monotonic TTC Measurement | High-resolution wall-clock Time-To-Crash measurement using `time.perf_counter()` to eliminate clock drift. | R3 / M2 | ✅ | ✅ | ✅ | ✅ |
| **F6** | Live PoC Minimization & Verification | Delta-debugging minimization against live compiled binary, computing authentic byte reduction percentage. | R3 / M2 | ✅ | ✅ | ✅ | ✅ |
| **F7** | Graceful Hybrid Fallback Engine | Deterministic fallback from live compilation failure to mock fixture evaluation without raising exceptions or failing test runs. | R2 / M1, M2 | ✅ | ✅ | ✅ | ✅ |
| **F8** | Master Corpus & 10-Target Consistency | Management of 10 real-world CVE targets with full ground-truth metadata, seed inputs, and ASan crash logs. | R1, R2, R3 / M2, M3 | ✅ | ✅ | ✅ | ✅ |
| **F9** | Multi-Tier Benchmark Test Suite | Multi-tier verification spanning unit feature tests, boundary checks, pairwise integration, and CLI scenario execution. | R1–R3 / M3 | ✅ | ✅ | ✅ | ✅ |
| **F10** | Adversarial Hardening & Concurrency Stress | Resistance against hanging compilers, corrupted source files, oversized payloads, and multi-threaded race conditions. | Hardening / M4 | ✅ | ✅ | ✅ | ✅ |

---

## 3. Real-World CVE Target Inventory (10 Targets)

The benchmark corpus contains 10 verified, diverse real-world CVE targets representing critical vulnerability classes across systems software:

| # | Target ID | CVE Reference | Real-World Library | Target Version | Vulnerability Class | CWE ID | Faulting Symbol | Memory Access | Fixtures Verified |
|---|:---|:---|:---|:---|:---|:---|:---|:---|:---:|
| 1 | `sqlite3_fts5_unicode` | CVE-2019-19645 | SQLite FTS5 | 3.31.0 | Heap-based Buffer Overflow | `CWE-122` | `fts5UnicodeTokenize` | WRITE_OOB (4B) | ✅ |
| 2 | `libpng_eXIf_int_overflow` | CVE-2019-7317 | LibPNG | 1.6.35 | Integer Overflow | `CWE-190` | `png_handle_eXIf` | WRITE_OOB (4B) | ✅ |
| 3 | `libxml2_entity_uaf` | CVE-2017-9047 | LibXML2 | 2.9.4 | Use After Free | `CWE-416` | `xmlParseAttValueComplex` | READ_UAF (1B) | ✅ |
| 4 | `libarchive_rar_double_free` | CVE-2019-18408 | LibArchive | 3.3.2 | Double Free | `CWE-415` | `rar_free_codes` | FREE_INVALID (8B) | ✅ |
| 5 | `openssl_bn_infinite_loop` | CVE-2022-0778 | OpenSSL | 1.1.1n | Infinite Loop / Resource Exhaustion | `CWE-835` | `BN_mod_sqrt` | CPU_EXHAUSTION | ✅ |
| 6 | `zlib_inflate_heap_oob` | CVE-2016-9843 | zlib | 1.2.8 | Heap-based Buffer Overflow | `CWE-787` | `inflate_fast` | WRITE_OOB (4B) | ✅ |
| 7 | `curl_cookie_leak_info` | CVE-2022-32205 | curl | 7.83.0 | Information Exposure | `CWE-200` | `Curl_cookie_add` | READ_OOB (16B) | ✅ |
| 8 | `ffmpeg_hevc_oob_read` | CVE-2020-22021 | FFmpeg | 4.2.1 | Out-of-bounds Read | `CWE-125` | `hevc_decode_frame` | READ_OOB (8B) | ✅ |
| 9 | `php_spl_type_confusion` | CVE-2021-21703 | PHP Engine | 7.4.15 | Type Confusion | `CWE-763` | `spl_array_it_get_current_data` | READ_INVALID (8B) | ✅ |
| 10 | `expat_entity_int_overflow` | CVE-2022-25236 | Expat XML Parser | 2.4.4 | Integer Overflow / Multi-byte | `CWE-190` | `xmlTokProlog` | WRITE_OOB (4B) | ✅ |

---

## 4. Test Architecture & Directory Layout

### 4.1 Component Diagram

```
                              ┌───────────────────────────────────┐
                              │            pytest / CLI           │
                              └─────────────────┬─────────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     ▼                                                     ▼
      ┌─────────────────────────────┐                       ┌─────────────────────────────┐
      │     Unit Benchmark Tests    │                       │   Integration E2E Tests     │
      │  (tests/unit/benchmarks/)   │                       │   (tests/integration/)      │
      ├─────────────────────────────┤                       ├─────────────────────────────┤
      │ - test_capabilities.py      │                       │ - test_cve_benchmark_e2e.py │
      │ - test_compiler_runner.py   │                       │ - test_cli_tools.py         │
      │ - test_e2e_benchmark_suite  │                       │ - test_server_e2e.py        │
      │ - test_expanded_corpus.py   │                       └─────────────────────────────┘
      │ - test_milestones_adversary │
      └──────────────┬──────────────┘
                     │
                     ▼
      ┌─────────────────────────────┐
      │     Corpus Fixtures         │
      │ (tests/fixtures/benchmarks) │
      ├─────────────────────────────┤
      │ - ground_truth_corpus.json  │
      │ - targets/sqlite_fts5/...   │
      │ - targets/libpng_parser/... │
      │ - targets/libxml2_parser/.. │
      │ - targets/libarchive_parser/│
      │ - targets/openssl_bn/...    │
      │ - targets/zlib_inflate/...  │
      │ - targets/curl_cookie/...   │
      │ - targets/ffmpeg_hevc/...   │
      │ - targets/php_spl/...       │
      │ - targets/expat_entity/...  │
      └─────────────────────────────┘
```

### 4.2 Fixture Layout Standard

Every target directory under `tests/fixtures/benchmarks/targets/<target_name>/` adheres to the standardized fixture contract:
- `target.json`: Ground truth metadata conforming to Pydantic `TargetGroundTruth` schema.
- `vulnerable.c`: Vulnerable C source implementation reproducing the defect.
- `patched.c`: Remediated C source implementation with defect resolved.
- `patch.diff`: Unified diff between vulnerable and patched source.
- `harness.c`: LibFuzzer/custom harness entrypoint `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.
- `asan_crash.log`: Verbatim AddressSanitizer crash log with stack trace and memory access violation.
- `raw_poc.bin` / `poc_raw.bin`: Triggering crash payload reproducing memory violation.
- `minimized_poc.bin` / `poc_minimized.bin`: Delta-debug minimized crash payload preserving faulting symbol.
- `seed_corpus.bin` / `seed_valid.bin`: Non-crashing valid input exercising normal code paths.
- `dictionary.dict`: Optional syntax token dictionary for fuzzing guidance.

---

## 5. Multi-Tier Testing Methodology

### Tier 1: Feature Coverage
- **Purpose**: Verify base functional behavior of each component against specified interfaces.
- **Coverage**: Minimum 5 dedicated test cases per feature (F1 through F8).
- **Execution**: Mock mode and live isolated unit tests.

### Tier 2: Boundary & Corner Cases
- **Purpose**: Exercise negative paths, boundary values, malformed inputs, and resource limits.
- **Coverage**: Corrupted JSON, missing fixtures, 0-byte PoCs, 11MB oversized inputs, out-of-range CVSS values, malformed CWE regex patterns, invalid minimizing ratios.

### Tier 3: Cross-Feature Combinations (Pairwise)
- **Purpose**: Validate interactions between configuration flags, capability detection, dynamic compilation, ASan crash triaging, scoring calculations, and report rendering.
- **Scenarios**:
  - Live mode with valid compiler $\rightarrow$ compile $\rightarrow$ execute $\rightarrow$ triage $\rightarrow$ minimize $\rightarrow$ score.
  - Live mode with missing compiler $\rightarrow$ detect absence $\rightarrow$ auto fallback $\rightarrow$ mock triage $\rightarrow$ score.
  - Strict mode (`auto_fallback=False`) with compilation failure $\rightarrow$ record error status without suite termination.
  - Custom `--clang-path` override propagating across subprocess invocations.

### Tier 4: Real-World Application Scenarios
- **Purpose**: End-to-end execution of CLI commands and report generation workflows in authentic runtime environments.
- **Workflows**:
  - `python3 scripts/run_cve_benchmark.py --live --targets sqlite3_fts5_unicode --output-format stdout`
  - `python3 scripts/run_cve_benchmark.py --mock --output-format both --output-dir artifacts/benchmarks`
  - Exit code verification: `0` (TPR $\ge 80\%$), `1` (invalid arguments / fatal setup error), `2` (TPR $< 80\%$).

### Tier 5: Adversarial Stress & Hardening
- **Purpose**: Empirical stress testing under adversarial conditions (infinite loop subprocesses, crashing compiler scripts, concurrent thread contention).

---

## 6. Pass / Fail Semantics & Verification Thresholds

| Metric | Target Threshold | Strict / Lenient | Failure Impact |
| :--- | :---: | :---: | :--- |
| **True Positive Rate (TPR)** | $\ge 80.0\%$ | Strict | Exit code 2 if below threshold; CI failure. |
| **CVSS v3.1 Tolerance** | $| \text{Pred} - \text{GT} | \le 0.5$ | Strict | Target CVSS tolerance marked failed if $>0.5$. |
| **CWE Taxonomic Match** | $\ge 0.50$ (Shared Ancestor) | Strict | Score $<0.5$ treated as classification mismatch. |
| **PoC Minimization Ratio** | $\ge 50.0\%$ (Target $\ge 80.0\%$) | Informational | Warns if minimization produces $<50\%$ reduction. |
| **Compiler Probe Timeout** | $\le 3.0\text{s}$ per probe | Strict | Probing process terminated; capability marked `False`. |
| **Target Execution Timeout** | Configurable (default 30s) | Strict | Subprocess terminated via SIGKILL; error recorded. |
| **Test Suite Pass Rate** | $100\%$ (0 failed) | Strict | Any test failure rejects build. |
| **Code Quality / Ruff** | 0 errors | Strict | `ruff check` must pass cleanly. |
| **Code Formatting / Black** | 100% compliant | Strict | `black --check --target-version py312` must pass. |
