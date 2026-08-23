# E2E Test Infra: Reversecore_MCP Optimization & Enhancement

## Test Philosophy
- Requirement-driven, opaque-box, and contract-verifying testing.
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Combinatorial Testing + Real-World Workload Testing + White-box Adversarial Hardening (Tier 5).
- Performance & Token Metrics: Strict validation of `orjson` serialization SLA (<1ms for 5,000 items) and measurable token reduction (40-80%) via smart pagination and compact representations.

## Feature Inventory & Test Coverage Map
| # | Feature | Requirement Source | Tier 1 (Feature) | Tier 2 (Boundary) | Tier 3 (Pairwise) | Tier 4 (Workload) |
|---|---------|-------------------|:----------------:|:-----------------:|:-----------------:|:-----------------:|
| 1 | FastMCP stdio/SSE Transport | R1 § FastMCP Transport | 5 | 5 | ✓ | ✓ |
| 2 | Progress Reporting & Context | R1 § Progress Reporting | 5 | 5 | ✓ | ✓ |
| 3 | Dynamic Resource Routing & Security | R1 § Dynamic Resource URIs | 5 | 5 | ✓ | ✓ |
| 4 | Prompt Registration & Discovery | R2 § Prompts Architecture | 5 | 5 | ✓ | ✓ |
| 5 | Specialized RE Reasoning Prompts | R2 § Advanced RE Prompts | 5 | 5 | ✓ | ✓ |
| 6 | Dynamic Context Resources (6 URIs) | R2 § Context Resources | 5 | 5 | ✓ | ✓ |
| 7 | Core Result Schema & Pagination | R3 § Output Schema | 5 | 5 | ✓ | ✓ |
| 8 | Double-Serialization Elimination | R3 § Serialization Optimization | 5 | 5 | ✓ | ✓ |
| 9 | High-Speed `orjson` Standardization | R3 § Serialization Benchmarks | 5 | 5 | ✓ | ✓ |
| 10 | Smart Pagination & Token Reduction | R3 § Token Efficiency | 5 | 5 | ✓ | ✓ |

## Test Architecture
- **Test Runners**:
  - `pytest tests/unit/ tests/integration/ -v` (Unit and integration suites)
  - `pytest tests/performance/test_performance_regression.py -v` (Serialization & Tool SLA benchmarks)
  - `ruff check reversecore_mcp/ tests/` (Linter validation)
  - `black --check --target-version py312 reversecore_mcp/ tests/` (Code formatting validation)
- **Pass/Fail Semantics**: 100% of test assertions must pass with exit code 0; code coverage must exceed 54% with zero regressions.
- **Directory Layout**:
  - `tests/unit/core/test_resources.py` (Static and dynamic MCP virtual resources)
  - `tests/unit/prompts/test_all_prompts.py` and `test_advanced_prompts.py` (Reasoning prompts)
  - `tests/unit/core/test_result.py` and `test_json_utils.py` (Data schemas, pagination, orjson)
  - `tests/integration/test_server_transport.py` (FastMCP stdio, SSE streaming, progress token notifications, Client API)
  - `tests/performance/test_performance_regression.py` (Performance regression & serialization SLAs)

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Target Complexity |
|---|----------|--------------------|-------------------|
| 1 | ASan Crash Log Triage to Exploit Feasibility | F1, F4, F5 (`vulnerability_triage_mode`), F7, F10 | Complex |
| 2 | Layered Malware Deobfuscation & Virtual Memory Map | F3, F5 (`malware_deobfuscation_mode`), F6 (`/memory_map`, `/signatures`), F8, F10 | Complex |
| 3 | Fast Function Navigation & Cross-Reference Tracing | F3, F6 (`/func/{addr}/xrefs`, `/func/{addr}/context`), F7, F10 (Compact Disasm) | Medium |
| 4 | Patch Diffing & 1-Day Vulnerability Inference | F4, F5 (`patch_diff_auto_mode`), F6 (`/metadata`, `/imports`), F8, F10 | Complex |
| 5 | High-Speed Batch Serialization & Tool Progress Streaming | F1, F2 (Context streaming), F7 (`PaginationMeta`), F8, F9 (`orjson`), F12 | Medium |

## Coverage Thresholds
- Tier 1: ≥5 test cases per feature (50+ feature coverage tests)
- Tier 2: ≥5 test cases per feature for edge/boundary conditions (50+ boundary tests)
- Tier 3: Pairwise combination matrix covering multi-feature interactions
- Tier 4: ≥5 realistic reverse engineering end-to-end workload scenarios
- Tier 5: White-box adversarial coverage hardening and fuzzing
- Benchmarks: `orjson` serialization speedup >= 4x, token reduction >= 40-80% on large outputs.
