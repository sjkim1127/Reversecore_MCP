# Test Coverage Gap Analysis: dormant_detector.py

This report details the test coverage gaps in `reversecore_mcp/tools/malware/dormant_detector.py` and proposes a testing strategy and specific test cases to achieve 100% (or near 100%) test coverage.

---

## 1. Executive Summary

- **Target File**: `reversecore_mcp/tools/malware/dormant_detector.py`
- **Current Coverage**: ~77% (84 lines uncovered out of 366 statements)
- **Key Coverage Gaps**:
  1. **LIEF Import and Mocking branches** (handling environment differences where LIEF is missing or mocked).
  2. **Process Pool Executor Isolation** (LIEF worker execution inside a separate process, which prevents the standard coverage tool from tracing it).
  3. **Radare2 Command Caching** (`_run_r2_cmd_cached` is never hit because tests either mock `_run_r2_cmd` or bypass the cache).
  4. **Heuristic Detection Details** (conditional checks for time-based and env-based APIs when using non-magic values, entropy calculations, and error-handling).
  5. **ESIL Reachability Edge Cases** (failure to parse PC, reachability failure, and validation logic).

---

## 2. Granular Coverage Gap Catalog

The table below lists each uncovered line/branch in `dormant_detector.py`, explains why it is currently uncovered, and provides the testing strategy to resolve it.

| File Line(s) | Code Block / Context | Why Uncovered | Strategy to Achieve Coverage |
| :--- | :--- | :--- | :--- |
| **20-21** | `except ImportError: lief = None` | LIEF is installed in the test environment, so this fallback is never executed. | Mock the `sys.modules["lief"]` to be `None` or raise `ImportError` on import during test initialization. |
| **81** | `return False` in `_is_lief_mocked` | LIEF is present and not mocked in the environment by default, skipping this check. | Test with `lief = None` and verify `_is_lief_mocked()` returns `False`. |
| **89-97** | Class name fallback checking in `_is_lief_mocked` | Custom objects with "Mock" in their name are not used; standard mocks trigger early return. | Test with a custom class having "Mock" in its name and verify it returns `True`. |
| **102-123** | `_run_lief_game_context_worker` implementation | Executed inside a subprocess via `ProcessPoolExecutor`. Coverage tools (`pytest-cov`) do not track child processes by default. | Execute `_run_lief_game_context_worker` directly in a main-thread test case. |
| **149-152** | Mocked LIEF signature loops in `_check_game_context` | Mocks in tests do not populate signatures with multiple signers. | Mock a `signatures` attribute on `lief` with custom `signers` list. |
| **155-156** | `except Exception` when LIEF is mocked | LIEF mock methods in tests return `None` or valid objects without raising exceptions. | Mock `lief.parse` to raise an exception when `_is_lief_mocked` is True. |
| **157-167** | Subprocess fallback in `_check_game_context` | Real/unmocked `lief` path with `ProcessPoolExecutor` is never executed in tests. | Test with a mock that does not trigger `_is_lief_mocked()`, and mock the executor/future to simulate success/exceptions. |
| **207-210** | PE Signature Trusted Publisher checks | Mocked signatures do not match game publisher names (e.g. "Blizzard", "Valve"). | Mock PE signatures containing game publisher substrings. |
| **214-216** | Section-based game indicator checks | Mocked sections do not contain "ress" or "il2cpp". | Mock section names containing "ress" or "il2cpp". |
| **252-257** | `_run_r2_cmd_cached` body | Caching helper is never executed; tests either disable cache or mock `_run_r2_cmd`. | Test calling `_run_r2_cmd(..., use_cache=True)` twice and assert second call uses cached result. |
| **280-281** | Cache key lookup in `_run_r2_cmd` | Direct caching branch is skipped. | Call `_run_r2_cmd` with `use_cache=True`. |
| **327** | `await ctx.info(...)` in emulation | No emulation tests pass a mock `Context` (`ctx`) object. | Run emulation test passing a mock `Context`. |
| **373-376** | `if not isinstance(functions, list)` check | Mocked `aflj` outputs return lists or corrupt strings, never non-list JSON (e.g., dict). | Return a JSON dict from the mock command (e.g. `{"error": "bad cmd"}`). |
| **591** | `if value <= 0: return 0.0` in entropy | Tested values are positive. | Call `_calculate_entropy_score` with negative and zero values. |
| **604-608** | `elif val_str.isdigit()` and `except ValueError` | Disassembled values in tests only use hex formatting; ValueError handling is not hit. | Test `_extract_hex_value` with decimal strings (e.g., `"12345"`) and malformed strings. |
| **615** | `if not start_addr: return "unconfirmed..."` | Functions in tests always have valid start addresses. | Call `_verify_reachability_with_esil` with `start_addr = None`. |
| **648-653** | ESIL verification failure branches | Test mocks always return successful reachability matching the target address. | Mock `aer PC` returning non-matching hex, ValueError, or cmd exception. |
| **660** | `await ctx.report_progress(...)` in paths | Context is mocked out / bypassed in the relevant test. | Call `_identify_conditional_paths` with a mock `Context`. |
| **672** | `if not cmds: continue` in batching | All batch functions in tests have valid offsets. | Pass a function dict missing the `"offset"` key. |
| **702** | `recent_api_calls.pop(0)` buffer limit | Fewer than 5 API calls are mocked in succession. | Mock a function that calls more than 5 time/env APIs prior to a comparison. |
| **712** | `if value is None: continue` operand check | Operand values always parse successfully. | Mock a comparison instruction with invalid hex operand format. |
| **731-732** | Medium confidence time API check | Magic values trigger the high-confidence branch first, bypassing the medium branch. | Test time API call followed by comparison with a non-magic value (e.g., `0x55555555`). |
| **734-735** | Medium confidence env API check | Same as above. | Test environment API call followed by comparison with a non-magic value. |
| **767-772** | JSON parsing & batch exception handlers | Radare2 outputs are always valid and process successfully. | Mock command execution to throw exceptions or return invalid JSON for a function. |

---

## 3. Recommended Testing Strategy

To achieve 100% test coverage without impacting production code stability:

### A. Environment Simulation (Import Mocks)
Use `unittest.mock.patch.dict` on `sys.modules` to test how the module behaves when `lief` is missing:
```python
with patch.dict("sys.modules", {"lief": None}):
    # Reload or test importing/functions
```

### B. Direct Execution of Subprocess Code
To cover `_run_lief_game_context_worker`, execute it directly in the test suite as a standard function:
```python
def test_game_context_worker_direct(tmp_path):
    # Call _run_lief_game_context_worker(str(tmp_path)) directly
```

### C. Cache Validation Test
Implement a test specifically asserting caching behavior:
```python
@pytest.mark.asyncio
async def test_r2_cmd_caching(tmp_path):
    # Call _run_r2_cmd(use_cache=True) twice.
    # Assert execute_subprocess_async is called only once.
```

### D. Parameterized Edge-Case Testing
Use `pytest.mark.parametrize` to supply diverse values to validation, extraction, and entropy calculation functions.

---

## 4. Proposed Test Cases

Below is a list of precise test cases that should be added to `tests/unit/tools/malware/test_dormant_detector.py`:

1. **`test_lief_not_installed`**: Bypasses `lief` presence to cover the `ImportError` branch (Lines 20-21).
2. **`test_is_lief_mocked_variations`**: Tests `_is_lief_mocked()` with `lief = None` and custom class objects to cover fallback branches (Lines 81, 89-97).
3. **`test_lief_game_context_worker_direct`**: Directly calls `_run_lief_game_context_worker` with valid/invalid files to cover worker lines (Lines 102-123).
4. **`test_check_game_context_mocked_exception`**: Triggers exception inside `_check_game_context` when `lief` is mocked to hit Line 155.
5. **`test_check_game_context_unmocked_process_pool`**: Triggers the `else` branch of `_check_game_context` (Lines 157-167) by mocking the process executor execution.
6. **`test_check_game_context_trusted_publisher_and_sections`**: Feeds `signatures` containing "Valve" and sections containing "il2cpp" to cover Lines 207-210 and 214-216.
7. **`test_r2_cmd_caching_behavior`**: Evaluates caching, cache invalidation on modification time change, and `use_cache=True` path (Lines 252-257, 280-281).
8. **`test_dormant_detector_invalid_json_type`**: Simulates `aflj` returning a JSON dictionary instead of a list (Lines 373-376).
9. **`test_entropy_zero_or_negative`**: Calls `_calculate_entropy_score` with negative and zero values (Line 591).
10. **`test_extract_hex_value_decimal_and_invalid`**: Feeds decimal and malformed strings to `_extract_hex_value` (Lines 604-608).
11. **`test_verify_reachability_no_start_addr`**: Calls reachability check with `None` start address (Line 615).
12. **`test_verify_reachability_failures`**: Tests when reachability stops at a different PC, fails parsing PC, or throws command exception (Lines 648-653).
13. **`test_identify_conditional_paths_batching_edge_cases`**: Covers missing offsets, context progress updates, and batch exception handling (Lines 660, 672, 767-772).
14. **`test_identify_conditional_paths_buffer_overflow`**: Calls more than 5 Time APIs to test buffer eviction (Line 702).
15. **`test_identify_conditional_paths_invalid_hex_operand`**: Fails operand extraction parsing (Line 712).
16. **`test_identify_conditional_paths_medium_confidence`**: Employs Time/Env API followed by non-magic values to cover Lines 731-732 and 734-735.
