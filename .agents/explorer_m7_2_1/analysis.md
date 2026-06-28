# Test Coverage Gap Analysis: dormant_detector.py

## Executive Summary
This report analyzes the test coverage gaps for the Dormant Detector tool (`reversecore_mcp/tools/malware/dormant_detector.py`).

Currently, running the unit tests in `tests/unit/tools/malware/test_dormant_detector.py` yields **77%** statement coverage (282/366 statements covered, with 84 statements missed). The second test file, `tests/unit/tools/malware/test_dormant_detector_standalone.py`, does not import or test `dormant_detector.py` directly; instead, it tests a legacy copied version of the tool's predecessor (`ghost_trace.py`) inside its own test file, yielding **0%** actual coverage on the real codebase.

To achieve 100% (or near 100% due to mock limitations) coverage, we identify all uncovered branches, explain why they are missed, and outline a precise testing strategy with concrete test cases.

---

## Detailed Gap Analysis

| Line Numbers | Code Section / Function | Description of Code Block | Reason Currently Missed |
|---|---|---|---|
| **20-21** | Module-level import | `except ImportError: lief = None` | The test environment has `lief` installed; thus, the import succeeds. |
| **81** | `_is_lief_mocked()` | `if not lief: return False` | Tests mock `lief` using `unittest.mock.MagicMock` or `Mock`, which are truthy. |
| **89-97** | `_is_lief_mocked()` | Fallback check for "Mock" string in class names when `unittest.mock` import fails. | `unittest.mock` is always available in the test environment, so the `try` block succeeds and returns early. |
| **102-123** | `_run_lief_game_context_worker()` | Full LIEF worker function for process pool execution. | This function is only executed in a subprocess. Subprocesses are not monitored by `pytest-cov`, and the main test suite mocks `lief` so it never spawns this worker. |
| **149-152** | `_check_game_context()` | Loop extracting signatures from `binary.signatures`. | Mock binary objects in the current test cases are created with `signatures = []`. |
| **155-167** | `_check_game_context()` | `else` branch using `ProcessPoolExecutor` to parse file with LIEF in separate process. | All current tests run in a mocked `lief` environment, meaning `_is_lief_mocked()` returns `True` and bypasses the `else` branch. |
| **207-210** | `_check_game_context()` | Digital signatures trusted publisher name checks. | Mock binary signatures list is empty, skipping signature verification. |
| **214-216** | `_check_game_context()` | Game-specific section name checks (e.g. `resS`, `il2cpp`). | Mock binary sections list is empty, skipping section checks. |
| **252-257** | `_run_r2_cmd_cached()` | Command executor wrapper with caching. | No unit tests invoke cached command execution; all tests mock `_run_r2_cmd` or call it with `use_cache=False`. |
| **280-281** | `_run_r2_cmd()` | Cache lookup branch `return await _run_r2_cmd_cached(...)`. | Unit tests patch `_run_r2_cmd` itself or explicitly specify `use_cache=False`. |
| **327** | `dormant_detector()` | Context logging during emulation phase. | The mock test case for emulation does not pass a `Context` (`ctx=None`). |
| **373-376** | `dormant_detector()` | Validation error handling when `functions` is not a list. | Current test cases either return a valid list or fail early due to a `None` result from JSON extraction. |
| **591** | `_calculate_entropy_score()` | Boundary condition check `if value <= 0: return 0.0`. | Value check filter skips integers <= 100. Thus, this branch is unreachable in the tool's natural control flow. |
| **604-608** | `_extract_hex_value()` | Decimal integer conversion, `ValueError` exception handler, and default `return None`. | Tests only pass hex values (`0x...`). Non-numeric/malformed hex values are not tested. |
| **615** | `_verify_reachability_with_esil()` | Defensive start address check `if not start_addr: return ...`. | Functions lacking offsets are skipped in the batch loop, so `start_addr` is always a valid address. |
| **648-653** | `_verify_reachability_with_esil()` | Reachability failure, register parsing exception, and radare2 execution exception handlers. | Tests only check the successful reachability branch where register parsing succeeds. |
| **660** | `_identify_conditional_paths()` | Context progress reporting: `await ctx.report_progress(...)`. | Tests do not pass a `Context` (`ctx=None`) to `_identify_conditional_paths`. |
| **672** | `_identify_conditional_paths()` | Empty batch command skip `if not cmds: continue`. | The functions list passed to batch processing always has valid offsets. |
| **702** | `_identify_conditional_paths()` | Popping old API calls from the queue `recent_api_calls.pop(0)`. | Tests simulate fewer than 5 consecutive API calls. |
| **712** | `_identify_conditional_paths()` | Skipping invalid extracted values `if value is None: continue`. | Disassembly values are always valid hexadecimal literals in the tests. |
| **731-732** | `_identify_conditional_paths()` | Heuristic matching for Time API trigger checks. | The mock disassembly matches a known magic value (`0xdeadbeef`), which takes precedence over Time/Env checks. |
| **734-735** | `_identify_conditional_paths()` | Heuristic matching for Env API trigger checks. | Preempted by the known magic values check branch. |
| **767-772** | `_identify_conditional_paths()` | Disassembly JSONDecodeError and batch execution exception handlers. | Radare2 command mock responses are always valid, malformed JSON is not tested. |

---

## Analysis of Legacy Test Suite (`test_dormant_detector_standalone.py`)
The file `tests/unit/tools/malware/test_dormant_detector_standalone.py` does not import `reversecore_mcp.tools.malware.dormant_detector`. Instead, it defines duplicate class models and copies obsolete source code from `ghost_trace.py` (the precursor to `dormant_detector.py`) directly into the test file.

Running this standalone test file exercises the duplicate code inside itself, resulting in **0% coverage** on the actual target file `reversecore_mcp/tools/malware/dormant_detector.py`.

**Recommendation:** Since `test_dormant_detector.py` is the official and correct test suite for the Dormant Detector tool, all new coverage tests should be added to `test_dormant_detector.py`. The standalone legacy test file `test_dormant_detector_standalone.py` should either be deleted or refactored to import the real tool.

---

## Discussion on Logically Unreachable Code
During the analysis, two instances of defensive programming were identified as logically unreachable under the tool's natural control flow:

1. **`_calculate_entropy_score()` line 591 (`if value <= 0: return 0.0`)**:
   - `_identify_conditional_paths()` only passes `value` to `_calculate_entropy_score()` if `_is_simple_value(value)` returns `False`.
   - `_is_simple_value()` returns `True` if `0 <= value <= 100`.
   - `_extract_hex_value()` only parses decimal integers (`val_str.isdigit()`) or hex strings starting with `0x`. Since negative signs (e.g. `-` or `-0x`) are not matched, it never returns a negative number.
   - Therefore, any `value` reaching the entropy calculation is strictly greater than 100. The check `value <= 0` can never evaluate to `True` during standard discovery execution.

2. **`_verify_reachability_with_esil()` line 615 (`if not start_addr: return ...`)**:
   - `_identify_conditional_paths()` batches functions by checking `if addr:` (where `addr = func.get("offset")`). Functions without an offset are skipped, ensuring `func_start` (the function's offset) is always a truthy value when passed to `_verify_reachability_with_esil()`.

**How to test:** Although unreachable via natural execution of the tool, these functions are defined at the module scope or are accessible directly. We can unit test them in isolation by importing and calling them directly with `None` or negative inputs.

---

## Recommended Testing Strategy
We recommend adding new test cases to `tests/unit/tools/malware/test_dormant_detector.py`. By structuring these tests as discrete unit tests targeting individual helper functions, we avoid complex integration setup and can cover 100% of the lines.

### Proposed Test Cases and Mock Specifications

#### 1. Module Imports and Mock Detection Gaps
* **Test Case: `test_is_lief_mocked_when_lief_is_none`**
  - **Setup**: Patch `reversecore_mcp.tools.malware.dormant_detector.lief` to `None`.
  - **Action**: Call `_is_lief_mocked()`.
  - **Assertion**: Assert that it returns `False`. Covers line 81.
* **Test Case: `test_is_lief_mocked_import_error_fallback`**
  - **Setup**: Patch `builtins.__import__` to raise `ImportError` when `unittest.mock` is requested. Create a dummy class `FakeMockClass` whose name contains "Mock".
  - **Action**: Call `_is_lief_mocked()` with `lief` set to an instance of `FakeMockClass`.
  - **Assertion**: Assert that it returns `True`. Covers lines 89-97.

#### 2. LIEF Subprocess Worker Gaps
* **Test Case: `test_run_lief_game_context_worker_success`**
  - **Setup**: Mock `lief.parse` to return a mock binary containing libraries, signers/signatures, and sections.
  - **Action**: Call `_run_lief_game_context_worker("dummy_path")` directly in the main test thread.
  - **Assertion**: Verify libraries, signatures, and sections are parsed correctly. Covers lines 102-120.
* **Test Case: `test_run_lief_game_context_worker_exceptions`**
  - **Setup**: Mock `lief.parse` to raise an exception or return `None`.
  - **Action**: Call `_run_lief_game_context_worker("dummy_path")`.
  - **Assertion**: Verify it returns an empty dictionary of list structures and handles the exception. Covers lines 107-108, 121-122.

#### 3. Game Context Check Mock Gaps
* **Test Case: `test_check_game_context_with_signatures_and_sections`**
  - **Setup**: Mock `lief` to be mocked. Define a mock binary containing signatures with valid signers (e.g. `Electronic Arts`) and sections with game names (e.g. `ress`).
  - **Action**: Call `_check_game_context(test_file)`.
  - **Assertion**: Verify indicators list contains both "Trusted Publisher" and "Game Section", and that the total score is accumulated correctly. Covers lines 149-152, 207-210, 214-216.
* **Test Case: `test_check_game_context_mocked_exception`**
  - **Setup**: Mock `lief` to be mocked, and make `lief.parse` raise an exception.
  - **Action**: Call `_check_game_context(test_file)`.
  - **Assertion**: Verify it returns the default context safely. Covers lines 155-156.
* **Test Case: `test_check_game_context_process_pool_success_and_error`**
  - **Setup**: Mock `_is_lief_mocked` to return `False`. Patch `concurrent.futures.ProcessPoolExecutor` to return a mock executor whose future returns a success dictionary in one test, and raises an exception in another test.
  - **Action**: Call `_check_game_context(test_file)`.
  - **Assertion**: Verify the success path sets the score/indicators based on process output, and the exception path returns the default context. Covers lines 158-167.

#### 4. Caching and `_run_r2_cmd_cached`
* **Test Case: `test_run_r2_cmd_cached_behavior`**
  - **Setup**: Mock `execute_subprocess_async` to track call count and return constant values. Call `_run_r2_cmd_cached.cache_clear()` to ensure cache is clean.
  - **Action**:
    1. Call `_run_r2_cmd` with `use_cache=True` (first call).
    2. Call `_run_r2_cmd` with same command (second call, cache hit).
    3. Call `_run_r2_cmd` with different command (third call, cache miss).
    4. Modify the temp binary size/time and call with original command (fourth call, cache invalidation).
  - **Assertion**: Assert execution happens 1 time for cache hit, and counts increment correctly for misses. Covers lines 252-257 and 280-281.

#### 5. Emulation Context and Parsing Validation Gaps
* **Test Case: `test_emulation_phase_context_logging`**
  - **Setup**: Create a mock `Context` with an async `info` method.
  - **Action**: Call `dormant_detector` with a focus function, hypothesis, and the mock context.
  - **Assertion**: Assert that `ctx.info` was called with the emulation start log message. Covers line 327.
* **Test Case: `test_dormant_detector_functions_not_list`**
  - **Setup**: Mock `_run_r2_cmd` to return a JSON object (dictionary) instead of a list (e.g. `'{"error": "no functions"}'`).
  - **Action**: Call `dormant_detector`.
  - **Assertion**: Assert that it returns an error with the `PARSE_ERROR` error code. Covers lines 373-376.

#### 6. Disassembly Value Parsing and Unreachable Branches
* **Test Case: `test_calculate_entropy_score_isolated`**
  - **Action**: Directly import and call `_calculate_entropy_score` with `0` and `-5`.
  - **Assertion**: Verify it returns `0.0`. Covers line 591 (the unreachable line).
* **Test Case: `test_verify_reachability_with_esil_isolated`**
  - **Action**: Directly import and call `_verify_reachability_with_esil` with `None` as start address.
  - **Assertion**: Verify it returns `"unconfirmed (no start address)"`. Covers line 615 (the unreachable line).
* **Test Case: `test_identify_conditional_paths_decimal_and_invalid`**
  - **Setup**: Mock batch disassembly to output a decimal integer check `cmp eax, 12345678` and an invalid hex check `cmp ebx, 0xinvalid`.
  - **Action**: Call `_identify_conditional_paths`.
  - **Assertion**: Verify decimal integer is converted and processed, while `0xinvalid` raises a `ValueError` inside `_extract_hex_value` and is gracefully skipped. Covers lines 604-608 and 712.

#### 7. ESIL Verification Gaps
* **Test Case: `test_verify_reachability_with_esil_scenarios`**
  - **Setup**: Directly import and call `_verify_reachability_with_esil`. Mock `_run_r2_cmd` to simulate three execution outcomes:
    1. PC matches target (reachability verified).
    2. PC is different (reachability unconfirmed).
    3. PC register parsing returns a non-hex value (register parse error).
    4. Execution command raises a runtime exception.
  - **Assertion**: Assert that correct status strings are returned in each scenario. Covers lines 648-653.

#### 8. Conditional Paths Logic Gaps
* **Test Case: `test_identify_conditional_paths_with_context`**
  - **Setup**: Create a mock `Context` with `report_progress` mocked.
  - **Action**: Call `_identify_conditional_paths` with the context and a functions list.
  - **Assertion**: Verify that `ctx.report_progress` was called. Covers line 660.
* **Test Case: `test_identify_conditional_paths_empty_cmds`**
  - **Action**: Call `_identify_conditional_paths` with a function dictionary lacking an `"offset"` attribute.
  - **Assertion**: Assert it returns an empty list. Covers line 672.
* **Test Case: `test_identify_conditional_paths_api_queue_limit`**
  - **Setup**: Mock disassembly to return more than 5 time/env API call instructions (e.g. 6 calls to `getenv`) followed by a cmp.
  - **Action**: Call `_identify_conditional_paths`.
  - **Assertion**: Verify the API list is limited to 5 elements by popping the oldest call, and the trigger pattern is flagged. Covers line 702.
* **Test Case: `test_identify_conditional_paths_triggers`**
  - **Setup**: Define two separate test cases where disassembly contains a non-magic value `cmp eax, 0x12345678` preceded by:
    1. A Time API call (`call sym.imp.time`).
    2. An Env API call (`call sym.imp.getenv`).
  - **Action**: Call `_identify_conditional_paths` and mock ESIL verification to return unconfirmed.
  - **Assertion**: Verify that they trigger medium confidence pattern matches with the appropriate reason string. Covers lines 731-732 and 734-735.
* **Test Case: `test_identify_conditional_paths_exceptions`**
  - **Setup**:
    1. Mock `_run_r2_cmd` to return valid JSON structures, but mock `json.loads` to raise `JSONDecodeError`.
    2. Mock `_run_r2_cmd` to raise `RuntimeError` during batch execution.
  - **Action**: Call `_identify_conditional_paths`.
  - **Assertion**: Verify that exceptions are caught, warnings are logged, and the function continues processing other batches/functions. Covers lines 767-772.
