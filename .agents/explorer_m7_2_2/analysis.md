# Test Coverage Analysis Report: `reversecore_mcp/tools/malware/dormant_detector.py`

## Executive Summary
This report analyzes the test coverage gaps in `reversecore_mcp/tools/malware/dormant_detector.py` based on execution of unit tests under `tests/unit/tools/malware/test_dormant_detector.py`.

Currently, `dormant_detector.py` has **77% test coverage**. There are 84 uncovered lines, primarily concentrated in:
1. **LIEF & Game Context Detection**: Mocked/unmocked behavior discrepancies, worker process pool exceptions, trusted publishers, and game section checking.
2. **Caching & Direct Execution**: `_run_r2_cmd_cached` logic and timeout calculations.
3. **Disassembly & Heuristic Logic**: Simple value checks, entropy calculations for edge cases, time/environment API sequence triggers, list length enforcement, and invalid value handling.
4. **ESIL Reachability & Exception Handling**: Edge cases in address reachability, register parsing failures, and batch execution exception handling.

Importantly, during this investigation, we uncovered a **silent alignment bug** in the batch disassembly loop that can misalign function objects and their disassembly blocks if any function lacks an `offset`.

---

## Detailed Gap Analysis & Recommendations

### 1. LIEF and Game Context Detection (Lines 20-21, 81, 89-97, 102-123, 149-152, 155-167, 207-210, 214-216)

#### A. Module-Level Import & Mock Checks (Lines 20-21, 81, 89-97)
*   **Code Segment**:
    ```python
    18: try:
    19:     import lief
    20: except ImportError:
    21:     lief = None
    ```
    and `_is_lief_mocked()`:
    ```python
    79: def _is_lief_mocked() -> bool:
    80:     if not lief:
    81:         return False
    ...
    89:     except ImportError:
    90:         pass
    ```
*   **Gap Description**: In the testing environment, `lief` is always installed. Thus, the `ImportError` branch and the `if not lief` check are never executed. Additionally, inside `_is_lief_mocked()`, the `ImportError` is never triggered, and the fallback to `cls_name` parsing (lines 91-97) is partially skipped or untested for non-mocked/unusual mock cases.
*   **Testing Strategy**:
    *   Test with `lief = None` by temporarily patching `reversecore_mcp.tools.malware.dormant_detector.lief` to `None` and calling `_is_lief_mocked()`.
    *   Test `ImportError` inside `_is_lief_mocked()` by patching `from unittest.mock import MagicMock, Mock` to raise `ImportError`.
    *   Test `_is_lief_mocked()` with a real, non-mocked object to verify the `False` return path (line 97).

#### B. Process-Pool Worker & Non-Mocked Path (Lines 102-123, 158-167)
*   **Code Segment**: `_run_lief_game_context_worker()` and the `ProcessPoolExecutor` block inside `_check_game_context()`.
*   **Gap Description**: The existing tests always mock `lief` such that `_is_lief_mocked()` returns `True`. This causes `_check_game_context` to run the mock parsing logic in the main process, completely bypassing the `ProcessPoolExecutor` path and the actual worker function `_run_lief_game_context_worker`.
*   **Testing Strategy**:
    *   Write a unit test that directly invokes `_run_lief_game_context_worker` with a fake file path, mocking `lief.parse` to return either `None`, a valid binary mock, or raise an exception.
    *   Test `_check_game_context` with a mock `lief` configured to look like a real (non-mock) class (e.g. changing its class name or removing mock markers) so that it enters the `else` branch, executes via the `ProcessPoolExecutor`, and handles worker timeouts or exceptions (lines 166-167).

#### C. LIEF Signatures, Sections, and Trusted Publishers (Lines 149-152, 155-157, 207-210, 214-216)
*   **Code Segment**:
    ```python
    149:                     if hasattr(binary, "signatures") and binary.signatures:
    150:                         for sig in binary.signatures:
    151:                             if hasattr(sig, "signers"):
    ...
    207:         issuer_lower = issuer.lower()
    208:         if any(t in issuer_lower for t in trusted):
    ```
*   **Gap Description**: Currently, the mocked `binary` does not supply signatures or game-related sections (like Unity `.ress` or `il2cpp`), leaving the signature verification, score aggregation, and game section checks unexecuted. The exception block at 156-157 is also not hit.
*   **Testing Strategy**:
    *   Provide a mock binary return value from `lief.parse` that contains a list of signatures with signers (e.g. issuer `"Electronic Arts"`) and sections containing `"ress"`.
    *   Verify that `context["score"]` increases correctly (trusted publisher +50, game section +10), and that the game client status becomes `True` (score >= 20).
    *   Cause `lief.parse` to raise an exception inside the mocked block to trigger the `except Exception:` handler at line 156.

---

### 2. Caching and Direct Execution (Lines 252-257, 280-281)

*   **Code Segment**: `_run_r2_cmd_cached()` and the caching branch in `_run_r2_cmd()`.
*   **Gap Description**: The tests mock `_run_r2_cmd` globally to return static function listings or disassembly. Consequently, the actual implementation of `_run_r2_cmd` is never executed with `use_cache=True`, leaving the cache wrapper and the `alru_cache` decorators untested.
*   **Testing Strategy**:
    *   Call `_run_r2_cmd` with `use_cache=True` and mock the underlying helper `execute_subprocess_async`.
    *   Assert that the first call invokes `execute_subprocess_async`.
    *   Assert that a second identical call returns the cached output immediately without invoking `execute_subprocess_async` again.
    *   Test cache key generation via `_get_file_cache_key` with modified file timestamps to verify cache invalidation.

---

### 3. Disassembly & Heuristic Logic (Lines 327, 373-376, 591, 604-608, 615, 672, 702, 712, 731-732, 734-735, 767-772)

#### A. Emulation Info Logging (Line 327)
*   **Code Segment**: `if ctx: await ctx.info(...)`
*   **Gap Description**: Emulation phase is tested, but `ctx` is passed as `None`, leaving the progress/info logging unexecuted.
*   **Testing Strategy**: Pass an `AsyncMock` context object and assert `ctx.info.assert_called_with(...)` is executed.

#### B. Function List Verification (Lines 373-376)
*   **Code Segment**: `if not isinstance(functions, list):`
*   **Gap Description**: If JSON parsing fails, `_extract_json_safely` returns `None`. However, if JSON parses into a dictionary instead of a list, it skips the `None` check but fails the list check. This branch is currently untested.
*   **Testing Strategy**: Mock radare2 output to return a JSON object (e.g. `'{"error": "not a list"}'`). Verify that it logs an error and returns `failure("PARSE_ERROR", ...)`.

#### C. Entropy and Parse Edge Cases (Lines 591, 604-608, 712)
*   **Code Segment**:
    ```python
    590:         if value <= 0:
    591:             return 0.0
    ```
    and `_extract_hex_value` exception handling.
*   **Gap Description**:
    *   `_calculate_entropy_score` is a nested helper. It is only called when a value is not "simple". But any value `<= 0` (like `0` or negative numbers) is filtered out beforehand by `_is_simple_value(value)` (which returns `True` for `0 <= value <= 100`). Thus, the `value <= 0` check inside `_calculate_entropy_score` is dead code under normal execution.
    *   `_extract_hex_value` parses decimal values or throws `ValueError` for bad hex (e.g., `0xinvalid`).
*   **Testing Strategy**:
    *   To cover line 591: Mock `_is_simple_value` to return `False` during a test. Pass a disassembly operand of `cmp eax, 0x00000000` (length >= 10, value evaluates to `0`). With `_is_simple_value` returning `False`, it will call `_calculate_entropy_score(0)` and execute line 591.
    *   To cover lines 604-608: Provide a disassembly line containing a decimal comparison like `cmp eax, 1234567` (to test `isdigit()`) and an invalid hex like `cmp eax, 0xG` (to trigger the `ValueError` exception handler).

#### D. Batch Processing Edge Cases & The Alignment Bug (Lines 615, 672)
*   **Code Segment**: `_verify_reachability_with_esil` and `_identify_conditional_paths` zip loop.
*   **Critical Findings (The Alignment Bug)**:
    In `_identify_conditional_paths`:
    ```python
    666:         for func in batch:
    667:             addr = func.get("offset")
    668:             if addr:
    669:                 cmds.append(f"pdfj @ {addr}")
    ...
    675:         batch_cmd = "; ".join(cmds)
    ...
    682:             for func, json_str in zip(batch, json_outputs, strict=False):
    ```
    If any function in the batch lacks an `offset` (e.g. `None`), it is *not* appended to `cmds`. Thus, `json_outputs` will contain fewer items than `batch`. Because `strict=False` is used, `zip` will align the functions sequentially.
    **Example**: If Function 0 has no offset, and Function 1 has offset `0x1000`, the disassembly of Function 1 will be zipped and evaluated as if it belongs to Function 0!

    When this misalignment occurs, `func_start = func.get("offset")` will return `None` (for Function 0), but the disassembly of Function 1 contains a suspicious instruction. This triggers the ESIL reachability verification:
    ```python
    749:                                         verification = await _verify_reachability_with_esil(
    750:                                             func_start, target_offset
    751:                                         )
    ```
    where `func_start` is `None`. This is how line 615 (`if not start_addr: return "unconfirmed (no start address)"`) gets hit!
*   **Testing Strategy**:
    *   To cover line 615 and test the misalignment edge case: Pass a batch of functions where the first function is missing its `"offset"` field, and the second function is a valid function with a suspicious check (e.g. `cmp eax, 0xdeadbeef`). Assert that the tool handles the misalignment/missing offset without crashing and returns `"unconfirmed (no start address)"` for the reachability status.
    *   To cover line 672 (`if not cmds: continue`): Pass a batch of functions where *none* of them have offsets. Assert the batch loop continues cleanly.

#### E. Sequence triggers & Sliding Window (Lines 702, 731-732, 734-735)
*   **Code Segment**:
    ```python
    701:                                     if len(recent_api_calls) > 5:
    702:                                         recent_api_calls.pop(0)
    ...
    730:                                 elif any(api in TIME_APIS for api in recent_api_calls):
    ...
    733:                                 elif any(api in ENV_APIS for api in recent_api_calls):
    ```
*   **Gap Description**:
    *   The sliding window size check is never triggered because the tests do not contain more than 5 calls to APIs.
    *   The Time/Env sequence checks (lines 731-732, 734-735) are skipped because the test uses `0xdeadbeef`, which matches `KNOWN_MAGIC_VALUES` first and enters the high-confidence `if` block, skipping the medium-confidence `elif` blocks.
*   **Testing Strategy**:
    *   Provide a mock disassembly with 6 consecutive API calls (e.g. `call getenv`, `call time`, etc.) followed by a `cmp` instruction. Verify the window size is kept to 5.
    *   Provide a mock disassembly with a Time API call followed by `cmp eax, 0x12345678` (non-magic, high-entropy) to hit the Time sequence pattern.
    *   Provide a mock disassembly with an Env API call (e.g., `getenv`) followed by `cmp eax, 0x12345678` to hit the Environment sequence pattern.

#### F. Batch Exceptions (Lines 767-772)
*   **Code Segment**: `except json.JSONDecodeError` and outer `except Exception` in batch processing.
*   **Testing Strategy**:
    *   Mock `_run_r2_cmd` to return invalid JSON string for a batch (triggers `JSONDecodeError`).
    *   Mock `_run_r2_cmd` to raise `RuntimeError` during batch command execution (triggers general `Exception`).

---

### 4. ESIL Reachability & Emulation Exceptions (Lines 648-653)

*   **Code Segment**: Exception handlers inside `_verify_reachability_with_esil()`.
*   **Gap Description**: The execution path where PC register parsing fails, or an unexpected error occurs during radare2 ESIL simulation, is not covered.
*   **Testing Strategy**:
    *   Mock `_run_r2_cmd` to return `"invalid_pc_hex"` when queried for `"aer PC"`. Assert it returns `"unconfirmed (register parse error)"` (line 649).
    *   Mock `_run_r2_cmd` to raise a `RuntimeError` during the ESIL command sequence. Assert it returns `"unconfirmed (error: RuntimeError...)"` (line 652).

---

## Actionable Test Cases to Implement

Below is the concrete list of test cases recommended to achieve ~100% coverage:

| Test Case Name | Objective | Mock Setup / Input | Expected Result |
| :--- | :--- | :--- | :--- |
| `test_lief_import_failure` | Cover lines 20-21, 81 | Patch `lief` to `None` in module | `_is_lief_mocked()` returns `False` |
| `test_is_lief_mocked_real_lief` | Cover lines 91-97 | Pass a mock `lief` object that mimics a real module (lacks "Mock" in class name) | `_is_lief_mocked()` returns `False` |
| `test_is_lief_mocked_missing_parse` | Cover lines 92-94 | Mock `lief` object without `parse` attribute | `_is_lief_mocked()` returns `False` |
| `test_lief_worker_success` | Cover lines 102-123 | Call `_run_lief_game_context_worker` with dummy path; mock LIEF parsing | Return dict containing libraries, signatures, sections |
| `test_lief_worker_exception` | Cover line 121-122 | Call `_run_lief_game_context_worker` and raise exception in `lief.parse` | Catches error, returns empty lists |
| `test_check_game_context_unmocked_path` | Cover lines 158-167 | Set up a real-looking class representation for `lief` to invoke `ProcessPoolExecutor` | Executes worker via pool, returns context |
| `test_check_game_context_trusted_publisher` | Cover lines 207-210 | Mock binary signatures list with issuer `"Ubisoft"` | `context["score"]` increases by 50, `is_game = True` |
| `test_check_game_context_game_sections` | Cover lines 214-216 | Mock binary sections list with `"il2cpp_metadata"` | `context["score"]` increases by 10 |
| `test_run_r2_cmd_caching_behavior` | Cover lines 252-257, 280-281 | Mock `execute_subprocess_async`. Call `_run_r2_cmd` twice | Second call does not invoke process; returns cached value |
| `test_dormant_detector_emulation_context` | Cover line 327 | Call `dormant_detector` with focus function and mock `ctx` | `ctx.info` is called with emulation details |
| `test_dormant_detector_dict_function_list` | Cover lines 373-376 | Mock radare2 to return a JSON dictionary `'{"status": "error"}'` | Returns failure `PARSE_ERROR` |
| `test_entropy_zero_value` | Cover line 591 | Mock `_is_simple_value` -> `False`. Disasm `cmp eax, 0x00000000` | Hits value <= 0 check; returns 0.0 entropy |
| `test_extract_hex_value_decimal` | Cover line 604-605 | Disasm `cmp eax, 999999` | Correctly parses decimal value |
| `test_extract_hex_value_exception` | Cover line 606-608 | Disasm `cmp eax, 0xinvalid` | Returns `None` gracefully |
| `test_esil_unconfirmed_no_start` | Cover line 615 (Alignment Bug) | Batch with Func 0 (`offset = None`) and Func 1 (suspicious logic) | Aligns disassembly to Func 0; returns `"unconfirmed (no start address)"` |
| `test_esil_register_parse_error` | Cover line 648-649 | Mock `"aer PC"` output to return `"garbage"` | Returns `"unconfirmed (register parse error)"` |
| `test_esil_general_exception` | Cover line 651-652 | Mock `_run_r2_cmd` to throw `RuntimeError` during ESIL steps | Returns `"unconfirmed (error: ...)"` |
| `test_progress_reporting` | Cover line 660 | Pass mock `ctx` to `_identify_conditional_paths` | `ctx.report_progress` is called during batch |
| `test_batch_no_cmds` | Cover line 672 | Pass functions all missing `offset` field | Skips execution safely |
| `test_sliding_window_api_calls` | Cover line 702 | Mock disasm with 6 API calls followed by cmp | Truncates recent calls list size to 5 |
| `test_time_sequence_trigger` | Cover lines 731-732 | Disasm `call time` followed by `cmp eax, 0x12345678` | Returns `"medium"` confidence trigger |
| `test_env_sequence_trigger` | Cover lines 733-735 | Disasm `call getenv` followed by `cmp eax, 0x12345678` | Returns `"medium"` confidence trigger |
| `test_batch_json_decode_error` | Cover lines 767-769 | Mock `_run_r2_cmd` to return invalid JSON list format | Handles error, continues execution |
| `test_batch_general_exception` | Cover lines 770-772 | Mock `_run_r2_cmd` to raise `RuntimeError` during batch execution | Handles error, continues execution |
