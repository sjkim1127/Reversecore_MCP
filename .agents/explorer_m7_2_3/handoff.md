# Handoff Report: dormant_detector.py Test Coverage Gap Analysis

## 1. Observation

- **Target File**: `reversecore_mcp/tools/malware/dormant_detector.py`
- **Existing Test Files**:
  - `tests/unit/tools/malware/test_dormant_detector.py`
  - `tests/unit/tools/malware/test_dormant_detector_standalone.py`
- **Command Executed**:
  `pytest tests/unit/tools/malware/test_dormant_detector.py --cov=reversecore_mcp/tools/malware/dormant_detector --cov-report=term-missing`
- **Verbatim Coverage Result**:
  ```
  reversecore_mcp/tools/malware/dormant_detector.py         366     84    77%   20-21, 81, 89-97, 102-123, 149-152, 155-167, 207-210, 214-216, 252-257, 280-281, 327, 373-376, 591, 604-608, 615, 648-653, 660, 672, 702, 712, 731-732, 734-735, 767-772
  ```
- **Code Observations**:
  - **LIEF process pool isolation**: The worker function `_run_lief_game_context_worker` (Lines 102-123) runs in a separate process via `ProcessPoolExecutor` (Line 162), bypassing the standard main-process coverage tracer.
  - **Radare2 command caching**: The caching path (`_run_r2_cmd_cached`, Lines 252-257) is never traversed since all tests call `_run_r2_cmd(..., use_cache=False)` or patch the command execution.
  - **Heuristics trigger confidence**: The test `test_identify_conditional_paths_heuristics` uses magic value `0xdeadbeef` which triggers high confidence (Line 723-728), leaving the medium confidence paths for time-based/env-based APIs (Lines 731-732, 734-735) untested.

---

## 2. Logic Chain

1. **Premise**: Code coverage tool tracks executed branches by hooking the interpreter execution path in the current python process.
2. **Inference 1**: Standard unit tests stub or mock out LIEF components or run them in subprocesses (multiprocessing). This isolates execution to subprocesses that do not run under the coverage tracer, causing Lines 102-123 and 157-167 to be marked uncovered.
3. **Inference 2**: Radare2 caching is skipped (Lines 252-257) because the `use_cache` parameter is defaults to True in production but bypassed/disabled in tests.
4. **Inference 3**: Medium-confidence heuristics (Lines 731-732, 734-735) are skipped because test cases evaluate known magic values, causing the logic to hit high confidence and exit prior conditional statements.
5. **Conclusion**: Achieving 100% test coverage requires direct worker execution, mock environment manipulation (to simulate missing LIEF and mocked LIEF exceptions), caching flow verification, and testing non-magic-value API checks.

---

## 3. Caveats

- **No Caveats**. The coverage results have been directly mapped to the source code blocks.

---

## 4. Conclusion

The coverage gaps are not due to lack of basic functionality tests, but are concentrated in subprocess execution, caching, and specific error-handling blocks. We can achieve 100% coverage by implementing the 16 proposed unit test cases in a new/updated test suite without altering production code.

---

## 5. Verification Method

To verify coverage improvement once implementation is completed, run:
```bash
pytest tests/unit/tools/malware/test_dormant_detector.py --cov=reversecore_mcp/tools/malware/dormant_detector --cov-report=term-missing
```
**Invalidation Conditions**: If any of the 84 statement lines listed in the Term-Missing output are still printed in the coverage report, the strategy is not fully successful.
