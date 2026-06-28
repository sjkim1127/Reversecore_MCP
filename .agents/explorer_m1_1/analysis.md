# Code Coverage Analysis & Mocking Strategies Report

## Executive Summary
This report analyzes the test coverage of the `reversecore_mcp/tools/` directory, focusing on five target modules. It identifies coverage gaps, explains why they occur (including a crucial mock-schema mismatch in `patch_explainer.py`), and provides detailed mocking strategies to test all uncovered paths hermetically without requiring external CLI tools or network access.

---

## 1. Baseline Coverage Metrics for `reversecore_mcp/tools/`
The table below shows the baseline coverage of all files under `reversecore_mcp/tools/` as of the current test suite run.

| Target Module | Statements | Missed | Coverage | Uncovered Lines |
| :--- | :---: | :---: | :---: | :--- |
| **`tools/analysis/capa_tools.py`** | **66** | **43** | **35%** | **21, 56-164** |
| **`tools/analysis/lief_tools.py`** | **196** | **125** | **36%** | **33-114, 135, 146-154, 161, 167, 174, 187, 191-193, 197-203, 209-214, 218-223, 253, 263, 273-276, 302-320, 324, 340-369** |
| **`tools/malware/adaptive_vaccine.py`** | **400** | **230** | **42%** | **27-28, 133, 217, 236, 250-255, 262-310, 321-329, 350-357, 366-380, 386-436, 546-622, 639-775** |
| **`tools/common/memory_tools.py`** | **115** | **56** | **51%** | **65-66, 197-210, 232-243, 276-297, 326-341, 373-383, 411-426, 453-467, 491-499** |
| **`tools/common/patch_explainer.py`** | **88** | **37** | **58%** | **55, 59, 79-164, 207-208, 213, 219** |
| `tools/analysis/crash_triage.py` | 135 | 115 | 15% | 48-119, 124-180, 185-250 |
| `tools/analysis/die_tools.py` | 117 | 117 | 0% | 9-271 |
| `tools/analysis/diff_tools.py` | 219 | 181 | 17% | 55-66, 135-259, 297-388, 475-635, 665-714 |
| `tools/analysis/emulation_tools.py` | 148 | 129 | 13% | 24-79, 120-296 |
| `tools/analysis/fuzz_tools.py` | 23 | 23 | 0% | 3-130 |
| `tools/analysis/signature_tools.py` | 170 | 130 | 24% | 57-64, 80, 97, 142-245, 283-394, 468-588 |
| `tools/analysis/source_auditor.py` | 68 | 44 | 35% | 58-135, 153 |
| `tools/analysis/static_analysis.py` | 176 | 136 | 23% | 65-161, 183-190, 239-351, 371-375, 404-431, 458-499 |
| `tools/analysis/symbolic_analysis.py` | 33 | 25 | 24% | 43-87 |
| `tools/common/assembler.py` | 197 | 197 | 0% | 3-365 |
| `tools/common/file_operations.py` | 149 | 122 | 18% | 26-44, 84-194, 214-229, 263-373 |
| `tools/common/server_tools.py` | 49 | 49 | 0% | 5-118 |
| `tools/forensics/artifact.py` | 187 | 156 | 17% | 48, 89-111, 150-200, 244-340, 379-444, 487-587 |
| `tools/forensics/disk.py` | 139 | 100 | 28% | 37, 42-50, 70-107, 146-200, 242-279, 317-358, 396, 427-446 |
| `tools/forensics/memory.py` | 186 | 147 | 21% | 57-95, 102-103, 126-153, 201-261, 286-319, 345-383, 416-456, 496-551 |
| `tools/forensics/network.py` | 238 | 204 | 14% | 58-63, 91-168, 204-248, 285-362, 405-486, 534-589 |
| `tools/malware/dormant_detector.py` | 366 | 321 | 12% | 20-21, 50-59, 66-73, 80-97, 102-123, 134-221, 226, 234-239, 252-257, 275-286, 322-453, 467-474, 490-511, 522-524, 537-778, 794-853 |
| `tools/malware/ioc_tools.py` | 159 | 133 | 16% | 28-43, 60-83, 142-310 |
| `tools/malware/vulnerability_hunter.py` | 254 | 224 | 12% | 346-354, 359-361, 408-794, 817-829, 834-856, 863-895, 900-907 |
| `tools/malware/yara_tools.py` | 111 | 84 | 24% | 56-105, 125-231 |
| `tools/patch_explainer.py` (legacy) | 3 | 3 | 0% | 8-15 |
| `tools/radare2/r2_analysis.py` | 351 | 297 | 15% | 68-144, 296-309, 319-357, 371-391, 438-600, 624-688, 705-769, 794-863, 921-1048 |
| `tools/radare2/r2_db.py` | 163 | 163 | 0% | 21-417 |
| `tools/radare2/r2_session.py` | 175 | 135 | 23% | 22-24, 86-90, 106-117, 130-148, 163-175, 186-197, 201-224, 228-235, 239-247, 251-258, 267-270, 278-281, 285-298, 302, 313-316, 321-334, 339-352, 361-376 |
| `tools/radare2/r2ghidra_tools.py` | 163 | 127 | 22% | 44-50, 61-68, 103-137, 169-219, 251-286, 333-381, 426-485 |
| `tools/radare2/radare2_mcp_tools.py` | 479 | 444 | 7% | 67-69, 73-94, 102-153, 163-164, 173-1276, 1283-1291, 1297-1301, 1329-1381, 1395-1396 |
| `tools/report/converter.py` | 108 | 108 | 0% | 10-366 |
| `tools/report/email.py` | 45 | 27 | 40% | 27-44, 53-57, 65-83 |
| `tools/report/report_mcp_tools.py` | 92 | 65 | 29% | 28-49, 67-69, 82-84, 94-96, 121-130, 147-153, 166-168, 178-180, 195-199, 214-218, 236-243, 257-261, 295-304, 319, 324-340, 351-353 |
| `tools/report/report_tools.py` | 350 | 294 | 16% | 64-79, 92-100, 110, 125-127, 133-142, 153-161, 198, 225-255, 281-310, 314-334, 340-357, 369-377, 393-401, 410-418, 422-438, 442-461, 487-619, 633-647, 651-665, 675-692, 700, 725-734, 748-750, 758, 782-868, 881-920, 925-957, 962-966, 971-972, 976-982, 986-993, 997-1003, 1007-1022, 1051-1078, 1084 |
| `tools/report/session.py` | 94 | 51 | 46% | 29-50, 55-58, 128-129, 133-134, 138-141, 145-160, 164-167, 171-172, 176-178, 182-183, 187-194 |
| `tools/report_tools.py` (legacy) | 3 | 3 | 0% | 8-11 |

---

## 2. Deep Dive: Target Modules Analysis & Mocking Strategies

### A. `reversecore_mcp/tools/analysis/capa_tools.py` (Coverage: 35%)

#### 1. Uncovered Areas
- **Lines 20-21**: Successful importing of `capa` in `_is_capa_available()`.
- **Lines 56-164**: Almost the entirety of `run_capa`. When CAPA is not installed in the test runner environment, the check `if not _is_capa_available()` exits early with a failure. Consequently, all rule loading, binary extraction, capability finding, MITRE/MBC mapping, risk scoring, and formatting loops are skipped.

#### 2. Mocking & Test Case Strategies
To exercise the full `run_capa` workflow without installing CAPA (which compiles native Vivisect code), we can mock CAPA libraries using `sys.modules` patching and mock helper functions.

*   **Test Case 1: CAPA available & Successful Analysis**
    Mock the CAPA functions to return simulated capabilities:
    ```python
    import sys
    from unittest.mock import MagicMock, patch

    async def test_run_capa_success(self):
        mock_capa = MagicMock()
        mock_loader = MagicMock()
        mock_main = MagicMock()
        mock_rules = MagicMock()

        # Mock get_rules returning mock rule dict
        mock_rule = MagicMock()
        mock_rule.meta = {
            "namespace": "defense-evasion/anti-debugging",
            "description": "Checks for debugger",
            "scope": "function",
            "att&ck": ["T1054"],
            "mbc": ["B0001"]
        }
        mock_rules.get_rules.return_value = ({"anti_debug_rule": mock_rule}, None)

        # Mock find_capabilities returning findings
        mock_main.find_capabilities.return_value = ({"anti_debug_rule": [MagicMock()]}, None)
        mock_main.get_default_root.return_value = "/mock/rules"
        mock_main.BACKEND_VIV = "vivisect"

        with patch.dict(sys.modules, {
            "capa": mock_capa,
            "capa.loader": mock_loader,
            "capa.main": mock_main,
            "capa.rules": mock_rules
        }):
            with patch("reversecore_mcp.tools.analysis.capa_tools._is_capa_available", return_value=True):
                with patch("reversecore_mcp.tools.analysis.capa_tools.validate_file_path", return_value="/mock/bin"):
                    from reversecore_mcp.tools.analysis.capa_tools import run_capa
                    result = await run_capa("/mock/bin")
                    assert result.status == "success"
                    assert len(result.data["capabilities"]) == 1
                    assert "T1054" in result.data["mitre_attack"]
    ```

*   **Test Case 2: CAPA Rules Load Failure**
    Mock `capa.rules.get_rules` to raise an exception. Assert that the function fails gracefully returning `CAPA_RULES_LOAD_FAILED`.
*   **Test Case 3: CAPA File Load Failure**
    Mock `capa.loader.get_extractor` to raise an exception. Assert that the function fails returning `CAPA_LOAD_FILE_FAILED`.
*   **Test Case 4: General Exception Handling**
    Force `find_capabilities` to throw an unexpected exception and assert that the outer try-except catches it and returns `CAPA_ANALYSIS_FAILED`.

---

### B. `reversecore_mcp/tools/analysis/lief_tools.py` (Coverage: 36%)

#### 1. Uncovered Areas
- **Lines 33-114**: Exploit mitigations parser `_extract_mitigations(binary)` for ELF (NX, PIE, stack canary, RELRO/BIND_NOW) and PE (NX, ASLR, CFG, SafeSEH, stack cookie).
- **Lines 135, 146-154, 161, 167, 174**: PE imports and exports parsing loops in `_extract_symbols(binary)`.
- **Lines 187, 191-193, 197-203, 209-214, 218-223**: Text formatter loops in `_format_lief_output` for mitigations, sections, imports, and exports.
- **Lines 252-257, 262-268, 273-276**: File size threshold validation.
- **Lines 302-320**: Multiprocess execution exceptions (Timeout, BrokenExecutor/Segfault crash, execution failure).
- **Lines 340-369**: `_run_lief_in_process` worker logic (not covered because the process pool is mocked).

#### 2. Mocking & Test Case Strategies
Rather than parsing a real complex binary to test every single edge case, we can write unit tests calling the helper functions directly with mock `lief` structures, and mock the process executor behavior.

*   **Test Case 1: Direct Unit Testing of `_extract_mitigations` for ELF**
    ```python
    import lief
    from unittest.mock import MagicMock
    from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

    def test_extract_mitigations_elf():
        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = True
        binary.is_pie = True

        # Mock stack canary symbol
        sym = MagicMock()
        sym.name = "__stack_chk_fail"
        binary.imported_symbols = [sym]

        # Mock RELRO segment
        seg = MagicMock()
        seg.type = lief.ELF.SEGMENT_TYPES.GNU_RELRO
        binary.segments = [seg]

        # Mock BIND_NOW flag
        binary.has.return_value = True
        flags = MagicMock(spec=lief.ELF.DynamicEntryFlags)
        flags.flags = [lief.ELF.DYNAMIC_FLAGS.BIND_NOW]
        binary.get.return_value = flags

        result = _extract_mitigations(binary)
        assert result["nx"] is True
        assert result["canary"] is True
        assert result["relro"] == "Full"
    ```

*   **Test Case 2: Direct Unit Testing of `_extract_mitigations` for PE**
    Mock `lief.PE.Binary`, `optional_header`, `dll_characteristics_lists`, and `load_configuration` (SafeSEH table check and stack cookie).
*   **Test Case 3: Process Execution Timeout**
    Mock the process pool executor to raise `concurrent.futures.TimeoutError` on `future.result()` and verify return is `TIMEOUT`.
*   **Test Case 4: Process Execution Segment Fault (Crash)**
    Mock the process pool executor to raise `concurrent.futures.ProcessBrokenExecutor` to verify return is `CRASH_DETECTED`.
*   **Test Case 5: Large File Size Triggers**
    Mock the `Path.stat().st_size` returned by `validate_file_path` to verify `FILE_TOO_LARGE` (> config limit), `FILE_TOO_LARGE_FOR_LIEF` (> 500MB), and warning warnings (> 100MB).
*   **Test Case 6: Direct Testing of `_run_lief_in_process`**
    Test the worker directly in the same process to verify it handles ELF/PE parsers properly.

---

### C. `reversecore_mcp/tools/malware/adaptive_vaccine.py` (Coverage: 42%)

#### 1. Uncovered Areas
- **Lines 262-310**: Subprocess worker logic `_run_lief_vaccine_worker`.
- **Lines 321-329**: `_is_lief_mocked` detection branches.
- **Lines 350-357, 366-380, 386-436**: Native architecture detection logic in `_detect_architecture`.
- **Lines 546-622**: `_va_to_file_offset` section lookup logic for PE and ELF.
- **Lines 639-775**: The entire binary patching function `_create_binary_patch` (since it is mocked out in the only test that calls it), including capstone instruction disassembly, NOP/NOP_JUMP byte generation, backup creation, write logic, and error rollback.

#### 2. Mocking & Test Case Strategies

*   **Test Case 1: `_create_binary_patch` Successful Run (Using Mocked Capstone)**
    We mock the Capstone disassembler and test the backup and patching flow on a temporary file.
    ```python
    import pytest
    from unittest.mock import MagicMock, patch
    from pathlib import Path

    @pytest.mark.asyncio
    async def test_create_binary_patch_success(tmp_path):
        dummy_bin = tmp_path / "target.exe"
        dummy_bin.write_bytes(b"\x90" * 100) # dummy bytes

        mock_instr = MagicMock()
        mock_instr.size = 5
        mock_instr.mnemonic = "cmp"
        mock_instr.op_str = "eax, 0x1234"

        mock_cs = MagicMock()
        mock_cs.disasm.return_value = [mock_instr]

        with patch("reversecore_mcp.tools.malware.adaptive_vaccine.Cs", return_value=mock_cs):
            with patch("reversecore_mcp.tools.malware.adaptive_vaccine._va_to_file_offset", return_value=(10, ".text")):
                with patch("reversecore_mchem_vaccine._detect_architecture", return_value="x86_64"):
                    from reversecore_mcp.tools.malware.adaptive_vaccine import _create_binary_patch

                    # Dry-run
                    res_dry = _create_binary_patch(dummy_bin, {"address": "0x40100a", "instruction": "cmp eax, 0x1234"}, dry_run=True)
                    assert res_dry["applied"] is False
                    assert res_dry["bytes"] == "9090909090"

                    # Non dry-run (apply patch)
                    res_apply = _create_binary_patch(dummy_bin, {"address": "0x40100a", "instruction": "cmp eax, 0x1234"}, dry_run=False)
                    assert res_apply["applied"] is True
                    assert Path(res_apply["backup"]).exists()
    ```

*   **Test Case 2: Capstone Unavailable Error**
    Mock `Cs = None` to assert that it raises `RuntimeError` ("Capstone engine not available. Cannot perform safe patching.").
*   **Test Case 3: Patch Rollback on Exception**
    Mock writing to file (`f.write`) to throw an `IOError` when applying patch. Verify that the backup file is restored and the audit log records `FAILURE`.
*   **Test Case 4: `_va_to_file_offset` Mapping logic**
    Directly call `_va_to_file_offset` passing mock lief structures representing PE and ELF binaries, confirming they lookup VA offset ranges correctly.

---

### D. `reversecore_mcp/tools/common/memory_tools.py` (Coverage: 51%)

#### 1. Uncovered Areas
- Out of 11 tools exposed by the plugin, only 3 (`create_memory_session`, `save_memory_item`, `recall_memory_item`) have partial tests.
- The remaining 8 tools are completely untested:
  - `list_memory_sessions` (duration formatting).
  - `get_memory_session_detail` (session retrieval/metadata summary).
  - `resume_memory_session` (restores status to `in_progress` and retrieves context).
  - `complete_memory_session` (marks completed with summary).
  - `save_pattern` (behavioral fingerprinting).
  - `find_similar_patterns` (cross-session pattern comparison).
  - `get_relevant_context` (past memory lookup).
  - `update_memory_session_time` (accumulates analysis time).
- **Line 65-66**: Warning log when binary hashing fails.

#### 2. Mocking & Test Case Strategies
We can add 15 detailed unit tests directly checking these tools. The memory store layer (`get_memory_store`) is already mocked in the test fixtures. We only need to write assertions for the MCP tools themselves.

*   **Test Case 1: Duration Formatting in `list_memory_sessions`**
    Mock `store.list_sessions` to return a session with `analysis_duration_seconds = 9000` (2.5 hours) and assert that `analysis_duration_formatted` is computed as `"2h 30m"`.
*   **Test Case 2: `resume_memory_session` Behavior**
    Test calling with `session_id` vs calling with `binary_name`. Mock the store to return a session for both, verify it calls `store.update_session` with `status="in_progress"`, and returns the context.
*   **Test Case 3: `complete_memory_session` Error handling**
    Mock `store.update_session` to return `False` (session not found) and assert that it returns `"status": "error"`.
*   **Test Case 4: Binary Hashing Error Path**
    In `create_memory_session`, pass a path that throws `PermissionError` when reading bytes. Assert that the function logs a warning and creates the session without a hash, rather than crashing.

---

### E. `reversecore_mcp/tools/common/patch_explainer.py` (Coverage: 58%)

#### 1. Uncovered Areas
- **Lines 55, 59**: Log lines when Context is provided.
- **Lines 79-164**: **The entire core analysis loop of `explain_patch`!**
  *   *Reason*: The unit test uses a mock result for `diff_binaries` containing the key `"changed_functions"`, but the actual implementation checks `changes = diff_result.data.get("changes", [])`. Because `"changes"` is missing from the mock, it defaults to `[]`, triggering an early return at line 71: `return success({"summary": "No significant code changes detected.", ...})`.
- **Lines 207-208, 213, 219**: Heuristic detection logic inside `_generate_explanation` for API hardening, integer overflow check, and logic removal.

#### 2. Mocking & Test Case Strategies

*   **Test Case 1: Correct the Mock Schema and Test the Decompilation Loop**
    We must fix the mock schema in `test_success` to supply a mock `changes` array with addresses. We will also mock `r2_decompile` to return original and patched pseudocode.
    ```python
    import pytest
    from unittest.mock import AsyncMock, patch, MagicMock
    from reversecore_mcp.core.result import success

    @pytest.mark.asyncio
    async def test_explain_patch_full_loop(tmp_path):
        file_a = tmp_path / "a.exe"
        file_a.write_bytes(b"A")
        file_b = tmp_path / "b.exe"
        file_b.write_bytes(b"B")

        # Correct mock schema matching changes
        mock_diff = MagicMock()
        mock_diff.status = "success"
        mock_diff.data = {
            "changes": [
                {"address": "0x401000", "description": "Modified function"}
            ]
        }

        # Decompile mocks representing before & after
        decompile_before = success({"pseudo_c": "void vuln() { strcpy(dest, src); }"})
        decompile_after = success({"pseudo_c": "void vuln() { if(src) strncpy(dest, src, 10); }"})

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a):
            with patch("reversecore_mcp.tools.common.patch_explainer.diff_binaries", new_callable=AsyncMock, return_value=mock_diff):
                with patch("reversecore_mcp.tools.common.patch_explainer.r2_decompile", new_callable=AsyncMock) as mock_decomp:
                    mock_decomp.side_effect = [decompile_before, decompile_after]

                    from reversecore_mcp.tools.common.patch_explainer import explain_patch
                    result = await explain_patch(str(file_a), str(file_b))

                    assert result.status == "success"
                    exp = result.data["explanations"][0]
                    assert exp["function"] == "0x401000"
                    assert "Added Security Check" in str(exp["explanation"])
                    assert "API Hardening" in str(exp["explanation"])
    ```

*   **Test Case 2: Unit Testing Heuristics directly**
    Instead of calling the orchestrator function, directly test `_generate_explanation` for:
    - **API Hardening**: `strcpy` -> `strncpy`, `gets` -> `fgets`, etc.
    - **Integer Overflow**: Adding `MAX` comparison.
    - **Logic Removal**: Reducing the line count of B to < 80% of A.
*   **Test Case 3: Decompilation Failure Handling**
    Mock `r2_decompile` to return `failure` and verify that the explanations list the function with `"error": "Failed to decompile one or both versions."` without crashing.

---

## 3. General Mocking Principles for Remaining Tools

To expand test coverage to 100% of all tool files under `reversecore_mcp/tools/`, developers should adhere to the following hermetic mocking guidelines:

1.  **SQLite/Database Mocking**:
    For database-backed tools like `reversecore_mcp/tools/radare2/r2_db.py`, run tests using an in-memory SQLite database (`sqlite3.connect(":memory:")`) to avoid writing to local disk or modifying persistent data.
2.  **YARA Engine Mocking**:
    For malware detection tools like `IOC` tools and `yara_tools.py`, use the `unittest.mock.patch` decorator on the `yara` module. Stub `yara.compile()` to return a mock rules object whose `match()` method returns a pre-configured list of rule matches.
3.  **Shell Commands / Radare2 Pool Mocking**:
    Radare2 analysis tools require an active R2 session. Instead of running a real Radare2 process (which fails if Radare2 is not installed or when analyzing complex binaries), mock the `R2Pool` connection manager. Set it up to return a mock client where `cmdj()` and `cmd()` return mocked JSON results (like symbol lists, xrefs, and instruction disassembly).
4.  **Process Pool Mocking**:
    Whenever a tool spawns a subprocess via `ProcessPoolExecutor` (such as in `lief_tools.py` or `dormant_detector.py`), mock the executor's `submit` method. Directly call the target worker function in the main test thread to collect code coverage for the worker while mocking the asynchronous runner's failures (timeouts, crashes, broken executors).
