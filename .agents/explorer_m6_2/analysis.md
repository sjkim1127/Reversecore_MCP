# Analysis: `patch_explainer.py` Coverage Expansion

## 1. Branch and Logic Split Analysis

Within `reversecore_mcp/tools/common/patch_explainer.py`, there are several critical logic branches and execution paths:

### 1.1 `explain_patch`
- **Branch 1: FastMCP Context Logging (`ctx` parameter)**
  - Lines 54-55: `if ctx: await ctx.info(...)`
  - Lines 58-59: `if ctx: await ctx.info(...)`
  - Lines 125-126: `if ctx: await ctx.info(...)`
  - *Current Status*: Not tested; `ctx` is always passed as `None` or omitted.
- **Branch 2: Binary Diff Failure (`diff_result.status != "success"`)**
  - Lines 63-67: Returns `failure("DIFF_FAILED", ...)`
  - *Current Status*: Tested in `test_diff_fails`.
- **Branch 3: Empty Changes (`not changes`)**
  - Lines 70-76: Returns `success({"summary": "No significant code changes detected.", "changes": []})`
  - *Current Status*: Tested in `test_no_changes`.
- **Branch 4: Target Function Resolution**
  - **Sub-branch 4a: Specific `function_name` provided** (Lines 104-105)
    - Directly appends `function_name` to `target_functions`.
  - **Sub-branch 4b: No `function_name` provided (Heuristic Mode)** (Lines 106-117)
    - Loops over `changes` and finds up to 3 unique `address` values.
    - Inside loop: `addr = change.get("address")`
    - Inside loop: `if addr and addr not in seen:`
    - Inside loop: `if len(target_functions) >= 3: break`
  - *Current Status*: Not fully tested. The "success" test is bypassed because of the incorrect mock structure (missing `"changes"` field in data).
- **Branch 5: No Changed Functions Identified (`not target_functions`)**
  - Lines 119-120: Returns `success({"summary": "No changed functions identified to analyze."})`
  - *Current Status*: Not tested.
- **Branch 6: Decompilation Failure (`not code_a or not code_b`)**
  - Lines 133-138 (Decompile A) and Lines 141-146 (Decompile B) check if decompile output is success and a dict with `"pseudo_c"`.
  - Lines 148-152: `if not code_a or not code_b:` -> Appends `{"function": func, "error": "Failed to decompile..."}` and continues.
  - *Current Status*: Not tested.

### 1.2 `_generate_explanation`
- **Branch 1: Added Security Check (`if_count_b > if_count_a`)**
  - Lines 187-191: Appends `🛡️ **Added Security Check**` to details, sets summary to `Security checks were added.`
  - *Current Status*: Tested in `test_security_check_added`.
- **Branch 2: Unsafe API Replacements**
  - Lines 195-200: Checks for replacements: `strcpy -> strncpy`, `sprintf -> snprintf`, `gets -> fgets`, `memcpy -> memcpy_s`.
  - Lines 205-208: `for old, new, msg in replacements:` -> `if old in code_a_str and new in code_b_str:` -> Appends `🔄 **API Hardening**` to details, sets summary to `Unsafe APIs were replaced.`
  - *Current Status*: Not tested.
- **Branch 3: Integer Overflow Check (`"MAX" in code_b_str and "MAX" not in code_a_str`)**
  - Lines 212-216: Appends `🔢 **Integer Overflow Check**` to details.
  - *Current Status*: Not tested.
- **Branch 4: Logic Removal (`len(lines_b) < len(lines_a) * 0.8`)**
  - Lines 218-221: Appends `✂️ **Logic Removal**` to details.
  - *Current Status*: Not tested.
- **Branch 5: Fallback explanation (`not explanation["details"]`)**
  - Lines 223-224: Appends `ℹ️ Logic modified without obvious security patterns.`
  - *Current Status*: Tested in `test_different_code`.

### 1.3 `_generate_diff_snippet`
- **Branch 1: Line Limitation (`list(diff)[:50]`)**
  - Line 239: Limits the returned diff output to at most 50 lines.
  - *Current Status*: Not tested with large diffs (only identical or short differences).

---

## 2. Mocking Plan for Untested Branches

To cover all branches of `explain_patch`, we must mock both `diff_binaries` and `r2_decompile` under various conditions:

### 2.1 Mocking `diff_binaries`
We mock the async function `diff_binaries` using `unittest.mock.AsyncMock`. Depending on the test case, it should return different `ToolResult` variants (using `success` or `failure` helper functions from `reversecore_mcp.core.result`):

1. **Failure Case:**
   ```python
   mock_diff_result = failure("DIFF_FAILED", "binary diff failed")
   ```
2. **Empty Changes Case:**
   ```python
   mock_diff_result = success({"changes": []})
   ```
3. **Changes with No Valid Address Case:**
   ```python
   mock_diff_result = success({"changes": [{"type": "code_change"}]})
   ```
4. **Heuristic Address Matching Case (no function name provided):**
   ```python
   mock_diff_result = success({
       "changes": [
           {"address": "0x1000", "type": "code_change"},
           {"address": "0x2000", "type": "code_change"},
           {"address": "0x1000", "type": "code_change"}, # duplicate
           {"address": "0x3000", "type": "code_change"},
           {"address": "0x4000", "type": "code_change"}, # 4th unique address (ignored because cap = 3)
       ]
   })
   ```

### 2.2 Mocking `r2_decompile`
We mock `r2_decompile` using `unittest.mock.AsyncMock`. Since it is called twice per function (for original binary `path_a` and modified binary `path_b`), we can use the `side_effect` or customize the return value:

1. **Success Case (returning pseudo-C):**
   ```python
   mock_decompile_result = success({"pseudo_c": "int main() { ... }"})
   ```
2. **Failure Case (status is error):**
   ```python
   mock_decompile_result = failure("DECOMPILE_ERROR", "r2ghidra failed")
   ```
3. **Mangled Data Case (not a dict or missing pseudo_c):**
   ```python
   mock_decompile_result = success("mangled_string_instead_of_dict")
   ```

---

## 3. Assertion Design for Heuristics inside `_generate_explanation`

To thoroughly verify each heuristic within `_generate_explanation`, we need dedicated unit tests with targeted inputs and assertions:

| Heuristic / Pattern | Input Code A | Input Code B | Expected Assertions |
| --- | --- | --- | --- |
| **Added Security Check** | `call_foo();` | `if (x > 0) {\n  call_foo();\n}` | `summary` contains "Security checks were added"<br>`details` has "Added Security Check" |
| **API: strcpy -> strncpy** | `strcpy(d, s);` | `strncpy(d, s, 10);` | `summary` contains "Unsafe APIs were replaced"<br>`details` has "strcpy -> strncpy" |
| **API: sprintf -> snprintf** | `sprintf(b, "%d", v);` | `snprintf(b, 10, "%d", v);` | `summary` contains "Unsafe APIs were replaced"<br>`details` has "sprintf -> snprintf" |
| **API: gets -> fgets** | `gets(b);` | `fgets(b, 10, stdin);` | `summary` contains "Unsafe APIs were replaced"<br>`details` has "gets -> fgets" |
| **API: memcpy -> memcpy_s** | `memcpy(d, s, l);` | `memcpy_s(d, sz, s, l);` | `summary` contains "Unsafe APIs were replaced"<br>`details` has "memcpy -> memcpy_s" |
| **Integer Overflow (MAX)** | `int x = a + b;` | `if (a > MAX - b) return;\nint x = a + b;` | `details` has "Integer Overflow Check" |
| **Logic Removal** | `line1;\nline2;\nline3;\nline4;\nline5;\nline6;\nline7;\nline8;\nline9;\nline10;` | `line1;\nline2;\nline3;\nline4;\nline5;\nline6;\nline7;` | `details` has "Logic Removal" |
| **Multiple Combined** | `strcpy(d, s);` | `if (x > MAX) return;\nstrncpy(d, s, 10);` | Both "API Hardening" and "Integer Overflow Check" details present.<br>`summary` is "Unsafe APIs were replaced." |

---

## 4. Proposed Test Code

Below is the proposed test code structure to be added to `tests/unit/tools/common/test_patch_explainer.py` to achieve 100% code coverage.

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from reversecore_mcp.core.result import success, failure

# --- Existing imports ---
from reversecore_mcp.tools.common.patch_explainer import (
    explain_patch,
    _generate_explanation,
    _generate_diff_snippet
)

class TestExplainPatchExtended:
    """Extended coverage tests for explain_patch."""

    @pytest.mark.asyncio
    async def test_explain_patch_with_context(self, tmp_path):
        # Setup temp files
        file_a = tmp_path / "a.txt"
        file_a.write_text("code A")
        file_b = tmp_path / "b.txt"
        file_b.write_text("code B")

        # Mock FastMCP Context
        mock_ctx = AsyncMock()

        # Mock diff_binaries & r2_decompile
        mock_diff = success({"changes": [{"address": "0x1000", "type": "code_change"}]})
        mock_dec = success({"pseudo_c": "int main() { return 0; }"})

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a):
            with patch("reversecore_mcp.tools.common.patch_explainer.diff_binaries", new_callable=AsyncMock, return_value=mock_diff):
                with patch("reversecore_mcp.tools.common.patch_explainer.r2_decompile", new_callable=AsyncMock, return_value=mock_dec):
                    result = await explain_patch(str(file_a), str(file_b), ctx=mock_ctx)

        # Assert context logging was called
        mock_ctx.info.assert_any_call("🔍 Analyzing patch: a.txt -> a.txt")
        mock_ctx.info.assert_any_call("📊 Diffing binaries to find changed functions...")
        mock_ctx.info.assert_any_call("🧠 Analyzing function: 0x1000...")
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_explain_patch_no_changed_functions(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        # Mock diff with changes but no addresses
        mock_diff = success({"changes": [{"type": "code_change_no_address"}]})

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a):
            with patch("reversecore_mcp.tools.common.patch_explainer.diff_binaries", new_callable=AsyncMock, return_value=mock_diff):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        assert result.data["summary"] == "No changed functions identified to analyze."

    @pytest.mark.asyncio
    async def test_explain_patch_heuristic_limit_and_duplicates(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        # Mock diff with duplicates and more than 3 unique addresses
        mock_diff = success({
            "changes": [
                {"address": "0x1000"},
                {"address": "0x2000"},
                {"address": "0x1000"}, # duplicate
                {"address": "0x3000"},
                {"address": "0x4000"}, # 4th unique (should be capped/ignored)
            ]
        })

        mock_dec = success({"pseudo_c": "int func() { return 0; }"})

        # We want to track how many times r2_decompile was called
        mock_decompile_spy = AsyncMock(return_value=mock_dec)

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a):
            with patch("reversecore_mcp.tools.common.patch_explainer.diff_binaries", new_callable=AsyncMock, return_value=mock_diff):
                with patch("reversecore_mcp.tools.common.patch_explainer.r2_decompile", mock_decompile_spy):
                    result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        # 3 target functions, each decompiled twice (once for A, once for B) = 6 calls
        assert mock_decompile_spy.call_count == 6
        # Assert the target addresses were exactly 0x1000, 0x2000, 0x3000
        called_addresses = {call.args[1] for call in mock_decompile_spy.call_args_list}
        assert called_addresses == {"0x1000", "0x2000", "0x3000"}

    @pytest.mark.asyncio
    async def test_explain_patch_decompile_failure(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        mock_diff = success({"changes": [{"address": "main"}]})

        # Mock decompile A returning success, decompile B returning failure
        mock_dec_error = failure("DECOMPILE_ERROR", "failed")

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a):
            with patch("reversecore_mcp.tools.common.patch_explainer.diff_binaries", new_callable=AsyncMock, return_value=mock_diff):
                with patch("reversecore_mcp.tools.common.patch_explainer.r2_decompile", new_callable=AsyncMock, return_value=mock_dec_error):
                    result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        explanation = result.data["explanations"][0]
        assert explanation["function"] == "main"
        assert "Failed to decompile one or both versions." in explanation["error"]


class TestGenerateExplanationHeuristics:
    """Dedicated unit tests for _generate_explanation heuristics."""

    def test_heuristic_strcpy_to_strncpy(self):
        code_a = "void f() { strcpy(dest, src); }"
        code_b = "void f() { strncpy(dest, src, 10); }"
        res = _generate_explanation(code_a, code_b)
        assert res["summary"] == "Unsafe APIs were replaced."
        assert any("strcpy" in d and "strncpy" in d for d in res["details"])

    def test_heuristic_sprintf_to_snprintf(self):
        code_a = "void f() { sprintf(dest, \"%s\", src); }"
        code_b = "void f() { snprintf(dest, 10, \"%s\", src); }"
        res = _generate_explanation(code_a, code_b)
        assert res["summary"] == "Unsafe APIs were replaced."
        assert any("sprintf" in d and "snprintf" in d for d in res["details"])

    def test_heuristic_gets_to_fgets(self):
        code_a = "void f() { gets(buf); }"
        code_b = "void f() { fgets(buf, 10, stdin); }"
        res = _generate_explanation(code_a, code_b)
        assert res["summary"] == "Unsafe APIs were replaced."
        assert any("gets" in d and "fgets" in d for d in res["details"])

    def test_heuristic_memcpy_to_memcpy_s(self):
        code_a = "void f() { memcpy(dest, src, n); }"
        code_b = "void f() { memcpy_s(dest, sz, src, n); }"
        res = _generate_explanation(code_a, code_b)
        assert res["summary"] == "Unsafe APIs were replaced."
        assert any("memcpy" in d and "memcpy_s" in d for d in res["details"])

    def test_heuristic_integer_overflow(self):
        code_a = "void f(int x) { buf[x] = 0; }"
        code_b = "void f(int x) { if (x > MAX_VAL) return; buf[x] = 0; }"
        res = _generate_explanation(code_a, code_b)
        assert any("Integer Overflow Check" in d for d in res["details"])

    def test_heuristic_logic_removal(self):
        code_a = "\n".join([f"line_{i};" for i in range(10)])
        code_b = "line_0; line_1;"  # substantially less lines (< 80%)
        res = _generate_explanation(code_a, code_b)
        assert any("Logic Removal" in d for d in res["details"])


class TestGenerateDiffSnippetExtended:
    """Extended coverage tests for _generate_diff_snippet."""

    def test_diff_snippet_limiting_to_50_lines(self):
        # Generate 60 lines of differing content to hit the list(diff)[:50] constraint
        code_a = "\n".join([f"lineA_{i}" for i in range(60)])
        code_b = "\n".join([f"lineB_{i}" for i in range(60)])
        res = _generate_diff_snippet(code_a, code_b)

        # Verify that total lines in the diff output is capped
        assert len(res.splitlines()) <= 50
```
