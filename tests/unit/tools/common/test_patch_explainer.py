"""Tests for reversecore_mcp.tools.common.patch_explainer."""

import json
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest


class TestGenerateExplanation:
    """Tests for _generate_explanation."""

    def test_identical_code(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation("mov eax, 1", "mov eax, 1")
        assert result["summary"] == "Code structure changed."

    def test_different_code(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation("mov eax, 1", "mov ebx, 2")
        assert "Logic modified without obvious security patterns" in str(result)

    def test_security_check_added(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation("call foo", "if (x > 0) {\n  call foo\n}")
        assert "Security checks were added" in result["summary"]

    def test_lower_bound_check_added_to_existing_condition(self):
        from reversecore_mcp.tools.common.patch_explainer import (
            _build_structured_patch_signals,
            _generate_explanation,
        )

        original = """
        if (99 < param_2) {
            return;
        }
        track->index[param_2] = ind;
        """
        patched = """
        if ((param_2 < 0) || (99 < param_2)) {
            return;
        }
        track->index[param_2] = ind;
        """

        result = _generate_explanation(original, patched)

        assert result["summary"] == "Security checks were added."
        assert any("Added Lower-Bound Check" in detail for detail in result["details"])
        signals = _build_structured_patch_signals(result, "track_set_index")
        assert signals[0]["signal_id"] == "RCMCP-PATCH-LOWER-BOUND-ADDED"
        assert signals[0]["patch_security_signal"] == "lower_bound_check_added"
        assert signals[0]["vulnerability_class"] == "out_of_bounds_access"
        assert signals[0]["function"] == "track_set_index"
        assert signals[0]["added_checks"] == ["param_2 < 0"]
        assert signals[0]["confidence"] == "high"
        assert signals[0]["verification_status"] == "patch_confirmed"

    def test_api_replacement_strcpy(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation("strcpy(dest, src);", "strncpy(dest, src, 10);")
        assert "Unsafe APIs were replaced" in result["summary"]
        assert any("strcpy" in detail and "strncpy" in detail for detail in result["details"])

    def test_api_replacement_sprintf(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation(
            "sprintf(dest, format, val);", "snprintf(dest, 10, format, val);"
        )
        assert "Unsafe APIs were replaced" in result["summary"]
        assert any("sprintf" in detail and "snprintf" in detail for detail in result["details"])

    def test_api_replacement_gets(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation("gets(buf);", "fgets(buf, 10, stdin);")
        assert "Unsafe APIs were replaced" in result["summary"]
        assert any("gets" in detail and "fgets" in detail for detail in result["details"])

    def test_api_replacement_memcpy(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation(
            "memcpy(dest, src, n);", "memcpy_s(dest, dest_size, src, n);"
        )
        assert "Unsafe APIs were replaced" in result["summary"]
        assert any("memcpy" in detail and "memcpy_s" in detail for detail in result["details"])

    def test_integer_overflow_check(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        result = _generate_explanation("int x = y + z;", "if (y > MAX - z) return; int x = y + z;")
        assert any("Integer Overflow Check" in detail for detail in result["details"])

    def test_logic_removal(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_explanation

        code_a = "\n".join([f"line{i};" for i in range(10)])
        code_b = "line1;"
        result = _generate_explanation(code_a, code_b)
        assert any("Logic Removal" in detail for detail in result["details"])


class TestGenerateDiffSnippet:
    """Tests for _generate_diff_snippet."""

    def test_identical(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_diff_snippet

        result = _generate_diff_snippet("line1\nline2", "line1\nline2")
        assert result == ""

    def test_different(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_diff_snippet

        result = _generate_diff_snippet("line1\nline2", "line1\nchanged")
        assert "changed" in result

    def test_context_lines(self):
        from reversecore_mcp.tools.common.patch_explainer import _generate_diff_snippet

        a = "\n".join([f"line{i}" for i in range(10)])
        b = "\n".join([f"line{i}" for i in range(10)])
        result = _generate_diff_snippet(a, b, context=2)
        assert result == ""


class TestExplainPatch:
    """Tests for explain_patch."""

    @pytest.mark.asyncio
    async def test_success_with_heuristics_and_ctx(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_a.write_text("dummy")
        file_b = tmp_path / "b.txt"
        file_b.write_text("dummy")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps(
            {
                "similarity": 0.85,
                "changes": [
                    {
                        "address": "0x401000",
                        "type": "code_change",
                        "description": "API change",
                    },
                    {
                        "address": "0x401080",
                        "type": "new_block",
                        "description": "added check",
                    },
                    {
                        "address": "0x401100",
                        "type": "code_change",
                        "description": "overflow check",
                    },
                    {
                        "address": "0x401200",
                        "type": "code_change",
                        "description": "logic removed",
                    },
                ],
                "total_changes": 4,
            }
        )

        async def mock_decompile_side_effect(file_path, function_address):
            is_a = "a.txt" in str(file_path)

            if function_address == "0x401000":
                # API Hardening heuristic
                code = (
                    "void func() {\n    strcpy(buf, src);\n}"
                    if is_a
                    else "void func() {\n    strncpy(buf, src, 10);\n}"
                )
            elif function_address == "0x401080":
                # Security check heuristic
                code = (
                    "void func() {\n    do_work();\n}"
                    if is_a
                    else "void func() {\n    if (x > 0) {\n        do_work();\n    }\n}"
                )
            elif function_address == "0x401100":
                # Integer overflow heuristic
                code = (
                    "void func() {\n    int res = x + y;\n}"
                    if is_a
                    else "void func() {\n    if (x > MAX - y) return;\n    int res = x + y;\n}"
                )
            elif function_address == "0x401200":
                # Logic removal heuristic
                code = "\n".join([f"line{i};" for i in range(10)]) if is_a else "line1;"
            else:
                code = ""

            from reversecore_mcp.core.result import success

            return success(
                {
                    "function": function_address,
                    "pseudo_c": code,
                    "decompiler": "r2ghidra",
                }
            )

        mock_ctx = AsyncMock()

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=lambda p: tmp_path / p,
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                    side_effect=mock_decompile_side_effect,
                ):
                    result = await explain_patch(str(file_a), str(file_b), ctx=mock_ctx)

        assert result.status == "success"
        data = result.data
        assert "Analyzed 3 function(s)." in data["summary"]  # Heuristic limit top 3
        exps = data["explanations"]
        assert len(exps) == 3

        # Verify target functions are the first 3 (limit top 3)
        funcs = [e["function"] for e in exps]
        assert funcs == ["0x401000", "0x401080", "0x401100"]

        # Verify 0x401000 got API hardening
        exp_0 = exps[0]["explanation"]
        assert exp_0["summary"] == "Unsafe APIs were replaced."
        assert any("API Hardening" in d for d in exp_0["details"])

        # Verify 0x401080 got security check
        exp_1 = exps[1]["explanation"]
        assert exp_1["summary"] == "Security checks were added."
        assert any("Security Check" in d for d in exp_1["details"])

        # Verify 0x401100 got integer overflow check
        exp_2 = exps[2]["explanation"]
        assert any("Integer Overflow Check" in d for d in exp_2["details"])

        # Verify mock_ctx was notified
        mock_ctx.info.assert_called()

    @pytest.mark.asyncio
    async def test_explain_patch_specific_function(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {
            "similarity": 0.9,
            "changes": [
                {
                    "address": "0x401000",
                    "type": "code_change",
                    "description": "API change",
                }
            ],
            "total_changes": 1,
        }

        from reversecore_mcp.core.result import success

        mock_decompile_res = success(
            {
                "function": "main",
                "pseudo_c": "int main() { return 0; }",
                "decompiler": "r2ghidra",
            }
        )

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=lambda p: tmp_path / p,
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ) as mock_diff:
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                    return_value=mock_decompile_res,
                ) as mock_decompile:
                    result = await explain_patch(str(file_a), str(file_b), function_name="main")

        assert result.status == "success"
        assert mock_diff.call_args[1]["function_name"] == "main"
        # Assert decompiled main function, not 0x401000
        mock_decompile.assert_has_calls([call(str(file_a), "main"), call(str(file_b), "main")])

    @pytest.mark.asyncio
    async def test_diff_fails(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        mock_diff_result = MagicMock()
        mock_diff_result.status = "error"
        mock_diff_result.message = "diff failed"

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=lambda p: tmp_path / p,
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_no_changes_deserialized(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps({"changes": []})

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=lambda p: tmp_path / p,
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_no_changes_none(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = None

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=lambda p: tmp_path / p,
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_no_functions_found(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        # Changes list has no address key
        mock_diff_result.data = json.dumps(
            {"changes": [{"type": "summary", "description": "Binary comparison completed."}]}
        )

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=lambda p: tmp_path / p,
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        assert result.data["summary"] == "No changed functions identified to analyze."

    @pytest.mark.asyncio
    async def test_decompilation_failure(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps(
            {
                "changes": [
                    {"address": "0x401000", "type": "code_change"},
                    {"address": "0x401080", "type": "new_block"},
                ]
            }
        )

        from reversecore_mcp.core.result import failure, success

        async def mock_decompile_side_effect(file_path, function_address):
            if function_address == "0x401000":
                return failure("DECOMPILE_ERROR", "Failed")
            return success(
                {
                    "function": function_address,
                    "pseudo_c": "void func() {}",
                    "decompiler": "r2ghidra",
                }
            )

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=lambda p: tmp_path / p,
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                    side_effect=mock_decompile_side_effect,
                ):
                    result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        exps = result.data["explanations"]
        assert len(exps) == 2
        # 0x401000 should have error
        assert "error" in exps[0]
        assert exps[0]["function"] == "0x401000"
        # 0x401080 should succeed (but have neutral explanation)
        assert "explanation" in exps[1]
        assert exps[1]["function"] == "0x401080"


class TestPatchExplainerStress:
    """Stress tests for patch_explainer to verify edge cases and limits."""

    def test_extreme_length_decompilation(self):
        from reversecore_mcp.tools.common.patch_explainer import (
            _generate_diff_snippet,
            _generate_explanation,
        )

        # Create massive files (e.g. 5,000 lines of code)
        code_a = "\n".join(f"int a{i} = {i};" for i in range(5000))
        code_b = "\n".join(f"int a{i} = {i + 1};" for i in range(5000))

        # Check explanation performance and results
        explanation = _generate_explanation(code_a, code_b)
        assert isinstance(explanation, dict)
        assert "details" in explanation

        # Check diff snippet performance and 50-line limit
        diff_snippet = _generate_diff_snippet(code_a, code_b)
        assert len(diff_snippet.splitlines()) <= 50

    def test_empty_or_whitespace_decompilation(self):
        from reversecore_mcp.tools.common.patch_explainer import (
            _generate_diff_snippet,
            _generate_explanation,
        )

        # Empty strings
        explanation = _generate_explanation("", "")
        assert explanation["summary"] == "Code structure changed."
        assert len(explanation["details"]) == 1
        assert "Logic modified without obvious security patterns" in explanation["details"][0]

        diff_snippet = _generate_diff_snippet("", "")
        assert diff_snippet == ""

        # Whitespace-only strings
        explanation = _generate_explanation("   \n  \t  ", "  \n\n  ")
        assert explanation["summary"] == "Code structure changed."

        diff_snippet = _generate_diff_snippet("  \n  ", " \n\n ")
        # Unified diff might output header lines even if content lines are empty/whitespace
        # Let's just assert it runs without exception
        assert isinstance(diff_snippet, str)

    def test_malformed_lines_and_weird_formatting(self):
        from reversecore_mcp.tools.common.patch_explainer import (
            _generate_diff_snippet,
            _generate_explanation,
        )

        # Extreme line lengths and Unicode/binary patterns
        code_a = "A" * 10000 + "\nstrcpy(dest, src);"
        code_b = "B" * 10000 + "\nstrncpy(dest, src, 10);"

        explanation = _generate_explanation(code_a, code_b)
        assert "Unsafe APIs were replaced" in explanation["summary"]

        diff_snippet = _generate_diff_snippet(code_a, code_b)
        assert len(diff_snippet.splitlines()) <= 50

    @pytest.mark.asyncio
    async def test_explain_patch_malformed_diff_data_types(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        # Mock diff result with data being a list instead of a dict
        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps([{"something": "else"}])

        with (
            patch(
                "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                side_effect=lambda p: tmp_path / p,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ),
        ):
            # The tool should handle AttributeError if it attempts to call .get() on list
            # and wrap it using @handle_tool_errors decorator which converts exceptions to failure
            result = await explain_patch(str(file_a), str(file_b))
            assert result.status == "error"

    @pytest.mark.asyncio
    async def test_explain_patch_malformed_changes_elements(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        # Mock diff result with changes being a list of non-dict items
        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps({"changes": ["not_a_dict"]})

        with (
            patch(
                "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                side_effect=lambda p: tmp_path / p,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ),
        ):
            # This should also be handled by @handle_tool_errors and return error status
            result = await explain_patch(str(file_a), str(file_b))
            assert result.status == "error"

    @pytest.mark.asyncio
    async def test_explain_patch_unhashable_address(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        # Mock diff result with changes having unhashable address (dict/list)
        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps({"changes": [{"address": {"invalid": "dict"}}]})

        with (
            patch(
                "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                side_effect=lambda p: tmp_path / p,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ),
        ):
            result = await explain_patch(str(file_a), str(file_b))
            assert result.status == "error"
            assert result.error_code == "INTERNAL_ERROR"
            assert "unhashable" in result.message or "typeerror" in result.message.lower()

    @pytest.mark.asyncio
    async def test_explain_patch_non_string_pseudo_c(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps(
            {"changes": [{"address": "0x401000", "type": "code_change"}]}
        )

        # Mock decompile returning non-string pseudo_c
        from reversecore_mcp.core.result import success

        mock_decompile_res = success(
            {
                "function": "0x401000",
                "pseudo_c": 12345,  # Non-string
                "decompiler": "r2ghidra",
            }
        )

        with (
            patch(
                "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                side_effect=lambda p: tmp_path / p,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                new_callable=AsyncMock,
                return_value=mock_decompile_res,
            ),
        ):
            result = await explain_patch(str(file_a), str(file_b))
            # Handled by @handle_tool_errors and returns error status
            assert result.status == "error"

    @pytest.mark.asyncio
    async def test_explain_patch_whitespace_and_invalid_function_name(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps({"changes": []})

        # Testing empty or whitespace-only function names
        for bad_func in ["", "   ", "\n", "invalid@func"]:
            with (
                patch(
                    "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                    side_effect=lambda p: tmp_path / p,
                ),
                patch(
                    "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                    new_callable=AsyncMock,
                    return_value=mock_diff_result,
                ),
            ):
                result = await explain_patch(str(file_a), str(file_b), function_name=bad_func)
                assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_explain_patch_empty_or_whitespace_diff_data(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        # Mock diff result with data being whitespace
        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = "   "

        with (
            patch(
                "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                side_effect=lambda p: tmp_path / p,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ),
        ):
            result = await explain_patch(str(file_a), str(file_b))
            assert result.status == "error"

    @pytest.mark.asyncio
    async def test_explain_patch_invalid_json_diff(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = "{invalid_json"

        with (
            patch(
                "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                side_effect=lambda p: tmp_path / p,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ),
        ):
            # JSONDecodeError should be caught and returned as an error ToolResult
            result = await explain_patch(str(file_a), str(file_b))
            assert result.status == "error"

    @pytest.mark.asyncio
    async def test_explain_patch_validation_error(self, tmp_path):
        from reversecore_mcp.core.exceptions import ValidationError
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
            side_effect=ValidationError("Invalid file path"),
        ):
            result = await explain_patch("invalid_a", "invalid_b")
            assert result.status == "error"
            assert result.error_code == "VALIDATION_ERROR"
            assert "invalid" in result.message.lower()

    @pytest.mark.asyncio
    async def test_explain_patch_null_changes(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("dummy")
        file_b.write_text("dummy")

        # Mock diff result with changes explicitly set to None
        # In python `not None` is True, so `if not changes:` is True, returning success with no changes.
        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = json.dumps({"changes": None})

        with (
            patch(
                "reversecore_mcp.tools.common.patch_explainer.validate_file_path",
                side_effect=lambda p: tmp_path / p,
            ),
            patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ),
        ):
            result = await explain_patch(str(file_a), str(file_b))
            assert result.status == "success"
            assert "no significant code changes" in result.data["summary"].lower()
