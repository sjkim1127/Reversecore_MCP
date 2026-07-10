"""Tests for reversecore_mcp.tools.common.patch_explainer."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core.result import failure, success
from reversecore_mcp.tools.common.patch_explainer import (
    _generate_diff_snippet,
    _generate_explanation,
    explain_patch,
)


class TestGenerateExplanation:
    """Tests for _generate_explanation."""

    def test_identical_code(self):
        result = _generate_explanation("mov eax, 1", "mov eax, 1")
        assert result["summary"] == "Code structure changed."

    def test_different_code(self):
        result = _generate_explanation("mov eax, 1", "mov ebx, 2")
        assert any(
            "Logic modified without obvious security patterns" in detail
            for detail in result["details"]
        )

    def test_security_check_added(self):
        result = _generate_explanation("call foo", "if (x > 0) {\n  call foo\n}")
        assert "Security checks were added" in result["summary"]
        assert any("Added Security Check" in detail for detail in result["details"])

    @pytest.mark.parametrize(
        "old_api,new_api,expected_msg",
        [
            ("strcpy", "strncpy", "Replaced unsafe string copy with bounded copy."),
            (
                "sprintf",
                "snprintf",
                "Replaced unsafe format string with bounded version.",
            ),
            ("gets", "fgets", "Replaced dangerous input function."),
            ("memcpy", "memcpy_s", "Replaced memory copy with secure version."),
        ],
    )
    def test_api_replacements(self, old_api, new_api, expected_msg):
        code_a = f"void func() {{ {old_api}(dest, src); }}"
        code_b = f"void func() {{ {new_api}(dest, src, size); }}"
        result = _generate_explanation(code_a, code_b)
        assert result["summary"] == "Unsafe APIs were replaced."
        assert any(expected_msg in detail for detail in result["details"])
        assert any("API Hardening" in detail for detail in result["details"])

    def test_integer_overflow_check(self):
        code_a = "void func() { int c = a + b; }"
        code_b = "void func() { if (a > MAX - b) return; int c = a + b; }"
        result = _generate_explanation(code_a, code_b)
        assert any("Integer Overflow Check" in detail for detail in result["details"])

    def test_logic_removal(self):
        code_a = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10"
        code_b = "line1\nline2"  # less than 8 lines (80% of 10)
        result = _generate_explanation(code_a, code_b)
        assert any("Logic Removal" in detail for detail in result["details"])


class TestGenerateDiffSnippet:
    """Tests for _generate_diff_snippet."""

    def test_identical(self):
        result = _generate_diff_snippet("line1\nline2", "line1\nline2")
        assert result == ""

    def test_different(self):
        result = _generate_diff_snippet("line1\nline2", "line1\nchanged")
        assert "changed" in result

    def test_context_lines(self):
        a = "\n".join([f"line{i}" for i in range(10)])
        b = "\n".join([f"line{i}" for i in range(10)])
        result = _generate_diff_snippet(a, b, context=2)
        assert result == ""


class TestExplainPatch:
    """Tests for explain_patch."""

    @pytest.mark.asyncio
    async def test_success_with_changes(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("void func() {}")
        file_b = tmp_path / "b.txt"
        file_b.write_text("void func() {}")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {
            "changes": [
                {
                    "address": "main",
                    "type": "code_change",
                    "description": "some change",
                },
            ],
            "similarity": 0.5,
        }

        mock_decompile_a = success({"pseudo_c": "void main() { strcpy(d, s); }"})
        mock_decompile_b = success({"pseudo_c": "void main() { strncpy(d, s, n); }"})

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                ) as mock_r2_dec:
                    mock_r2_dec.side_effect = [mock_decompile_a, mock_decompile_b]

                    result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        data = result.data
        assert data["summary"] == "Analyzed 1 function(s)."
        assert len(data["explanations"]) == 1
        explanation = data["explanations"][0]
        assert explanation["function"] == "main"
        assert "Unsafe APIs were replaced." in explanation["explanation"]["summary"]
        assert "strncpy" in explanation["diff_snippet"]

    @pytest.mark.asyncio
    async def test_success_specific_function(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("void func() {}")
        file_b = tmp_path / "b.txt"
        file_b.write_text("void func() {}")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {
            "changes": [
                {"address": "0x1000", "type": "code_change"},
            ],
            "similarity": 0.9,
        }

        mock_decompile_a = success({"pseudo_c": "void target() { x = 1; }"})
        mock_decompile_b = success({"pseudo_c": "void target() { x = 2; }"})

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ) as mock_diff:
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                ) as mock_r2_dec:
                    mock_r2_dec.side_effect = [mock_decompile_a, mock_decompile_b]

                    result = await explain_patch(str(file_a), str(file_b), function_name="target")

        assert result.status == "success"
        mock_diff.assert_called_once_with(str(file_a), str(file_b), function_name="target")
        assert result.data["summary"] == "Analyzed 1 function(s)."
        assert result.data["explanations"][0]["function"] == "target"

    @pytest.mark.asyncio
    async def test_heuristic_function_selection_limit_and_uniqueness(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("void func() {}")
        file_b = tmp_path / "b.txt"
        file_b.write_text("void func() {}")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        # 5 changes, with duplicates, expecting first 3 unique (0x1000, 0x2000, 0x3000)
        mock_diff_result.data = {
            "changes": [
                {"address": "0x1000"},
                {"address": "0x2000"},
                {"address": "0x1000"},
                {"address": "0x3000"},
                {"address": "0x4000"},
            ],
            "similarity": 0.5,
        }

        mock_decompile = success({"pseudo_c": "void func() {}"})

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                    return_value=mock_decompile,
                ) as mock_r2_dec:
                    result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        assert result.data["summary"] == "Analyzed 3 function(s)."
        # Verify r2_decompile was called for 0x1000, 0x2000, 0x3000, twice each (A and B)
        assert mock_r2_dec.call_count == 6

    @pytest.mark.asyncio
    async def test_diff_fails(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("mov eax, 1")
        file_b = tmp_path / "b.txt"
        file_b.write_text("mov ebx, 2")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "error"
        mock_diff_result.message = "diff failed"

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "error"
        assert result.error_code == "DIFF_FAILED"
        assert "Binary diff failed" in result.message

    @pytest.mark.asyncio
    async def test_no_changes(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("mov eax, 1")
        file_b = tmp_path / "b.txt"
        file_b.write_text("mov eax, 1")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {"changes": []}

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        assert result.data["summary"] == "No significant code changes detected."

    @pytest.mark.asyncio
    async def test_no_changed_functions_identified(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("mov eax, 1")
        file_b = tmp_path / "b.txt"
        file_b.write_text("mov eax, 1")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        # changes exists but they don't have addresses (so target_functions is empty)
        mock_diff_result.data = {"changes": [{"type": "global_variable_change"}]}

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        assert result.data["summary"] == "No changed functions identified to analyze."

    @pytest.mark.asyncio
    async def test_decompile_failure(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("void func() {}")
        file_b = tmp_path / "b.txt"
        file_b.write_text("void func() {}")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {
            "changes": [
                {"address": "main"},
            ]
        }

        # Simulate failure in decompile A (e.g. status != success)
        mock_decompile_a = failure("DECOMPILE_ERROR", "Failed")
        mock_decompile_b = success({"pseudo_c": "void main() {}"})

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                ) as mock_r2_dec:
                    mock_r2_dec.side_effect = [mock_decompile_a, mock_decompile_b]

                    result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
        assert len(result.data["explanations"]) == 1
        assert (
            result.data["explanations"][0]["error"] == "Failed to decompile one or both versions."
        )

    @pytest.mark.asyncio
    async def test_with_fastmcp_context(self, tmp_path):
        file_a = tmp_path / "a.txt"
        file_a.write_text("void func() {}")
        file_b = tmp_path / "b.txt"
        file_b.write_text("void func() {}")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {
            "changes": [
                {"address": "main"},
            ]
        }

        mock_decompile_a = success({"pseudo_c": "void main() {}"})
        mock_decompile_b = success({"pseudo_c": "void main() {}"})

        mock_ctx = AsyncMock()

        with patch("reversecore_mcp.tools.common.patch_explainer.validate_file_path") as mock_val:
            mock_val.side_effect = [file_a, file_b]
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                with patch(
                    "reversecore_mcp.tools.common.patch_explainer.r2_decompile",
                    new_callable=AsyncMock,
                ) as mock_r2_dec:
                    mock_r2_dec.side_effect = [mock_decompile_a, mock_decompile_b]

                    result = await explain_patch(str(file_a), str(file_b), ctx=mock_ctx)

        assert result.status == "success"
        assert mock_ctx.info.call_count == 3  # Start, Diffing, and function main logs
        mock_ctx.info.assert_any_call(f"🔍 Analyzing patch: {file_a.name} -> {file_b.name}")
        mock_ctx.info.assert_any_call("📊 Diffing binaries to find changed functions...")
        mock_ctx.info.assert_any_call("🧠 Analyzing function: main...")
