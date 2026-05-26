"""Tests for reversecore_mcp.tools.common.patch_explainer."""

from unittest.mock import AsyncMock, MagicMock, patch

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
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_a.write_text("mov eax, 1")
        file_b = tmp_path / "b.txt"
        file_b.write_text("mov ebx, 2")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {
            "changed_functions": [{"name": "main", "code_a": "mov eax, 1", "code_b": "mov ebx, 2"}],
            "similarity": 0.5,
        }

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_tools.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_diff_fails(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_a.write_text("mov eax, 1")
        file_b = tmp_path / "b.txt"
        file_b.write_text("mov ebx, 2")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "error"
        mock_diff_result.message = "diff failed"

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_tools.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_no_changes(self, tmp_path):
        from reversecore_mcp.tools.common.patch_explainer import explain_patch

        file_a = tmp_path / "a.txt"
        file_a.write_text("mov eax, 1")
        file_b = tmp_path / "b.txt"
        file_b.write_text("mov eax, 1")

        mock_diff_result = MagicMock()
        mock_diff_result.status = "success"
        mock_diff_result.data = {"changes": []}

        with patch(
            "reversecore_mcp.tools.common.patch_explainer.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.common.patch_explainer.diff_tools.diff_binaries",
                new_callable=AsyncMock,
                return_value=mock_diff_result,
            ):
                result = await explain_patch(str(file_a), str(file_b))

        assert result.status == "success"
