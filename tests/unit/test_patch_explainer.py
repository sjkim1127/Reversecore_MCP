from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.result import ToolSuccess
from reversecore_mcp.tools.common.patch_explainer import _generate_explanation, explain_patch


@pytest.mark.asyncio
async def test_explain_patch_success():
    # Mock diff_tools.diff_binaries
    mock_diff_result = ToolSuccess(
        status="success", data={"changes": [{"address": "0x401000", "type": "code_change"}]}
    )

    # Mock decompilation.smart_decompile
    mock_decomp_result_a = ToolSuccess(status="success", data="void func() { strcpy(dest, src); }")
    mock_decomp_result_b = ToolSuccess(
        status="success", data="void func() { strncpy(dest, src, 10); }"
    )

    with (
        patch(
            "reversecore_mcp.tools.diff_tools.diff_binaries", new_callable=AsyncMock
        ) as mock_diff,
        patch(
            "reversecore_mcp.tools.decompilation.smart_decompile", new_callable=AsyncMock
        ) as mock_decomp,
        patch("reversecore_mcp.tools.patch_explainer.validate_file_path") as mock_validate,
    ):
        mock_validate.side_effect = lambda x: Path(x)
        mock_diff.return_value = mock_diff_result
        # Side effect for decompilation: first call A, second call B
        mock_decomp.side_effect = [mock_decomp_result_a, mock_decomp_result_b]

        result = await explain_patch("v1.exe", "v2.exe")

        if result.status != "success":
            print(f"Test failed with error: {result.message}")
            if hasattr(result, "details"):
                print(f"Details: {result.details}")

        assert result.status == "success"
        explanations = result.data["explanations"]
        assert len(explanations) == 1
        assert explanations[0]["function"] == "0x401000"

        details = explanations[0]["explanation"]["details"]
        assert any("API Hardening" in d for d in details)
        assert any("strcpy" in d and "strncpy" in d for d in details)


@pytest.mark.asyncio
async def test_explain_patch_added_check():
    # Test heuristic for added if-check
    code_a = """
    void func(int a) {
        process(a);
    }
    """
    code_b = """
    void func(int a) {
        if (a > 100) return;
        process(a);
    }
    """

    explanation = _generate_explanation(code_a, code_b)
    assert explanation["summary"] == "Security checks were added."
    assert any("Added Security Check" in d for d in explanation["details"])


@pytest.mark.asyncio
async def test_explain_patch_no_changes():
    mock_diff_result = ToolSuccess(status="success", data={"changes": []})

    with (
        patch(
            "reversecore_mcp.tools.diff_tools.diff_binaries", new_callable=AsyncMock
        ) as mock_diff,
        patch("reversecore_mcp.tools.patch_explainer.validate_file_path") as mock_validate,
    ):
        mock_validate.side_effect = lambda x: Path(x)
        mock_diff.return_value = mock_diff_result

        result = await explain_patch("v1.exe", "v2.exe")

        if result.status != "success":
            print(f"Test failed with error: {result.message}")
            if hasattr(result, "details"):
                print(f"Details: {result.details}")

        assert result.status == "success"
        assert result.data["summary"] == "No significant code changes detected."
