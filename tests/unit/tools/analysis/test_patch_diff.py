from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.result import success
from reversecore_mcp.tools.analysis.diff_tools import patch_diff_1day


@pytest.fixture
def mock_binary(tmp_path):
    binary_path = tmp_path / "test.bin"
    binary_path.write_text("dummy")
    return str(binary_path)


@pytest.mark.asyncio
@patch("reversecore_mcp.tools.analysis.diff_tools.diff_binaries", new_callable=AsyncMock)
@patch(
    "reversecore_mcp.tools.analysis.diff_tools.analyze_variant_changes",
    new_callable=AsyncMock,
)
async def test_patch_diff_1day_identical(mock_variant, mock_diff, mock_binary):
    mock_diff.return_value = success({"similarity": 1.0, "changes": []})
    result = await patch_diff_1day(mock_binary, mock_binary)
    assert result.status == "success"
    assert "identical" in result.data["message"]


@pytest.mark.asyncio
@patch("reversecore_mcp.tools.analysis.diff_tools.diff_binaries", new_callable=AsyncMock)
@patch(
    "reversecore_mcp.tools.analysis.diff_tools.analyze_variant_changes",
    new_callable=AsyncMock,
)
async def test_patch_diff_1day_different(mock_variant, mock_diff, mock_binary):
    mock_diff.return_value = success({"similarity": 0.8, "changes": [{"type": "code_change"}]})
    mock_variant.return_value = success(
        {"top_modified_functions": [{"function": "vuln", "change_count": 5}]}
    )
    result = await patch_diff_1day(mock_binary, mock_binary)
    assert result.status == "success"
    assert "Significant differences" in result.data["patch_analysis"]
    assert len(result.data["top_modified_functions"]) == 1
