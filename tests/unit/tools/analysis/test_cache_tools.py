"""Unit tests for Portable Cache Export/Import tools."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core.result import ToolError, ToolSuccess
from reversecore_mcp.tools.analysis.cache_tools import (
    export_analysis_cache,
    import_analysis_cache,
)


@pytest.fixture
def mock_cache_data():
    return {
        "file_hash": "a1b2c3d4e5f6",
        "format": "rcpack",
        "version": "1.0",
        "entries": [
            {
                "function_address": "0x401000",
                "decompiler": "ghidra",
                "status": "success",
                "data": json.dumps({"status": "success", "data": "void main() {}"}),
            }
        ],
    }


@pytest.mark.asyncio
async def test_export_analysis_cache_success(mock_cache_data, tmp_path):
    with (
        patch("reversecore_mcp.tools.analysis.cache_tools.validate_file_path") as mock_validate,
        patch("reversecore_mcp.tools.analysis.cache_tools.calculate_file_sha256") as mock_calc,
        patch(
            "reversecore_mcp.tools.analysis.cache_tools.export_cache_by_hash",
            new_callable=AsyncMock,
        ) as mock_export,
        patch("reversecore_mcp.tools.analysis.cache_tools.get_config") as mock_get_config,
    ):
        mock_path = MagicMock()
        mock_path.name = "test_bin"
        mock_validate.return_value = mock_path

        mock_calc.return_value = "a1b2c3d4e5f6"
        mock_export.return_value = mock_cache_data

        config = MagicMock()
        config.workspace = tmp_path
        mock_get_config.return_value = config

        result = await export_analysis_cache("fake/path", "custom.rcpack")

        assert isinstance(result, ToolSuccess)
        assert result.metadata["entries_count"] == 1
        assert "custom.rcpack" in result.metadata["export_path"]

        export_file = tmp_path / "custom.rcpack"
        assert export_file.exists()

        with open(export_file) as f:
            saved_data = json.load(f)
            assert saved_data["file_hash"] == "a1b2c3d4e5f6"
            assert len(saved_data["entries"]) == 1


@pytest.mark.asyncio
async def test_export_analysis_cache_empty(tmp_path):
    with (
        patch("reversecore_mcp.tools.analysis.cache_tools.validate_file_path") as mock_validate,
        patch("reversecore_mcp.tools.analysis.cache_tools.calculate_file_sha256") as mock_calc,
        patch(
            "reversecore_mcp.tools.analysis.cache_tools.export_cache_by_hash",
            new_callable=AsyncMock,
        ) as mock_export,
    ):
        mock_validate.return_value = MagicMock()
        mock_calc.return_value = "a1b2c3d4e5f6"
        mock_export.return_value = {"entries": []}

        result = await export_analysis_cache("fake/path")

        assert isinstance(result, ToolError)
        assert result.error_code == "CACHE_EXPORT_EMPTY"


@pytest.mark.asyncio
async def test_import_analysis_cache_success(mock_cache_data, tmp_path):
    pack_path = tmp_path / "test.rcpack"
    with open(pack_path, "w") as f:
        json.dump(mock_cache_data, f)

    with (
        patch("reversecore_mcp.tools.analysis.cache_tools.validate_file_path") as mock_validate,
        patch(
            "reversecore_mcp.tools.analysis.cache_tools.import_cache_data",
            new_callable=AsyncMock,
        ) as mock_import,
    ):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.__str__.return_value = str(pack_path)
        # Mocking __fspath__ so open() works on the mock
        mock_path.__fspath__.return_value = str(pack_path)
        mock_validate.return_value = pack_path

        mock_import.return_value = 1

        result = await import_analysis_cache(str(pack_path))

        assert isinstance(result, ToolSuccess)
        assert result.metadata["imported_count"] == 1
        assert result.metadata["file_hash"] == "a1b2c3d4e5f6"


@pytest.mark.asyncio
async def test_import_analysis_cache_invalid_format(tmp_path):
    pack_path = tmp_path / "test.rcpack"
    with open(pack_path, "w") as f:
        json.dump({"format": "wrong", "entries": []}, f)

    with patch("reversecore_mcp.tools.analysis.cache_tools.validate_file_path") as mock_validate:
        mock_validate.return_value = pack_path

        result = await import_analysis_cache(str(pack_path))

        assert isinstance(result, ToolError)
        assert result.error_code == "CACHE_IMPORT_INVALID"
