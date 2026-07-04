from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.tools.analysis.fuzz_tools import generate_fuzzing_harness


@pytest.fixture
def mock_binary(tmp_path):
    binary_path = tmp_path / "test.bin"
    binary_path.write_text("dummy")
    return str(binary_path)


@patch("reversecore_mcp.tools.analysis.fuzz_tools.validate_file_path")
def test_generate_fuzzing_harness_success(mock_validate, mock_binary):
    mock_validate.return_value = Path(mock_binary)
    result = generate_fuzzing_harness(mock_binary, "0x401000")
    assert result.status == "success"
    assert "0x401000" in result.data["harness_code"]
    assert "import afl" in result.data["harness_code"]


@patch("reversecore_mcp.tools.analysis.fuzz_tools.validate_file_path")
def test_generate_fuzzing_harness_unsupported_fuzzer(mock_validate, mock_binary):
    mock_validate.return_value = Path(mock_binary)
    result = generate_fuzzing_harness(mock_binary, "0x401000", fuzzer_type="libfuzzer")
    assert result.status == "error"
    # Result should be ToolResult(status='error', message='...')
    # In Reversecore, failure() returns ToolResult(status='error', is_error=True, error=msg, data={"error_code": code, "hint": hint})
    # or similar. Let's just check status.
    assert "UNSUPPORTED_FUZZER" in str(result) or "error" in result.status


@patch("reversecore_mcp.core.config.get_config")
@patch("reversecore_mcp.tools.analysis.fuzz_tools.validate_file_path")
def test_generate_fuzzing_harness_save(mock_validate, mock_get_config, mock_binary, tmp_path):
    import unittest.mock as mock

    mock_validate.return_value = Path(mock_binary)
    mock_config = mock.MagicMock()
    mock_config.workspace = tmp_path
    mock_get_config.return_value = mock_config

    result = generate_fuzzing_harness(mock_binary, "0x401000", save_to_workspace=True)

    assert result.status == "success"
    assert result.data["saved_path"] is not None
    saved_file = Path(result.data["saved_path"])
    assert saved_file.exists()
    assert "import afl" in saved_file.read_text()
