"""Unit tests for symbolic analysis module."""

from unittest.mock import patch

import pytest

from reversecore_mcp.tools.analysis.symbolic_analysis import verify_path_and_get_args


@pytest.fixture
def mock_subprocess():
    with patch(
        "reversecore_mcp.tools.analysis.symbolic_analysis.execute_subprocess_async"
    ) as mock_exec:
        yield mock_exec


@pytest.mark.asyncio
async def test_verify_path_satisfiable(mock_subprocess):
    """Test successful path verification."""
    mock_subprocess.return_value = (
        '{"satisfiable": true, "concrete_input": "test_input", "target_address": "0x401000", "error": null}\n',
        "",
    )

    result = await verify_path_and_get_args("/bin/test", target_addr=0x401000)

    assert result["satisfiable"] is True
    assert result["concrete_input"] == "test_input"
    assert result["error"] is None

    # Check if correct command was built
    mock_subprocess.assert_called_once()
    args, kwargs = mock_subprocess.call_args
    cmd = args[0]
    import sys

    assert cmd[0] in ("python", "python3", sys.executable)
    assert "--binary" in cmd
    assert "/bin/test" in cmd
    assert "--target-addr" in cmd
    assert "4198400" in cmd  # 0x401000 in decimal


@pytest.mark.asyncio
async def test_verify_path_unsatisfiable(mock_subprocess):
    """Test unsatisfiable path verification."""
    mock_subprocess.return_value = (
        '{"satisfiable": false, "concrete_input": null, "target_address": "0x401000", "error": null}\n',
        "",
    )

    result = await verify_path_and_get_args("/bin/test", target_addr=0x401000)

    assert result["satisfiable"] is False
    assert result["concrete_input"] is None
    assert result["error"] is None


@pytest.mark.asyncio
async def test_verify_path_with_start_addr(mock_subprocess):
    """Test with start address specified."""
    mock_subprocess.return_value = (
        '{"satisfiable": true, "concrete_input": "", "target_address": "0x401000", "error": null}\n',
        "",
    )

    result = await verify_path_and_get_args("/bin/test", target_addr=0x401000, start_addr=0x400000)

    assert result["satisfiable"] is True

    # Check if correct command was built
    args, _ = mock_subprocess.call_args
    cmd = args[0]
    assert "--start-addr" in cmd
    assert "4194304" in cmd  # 0x400000 in decimal


@pytest.mark.asyncio
async def test_verify_path_json_error(mock_subprocess):
    """Test handling of invalid JSON output from worker."""
    mock_subprocess.return_value = ("invalid output\n", "")

    result = await verify_path_and_get_args("/bin/test", target_addr=0x401000)

    assert result["satisfiable"] is False
    assert result["error"] == "Invalid output format from worker"


@pytest.mark.asyncio
async def test_verify_path_execution_error(mock_subprocess):
    """Test handling of subprocess execution error."""
    mock_subprocess.side_effect = Exception("Subprocess failed")

    result = await verify_path_and_get_args("/bin/test", target_addr=0x401000)

    assert result["satisfiable"] is False
    assert "Subprocess failed" in result["error"]
