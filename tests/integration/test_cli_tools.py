"""Integration tests for CLI tools using ToolResult assertions."""

import shutil
import subprocess

import pytest

from reversecore_mcp.tools import cli_tools


def _require_command(command: str) -> None:
    """Skip tests if the required CLI tool is missing."""
    if shutil.which(command) is None:
        pytest.skip(f"{command} command not available on this system")


class TestRunFile:
    """Integration tests for run_file tool."""

    def test_run_file_success(self, sample_binary_path, patched_workspace_config):
        """Test successful file type identification."""
        _require_command("file")
        result = cli_tools.run_file(str(sample_binary_path))
        assert result.status == "success"
        assert isinstance(result.data, str)
        assert result.metadata and "bytes_read" in result.metadata

    def test_run_file_nonexistent(self, workspace_dir, patched_workspace_config):
        """Test file command on nonexistent file."""
        result = cli_tools.run_file(str(workspace_dir / "nonexistent.txt"))
        assert result.status == "error" and result.error_code == "VALIDATION_ERROR"

    def test_run_file_outside_workspace(self, workspace_dir, tmp_path, patched_workspace_config):
        """Test that file outside workspace is rejected."""
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("test")
        
        result = cli_tools.run_file(str(outside_file))
        assert result.status == "error"
        assert "outside" in result.message.lower()
        assert result.error_code == "VALIDATION_ERROR"


class TestRunStrings:
    """Integration tests for run_strings tool."""

    def test_run_strings_success(self, sample_binary_path, patched_workspace_config):
        """Test successful string extraction."""
        _require_command("strings")
        result = cli_tools.run_strings(str(sample_binary_path), min_length=4)
        assert result.status == "success"
        assert "Hello World" in result.data
        assert result.metadata and result.metadata.get("bytes_read") is not None

    def test_run_strings_min_length(self, sample_binary_path, patched_workspace_config):
        """Test string extraction with different min_length."""
        _require_command("strings")
        result = cli_tools.run_strings(str(sample_binary_path), min_length=10)
        assert result.status == "success"
        assert "Hello World" in result.data

    def test_run_strings_nonexistent(self, workspace_dir, patched_workspace_config):
        """Test strings command on nonexistent file."""
        result = cli_tools.run_strings(str(workspace_dir / "nonexistent.txt"))
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"


class TestRunRadare2:
    """Integration tests for run_radare2 tool."""

    def test_run_radare2_success(self, sample_binary_path, patched_workspace_config):
        """Test successful radare2 command execution."""
        # Skip if radare2 is not installed
        try:
            subprocess.run(["r2", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("radare2 not installed")

        result = cli_tools.run_radare2(str(sample_binary_path), "i")
        assert result.status == "success"
        assert isinstance(result.data, str)
        assert result.metadata and result.metadata.get("bytes_read") is not None

    def test_run_radare2_invalid_command(self, sample_binary_path, patched_workspace_config):
        """Test radare2 with invalid command."""
        try:
            subprocess.run(["r2", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("radare2 not installed")

        result = cli_tools.run_radare2(str(sample_binary_path), "invalid_command_xyz")
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

