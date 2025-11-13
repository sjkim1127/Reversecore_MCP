"""
Integration tests for CLI tools.
"""

import os
import subprocess
from pathlib import Path

import pytest

from reversecore_mcp.tools import cli_tools


class TestRunFile:
    """Integration tests for run_file tool."""

    def test_run_file_success(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test successful file type identification."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        result = cli_tools.run_file(sample_binary_path)
        assert "data" in result.lower() or "binary" in result.lower()

    def test_run_file_nonexistent(self, workspace_dir, monkeypatch):
        """Test file command on nonexistent file."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        result = cli_tools.run_file(str(workspace_dir / "nonexistent.txt"))
        assert "Error" in result

    def test_run_file_outside_workspace(self, workspace_dir, tmp_path, monkeypatch):
        """Test that file outside workspace is rejected."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("test")
        
        result = cli_tools.run_file(str(outside_file))
        assert "Error" in result
        assert "outside" in result.lower()


class TestRunStrings:
    """Integration tests for run_strings tool."""

    def test_run_strings_success(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test successful string extraction."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        # Reload settings to pick up new environment variable
        from reversecore_mcp.core.config import reload_settings
        reload_settings()
        
        result = cli_tools.run_strings(sample_binary_path, min_length=4)
        assert "Hello World" in result

    def test_run_strings_min_length(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test string extraction with different min_length."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        # Reload settings to pick up new environment variable
        from reversecore_mcp.core.config import reload_settings
        reload_settings()
        
        result = cli_tools.run_strings(sample_binary_path, min_length=10)
        assert "Hello World" in result

    def test_run_strings_nonexistent(self, workspace_dir, monkeypatch):
        """Test strings command on nonexistent file."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        result = cli_tools.run_strings(str(workspace_dir / "nonexistent.txt"))
        assert "Error" in result


class TestRunRadare2:
    """Integration tests for run_radare2 tool."""

    def test_run_radare2_success(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test successful radare2 command execution."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        # Skip if radare2 is not installed
        try:
            subprocess.run(["r2", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("radare2 not installed")
        
        result = cli_tools.run_radare2(sample_binary_path, "i")
        # Should return some output (even if minimal)
        assert isinstance(result, str)

    def test_run_radare2_invalid_command(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test radare2 with invalid command."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        try:
            subprocess.run(["r2", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("radare2 not installed")
        
        result = cli_tools.run_radare2(sample_binary_path, "invalid_command_xyz")
        # Should return error message
        assert isinstance(result, str)

