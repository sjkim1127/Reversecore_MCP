"""
Integration tests for library tools.
"""

import os
from pathlib import Path

import pytest

from reversecore_mcp.tools import lib_tools


class TestRunYara:
    """Integration tests for run_yara tool."""

    def test_run_yara_success(self, workspace_dir, tmp_path, monkeypatch):
        """Test successful YARA scan."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        # Create test file
        test_file = workspace_dir / "test.txt"
        test_file.write_text("This is a test file with some content")
        
        # Create YARA rule
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "test.yar"
        rule_file.write_text('rule test { strings: $a = "test" condition: $a }')
        
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(rules_dir))
        
        try:
            import yara
        except ImportError:
            pytest.skip("yara-python not installed")
        
        result = lib_tools.run_yara(str(test_file), str(rule_file))
        assert "test" in result.lower() or "no match" in result.lower()

    def test_run_yara_nonexistent_file(self, workspace_dir, tmp_path, monkeypatch):
        """Test YARA scan on nonexistent file."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "test.yar"
        rule_file.write_text('rule test { condition: true }')
        
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(rules_dir))
        
        try:
            import yara
        except ImportError:
            pytest.skip("yara-python not installed")
        
        result = lib_tools.run_yara(
            str(workspace_dir / "nonexistent.txt"), str(rule_file)
        )
        assert "Error" in result


class TestDisassembleWithCapstone:
    """Integration tests for disassemble_with_capstone tool."""

    def test_disassemble_x86_64(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test disassembly with x86-64 architecture."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        
        try:
            from capstone import Cs
        except ImportError:
            pytest.skip("capstone not installed")
        
        result = lib_tools.disassemble_with_capstone(
            sample_binary_path, offset=0, size=16, arch="x86", mode="64"
        )
        assert isinstance(result, str)

    def test_disassemble_invalid_arch(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test disassembly with invalid architecture."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        # Reload settings to pick up new environment variable
        from reversecore_mcp.core.config import reload_settings
        reload_settings()
        
        try:
            from capstone import Cs
        except ImportError:
            pytest.skip("capstone not installed")
        
        result = lib_tools.disassemble_with_capstone(
            sample_binary_path, arch="invalid_arch", mode="64"
        )
        assert "Error" in result
        assert "Unsupported architecture" in result

    def test_disassemble_invalid_mode(self, workspace_dir, sample_binary_path, monkeypatch):
        """Test disassembly with invalid mode."""
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))
        # Reload settings to pick up new environment variable
        from reversecore_mcp.core.config import reload_settings
        reload_settings()
        
        try:
            from capstone import Cs
        except ImportError:
            pytest.skip("capstone not installed")
        
        result = lib_tools.disassemble_with_capstone(
            sample_binary_path, arch="x86", mode="invalid_mode"
        )
        assert "Error" in result
        assert "Unsupported mode" in result

