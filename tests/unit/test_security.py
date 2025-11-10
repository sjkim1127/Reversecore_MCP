"""
Unit tests for core.security module.
"""

import os
import tempfile
from pathlib import Path

import pytest

from reversecore_mcp.core.security import validate_file_path


class TestValidateFilePath:
    """Test cases for validate_file_path function."""

    def test_valid_file_in_workspace(self, workspace_dir, sample_binary_path):
        """Test that a valid file in workspace is accepted."""
        # Set workspace environment
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        
        result = validate_file_path(sample_binary_path)
        assert result == str(Path(sample_binary_path).resolve())

    def test_file_outside_workspace(self, workspace_dir):
        """Test that a file outside workspace is rejected."""
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        
        # Create file outside workspace
        outside_file = workspace_dir.parent / "outside_file.txt"
        outside_file.write_text("test")
        
        with pytest.raises(ValueError, match="outside allowed workspace"):
            validate_file_path(str(outside_file))

    def test_nonexistent_file(self, workspace_dir):
        """Test that a nonexistent file raises ValueError."""
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        
        nonexistent = workspace_dir / "nonexistent.txt"
        with pytest.raises(ValueError, match="Invalid file path"):
            validate_file_path(str(nonexistent))

    def test_directory_instead_of_file(self, workspace_dir):
        """Test that a directory path is rejected."""
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        
        with pytest.raises(ValueError, match="does not point to a file"):
            validate_file_path(str(workspace_dir))

    def test_symlink_outside_workspace(self, workspace_dir, tmp_path):
        """Test that symlink pointing outside workspace is blocked."""
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        
        # Create file outside workspace
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("secret")
        
        # Create symlink in workspace pointing outside
        symlink = workspace_dir / "symlink"
        symlink.symlink_to(outside_file)
        
        # Should be blocked because resolved path is outside workspace
        with pytest.raises(ValueError, match="outside allowed workspace"):
            validate_file_path(str(symlink))

    def test_path_traversal_attack(self, workspace_dir):
        """Test that path traversal attempts are blocked."""
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        
        # Try to access parent directory
        traversal_path = workspace_dir / ".." / ".." / "etc" / "passwd"
        
        with pytest.raises(ValueError):
            validate_file_path(str(traversal_path))

    def test_read_only_directory_access(self, workspace_dir, tmp_path):
        """Test that read-only directories are accessible when read_only=True."""
        # Create rules directory
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "test.yar"
        rule_file.write_text("rule test { condition: true }")
        
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        os.environ["REVERSECORE_READ_DIRS"] = str(rules_dir)
        
        # Should work with read_only=True
        result = validate_file_path(str(rule_file), read_only=True)
        assert result == str(rule_file.resolve())
        
        # Should fail with read_only=False
        with pytest.raises(ValueError, match="outside allowed"):
            validate_file_path(str(rule_file), read_only=False)

    def test_workspace_attack_edge_case(self, workspace_dir):
        """Test edge case: /app/workspace-attack should be blocked."""
        os.environ["REVERSECORE_WORKSPACE"] = str(workspace_dir)
        
        # Create a directory that starts with workspace path but is different
        attack_dir = Path(str(workspace_dir) + "-attack")
        attack_dir.mkdir(exist_ok=True)
        attack_file = attack_dir / "file.txt"
        attack_file.write_text("attack")
        
        # Should be blocked even though path starts with workspace
        with pytest.raises(ValueError, match="outside allowed"):
            validate_file_path(str(attack_file))

