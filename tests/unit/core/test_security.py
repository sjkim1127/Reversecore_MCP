"""
Unit tests for core.security module.
"""

from pathlib import Path

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.security import WorkspaceConfig, validate_file_path


@pytest.mark.security
class TestValidateFilePath:
    """Test cases for validate_file_path function."""

    def test_valid_file_in_workspace(self, sample_binary_path, workspace_config):
        """Test that a valid file in workspace is accepted."""
        result = validate_file_path(str(sample_binary_path), config=workspace_config)
        assert result == sample_binary_path.resolve()

    def test_file_outside_workspace(self, workspace_dir, workspace_config):
        """Test that a file outside workspace is rejected."""
        # Create file outside workspace
        outside_file = workspace_dir.parent / "outside_file.txt"
        outside_file.write_text("test")

        with pytest.raises(ValidationError, match="outside allowed"):
            validate_file_path(str(outside_file), config=workspace_config)

    def test_nonexistent_file(self, workspace_dir, workspace_config):
        """Test that a nonexistent file raises ValueError."""
        nonexistent = workspace_dir / "nonexistent.txt"
        with pytest.raises(ValidationError, match="Invalid file path"):
            validate_file_path(str(nonexistent), config=workspace_config)

    def test_directory_instead_of_file(self, workspace_dir, workspace_config):
        """Test that a directory path is rejected."""
        with pytest.raises(ValidationError, match="does not point to a file"):
            validate_file_path(str(workspace_dir), config=workspace_config)

    def test_symlink_outside_workspace(self, workspace_dir, tmp_path, workspace_config):
        """Test that symlink pointing outside workspace is blocked."""
        # Create file outside workspace
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("secret")

        # Create symlink in workspace pointing outside
        symlink = workspace_dir / "symlink"
        try:
            symlink.symlink_to(outside_file)
        except OSError:
            pytest.skip("Symlinks not supported or insufficient privileges")

        # Should be blocked because resolved path is outside workspace
        with pytest.raises(ValidationError, match="outside allowed"):
            validate_file_path(str(symlink), config=workspace_config)

    def test_path_traversal_attack(self, workspace_dir, workspace_config):
        """Test that path traversal attempts are blocked."""
        # Try to access parent directory
        traversal_path = workspace_dir / ".." / ".." / "etc" / "passwd"

        with pytest.raises(ValidationError):
            validate_file_path(str(traversal_path), config=workspace_config)

    def test_read_only_directory_access(self, workspace_dir, tmp_path):
        """Test that read-only directories are accessible when read_only=True."""
        # Create rules directory
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir(exist_ok=True)
        rule_file = rules_dir / "test.yar"
        rule_file.write_text("rule test { condition: true }")

        config = WorkspaceConfig(workspace=workspace_dir, read_only_dirs=(rules_dir,))

        # Should work with read_only=True
        result = validate_file_path(str(rule_file), read_only=True, config=config)
        assert result == rule_file.resolve()

        # Should fail with read_only=False
        with pytest.raises(ValidationError, match="outside allowed"):
            validate_file_path(str(rule_file), read_only=False, config=config)

    def test_workspace_attack_edge_case(self, workspace_dir, workspace_config):
        """Test edge case: /app/workspace-attack should be blocked."""
        # Create a directory that starts with workspace path but is different
        attack_dir = Path(str(workspace_dir) + "-attack")
        attack_dir.mkdir(exist_ok=True)
        attack_file = attack_dir / "file.txt"
        attack_file.write_text("attack")

        # Should be blocked even though path starts with workspace
        with pytest.raises(ValidationError, match="outside allowed"):
            validate_file_path(str(attack_file), config=workspace_config)

    def test_reset_workspace_config(self, workspace_dir):
        """Test reset_workspace_config clears cached config."""
        from reversecore_mcp.core.security import (
            get_workspace_config,
            reset_workspace_config,
        )

        config1 = get_workspace_config()
        reset_workspace_config()
        config2 = get_workspace_config()
        assert config1 is not config2

    def test_host_absolute_path_extracts_filename(self, workspace_dir, workspace_config):
        """Test that host-style absolute path extracts filename if in workspace."""
        test_file = workspace_dir / "sample.exe"
        test_file.write_text("test")
        # Pass a fake host path - should extract "sample.exe" and find it in workspace
        result = validate_file_path(
            "/Users/host/Reversecore_MCP/sample.exe", config=workspace_config
        )
        assert result.name == "sample.exe"

    def test_relative_path_resolves_in_workspace(self, workspace_dir, workspace_config):
        """Test that relative path is resolved against workspace."""
        test_file = workspace_dir / "relative.bin"
        test_file.write_text("test")
        result = validate_file_path("relative.bin", config=workspace_config)
        assert result.name == "relative.bin"

    def test_read_only_error_includes_allowed_dirs(self, workspace_dir, tmp_path):
        """Test error message includes read-only dirs when read_only=True."""
        rules_dir = tmp_path / "rules_ro"
        rules_dir.mkdir(exist_ok=True)
        outside_file = tmp_path / "outside_ro.txt"
        outside_file.write_text("test")
        config = WorkspaceConfig(workspace=workspace_dir, read_only_dirs=(rules_dir,))

        with pytest.raises(ValidationError, match="Set REVERSECORE_WORKSPACE") as exc_info:
            validate_file_path(str(outside_file), read_only=True, config=config)
        assert str(rules_dir) in str(exc_info.value)

    def test_bypass_cache_option(self, sample_binary_path, workspace_config):
        """Test that bypass_cache option resolves path dynamically and bypasses/uses cache as configured."""
        from reversecore_mcp.core.security import _resolve_path_cached

        # Clear cache first
        _resolve_path_cached.cache_clear()

        # 1. Calling validate_file_path with bypass_cache=True (default) should NOT populate cache
        validate_file_path(str(sample_binary_path), config=workspace_config, bypass_cache=True)
        info = _resolve_path_cached.cache_info()
        assert info.currsize == 0

        # 2. Calling validate_file_path with bypass_cache=False should populate cache
        validate_file_path(str(sample_binary_path), config=workspace_config, bypass_cache=False)
        info = _resolve_path_cached.cache_info()
        assert info.currsize == 1
