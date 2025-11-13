"""
Unit tests for core.config module.
"""

import pytest
from pathlib import Path
from reversecore_mcp.core.config import Settings, get_settings, reload_settings


class TestSettings:
    """Test cases for Settings configuration."""

    def test_default_settings(self, monkeypatch):
        """Test default settings values."""
        # Clear any existing environment variables
        monkeypatch.delenv("REVERSECORE_WORKSPACE", raising=False)
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        monkeypatch.delenv("RATE_LIMIT", raising=False)
        monkeypatch.delenv("STRUCTURED_ERRORS", raising=False)
        
        settings = reload_settings()
        assert settings.reversecore_workspace == Path("/app/workspace")
        assert settings.log_level == "INFO"
        assert settings.rate_limit == 60
        assert settings.structured_errors is False

    def test_environment_override(self, monkeypatch, tmp_path):
        """Test that environment variables override defaults."""
        workspace = tmp_path / "custom_workspace"
        workspace.mkdir()
        
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("RATE_LIMIT", "120")
        monkeypatch.setenv("STRUCTURED_ERRORS", "true")
        
        settings = reload_settings()
        assert settings.reversecore_workspace == workspace
        assert settings.log_level == "DEBUG"
        assert settings.rate_limit == 120
        assert settings.structured_errors is True

    def test_allowed_workspace_resolution(self, tmp_path, monkeypatch):
        """Test that allowed_workspace returns resolved path."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        
        settings = reload_settings()
        assert settings.allowed_workspace == workspace.resolve()

    def test_allowed_read_dirs_parsing(self, tmp_path, monkeypatch):
        """Test comma-separated read dirs parsing."""
        dir1 = tmp_path / "rules1"
        dir2 = tmp_path / "rules2"
        dir1.mkdir()
        dir2.mkdir()
        
        monkeypatch.setenv("REVERSECORE_READ_DIRS", f"{dir1},{dir2}")
        settings = reload_settings()
        
        assert len(settings.allowed_read_dirs) == 2
        assert dir1.resolve() in settings.allowed_read_dirs
        assert dir2.resolve() in settings.allowed_read_dirs

    def test_singleton_pattern(self):
        """Test that get_settings returns the same instance."""
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2

    def test_reload_settings_creates_new_instance(self):
        """Test that reload_settings creates a new instance."""
        settings1 = get_settings()
        settings2 = reload_settings()
        # After reload, get_settings should return the new instance
        settings3 = get_settings()
        assert settings2 is settings3

    def test_empty_read_dirs_handling(self, monkeypatch):
        """Test handling of empty read dirs."""
        monkeypatch.setenv("REVERSECORE_READ_DIRS", "")
        settings = reload_settings()
        assert settings.allowed_read_dirs == []

    def test_read_dirs_with_whitespace(self, tmp_path, monkeypatch):
        """Test that whitespace in read dirs is handled correctly."""
        dir1 = tmp_path / "rules1"
        dir2 = tmp_path / "rules2"
        dir1.mkdir()
        dir2.mkdir()
        
        # Add extra whitespace
        monkeypatch.setenv("REVERSECORE_READ_DIRS", f" {dir1} , {dir2} ")
        settings = reload_settings()
        
        assert len(settings.allowed_read_dirs) == 2
        assert dir1.resolve() in settings.allowed_read_dirs
        assert dir2.resolve() in settings.allowed_read_dirs
