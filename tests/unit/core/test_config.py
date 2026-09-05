"""Unit tests for the pydantic-settings based Config loader."""

from pathlib import Path

import pytest

from reversecore_mcp.core.config import (
    Config,
    LogFormat,
    Settings,
    TransportMode,
    get_config,
    get_settings,
    reset_config,
)


def _provision_env(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    read_dir = tmp_path / "rules"
    read_dir.mkdir()
    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
    monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
    return workspace, read_dir


class TestConfigDefaults:
    """Verify default values and parsing behavior."""

    def test_default_values(self, monkeypatch, tmp_path):
        """Config.from_env should honor module defaults when env vars are unset."""
        workspace, read_dir = _provision_env(monkeypatch, tmp_path)
        for key in (
            "LOG_LEVEL",
            "LOG_FILE",
            "LOG_FORMAT",
            "STRUCTURED_ERRORS",
            "RATE_LIMIT",
            "LIEF_MAX_FILE_SIZE",
            "MCP_TRANSPORT",
        ):
            monkeypatch.delenv(key, raising=False)

        config = reset_config()

        assert config.workspace == workspace
        assert config.read_only_dirs == (read_dir,)
        assert config.log_level == "INFO"
        # Log file path depends on platform
        assert "reversecore" in str(config.log_file).lower()
        assert config.log_format == "human"
        assert config.structured_errors is False
        assert config.rate_limit == 60
        assert config.lief_max_file_size == 1_000_000_000
        assert config.mcp_transport == "stdio"

    def test_environment_overrides(self, monkeypatch, tmp_path):
        """Environment variables should override defaults when present."""
        workspace = tmp_path / "custom-workspace"
        workspace.mkdir()
        read_dir_one = tmp_path / "rules1"
        read_dir_two = tmp_path / "rules2"
        read_dir_one.mkdir()
        read_dir_two.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", f" {read_dir_one} , {read_dir_two} ")
        monkeypatch.setenv("LOG_LEVEL", "debug")
        monkeypatch.setenv("LOG_FILE", str(tmp_path / "app.log"))
        monkeypatch.setenv("LOG_FORMAT", "json")
        monkeypatch.setenv("REVERSECORE_STRUCTURED_ERRORS", "true")
        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "120")
        monkeypatch.setenv("REVERSECORE_LIEF_MAX_FILE_SIZE", "2000000")  # Must meet minimum
        monkeypatch.setenv("MCP_TRANSPORT", "http")

        config = reset_config()

        assert config.workspace == workspace.resolve()
        assert config.read_only_dirs == (
            read_dir_one.resolve(),
            read_dir_two.resolve(),
        )
        assert config.log_level == "DEBUG"
        assert config.log_file == Path(tmp_path / "app.log")
        assert config.log_format == "json"
        assert config.structured_errors is True
        assert config.rate_limit == 120
        assert config.lief_max_file_size == 2000000
        assert config.mcp_transport == "http"


class TestConfigCaching:
    """Ensure get_config/reset_config manage the singleton correctly."""

    def test_get_config_returns_cached_instance(self, monkeypatch, tmp_path):
        """Multiple calls to get_config should return the same object."""
        _provision_env(monkeypatch, tmp_path)
        reset_config()
        first = get_config()
        second = get_config()
        assert first is second

    def test_reset_config_reloads_from_env(self, monkeypatch, tmp_path):
        """reset_config should rebuild the singleton when env changes."""
        workspace_one = tmp_path / "ws1"
        workspace_two = tmp_path / "ws2"
        workspace_one.mkdir()
        workspace_two.mkdir()
        read_dir = tmp_path / "rules"
        read_dir.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_one))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config_one = reset_config()
        assert config_one.workspace == workspace_one.resolve()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_two))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config_two = reset_config()
        assert config_two.workspace == workspace_two.resolve()
        # After reset, get_config should return the latest snapshot
        assert get_config() is config_two


class TestConfigValidation:
    """Exercise Config.validate_paths edge cases."""

    def test_validate_paths_success(self, monkeypatch, tmp_path):
        workspace = tmp_path / "workspace"
        read_dir = tmp_path / "rules"
        workspace.mkdir()
        read_dir.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()

        config.validate_paths()  # Should not raise

    def test_validate_paths_workspace_missing(self, monkeypatch, tmp_path):
        """When workspace is missing and non-strict mode, config should still be created."""
        workspace = tmp_path / "missing"
        read_dir = tmp_path / "rules"
        read_dir.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))

        # With non-strict validation (default), config is created
        # The workspace path is kept as-is even if it doesn't exist
        config = reset_config()
        # In pydantic-settings, the path is kept as specified
        assert config.workspace == workspace

    def test_validate_paths_workspace_not_directory(self, monkeypatch, tmp_path):
        """When workspace is a file, it should fall back to cwd."""
        workspace = tmp_path / "file.txt"
        workspace.write_text("not a dir")
        read_dir = tmp_path / "rules"
        read_dir.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))

        # With non-strict validation (default), it should not raise
        # but the workspace path won't exist as a directory
        config = reset_config()
        # The config is created, workspace falls back to cwd
        assert config.workspace.exists()

    def test_validate_paths_read_dir_missing(self, monkeypatch, tmp_path):
        """When read dir is missing, it should be filtered out."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        read_dir = tmp_path / "missing"

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))

        # With non-strict validation (default), missing read dirs are filtered out
        config = reset_config()
        # Missing read dir should be filtered out
        assert len(config.read_only_dirs) == 0

    def test_validate_paths_read_dir_not_directory(self, monkeypatch, tmp_path):
        """When read dir is a file, it should be filtered out."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        read_dir = tmp_path / "file.txt"
        read_dir.write_text("not a dir")

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))

        # With non-strict validation (default), non-directory read paths are filtered
        config = reset_config()
        # File paths are filtered out from read_only_dirs
        assert len(config.read_only_dirs) == 0

    def test_validate_paths_strict_mode(self, monkeypatch, tmp_path):
        """When strict mode is enabled, missing paths should raise."""
        workspace = tmp_path / "missing"
        read_dir = tmp_path / "rules"
        read_dir.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        monkeypatch.setenv("REVERSECORE_STRICT_PATHS", "true")

        with pytest.raises(ValueError, match="Workspace directory does not exist"):
            reset_config()

    def test_validate_paths_strict_false_workspace_missing(self, monkeypatch, tmp_path):
        """When strict=False and workspace missing, validate_paths logs warning and does not raise."""
        read_dir = tmp_path / "rules"
        read_dir.mkdir()
        workspace_missing = tmp_path / "nonexistent"
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_missing))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()
        config.validate_paths(strict=False)  # no raise

    def test_validate_paths_workspace_not_dir_strict(self, monkeypatch, tmp_path):
        """When workspace is a file and strict=True, validate_paths raises."""
        workspace_file = tmp_path / "file.txt"
        workspace_file.write_text("x")
        read_dir = tmp_path / "rules"
        read_dir.mkdir()
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_file))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()
        with pytest.raises(ValueError, match="not a directory"):
            config.validate_paths(strict=True)

    def test_validate_paths_workspace_not_dir_non_strict(self, monkeypatch, tmp_path):
        """When workspace is a file and strict=False, validate_paths does not raise."""
        workspace_file = tmp_path / "file.txt"
        workspace_file.write_text("x")
        read_dir = tmp_path / "rules"
        read_dir.mkdir()
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_file))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()
        config.validate_paths(strict=False)

    def test_validate_paths_read_dir_missing_strict(self, monkeypatch, tmp_path):
        """When a read_only dir is missing and strict=True, validate_paths raises."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        read_missing = tmp_path / "missing_dir"
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_missing))
        # Use override so the missing path is actually in read_only_dirs (Settings filters it out)
        config = reset_config()
        config._read_only_dirs_override = (read_missing,)
        with pytest.raises(ValueError, match="Read directory does not exist"):
            config.validate_paths(strict=True)

    def test_validate_paths_read_dir_not_dir_strict(self, monkeypatch, tmp_path):
        """When a read_only path is a file and strict=True, validate_paths raises."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        read_file = tmp_path / "read_file.txt"
        read_file.write_text("x")
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_file))
        config = reset_config()
        # Settings filters out non-dirs; override to force the file path in
        config._read_only_dirs_override = (read_file,)
        with pytest.raises(ValueError, match="not a directory"):
            config.validate_paths(strict=True)

    def test_get_settings_returns_underlying_settings(self, monkeypatch, tmp_path):
        """get_settings() returns the same Settings instance as get_config()._settings."""
        _provision_env(monkeypatch, tmp_path)
        reset_config()
        settings = get_settings()
        assert settings is get_config()._settings

    def test_config_read_only_dirs_override(self, monkeypatch, tmp_path):
        """When read_only_dirs override is set, Config uses it instead of settings."""
        workspace = tmp_path / "ws_override"
        workspace.mkdir()
        read_dir = tmp_path / "rules_override"
        read_dir.mkdir()
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        settings = Settings()
        override_dirs = (tmp_path / "override1", tmp_path / "override2")
        config = Config(settings=settings, read_only_dirs=override_dirs)
        assert config.read_only_dirs == override_dirs


class TestPydanticSettings:
    """Test the pydantic-settings specific functionality."""

    def test_settings_direct_instantiation(self, tmp_path, monkeypatch):
        """Settings can be instantiated directly with values."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        monkeypatch.delenv("REVERSECORE_WORKSPACE", raising=False)
        monkeypatch.delenv("REVERSECORE_READ_DIRS", raising=False)

        settings = Settings(workspace=workspace)
        assert settings.workspace == workspace
        assert settings.log_level == "INFO"
        assert settings.log_format == LogFormat.HUMAN
        assert settings.mcp_transport == TransportMode.STDIO

    def test_log_format_enum(self, monkeypatch, tmp_path):
        """LogFormat enum should work correctly."""
        workspace, _ = _provision_env(monkeypatch, tmp_path)
        monkeypatch.setenv("LOG_FORMAT", "json")
        config = reset_config()
        assert config.log_format == "json"

        settings = get_settings()
        assert settings.log_format == LogFormat.JSON

    def test_transport_mode_enum(self, monkeypatch, tmp_path):
        """TransportMode enum should work correctly."""
        workspace, _ = _provision_env(monkeypatch, tmp_path)
        monkeypatch.setenv("MCP_TRANSPORT", "http")
        config = reset_config()
        assert config.mcp_transport == "http"

        settings = get_settings()
        assert settings.mcp_transport == TransportMode.HTTP

    def test_r2_pool_settings(self, monkeypatch, tmp_path):
        """R2 pool settings should be configurable."""
        workspace, _ = _provision_env(monkeypatch, tmp_path)
        monkeypatch.setenv("REVERSECORE_R2_POOL_SIZE", "5")
        monkeypatch.setenv("REVERSECORE_R2_POOL_TIMEOUT", "60")

        config = reset_config()
        assert config.r2_pool_size == 5
        assert config.r2_pool_timeout == 60

    def test_get_settings_returns_underlying_settings(self, monkeypatch, tmp_path):
        """get_settings should return the pydantic Settings instance."""
        workspace, _ = _provision_env(monkeypatch, tmp_path)
        reset_config()

        settings = get_settings()
        assert isinstance(settings, Settings)
        assert settings.workspace == workspace

    def test_invalid_log_level_raises_error(self, monkeypatch, tmp_path):
        """Invalid log level should raise validation error."""
        workspace, _ = _provision_env(monkeypatch, tmp_path)
        monkeypatch.setenv("LOG_LEVEL", "INVALID")

        with pytest.raises(ValueError, match="Invalid log level"):
            reset_config()

    def test_rate_limit_bounds(self, monkeypatch, tmp_path):
        """Rate limit should respect bounds."""
        workspace, _ = _provision_env(monkeypatch, tmp_path)

        # Valid rate limit
        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "500")
        config = reset_config()
        assert config.rate_limit == 500

        # Rate limit below minimum should raise error
        monkeypatch.setenv("REVERSECORE_RATE_LIMIT", "0")
        with pytest.raises(ValueError):
            reset_config()

    def test_config_wrapper_compatibility(self, monkeypatch, tmp_path):
        """Config wrapper should provide same interface as before."""
        workspace, read_dir = _provision_env(monkeypatch, tmp_path)
        config = reset_config()

        # All properties should be accessible
        assert isinstance(config.workspace, Path)
        assert isinstance(config.read_only_dirs, tuple)
        assert isinstance(config.log_level, str)
        assert isinstance(config.log_file, Path)
        assert isinstance(config.log_format, str)
        assert isinstance(config.structured_errors, bool)
        assert isinstance(config.rate_limit, int)
        assert isinstance(config.lief_max_file_size, int)
        assert isinstance(config.mcp_transport, str)
        assert isinstance(config.default_tool_timeout, int)
        assert isinstance(config.r2_pool_size, int)
        assert isinstance(config.r2_pool_timeout, int)

    def test_get_settings_no_deprecation_warning(self, monkeypatch, tmp_path):
        """get_settings() must not emit deprecation warnings."""
        import warnings

        _provision_env(monkeypatch, tmp_path)
        reset_config()
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            settings = get_settings()
            assert settings is not None
            dep_warnings = [w for w in recorded if issubclass(w.category, DeprecationWarning)]
            assert dep_warnings == []

    def test_direct_config_instantiation_emits_deprecation_warning(self):
        """Direct Config() instantiation should emit deprecation warning."""
        import warnings

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            _ = Config()
            dep_warnings = [w for w in recorded if issubclass(w.category, DeprecationWarning)]
            assert len(dep_warnings) == 1
            assert "Config wrapper is deprecated" in str(dep_warnings[0].message)
