"""Unit tests for the lightweight Config loader."""

from pathlib import Path

import pytest

from reversecore_mcp.core.config import Config, get_config, reset_config


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
        assert config.log_file == Path("/tmp/reversecore/app.log")
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
        monkeypatch.setenv("STRUCTURED_ERRORS", "true")
        monkeypatch.setenv("RATE_LIMIT", "120")
        monkeypatch.setenv("LIEF_MAX_FILE_SIZE", "2048")
        monkeypatch.setenv("MCP_TRANSPORT", "websocket")

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
        assert config.lief_max_file_size == 2048
        assert config.mcp_transport == "websocket"


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
        workspace = tmp_path / "missing"
        read_dir = tmp_path / "rules"
        read_dir.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()

        with pytest.raises(ValueError, match="Workspace directory does not exist"):
            config.validate_paths()

    def test_validate_paths_workspace_not_directory(self, monkeypatch, tmp_path):
        workspace = tmp_path / "file.txt"
        workspace.write_text("not a dir")
        read_dir = tmp_path / "rules"
        read_dir.mkdir()

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()

        with pytest.raises(ValueError, match="Workspace path is not a directory"):
            config.validate_paths()

    def test_validate_paths_read_dir_missing(self, monkeypatch, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        read_dir = tmp_path / "missing"

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()

        with pytest.raises(ValueError, match="Read directory does not exist"):
            config.validate_paths()

    def test_validate_paths_read_dir_not_directory(self, monkeypatch, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        read_dir = tmp_path / "file.txt"
        read_dir.write_text("not a dir")

        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))
        config = reset_config()

        with pytest.raises(ValueError, match="Read directory path is not a directory"):
            config.validate_paths()

