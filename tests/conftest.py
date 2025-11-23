"""Pytest configuration and shared fixtures with explicit dependency injection."""

from pathlib import Path

import pytest

from reversecore_mcp.core import security
from reversecore_mcp.core.config import Config
from reversecore_mcp.core.security import WorkspaceConfig


@pytest.fixture
def workspace_dirs(tmp_path):
    """Provision a writable workspace and read-only directory for tests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return workspace, rules_dir


@pytest.fixture
def workspace_dir(workspace_dirs):
    """Return the workspace directory path."""
    workspace, _ = workspace_dirs
    return workspace


@pytest.fixture
def read_only_dir(workspace_dirs):
    """Return the dedicated read-only directory path."""
    _, read_dir = workspace_dirs
    return read_dir


@pytest.fixture
def workspace_config(workspace_dirs) -> WorkspaceConfig:
    """Provide a WorkspaceConfig instance for file validation tests."""
    workspace, read_dir = workspace_dirs
    return WorkspaceConfig(workspace=workspace, read_only_dirs=(read_dir,))


@pytest.fixture
def config(workspace_dirs, tmp_path) -> Config:
    """Provide a Config instance for components that require it."""
    workspace, read_dir = workspace_dirs
    return Config(
        workspace=workspace,
        read_only_dirs=(read_dir,),
        log_level="INFO",
        log_file=tmp_path / "reversecore.log",
        log_format="human",
        structured_errors=False,
        rate_limit=60,
        lief_max_file_size=1_000_000_000,
        mcp_transport="stdio",
        default_tool_timeout=60,
    )


@pytest.fixture
def sample_binary_path(workspace_dir):
    """Create a simple test binary file inside the workspace."""
    binary_path = workspace_dir / "test_binary.bin"
    binary_path.write_bytes(b"\x00\x01\x02\x03Hello World\x00")
    return binary_path


@pytest.fixture
def patched_workspace_config(workspace_config, monkeypatch):
    """Patch the global WORKSPACE_CONFIG for modules that read it directly."""
    monkeypatch.setattr(security, "WORKSPACE_CONFIG", workspace_config)
    return workspace_config


@pytest.fixture
def patched_config(config, monkeypatch):
    """Ensure get_config() calls inside modules return the test Config."""
    monkeypatch.setattr("reversecore_mcp.core.config._CONFIG", config)
    monkeypatch.setattr("reversecore_mcp.core.config.get_config", lambda: config)

    # Note: lib_tools no longer imports get_config at module level
    # Individual tool modules import it directly from core.config
    return config

