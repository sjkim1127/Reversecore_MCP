"""
Pytest configuration and shared fixtures.
"""

import os
import tempfile
from pathlib import Path

import pytest

# Set test environment variables (will be overridden by individual tests)
os.environ["LOG_LEVEL"] = "INFO"


@pytest.fixture(autouse=True)
def reset_workspace_env(monkeypatch, tmp_path):
    """Automatically set workspace environment for each test using tmp_path.

    Note: Do not create the directory here to avoid double-creation with
    other fixtures. Just set the environment variables. The `workspace_dir`
    fixture is responsible for creating the directory.
    """
    workspace = tmp_path / "workspace"

    # Set environment variables for this test
    # security.py uses _get_allowed_workspace() which reads env vars dynamically
    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
    monkeypatch.setenv("REVERSECORE_READ_DIRS", str(tmp_path / "rules"))
    
    # Reload settings to pick up new environment variables
    # This is critical because get_settings() uses a singleton pattern
    from reversecore_mcp.core.config import reload_settings
    reload_settings()

    return workspace


@pytest.fixture
def workspace_dir(tmp_path):
    """Create a temporary workspace directory for tests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def sample_binary_path(workspace_dir, monkeypatch):
    """Create a simple test binary file."""
    # Ensure workspace env is set for this test
    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace_dir))

    binary_path = workspace_dir / "test_binary.bin"
    # Create a simple binary with some data
    binary_path.write_bytes(b"\x00\x01\x02\x03Hello World\x00")
    return str(binary_path)

