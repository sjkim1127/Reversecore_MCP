"""
Pytest configuration and shared fixtures.
"""

import os
import tempfile
from pathlib import Path

import pytest

# Set test environment variables
os.environ["REVERSECORE_WORKSPACE"] = str(Path(__file__).parent / "fixtures" / "workspace")
os.environ["REVERSECORE_READ_DIRS"] = str(Path(__file__).parent / "fixtures" / "rules")
os.environ["LOG_LEVEL"] = "INFO"


@pytest.fixture
def workspace_dir(tmp_path):
    """Create a temporary workspace directory for tests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


@pytest.fixture
def sample_binary_path(workspace_dir):
    """Create a simple test binary file."""
    binary_path = workspace_dir / "test_binary.bin"
    # Create a simple binary with some data
    binary_path.write_bytes(b"\x00\x01\x02\x03Hello World\x00")
    return str(binary_path)

