"""
Unit tests for server main() transport selection.
"""

import sys

import pytest


def test_server_main_stdio(monkeypatch, tmp_path):
    # Set LOG_FILE to writable temp path BEFORE import to avoid /var/log permission issues
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "app.log"))
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")

    # Set up workspace and read dirs for path validation
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    read_dir = tmp_path / "rules"
    read_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
    monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))

    # Reload settings to pick up new environment variables
    from reversecore_mcp.core.config import reload_settings

    reload_settings()

    # Ensure fresh import
    sys.modules.pop("reversecore_mcp.server", None)
    from reversecore_mcp import server

    called = {"run": False}

    def _run(transport: str = "stdio"):
        called["run"] = True
        called["transport"] = transport

    # Patch run method only
    monkeypatch.setattr(server.mcp, "run", _run, raising=True)

    server.main()

    assert called["run"] is True
    assert called["transport"] == "stdio"


def test_server_main_http(monkeypatch, tmp_path):
    try:
        import fastapi  # noqa: F401
    except ImportError:
        pytest.skip("fastapi not installed")

    # Set LOG_FILE to writable temp path BEFORE import
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "app.log"))
    monkeypatch.setenv("MCP_TRANSPORT", "http")

    # Set up workspace and read dirs for path validation
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    read_dir = tmp_path / "rules"
    read_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
    monkeypatch.setenv("REVERSECORE_READ_DIRS", str(read_dir))

    # Reload settings to pick up new environment variables
    from reversecore_mcp.core.config import reload_settings

    reload_settings()

    # Mock uvicorn module before import using MagicMock
    # MagicMock automatically handles any attribute access
    from unittest.mock import MagicMock

    called = {"uvicorn_run": False}

    mock_uvicorn = MagicMock()

    def mock_run(app, host: str = None, port: int = None, **kwargs):
        called["uvicorn_run"] = True
        called["host"] = host
        called["port"] = port

    mock_uvicorn.run = mock_run

    monkeypatch.setitem(sys.modules, "uvicorn", mock_uvicorn)
    monkeypatch.setitem(sys.modules, "uvicorn.server", mock_uvicorn.server)

    # Ensure fresh import
    sys.modules.pop("reversecore_mcp.server", None)
    from reversecore_mcp import server

    server.main()

    assert called["uvicorn_run"] is True
    # Overridden to 127.0.0.1 because MCP_API_KEY is empty/unset (Safe Bind Address Fallback)
    assert called["host"] == "127.0.0.1"
    assert called["port"] == 8000
