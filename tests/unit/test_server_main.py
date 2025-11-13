"""
Unit tests for reversecore_mcp.server main() transport selection.
"""

import types
import sys
import importlib

import pytest


def test_server_main_stdio(monkeypatch, tmp_path):
    # Set LOG_FILE to writable temp path BEFORE import to avoid /var/log permission issues
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "app.log"))
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    
    # Reload settings to pick up new environment variables
    from reversecore_mcp.core.config import reload_settings
    reload_settings()

    # Ensure fresh import
    sys.modules.pop("reversecore_mcp.server", None)
    import reversecore_mcp.server as server

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
    # Set LOG_FILE to writable temp path BEFORE import
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "app.log"))
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    
    # Reload settings to pick up new environment variables
    from reversecore_mcp.core.config import reload_settings
    reload_settings()

    # Mock uvicorn module before import
    called = {"uvicorn_run": False}

    class _Uvicorn:
        @staticmethod
        def run(app, host: str = None, port: int = None):
            called["uvicorn_run"] = True
            called["host"] = host
            called["port"] = port

    monkeypatch.setitem(sys.modules, "uvicorn", _Uvicorn)

    # Ensure fresh import
    sys.modules.pop("reversecore_mcp.server", None)
    import reversecore_mcp.server as server

    # Provide a minimal FastAPI-like app with required attributes
    class _App:
        def __init__(self):
            self.state = types.SimpleNamespace()
        def add_exception_handler(self, *args, **kwargs):
            return None
        def middleware(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator

    monkeypatch.setattr(server.mcp, "app", _App(), raising=True)

    server.main()

    assert called["uvicorn_run"] is True
    assert called["host"] == "0.0.0.0"
    assert called["port"] == 8000
