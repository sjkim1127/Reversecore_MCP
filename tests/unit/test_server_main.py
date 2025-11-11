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

    # Ensure fresh import
    sys.modules.pop("reversecore_mcp.server", None)
    import reversecore_mcp.server as server

    called = {"run": False}

    class _MCP:
        def run(self, transport: str = "stdio"):
            called["run"] = True
            called["transport"] = transport

    # Replace server.mcp with dummy
    monkeypatch.setattr(server, "mcp", _MCP(), raising=True)

    server.main()

    assert called["run"] is True
    assert called["transport"] == "stdio"


def test_server_main_http(monkeypatch, tmp_path):
    # Set LOG_FILE to writable temp path BEFORE import
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "app.log"))
    monkeypatch.setenv("MCP_TRANSPORT", "http")

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

    # Replace server.mcp.app with dummy for uvicorn.run signature
    class _App:
        pass

    class _MCP2:
        def __init__(self):
            self.app = _App()
        def run(self, transport: str = "stdio"):
            # Should not be called in http mode
            raise AssertionError("mcp.run should not be called in http mode")

    monkeypatch.setattr(server, "mcp", _MCP2(), raising=True)

    server.main()

    assert called["uvicorn_run"] is True
    assert called["host"] == "0.0.0.0"
    assert called["port"] == 8000
