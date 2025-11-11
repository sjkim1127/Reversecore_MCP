"""
Unit tests for reversecore_mcp.server main() transport selection.
"""

import types
import sys

import pytest


def test_server_main_stdio(monkeypatch):
    import reversecore_mcp.server as server

    # Force stdio mode
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")

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


def test_server_main_http(monkeypatch):
    # Import server fresh to ensure state
    import importlib
    import reversecore_mcp.server as server

    # Force http mode
    monkeypatch.setenv("MCP_TRANSPORT", "http")

    # Mock uvicorn module
    called = {"uvicorn_run": False}

    class _Uvicorn:
        @staticmethod
        def run(app, host: str = None, port: int = None):
            called["uvicorn_run"] = True
            called["host"] = host
            called["port"] = port

    monkeypatch.setitem(sys.modules, "uvicorn", _Uvicorn)

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
