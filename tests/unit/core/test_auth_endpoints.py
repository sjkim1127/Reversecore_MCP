"""
Unit tests for API key authentication and secure binding logic.
"""

import os
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from reversecore_mcp.server import APIKeyAuthMiddleware


def test_api_key_auth_middleware_exempt_paths():
    """Test that exempt paths bypass authentication."""
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    app.add_middleware(APIKeyAuthMiddleware, api_key="secret-key")
    client = TestClient(app)

    # Health check is exempt and should return 200 without headers
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_api_key_auth_middleware_blocked_without_key():
    """Test that non-exempt paths are blocked with 403 when key is missing."""
    app = FastAPI()

    @app.get("/metrics")
    def metrics():
        return {"metrics": "data"}

    app.add_middleware(APIKeyAuthMiddleware, api_key="secret-key")
    client = TestClient(app)

    response = client.get("/metrics")
    assert response.status_code == 403
    assert "Invalid or missing API key" in response.json()["detail"]


def test_api_key_auth_middleware_valid_x_api_key():
    """Test that valid key via X-API-Key header is accepted."""
    app = FastAPI()

    @app.get("/metrics")
    def metrics():
        return {"metrics": "data"}

    app.add_middleware(APIKeyAuthMiddleware, api_key="secret-key")
    client = TestClient(app)

    response = client.get("/metrics", headers={"X-API-Key": "secret-key"})
    assert response.status_code == 200
    assert response.json() == {"metrics": "data"}


def test_api_key_auth_middleware_valid_bearer_token():
    """Test that valid key via Authorization Bearer header is accepted."""
    app = FastAPI()

    @app.get("/metrics")
    def metrics():
        return {"metrics": "data"}

    app.add_middleware(APIKeyAuthMiddleware, api_key="secret-key")
    client = TestClient(app)

    response = client.get("/metrics", headers={"Authorization": "Bearer secret-key"})
    assert response.status_code == 200
    assert response.json() == {"metrics": "data"}


def test_api_key_auth_middleware_invalid_key():
    """Test that invalid key is rejected with 403."""
    app = FastAPI()

    @app.get("/metrics")
    def metrics():
        return {"metrics": "data"}

    app.add_middleware(APIKeyAuthMiddleware, api_key="secret-key")
    client = TestClient(app)

    response = client.get("/metrics", headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 403


@patch("uvicorn.run")
@patch("reversecore_mcp.server.FastMCP.http_app")
@patch("reversecore_mcp.server.get_config")
def test_safe_bind_address_fallback_no_api_key(mock_get_config, mock_http_app, mock_uvicorn_run):
    """Test that host is overridden to 127.0.0.1 when binding to external interface without API key."""
    from reversecore_mcp.server import main

    # Mock settings
    mock_settings = MagicMock()
    mock_settings.mcp_transport = "http"
    mock_settings.host = "0.0.0.0"
    mock_settings.port = 8000
    mock_get_config.return_value = mock_settings

    # Run server main with empty API key env
    with patch.dict(os.environ, {}, clear=True):
        if "MCP_API_KEY" in os.environ:
            del os.environ["MCP_API_KEY"]

        # Call main (will run HTTP setup since mcp_transport="http")
        main()

        # Verify uvicorn.run was called with overridden host "127.0.0.1" instead of "0.0.0.0"
        mock_uvicorn_run.assert_called_once()
        args, kwargs = mock_uvicorn_run.call_args
        assert kwargs.get("host") == "127.0.0.1"


@patch("uvicorn.run")
@patch("reversecore_mcp.server.FastMCP.http_app")
@patch("reversecore_mcp.server.get_config")
def test_safe_bind_address_with_api_key(mock_get_config, mock_http_app, mock_uvicorn_run):
    """Test that host is NOT overridden when binding to external interface with API key."""
    from reversecore_mcp.server import main

    # Mock settings
    mock_settings = MagicMock()
    mock_settings.mcp_transport = "http"
    mock_settings.host = "0.0.0.0"
    mock_settings.port = 8000
    mock_get_config.return_value = mock_settings

    # Run server main with API key env
    with patch.dict(os.environ, {"MCP_API_KEY": "testkey"}):
        main()

        # Verify uvicorn.run was called with original host "0.0.0.0"
        mock_uvicorn_run.assert_called_once()
        args, kwargs = mock_uvicorn_run.call_args
        assert kwargs.get("host") == "0.0.0.0"
