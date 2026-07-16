"""Unit tests for dashboard HTMX fragments."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from reversecore_mcp.dashboard import get_router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(get_router())
    return TestClient(app)


def test_metrics_fragment(client):
    """Test that the metrics fragment returns HTML and 200 OK."""
    response = client.get("/dashboard/api/metrics-fragment")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "stats-grid" in response.text
    assert "Total Requests" in response.text


def test_files_fragment(client):
    """Test that the files fragment returns HTML and 200 OK."""
    response = client.get("/dashboard/api/files-fragment")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

    # It might return empty state or table depending on the workspace fixture
    if "file-table" in response.text:
        assert "Filename" in response.text
    else:
        assert "No files in workspace" in response.text
