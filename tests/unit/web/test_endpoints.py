"""Unit tests for reversecore_mcp/web/endpoints.py.

Uses FastAPI TestClient with comprehensive mocking of external dependencies
(filesystem, tool availability, metrics) so tests run in CI without radare2
or other binaries installed.
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from reversecore_mcp.web.endpoints import router

# ---------------------------------------------------------------------------
# TestClient fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path: Path):
    """Return a TestClient whose Config points to a real tmp workspace."""
    app = FastAPI()
    app.include_router(router)

    mock_cfg = MagicMock()
    mock_cfg.api_key = "test-secret"
    mock_cfg.workspace = tmp_path
    mock_cfg.max_upload_size = 10_000_000  # 10 MB

    with patch("reversecore_mcp.web.endpoints.get_config", return_value=mock_cfg):
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


@pytest.fixture()
def client_no_key(tmp_path: Path):
    """TestClient where no API key is configured."""
    app = FastAPI()
    app.include_router(router)

    mock_cfg = MagicMock()
    mock_cfg.api_key = None
    mock_cfg.workspace = tmp_path

    with patch("reversecore_mcp.web.endpoints.get_config", return_value=mock_cfg):
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_returns_alive(self, client):
        body = client.get("/health").json()
        assert body == {"status": "alive"}

    def test_no_authentication_required(self, client_no_key):
        r = client_no_key.get("/health")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# /health/live
# ---------------------------------------------------------------------------


class TestLivenessEndpoint:
    def test_returns_200(self, client):
        assert client.get("/health/live").status_code == 200

    def test_returns_alive_json(self, client):
        assert client.get("/health/live").json() == {"status": "alive"}


# ---------------------------------------------------------------------------
# /health/ready
# ---------------------------------------------------------------------------


class TestReadinessEndpoint:
    def test_ready_when_workspace_and_radare2_present(self, client, tmp_path):
        with patch(
            "reversecore_mcp.web.endpoints.shutil.which",
            return_value="/usr/bin/radare2",
        ):
            r = client.get("/health/ready")
        assert r.status_code == 200
        assert r.json()["ready"] is True

    def test_not_ready_when_radare2_missing(self, client):
        with patch("reversecore_mcp.web.endpoints.shutil.which", return_value=None):
            r = client.get("/health/ready")
        assert r.status_code == 503
        assert r.json()["ready"] is False

    def test_not_ready_when_workspace_missing(self, tmp_path):
        app = FastAPI()
        app.include_router(router)
        mock_cfg = MagicMock()
        mock_cfg.api_key = "key"
        mock_cfg.workspace = tmp_path / "nonexistent"
        with patch("reversecore_mcp.web.endpoints.get_config", return_value=mock_cfg):
            with patch(
                "reversecore_mcp.web.endpoints.shutil.which",
                return_value="/usr/bin/radare2",
            ):
                with TestClient(app, raise_server_exceptions=False) as c:
                    r = c.get("/health/ready")
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# /health/details
# ---------------------------------------------------------------------------


class TestHealthDetailsEndpoint:
    def test_requires_api_key_configured(self, client_no_key):
        r = client_no_key.get("/health/details")
        assert r.status_code == 403

    def test_returns_200_with_valid_key(self, client):
        with patch("reversecore_mcp.web.endpoints.shutil.which", return_value=None):
            r = client.get("/health/details")
        assert r.status_code == 200

    def test_response_contains_required_fields(self, client):
        with patch("reversecore_mcp.web.endpoints.shutil.which", return_value=None):
            body = client.get("/health/details").json()
        for field in ("status", "service", "version", "timestamp", "dependencies"):
            assert field in body, f"Missing field: {field}"

    def test_status_degraded_when_radare2_missing(self, client):
        with patch("reversecore_mcp.web.endpoints.shutil.which", return_value=None):
            body = client.get("/health/details").json()
        assert body["status"] == "degraded"
        assert body["dependencies"]["radare2"]["status"] == "unavailable"

    def test_status_healthy_when_all_tools_present(self, client):
        with patch("reversecore_mcp.web.endpoints.shutil.which", return_value="/usr/bin/tool"):
            body = client.get("/health/details").json()
        assert body["status"] == "healthy"

    def test_dependency_fields_present(self, client):
        with patch("reversecore_mcp.web.endpoints.shutil.which", return_value=None):
            body = client.get("/health/details").json()
        deps = body["dependencies"]
        for dep in ("radare2", "java", "graphviz", "yara", "binwalk"):
            assert dep in deps


# ---------------------------------------------------------------------------
# /metrics
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    def test_returns_200(self, client):
        with patch(
            "reversecore_mcp.web.endpoints.metrics_collector.get_metrics",
            return_value={"tool_calls": 0},
        ):
            r = client.get("/metrics")
        assert r.status_code == 200

    def test_returns_json(self, client):
        with patch(
            "reversecore_mcp.web.endpoints.metrics_collector.get_metrics",
            return_value={"tool_calls": 42},
        ):
            body = client.get("/metrics").json()
        assert body["tool_calls"] == 42


# ---------------------------------------------------------------------------
# /upload
# ---------------------------------------------------------------------------


class TestUploadEndpoint:
    def _make_file(self, content: bytes = b"\x00" * 16, filename: str = "sample.bin"):
        return {"file": (filename, io.BytesIO(content), "application/octet-stream")}

    def test_upload_success(self, client):
        with (
            patch(
                "reversecore_mcp.web.endpoints._validate_file_magic",
                new_callable=AsyncMock,
            ),
            patch("reversecore_mcp.web.endpoints.audit_logger"),
            patch("reversecore_mcp.web.endpoints.invalidate_path_cache"),
        ):
            r = client.post("/upload", files=self._make_file())
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"
        assert "filename" in body
        assert "size" in body

    def test_upload_disabled_returns_400(self, client):
        with patch.dict("os.environ", {"REVERSECORE_UPLOAD_ENABLED": "false"}):
            r = client.post("/upload", files=self._make_file())
        assert r.status_code == 400
        assert "disabled" in r.json()["message"].lower()

    def test_upload_no_file_returns_422(self, client):
        r = client.post("/upload")
        assert r.status_code == 422

    def test_upload_file_too_large_returns_413(self, tmp_path):
        app = FastAPI()
        app.include_router(router)
        mock_cfg = MagicMock()
        mock_cfg.api_key = "key"
        mock_cfg.workspace = tmp_path
        mock_cfg.max_upload_size = 10  # 10 bytes — tiny limit

        with patch("reversecore_mcp.web.endpoints.get_config", return_value=mock_cfg):
            with TestClient(app, raise_server_exceptions=False) as c:
                with patch("reversecore_mcp.web.endpoints.invalidate_path_cache"):
                    r = c.post(
                        "/upload",
                        files={
                            "file": (
                                "big.bin",
                                io.BytesIO(b"A" * 100),
                                "application/octet-stream",
                            )
                        },
                    )
        assert r.status_code == 413

    def test_upload_magic_validation_failure_returns_500(self, client):
        with (
            patch(
                "reversecore_mcp.web.endpoints._validate_file_magic",
                new_callable=AsyncMock,
                side_effect=ValueError("Security Alert: executable"),
            ),
            patch("reversecore_mcp.web.endpoints.audit_logger"),
            patch("reversecore_mcp.web.endpoints.invalidate_path_cache"),
        ):
            r = client.post("/upload", files=self._make_file())
        # rejected by magic validation — endpoint catches and returns 500
        assert r.status_code == 500

    def test_upload_sanitizes_path_traversal_filename(self, client):
        with (
            patch(
                "reversecore_mcp.web.endpoints._validate_file_magic",
                new_callable=AsyncMock,
            ),
            patch("reversecore_mcp.web.endpoints.audit_logger"),
            patch("reversecore_mcp.web.endpoints.invalidate_path_cache"),
        ):
            r = client.post(
                "/upload",
                files={"file": ("../../etc/passwd", io.BytesIO(b"data"), "text/plain")},
            )
        if r.status_code == 200:
            filename = r.json()["filename"]
            assert ".." not in filename
            assert "/" not in filename


# ---------------------------------------------------------------------------
# _validate_file_magic helper
# ---------------------------------------------------------------------------


class TestValidateFileMagic:
    @pytest.mark.asyncio
    async def test_elf_in_txt_extension_raises(self, tmp_path):
        from reversecore_mcp.web.endpoints import _validate_file_magic

        f = tmp_path / "malicious.txt"
        f.write_bytes(b"\x7fELF" + b"\x00" * 20)

        with patch("reversecore_mcp.web.endpoints.magic", None):
            with pytest.raises(ValueError, match="Security Alert"):
                await _validate_file_magic(str(f), "malicious.txt")

    @pytest.mark.asyncio
    async def test_normal_binary_ok(self, tmp_path):
        from reversecore_mcp.web.endpoints import _validate_file_magic

        f = tmp_path / "sample.bin"
        f.write_bytes(b"\x7fELF" + b"\x00" * 20)

        with patch("reversecore_mcp.web.endpoints.magic", None):
            # .bin extension is not in the safe list so no error expected
            await _validate_file_magic(str(f), "sample.bin")

    @pytest.mark.asyncio
    async def test_pe_in_pdf_extension_raises(self, tmp_path):
        from reversecore_mcp.web.endpoints import _validate_file_magic

        f = tmp_path / "invoice.pdf"
        f.write_bytes(b"MZ" + b"\x00" * 20)

        with patch("reversecore_mcp.web.endpoints.magic", None):
            with pytest.raises(ValueError, match="Security Alert"):
                await _validate_file_magic(str(f), "invoice.pdf")
