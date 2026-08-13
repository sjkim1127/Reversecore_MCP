"""Unit tests for the vt_lookup VirusTotal integration tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.tools.analysis.vt_lookup import (
    _classify_ioc,
    _extract_verdict,
    _vt_url_for,
)

# ---------------------------------------------------------------------------
# _classify_ioc
# ---------------------------------------------------------------------------


class TestClassifyIoc:
    def test_md5_hash(self):
        assert _classify_ioc("44d88612fea8a8f36de82e1278abb02f") == "hash"

    def test_sha1_hash(self):
        assert _classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_sha256_hash(self):
        assert (
            _classify_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            == "hash"
        )

    def test_ipv4_address(self):
        assert _classify_ioc("8.8.8.8") == "ip"
        assert _classify_ioc("192.168.1.1") == "ip"

    def test_domain(self):
        assert _classify_ioc("evil.example.com") == "domain"
        assert _classify_ioc("malware-c2.ru") == "domain"

    def test_http_url(self):
        assert _classify_ioc("http://evil.com/payload.exe") == "url"

    def test_https_url(self):
        assert _classify_ioc("https://phishing.example.com/login") == "url"

    def test_unknown(self):
        assert _classify_ioc("not-an-ioc") == "unknown"
        assert _classify_ioc("") == "unknown"
        assert _classify_ioc("random string with spaces") == "unknown"

    def test_strips_whitespace(self):
        assert _classify_ioc("  8.8.8.8  ") == "ip"

    def test_case_insensitive_hash(self):
        assert _classify_ioc("44D88612FEA8A8F36DE82E1278ABB02F") == "hash"


# ---------------------------------------------------------------------------
# _vt_url_for
# ---------------------------------------------------------------------------


class TestVtUrlFor:
    def test_ip_url(self):
        url = _vt_url_for("ip", "1.2.3.4")
        assert url == "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"

    def test_domain_url(self):
        url = _vt_url_for("domain", "evil.example.com")
        assert url == "https://www.virustotal.com/api/v3/domains/evil.example.com"

    def test_hash_url(self):
        url = _vt_url_for("hash", "44d88612fea8a8f36de82e1278abb02f")
        assert "files/44d88612fea8a8f36de82e1278abb02f" in url

    def test_hash_lowercased(self):
        url = _vt_url_for("hash", "44D88612FEA8A8F36DE82E1278ABB02F")
        assert "44d88612fea8a8f36de82e1278abb02f" in url

    def test_url_type_base64_encoded(self):
        vt_url = _vt_url_for("url", "https://evil.com/payload")
        # Base64url encoded, no padding
        assert "urls/" in vt_url
        assert "=" not in vt_url.split("urls/")[1]

    def test_unknown_type_returns_empty(self):
        url = _vt_url_for("unknown", "garbage")
        assert url == ""


# ---------------------------------------------------------------------------
# _extract_verdict
# ---------------------------------------------------------------------------


class TestExtractVerdict:
    def _make_data(self, malicious=0, suspicious=0, undetected=10, ioc_type="hash"):
        return {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": 0,
                },
                "reputation": -5 if malicious > 0 else 0,
            }
        }

    def test_malicious_verdict(self):
        data = self._make_data(malicious=60)
        verdict = _extract_verdict(data, "hash")
        assert verdict["verdict"] == "malicious"
        assert verdict["malicious_detections"] == 60

    def test_suspicious_verdict_low_malicious(self):
        data = self._make_data(malicious=2)
        verdict = _extract_verdict(data, "ip")
        assert verdict["verdict"] == "suspicious"

    def test_suspicious_verdict_high_suspicious(self):
        data = self._make_data(suspicious=5)
        verdict = _extract_verdict(data, "domain")
        assert verdict["verdict"] == "suspicious"

    def test_clean_verdict(self):
        data = self._make_data(malicious=0, suspicious=0)
        verdict = _extract_verdict(data, "hash")
        assert verdict["verdict"] == "clean"

    def test_no_data_verdict(self):
        verdict = _extract_verdict({"attributes": {}}, "hash")
        assert verdict["verdict"] == "no_data"

    def test_hash_enrichment_fields(self):
        data = {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "undetected": 5},
                "meaningful_name": "eicar.exe",
                "type_description": "PE32",
                "size": 68,
                "first_submission_date": 1234567890,
                "last_analysis_date": 1234567999,
                "popular_threat_classification": {
                    "popular_threat_name": [
                        {"value": "eicar.test"},
                        {"value": "test.file"},
                    ]
                },
            }
        }
        verdict = _extract_verdict(data, "hash")
        assert verdict["meaningful_name"] == "eicar.exe"
        assert verdict["file_type"] == "PE32"
        assert verdict["size"] == 68
        assert "eicar.test" in verdict["threat_labels"]

    def test_ip_enrichment_fields(self):
        data = {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "undetected": 3},
                "country": "RU",
                "as_owner": "AS1234 Evil Corp",
                "network": "1.2.3.0/24",
            }
        }
        verdict = _extract_verdict(data, "ip")
        assert verdict["country"] == "RU"
        assert verdict["as_owner"] == "AS1234 Evil Corp"

    def test_url_enrichment_fields(self):
        data = {
            "attributes": {
                "last_analysis_stats": {"malicious": 1, "undetected": 9},
                "last_final_url": "https://evil.com/redirect",
                "title": "Phishing Page",
                "last_analysis_date": 1234567890,
            }
        }
        verdict = _extract_verdict(data, "url")
        assert verdict["final_url"] == "https://evil.com/redirect"
        assert verdict["title"] == "Phishing Page"


# ---------------------------------------------------------------------------
# vt_lookup (integration-style unit tests using httpx mocking)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestVtLookup:
    async def test_empty_iocs_returns_failure(self):
        from reversecore_mcp.tools.analysis.vt_lookup import vt_lookup

        result = await vt_lookup([])
        assert result.status == "error"
        assert "No IOCs" in result.message

    async def test_missing_api_key_returns_failure(self):
        from reversecore_mcp.tools.analysis.vt_lookup import vt_lookup

        with patch("reversecore_mcp.tools.analysis.vt_lookup.get_config") as mock_cfg:
            mock_cfg.return_value.vt_api_key = ""
            mock_cfg.return_value.vt_request_timeout = 30
            result = await vt_lookup(["8.8.8.8"])
        assert result.status == "error"
        assert "API key" in result.message

    async def test_all_unknown_iocs_returns_failure(self):
        from reversecore_mcp.tools.analysis.vt_lookup import vt_lookup

        with patch("reversecore_mcp.tools.analysis.vt_lookup.get_config") as mock_cfg:
            mock_cfg.return_value.vt_api_key = "test-key"
            mock_cfg.return_value.vt_request_timeout = 30
            result = await vt_lookup(["not-ioc-1", "not-ioc-2"])
        assert result.status == "error"
        assert "classified" in result.message.lower()

    async def test_successful_hash_lookup(self):
        """Mock a 200 response for a hash lookup."""
        from reversecore_mcp.tools.analysis.vt_lookup import vt_lookup

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 67,
                        "suspicious": 0,
                        "undetected": 5,
                    },
                    "reputation": -50,
                    "meaningful_name": "eicar.exe",
                    "type_description": "PE32",
                    "size": 68,
                    "first_submission_date": 1000000,
                    "last_analysis_date": 2000000,
                }
            }
        }

        with (
            patch("reversecore_mcp.tools.analysis.vt_lookup.get_config") as mock_cfg,
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            mock_cfg.return_value.vt_api_key = "fake-api-key"
            mock_cfg.return_value.vt_request_timeout = 30

            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = await vt_lookup(["44d88612fea8a8f36de82e1278abb02f"])

        assert result.status == "success"
        data = result.data
        assert data["summary"]["malicious"] == 1
        assert len(data["results"]) == 1
        assert data["results"][0]["verdict"] == "malicious"

    async def test_404_gives_not_found_verdict(self):
        from reversecore_mcp.tools.analysis.vt_lookup import vt_lookup

        mock_response = MagicMock()
        mock_response.status_code = 404

        with (
            patch("reversecore_mcp.tools.analysis.vt_lookup.get_config") as mock_cfg,
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            mock_cfg.return_value.vt_api_key = "fake-key"
            mock_cfg.return_value.vt_request_timeout = 30

            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = await vt_lookup(["8.8.8.8"])

        assert result.status == "success"
        assert result.data["results"][0]["verdict"] == "not_found"

    async def test_truncates_to_20_iocs(self):
        from reversecore_mcp.tools.analysis.vt_lookup import vt_lookup

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"attributes": {"last_analysis_stats": {}}}}

        with (
            patch("reversecore_mcp.tools.analysis.vt_lookup.get_config") as mock_cfg,
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            mock_cfg.return_value.vt_api_key = "fake-key"
            mock_cfg.return_value.vt_request_timeout = 30

            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            # 25 IPs, should be truncated to 20
            iocs = [f"1.2.3.{i}" for i in range(25)]
            result = await vt_lookup(iocs, api_key="fake-key")

        assert result.status == "success"
        assert result.data["queried"] == 20
