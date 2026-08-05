"""VirusTotal IOC reputation lookup tool.

Queries the VirusTotal API v3 for IP addresses, domain names, URLs,
and file hashes extracted from binary analysis (e.g. from extract_iocs).

Requires: REVERSECORE_VT_API_KEY environment variable.

Available tools (MCP-registered):
    vt_lookup — Bulk IOC reputation check via VirusTotal API v3
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _classify_ioc(ioc: str) -> str:
    """Classify a single IOC string into: ip, domain, url, hash, or unknown."""
    ioc = ioc.strip()
    if _HASH_RE.match(ioc):
        return "hash"
    if _URL_RE.match(ioc):
        return "url"
    if _IPV4_RE.match(ioc):
        try:
            ipaddress.ip_address(ioc)
            return "ip"
        except ValueError:
            pass
    # Coarse domain check: has a dot, no spaces, no slashes
    if "." in ioc and " " not in ioc and "/" not in ioc:
        return "domain"
    return "unknown"


def _vt_url_for(ioc_type: str, ioc: str) -> str:
    """Return the VT API v3 endpoint URL for the given IOC."""
    import base64

    if ioc_type == "ip":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        return f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        return f"https://www.virustotal.com/api/v3/files/{ioc.lower()}"
    elif ioc_type == "url":
        # VT URL lookups require base64url-encoded URL (without padding)
        encoded = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
        return f"https://www.virustotal.com/api/v3/urls/{encoded}"
    return ""


def _extract_verdict(data: dict[str, Any], ioc_type: str) -> dict[str, Any]:
    """Extract the key reputation fields from a VT API v3 response."""
    attrs = data.get("attributes", {})
    last_analysis = attrs.get("last_analysis_stats", {})

    malicious = last_analysis.get("malicious", 0)
    suspicious = last_analysis.get("suspicious", 0)
    total = sum(last_analysis.values()) if last_analysis else 0

    # Determine verdict
    if malicious >= 5:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "suspicious"
    elif total > 0:
        verdict = "clean"
    else:
        verdict = "no_data"

    result: dict[str, Any] = {
        "verdict": verdict,
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,
        "total_engines": total,
        "reputation": attrs.get("reputation", None),
    }

    # Type-specific enrichment
    if ioc_type == "hash":
        result["meaningful_name"] = attrs.get("meaningful_name") or attrs.get("name")
        result["file_type"] = attrs.get("type_description") or attrs.get("magic")
        result["size"] = attrs.get("size")
        result["first_seen"] = attrs.get("first_submission_date")
        result["last_seen"] = attrs.get("last_analysis_date")
        # Extract top malware family tags
        popular_tags = attrs.get("popular_threat_classification", {})
        result["threat_labels"] = [
            lbl.get("value") for lbl in popular_tags.get("popular_threat_name", [])
        ][:5]

    elif ioc_type in ("ip", "domain"):
        result["country"] = attrs.get("country")
        result["as_owner"] = attrs.get("as_owner")
        result["network"] = attrs.get("network")
        result["last_https_certificate_date"] = attrs.get("last_https_certificate_date")

    elif ioc_type == "url":
        result["final_url"] = attrs.get("last_final_url") or attrs.get("url")
        result["title"] = attrs.get("title")
        result["last_analysis_date"] = attrs.get("last_analysis_date")

    return result


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------


@log_execution(tool_name="vt_lookup")
@track_metrics("vt_lookup")
@handle_tool_errors
async def vt_lookup(
    iocs: list[str],
    api_key: str | None = None,
) -> ToolResult:
    """Look up IOC reputation using the VirusTotal API v3.

    Accepts a list of file hashes (MD5/SHA1/SHA256), IP addresses, domain
    names, and URLs. Returns per-IOC verdict, detection counts, and
    enrichment data from VirusTotal's 70+ security vendors.

    **API key required**: Set ``REVERSECORE_VT_API_KEY`` environment variable,
    or pass the key directly via the ``api_key`` parameter.

    Args:
        iocs: List of IOCs to look up (max 20 per call). Supported types:
            - File hashes: MD5 (32 chars), SHA1 (40), SHA256 (64)
            - IP addresses: IPv4 (e.g. ``8.8.8.8``)
            - Domain names: (e.g. ``evil.example.com``)
            - URLs: (e.g. ``https://evil.example.com/payload.exe``)
        api_key: VirusTotal API key. If omitted, uses ``REVERSECORE_VT_API_KEY``
            environment variable.

    Returns:
        ToolResult with per-IOC verdict dicts on success:

        .. code-block:: json

            {
              "results": [
                {
                  "ioc": "44d88612fea8a8f36de82e1278abb02f",
                  "type": "hash",
                  "verdict": "malicious",
                  "malicious_detections": 67,
                  "total_engines": 72,
                  "threat_labels": ["eicar.test"]
                }
              ],
              "summary": {"malicious": 1, "suspicious": 0, "clean": 0, "no_data": 0}
            }

    Example:
        >>> result = await vt_lookup(["44d88612fea8a8f36de82e1278abb02f", "1.2.3.4"])
    """
    if not iocs:
        return failure("VALIDATION_ERROR", "No IOCs provided. Pass a non-empty list.")

    # Limit to 20 IOCs per call to avoid rate limits
    if len(iocs) > 20:
        iocs = iocs[:20]
        logger.warning("vt_lookup: truncated IOC list to 20 entries")

    # Resolve API key
    cfg = get_config()
    resolved_key = api_key or cfg.vt_api_key
    if not resolved_key:
        return failure(
            "MISSING_API_KEY",
            "VirusTotal API key not configured.",
            hint=(
                "Set the REVERSECORE_VT_API_KEY environment variable, "
                "or pass api_key= directly to vt_lookup()."
            ),
        )

    timeout = cfg.vt_request_timeout

    # Classify IOCs
    classified: list[tuple[str, str]] = []  # (ioc, type)
    skipped: list[str] = []
    for ioc in iocs:
        ioc = ioc.strip()
        if not ioc:
            continue
        ioc_type = _classify_ioc(ioc)
        if ioc_type == "unknown":
            skipped.append(ioc)
        else:
            classified.append((ioc, ioc_type))

    if not classified:
        return failure(
            "VALIDATION_ERROR",
            "None of the provided IOCs could be classified (expected hash, IP, domain, or URL).",
            hint=f"Unclassifiable IOCs: {skipped[:5]}",
        )

    # --- HTTP client ---
    try:
        import httpx
    except ImportError:
        return failure(
            "DEPENDENCY_ERROR",
            "httpx is required for vt_lookup. Install it: pip install httpx",
        )

    headers = {"x-apikey": resolved_key, "Accept": "application/json"}
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        semaphore = asyncio.Semaphore(4)  # max 4 concurrent VT requests

        async def _fetch(ioc: str, ioc_type: str) -> None:
            url = _vt_url_for(ioc_type, ioc)
            if not url:
                errors.append({"ioc": ioc, "error": "Could not build VT URL"})
                return
            async with semaphore:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.json()
                        verdict = _extract_verdict(body.get("data", {}), ioc_type)
                        verdict["ioc"] = ioc
                        verdict["type"] = ioc_type
                        results.append(verdict)
                    elif resp.status_code == 404:
                        results.append(
                            {
                                "ioc": ioc,
                                "type": ioc_type,
                                "verdict": "not_found",
                                "malicious_detections": 0,
                                "total_engines": 0,
                            }
                        )
                    elif resp.status_code == 401:
                        errors.append({"ioc": ioc, "error": "Invalid API key (HTTP 401)"})
                    elif resp.status_code == 429:
                        errors.append(
                            {"ioc": ioc, "error": "VirusTotal rate limit exceeded (HTTP 429)"}
                        )
                    else:
                        errors.append(
                            {"ioc": ioc, "error": f"VT API returned HTTP {resp.status_code}"}
                        )
                except httpx.TimeoutException:
                    errors.append({"ioc": ioc, "error": f"Request timed out after {timeout}s"})
                except Exception as exc:
                    errors.append({"ioc": ioc, "error": str(exc)})

        await asyncio.gather(*[_fetch(ioc, ioc_type) for ioc, ioc_type in classified])

    # Build summary
    summary: dict[str, int] = {
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
        "no_data": 0,
        "not_found": 0,
    }
    for r in results:
        v = r.get("verdict", "no_data")
        summary[v] = summary.get(v, 0) + 1

    return success(
        {
            "results": results,
            "summary": summary,
            "skipped_unclassifiable": skipped,
            "errors": errors,
            "queried": len(classified),
        },
        total_malicious=summary["malicious"],
        total_suspicious=summary["suspicious"],
    )
