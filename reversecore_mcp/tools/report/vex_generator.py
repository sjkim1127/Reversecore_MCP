"""
VEX (Vulnerability Exploitability eXchange) Generator Module.

This module generates CSAF 2.0 (Common Security Advisory Framework) compliant
VEX JSON documents based on vulnerability analysis results.
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# CSAF VEX Version and Profile standards
CSAF_VERSION = "2.0"
CSAF_PROFILE = "csaf_vex"

# Mapping internal confidence levels to CSAF Product Statuses
# https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3224-vulnerabilities-property---product-status
CONFIDENCE_TO_STATUS = {
    "confirmed": "known_affected",
    "likely": "under_investigation",
    "possible": "under_investigation",
    "low": "under_investigation",
    "false_positive": "known_not_affected",
}

# Mapping internal evidence levels (from vulnerability_hunter) to CSAF Justifications
# Used when status is 'known_not_affected'
EVIDENCE_TO_JUSTIFICATION = {
    "dead_code": "vulnerable_code_not_in_execute_path",
    "static_sink": "vulnerable_code_cannot_be_controlled_by_adversary",
    "guarded_sink": "vulnerable_code_cannot_be_controlled_by_adversary",
    # default fallback
    "default": "component_not_present",
}


def _generate_document_tracking(
    title: str,
    version: str = "1.0.0",
    revision_history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Generate the CSAF document tracking section."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    if not revision_history:
        revision_history = [
            {"date": now, "number": "1.0.0", "summary": "Initial VEX report generation"}
        ]

    return {
        "current_release_date": now,
        "id": f"RCMCP-VEX-{uuid.uuid4().hex[:8].upper()}",
        "initial_release_date": now,
        "revision_history": revision_history,
        "status": "final",
        "version": version,
    }


def _generate_document_publisher() -> dict[str, Any]:
    """Generate the CSAF document publisher section."""
    return {
        "category": "vendor",
        "name": "Reversecore MCP Automated Analysis",
        "namespace": "https://github.com/sjkim1127/Reversecore_MCP",
    }


def generate_csaf_vex(
    product_name: str,
    product_version: str,
    vulnerabilities: list[dict[str, Any]],
    document_title: str = "Reversecore MCP VEX Report",
) -> str:
    """Generate a CSAF 2.0 VEX JSON string.

    Args:
        product_name: Name of the analyzed binary/product.
        product_version: Version or hash of the product.
        vulnerabilities: List of dictionaries containing vulnerability findings.
            Expected keys per dict:
            - id (e.g., "CVE-2023-1234" or custom ID)
            - description
            - confidence ("confirmed", "false_positive", etc.)
            - evidence_level (optional, for justification mapping)
        document_title: Title of the VEX report.

    Returns:
        JSON string representing the CSAF VEX document.
    """
    product_id = f"CSAFPID-{uuid.uuid4().hex[:8]}"

    # Build Product Tree
    product_tree = {
        "branches": [
            {
                "category": "vendor",
                "name": "Analyzed Product",
                "branches": [
                    {
                        "category": "product_name",
                        "name": product_name,
                        "product": {
                            "name": f"{product_name} {product_version}",
                            "product_id": product_id,
                        },
                    }
                ],
            }
        ]
    }

    # Build Vulnerabilities list
    csaf_vulns = []
    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", f"VULN-{uuid.uuid4().hex[:8]}")
        confidence = vuln.get("confidence", "under_investigation")
        evidence = vuln.get("evidence_level", "default")

        status = CONFIDENCE_TO_STATUS.get(confidence, "under_investigation")

        vuln_entry: dict[str, Any] = {
            "cve": vuln_id if vuln_id.startswith("CVE-") else None,
            "notes": [
                {
                    "category": "description",
                    "text": vuln.get("description", "No description provided."),
                    "title": "Vulnerability Description",
                }
            ],
            "product_status": {status: [product_id]},
        }

        # Remove null CVE if not applicable
        if not vuln_entry["cve"]:
            del vuln_entry["cve"]

        # If known_not_affected, we must provide a justification via threats section or specific fields
        # In CSAF 2.0, threats category "impact" can be used to describe justifications.
        if status == "known_not_affected":
            justification = EVIDENCE_TO_JUSTIFICATION.get(
                evidence, EVIDENCE_TO_JUSTIFICATION["default"]
            )
            vuln_entry["threats"] = [
                {
                    "category": "impact",
                    "details": f"Justification: {justification}",
                    "product_ids": [product_id],
                }
            ]

        csaf_vulns.append(vuln_entry)

    csaf_document = {
        "document": {
            "category": CSAF_PROFILE,
            "csaf_version": CSAF_VERSION,
            "publisher": _generate_document_publisher(),
            "title": document_title,
            "tracking": _generate_document_tracking(title=document_title),
        },
        "product_tree": product_tree,
        "vulnerabilities": csaf_vulns,
    }

    return json.dumps(csaf_document, indent=2)
