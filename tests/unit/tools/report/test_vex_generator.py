import json

import pytest

from reversecore_mcp.tools.report.vex_generator import (
    EVIDENCE_TO_JUSTIFICATION,
    generate_csaf_vex,
)


@pytest.fixture
def sample_vulnerabilities():
    return [
        {
            "id": "CVE-2023-1001",
            "description": "Buffer overflow in parsing routine",
            "confidence": "confirmed",
            "evidence_level": "dynamic_crash",
        },
        {
            "id": "VULN-CUSTOM-001",
            "description": "Hardcoded credentials in test config",
            "confidence": "false_positive",
            "evidence_level": "dead_code",
        },
        {
            "id": "CVE-2023-1002",
            "description": "Unvalidated input",
            "confidence": "likely",
            "evidence_level": "symbolic_reachable",
        },
    ]


@pytest.mark.unit
def test_generate_csaf_vex_structure(sample_vulnerabilities):
    """Test that the generated VEX JSON contains all mandatory CSAF sections."""
    result_str = generate_csaf_vex(
        product_name="TestApp",
        product_version="1.0",
        vulnerabilities=sample_vulnerabilities,
        document_title="Test VEX",
    )

    data = json.loads(result_str)

    assert "document" in data
    assert data["document"]["category"] == "csaf_vex"
    assert data["document"]["title"] == "Test VEX"
    assert "publisher" in data["document"]
    assert "tracking" in data["document"]

    assert "product_tree" in data

    assert "vulnerabilities" in data
    assert len(data["vulnerabilities"]) == 3


@pytest.mark.unit
def test_generate_csaf_vex_status_mapping(sample_vulnerabilities):
    """Test that confidence translates to correct CSAF product_status."""
    result_str = generate_csaf_vex(
        product_name="TestApp",
        product_version="1.0",
        vulnerabilities=sample_vulnerabilities,
    )

    data = json.loads(result_str)
    vulns = data["vulnerabilities"]

    # CVE-2023-1001 (confirmed -> known_affected)
    vuln1 = next(v for v in vulns if v.get("cve") == "CVE-2023-1001")
    assert "known_affected" in vuln1["product_status"]

    # VULN-CUSTOM-001 (false_positive -> known_not_affected)
    # Custom IDs might not be mapped to cve, but rather left without a 'cve' field
    vuln2 = vulns[1]
    assert "cve" not in vuln2
    assert "known_not_affected" in vuln2["product_status"]

    # Check justification is generated via threats section for not affected
    assert "threats" in vuln2
    threat_text = vuln2["threats"][0]["details"]
    assert EVIDENCE_TO_JUSTIFICATION["dead_code"] in threat_text


@pytest.mark.unit
def test_generate_csaf_vex_empty_vulnerabilities():
    """Test generating VEX with no vulnerabilities."""
    result_str = generate_csaf_vex(
        product_name="SecureApp",
        product_version="2.0",
        vulnerabilities=[],
    )

    data = json.loads(result_str)
    assert len(data.get("vulnerabilities", [])) == 0
    assert data["document"]["csaf_version"] == "2.0"
