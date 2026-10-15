"""Unit tests for EvidenceOrigin and provenance tracking (Issue #321)."""

from datetime import datetime

import pytest

from reversecore_mcp.core.evidence import (
    AnalysisMetadata,
    Evidence,
    EvidenceLevel,
    EvidenceOrigin,
    Finding,
    artifact_finding,
    capability_finding,
    runtime_finding,
    structural_finding,
)
from reversecore_mcp.core.report_generator import EvidenceBasedReport


@pytest.mark.unit
class TestEvidenceOrigin:
    """Tests for EvidenceOrigin enum."""

    def test_origin_values(self):
        assert EvidenceOrigin.ARTIFACT.value == "artifact"
        assert EvidenceOrigin.STRUCTURAL.value == "structural"
        assert EvidenceOrigin.CAPABILITY.value == "capability"
        assert EvidenceOrigin.RUNTIME.value == "runtime"

    def test_origin_ranks(self):
        assert EvidenceOrigin.ARTIFACT.rank < EvidenceOrigin.STRUCTURAL.rank
        assert EvidenceOrigin.STRUCTURAL.rank < EvidenceOrigin.CAPABILITY.rank
        assert EvidenceOrigin.CAPABILITY.rank < EvidenceOrigin.RUNTIME.rank

    def test_origin_symbols(self):
        assert EvidenceOrigin.ARTIFACT.symbol == "📄"
        assert EvidenceOrigin.STRUCTURAL.symbol == "🕸️"
        assert EvidenceOrigin.CAPABILITY.symbol == "⚡"
        assert EvidenceOrigin.RUNTIME.symbol == "🏃"


@pytest.mark.unit
class TestEvidenceWithOrigin:
    """Tests for Evidence dataclass origin field."""

    def test_default_origin(self):
        ev = Evidence(source="strings", location="0x401000", description="Found URL")
        assert ev.origin == EvidenceOrigin.ARTIFACT
        data = ev.to_dict()
        assert data["origin"] == "artifact"
        assert data["origin_symbol"] == "📄"

    def test_explicit_origin(self):
        ev = Evidence(
            source="r2_esil",
            location="0x401500",
            description="Emulated decryption loop",
            origin=EvidenceOrigin.RUNTIME,
        )
        assert ev.origin == EvidenceOrigin.RUNTIME
        data = ev.to_dict()
        assert data["origin"] == "runtime"
        assert data["origin_symbol"] == "🏃"


@pytest.mark.unit
class TestFindingProvenance:
    """Tests for Finding provenance and classification."""

    def test_default_origin_empty_evidence(self):
        finding = Finding(
            title="Embedded Domain",
            description="Suspicious domain in binary",
            level=EvidenceLevel.OBSERVED,
            category="c2",
        )
        assert finding.origin == EvidenceOrigin.ARTIFACT
        assert finding.classification == "artifact_only"

    def test_derived_origin_multi_evidence(self):
        finding = Finding(
            title="PowerShell Execution",
            description="Process launch capability",
            level=EvidenceLevel.INFERRED,
            category="execution",
        )
        finding.add_evidence(
            source="strings",
            location="0x483210",
            description="Found powershell.exe string",
            origin=EvidenceOrigin.ARTIFACT,
        )
        assert finding.origin == EvidenceOrigin.ARTIFACT
        assert finding.classification == "artifact_only"

        # Add code xref (structural)
        finding.add_evidence(
            source="r2_axt",
            location="0x401920",
            description="lea rdi, [0x483210] in sub_401920",
            origin=EvidenceOrigin.STRUCTURAL,
        )
        assert finding.origin == EvidenceOrigin.STRUCTURAL
        assert finding.classification == "behavior_capable"

        # Add emulation trace (runtime)
        finding.add_evidence(
            source="qiling",
            location="0x401950",
            description="CreateProcessA intercepted with powershell.exe",
            origin=EvidenceOrigin.RUNTIME,
        )
        assert finding.origin == EvidenceOrigin.RUNTIME
        assert finding.classification == "runtime_confirmed"

    def test_provenance_validation(self):
        # Artifact-only claiming runtime execution
        bad_finding = Finding(
            title="Sample executes powershell.exe",
            description="Directly runs powershell at startup",
            level=EvidenceLevel.OBSERVED,
            category="execution",
        )
        bad_finding.add_evidence(
            source="strings",
            location="0x1000",
            description="string present",
            origin=EvidenceOrigin.ARTIFACT,
        )
        is_valid, warning = bad_finding.validate_provenance()
        assert not is_valid
        assert "Artifact-only finding cannot claim runtime execution" in (warning or "")

        # Valid structural finding
        good_finding = structural_finding(
            title="Sample references powershell.exe in code",
            description="Cross reference found in sub_401920",
            category="execution",
        )
        is_valid, warning = good_finding.validate_provenance()
        assert is_valid
        assert warning is None

    def test_finding_to_dict_and_markdown(self):
        finding = capability_finding(
            title="AES Encryption Loop",
            description="AES S-box lookup and key expansion",
            category="cryptography",
        )
        finding.add_evidence(
            source="capa",
            location="0x402000",
            description="encrypt data using AES rule match",
            origin=EvidenceOrigin.CAPABILITY,
        )
        data = finding.to_dict()
        assert data["origin"] == "capability"
        assert data["classification"] == "behavior_capable"
        assert data["origin_symbol"] == "⚡"

        md = finding.format_markdown()
        assert "Origin" in md
        assert "Capability" in md
        assert "behavior_capable" in md


@pytest.mark.unit
class TestReportProvenanceSummary:
    """Tests for report generator integration with provenance."""

    def test_report_provenance_counts(self):
        meta = AnalysisMetadata(
            session_id="sess_123",
            sample_name="sample.exe",
            sample_hash="a" * 64,
            start_time=datetime.now(),
        )
        report = EvidenceBasedReport(metadata=meta)

        f1 = artifact_finding("URL string", "Found URL in .rdata", "recon")
        f2 = structural_finding("Function Xref", "Xref from main", "flow")
        f3 = runtime_finding("Dynamic Beacon", "Emulated network call", "c2")

        report.add_finding(f1)
        report.add_finding(f2)
        report.add_finding(f3)

        assert report.artifact_only_count == 1
        assert report.behavior_capable_count == 1
        assert report.runtime_confirmed_count == 1

        md = report.generate_markdown()
        assert "Artifact-Only Findings" in md
        assert "Behavior-Capable Findings" in md
        assert "Runtime-Confirmed Findings" in md

        data = report.to_dict()
        assert "provenance_summary" in data
        assert data["provenance_summary"]["artifact_only_count"] == 1
        assert data["provenance_summary"]["behavior_capable_count"] == 1
        assert data["provenance_summary"]["runtime_confirmed_count"] == 1
