"""Unit tests for evidence module."""

from datetime import datetime, timedelta

import pytest

from reversecore_mcp.core.evidence import (
    EvidenceLevel,
    MITREConfidence,
    Evidence,
    Finding,
    MITRETechnique,
    AnalysisMetadata,
    observed_finding,
    inferred_finding,
    possible_finding,
)


class TestEvidenceLevel:
    """Tests for EvidenceLevel enum."""

    def test_observed_symbol(self):
        """Test OBSERVED level symbol."""
        assert EvidenceLevel.OBSERVED.symbol == "🔍"

    def test_inferred_symbol(self):
        """Test INFERRED level symbol."""
        assert EvidenceLevel.INFERRED.symbol == "🔎"

    def test_possible_symbol(self):
        """Test POSSIBLE level symbol."""
        assert EvidenceLevel.POSSIBLE.symbol == "❓"

    def test_observed_confidence_score(self):
        """Test OBSERVED confidence score."""
        assert EvidenceLevel.OBSERVED.confidence_score == 1.0

    def test_inferred_confidence_score(self):
        """Test INFERRED confidence score."""
        score = EvidenceLevel.INFERRED.confidence_score
        assert 0.7 <= score <= 0.85

    def test_possible_confidence_score(self):
        """Test POSSIBLE confidence score."""
        score = EvidenceLevel.POSSIBLE.confidence_score
        assert 0.4 <= score <= 0.6


class TestMITREConfidence:
    """Tests for MITREConfidence enum."""

    def test_confidence_values(self):
        """Test all confidence level values."""
        assert MITREConfidence.CONFIRMED.value == "confirmed"
        assert MITREConfidence.HIGH.value == "high"
        assert MITREConfidence.MEDIUM.value == "medium"
        assert MITREConfidence.LOW.value == "low"


class TestEvidence:
    """Tests for Evidence dataclass."""

    def test_evidence_creation(self):
        """Test creating evidence."""
        evidence = Evidence(
            source="Procmon",
            location="0x401000",
            description="CreateMutexA call observed",
        )
        assert evidence.source == "Procmon"
        assert evidence.location == "0x401000"
        assert evidence.description == "CreateMutexA call observed"
        assert evidence.raw_data is None
        assert isinstance(evidence.timestamp, datetime)

    def test_evidence_with_raw_data(self):
        """Test evidence with raw data."""
        evidence = Evidence(
            source="Sandbox",
            location="network",
            description="C2 beacon detected",
            raw_data='{"ip": "1.2.3.4", "port": 443}',
        )
        assert evidence.raw_data == '{"ip": "1.2.3.4", "port": 443}'

    def test_evidence_to_dict(self):
        """Test evidence serialization."""
        evidence = Evidence(
            source="IDA",
            location="sub_401000",
            description="Encryption loop found",
        )
        data = evidence.to_dict()
        assert data["source"] == "IDA"
        assert data["location"] == "sub_401000"
        assert data["description"] == "Encryption loop found"
        assert "timestamp" in data


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            title="Ransomware Encryption",
            description="File encryption routine detected",
            level=EvidenceLevel.INFERRED,
            category="impact",
        )
        assert finding.title == "Ransomware Encryption"
        assert finding.level == EvidenceLevel.INFERRED
        assert finding.category == "impact"
        assert finding.evidence == []

    def test_add_evidence(self):
        """Test adding evidence to finding."""
        finding = Finding(
            title="C2 Communication",
            description="Network callback detected",
            level=EvidenceLevel.OBSERVED,
            category="command-and-control",
        )
        finding.add_evidence(
            source="Wireshark",
            location="192.168.1.100:443",
            description="HTTPS beacon every 60s",
        )
        assert len(finding.evidence) == 1
        assert finding.evidence[0].source == "Wireshark"

    def test_finding_confidence(self):
        """Test finding confidence calculation (property)."""
        finding = Finding(
            title="Test",
            description="Test finding",
            level=EvidenceLevel.OBSERVED,
            category="test",
        )
        confidence = finding.confidence  # property, not method
        assert 0.0 <= confidence <= 1.0

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            title="Persistence",
            description="Registry modification",
            level=EvidenceLevel.INFERRED,
            category="persistence",
        )
        data = finding.to_dict()
        assert data["title"] == "Persistence"
        assert data["level"] == "inferred"
        assert data["category"] == "persistence"

    def test_finding_format_markdown(self):
        """Test markdown formatting."""
        finding = Finding(
            title="Malware Detection",
            description="Suspicious behavior found",
            level=EvidenceLevel.OBSERVED,
            category="detection",
        )
        finding.add_evidence(
            source="YARA",
            location="file.exe",
            description="Matched ransomware rule",
        )
        md = finding.format_markdown()
        assert "Malware Detection" in md
        assert "🔍" in md
        assert "YARA" in md


class TestMITRETechnique:
    """Tests for MITRETechnique dataclass."""

    def test_technique_creation(self):
        """Test creating a MITRE technique."""
        technique = MITRETechnique(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="Impact",
            confidence=MITREConfidence.CONFIRMED,
        )
        assert technique.technique_id == "T1486"
        assert technique.tactic == "Impact"
        assert technique.confidence == MITREConfidence.CONFIRMED

    def test_technique_to_dict(self):
        """Test technique serialization."""
        technique = MITRETechnique(
            technique_id="T1055",
            technique_name="Process Injection",
            tactic="Defense Evasion",
            confidence=MITREConfidence.HIGH,
        )
        data = technique.to_dict()
        assert data["technique_id"] == "T1055"
        assert data["confidence"] == "high"

    def test_technique_format_markdown_row(self):
        """Test markdown table row formatting."""
        technique = MITRETechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            confidence=MITREConfidence.MEDIUM,
        )
        row = technique.format_markdown_row()
        assert "T1059.001" in row
        assert "PowerShell" in row
        assert "|" in row


class TestAnalysisMetadata:
    """Tests for AnalysisMetadata dataclass."""

    def test_metadata_creation(self):
        """Test creating analysis metadata."""
        metadata = AnalysisMetadata(
            session_id="session-123",
            sample_name="malware.exe",
            sample_hash="abc123",
            start_time=datetime.now(),
        )
        assert metadata.session_id == "session-123"
        assert metadata.sample_name == "malware.exe"
        assert metadata.analyst == "Reversecore MCP"

    def test_duration_seconds(self):
        """Test duration calculation in seconds (property)."""
        start = datetime.now()
        end = start + timedelta(seconds=120)
        metadata = AnalysisMetadata(
            session_id="test",
            sample_name="test.exe",
            sample_hash="hash",
            start_time=start,
            end_time=end,
        )
        assert metadata.duration_seconds == 120  # property, not method

    def test_duration_seconds_ongoing(self):
        """Test duration when analysis is ongoing returns a float."""
        metadata = AnalysisMetadata(
            session_id="test",
            sample_name="test.exe",
            sample_hash="hash",
            start_time=datetime.now() - timedelta(seconds=10),
        )
        # When no end_time, it calculates from start_time to now
        assert metadata.duration_seconds >= 0

    def test_duration_formatted(self):
        """Test human-readable duration (property)."""
        start = datetime.now()
        end = start + timedelta(hours=1, minutes=30, seconds=45)
        metadata = AnalysisMetadata(
            session_id="test",
            sample_name="test.exe",
            sample_hash="hash",
            start_time=start,
            end_time=end,
        )
        formatted = metadata.duration_formatted  # property, not method
        assert "hour" in formatted or "minute" in formatted

    def test_metadata_to_dict(self):
        """Test metadata serialization."""
        metadata = AnalysisMetadata(
            session_id="session-456",
            sample_name="sample.dll",
            sample_hash="def456",
            start_time=datetime.now(),
            tools_used=["radare2", "yara"],
        )
        data = metadata.to_dict()
        assert data["session_id"] == "session-456"
        assert "radare2" in data["tools_used"]


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_observed_finding(self):
        """Test observed_finding helper."""
        finding = observed_finding(
            title="Network Activity",
            description="C2 beacon detected",
            category="network",
        )
        assert finding.level == EvidenceLevel.OBSERVED
        assert finding.title == "Network Activity"

    def test_inferred_finding(self):
        """Test inferred_finding helper."""
        finding = inferred_finding(
            title="Encryption Capability",
            description="CryptEncrypt API import",
            category="crypto",
        )
        assert finding.level == EvidenceLevel.INFERRED

    def test_possible_finding(self):
        """Test possible_finding helper."""
        finding = possible_finding(
            title="Data Exfiltration",
            description="Large buffer allocation",
            category="exfiltration",
        )
        assert finding.level == EvidenceLevel.POSSIBLE
