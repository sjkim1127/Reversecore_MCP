"""Unit tests for evidence-based report generator."""

from datetime import datetime, timedelta

from reversecore_mcp.core.evidence import (
    AnalysisMetadata,
    EvidenceLevel,
    Finding,
    MITREConfidence,
    MITRETechnique,
)
from reversecore_mcp.core.report_generator import (
    EvidenceBasedReport,
    create_report,
)


def _metadata():
    return AnalysisMetadata(
        session_id="test-session",
        sample_name="sample.exe",
        sample_hash="a" * 64,
        start_time=datetime.now(),
    )


class TestEvidenceBasedReport:
    """Tests for EvidenceBasedReport."""

    def test_add_finding(self):
        r = EvidenceBasedReport(metadata=_metadata())
        f = Finding("Title", "Desc", EvidenceLevel.OBSERVED, "test")
        r.add_finding(f)
        assert len(r.findings) == 1
        assert r.findings[0].title == "Title"

    def test_add_mitre(self):
        r = EvidenceBasedReport(metadata=_metadata())
        t = MITRETechnique("T1055", "Process Injection", "Defense Evasion", MITREConfidence.HIGH)
        r.add_mitre(t)
        assert len(r.mitre_techniques) == 1
        assert r.mitre_techniques[0].technique_id == "T1055"

    def test_add_ioc(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.add_ioc("ip", "1.2.3.4")
        r.add_ioc("ip", "5.6.7.8")
        r.add_ioc("ip", "1.2.3.4")  # duplicate not added
        assert r.iocs["ip"] == ["1.2.3.4", "5.6.7.8"]
        r.add_ioc("domain", "evil.com")
        assert "domain" in r.iocs

    def test_set_family(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.set_family("Emotet", 0.9, ["YARA match", "Import hash"])
        assert r.malware_family == "Emotet"
        assert r.family_confidence == 0.9
        assert r.family_evidence == ["YARA match", "Import hash"]

    def test_finalize(self):
        r = EvidenceBasedReport(metadata=_metadata())
        assert r.metadata.end_time is None
        r.finalize()
        assert r.metadata.end_time is not None

    def test_observed_inferred_possible_count(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.add_finding(Finding("A", "a", EvidenceLevel.OBSERVED, "x"))
        r.add_finding(Finding("B", "b", EvidenceLevel.OBSERVED, "x"))
        r.add_finding(Finding("C", "c", EvidenceLevel.INFERRED, "x"))
        r.add_finding(Finding("D", "d", EvidenceLevel.POSSIBLE, "x"))
        assert r.observed_count == 2
        assert r.inferred_count == 1
        assert r.possible_count == 1

    def test_overall_confidence_empty(self):
        r = EvidenceBasedReport(metadata=_metadata())
        assert r.overall_confidence == 0.0

    def test_overall_confidence_with_findings(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.add_finding(Finding("F", "f", EvidenceLevel.OBSERVED, "x"))
        assert 0 <= r.overall_confidence <= 1.0

    def test_generate_markdown_minimal(self):
        r = EvidenceBasedReport(metadata=_metadata())
        md = r.generate_markdown()
        assert "Malware Analysis Report" in md
        assert "sample.exe" in md
        assert "Confidence Summary" in md
        assert "Malware Identification" in md

    def test_generate_markdown_family_confidence_bands(self):
        meta = _metadata()
        for conf, expected in [
            (0.9, "CONFIRMED"),
            (0.7, "LIKELY"),
            (0.5, "POSSIBLE"),
            (0.2, "UNCERTAIN"),
        ]:
            r = EvidenceBasedReport(metadata=meta, family_confidence=conf)
            md = r.generate_markdown()
            assert expected in md

    def test_generate_markdown_with_family_evidence(self):
        r = EvidenceBasedReport(
            metadata=_metadata(),
            family_evidence=["YARA: Emotet", "Imphash match"],
        )
        md = r.generate_markdown()
        assert "Identification Evidence" in md
        assert "YARA: Emotet" in md

    def test_generate_markdown_with_executive_summary(self):
        r = EvidenceBasedReport(metadata=_metadata(), executive_summary="Sample is ransomware.")
        md = r.generate_markdown()
        assert "Executive Summary" in md
        assert "Sample is ransomware" in md

    def test_generate_markdown_with_findings(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.add_finding(Finding("Obs", "o", EvidenceLevel.OBSERVED, "x"))
        r.add_finding(Finding("Inf", "i", EvidenceLevel.INFERRED, "y"))
        md = r.generate_markdown()
        assert "Analysis Findings" in md
        assert "Obs" in md
        assert "Inf" in md

    def test_generate_markdown_with_mitre(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.add_mitre(
            MITRETechnique("T1055", "Process Injection", "Defense Evasion", MITREConfidence.HIGH)
        )
        md = r.generate_markdown()
        assert "MITRE ATT&CK" in md
        assert "T1055" in md

    def test_generate_markdown_with_iocs(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.add_ioc("ip", "10.0.0.1")
        md = r.generate_markdown()
        assert "Indicators of Compromise" in md
        assert "10.0.0.1" in md

    def test_generate_markdown_with_yara_rule(self):
        r = EvidenceBasedReport(
            metadata=_metadata(), yara_rule="rule Test { strings: $a = { 4d 5a } condition: $a }"
        )
        md = r.generate_markdown()
        assert "Detection Rule" in md
        assert "rule Test" in md

    def test_generate_markdown_with_recommendations(self):
        r = EvidenceBasedReport(
            metadata=_metadata(), recommendations=["Isolate host", "Collect memory"]
        )
        md = r.generate_markdown()
        assert "Recommendations" in md
        assert "Isolate host" in md

    def test_generate_markdown_footer_with_end_time(self):
        meta = _metadata()
        meta.end_time = datetime.now() + timedelta(minutes=5)
        r = EvidenceBasedReport(metadata=meta)
        md = r.generate_markdown()
        assert "End Time" in md
        assert "Report Metadata" in md

    def test_to_dict(self):
        r = EvidenceBasedReport(metadata=_metadata())
        r.add_finding(Finding("F", "f", EvidenceLevel.OBSERVED, "x"))
        d = r.to_dict()
        assert d["malware_family"] == "Unknown"
        assert "metadata" in d
        assert "findings" in d
        assert d["confidence_summary"]["observed_count"] == 1

    def test_to_json(self):
        r = EvidenceBasedReport(metadata=_metadata())
        js = r.to_json(indent=2)
        assert "session_id" in js
        assert "test-session" in js


class TestCreateReport:
    """Tests for create_report factory."""

    def test_create_report_default_analyst(self):
        r = create_report("sid", "sample.exe", "hash" + "0" * 58)
        assert r.metadata.session_id == "sid"
        assert r.metadata.sample_name == "sample.exe"
        assert r.metadata.sample_hash == "hash" + "0" * 58
        assert r.metadata.analyst == "Reversecore MCP"

    def test_create_report_custom_analyst(self):
        r = create_report("sid", "s", "h", analyst="Custom Analyst")
        assert r.metadata.analyst == "Custom Analyst"
