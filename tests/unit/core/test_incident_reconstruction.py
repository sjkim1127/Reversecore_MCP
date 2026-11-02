"""Unit tests for cross-source incident reconstruction engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reversecore_mcp.core.incident_reconstruction import (
    CorrelationStrength,
    EvidenceEntity,
    EvidenceSourceType,
    IncidentReconstruction,
    reconstruct_incident,
)
from reversecore_mcp.prompts.incident_reconstruction import (
    incident_reconstruction_mode,
)

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "incident_reconstruction"


def load_fixture() -> tuple[str, str, str, list[EvidenceEntity]]:
    fixture_path = FIXTURES_DIR / "multi_source_incident.json"
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)
    obs = [EvidenceEntity.from_dict(o) for o in data.get("observations", [])]
    return (
        data.get("incident_id", ""),
        data.get("title", ""),
        data.get("summary_notes", ""),
        obs,
    )


@pytest.mark.unit
def test_full_multi_source_reconstruction_and_provenance_preservation():
    """AC1 & AC4: Multi-source correlation preserves tool provenance and separates facts from inferences."""
    inc_id, title, notes, observations = load_fixture()
    incident = reconstruct_incident(inc_id, title, observations, notes)

    assert incident.incident_id == "inc_2026_apt_stage1"
    assert len(incident.present_sources) == 4  # binary, disk, memory, pcap

    # AC1: Check that correlated entities retain each observation's exact provenance tool
    domain_corr = next(
        (
            e
            for e in incident.correlated_entities
            if e.canonical_value == "c2-gateway.apt-actor.org"
        ),
        None,
    )
    assert domain_corr is not None
    assert domain_corr.correlation_strength == CorrelationStrength.MULTI_SOURCE
    assert set(domain_corr.sources) == {"binary", "pcap"}
    provenance_tools = {o.provenance_tool for o in domain_corr.observations}
    assert "extract_iocs" in provenance_tools
    assert "pcap_extract_dns" in provenance_tools

    # AC4: Verify strict separation of observed facts from inferred relationships
    assert len(incident.observed_facts) > 0
    assert any("[FACT]" in f or "independently observed" in f for f in incident.observed_facts)
    assert len(incident.inferred_relationships) > 0
    assert any("matches network IOCs" in r for r in incident.inferred_relationships)

    # Verify timeline is ordered chronologically
    assert len(incident.timeline) == 5
    timestamps = [t.timestamp for t in incident.timeline]
    assert timestamps == sorted(timestamps)

    # Verify markdown formatting renders sections
    md = incident.format_markdown()
    assert "Incident Investigation Dossier:" in md
    assert "Directly Observed Facts" in md
    assert "Inferred Hypotheses" in md
    assert "Chronological Incident Timeline" in md
    assert "extract_iocs" in md
    assert "pcap_extract_dns" in md


@pytest.mark.unit
def test_conflicting_timestamps_and_entity_values_surfaced():
    """AC2: Conflicting timestamps or entity values remain visible rather than being silently merged."""
    inc_id, title, notes, observations = load_fixture()
    incident = reconstruct_incident(inc_id, title, observations, notes)

    # Discrepancies must be surfaced in the conflicts list
    assert len(incident.conflicts) >= 2

    # 1. Path discrepancy (Memory temp path vs Disk public path)
    path_conflict = next(
        (c for c in incident.conflicts if c.get("dimension") == "executable_path_discrepancy"),
        None,
    )
    assert path_conflict is not None
    assert "Temp" in path_conflict.get("val_a", "")
    assert "Public" in path_conflict.get("val_b", "")

    # 2. Timestamp conflict (Compile time > modified time / timestomp)
    time_conflict = next(
        (c for c in incident.conflicts if c.get("dimension") == "timestamp_timestomp"),
        None,
    )
    assert time_conflict is not None
    assert "timestomping" in time_conflict.get("note", "").lower()

    # Verify discrepancies table appears in report
    md = incident.format_markdown()
    assert "Forensic Discrepancies & Conflicting Observations" in md
    assert "executable_path_discrepancy" in md
    assert "timestamp_timestomp" in md


@pytest.mark.unit
def test_partial_reconstruction_pcap_and_binary_only():
    """AC3: Running with only PCAP + binary still produces a useful partial reconstruction."""
    obs = [
        EvidenceEntity(
            entity_type="domain",
            value="malicious-c2.net",
            source_type=EvidenceSourceType.BINARY,
            source_artifact="sample.bin",
            provenance_tool="extract_iocs",
            confidence=0.9,
        ),
        EvidenceEntity(
            entity_type="domain",
            value="malicious-c2.net",
            source_type=EvidenceSourceType.PCAP,
            source_artifact="capture.pcap",
            provenance_tool="pcap_extract_dns",
            timestamp="2026-03-01T15:00:00Z",
            confidence=1.0,
        ),
    ]

    incident = reconstruct_incident(
        incident_id="partial_01",
        title="PCAP and Binary Only Investigation",
        observations=obs,
    )

    assert incident.present_sources == ["binary", "pcap"]
    assert len(incident.correlated_entities) == 1
    corr = incident.correlated_entities[0]
    assert corr.canonical_value == "malicious-c2.net"
    assert corr.correlation_strength == CorrelationStrength.MULTI_SOURCE
    assert len(incident.timeline) == 1
    assert len(incident.inferred_relationships) >= 1

    md = incident.format_markdown()
    assert "malicious-c2.net" in md
    assert "extract_iocs" in md
    assert "pcap_extract_dns" in md


@pytest.mark.unit
def test_partial_reconstruction_memory_and_disk_only():
    """AC3: Running with only Memory + Disk produces a useful partial reconstruction."""
    obs = [
        EvidenceEntity(
            entity_type="file_path",
            value="C:\\Windows\\System32\\srvhost.exe",
            source_type=EvidenceSourceType.DISK,
            source_artifact="mft.raw",
            provenance_tool="disk_analyze_mft",
            timestamp="2026-02-28T09:00:00Z",
        ),
        EvidenceEntity(
            entity_type="process_name",
            value="srvhost.exe",
            source_type=EvidenceSourceType.MEMORY,
            source_artifact="memory.dmp",
            provenance_tool="memory_list_processes",
            timestamp="2026-02-28T09:05:00Z",
            context={"pid": 1120, "executable_path": "C:\\Windows\\System32\\srvhost.exe"},
        ),
    ]

    incident = reconstruct_incident(
        incident_id="partial_02",
        title="Memory and Disk Only Investigation",
        observations=obs,
    )

    assert incident.present_sources == ["disk", "memory"]
    assert len(incident.timeline) == 2
    assert len(incident.inferred_relationships) >= 1

    md = incident.format_markdown()
    assert "srvhost.exe" in md
    assert "disk_analyze_mft" in md
    assert "memory_list_processes" in md


@pytest.mark.unit
def test_serialization_roundtrip_incident():
    """Verify JSON serialization and deserialization roundtrip for IncidentReconstruction."""
    inc_id, title, notes, observations = load_fixture()
    incident = reconstruct_incident(inc_id, title, observations, notes)

    data = incident.to_dict()
    restored = IncidentReconstruction.from_dict(data)

    assert restored.incident_id == incident.incident_id
    assert restored.title == incident.title
    assert len(restored.correlated_entities) == len(incident.correlated_entities)
    assert len(restored.timeline) == len(incident.timeline)
    assert len(restored.conflicts) == len(incident.conflicts)


@pytest.mark.unit
def test_incident_reconstruction_mode_prompt_generation():
    """Verify guided prompt renders with required DFIR SOP steps."""
    prompt = incident_reconstruction_mode(
        evidence_sources="binary,memory,pcap,disk",
        target_host_or_case="ENDPOINT-099",
        primary_indicator="c2-gateway.apt-actor.org",
    )

    assert "ENDPOINT-099" in prompt
    assert "c2-gateway.apt-actor.org" in prompt
    assert "extract_iocs" in prompt
    assert "pcap_extract_dns" in prompt
    assert "memory_list_processes" in prompt
    assert "disk_analyze_mft" in prompt
    assert "Provenance is sacred" in prompt
    assert "timestomping" in prompt
