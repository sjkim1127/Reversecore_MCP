# Cross-Source Incident Reconstruction Workflow

The **Cross-Source Incident Reconstruction Workflow** composes Reversecore's existing binary, memory, PCAP, and disk forensic capabilities into a unified investigation pipeline.

Instead of presenting disjointed outputs from individual tools, this workflow connects the dots across evidence sources to answer critical incident response questions:
- **How was the binary staged on disk?**
- **Was the process actively executing or injected in memory?**
- **Did the host communicate with malicious C2 infrastructure observed in network PCAPs?**
- **Were timestamps manipulated (timestomping) or paths masqueraded?**

---

## Architecture & Composed Forensic Primitives

```
┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│  Binary Sample  │  │   Memory Dump    │  │  Network PCAP   │  │    Disk Image    │
└────────┬────────┘  └────────┬─────────┘  └────────┬────────┘  └────────┬─────────┘
         │                    │                     │                    │
  extract_iocs       memory_processes       pcap_extract_dns       disk_analyze_mft
  parse_lief         memory_injections      pcap_connections       disk_extract_file
         │                    │                     │                    │
         └────────────────────┼─────────────────────┼────────────────────┘
                              ▼
            ┌───────────────────────────────────┐
            │ Normalized Evidence Entity Stream │
            └─────────────────┬─────────────────┘
                              ▼
            ┌───────────────────────────────────┐
            │   Incident Reconstruction Engine  │
            │   - Cross-source entity correlation│
            │   - Discrepancy & conflict tracker│
            │   - Chronological timeline builder│
            │   - Facts vs Inferences classifier│
            └─────────────────┬─────────────────┘
                              ▼
            ┌───────────────────────────────────┐
            │ Investigation Dossier & Sigma IOCs│
            └───────────────────────────────────┘
```

---

## Core Invariants & Rules

1. **Sacred Source Provenance**:
   - Every correlated entity retains its original tool name, artifact path, and observation context. Provenance is never merged away.
2. **Explicit Discrepancy Visibility**:
   - Conflicting evidence (e.g. compile time later than filesystem modification time, or memory process executing out of `Temp` while disk file is in `Public`) is highlighted in a dedicated Discrepancies table.
3. **Strict Separation of Facts and Inferences**:
   - Directly recorded packet timestamps, memory process tables, and filesystem records are marked as `[FACT]`.
   - Threat actor motives, campaign attribution, and multi-stage intentions are marked as `[INFERRED]`.
4. **Graceful Partial Degradation**:
   - If an investigator only has PCAP + Binary, or Memory + Disk, the workflow reconstructs a partial incident thread without failing.
5. **Detection Engineering Export**:
   - High-confidence cross-source IOCs are extracted for immediate ingestion into Sigma rules, YARA rules, or threat intelligence handoffs.

---

## Normalized Entity Schema

| Field | Type | Description |
|---|---|---|
| `entity_type` | `str` | `hash`, `domain`, `ip`, `file_path`, `process_name`, `pid`, `mutex` |
| `value` | `str` | Canonical string value of the indicator |
| `source_type` | `str` | `binary`, `memory`, `pcap`, or `disk` |
| `source_artifact` | `str` | File path or identifier of the raw evidence artifact |
| `provenance_tool` | `str` | Reversecore tool responsible for extraction |
| `timestamp` | `str` (ISO-8601) | Recorded event time in UTC (or `None` if static) |
| `evidence_level` | `str` | `OBSERVED`, `INFERRED`, or `POSSIBLE` |
| `context` | `dict` | Extra metadata (e.g. PID, dest port, query type, MFT flags) |

---

## Incremental MCP Client Execution Pattern

An MCP client or AI agent executes the workflow in progressive steps:

```python
from reversecore_mcp.core.incident_reconstruction import (
    EvidenceEntity,
    EvidenceSourceType,
    reconstruct_incident,
)

# 1. Collect normalized observations from each tool
observations = [
    # Binary observation
    EvidenceEntity(
        entity_type="domain",
        value="c2-gateway.apt-actor.org",
        source_type=EvidenceSourceType.BINARY,
        source_artifact="evidence/payload.exe",
        provenance_tool="extract_iocs",
    ),
    # PCAP observation
    EvidenceEntity(
        entity_type="domain",
        value="c2-gateway.apt-actor.org",
        source_type=EvidenceSourceType.PCAP,
        source_artifact="evidence/traffic.pcap",
        provenance_tool="pcap_extract_dns",
        timestamp="2026-03-01T12:05:00Z",
    ),
]

# 2. Reconstruct incident dossier
incident = reconstruct_incident(
    incident_id="inc_001",
    title="Targeted C2 Intrusion",
    observations=observations,
)

# 3. Output analyst report
print(incident.format_markdown())
```

---

## Guided Prompt (`incident_reconstruction_mode`)

AI agents can trigger the guided investigation prompt:

```python
incident_reconstruction_mode(
    evidence_sources="binary,pcap,disk",
    target_host_or_case="HOST-SEC-042",
    primary_indicator="c2-gateway.apt-actor.org",
)
```
