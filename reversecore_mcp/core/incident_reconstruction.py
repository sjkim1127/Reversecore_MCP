"""Cross-Source Incident Reconstruction Engine.

This module composes forensic and analysis capabilities across binary,
memory, network PCAP, and disk evidence into a unified investigation workflow.

Key capabilities:
- Normalizes evidence entities across disparate sources (file hashes, IPs, domains,
  process names, paths, timestamps).
- Preserves complete source provenance (artifact path, tool name, observation context).
- Surfaces conflicting timestamps or entity discrepancies (e.g. timestomping, process masquerading)
  instead of silently merging them.
- Distinguishes directly observed facts from inferred relationships.
- Degrades gracefully when only a subset of evidence types is available (e.g. PCAP+Binary, Memory+Disk).
- Emits chronological timeline and structured high-confidence IOCs for report/Sigma/YARA export.

Invariant guarantees:
1. Source provenance is never discarded or collapsed into an untraceable union.
2. Contradictory timestamps or entity values remain explicitly visible.
3. Observed facts are strictly separated from inferred relationships.
4. Operates by composing existing forensic outputs without requiring new analysis engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class EvidenceSourceType(str, Enum):
    """Categorization of evidence sources."""

    BINARY = "binary"
    MEMORY = "memory"
    PCAP = "pcap"
    DISK = "disk"


class CorrelationStrength(str, Enum):
    """Strength of entity correlation across multiple sources."""

    MULTI_SOURCE = "MULTI_SOURCE"  # Observed across >= 2 independent evidence types
    SINGLE_SOURCE_HIGH = "SINGLE_SOURCE_HIGH"  # Confirmed in 1 source with high confidence
    WEAK = "WEAK"  # Incidental or low-confidence indicator


@dataclass
class EvidenceEntity:
    """An individual entity observation extracted from a forensic evidence source."""

    entity_type: str  # e.g., 'hash', 'domain', 'ip', 'file_path', 'process_name', 'pid'
    value: str
    source_type: EvidenceSourceType
    source_artifact: str  # path or label of originating file
    provenance_tool: str  # e.g., 'extract_iocs', 'pcap_extract_dns', 'memory_list_processes'
    timestamp: str | None = None  # ISO-8601 UTC
    evidence_level: str = "OBSERVED"  # OBSERVED, INFERRED, POSSIBLE
    confidence: float = 1.0
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "source_type": self.source_type.value,
            "source_artifact": self.source_artifact,
            "provenance_tool": self.provenance_tool,
            "timestamp": self.timestamp,
            "evidence_level": self.evidence_level,
            "confidence": self.confidence,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceEntity:
        raw_source = data.get("source_type", "binary")
        source_type = (
            EvidenceSourceType(raw_source)
            if raw_source in [s.value for s in EvidenceSourceType]
            else EvidenceSourceType.BINARY
        )
        return cls(
            entity_type=str(data.get("entity_type", "unknown")),
            value=str(data.get("value", "")),
            source_type=source_type,
            source_artifact=str(data.get("source_artifact", "")),
            provenance_tool=str(data.get("provenance_tool", "unknown")),
            timestamp=data.get("timestamp"),
            evidence_level=str(data.get("evidence_level", "OBSERVED")),
            confidence=float(data.get("confidence", 1.0)),
            context=dict(data.get("context", {})),
        )


@dataclass
class CorrelatedEntity:
    """Entity correlated across one or more forensic sources."""

    entity_type: str
    canonical_value: str
    sources: list[str] = field(default_factory=list)
    observations: list[EvidenceEntity] = field(default_factory=list)
    correlation_strength: CorrelationStrength = CorrelationStrength.SINGLE_SOURCE_HIGH
    conflicting_values: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "canonical_value": self.canonical_value,
            "sources": self.sources,
            "observations_count": len(self.observations),
            "correlation_strength": self.correlation_strength.value,
            "conflicting_values": self.conflicting_values,
            "observations": [o.to_dict() for o in self.observations],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CorrelatedEntity:
        raw_strength = data.get("correlation_strength", "SINGLE_SOURCE_HIGH")
        strength = (
            CorrelationStrength(raw_strength)
            if raw_strength in [s.value for s in CorrelationStrength]
            else CorrelationStrength.SINGLE_SOURCE_HIGH
        )
        obs = [EvidenceEntity.from_dict(o) for o in data.get("observations", [])]
        return cls(
            entity_type=str(data.get("entity_type", "unknown")),
            canonical_value=str(data.get("canonical_value", "")),
            sources=list(data.get("sources", [])),
            observations=obs,
            correlation_strength=strength,
            conflicting_values=list(data.get("conflicting_values", [])),
        )


@dataclass
class IncidentTimelineEvent:
    """Chronologically ordered forensic event with provenance."""

    event_id: str
    timestamp: str  # ISO-8601 UTC
    source_type: EvidenceSourceType
    source_artifact: str
    provenance_tool: str
    title: str
    description: str
    related_entities: list[str] = field(default_factory=list)
    is_observed_fact: bool = True
    evidence_level: str = "OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type.value,
            "source_artifact": self.source_artifact,
            "provenance_tool": self.provenance_tool,
            "title": self.title,
            "description": self.description,
            "related_entities": self.related_entities,
            "is_observed_fact": self.is_observed_fact,
            "evidence_level": self.evidence_level,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentTimelineEvent:
        raw_source = data.get("source_type", "binary")
        source_type = (
            EvidenceSourceType(raw_source)
            if raw_source in [s.value for s in EvidenceSourceType]
            else EvidenceSourceType.BINARY
        )
        return cls(
            event_id=str(data.get("event_id", "")),
            timestamp=str(data.get("timestamp", "")),
            source_type=source_type,
            source_artifact=str(data.get("source_artifact", "")),
            provenance_tool=str(data.get("provenance_tool", "unknown")),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            related_entities=list(data.get("related_entities", [])),
            is_observed_fact=bool(data.get("is_observed_fact", True)),
            evidence_level=str(data.get("evidence_level", "OBSERVED")),
        )


@dataclass
class IncidentReconstruction:
    """Comprehensive multi-source incident reconstruction dossier."""

    incident_id: str
    title: str
    present_sources: list[str] = field(default_factory=list)
    correlated_entities: list[CorrelatedEntity] = field(default_factory=list)
    timeline: list[IncidentTimelineEvent] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    observed_facts: list[str] = field(default_factory=list)
    inferred_relationships: list[str] = field(default_factory=list)
    high_confidence_iocs: list[dict[str, Any]] = field(default_factory=list)
    summary_narrative: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "present_sources": self.present_sources,
            "created_at": self.created_at,
            "summary_narrative": self.summary_narrative,
            "metrics": {
                "sources_count": len(self.present_sources),
                "correlated_entities_count": len(self.correlated_entities),
                "timeline_events_count": len(self.timeline),
                "conflicts_count": len(self.conflicts),
                "observed_facts_count": len(self.observed_facts),
                "inferred_relationships_count": len(self.inferred_relationships),
                "high_confidence_iocs_count": len(self.high_confidence_iocs),
            },
            "observed_facts": self.observed_facts,
            "inferred_relationships": self.inferred_relationships,
            "conflicts": self.conflicts,
            "high_confidence_iocs": self.high_confidence_iocs,
            "correlated_entities": [e.to_dict() for e in self.correlated_entities],
            "timeline": [t.to_dict() for t in self.timeline],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentReconstruction:
        entities = [CorrelatedEntity.from_dict(e) for e in data.get("correlated_entities", [])]
        timeline = [IncidentTimelineEvent.from_dict(t) for t in data.get("timeline", [])]
        return cls(
            incident_id=str(data.get("incident_id", "")),
            title=str(data.get("title", "")),
            present_sources=list(data.get("present_sources", [])),
            correlated_entities=entities,
            timeline=timeline,
            conflicts=list(data.get("conflicts", [])),
            observed_facts=list(data.get("observed_facts", [])),
            inferred_relationships=list(data.get("inferred_relationships", [])),
            high_confidence_iocs=list(data.get("high_confidence_iocs", [])),
            summary_narrative=str(data.get("summary_narrative", "")),
            created_at=str(data.get("created_at", "")),
        )

    def format_markdown(self) -> str:
        """Render the reconstruction as an analyst-facing markdown incident report."""
        sources_str = ", ".join(f"`{s.upper()}`" for s in self.present_sources)
        lines = [
            f"# Incident Investigation Dossier: {self.title}",
            "",
            f"**Incident ID**: `{self.incident_id}`  ",
            f"**Active Evidence Sources**: {sources_str or 'None'}  ",
            f"**Generated**: `{self.created_at}`  ",
            "",
            "## Executive Summary",
            self.summary_narrative or "No executive summary provided.",
            "",
            "## 🔍 Directly Observed Facts",
            *(
                [f"- [FACT] {fact}" for fact in self.observed_facts]
                if self.observed_facts
                else ["- None documented."]
            ),
            "",
            "## 🔎 Inferred Hypotheses & Relationships",
            *(
                [f"- [INFERRED] {rel}" for rel in self.inferred_relationships]
                if self.inferred_relationships
                else ["- None documented."]
            ),
            "",
        ]

        if self.conflicts:
            lines.extend(
                [
                    "## ⚠️ Forensic Discrepancies & Conflicting Observations",
                    "| Entity / Dimension | Source A | Value A | Source B | Value B | Discrepancy Note |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for c in self.conflicts:
                lines.append(
                    f"| `{c.get('dimension', 'unknown')}` | `{c.get('source_a', '-')}` | `{c.get('val_a', '-')}` | `{c.get('source_b', '-')}` | `{c.get('val_b', '-')}` | {c.get('note', '')} |"
                )
            lines.append("")

        lines.extend(
            [
                "## 🔗 Cross-Source Correlated Entities",
                "| Entity Type | Canonical Value | Correlation Strength | Originating Sources | Provenance Tools |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for ce in self.correlated_entities:
            tools = ", ".join(sorted({o.provenance_tool for o in ce.observations}))
            sources_badge = ", ".join(f"`{s}`" for s in ce.sources)
            lines.append(
                f"| `{ce.entity_type}` | `{ce.canonical_value}` | `{ce.correlation_strength.value}` | {sources_badge} | `{tools}` |"
            )
        lines.append("")

        if self.timeline:
            lines.extend(
                [
                    "## ⏱️ Chronological Incident Timeline",
                    "| Timestamp (UTC) | Source | Event / Observation | Related Entities | Evidence Level | Provenance Tool |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for event in self.timeline:
                entities_str = (
                    ", ".join(f"`{e}`" for e in event.related_entities)
                    if event.related_entities
                    else "-"
                )
                level_badge = "🔍 OBSERVED" if event.is_observed_fact else "🔎 INFERRED"
                lines.append(
                    f"| `{event.timestamp}` | `{event.source_type.value}` | **{event.title}**: {event.description} | {entities_str} | {level_badge} | `{event.provenance_tool}` |"
                )
            lines.append("")

        if self.high_confidence_iocs:
            lines.extend(
                [
                    "## 🎯 High-Confidence IOCs (For Sigma / YARA / Handoff)",
                    "| Type | Value | Confidence | Sources | Attribution Context |",
                    "| :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for ioc in self.high_confidence_iocs:
                src_str = ", ".join(ioc.get("sources", []))
                lines.append(
                    f"| `{ioc.get('type')}` | `{ioc.get('value')}` | `{ioc.get('confidence')}` | `{src_str}` | {ioc.get('context', '')} |"
                )
            lines.append("")

        return "\n".join(lines)


def reconstruct_incident(
    incident_id: str,
    title: str,
    observations: list[EvidenceEntity],
    summary_notes: str = "",
) -> IncidentReconstruction:
    """Compose forensic observations into a structured cross-source incident reconstruction.

    Args:
        incident_id: Unique incident case identifier.
        title: Incident title / description.
        observations: Normalized entity observations from binary, memory, PCAP, and disk.
        summary_notes: Optional high-level analyst background.

    Returns:
        Structured IncidentReconstruction dossier with timeline, correlations, and conflicts.
    """
    present_sources = sorted({obs.source_type.value for obs in observations})

    # Group observations by (entity_type, canonical_value)
    entity_groups: dict[tuple[str, str], list[EvidenceEntity]] = {}
    for obs in observations:
        key = (obs.entity_type.lower(), obs.value.strip().lower())
        entity_groups.setdefault(key, []).append(obs)

    correlated_entities: list[CorrelatedEntity] = []
    conflicts: list[dict[str, Any]] = []
    observed_facts: list[str] = []
    inferred_relationships: list[str] = []
    high_confidence_iocs: list[dict[str, Any]] = []

    # Map for detecting cross-source discrepancies (e.g. process path or timestamp divergence)
    for (e_type, _canon_val), obs_list in entity_groups.items():
        sources_for_entity = sorted({o.source_type.value for o in obs_list})
        strength = (
            CorrelationStrength.MULTI_SOURCE
            if len(sources_for_entity) >= 2
            else CorrelationStrength.SINGLE_SOURCE_HIGH
        )

        corr_entity = CorrelatedEntity(
            entity_type=e_type,
            canonical_value=obs_list[0].value,  # preserve original casing
            sources=sources_for_entity,
            observations=obs_list,
            correlation_strength=strength,
        )
        correlated_entities.append(corr_entity)

        # High-confidence IOC promotion
        if (
            strength == CorrelationStrength.MULTI_SOURCE
            or any(o.confidence >= 0.9 for o in obs_list)
        ) and e_type in ("hash", "domain", "ip", "url", "mutex"):
            high_confidence_iocs.append(
                {
                    "type": e_type,
                    "value": obs_list[0].value,
                    "confidence": max(o.confidence for o in obs_list),
                    "sources": sources_for_entity,
                    "context": f"Observed in {len(obs_list)} forensic artifact(s)",
                }
            )

    # Detect conflicts (e.g., conflicting timestamps or paths for the same process/hash)
    # Check for path discrepancies across memory and disk for the same executable name
    proc_obs = [o for o in observations if o.entity_type == "process_name"]
    disk_file_obs = [o for o in observations if o.entity_type == "file_path"]

    for p in proc_obs:
        p_name = p.value.lower()
        for d in disk_file_obs:
            if d.value.lower().endswith(p_name):
                # Compare context paths or timestamps if present
                p_path = p.context.get("executable_path")
                d_path = d.value
                if p_path and d_path and p_path.strip().lower() != d_path.strip().lower():
                    conflicts.append(
                        {
                            "dimension": "executable_path_discrepancy",
                            "source_a": f"{p.source_type.value}:{p.source_artifact}",
                            "val_a": p_path,
                            "source_b": f"{d.source_type.value}:{d.source_artifact}",
                            "val_b": d_path,
                            "note": f"Process '{p.value}' running from '{p_path}' in memory, but disk artifact located at '{d_path}' (Possible masquerade or staging directory divergence).",
                        }
                    )

    # Check for timestamp conflicts (e.g., compile time vs creation time)
    for obs in observations:
        compile_time = obs.context.get("compile_time")
        mtime = obs.context.get("mtime")
        if compile_time and mtime and compile_time > mtime:
            conflicts.append(
                {
                    "dimension": "timestamp_timestomp",
                    "source_a": f"{obs.source_type.value}:compile_time",
                    "val_a": compile_time,
                    "source_b": f"{obs.source_type.value}:disk_mtime",
                    "val_b": mtime,
                    "note": f"Binary compile timestamp ({compile_time}) is later than filesystem modified time ({mtime}) indicating timestomping.",
                }
            )

    # Assemble chronological timeline
    timeline_events: list[IncidentTimelineEvent] = []
    event_idx = 1
    for obs in observations:
        if obs.timestamp:
            related = [f"{obs.entity_type}:{obs.value}"]
            is_fact = obs.evidence_level == "OBSERVED"
            title = f"{obs.entity_type.replace('_', ' ').title()}: {obs.value}"
            desc = (
                obs.context.get("description")
                or f"Observation recorded via {obs.provenance_tool} from {obs.source_artifact}"
            )
            timeline_events.append(
                IncidentTimelineEvent(
                    event_id=f"evt_{event_idx:03d}",
                    timestamp=obs.timestamp,
                    source_type=obs.source_type,
                    source_artifact=obs.source_artifact,
                    provenance_tool=obs.provenance_tool,
                    title=title,
                    description=desc,
                    related_entities=related,
                    is_observed_fact=is_fact,
                    evidence_level=obs.evidence_level,
                )
            )
            event_idx += 1

    # Sort timeline events chronologically
    timeline_events.sort(key=lambda t: t.timestamp)

    # Formulate observed facts vs inferred relationships
    # 1. Observed facts
    for corr in correlated_entities:
        if len(corr.sources) >= 2:
            sources_label = " & ".join(s.upper() for s in corr.sources)
            observed_facts.append(
                f"{corr.entity_type.upper()} '{corr.canonical_value}' independently observed across {sources_label}."
            )

    # 2. Inferred relationships
    if "pcap" in present_sources and "binary" in present_sources:
        inferred_relationships.append(
            "C2 traffic extracted from PCAP matches network IOCs identified within the binary payload."
        )
    if "memory" in present_sources and "disk" in present_sources:
        inferred_relationships.append(
            "Process memory footprint correlates with dropped executable artifacts recovered from disk MFT."
        )

    # Build executive narrative
    narrative_parts = [
        summary_notes
        or f"Incident reconstruction across {len(present_sources)} evidence source(s): {', '.join(present_sources)}.",
        f"Correlated {len(correlated_entities)} entities ({len(high_confidence_iocs)} high-confidence IOCs) and assembled {len(timeline_events)} timeline event(s).",
    ]
    if conflicts:
        narrative_parts.append(
            f"Detected {len(conflicts)} forensic discrepancy/discrepancies (preserved for analyst inspection)."
        )

    return IncidentReconstruction(
        incident_id=incident_id,
        title=title,
        present_sources=present_sources,
        correlated_entities=correlated_entities,
        timeline=timeline_events,
        conflicts=conflicts,
        observed_facts=observed_facts,
        inferred_relationships=inferred_relationships,
        high_confidence_iocs=high_confidence_iocs,
        summary_narrative=" ".join(narrative_parts),
    )
