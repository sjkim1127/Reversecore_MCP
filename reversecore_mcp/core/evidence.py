"""
Evidence-based analysis types and confidence levels.

This module provides data structures for tracking the evidence level
and confidence of analysis findings, preventing hallucination and
over-inference in automated reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EvidenceLevel(str, Enum):
    """Evidence level classification for analysis findings.

    Based on professional SOC/IR standards:
    - OBSERVED: Directly observed through dynamic analysis or tracing
    - INFERRED: Logically inferred from static analysis (high confidence)
    - POSSIBLE: Hypothesized based on patterns (requires verification)
    """

    OBSERVED = "observed"  # Directly observed (dynamic analysis, logs, traces)
    INFERRED = "inferred"  # Logically inferred from static analysis
    POSSIBLE = "possible"  # Possible but needs verification

    @property
    def symbol(self) -> str:
        """Return a symbol for display."""
        return {
            "observed": "🔍",
            "inferred": "🔎",
            "possible": "❓",
        }[self.value]

    @property
    def confidence_score(self) -> float:
        """Return a confidence score (0.0-1.0)."""
        return {
            "observed": 1.0,
            "inferred": 0.7,
            "possible": 0.4,
        }[self.value]


class MITREConfidence(str, Enum):
    """MITRE ATT&CK mapping confidence levels."""

    CONFIRMED = "confirmed"  # Multiple evidence sources
    HIGH = "high"  # Strong single evidence
    MEDIUM = "medium"  # Inferred from API/patterns
    LOW = "low"  # Possible based on behavior


@dataclass
class Evidence:
    """Evidence record for a finding."""

    source: str  # e.g., "strings", "imports", "decompile", "sandbox"
    location: str  # e.g., "0x401000", "section:.rsrc", "log:procmon"
    description: str  # What was found
    raw_data: str | None = None  # Raw evidence (hex, string, etc.)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "location": self.location,
            "description": self.description,
            "raw_data": self.raw_data,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Finding:
    """An analysis finding with evidence tracking."""

    title: str
    description: str
    level: EvidenceLevel
    category: str  # e.g., "persistence", "encryption", "network"
    evidence: list[Evidence] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def add_evidence(
        self, source: str, location: str, description: str, raw_data: str | None = None
    ) -> None:
        """Add evidence to this finding."""
        self.evidence.append(
            Evidence(
                source=source,
                location=location,
                description=description,
                raw_data=raw_data,
            )
        )

    @property
    def confidence(self) -> float:
        """Calculate overall confidence based on evidence level and count."""
        base = self.level.confidence_score
        # More evidence = higher confidence (up to 20% boost)
        evidence_boost = min(len(self.evidence) * 0.05, 0.2)
        return min(base + evidence_boost, 1.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "level": self.level.value,
            "level_symbol": self.level.symbol,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "evidence_count": len(self.evidence),
            "evidence": [e.to_dict() for e in self.evidence],
            "mitre_techniques": self.mitre_techniques,
        }

    def format_markdown(self) -> str:
        """Format finding as markdown with evidence."""
        lines = [
            f"### {self.level.symbol} [{self.level.value.upper()}] {self.title}",
            "",
            f"**Confidence**: {self.confidence:.0%}",
            f"**Category**: {self.category}",
            "",
            self.description,
            "",
        ]

        if self.evidence:
            lines.append("**Evidence:**")
            for i, ev in enumerate(self.evidence, 1):
                lines.append(f"  {i}. `{ev.source}` @ `{ev.location}`: {ev.description}")
                if ev.raw_data:
                    lines.append("     ```")
                    lines.append(
                        f"     {ev.raw_data[:200]}{'...' if len(ev.raw_data) > 200 else ''}"
                    )
                    lines.append("     ```")

        if self.mitre_techniques:
            lines.append("")
            lines.append(f"**MITRE ATT&CK**: {', '.join(self.mitre_techniques)}")

        return "\n".join(lines)


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique with confidence tracking."""

    technique_id: str  # e.g., "T1055"
    technique_name: str
    tactic: str
    confidence: MITREConfidence
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence.value,
            "evidence_count": len(self.evidence),
        }

    def format_markdown_row(self) -> str:
        """Format as markdown table row."""
        conf_symbol = {
            "confirmed": "✅",
            "high": "🟢",
            "medium": "🟡",
            "low": "🔴",
        }[self.confidence.value]

        return f"| {self.technique_id} | {self.technique_name} | {self.tactic} | {conf_symbol} {self.confidence.value} |"


@dataclass
class AnalysisMetadata:
    """Unified metadata for analysis session (single source of truth)."""

    session_id: str
    sample_name: str
    sample_hash: str  # SHA256
    start_time: datetime
    end_time: datetime | None = None
    analyst: str = "Reversecore MCP"
    tools_used: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Calculate analysis duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()

    @property
    def duration_formatted(self) -> str:
        """Return human-readable duration."""
        seconds = self.duration_seconds
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        else:
            return f"{seconds / 3600:.1f} hours"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "sample_name": self.sample_name,
            "sample_hash": self.sample_hash,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration_formatted,
            "duration_seconds": round(self.duration_seconds, 2),
            "analyst": self.analyst,
            "tools_used": self.tools_used,
        }


# Helper functions for quick finding creation
def observed_finding(title: str, description: str, category: str, **kwargs) -> Finding:
    """Create an OBSERVED level finding."""
    return Finding(
        title=title,
        description=description,
        level=EvidenceLevel.OBSERVED,
        category=category,
        **kwargs,
    )


def inferred_finding(title: str, description: str, category: str, **kwargs) -> Finding:
    """Create an INFERRED level finding."""
    return Finding(
        title=title,
        description=description,
        level=EvidenceLevel.INFERRED,
        category=category,
        **kwargs,
    )


def possible_finding(title: str, description: str, category: str, **kwargs) -> Finding:
    """Create a POSSIBLE level finding."""
    return Finding(
        title=title,
        description=description,
        level=EvidenceLevel.POSSIBLE,
        category=category,
        **kwargs,
    )
