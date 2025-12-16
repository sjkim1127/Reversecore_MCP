"""
Evidence-based Report Generator for Malware Analysis.

This module generates professional SOC/IR reports with evidence tracking,
confidence levels, and clear differentiation between observed facts and inferences.
"""

from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass, field

from reversecore_mcp.core.evidence import (
    EvidenceLevel,
    MITREConfidence,
    Finding,
    Evidence,
    MITRETechnique,
    AnalysisMetadata,
)
from reversecore_mcp.core import json_utils as json


@dataclass
class EvidenceBasedReport:
    """Evidence-based malware analysis report."""
    
    metadata: AnalysisMetadata
    executive_summary: str = ""
    malware_family: str = "Unknown"
    family_confidence: float = 0.0
    family_evidence: list[str] = field(default_factory=list)
    
    findings: list[Finding] = field(default_factory=list)
    mitre_techniques: list[MITRETechnique] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    
    recommendations: list[str] = field(default_factory=list)
    yara_rule: Optional[str] = None
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self.findings.append(finding)
    
    def add_mitre(self, technique: MITRETechnique) -> None:
        """Add a MITRE technique mapping."""
        self.mitre_techniques.append(technique)
    
    def add_ioc(self, ioc_type: str, value: str) -> None:
        """Add an IOC."""
        if ioc_type not in self.iocs:
            self.iocs[ioc_type] = []
        if value not in self.iocs[ioc_type]:
            self.iocs[ioc_type].append(value)
    
    def set_family(self, family: str, confidence: float, evidence: list[str]) -> None:
        """Set malware family with confidence and evidence."""
        self.malware_family = family
        self.family_confidence = confidence
        self.family_evidence = evidence
    
    def finalize(self) -> None:
        """Finalize the report (set end time)."""
        self.metadata.end_time = datetime.now()
    
    @property
    def observed_count(self) -> int:
        return sum(1 for f in self.findings if f.level == EvidenceLevel.OBSERVED)
    
    @property
    def inferred_count(self) -> int:
        return sum(1 for f in self.findings if f.level == EvidenceLevel.INFERRED)
    
    @property
    def possible_count(self) -> int:
        return sum(1 for f in self.findings if f.level == EvidenceLevel.POSSIBLE)
    
    @property
    def overall_confidence(self) -> float:
        """Calculate overall report confidence."""
        if not self.findings:
            return 0.0
        return sum(f.confidence for f in self.findings) / len(self.findings)
    
    def generate_markdown(self) -> str:
        """Generate professional markdown report."""
        lines = []
        
        # Header
        lines.append(f"# 🔬 Malware Analysis Report")
        lines.append("")
        lines.append(f"**Sample**: {self.metadata.sample_name}")
        lines.append(f"**SHA256**: `{self.metadata.sample_hash}`")
        lines.append(f"**Analysis Date**: {self.metadata.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Duration**: {self.metadata.duration_formatted}")
        lines.append(f"**Analyst**: {self.metadata.analyst}")
        lines.append("")
        
        # Confidence Summary Box
        lines.append("---")
        lines.append("")
        lines.append("## 📊 Confidence Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Overall Confidence** | {self.overall_confidence:.0%} |")
        lines.append(f"| 🔍 Observed Findings | {self.observed_count} |")
        lines.append(f"| 🔎 Inferred Findings | {self.inferred_count} |")
        lines.append(f"| ❓ Possible Findings | {self.possible_count} |")
        lines.append("")
        
        # Malware Family Identification
        lines.append("---")
        lines.append("")
        lines.append("## 🦠 Malware Identification")
        lines.append("")
        
        if self.family_confidence >= 0.8:
            verdict = "✅ **CONFIRMED**"
        elif self.family_confidence >= 0.6:
            verdict = "🟡 **LIKELY**"
        elif self.family_confidence >= 0.4:
            verdict = "🟠 **POSSIBLE**"
        else:
            verdict = "❓ **UNCERTAIN**"
        
        lines.append(f"**Family**: {self.malware_family}")
        lines.append(f"**Confidence**: {self.family_confidence:.0%} {verdict}")
        lines.append("")
        
        if self.family_evidence:
            lines.append("**Identification Evidence:**")
            for ev in self.family_evidence:
                lines.append(f"  - {ev}")
            lines.append("")
        
        # Executive Summary
        if self.executive_summary:
            lines.append("---")
            lines.append("")
            lines.append("## 📋 Executive Summary")
            lines.append("")
            lines.append(self.executive_summary)
            lines.append("")
        
        # Findings by Evidence Level
        lines.append("---")
        lines.append("")
        lines.append("## 🔍 Analysis Findings")
        lines.append("")
        lines.append("> **Legend**: 🔍 Observed (verified) | 🔎 Inferred (high confidence) | ❓ Possible (needs verification)")
        lines.append("")
        
        # Group findings by level
        for level in [EvidenceLevel.OBSERVED, EvidenceLevel.INFERRED, EvidenceLevel.POSSIBLE]:
            level_findings = [f for f in self.findings if f.level == level]
            if level_findings:
                lines.append(f"### {level.symbol} {level.value.upper()} Findings ({len(level_findings)})")
                lines.append("")
                for finding in level_findings:
                    lines.append(finding.format_markdown())
                    lines.append("")
        
        # MITRE ATT&CK Mapping
        if self.mitre_techniques:
            lines.append("---")
            lines.append("")
            lines.append("## ⚔️ MITRE ATT&CK Mapping")
            lines.append("")
            lines.append("> **Confidence Levels**: ✅ Confirmed | 🟢 High | 🟡 Medium | 🔴 Low")
            lines.append("")
            lines.append("| Technique ID | Name | Tactic | Confidence |")
            lines.append("|-------------|------|--------|------------|")
            for tech in self.mitre_techniques:
                lines.append(tech.format_markdown_row())
            lines.append("")
        
        # IOCs
        if self.iocs:
            lines.append("---")
            lines.append("")
            lines.append("## 🎯 Indicators of Compromise (IOCs)")
            lines.append("")
            for ioc_type, values in self.iocs.items():
                lines.append(f"### {ioc_type.title()} ({len(values)})")
                lines.append("")
                for val in values:
                    lines.append(f"- `{val}`")
                lines.append("")
        
        # YARA Rule
        if self.yara_rule:
            lines.append("---")
            lines.append("")
            lines.append("## 📝 Detection Rule (YARA)")
            lines.append("")
            lines.append("```yara")
            lines.append(self.yara_rule)
            lines.append("```")
            lines.append("")
        
        # Recommendations
        if self.recommendations:
            lines.append("---")
            lines.append("")
            lines.append("## 🛡️ Recommendations")
            lines.append("")
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("")
        lines.append("## 📎 Report Metadata")
        lines.append("")
        lines.append(f"- **Session ID**: {self.metadata.session_id}")
        lines.append(f"- **Start Time**: {self.metadata.start_time.isoformat()}")
        if self.metadata.end_time:
            lines.append(f"- **End Time**: {self.metadata.end_time.isoformat()}")
        lines.append(f"- **Duration**: {self.metadata.duration_formatted}")
        lines.append(f"- **Tools Used**: {', '.join(self.metadata.tools_used) if self.metadata.tools_used else 'N/A'}")
        lines.append("")
        lines.append("---")
        lines.append(f"*Generated by Reversecore MCP Server*")
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for JSON export."""
        return {
            "metadata": self.metadata.to_dict(),
            "executive_summary": self.executive_summary,
            "malware_family": self.malware_family,
            "family_confidence": self.family_confidence,
            "family_evidence": self.family_evidence,
            "confidence_summary": {
                "overall": round(self.overall_confidence, 2),
                "observed_count": self.observed_count,
                "inferred_count": self.inferred_count,
                "possible_count": self.possible_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "mitre_techniques": [t.to_dict() for t in self.mitre_techniques],
            "iocs": self.iocs,
            "recommendations": self.recommendations,
            "yara_rule": self.yara_rule,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export report as JSON."""
        return json.dumps(self.to_dict(), indent=indent)


def create_report(
    session_id: str,
    sample_name: str,
    sample_hash: str,
    analyst: str = "Reversecore MCP",
) -> EvidenceBasedReport:
    """Create a new evidence-based report."""
    metadata = AnalysisMetadata(
        session_id=session_id,
        sample_name=sample_name,
        sample_hash=sample_hash,
        start_time=datetime.now(),
        analyst=analyst,
    )
    return EvidenceBasedReport(metadata=metadata)
