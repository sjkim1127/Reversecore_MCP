"""
Session management for malware analysis reports.

Provides AnalysisSession dataclass and timezone utilities.
"""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class TimezonePreset(Enum):
    """Frequently used timezone presets"""
    UTC = "UTC"
    KST = "Asia/Seoul"          # UTC+9
    JST = "Asia/Tokyo"          # UTC+9
    CST = "Asia/Shanghai"       # UTC+8
    EST = "America/New_York"    # UTC-5/-4
    PST = "America/Los_Angeles" # UTC-8/-7
    CET = "Europe/Paris"        # UTC+1/+2
    GMT = "Europe/London"       # UTC+0/+1


# Timezone handling using standard library zoneinfo (Python 3.9+)
try:
    from zoneinfo import ZoneInfo
except ImportError:
    # Fallback for older python versions if backports.zoneinfo not installed
    from datetime import timezone, timedelta
    
    class ZoneInfo:
        def __init__(self, key: str):
            self.key = key
            
        def utcoffset(self, dt):
            # Very basic fallback - DOES NOT HANDLE DST
            # This is just to prevent crashes if zoneinfo missing
            offsets = {
                "Asia/Seoul": 9, "Asia/Tokyo": 9, "Asia/Shanghai": 8,
                "America/New_York": -5, "America/Los_Angeles": -8,
                "Europe/Paris": 1, "Europe/London": 0, "UTC": 0
            }
            return timedelta(hours=offsets.get(self.key, 0))

def get_timezone(tz_name: str):
    """Get timezone object by name with DST support."""
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return ZoneInfo("UTC")

# Timezone offsets (standard time)
TIMEZONE_OFFSETS: dict[str, int] = {
    "UTC": 0,
    "Asia/Seoul": 9,
    "Asia/Tokyo": 9,
    "Asia/Shanghai": 8,
    "America/New_York": -5,
    "America/Los_Angeles": -8,
    "Europe/Paris": 1,
    "Europe/London": 0,
}

# Timezone abbreviation mapping (kept for display purposes)
TIMEZONE_ABBRS: dict[str, str] = {
    "UTC": "UTC",
    "Asia/Seoul": "KST",
    "Asia/Tokyo": "JST",
    "Asia/Shanghai": "CST",
    "America/New_York": "ET",
    "America/Los_Angeles": "PT",
    "Europe/Paris": "CET",
    "Europe/London": "GMT",
}


@dataclass
class AnalysisSession:
    """Data class for tracking analysis session information"""
    session_id: str
    sample_path: str | None = None
    sample_name: str | None = None
    analyst: str = "Security Researcher"

    # Timestamps (stored in UTC)
    started_at: datetime | None = None
    ended_at: datetime | None = None

    # Session status
    status: str = "initialized"  # initialized, in_progress, completed, aborted

    # Data collected during analysis
    findings: dict[str, Any] = field(default_factory=dict)
    iocs: dict[str, list[str]] = field(default_factory=lambda: {
        "hashes": [],
        "ips": [],
        "domains": [],
        "urls": [],
        "files": [],
        "registry": [],
        "mutexes": [],
        "emails": [],
        "bitcoin_addresses": [],   # For ransomware BTC wallets
        "crypto_wallets": [],      # ETH, XMR, etc.
    })
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    notes: list[dict[str, str]] = field(default_factory=list)

    # Additional metadata
    tags: list[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    malware_family: str | None = None

    def start(self):
        """Start session"""
        self.started_at = datetime.now(timezone.utc)
        self.status = "in_progress"

    def end(self, status: str = "completed"):
        """End session"""
        self.ended_at = datetime.now(timezone.utc)
        self.status = status

    def get_duration(self) -> timedelta | None:
        """Calculate analysis duration"""
        if not self.started_at:
            return None
        end = self.ended_at or datetime.now(timezone.utc)
        return end - self.started_at

    def get_duration_str(self) -> str:
        """Human-readable duration string"""
        duration = self.get_duration()
        if duration is None:
            return "N/A"

        total_seconds = int(duration.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")

        return " ".join(parts)

    def add_ioc(self, ioc_type: str, value: str) -> bool:
        """Add IOC"""
        if ioc_type in self.iocs and value not in self.iocs[ioc_type]:
            self.iocs[ioc_type].append(value)
            return True
        return False

    def add_note(self, note: str, category: str = "general"):
        """Add analysis note"""
        timestamp = datetime.now(timezone.utc).isoformat()
        self.notes.append({
            "timestamp": timestamp,
            "note": note,
            "category": category
        })

    def add_mitre(self, technique_id: str, technique_name: str, tactic: str):
        """Add MITRE ATT&CK technique"""
        entry = {"id": technique_id, "name": technique_name, "tactic": tactic}
        if entry not in self.mitre_techniques:
            self.mitre_techniques.append(entry)

    def add_tag(self, tag: str):
        """Add tag"""
        if tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        data = asdict(self)
        # Convert datetime objects to ISO format
        if self.started_at:
            data["started_at"] = self.started_at.isoformat()
        if self.ended_at:
            data["ended_at"] = self.ended_at.isoformat()
        data["duration"] = self.get_duration_str()
        return data
