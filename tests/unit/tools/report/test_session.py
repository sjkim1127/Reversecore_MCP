"""Tests for reversecore_mcp.tools.report.session."""

from datetime import datetime

from reversecore_mcp.tools.report.session import (
    AnalysisSession,
    TimezonePreset,
    get_timezone,
)


class TestTimezonePreset:
    """Tests for TimezonePreset."""

    def test_utc(self):
        preset = TimezonePreset.UTC
        assert preset.name == "UTC"
        assert preset.value == "UTC"

    def test_kst(self):
        preset = TimezonePreset.KST
        assert preset.name == "KST"
        assert preset.value == "Asia/Seoul"

    def test_est(self):
        preset = TimezonePreset.EST
        assert preset.value == "America/New_York"


class TestGetTimezone:
    """Tests for get_timezone."""

    def test_valid(self):
        tz = get_timezone("UTC")
        assert tz is not None

    def test_invalid(self):
        tz = get_timezone("Invalid/Timezone")
        assert tz is not None


class TestAnalysisSession:
    """Tests for AnalysisSession."""

    def test_creation(self):
        session = AnalysisSession(
            session_id="test-123",
            sample_name="test.exe",
            started_at=datetime.now(),
        )
        assert session.session_id == "test-123"
        assert session.sample_name == "test.exe"

    def test_get_duration_not_started(self):
        session = AnalysisSession(session_id="s1")
        assert session.get_duration() is None

    def test_get_duration_str_not_started(self):
        session = AnalysisSession(session_id="s1")
        assert session.get_duration_str() == "N/A"

    def test_get_duration_str_with_hours(self):
        from datetime import datetime, timedelta, timezone

        session = AnalysisSession(session_id="s1")
        session.started_at = datetime.now(timezone.utc) - timedelta(hours=1, minutes=30, seconds=45)
        result = session.get_duration_str()
        assert "1h" in result
        assert "30m" in result
        assert "45s" in result

    def test_add_ioc_invalid_type(self):
        session = AnalysisSession(session_id="s1")
        result = session.add_ioc("unknown_type", "value")
        assert result is False

    def test_to_dict_with_end(self):
        session = AnalysisSession(session_id="s1")
        session.start()
        session.end("completed")
        result = session.to_dict()
        assert result["status"] == "completed"
        assert "ended_at" in result
        assert result["duration"] != "N/A"

    def test_add_ioc_success(self):
        session = AnalysisSession(session_id="s1")
        assert session.add_ioc("hashes", "abc") is True
        assert session.add_ioc("hashes", "abc") is False  # duplicate

    def test_add_note(self):
        session = AnalysisSession(session_id="s1")
        session.add_note("some note", "malware")
        assert len(session.notes) == 1
        assert session.notes[0]["note"] == "some note"
        assert session.notes[0]["category"] == "malware"

    def test_add_mitre(self):
        session = AnalysisSession(session_id="s1")
        session.add_mitre("T1055", "Process Injection", "Defense Evasion")
        session.add_mitre("T1055", "Process Injection", "Defense Evasion")  # duplicate
        assert len(session.mitre_techniques) == 1
        assert session.mitre_techniques[0]["id"] == "T1055"

    def test_add_tag(self):
        session = AnalysisSession(session_id="s1")
        session.add_tag("ransomware")
        session.add_tag("ransomware")  # duplicate
        assert session.tags == ["ransomware"]


def test_fallback_zoneinfo(monkeypatch):
    """Test fallback ZoneInfo when zoneinfo is not available."""
    import sys
    from importlib import reload

    # Block zoneinfo
    monkeypatch.setitem(sys.modules, "zoneinfo", None)

    # Reload session module to trigger ImportError fallback
    from reversecore_mcp.tools.report import session

    reload(session)

    try:
        # Now session.ZoneInfo is the fallback class
        fallback_zi = session.ZoneInfo("Asia/Seoul")
        assert fallback_zi.key == "Asia/Seoul"

        # Test utcoffset
        from datetime import timedelta

        offset = fallback_zi.utcoffset(None)
        assert offset == timedelta(hours=9)

        # Test fallback get_timezone and offsets
        tz = session.get_timezone("Asia/Seoul")
        assert tz.key == "Asia/Seoul"

        # Test get_timezone fallback behavior for invalid zone
        tz_invalid = session.get_timezone("Invalid/Timezone")
        assert tz_invalid.key == "Invalid/Timezone"
    finally:
        # Restore zoneinfo and reload back to normal
        monkeypatch.undo()
        if "zoneinfo" in sys.modules and sys.modules["zoneinfo"] is None:
            del sys.modules["zoneinfo"]
        reload(session)
