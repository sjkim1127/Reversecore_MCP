"""Tests for reversecore_mcp.tools.report.session."""

from datetime import datetime

from reversecore_mcp.tools.report.session import AnalysisSession, TimezonePreset, get_timezone


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
