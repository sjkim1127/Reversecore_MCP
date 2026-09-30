"""Unit tests for ReportTools module."""

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.tools.report.report_tools import ReportTools
from reversecore_mcp.tools.report.session import TIMEZONE_OFFSETS


class TestReportToolsInit:
    """Tests for ReportTools initialization."""

    def test_init_creates_directories(self, tmp_path):
        """Should create output directory on init."""
        out_dir = tmp_path / "reports"
        rt = ReportTools(template_dir=tmp_path / "templates", output_dir=out_dir)
        assert out_dir.exists()
        assert rt.template_dir == tmp_path / "templates"

    def test_init_default_timezone(self, tmp_path):
        """Should default to UTC timezone."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        assert rt.default_timezone == "UTC"
        assert rt.timezone_offset == 0

    def test_init_custom_timezone(self, tmp_path):
        """Should accept custom timezone."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path, default_timezone="Asia/Seoul")
        assert rt.default_timezone == "Asia/Seoul"
        assert rt.timezone_offset == TIMEZONE_OFFSETS["Asia/Seoul"]


class TestTimezoneManagement:
    """Tests for timezone methods."""

    def test_set_timezone_valid(self, tmp_path):
        """Should return timezone info for valid timezone."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        result = rt.set_timezone("Asia/Seoul")
        assert result["success"] is True
        assert result["timezone"] == "Asia/Seoul"
        assert "current_time" in result

    def test_set_timezone_updates_state_used_by_time_operations(self, tmp_path):
        rt = ReportTools(
            template_dir=tmp_path,
            output_dir=tmp_path,
            default_timezone="Asia/Seoul",
        )

        rt.set_timezone("UTC")
        utc_info = rt.get_timezone_info()
        utc_timestamp = rt.get_timestamp_data()
        assert utc_info["current_timezone"] == "UTC"
        assert utc_info["utc_offset"] == 0
        assert utc_timestamp["timezone"] == "UTC"
        assert utc_timestamp["timezone_offset"] == "UTC+0"

        rt.set_timezone("Asia/Tokyo")
        tokyo_info = rt.get_timezone_info()
        tokyo_timestamp = rt.get_timestamp_data()
        assert tokyo_info["current_timezone"] == "Asia/Tokyo"
        assert tokyo_info["utc_offset"] == 9
        assert tokyo_timestamp["timezone"] == "Asia/Tokyo"
        assert tokyo_timestamp["timezone_offset"] == "UTC+9"

    def test_set_timezone_invalid(self, tmp_path):
        """Should reject unknown timezone."""
        rt = ReportTools(
            template_dir=tmp_path,
            output_dir=tmp_path,
            default_timezone="Asia/Seoul",
        )
        result = rt.set_timezone("Mars/Colony")
        assert result["success"] is False
        assert "Unknown timezone" in result["error"]
        assert "available" in result
        assert rt.get_timezone_info()["current_timezone"] == "Asia/Seoul"

    def test_get_timezone_info(self, tmp_path):
        """Should return timezone config."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path, default_timezone="UTC")
        result = rt.get_timezone_info()
        assert result["current_timezone"] == "UTC"
        assert "utc_offset" in result
        assert "available_timezones" in result

    @pytest.mark.parametrize(
        ("utc_now", "zone", "expected_time", "expected_abbr", "expected_offset"),
        [
            (
                datetime(2026, 3, 8, 6, 59, tzinfo=timezone.utc),
                "America/New_York",
                "01:59:00",
                "EST",
                "UTC-5",
            ),
            (
                datetime(2026, 3, 8, 7, 1, tzinfo=timezone.utc),
                "America/New_York",
                "03:01:00",
                "EDT",
                "UTC-4",
            ),
            (
                datetime(2026, 11, 1, 5, 59, tzinfo=timezone.utc),
                "America/New_York",
                "01:59:00",
                "EDT",
                "UTC-4",
            ),
            (
                datetime(2026, 11, 1, 6, 1, tzinfo=timezone.utc),
                "America/New_York",
                "01:01:00",
                "EST",
                "UTC-5",
            ),
            (
                datetime(2026, 3, 8, 9, 59, tzinfo=timezone.utc),
                "America/Los_Angeles",
                "01:59:00",
                "PST",
                "UTC-8",
            ),
            (
                datetime(2026, 3, 8, 10, 1, tzinfo=timezone.utc),
                "America/Los_Angeles",
                "03:01:00",
                "PDT",
                "UTC-7",
            ),
            (
                datetime(2026, 11, 1, 8, 59, tzinfo=timezone.utc),
                "America/Los_Angeles",
                "01:59:00",
                "PDT",
                "UTC-7",
            ),
            (
                datetime(2026, 11, 1, 9, 1, tzinfo=timezone.utc),
                "America/Los_Angeles",
                "01:01:00",
                "PST",
                "UTC-8",
            ),
            (
                datetime(2026, 3, 29, 0, 59, tzinfo=timezone.utc),
                "Europe/Paris",
                "01:59:00",
                "CET",
                "UTC+1",
            ),
            (
                datetime(2026, 3, 29, 1, 1, tzinfo=timezone.utc),
                "Europe/Paris",
                "03:01:00",
                "CEST",
                "UTC+2",
            ),
            (
                datetime(2026, 10, 25, 0, 59, tzinfo=timezone.utc),
                "Europe/Paris",
                "02:59:00",
                "CEST",
                "UTC+2",
            ),
            (
                datetime(2026, 10, 25, 1, 1, tzinfo=timezone.utc),
                "Europe/Paris",
                "02:01:00",
                "CET",
                "UTC+1",
            ),
            (
                datetime(2026, 3, 29, 0, 59, tzinfo=timezone.utc),
                "Europe/London",
                "00:59:00",
                "GMT",
                "UTC+0",
            ),
            (
                datetime(2026, 3, 29, 1, 1, tzinfo=timezone.utc),
                "Europe/London",
                "02:01:00",
                "BST",
                "UTC+1",
            ),
            (
                datetime(2026, 10, 25, 0, 59, tzinfo=timezone.utc),
                "Europe/London",
                "01:59:00",
                "BST",
                "UTC+1",
            ),
            (
                datetime(2026, 10, 25, 1, 1, tzinfo=timezone.utc),
                "Europe/London",
                "01:01:00",
                "GMT",
                "UTC+0",
            ),
            (
                datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
                "Asia/Seoul",
                "09:00:00",
                "KST",
                "UTC+9",
            ),
            (
                datetime(2026, 7, 1, 0, 0, tzinfo=timezone.utc),
                "Asia/Seoul",
                "09:00:00",
                "KST",
                "UTC+9",
            ),
        ],
    )
    def test_timezone_conversion_tracks_dst_and_fixed_offsets(
        self, tmp_path, utc_now, zone, expected_time, expected_abbr, expected_offset
    ):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        with patch("reversecore_mcp.tools.report.report_tools.datetime") as datetime_mock:
            datetime_mock.now.return_value = utc_now
            result = rt.get_timestamp_data(zone)

        assert result["time"] == expected_time
        assert result["timezone_abbr"] == expected_abbr
        assert result["timezone_offset"] == expected_offset
        assert rt._format_time(utc_now, tz_name=zone).endswith(f"({expected_abbr})")

    def test_timezone_info_uses_current_dst_offset(self, tmp_path):
        rt = ReportTools(
            template_dir=tmp_path,
            output_dir=tmp_path,
            default_timezone="America/New_York",
        )
        summer_utc = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
        with patch("reversecore_mcp.tools.report.report_tools.datetime") as datetime_mock:
            datetime_mock.now.return_value = summer_utc
            result = rt.get_timezone_info()

        assert result["utc_offset"] == -4
        assert result["abbreviation"] == "EDT"
        assert result["available_timezones"]["America/New_York"] == {
            "offset": "UTC-4",
            "abbreviation": "EDT",
        }


class TestTimestampGeneration:
    """Tests for timestamp methods."""

    def test_get_timestamp_data(self, tmp_path):
        """Should return timestamp data dict."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        result = rt.get_timestamp_data()
        assert "timestamp_unix" in result
        assert "datetime_iso" in result
        assert "date" in result
        assert "time" in result
        assert "timezone" in result
        assert "platform" in result

    def test_get_timestamp_data_with_tz(self, tmp_path):
        """Should return timestamp in specified timezone."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        result = rt.get_timestamp_data("Asia/Seoul")
        assert result["timezone"] == "Asia/Seoul"

    @pytest.mark.asyncio
    async def test_get_current_time(self, tmp_path):
        """Should return current time data."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        result = await rt.get_current_time()
        assert "timestamp_unix" in result


class TestSessionManagement:
    """Tests for session lifecycle."""

    @pytest.fixture
    def rt(self, tmp_path):
        return ReportTools(template_dir=tmp_path, output_dir=tmp_path)

    @pytest.mark.asyncio
    async def test_start_session(self, rt):
        """Should create and start a session."""
        result = await rt.start_session(sample_path="/app/test.bin", analyst="Alice")
        assert result["success"] is True
        assert "session_id" in result
        assert rt.current_session_id == result["session_id"]

    @pytest.mark.asyncio
    async def test_start_session_without_sample(self, rt):
        """Should create session without sample path."""
        result = await rt.start_session(analyst="Bob")
        assert result["success"] is True
        assert result["session_id"] in rt.sessions

    @pytest.mark.asyncio
    async def test_start_session_with_tags_and_sample(self, rt, tmp_path):
        sample = tmp_path / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        result = await rt.start_session(sample_path=str(sample), tags=["trojan", "backdoor"])
        assert result["success"] is True
        assert "trojan" in rt.sessions[result["session_id"]].tags

    @pytest.mark.asyncio
    async def test_end_session(self, rt):
        """Should end active session."""
        await rt.start_session()
        sid = rt.current_session_id
        result = await rt.end_session(status="completed", summary="Done")
        assert result["success"] is True
        assert result["session_id"] == sid
        assert "duration" in result
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_end_session_not_found(self, rt):
        """Should handle ending non-existent session."""
        result = await rt.end_session(session_id="nonexistent")
        assert result["success"] is False
        assert "No active session found" in result["error"]

    @pytest.mark.asyncio
    async def test_get_session_info(self, rt):
        """Should return session info."""
        await rt.start_session(analyst="Charlie")
        result = await rt.get_session_info()
        assert result["success"] is True
        assert "session" in result
        assert result["session"]["analyst"] == "Charlie"

    @pytest.mark.asyncio
    async def test_get_session_info_after_end(self, rt):
        result = await rt.start_session()
        sid = result["session_id"]
        await rt.end_session(status="completed")
        result = await rt.get_session_info(session_id=sid)
        assert result["success"] is True
        assert "ended_at_formatted" in result["session"]

    @pytest.mark.asyncio
    async def test_add_session_ioc(self, rt):
        """Should add IOC to session."""
        await rt.start_session()
        result = await rt.add_session_ioc("ips", "192.168.1.1")
        assert result["success"] is True
        assert result["ioc"]["type"] == "ips"
        assert result["total_iocs"] == 1

    @pytest.mark.asyncio
    async def test_add_session_note(self, rt):
        """Should add note to session."""
        await rt.start_session()
        result = await rt.add_session_note("Suspicious import table")
        assert result["success"] is True
        assert result["note_added"] == "Suspicious import table"
        assert result["total_notes"] == 1

    @pytest.mark.asyncio
    async def test_add_session_mitre(self, rt):
        """Should add MITRE technique."""
        await rt.start_session()
        result = await rt.add_session_mitre("T1055", "Process Injection", "Defense Evasion")
        assert result["success"] is True
        assert result["total_techniques"] == 1

    @pytest.mark.asyncio
    async def test_add_session_tag(self, rt):
        """Should add tag to session."""
        await rt.start_session()
        result = await rt.add_session_tag("trojan")
        assert result["success"] is True
        assert "trojan" in result["all_tags"]

    @pytest.mark.asyncio
    async def test_set_session_severity(self, rt):
        """Should set session severity."""
        await rt.start_session()
        result = await rt.set_session_severity("high")
        assert result["success"] is True
        assert result["severity"] == "high"

    @pytest.mark.asyncio
    async def test_set_session_severity_invalid(self, rt):
        """Should reject invalid severity."""
        await rt.start_session()
        result = await rt.set_session_severity("extreme")
        assert result["success"] is False
        assert "Invalid severity" in result["error"]

    @pytest.mark.asyncio
    async def test_add_session_tag_no_session(self, rt):
        result = await rt.add_session_tag("trojan")
        assert result["success"] is False
        assert "No active session" in result["error"]

    @pytest.mark.asyncio
    async def test_set_session_severity_no_session(self, rt):
        result = await rt.set_session_severity("high")
        assert result["success"] is False
        assert "No active session" in result["error"]

    @pytest.mark.asyncio
    async def test_add_session_ioc_no_session(self, rt):
        result = await rt.add_session_ioc("ips", "1.1.1.1")
        assert result["success"] is False
        assert "No active session" in result["error"]

    @pytest.mark.asyncio
    async def test_add_session_ioc_invalid_type(self, rt):
        await rt.start_session()
        result = await rt.add_session_ioc("invalid_type", "value")
        assert result["success"] is False
        assert "Invalid IOC type" in result["error"]

    @pytest.mark.asyncio
    async def test_add_session_note_no_session(self, rt):
        result = await rt.add_session_note("note")
        assert result["success"] is False
        assert "No active session" in result["error"]

    @pytest.mark.asyncio
    async def test_add_session_mitre_no_session(self, rt):
        result = await rt.add_session_mitre("T1055", "Process Injection", "Defense Evasion")
        assert result["success"] is False
        assert "No active session" in result["error"]

    @pytest.mark.asyncio
    async def test_list_sessions(self, rt):
        """Should list all sessions."""
        await rt.start_session(sample_path="/app/a.bin")
        await rt.start_session(sample_path="/app/b.bin")
        result = await rt.list_sessions()
        assert result["total"] == 2
        assert len(result["sessions"]) == 2

    @pytest.mark.asyncio
    async def test_sessions_are_isolated_by_owner(self, rt):
        """Implicit and explicit session access stays within the caller boundary."""
        session_a = await rt.start_session(analyst="Alice", owner_id="client-a")
        session_b = await rt.start_session(analyst="Bob", owner_id="client-b")
        sid_a = session_a["session_id"]
        sid_b = session_b["session_id"]
        assert rt.current_session_id is None

        note_a = await rt.add_session_note("A note", owner_id="client-a")
        assert note_a["success"] is True
        assert note_a["total_notes"] == 1
        assert (await rt.add_session_ioc("ips", "192.0.2.1", owner_id="client-a"))["success"]
        assert (await rt.add_session_note("B note", owner_id="client-b"))["success"]
        assert (await rt.add_session_ioc("ips", "198.51.100.2", owner_id="client-b"))["success"]

        info_a = await rt.get_session_info(owner_id="client-a")
        info_b = await rt.get_session_info(owner_id="client-b")
        assert info_a["session"]["session_id"] == sid_a
        assert info_a["session"]["analyst"] == "Alice"
        assert info_a["session"]["notes"][0]["note"] == "A note"
        assert info_a["session"]["iocs"]["ips"] == ["192.0.2.1"]
        assert info_b["session"]["session_id"] == sid_b
        assert info_b["session"]["analyst"] == "Bob"
        assert info_b["session"]["notes"][0]["note"] == "B note"
        assert info_b["session"]["iocs"]["ips"] == ["198.51.100.2"]

        sessions_a = await rt.list_sessions(owner_id="client-a")
        sessions_b = await rt.list_sessions(owner_id="client-b")
        assert sessions_a["total"] == 1
        assert sessions_a["current_session"] == sid_a
        assert [item["session_id"] for item in sessions_a["sessions"]] == [sid_a]
        assert sessions_b["total"] == 1
        assert sessions_b["current_session"] == sid_b
        assert [item["session_id"] for item in sessions_b["sessions"]] == [sid_b]

        cross_owner_status = await rt.get_session_info(sid_b, owner_id="client-a")
        assert cross_owner_status["success"] is False
        assert cross_owner_status["active_sessions"] == [sid_a]
        cross_owner_note = await rt.add_session_note(
            "Should not be written", session_id=sid_b, owner_id="client-a"
        )
        assert cross_owner_note["success"] is False
        cross_owner_end = await rt.end_session(session_id=sid_b, owner_id="client-a")
        assert cross_owner_end["success"] is False
        assert rt.sessions[sid_b].status == "in_progress"

        explicit_note = await rt.add_session_note(
            "Explicit A note", session_id=sid_a, owner_id="client-a"
        )
        assert explicit_note["success"] is True
        ended_a = await rt.end_session(owner_id="client-a")
        assert ended_a["session_id"] == sid_a
        assert (await rt.get_session_info(owner_id="client-b"))["session"]["session_id"] == sid_b

    @pytest.mark.asyncio
    async def test_owner_cannot_create_report_from_another_owners_session(self, rt):
        template = rt.template_dir / "full_analysis.md"
        template.write_text("{{SESSION_ID}}", encoding="utf-8")
        session_a = await rt.start_session(owner_id="client-a")
        session_b = await rt.start_session(owner_id="client-b")
        existing_files = set(rt.output_dir.glob("*.md"))

        result = await rt.create_report(
            template_type="full_analysis",
            session_id=session_b["session_id"],
            owner_id="client-a",
        )

        assert result == {"success": False, "error": "No active session found"}
        assert set(rt.output_dir.glob("*.md")) == existing_files
        assert session_a["session_id"] != session_b["session_id"]

    @pytest.mark.asyncio
    async def test_session_id_collision_does_not_replace_existing_owner(self, rt):
        existing = await rt.start_session(owner_id="client-a")
        duplicate_hex = existing["session_id"].removeprefix("SES-").lower()

        with (
            patch(
                "reversecore_mcp.tools.report.report_tools.uuid.uuid4",
                side_effect=[
                    SimpleNamespace(hex=duplicate_hex),
                    SimpleNamespace(hex="12345678abcdef00"),
                ],
            ),
            patch.object(rt, "_extract_sample_info", new=AsyncMock(return_value={})),
        ):
            created = await rt.start_session(sample_path="/tmp/sample.bin", owner_id="client-b")

        assert created["session_id"] != existing["session_id"]
        assert rt.sessions[existing["session_id"]].analyst == "Security Researcher"
        assert rt.session_owners[existing["session_id"]] == "client-a"
        assert rt.session_owners[created["session_id"]] == "client-b"


class TestReportGeneration:
    """Tests for report generation."""

    @pytest.fixture
    def rt(self, tmp_path):
        return ReportTools(template_dir=tmp_path, output_dir=tmp_path)

    @pytest.mark.asyncio
    async def test_create_report_no_session(self, rt):
        """Should fail when template is missing."""
        result = await rt.create_report()
        assert result["success"] is False
        assert "Template not found" in result["error"]

    @pytest.mark.asyncio
    async def test_create_report_uses_updated_default_timezone(self, rt):
        template = rt.template_dir / "full_analysis.md"
        template.write_text("{{TIMEZONE}}|{{TIMEZONE_ABBR}}|{{DATETIME_FULL}}", encoding="utf-8")

        rt.set_timezone("UTC")
        utc_result = await rt.create_report(template_type="full_analysis")
        assert utc_result["success"] is True
        assert "UTC|UTC|" in utc_result["report_content"]

        rt.set_timezone("Asia/Tokyo")
        tokyo_result = await rt.create_report(template_type="full_analysis")
        assert tokyo_result["success"] is True
        assert "Asia/Tokyo|JST|" in tokyo_result["report_content"]

    @pytest.mark.asyncio
    async def test_create_report_full(self, rt):
        """Should generate full analysis report."""
        # Create a minimal template
        template = rt.template_dir / "full_analysis.md"
        template.write_text("# Report\nSeverity: {{{SEVERITY}}}\n")
        await rt.start_session(sample_path="/app/test.bin", analyst="Alice")
        await rt.add_session_ioc("hashes", "d41d8cd98f00b204e9800998ecf8427e")
        result = await rt.create_report(template_type="full_analysis")
        assert result["success"] is True
        assert "report_id" in result
        assert "path" in result
        assert Path(result["path"]).exists()

    @pytest.mark.asyncio
    async def test_create_report_with_custom_fields(self, rt):
        template = rt.template_dir / "full_analysis.md"
        template.write_text("# {{{CUSTOM_KEY}}}\n")
        await rt.start_session()
        result = await rt.create_report(
            template_type="full_analysis", custom_fields={"custom_key": "custom_value"}
        )
        assert result["success"] is True
        assert "custom_value" in result["report_content"]

    @pytest.mark.asyncio
    async def test_list_templates(self, rt):
        """Should list available templates."""
        result = await rt.list_templates()
        assert "total" in result
        assert "templates" in result
        assert isinstance(result["templates"], list)

    @pytest.mark.asyncio
    async def test_get_report(self, rt):
        """Should retrieve generated report."""
        template = rt.template_dir / "full_analysis.md"
        template.write_text("# Report\n")
        await rt.start_session()
        created = await rt.create_report(template_type="full_analysis")
        rid = created["report_id"]
        result = await rt.get_report(rid)
        assert result["success"] is True
        assert "content" in result
        assert "size" in result

    @pytest.mark.asyncio
    async def test_get_report_not_found(self, rt):
        """Should handle missing report."""
        result = await rt.get_report("nonexistent")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "report_id",
        ["../secret", "../../etc/passwd", "/tmp/report", "nested/report", "nested\\report"],
    )
    async def test_get_report_rejects_path_like_ids(self, rt, report_id):
        """Path-like report IDs must never be interpreted as filesystem paths."""
        outside = rt.output_dir.parent / "secret.md"
        outside.write_text("sensitive")
        result = await rt.get_report(report_id)
        assert result["success"] is False
        assert result["error"] == "Invalid report ID or report not found"
        assert "sensitive" not in str(result)

    @pytest.mark.asyncio
    async def test_list_reports(self, rt):
        """Should list generated reports."""
        template = rt.template_dir / "full_analysis.md"
        template.write_text("# Report\n")
        await rt.start_session()
        await rt.create_report(template_type="full_analysis")
        result = await rt.list_reports()
        assert result["total"] >= 1
        assert len(result["reports"]) >= 1


class TestEmailAndContacts:
    """Tests for email and contact management."""

    @pytest.fixture
    def rt(self, tmp_path):
        return ReportTools(template_dir=tmp_path, output_dir=tmp_path)

    @pytest.mark.asyncio
    async def test_get_email_status(self, rt):
        """Should return email config status."""
        result = await rt.get_email_status()
        assert "configured" in result
        assert "smtp_server" in result

    @pytest.mark.asyncio
    async def test_configure_email(self, rt):
        """Should update email configuration."""
        result = await rt.configure_email("smtp.example.com", 587, "user", "pass")
        assert result["success"] is True
        assert rt.email_config.smtp_server == "smtp.example.com"

    @pytest.mark.asyncio
    async def test_add_quick_contact(self, rt):
        """Should add a quick contact."""
        result = await rt.add_quick_contact("Alice", "alice@example.com")
        assert result["success"] is True
        assert result["contact"]["email"] == "alice@example.com"
        assert result["total_contacts"] == 1

    @pytest.mark.asyncio
    async def test_list_quick_contacts(self, rt):
        """Should list quick contacts."""
        await rt.add_quick_contact("Alice", "alice@example.com")
        await rt.add_quick_contact("Bob", "bob@example.com")
        result = await rt.list_quick_contacts()
        assert result["total"] == 2
        assert len(result["contacts"]) == 2

    @pytest.mark.asyncio
    async def test_send_report_not_found(self, rt):
        """Should fail when report file is missing."""
        result = await rt.send_report("r1", ["a@example.com"])
        assert result["success"] is False
        assert "not found" in result["error"].lower()


class TestHelperMethods:
    """Tests for static/private helper methods."""

    def test_identify_file_type_elf(self):
        """Should identify ELF binary."""
        data = b"\x7fELF\x02\x01\x01"
        result = ReportTools._identify_file_type(data)
        assert "ELF" in result

    def test_identify_file_type_pe(self):
        """Should identify PE binary."""
        data = b"MZ" + b"\x00" * 100
        result = ReportTools._identify_file_type(data)
        assert "PE" in result

    def test_identify_file_type_too_small(self):
        """Should handle tiny files."""
        result = ReportTools._identify_file_type(b"hi")
        assert "too small" in result

    def test_human_readable_size(self):
        """Should format bytes to human readable."""
        assert ReportTools._human_readable_size(512) == "512.0 B"
        assert "KB" in ReportTools._human_readable_size(2048)
        assert "MB" in ReportTools._human_readable_size(2 * 1024 * 1024)

    def test_get_severity_emoji(self):
        """Should return correct emoji."""
        assert ReportTools._get_severity_emoji("low") == "🟢"
        assert ReportTools._get_severity_emoji("critical") == "🔴"
        assert ReportTools._get_severity_emoji("unknown") == "⚪"

    def test_format_iocs_yaml_empty(self, tmp_path):
        """Should handle empty IOCs."""
        rt = ReportTools.__new__(ReportTools)
        result = rt._format_iocs_yaml({})
        assert "No IOCs" in result

    def test_format_iocs_yaml_with_data(self, tmp_path):
        """Should format IOCs in YAML."""
        iocs = {"ips": ["1.1.1.1", "2.2.2.2"]}
        rt = ReportTools.__new__(ReportTools)
        result = rt._format_iocs_yaml(iocs)
        assert "ips:" in result
        assert "1.1.1.1" in result

    def test_format_iocs_markdown_empty(self, tmp_path):
        """Should handle empty IOCs in markdown."""
        rt = ReportTools.__new__(ReportTools)
        result = rt._format_iocs_markdown({})
        assert "No IOCs" in result

    def test_identify_file_type_pdf(self):
        assert "PDF" in ReportTools._identify_file_type(b"%PDF-1.4")

    def test_identify_file_type_zip(self):
        assert "ZIP" in ReportTools._identify_file_type(b"PK\x03\x04")

    def test_identify_file_type_text(self):
        assert "Text" in ReportTools._identify_file_type(b"hello world text")

    def test_identify_file_type_unknown(self):
        assert "Unknown Binary" == ReportTools._identify_file_type(b"\xff\xfe\x00\x01")

    def test_human_readable_size_tb(self):
        assert "TB" in ReportTools._human_readable_size(1024 * 1024 * 1024 * 1024)

    def test_get_local_time(self, tmp_path):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path, default_timezone="Asia/Seoul")
        result = rt._get_local_time()
        assert result is not None

    def test_format_time_no_tz(self, tmp_path):
        from datetime import datetime, timezone

        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        dt = datetime.now(timezone.utc)
        result = rt._format_time(dt, include_tz=False)
        assert "(" not in result

    def test_format_mitre_table_with_data(self):
        rt = ReportTools.__new__(ReportTools)
        techniques = [
            {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        ]
        result = rt._format_mitre_table(techniques)
        assert "T1055" in result
        assert "Process Injection" in result

    def test_format_notes_empty(self):
        rt = ReportTools.__new__(ReportTools)
        result = rt._format_notes([])
        assert "No notes" in result

    def test_format_notes_with_data(self):
        rt = ReportTools.__new__(ReportTools)
        notes = [
            {
                "timestamp": "2024-01-01T12:00:00Z",
                "note": "suspicious import",
                "category": "finding",
            },
        ]
        result = rt._format_notes(notes)
        assert "suspicious import" in result

    @pytest.mark.asyncio
    async def test_send_report_email_not_configured(self, tmp_path):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        report = tmp_path / "r1.md"
        report.write_text("# Report")
        result = await rt.send_report("r1", ["a@example.com"])
        assert result["success"] is False
        assert "Email not configured" in result["error"]

    @pytest.mark.asyncio
    async def test_send_report_success(self, tmp_path):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        rt.email_config.smtp_server = "smtp.example.com"
        rt.email_config.username = "user"
        rt.email_config.password = "pass"
        report = tmp_path / "r1.md"
        report.write_text("# Report")
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="# Report")
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_file)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "reversecore_mcp.tools.report.report_tools.aiosmtplib.send",
            new_callable=AsyncMock,
        ):
            with patch(
                "reversecore_mcp.tools.report.report_tools.aiofiles.open",
                return_value=mock_ctx,
            ):
                result = await rt.send_report("r1", ["a@example.com"])
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_report_with_quick_contact(self, tmp_path):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        rt.email_config.smtp_server = "smtp.example.com"
        rt.email_config.username = "user"
        rt.email_config.password = "pass"
        rt.quick_contacts["Alice"] = {"email": "alice@test.com", "role": "Analyst"}
        report = tmp_path / "r1.md"
        report.write_text("# Report")
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="# Report")
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_file)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "reversecore_mcp.tools.report.report_tools.aiosmtplib.send",
            new_callable=AsyncMock,
        ):
            with patch(
                "reversecore_mcp.tools.report.report_tools.aiofiles.open",
                return_value=mock_ctx,
            ):
                result = await rt.send_report("r1", ["Alice"])
        assert result["success"] is True
        assert "alice@test.com" in result["recipients"]

    @pytest.mark.asyncio
    async def test_send_report_exception(self, tmp_path):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        rt.email_config.smtp_server = "smtp.example.com"
        rt.email_config.username = "user"
        rt.email_config.password = "pass"
        report = tmp_path / "r1.md"
        report.write_text("# Report")
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="# Report")
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_file)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "reversecore_mcp.tools.report.report_tools.aiosmtplib.send",
            side_effect=Exception("SMTP error"),
        ):
            with patch(
                "reversecore_mcp.tools.report.report_tools.aiofiles.open",
                return_value=mock_ctx,
            ):
                result = await rt.send_report("r1", ["a@example.com"])
        assert result["success"] is False
        assert "SMTP error" in result["error"]

    @pytest.mark.asyncio
    async def test_create_report_with_sample_path(self, tmp_path):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        template = rt.template_dir / "full_analysis.md"
        template.write_text("# {{{SAMPLE_NAME}}}\n")
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELF")
        result = await rt.create_report(template_type="full_analysis", sample_path=str(sample))
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_list_templates_with_desc(self, tmp_path):
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        template = rt.template_dir / "test.md"
        template.write_text("<!-- test template -->\n# Test")
        result = await rt.list_templates()
        assert result["total"] == 1
        assert result["templates"][0]["description"] == "test template"

    @pytest.mark.asyncio
    async def test_extract_sample_info(self, tmp_path):
        """Should extract metadata from sample."""
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELF test data")
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        result = await rt._extract_sample_info(str(sample))
        assert result["filename"] == "sample.bin"
        assert result["filesize"] == len(b"\x7fELF test data")
        assert "ELF" in result["file_type"]
        assert "md5" in result
        assert "sha256" in result


class TestGetReportTools:
    """Tests for get_report_tools singleton."""

    def test_singleton(self, tmp_path):
        from reversecore_mcp.tools.report.report_tools import (
            get_report_tools,
            reset_report_tools,
        )

        reset_report_tools()
        rt1 = get_report_tools(template_dir=tmp_path, output_dir=tmp_path)
        rt2 = get_report_tools(template_dir=tmp_path, output_dir=tmp_path)
        assert rt1 is rt2
