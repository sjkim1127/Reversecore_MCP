"""Unit tests for ReportTools module."""

from pathlib import Path
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

    def test_set_timezone_invalid(self, tmp_path):
        """Should reject unknown timezone."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path)
        result = rt.set_timezone("Mars/Colony")
        assert result["success"] is False
        assert "Unknown timezone" in result["error"]
        assert "available" in result

    def test_get_timezone_info(self, tmp_path):
        """Should return timezone config."""
        rt = ReportTools(template_dir=tmp_path, output_dir=tmp_path, default_timezone="UTC")
        result = rt.get_timezone_info()
        assert result["current_timezone"] == "UTC"
        assert "utc_offset" in result
        assert "available_timezones" in result


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
