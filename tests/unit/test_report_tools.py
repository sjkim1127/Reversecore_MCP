"""
Unit tests for report_tools module.

Tests:
- Timezone management
- Timestamp generation
- Session management
- IOC collection
- Report generation
"""

import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from reversecore_mcp.tools.report.report_tools import (
    ReportTools,
    AnalysisSession,
    TimezonePreset,
    TIMEZONE_OFFSETS,
    TIMEZONE_ABBRS,
    get_report_tools,
)


@pytest.fixture
def temp_dirs():
    """Create temporary directories for templates and reports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        template_dir = Path(tmpdir) / "templates"
        output_dir = Path(tmpdir) / "reports"
        template_dir.mkdir()
        output_dir.mkdir()
        
        # Create a test template
        test_template = template_dir / "full_analysis.md"
        test_template.write_text("""<!-- Test template -->
# Report {{REPORT_ID}}

**Date:** {{DATE}}
**Analyst:** {{ANALYST}}
**Session:** {{SESSION_ID}}
**Duration:** {{ANALYSIS_DURATION}}

## IOCs
{{IOCS_YAML}}

## MITRE
{{MITRE_TABLE}}

## Notes
{{ANALYSIS_NOTES}}
""", encoding='utf-8')
        
        yield template_dir, output_dir


@pytest.fixture
def report_tools(temp_dirs):
    """Create a ReportTools instance with temporary directories."""
    template_dir, output_dir = temp_dirs
    return ReportTools(
        template_dir=template_dir,
        output_dir=output_dir,
        default_timezone="UTC"
    )


class TestTimezoneManagement:
    """Test timezone-related functionality."""
    
    def test_set_timezone_valid(self, report_tools):
        """Test setting a valid timezone."""
        result = report_tools.set_timezone("Asia/Seoul")
        
        assert result["success"] is True
        assert result["timezone"] == "Asia/Seoul"
        assert result["utc_offset"] == "UTC+9"
        assert report_tools.default_timezone == "Asia/Seoul"
        assert report_tools.timezone_offset == 9
    
    def test_set_timezone_invalid(self, report_tools):
        """Test setting an invalid timezone."""
        result = report_tools.set_timezone("Invalid/Timezone")
        
        assert result["success"] is False
        assert "error" in result
        assert "available" in result
    
    def test_get_timezone_info(self, report_tools):
        """Test retrieving timezone information."""
        result = report_tools.get_timezone_info()
        
        assert "current_timezone" in result
        assert "utc_offset" in result
        assert "available_timezones" in result
        assert len(result["available_timezones"]) == len(TIMEZONE_OFFSETS)
    
    def test_timezone_presets(self):
        """Test timezone preset enum values."""
        assert TimezonePreset.UTC.value == "UTC"
        assert TimezonePreset.KST.value == "Asia/Seoul"
        assert TimezonePreset.EST.value == "America/New_York"


class TestTimestampGeneration:
    """Test timestamp generation functionality."""
    
    def test_get_timestamp_data(self, report_tools):
        """Test getting timestamp data."""
        ts = report_tools.get_timestamp_data()
        
        # Check required fields exist
        assert "report_id" in ts
        assert "date" in ts
        assert "date_long" in ts
        assert "date_short" in ts
        assert "date_eu" in ts
        assert "date_us" in ts
        assert "datetime_full" in ts
        assert "datetime_utc" in ts
        assert "timestamp_unix" in ts
        assert "timezone" in ts
        assert "weekday" in ts
        assert "weekday_short" in ts
        assert "month_name" in ts
        assert "month_name_short" in ts
        
        # Check report_id format
        assert ts["report_id"].startswith("MAR-")
        
        # Check date format
        assert len(ts["date"].split("-")) == 3
        
        # Check unix timestamp is reasonable
        assert ts["timestamp_unix"] > 0
    
    def test_timestamp_timezone_conversion(self, report_tools):
        """Test timestamp conversion between timezones."""
        report_tools.set_timezone("UTC")
        ts_utc = report_tools.get_timestamp_data()
        
        report_tools.set_timezone("Asia/Seoul")
        ts_kst = report_tools.get_timestamp_data()
        
        # Same unix timestamp regardless of timezone
        # Allow small difference due to test execution time
        assert abs(ts_utc["timestamp_unix"] - ts_kst["timestamp_unix"]) < 2
        
        # Different timezone info
        assert ts_utc["timezone"] == "UTC"
        assert ts_kst["timezone"] == "Asia/Seoul"
    
    @pytest.mark.asyncio
    async def test_get_current_time(self, report_tools):
        """Test async get_current_time method."""
        result = await report_tools.get_current_time()
        
        assert "report_id" in result
        assert "datetime_full" in result
        assert "hostname" in result


class TestAnalysisSession:
    """Test AnalysisSession dataclass functionality."""
    
    def test_session_creation(self):
        """Test creating a new session."""
        session = AnalysisSession(
            session_id="SES-TEST1234",
            analyst="Test Analyst"
        )
        
        assert session.session_id == "SES-TEST1234"
        assert session.analyst == "Test Analyst"
        assert session.status == "initialized"
        assert session.started_at is None
    
    def test_session_start(self):
        """Test starting a session."""
        session = AnalysisSession(session_id="SES-TEST")
        session.start()
        
        assert session.status == "in_progress"
        assert session.started_at is not None
        assert isinstance(session.started_at, datetime)
    
    def test_session_end(self):
        """Test ending a session."""
        session = AnalysisSession(session_id="SES-TEST")
        session.start()
        session.end("completed")
        
        assert session.status == "completed"
        assert session.ended_at is not None
    
    def test_session_duration(self):
        """Test duration calculation."""
        session = AnalysisSession(session_id="SES-TEST")
        
        # Before start, duration should be None/N/A
        duration_str_before = session.get_duration_str()
        assert duration_str_before == "N/A"
        
        # After start
        session.start()
        
        # Should return a timedelta
        duration = session.get_duration()
        assert isinstance(duration, timedelta)
        
        # Duration string should be formatted with at least seconds
        duration_str = session.get_duration_str()
        assert "s" in duration_str
    
    def test_session_add_ioc(self):
        """Test adding IOCs to session."""
        session = AnalysisSession(session_id="SES-TEST")
        
        assert session.add_ioc("domains", "evil.com") is True
        assert session.add_ioc("domains", "evil.com") is False  # Duplicate
        assert session.add_ioc("ips", "192.168.1.1") is True
        
        assert "evil.com" in session.iocs["domains"]
        assert "192.168.1.1" in session.iocs["ips"]
    
    def test_session_add_note(self):
        """Test adding notes to session."""
        session = AnalysisSession(session_id="SES-TEST")
        session.add_note("Found suspicious behavior", "finding")
        
        assert len(session.notes) == 1
        assert session.notes[0]["note"] == "Found suspicious behavior"
        assert session.notes[0]["category"] == "finding"
        assert "timestamp" in session.notes[0]
    
    def test_session_add_mitre(self):
        """Test adding MITRE techniques."""
        session = AnalysisSession(session_id="SES-TEST")
        session.add_mitre("T1055", "Process Injection", "Defense Evasion")
        
        assert len(session.mitre_techniques) == 1
        assert session.mitre_techniques[0]["id"] == "T1055"
    
    def test_session_to_dict(self):
        """Test serialization to dictionary."""
        session = AnalysisSession(session_id="SES-TEST")
        session.start()
        session.add_ioc("domains", "test.com")
        
        data = session.to_dict()
        
        assert data["session_id"] == "SES-TEST"
        assert "started_at" in data
        assert "duration" in data


class TestSessionManagement:
    """Test session management in ReportTools."""
    
    @pytest.mark.asyncio
    async def test_start_session(self, report_tools):
        """Test starting a new session."""
        result = await report_tools.start_session(
            analyst="Test Analyst",
            severity="high"
        )
        
        assert result["success"] is True
        assert "session_id" in result
        assert result["session_id"].startswith("SES-")
        assert result["analyst"] == "Test Analyst"
        assert report_tools.current_session_id is not None
    
    @pytest.mark.asyncio
    async def test_start_session_with_sample(self, report_tools, temp_dirs):
        """Test starting a session with a sample file."""
        # Create a test sample
        template_dir, output_dir = temp_dirs
        sample_path = template_dir.parent / "test_sample.bin"
        sample_path.write_bytes(b"MZ" + b"\x00" * 100)  # PE-like
        
        result = await report_tools.start_session(
            sample_path=str(sample_path),
            analyst="Test"
        )
        
        assert result["success"] is True
        assert result["sample"] == "test_sample.bin"
        
        # Check hashes were added as IOCs
        session = report_tools.sessions[result["session_id"]]
        assert len(session.iocs["hashes"]) > 0
    
    @pytest.mark.asyncio
    async def test_end_session(self, report_tools):
        """Test ending a session."""
        await report_tools.start_session()
        result = await report_tools.end_session(summary="Test complete")
        
        assert result["success"] is True
        assert result["status"] == "completed"
        assert "duration" in result
        assert report_tools.current_session_id is None
    
    @pytest.mark.asyncio
    async def test_end_session_no_active(self, report_tools):
        """Test ending when no session is active."""
        result = await report_tools.end_session()
        
        assert result["success"] is False
        assert "error" in result
    
    @pytest.mark.asyncio
    async def test_get_session_info(self, report_tools):
        """Test getting session information."""
        start_result = await report_tools.start_session()
        session_id = start_result["session_id"]
        
        result = await report_tools.get_session_info(session_id)
        
        assert result["success"] is True
        assert result["session"]["session_id"] == session_id
        assert result["session"]["is_current"] is True
    
    @pytest.mark.asyncio
    async def test_list_sessions(self, report_tools):
        """Test listing all sessions."""
        await report_tools.start_session()
        await report_tools.start_session()
        
        result = await report_tools.list_sessions()
        
        assert result["total"] == 2
        assert len(result["sessions"]) == 2


class TestIOCCollection:
    """Test IOC collection functionality."""
    
    @pytest.mark.asyncio
    async def test_add_session_ioc(self, report_tools):
        """Test adding IOCs to session."""
        await report_tools.start_session()
        
        result = await report_tools.add_session_ioc("domains", "malware.com")
        
        assert result["success"] is True
        assert result["added"] is True
        assert result["total_iocs"] == 1
    
    @pytest.mark.asyncio
    async def test_add_session_ioc_invalid_type(self, report_tools):
        """Test adding IOC with invalid type."""
        await report_tools.start_session()
        
        result = await report_tools.add_session_ioc("invalid_type", "value")
        
        assert result["success"] is False
        assert "valid_types" in result
    
    @pytest.mark.asyncio
    async def test_add_session_note(self, report_tools):
        """Test adding notes to session."""
        await report_tools.start_session()
        
        result = await report_tools.add_session_note(
            "Found anti-debug technique",
            category="finding"
        )
        
        assert result["success"] is True
        assert result["category"] == "finding"
        assert result["total_notes"] == 1
    
    @pytest.mark.asyncio
    async def test_add_session_mitre(self, report_tools):
        """Test adding MITRE techniques."""
        await report_tools.start_session()
        
        result = await report_tools.add_session_mitre(
            "T1055.001",
            "DLL Injection",
            "Defense Evasion"
        )
        
        assert result["success"] is True
        assert result["total_techniques"] == 1
    
    @pytest.mark.asyncio
    async def test_add_session_tag(self, report_tools):
        """Test adding tags to session."""
        await report_tools.start_session()
        
        result = await report_tools.add_session_tag("ransomware")
        
        assert result["success"] is True
        assert "ransomware" in result["all_tags"]
    
    @pytest.mark.asyncio
    async def test_set_session_severity(self, report_tools):
        """Test setting session severity."""
        await report_tools.start_session()
        
        result = await report_tools.set_session_severity("critical")
        
        assert result["success"] is True
        assert result["severity"] == "critical"
    
    @pytest.mark.asyncio
    async def test_set_session_severity_invalid(self, report_tools):
        """Test setting invalid severity."""
        await report_tools.start_session()
        
        result = await report_tools.set_session_severity("invalid")
        
        assert result["success"] is False
        assert "valid_severities" in result


class TestReportGeneration:
    """Test report generation functionality."""
    
    @pytest.mark.asyncio
    async def test_create_report_basic(self, report_tools):
        """Test basic report creation."""
        await report_tools.start_session()
        await report_tools.add_session_ioc("domains", "test.com")
        await report_tools.add_session_note("Test note")
        
        result = await report_tools.create_report(
            template_type="full_analysis",
            analyst="Test Analyst"
        )
        
        assert result["success"] is True
        assert result["report_id"].startswith("MAR-")
        assert Path(result["path"]).exists()
        assert "report_content" in result
    
    @pytest.mark.asyncio
    async def test_create_report_template_not_found(self, report_tools):
        """Test report creation with non-existent template."""
        result = await report_tools.create_report(
            template_type="nonexistent"
        )
        
        assert result["success"] is False
        assert "error" in result
        assert "available_templates" in result
    
    @pytest.mark.asyncio
    async def test_list_templates(self, report_tools):
        """Test listing available templates."""
        result = await report_tools.list_templates()
        
        assert result["total"] >= 1
        assert len(result["templates"]) >= 1
    
    @pytest.mark.asyncio
    async def test_get_report(self, report_tools):
        """Test retrieving a generated report."""
        await report_tools.start_session()
        create_result = await report_tools.create_report()
        
        result = await report_tools.get_report(create_result["report_id"])
        
        assert result["success"] is True
        assert "content" in result
    
    @pytest.mark.asyncio
    async def test_get_report_not_found(self, report_tools):
        """Test retrieving non-existent report."""
        result = await report_tools.get_report("MAR-NONEXISTENT")
        
        assert result["success"] is False
        assert "available_reports" in result
    
    @pytest.mark.asyncio
    async def test_list_reports(self, report_tools):
        """Test listing generated reports."""
        await report_tools.start_session()
        await report_tools.create_report()
        
        result = await report_tools.list_reports()
        
        assert result["total"] >= 1


class TestEmailFunctionality:
    """Test email-related functionality."""
    
    @pytest.mark.asyncio
    async def test_configure_email(self, report_tools):
        """Test email configuration."""
        result = await report_tools.configure_email(
            smtp_server="smtp.test.com",
            smtp_port=587,
            username="test@test.com",
            password="password",
            use_tls=True
        )
        
        assert result["success"] is True
        assert report_tools.email_config.smtp_server == "smtp.test.com"
    
    @pytest.mark.asyncio
    async def test_add_quick_contact(self, report_tools):
        """Test adding quick contacts."""
        result = await report_tools.add_quick_contact(
            name="SOC Lead",
            email="soc@company.com",
            role="SOC Manager"
        )
        
        assert result["success"] is True
        assert "SOC Lead" in report_tools.quick_contacts
    
    @pytest.mark.asyncio
    async def test_list_quick_contacts(self, report_tools):
        """Test listing quick contacts."""
        await report_tools.add_quick_contact("Test", "test@test.com")
        
        result = await report_tools.list_quick_contacts()
        
        assert result["total"] == 1
    
    @pytest.mark.asyncio
    async def test_send_report_no_config(self, report_tools):
        """Test sending report without email config."""
        await report_tools.start_session()
        create_result = await report_tools.create_report()
        
        result = await report_tools.send_report(
            report_id=create_result["report_id"],
            recipients=["test@test.com"]
        )
        
        assert result["success"] is False
        assert "not configured" in result["error"]


class TestHelperMethods:
    """Test helper methods."""
    
    def test_human_readable_size(self, report_tools):
        """Test file size formatting."""
        assert ReportTools._human_readable_size(512) == "512.0 B"
        assert ReportTools._human_readable_size(1024) == "1.0 KB"
        assert ReportTools._human_readable_size(1048576) == "1.0 MB"
    
    def test_get_severity_emoji(self, report_tools):
        """Test severity emoji mapping."""
        assert ReportTools._get_severity_emoji("low") == "🟢"
        assert ReportTools._get_severity_emoji("medium") == "🟡"
        assert ReportTools._get_severity_emoji("high") == "🟠"
        assert ReportTools._get_severity_emoji("critical") == "🔴"
    
    def test_identify_file_type(self, report_tools):
        """Test file type identification."""
        assert "PE" in ReportTools._identify_file_type(b"MZ\x00\x00")
        assert "ELF" in ReportTools._identify_file_type(b"\x7fELF")
        assert "PDF" in ReportTools._identify_file_type(b"%PDF-1.4")
        assert "ZIP" in ReportTools._identify_file_type(b"PK\x03\x04")
    
    def test_format_iocs_yaml(self, report_tools):
        """Test IOC YAML formatting."""
        iocs = {
            "domains": ["evil.com", "bad.net"],
            "ips": ["192.168.1.1"],
            "urls": []
        }
        
        result = report_tools._format_iocs_yaml(iocs)
        
        assert "domains:" in result
        assert "evil.com" in result
        assert "ips:" in result
    
    def test_format_mitre_table(self, report_tools):
        """Test MITRE table formatting."""
        techniques = [
            {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"}
        ]
        
        result = report_tools._format_mitre_table(techniques)
        
        assert "T1055" in result
        assert "Process Injection" in result


class TestSingleton:
    """Test singleton instance functionality."""
    
    def test_get_report_tools_singleton(self, temp_dirs):
        """Test that get_report_tools returns singleton."""
        # Reset singleton
        import reversecore_mcp.tools.report_tools as rt_module
        rt_module._default_report_tools = None
        
        template_dir, output_dir = temp_dirs
        
        tools1 = get_report_tools(template_dir, output_dir)
        tools2 = get_report_tools()
        
        assert tools1 is tools2
