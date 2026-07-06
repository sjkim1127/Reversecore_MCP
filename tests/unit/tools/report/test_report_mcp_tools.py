"""Tests for reversecore_mcp.tools.report.report_mcp_tools."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.tools.report.report_mcp_tools import (
    add_analysis_note,
    add_ioc,
    add_mitre_technique,
    create_analysis_report,
    end_report_session,
    generate_vex_report,
    get_report_session_status,
    get_system_time,
    get_timezone_info,
    list_report_sessions,
    register_report_tools,
    set_severity,
    set_timezone,
    start_report_session,
)


class TestReportMcpTools:
    """Tests for report MCP tool wrappers."""

    @pytest.fixture(autouse=True)
    def mock_report_tools(self):
        self.rt = MagicMock()
        self.rt.get_current_time = AsyncMock(return_value={"time": "12:00"})
        self.rt.set_timezone = MagicMock(return_value={"success": True})
        self.rt.get_timezone_info = MagicMock(return_value={"timezone": "UTC"})
        self.rt.start_session = AsyncMock(return_value={"success": True, "session_id": "s1"})
        self.rt.end_session = AsyncMock(return_value={"success": True})
        self.rt.get_session_info = AsyncMock(return_value={"success": True, "session": {}})
        self.rt.list_sessions = AsyncMock(return_value={"total": 0, "sessions": []})
        self.rt.add_session_ioc = AsyncMock(return_value={"success": True})
        self.rt.add_session_note = AsyncMock(return_value={"success": True})
        self.rt.add_session_mitre = AsyncMock(return_value={"success": True})
        self.rt.set_session_severity = AsyncMock(return_value={"success": True})
        self.rt.create_report = AsyncMock(return_value={"success": True})

        with patch(
            "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools", return_value=self.rt
        ):
            yield

    @pytest.mark.asyncio
    async def test_get_system_time(self):
        result = await get_system_time()
        assert "12:00" in result

    @pytest.mark.asyncio
    async def test_set_timezone(self):
        result = await set_timezone("UTC")
        assert "success" in result

    @pytest.mark.asyncio
    async def test_get_timezone_info(self):
        result = await get_timezone_info()
        assert "UTC" in result

    @pytest.mark.asyncio
    async def test_start_report_session(self):
        result = await start_report_session(sample_path="/app/test.bin", analyst="Alice")
        assert "s1" in result

    @pytest.mark.asyncio
    async def test_end_report_session(self):
        result = await end_report_session(session_id="s1", status="completed")
        assert "success" in result

    @pytest.mark.asyncio
    async def test_get_report_session_status(self):
        result = await get_report_session_status(session_id="s1")
        assert "success" in result

    @pytest.mark.asyncio
    async def test_list_report_sessions(self):
        result = await list_report_sessions()
        assert "total" in result

    @pytest.mark.asyncio
    async def test_add_ioc(self):
        result = await add_ioc("ips", "1.1.1.1", session_id="s1")
        assert "success" in result

    @pytest.mark.asyncio
    async def test_add_analysis_note(self):
        result = await add_analysis_note("note", category="finding", session_id="s1")
        assert "success" in result

    @pytest.mark.asyncio
    async def test_add_mitre_technique(self):
        result = await add_mitre_technique(
            "T1055", "Process Injection", "Defense Evasion", session_id="s1"
        )
        assert "success" in result

    @pytest.mark.asyncio
    async def test_set_severity(self):
        result = await set_severity("high", session_id="s1")
        assert "success" in result

    @pytest.mark.asyncio
    async def test_create_analysis_report(self):
        result = await create_analysis_report(template_type="full_analysis", session_id="s1")
        assert "success" in result

    @pytest.mark.asyncio
    async def test_generate_vex_report(self):
        vulns_json = '[{"id": "CVE-TEST", "description": "test"}]'
        result = await generate_vex_report("App", "1.0", vulns_json)
        assert "csaf_vex" in result
        assert "CVE-TEST" in result


class TestRegisterReportTools:
    """Tests for register_report_tools."""

    def test_register(self):
        mcp = MagicMock()
        register_report_tools(mcp)
        assert mcp.tool.call_count == 13
