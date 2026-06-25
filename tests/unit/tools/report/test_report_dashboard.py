"""Tests for report conversion and report dashboard routes."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.report.converter import (
    convert_report,
    html_to_pdf,
    markdown_to_html,
    markdown_to_json,
)


class TestReportConverter:
    """Tests for the report conversion utilities."""

    def test_markdown_to_html(self):
        md = "# Malware Analysis Report\n\n**Report ID:** MAR-TEST\n\n## Summary\nThis is a test."
        html = markdown_to_html(md, title="Test Title")
        assert "<title>Test Title</title>" in html
        assert "<h1>Malware Analysis Report</h1>" in html
        assert "<strong>Report ID:</strong> MAR-TEST" in html
        assert "<h2>Summary</h2>" in html

    def test_html_to_pdf(self, tmp_path):
        html = "<html><body><h1>Test</h1></body></html>"
        pdf_path = tmp_path / "test.pdf"
        success = html_to_pdf(html, pdf_path)
        assert success is True
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0

    def test_markdown_to_json(self):
        md = (
            "# Malware Analysis Report\n\n"
            "**Report ID:** MAR-2026-TEST\n"
            "**Analyst:** Test Analyst\n\n"
            "## Indicators of Compromise\n"
            "- `hashes`: MD5: 44d88612fea8a8f36de82e1278abb02f\n"
            "- `ips`: 192.168.1.100\n\n"
            "## MITRE ATT&CK\n"
            "| ID | Name | Tactic |\n"
            "|---|---|---|\n"
            "| T1055 | Process Injection | Privilege Escalation |"
        )
        data = markdown_to_json(md, "MAR-2026-TEST")
        assert data["report_id"] == "MAR-2026-TEST"
        assert data["title"] == "Malware Analysis Report"
        assert data["metadata"]["report_id"] == "MAR-2026-TEST"
        assert data["metadata"]["analyst"] == "Test Analyst"

        # Test IOC extraction
        iocs = data["sections"]["indicators_of_compromise"]["iocs"]
        assert len(iocs) == 2
        assert iocs[0]["type"] == "hashes"
        assert "MD5: 44d88612fea8a8f36de82e1278abb02f" in iocs[0]["value"]
        assert iocs[1]["type"] == "ips"
        assert iocs[1]["value"] == "192.168.1.100"

        # Test MITRE extraction
        techniques = data["sections"]["mitre_attack"]["techniques"]
        assert len(techniques) == 1
        assert techniques[0]["id"] == "T1055"
        assert techniques[0]["name"] == "Process Injection"

    def test_convert_report(self, tmp_path):
        # Create a mock report source markdown
        report_dir = tmp_path / "reports"
        report_dir.mkdir()
        report_file = report_dir / "MAR-TEST.md"
        report_file.write_text("# Report\n**Report ID:** MAR-TEST\n## Details\nSome info.")

        # Patch config and paths
        with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = tmp_path
            mock_get_config.return_value = mock_config

            # 1. Convert to Markdown (just returns original)
            res_md = convert_report(report_file, "markdown")
            assert res_md == report_file

            # 2. Convert to HTML
            res_html = convert_report(report_file, "html")
            assert res_html.suffix == ".html"
            assert res_html.exists()

            # 3. Convert to PDF
            res_pdf = convert_report(report_file, "pdf")
            assert res_pdf.suffix == ".pdf"
            assert res_pdf.exists()

            # 4. Convert to JSON
            res_json = convert_report(report_file, "json")
            assert res_json.suffix == ".json"
            assert res_json.exists()


class TestReportDashboardRoutes:
    """Tests for the dashboard routes related to report management."""

    @pytest.mark.asyncio
    async def test_dashboard_reports(self, tmp_path):
        from reversecore_mcp.dashboard import dashboard_reports

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "sample.exe").write_bytes(b"MZ")

        # Mock config
        with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config

            # Mock report tools list_reports
            with patch(
                "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
            ) as mock_get_tools:
                mock_tools = MagicMock()
                mock_tools.list_reports.return_value = {
                    "reports": [
                        {
                            "report_id": "MAR-2026-TEST",
                            "path": "/reports/MAR-2026-TEST.md",
                            "size": 1024,
                            "created": "2026-06-25T12:00:00",
                        }
                    ]
                }
                mock_get_tools.return_value = mock_tools

                # Mock templates response
                with patch("starlette.templating.Jinja2Templates.TemplateResponse") as mock_tr:
                    mock_tr.return_value = MagicMock()
                    request = MagicMock()
                    request.cookies = {"session_id": "session123"}

                    result = await dashboard_reports(request)
                    assert result is not None

                    # Verify templates parameters
                    args, kwargs = mock_tr.call_args
                    assert args[1] == "reports.html"
                    context = args[2]
                    assert len(context["reports"]) == 1
                    assert context["reports"][0]["id"] == "MAR-2026-TEST"
                    assert "sample.exe" in context["workspace_files"]

    @pytest.mark.asyncio
    async def test_dashboard_report_view_success(self):
        from reversecore_mcp.dashboard import dashboard_report_view

        with patch(
            "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
        ) as mock_get_tools:
            mock_tools = MagicMock()
            mock_tools.get_report.return_value = {"success": True, "content": "# Test Report"}
            mock_get_tools.return_value = mock_tools

            with patch("starlette.templating.Jinja2Templates.TemplateResponse") as mock_tr:
                mock_tr.return_value = MagicMock()
                request = MagicMock()

                result = await dashboard_report_view(request, "MAR-TEST")
                assert result is not None

                args, kwargs = mock_tr.call_args
                assert args[1] == "report_view.html"
                assert args[2]["report_id"] == "MAR-TEST"
                assert "<h1>Test Report</h1>" in args[2]["html_content"]

    @pytest.mark.asyncio
    async def test_dashboard_report_view_not_found(self):
        from reversecore_mcp.dashboard import dashboard_report_view

        with patch(
            "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
        ) as mock_get_tools:
            mock_tools = MagicMock()
            mock_tools.get_report.return_value = {"success": False}
            mock_get_tools.return_value = mock_tools

            with patch("starlette.templating.Jinja2Templates.TemplateResponse") as mock_tr:
                mock_tr.return_value = MagicMock()
                request = MagicMock()

                result = await dashboard_report_view(request, "MAR-INVALID")
                assert result is not None

                args, kwargs = mock_tr.call_args
                assert args[1] == "error.html"

    @pytest.mark.asyncio
    async def test_dashboard_report_download(self, tmp_path):
        from fastapi.responses import FileResponse

        from reversecore_mcp.dashboard import dashboard_report_download

        report_dir = tmp_path / "reports"
        report_dir.mkdir()
        report_file = report_dir / "MAR-TEST.md"
        report_file.touch()

        with patch(
            "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
        ) as mock_get_tools:
            mock_tools = MagicMock()
            mock_tools.output_dir = report_dir
            mock_get_tools.return_value = mock_tools

            # Mock converter
            with patch("reversecore_mcp.tools.report.converter.convert_report") as mock_convert:
                mock_convert.return_value = report_dir / "MAR-TEST.pdf"

                result = await dashboard_report_download("MAR-TEST", format="pdf")
                assert isinstance(result, FileResponse)
                assert Path(result.path) == report_dir / "MAR-TEST.pdf"
                assert result.media_type == "application/pdf"

    @pytest.mark.asyncio
    async def test_dashboard_report_create(self, tmp_path):
        from fastapi.responses import RedirectResponse

        from reversecore_mcp.dashboard import dashboard_report_create

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        binary_file = workspace / "malware.exe"
        binary_file.write_bytes(b"MZ")

        # Mock token verification
        with patch("reversecore_mcp.dashboard._verify_csrf_token", return_value=True):
            with patch("reversecore_mcp.core.config.get_config") as mock_get_config:
                mock_config = MagicMock()
                mock_config.workspace = workspace
                mock_get_config.return_value = mock_config

                with patch(
                    "reversecore_mcp.core.security.validate_file_path", return_value=binary_file
                ):
                    with patch(
                        "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
                    ) as mock_get_tools:
                        from unittest.mock import AsyncMock

                        mock_tools = MagicMock()
                        mock_tools.start_session = AsyncMock(
                            return_value={"session_id": "SES-1234"}
                        )
                        mock_tools.add_session_ioc = AsyncMock()
                        mock_tools.add_session_note = AsyncMock()
                        mock_tools.create_report = AsyncMock()
                        mock_tools.end_session = AsyncMock()
                        mock_get_tools.return_value = mock_tools

                        # Mock IOC extraction using AsyncMock since extract_iocs is async
                        with patch(
                            "reversecore_mcp.tools.malware.ioc_tools.extract_iocs",
                            new_callable=AsyncMock,
                        ) as mock_extract:
                            mock_ioc_res = MagicMock()
                            mock_ioc_res.status = "success"
                            mock_ioc_res.data = {"hashes": {"md5": "1a2b3c"}}
                            mock_extract.return_value = mock_ioc_res

                            request = MagicMock()
                            request.cookies = {"session_id": "session123"}

                            result = await dashboard_report_create(
                                request=request,
                                filename="malware.exe",
                                analyst="Analyst Test",
                                severity="high",
                                malware_family="TestFamily",
                                tags="tag1,tag2",
                                csrf_token="valid_token",
                            )

                            if not isinstance(result, RedirectResponse):
                                if hasattr(result, "context"):
                                    print("Failed redirect context:", result.context)

                            assert isinstance(result, RedirectResponse)
                            assert result.headers["location"] == "/dashboard/reports"

                            # Verify session methods were called
                            mock_tools.start_session.assert_called_once()
                            mock_tools.create_report.assert_called_once()
                            mock_tools.end_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_dashboard_report_delete(self, tmp_path):
        from fastapi.responses import RedirectResponse

        from reversecore_mcp.dashboard import dashboard_report_delete

        report_dir = tmp_path / "reports"
        report_dir.mkdir()
        report_file = report_dir / "MAR-TEST.md"
        report_file.touch()

        # Mock token verification
        with patch("reversecore_mcp.dashboard._verify_csrf_token", return_value=True):
            with patch(
                "reversecore_mcp.tools.report.report_mcp_tools.get_report_tools"
            ) as mock_get_tools:
                mock_tools = MagicMock()
                mock_tools.output_dir = report_dir
                mock_get_tools.return_value = mock_tools

                request = MagicMock()
                request.cookies = {"session_id": "session123"}

                result = await dashboard_report_delete(
                    request, "MAR-TEST", csrf_token="valid_token"
                )

                assert isinstance(result, RedirectResponse)
                assert result.headers["location"] == "/dashboard/reports"
                # File should be deleted
                assert not report_file.exists()
