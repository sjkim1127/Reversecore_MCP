"""
Web Dashboard for Reversecore MCP.

Provides a visual interface for binary analysis using FastAPI + Jinja2.

SECURITY NOTES:
- All user-provided data (filenames, binary strings) is auto-escaped by Jinja2
- Path traversal protection via validate_file_path()
- CSRF tokens required for state-changing operations
"""

import html
import secrets
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Setup paths
DASHBOARD_DIR = Path(__file__).parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"

# Create router
router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# Setup templates with auto-escaping enabled (default)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# CSRF token storage (in production, use Redis or database)
_csrf_tokens: dict[str, str] = {}


def _generate_csrf_token(session_id: str) -> str:
    """Generate a CSRF token for a session."""
    token = secrets.token_urlsafe(32)
    _csrf_tokens[session_id] = token
    return token


def _verify_csrf_token(session_id: str, token: str) -> bool:
    """Verify a CSRF token."""
    expected = _csrf_tokens.get(session_id)
    return expected is not None and secrets.compare_digest(expected, token)


def _sanitize_for_display(text: str, max_length: int = 1000) -> str:
    """
    Sanitize binary-extracted text for safe display.

    This is a defense-in-depth measure on top of Jinja2's auto-escaping.
    """
    if not isinstance(text, str):
        text = str(text)
    # Truncate long strings
    if len(text) > max_length:
        text = text[:max_length] + "... [truncated]"
    # HTML escape (Jinja2 does this, but we double-check for safety)
    return html.escape(text)


def get_router() -> APIRouter:
    """Get the dashboard router."""
    return router


def get_static_files() -> StaticFiles:
    """Get static files mount."""
    return StaticFiles(directory=str(STATIC_DIR))


@router.get("/", response_class=HTMLResponse)
async def dashboard_index(request: Request):
    """Dashboard overview page."""
    from reversecore_mcp.core.config import get_config

    settings = get_config()
    workspace = settings.workspace

    # Get list of files in workspace
    files: list[dict[str, Any]] = []
    if workspace.exists():
        for f in workspace.iterdir():
            if f.is_file() and not f.name.startswith("."):
                stat = f.stat()
                # Sanitize filename for display (defense in depth)
                files.append(
                    {
                        "name": _sanitize_for_display(f.name, 255),
                        "name_raw": f.name,  # For URL construction
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                    }
                )

    # Sort by modified time (newest first)
    files.sort(key=lambda x: x["modified"], reverse=True)

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "files": files,
            "workspace": str(workspace),
            "file_count": len(files),
        },
    )


@router.get("/analysis/{filename}", response_class=HTMLResponse)
async def dashboard_analysis(request: Request, filename: str):
    """Analysis page for a specific file."""
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.security import validate_file_path

    settings = get_config()
    file_path = settings.workspace / filename

    try:
        validated_path = validate_file_path(str(file_path))
    except Exception as e:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": _sanitize_for_display(str(e))},
        )

    # Get basic file info
    file_info = {
        "name": _sanitize_for_display(validated_path.name, 255),
        "path": str(validated_path),
        "size": validated_path.stat().st_size,
    }

    # Try to get functions list
    functions = []
    disasm = ""

    try:
        from reversecore_mcp.tools.radare2.r2_session import R2Session

        session = R2Session(str(validated_path))
        session.analyze(level=1)

        # Get functions
        funcs_json = session.cmdj("aflj") or []
        for func in funcs_json[:50]:  # Limit to 50
            # SECURITY: Sanitize function names from binary
            functions.append(
                {
                    "name": _sanitize_for_display(func.get("name", "unknown"), 100),
                    "offset": hex(func.get("offset", 0)),
                    "size": func.get("size", 0),
                }
            )

        # Get entry point disassembly
        raw_disasm = session.cmd("pdf @ entry0") or "No disassembly available"
        # SECURITY: Sanitize disassembly output
        disasm = _sanitize_for_display(raw_disasm, 50000)

    except Exception as e:
        disasm = f"Error: {_sanitize_for_display(str(e))}"

    return templates.TemplateResponse(
        request,
        "analysis.html",
        {
            "file": file_info,
            "functions": functions,
            "disasm": disasm,
        },
    )


@router.get("/iocs/{filename}", response_class=HTMLResponse)
async def dashboard_iocs(request: Request, filename: str):
    """IOC extraction page."""
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.security import validate_file_path

    settings = get_config()
    file_path = settings.workspace / filename

    try:
        validated_path = validate_file_path(str(file_path))
    except Exception as e:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": _sanitize_for_display(str(e))},
        )

    # Extract IOCs
    iocs: dict = {"urls": [], "ips": [], "emails": [], "strings": []}

    try:
        from reversecore_mcp.tools.malware.ioc_tools import extract_iocs

        result = await extract_iocs(str(validated_path))
        if result.status == "success" and isinstance(result.data, dict):
            raw_iocs = result.data
            # SECURITY: Sanitize all IOC values extracted from binary
            iocs["urls"] = [_sanitize_for_display(u, 500) for u in raw_iocs.get("urls", [])]
            iocs["ips"] = [_sanitize_for_display(ip, 50) for ip in raw_iocs.get("ips", [])]
            iocs["emails"] = [_sanitize_for_display(e, 100) for e in raw_iocs.get("emails", [])]
            iocs["strings"] = [
                _sanitize_for_display(s, 200) for s in raw_iocs.get("strings", [])[:100]
            ]

    except Exception as e:
        iocs["error"] = _sanitize_for_display(str(e))

    return templates.TemplateResponse(
        request,
        "iocs.html",
        {
            "filename": _sanitize_for_display(filename, 255),
            "iocs": iocs,
        },
    )


# =============================================================================
# Report Management Routes
# =============================================================================


@router.get("/reports", response_class=HTMLResponse)
async def dashboard_reports(request: Request):
    """List all generated reports and available workspace files for creation."""
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.tools.report.report_mcp_tools import get_report_tools

    settings = get_config()
    report_tools = get_report_tools()

    # 1. Get reports list
    reports_res = report_tools.list_reports()
    reports = reports_res.get("reports", [])

    # 2. Get workspace files list for the creation dropdown
    workspace_files = []
    if settings.workspace.exists():
        for f in settings.workspace.iterdir():
            # Exclude directories, hidden files, and temp files
            if f.is_file() and not f.name.startswith(".") and not f.suffix == ".tmp":
                workspace_files.append(f.name)

    # Use a secure CSRF token for delete/create actions
    session_id = request.cookies.get("session_id", "default_session")
    csrf_token = _generate_csrf_token(session_id)

    # Format the reports list with human-readable values
    formatted_reports = []
    for r in reports:
        formatted_reports.append(
            {
                "id": r["report_id"],
                "path": r["path"],
                "size_kb": round(r["size"] / 1024, 2),
                "created": r["created"].replace("T", " ")[:19],
            }
        )

    # Prepare response, set session cookie if not exists
    response = templates.TemplateResponse(
        request,
        "reports.html",
        {
            "reports": formatted_reports,
            "workspace_files": workspace_files,
            "csrf_token": csrf_token,
        },
    )
    if "session_id" not in request.cookies:
        response.set_cookie("session_id", session_id, httponly=True)
    return response


@router.get("/reports/{report_id}", response_class=HTMLResponse)
async def dashboard_report_view(request: Request, report_id: str):
    """View styled HTML report in the browser."""
    from reversecore_mcp.tools.report.converter import markdown_to_html
    from reversecore_mcp.tools.report.report_mcp_tools import get_report_tools

    report_tools = get_report_tools()
    report_res = report_tools.get_report(report_id)

    if not report_res.get("success"):
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": f"Report not found: {report_id}"},
        )

    md_content = report_res["content"]
    # Convert markdown to html body (styled in the template)
    html_content = markdown_to_html(md_content, title=f"Report {report_id}")

    return templates.TemplateResponse(
        request,
        "report_view.html",
        {
            "report_id": report_id,
            "html_content": html_content,
        },
    )


@router.get("/reports/{report_id}/download")
async def dashboard_report_download(report_id: str, format: str = "pdf"):
    """Download a report in pdf, html, json, or markdown formats."""
    from reversecore_mcp.tools.report.converter import convert_report
    from reversecore_mcp.tools.report.report_mcp_tools import get_report_tools

    report_tools = get_report_tools()
    report_path = report_tools.output_dir / f"{report_id}.md"

    if not report_path.exists():
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    try:
        converted_path = convert_report(report_path, format)
    except Exception as e:
        from fastapi import HTTPException

        raise HTTPException(status_code=500, detail=f"Failed to convert report: {str(e)}")

    # Map format to content type and file extension
    fmt = format.lower()
    media_types = {
        "pdf": "application/pdf",
        "html": "text/html",
        "json": "application/json",
        "markdown": "text/markdown",
        "md": "text/markdown",
    }
    media_type = media_types.get(fmt, "application/octet-stream")
    ext = "md" if fmt == "markdown" else fmt

    return FileResponse(
        path=converted_path,
        media_type=media_type,
        filename=f"{report_id}.{ext}",
    )


@router.post("/reports/create")
async def dashboard_report_create(
    request: Request,
    filename: str = Form(...),
    analyst: str = Form("Security Researcher"),
    severity: str = Form("medium"),
    malware_family: str = Form(""),
    tags: str = Form(""),
    csrf_token: str = Form(...),
):
    """Create a new report based on an existing file inside the workspace."""
    session_id = request.cookies.get("session_id", "default_session")
    if not _verify_csrf_token(session_id, csrf_token):
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": "CSRF validation failed. Action rejected."},
        )

    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.security import validate_file_path
    from reversecore_mcp.tools.malware.ioc_tools import extract_iocs
    from reversecore_mcp.tools.report.report_mcp_tools import get_report_tools

    settings = get_config()
    report_tools = get_report_tools()
    file_path = settings.workspace / filename

    try:
        validated_path = validate_file_path(str(file_path))
    except Exception as e:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": f"Invalid file path: {str(e)}"},
        )

    try:
        # Start a structured report session
        session_res = await report_tools.start_session(
            sample_path=str(validated_path),
            analyst=analyst,
            severity=severity,
            malware_family=malware_family or None,
            tags=[t.strip() for t in tags.split(",") if t.strip()] if tags else None,
        )

        current_sid = session_res["session_id"]

        # Enhance report by extracting IOCs from binary
        try:
            ioc_result = await extract_iocs(str(validated_path))
            if ioc_result.status == "success" and isinstance(ioc_result.data, dict):
                raw_iocs = ioc_result.data

                # Add extracted hashes to session IOCs
                for h_type in ["md5", "sha1", "sha256"]:
                    if h_type in raw_iocs.get("hashes", {}):
                        await report_tools.add_session_ioc(
                            "hashes", f"{h_type.upper()}: {raw_iocs['hashes'][h_type]}", current_sid
                        )

                # Add network IOCs
                for ip in raw_iocs.get("ips", [])[:5]:
                    await report_tools.add_session_ioc("ips", ip, current_sid)
                for domain in raw_iocs.get("domains", [])[:5]:
                    await report_tools.add_session_ioc("domains", domain, current_sid)
                for url in raw_iocs.get("urls", [])[:5]:
                    await report_tools.add_session_ioc("urls", url, current_sid)

        except Exception as ioc_err:
            try:
                logger.warning(f"Failed to auto-extract IOCs for new report: {ioc_err}")
            except NameError:
                print(f"Failed to auto-extract IOCs for new report: {ioc_err}")

        # Add a note about auto-extraction
        await report_tools.add_session_note(
            "Auto-extracted static indicators of compromise and hashes.", "general", current_sid
        )

        # Generate report and write markdown file
        await report_tools.create_report(
            template_type="full_analysis",
            session_id=current_sid,
            analyst=analyst,
            classification="TLP:AMBER",
        )

        # Close session
        await report_tools.end_session(
            session_id=current_sid,
            status="completed",
            summary="Automated static analysis report generated.",
        )

    except Exception as e:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": f"Failed to generate report: {str(e)}"},
        )

    return RedirectResponse(url="/dashboard/reports", status_code=303)


@router.post("/reports/{report_id}/delete")
async def dashboard_report_delete(
    request: Request,
    report_id: str,
    csrf_token: str = Form(...),
):
    """Delete a generated report."""
    session_id = request.cookies.get("session_id", "default_session")
    if not _verify_csrf_token(session_id, csrf_token):
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": "CSRF validation failed. Action rejected."},
        )

    from reversecore_mcp.tools.report.report_mcp_tools import get_report_tools

    report_tools = get_report_tools()
    report_path = report_tools.output_dir / f"{report_id}.md"

    if report_path.exists():
        try:
            report_path.unlink()
        except Exception as e:
            return templates.TemplateResponse(
                request,
                "error.html",
                {"error": f"Failed to delete report: {str(e)}"},
            )
    else:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"error": f"Report {report_id} does not exist."},
        )

    return RedirectResponse(url="/dashboard/reports", status_code=303)
