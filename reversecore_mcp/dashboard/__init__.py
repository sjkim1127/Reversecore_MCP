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

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
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
