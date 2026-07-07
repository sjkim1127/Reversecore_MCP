"""
MCP Tool Definitions for Report Generation
Register these tools in your MCP server
"""

from pathlib import Path
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

from .report_tools import EmailConfig, ReportTools
from .sigma_generator import generate_sigma_rule
from .vex_generator import generate_csaf_vex

logger = get_logger(__name__)

# Global report_tools instance (initialized on first plugin registration)
_report_tools: ReportTools | None = None


def get_report_tools(
    template_dir: Path | None = None,
    output_dir: Path | None = None,
    default_timezone: str = "Asia/Seoul",
) -> ReportTools:
    """Get or create ReportTools singleton instance."""
    global _report_tools
    if _report_tools is None:
        # Use package-relative path for templates (works regardless of CWD)
        if template_dir is None:
            # Check Docker path first (/app/templates/reports)
            docker_path = Path("/app/templates/reports")
            if docker_path.exists():
                template_dir = docker_path
            else:
                # Fallback: Get the package root directory for local development
                package_root = Path(
                    __file__
                ).parent.parent.parent  # tools/report -> tools -> reversecore_mcp
                project_root = package_root.parent  # reversecore_mcp -> Reversecore_MCP
                template_dir = project_root / "templates" / "reports"

        _report_tools = ReportTools(
            template_dir=template_dir,
            output_dir=output_dir or Path("reports"),
            default_timezone=default_timezone,
            email_config=EmailConfig.from_env(),
        )
    return _report_tools


# =============================================================================
# Tool Functions (defined at module level for proper decoration)
# =============================================================================


async def get_system_time() -> str:
    """
    Get accurate system timestamp from the server.

    Returns OS-level time data to prevent AI date hallucination.
    Includes multiple formats (ISO, Unix, human-readable) and timezone info.

    Returns:
        JSON with report_id, date formats, time formats, timezone info
    """
    report_tools = get_report_tools()
    result = await report_tools.get_current_time()
    return json.dumps(result, indent=2, ensure_ascii=False)


async def set_timezone(timezone: str) -> str:
    """
    Set the default timezone for timestamps.

    Args:
        timezone: Timezone name (UTC, Asia/Seoul, Asia/Tokyo, etc.)

    Returns:
        JSON with success status and current time in new timezone
    """
    report_tools = get_report_tools()
    result = report_tools.set_timezone(timezone)
    return json.dumps(result, indent=2, ensure_ascii=False)


async def get_timezone_info() -> str:
    """
    Get current timezone configuration and available options.

    Returns:
        JSON with current timezone, offset, and all available timezones
    """
    report_tools = get_report_tools()
    result = report_tools.get_timezone_info()
    return json.dumps(result, indent=2, ensure_ascii=False)


async def start_report_session(
    sample_path: str = "",
    analyst: str = "Security Researcher",
    severity: str = "medium",
    malware_family: str = "",
    tags: str = "",
) -> str:
    """
    Start a new malware analysis session.

    Automatically tracks start time, sample hashes, IOCs, and MITRE techniques.

    Args:
        sample_path: Path to the malware sample to analyze
        analyst: Name of the analyst
        severity: Initial severity (low, medium, high, critical)
        malware_family: Known malware family name
        tags: Comma-separated tags

    Returns:
        Session ID and initial information
    """
    report_tools = get_report_tools()
    tags_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    result = await report_tools.start_session(
        sample_path=sample_path if sample_path else None,
        analyst=analyst,
        severity=severity,
        malware_family=malware_family if malware_family else None,
        tags=tags_list,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def end_report_session(
    session_id: str = "", status: str = "completed", summary: str = ""
) -> str:
    """
    End the current analysis session.

    Args:
        session_id: Session ID to end (uses current if not specified)
        status: Final status - "completed" or "aborted"
        summary: Brief summary of findings

    Returns:
        Session summary with duration and collected data stats
    """
    report_tools = get_report_tools()
    result = await report_tools.end_session(
        session_id=session_id if session_id else None,
        status=status,
        summary=summary if summary else None,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def get_report_session_status(session_id: str = "") -> str:
    """
    Get current session information and collected data.

    Args:
        session_id: Session ID to query (uses current if not specified)

    Returns:
        Complete session data including IOCs, techniques, notes, duration
    """
    report_tools = get_report_tools()
    result = await report_tools.get_session_info(session_id=session_id if session_id else None)
    return json.dumps(result, indent=2, ensure_ascii=False)


async def list_report_sessions() -> str:
    """
    List all analysis sessions with their status and duration.

    Returns:
        List of all sessions with summary information
    """
    report_tools = get_report_tools()
    result = await report_tools.list_sessions()
    return json.dumps(result, indent=2, ensure_ascii=False)


async def add_ioc(ioc_type: str, value: str, session_id: str = "") -> str:
    """
    Add an Indicator of Compromise to the current session.

    Args:
        ioc_type: Type of IOC (hashes, ips, domains, urls, files, registry, mutexes, emails)
        value: The IOC value
        session_id: Session ID (uses current if not specified)

    Returns:
        Confirmation with total IOC count
    """
    report_tools = get_report_tools()
    result = await report_tools.add_session_ioc(
        ioc_type=ioc_type, value=value, session_id=session_id if session_id else None
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def add_analysis_note(note: str, category: str = "general", session_id: str = "") -> str:
    """
    Add a timestamped note to the analysis session.

    Args:
        note: The analysis note
        category: Note category (general, finding, todo, warning)
        session_id: Session ID (uses current if not specified)

    Returns:
        Confirmation with timestamped note
    """
    report_tools = get_report_tools()
    result = await report_tools.add_session_note(
        note=note, category=category, session_id=session_id if session_id else None
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def add_mitre_technique(
    technique_id: str, technique_name: str, tactic: str, session_id: str = ""
) -> str:
    """
    Add a MITRE ATT&CK technique to the session.

    Args:
        technique_id: MITRE ID (e.g., "T1055", "T1547.001")
        technique_name: Technique name
        tactic: MITRE tactic (e.g., "Defense Evasion", "Persistence")
        session_id: Session ID (uses current if not specified)

    Returns:
        Confirmation with technique count
    """
    report_tools = get_report_tools()
    result = await report_tools.add_session_mitre(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        session_id=session_id if session_id else None,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def set_severity(severity: str, session_id: str = "") -> str:
    """
    Update the severity level of the analysis.

    Args:
        severity: Severity level (low, medium, high, critical)
        session_id: Session ID (uses current if not specified)

    Returns:
        Confirmation with new severity
    """
    report_tools = get_report_tools()
    result = await report_tools.set_session_severity(
        severity=severity, session_id=session_id if session_id else None
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def create_analysis_report(
    template_type: str = "full_analysis",
    session_id: str = "",
    sample_path: str = "",
    analyst: str = "Security Researcher",
    classification: str = "TLP:AMBER",
    output_format: str = "markdown",
) -> str:
    """
    Generate a comprehensive analysis report.

    Args:
        template_type: Report template type. Options:
            - "full_analysis" (default) — complete technical report
            - "executive_summary"       — high-level management brief
            - "ioc_report"             — IOC-focused export
            - "quick_scan"             — terse one-page summary
        session_id: Session ID returned by start_report_session.
            Uses the most recent active session if not specified.
        sample_path: Path to the sample file. Only needed when not using
            a session (session_id takes precedence when provided).
        analyst: Analyst name shown in report header.
            Default: "Security Researcher".
        classification: Report classification level. Options:
            "TLP:RED", "TLP:AMBER" (default), "TLP:GREEN", "TLP:WHITE".
        output_format: Output format. Must be "markdown" (default) or "json".
            IMPORTANT: The parameter name is 'output_format', NOT 'format'.

    Returns:
        Generated report content and saved file path.
    """
    report_tools = get_report_tools()
    result = await report_tools.create_report(
        template_type=template_type,
        session_id=session_id if session_id else None,
        sample_path=sample_path if sample_path else None,
        analyst=analyst,
        classification=classification,
        output_format=output_format,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def generate_vex_report(
    product_name: str,
    product_version: str,
    vulnerabilities: str,
    document_title: str = "Reversecore MCP VEX Report",
) -> str:
    """Generate a CSAF 2.0 VEX JSON report from vulnerability findings.

    VEX (Vulnerability Exploitability eXchange) is a format for sharing the
    exploitability status of a software product in a machine-readable way.

    Args:
        product_name: Name of the analyzed binary or product.
        product_version: Version, hash, or build identifier of the product.
        vulnerabilities: JSON string containing a list of vulnerability objects.
            Each object should have:
            - id: str (e.g., "CVE-2023-1234")
            - description: str
            - confidence: str ("confirmed", "likely", "false_positive", etc.)
            - evidence_level: str (optional, e.g., "dead_code", "static_sink")
        document_title: Title of the generated document.

    Returns:
        JSON string representing the CSAF 2.0 VEX document.
    """
    try:
        vuln_list = json.loads(vulnerabilities)
        if not isinstance(vuln_list, list):
            return json.dumps({"status": "error", "message": "vulnerabilities must be a JSON list"})
    except Exception as e:
        return json.dumps(
            {"status": "error", "message": f"Failed to parse vulnerabilities JSON: {e}"}
        )

    vex_json = generate_csaf_vex(
        product_name=product_name,
        product_version=product_version,
        vulnerabilities=vuln_list,
        document_title=document_title,
    )
    return vex_json


# =============================================================================
# Plugin Class
# =============================================================================


class ReportToolsPlugin(Plugin):
    """Plugin for Report Generation tools."""

    name = "report_tools"
    description = "Malware analysis report generation tools with session tracking, IOC collection, and email delivery."

    def __init__(self):
        self._report_tools = None

    def register(self, mcp_server: Any) -> None:
        """Register report tools with the MCP server."""
        # Initialize ReportTools singleton
        self._report_tools = get_report_tools()

        # Register all tools
        mcp_server.tool(get_system_time)
        mcp_server.tool(set_timezone)
        mcp_server.tool(get_timezone_info)
        mcp_server.tool(start_report_session)
        mcp_server.tool(end_report_session)
        mcp_server.tool(get_report_session_status)
        mcp_server.tool(list_report_sessions)
        mcp_server.tool(add_ioc)
        mcp_server.tool(add_analysis_note)
        mcp_server.tool(add_mitre_technique)
        mcp_server.tool(set_severity)
        mcp_server.tool(create_analysis_report)
        mcp_server.tool(generate_vex_report)
        mcp_server.tool(generate_sigma_rule)

        logger.info(f"Registered {self.name} plugin with 14 report tools")


# Legacy function for backward compatibility
def register_report_tools(
    mcp_server, template_dir: Path | None = None, output_dir: Path | None = None
):
    """
    Legacy function for registering report tools.
    Use ReportToolsPlugin class instead for Plugin pattern.
    """
    plugin = ReportToolsPlugin()
    plugin.register(mcp_server)
    return plugin._report_tools
