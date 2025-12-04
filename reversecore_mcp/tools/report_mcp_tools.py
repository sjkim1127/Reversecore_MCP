"""
MCP Tool Definitions for Report Generation
Register these tools in your MCP server
"""

# Use optimized JSON implementation (3-5x faster than standard json)
from pathlib import Path

from reversecore_mcp.core import json_utils as json

from .report_tools import get_report_tools


def register_report_tools(mcp_server, template_dir: Path | None = None, output_dir: Path | None = None):
    """
    Register report tools with the MCP server.
    
    Args:
        mcp_server: FastMCP server instance
        template_dir: Template directory path
        output_dir: Output directory path
    
    Returns:
        ReportTools instance
    """

    # Initialize ReportTools instance
    report_tools = get_report_tools(
        template_dir=template_dir or Path("templates/reports"),
        output_dir=output_dir or Path("reports"),
        default_timezone="Asia/Seoul"
    )

    # =========================================================================
    # Time & Timezone Tools
    # =========================================================================

    @mcp_server.tool()
    async def get_system_time() -> str:
        """
        Get accurate system timestamp from the server.
        
        Returns OS-level time data to prevent AI date hallucination.
        Includes multiple formats (ISO, Unix, human-readable) and timezone info.
        
        Use this when you need to know the current date/time for reports.
        
        Returns:
            JSON with report_id, date formats, time formats, timezone info
            
        Example Response:
            {
              "report_id": "MAR-20251205-143052",
              "date": "2025-12-05",
              "date_long": "December 05, 2025",
              "date_eu": "05/12/2025",
              "weekday": "Friday",
              "weekday_short": "Fri",
              "datetime_full": "2025-12-05 14:30:52 (KST)",
              "timestamp_unix": 1733376652,
              "timezone": "Asia/Seoul"
            }
        """
        result = await report_tools.get_current_time()
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def set_timezone(timezone: str) -> str:
        """
        Set the default timezone for timestamps.
        
        Args:
            timezone: Timezone name. Available options:
                - UTC (UTC+0)
                - Asia/Seoul (UTC+9, KST) - Default
                - Asia/Tokyo (UTC+9, JST)
                - Asia/Shanghai (UTC+8, CST)
                - America/New_York (UTC-5, EST)
                - America/Los_Angeles (UTC-8, PST)
                - Europe/Paris (UTC+1, CET)
                - Europe/London (UTC+0, GMT)
        
        Returns:
            JSON with success status and current time in new timezone
        """
        result = report_tools.set_timezone(timezone)
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def get_timezone_info() -> str:
        """
        Get current timezone configuration and available options.
        
        Returns:
            JSON with current timezone, offset, and all available timezones
        """
        result = report_tools.get_timezone_info()
        return json.dumps(result, indent=2, ensure_ascii=False)

    # =========================================================================
    # Session Management Tools
    # =========================================================================

    @mcp_server.tool()
    async def start_analysis_session(
        sample_path: str = "",
        analyst: str = "Security Researcher",
        severity: str = "medium",
        malware_family: str = "",
        tags: str = ""
    ) -> str:
        """
        Start a new malware analysis session.
        
        Automatically tracks:
        - Start time (server-side, accurate)
        - Sample file hashes (MD5, SHA1, SHA256)
        - IOCs discovered during analysis
        - MITRE ATT&CK techniques
        - Analysis notes with timestamps
        
        Args:
            sample_path: Path to the malware sample to analyze
            analyst: Name of the analyst
            severity: Initial severity assessment (low, medium, high, critical)
            malware_family: Known malware family name (if identified)
            tags: Comma-separated tags (e.g., "ransomware,apt,financial")
        
        Returns:
            Session ID and initial information
            
        Example:
            start_analysis_session(
                sample_path="/samples/malware.exe",
                analyst="Kim",
                severity="high",
                tags="trojan,banking"
            )
        """
        tags_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None

        result = await report_tools.start_session(
            sample_path=sample_path if sample_path else None,
            analyst=analyst,
            severity=severity,
            malware_family=malware_family if malware_family else None,
            tags=tags_list
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def end_analysis_session(
        session_id: str = "",
        status: str = "completed",
        summary: str = ""
    ) -> str:
        """
        End the current analysis session.
        
        Args:
            session_id: Session ID to end (uses current session if not specified)
            status: Final status - "completed" or "aborted"
            summary: Brief summary of analysis findings
        
        Returns:
            Session summary with duration and collected data stats
        """
        result = await report_tools.end_session(
            session_id=session_id if session_id else None,
            status=status,
            summary=summary if summary else None
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def get_session_status(session_id: str = "") -> str:
        """
        Get current session information and collected data.
        
        Shows all IOCs, MITRE techniques, notes, and timing information.
        
        Args:
            session_id: Session ID to query (uses current session if not specified)
        
        Returns:
            Complete session data including IOCs, techniques, notes, duration
        """
        result = await report_tools.get_session_info(
            session_id=session_id if session_id else None
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def list_analysis_sessions() -> str:
        """
        List all analysis sessions with their status and duration.
        
        Returns:
            List of all sessions with summary information
        """
        result = await report_tools.list_sessions()
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def add_ioc(
        ioc_type: str,
        value: str,
        session_id: str = ""
    ) -> str:
        """
        Add an Indicator of Compromise to the current session.
        
        Args:
            ioc_type: Type of IOC:
                - hashes: File hashes (MD5, SHA1, SHA256)
                - ips: IP addresses
                - domains: Domain names
                - urls: Full URLs
                - files: File paths
                - registry: Registry keys
                - mutexes: Mutex names
                - emails: Email addresses
            value: The IOC value
            session_id: Session ID (uses current session if not specified)
        
        Examples:
            add_ioc("domains", "malware-c2.evil.com")
            add_ioc("ips", "192.168.1.100")
            add_ioc("hashes", "MD5: d41d8cd98f00b204e9800998ecf8427e")
            add_ioc("registry", "HKCU\\Software\\Malware\\AutoRun")
            add_ioc("urls", "https://evil.com/payload.exe")
        """
        result = await report_tools.add_session_ioc(
            ioc_type=ioc_type,
            value=value,
            session_id=session_id if session_id else None
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def add_analysis_note(
        note: str,
        category: str = "general",
        session_id: str = ""
    ) -> str:
        """
        Add an analysis note to the current session.
        Notes are automatically timestamped by the server.
        
        Args:
            note: The note content
            category: Note category:
                - general: General observations
                - finding: Important findings
                - warning: Warnings or concerns
                - important: Critical information
                - behavior: Behavioral observations
            session_id: Session ID (uses current session if not specified)
        
        Examples:
            add_analysis_note("Found anti-VM check using CPUID", "finding")
            add_analysis_note("C2 communication uses custom XOR encryption", "important")
            add_analysis_note("Creates scheduled task for persistence", "behavior")
        """
        result = await report_tools.add_session_note(
            note=note,
            category=category,
            session_id=session_id if session_id else None
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def add_mitre_technique(
        technique_id: str,
        technique_name: str,
        tactic: str,
        session_id: str = ""
    ) -> str:
        """
        Add a MITRE ATT&CK technique to the current session.
        
        Args:
            technique_id: MITRE technique ID (e.g., "T1055.001", "T1497")
            technique_name: Technique name (e.g., "Process Injection: DLL Injection")
            tactic: ATT&CK tactic:
                - Initial Access
                - Execution
                - Persistence
                - Privilege Escalation
                - Defense Evasion
                - Credential Access
                - Discovery
                - Lateral Movement
                - Collection
                - Command and Control
                - Exfiltration
                - Impact
            session_id: Session ID (uses current session if not specified)
        
        Examples:
            add_mitre_technique("T1055.001", "Process Injection: DLL Injection", "Defense Evasion")
            add_mitre_technique("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion")
            add_mitre_technique("T1053.005", "Scheduled Task/Job", "Persistence")
        """
        result = await report_tools.add_session_mitre(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            session_id=session_id if session_id else None
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def add_session_tag(
        tag: str,
        session_id: str = ""
    ) -> str:
        """
        Add a tag to the current session.
        
        Tags help categorize and filter analyses.
        
        Args:
            tag: Tag to add (e.g., "ransomware", "apt", "banking-trojan")
            session_id: Session ID (uses current session if not specified)
        
        Common tags:
            - ransomware, trojan, worm, backdoor, rootkit
            - apt, nation-state, cybercrime, hacktivism
            - financial, healthcare, government, critical-infrastructure
            - windows, linux, macos, android, ios
        """
        result = await report_tools.add_session_tag(
            tag=tag,
            session_id=session_id if session_id else None
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def set_session_severity(
        severity: str,
        session_id: str = ""
    ) -> str:
        """
        Update the severity level of the current session.
        
        Args:
            severity: Severity level:
                - low: Minor threat, limited impact
                - medium: Moderate threat, some impact
                - high: Significant threat, major impact
                - critical: Severe threat, immediate action required
            session_id: Session ID (uses current session if not specified)
        """
        result = await report_tools.set_session_severity(
            severity=severity,
            session_id=session_id if session_id else None
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    # =========================================================================
    # Report Generation Tools
    # =========================================================================

    @mcp_server.tool()
    async def create_analysis_report(
        template_type: str = "full_analysis",
        session_id: str = "",
        sample_path: str = "",
        analyst: str = "Security Researcher",
        classification: str = "TLP:AMBER"
    ) -> str:
        """
        Generate a malware analysis report.
        
        If a session is active, automatically includes:
        - Analysis start/end times and duration
        - All collected IOCs
        - MITRE ATT&CK mappings
        - Analysis notes with timestamps
        - Sample metadata (hashes, file type, size)
        
        All timestamps are generated server-side for accuracy.
        
        Args:
            template_type: Report template:
                - full_analysis: Comprehensive technical report for analysts
                - quick_triage: Fast initial assessment for SOC teams
                - ioc_summary: IOC-focused report for threat intelligence
                - executive_brief: Non-technical summary for management
            session_id: Session ID to use (uses current session if not specified)
            sample_path: Sample path (only needed if no session)
            analyst: Analyst name
            classification: Traffic Light Protocol classification:
                - TLP:WHITE - Unlimited disclosure
                - TLP:GREEN - Community-wide sharing
                - TLP:AMBER - Limited disclosure (default)
                - TLP:RED - Personal/organization only
        
        Returns:
            JSON with report_id, path, and generated content
        """
        result = await report_tools.create_report(
            template_type=template_type,
            session_id=session_id if session_id else None,
            sample_path=sample_path if sample_path else None,
            analyst=analyst,
            classification=classification
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def list_report_templates() -> str:
        """
        List available report templates with descriptions.
        
        Returns:
            List of templates with name, description, and path
        """
        result = await report_tools.list_templates()
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def get_report(report_id: str) -> str:
        """
        Retrieve a generated report by ID.
        
        Args:
            report_id: Report ID (e.g., "MAR-20251205-143052")
        
        Returns:
            Report content and metadata
        """
        result = await report_tools.get_report(report_id)
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def list_reports() -> str:
        """
        List all generated reports.
        
        Returns:
            List of reports with ID, path, size, and timestamps
        """
        result = await report_tools.list_reports()
        return json.dumps(result, indent=2, ensure_ascii=False)

    # =========================================================================
    # Email / Delivery Tools
    # =========================================================================

    @mcp_server.tool()
    async def configure_report_email(
        smtp_server: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        use_tls: bool = True
    ) -> str:
        """
        Configure email settings for report delivery.
        
        Args:
            smtp_server: SMTP server address (e.g., "smtp.gmail.com")
            smtp_port: SMTP port (default: 587 for TLS)
            username: Email username/address
            password: Email password or app-specific password
            use_tls: Use TLS encryption (recommended)
        
        Note: 
        - For Gmail, use App Passwords with 2FA enabled.
        - For Naver, enable POP3/SMTP and use app password.
        - You can also set email via environment variables (.env file).
        """
        result = await report_tools.configure_email(
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            username=username,
            password=password,
            use_tls=use_tls
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def get_email_status() -> str:
        """
        Check email configuration status.
        
        Shows whether email is configured and ready to send.
        If not configured, provides hints on how to set it up.
        
        Email can be configured via:
        1. Environment variables (.env file) - recommended for persistent config
        2. configure_report_email tool - runtime configuration
        
        Environment variables:
        - REPORT_SMTP_SERVER: SMTP server (e.g., smtp.naver.com)
        - REPORT_SMTP_PORT: Port (default: 587)
        - REPORT_SMTP_USERNAME: Email account
        - REPORT_SMTP_PASSWORD: Password or app password
        - REPORT_SMTP_USE_TLS: Use TLS (default: true)
        - REPORT_QUICK_CONTACTS: Preset contacts (format: name:email:role,...)
        
        Returns:
            JSON with configuration status and hints
        """
        result = await report_tools.get_email_status()
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def add_quick_contact(
        name: str,
        email: str,
        role: str = "Security Analyst"
    ) -> str:
        """
        Add a quick contact for easy report delivery.
        
        Quick contacts can be referenced by name when sending reports.
        
        Args:
            name: Contact name (used as reference)
            email: Email address
            role: Contact's role (for documentation)
        
        Example:
            add_quick_contact("SOC Lead", "soc-lead@company.com", "SOC Manager")
            add_quick_contact("CISO", "ciso@company.com", "Chief Information Security Officer")
        """
        result = await report_tools.add_quick_contact(
            name=name,
            email=email,
            role=role
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def list_quick_contacts() -> str:
        """
        List all configured quick contacts.
        
        Returns:
            List of contacts with name, email, and role
        """
        result = await report_tools.list_quick_contacts()
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp_server.tool()
    async def send_report_email(
        report_id: str,
        recipients: str,
        subject: str = "",
        message: str = "",
        include_attachment: bool = True
    ) -> str:
        """
        Send a report via email.
        
        Args:
            report_id: Report ID to send (e.g., "MAR-20251205-143052")
            recipients: Comma-separated email addresses or quick contact names
                       (e.g., "analyst@company.com,SOC Lead,CISO")
            subject: Email subject (auto-generated if not specified)
            message: Email body (auto-generated with report preview if not specified)
            include_attachment: Attach the report file (default: True)
        
        Example:
            send_report_email(
                report_id="MAR-20251205-143052",
                recipients="SOC Lead,analyst@company.com",
                subject="[URGENT] Critical Malware Analysis Report"
            )
        
        Note: Configure email settings first with configure_report_email.
        """
        recipients_list = [r.strip() for r in recipients.split(",") if r.strip()]

        result = await report_tools.send_report(
            report_id=report_id,
            recipients=recipients_list,
            subject=subject if subject else None,
            message=message if message else None,
            include_attachment=include_attachment
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    return report_tools
