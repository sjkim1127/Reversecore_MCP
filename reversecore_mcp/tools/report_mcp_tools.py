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

    @mcp_server.tool()
    async def generate_malware_submission(
        file_path: str,
        analyst_name: str = "Automated AI",
        tags: str = "malware"
    ) -> str:
        """
        Generate a standardized JSON report for malware submission.
        
        Collects comprehensive file analysis data adhering to the submission schema:
        - File Metadata (Hashes, Size, Type, Timestamp)
        - Sections & Imports (via LIEF)
        - Strings (Truncated preview + Full count)
        - IOCs (IPs, Domains, Bitcoin, Hashes from strings)
        
        Args:
            file_path: Path to the malware sample (must be in workspace)
            analyst_name: Name of the analyst
            tags: Comma-separated tags
            
        Returns:
            JSON result with report path and summary
        """
        import hashlib
        import os
        from datetime import datetime, timezone
        from reversecore_mcp.core.security import validate_file_path
        
        # 1. File Validation & Metadata
        try:
            validated_path = validate_file_path(file_path)
            file_path_str = str(validated_path)
            
            # Basic stats
            stat = validated_path.stat()
            file_size = stat.st_size
            
            # Calculate Hashes
            hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
            with open(validated_path, "rb") as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)
            
            file_hashes = {k: v.hexdigest() for k, v in hashes.items()}
            
            # 2. Tool Integration
            report_data = {
                "filename": validated_path.name,
                "sha256": file_hashes["sha256"],
                "md5": file_hashes["md5"],
                "sha1": file_hashes["sha1"],
                "size": file_size,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "analyst": analyst_name,
                "tags": [t.strip() for t in tags.split(",") if t.strip()],
                "file_type": "unknown", # Will be updated by tools
                "sections": [],
                "imports": [],
                "strings_truncated": True,
                "strings_preview": [],
                "strings_count": 0,
                "iocs": {},
                "logs": []
            }

            # LIEF Analysis (Sections, Imports, Type)
            try:
                from reversecore_mcp.tools.lief_tools import parse_binary_with_lief
                lief_result = parse_binary_with_lief(file_path_str, format="json")
                if lief_result.status == "success":
                    data = lief_result.data
                    report_data["file_type"] = data.get("format", "unknown")
                    report_data["sections"] = data.get("sections", [])
                    
                    # Flatten imports for schema compatibility
                    imports_raw = data.get("imports", [])
                    # Simplification: List of objects with dll name and functions
                    report_data["imports"] = imports_raw
                    
                    if "entry_point" in data:
                        report_data["entry_point"] = data["entry_point"]
                else:
                    report_data["logs"].append({
                        "tool": "lief",
                        "error_message": lief_result.error_message
                    })
            except Exception as e:
                report_data["logs"].append({"tool": "lief", "error_message": str(e)})

            # String Extraction
            all_strings_content = ""
            try:
                from reversecore_mcp.tools.static_analysis import run_strings
                # Request limited size for preview, but enough for IOCs
                strings_result = await run_strings(file_path_str, min_length=4, max_output_size=1024*1024) # 1MB limit for memory safety
                
                if strings_result.status == "success":
                    all_strings_content = strings_result.content if isinstance(strings_result.content, str) else str(strings_result.data)
                    string_lines = all_strings_content.splitlines()
                    report_data["strings_count"] = len(string_lines)
                    report_data["strings_preview"] = string_lines[:500] # First 500 strings
                else:
                    report_data["logs"].append({
                        "tool": "strings",
                        "error_message": strings_result.error_message
                    })
            except Exception as e:
                report_data["logs"].append({"tool": "strings", "error_message": str(e)})

            # IOC Extraction (using strings content)
            try:
                from reversecore_mcp.tools.ioc_tools import extract_iocs
                # We can't pass raw content to extract_iocs as it expects file path.
                # However, extract_iocs runs strings internally if file is binary.
                # So we just run extract_iocs on the file.
                ioc_result = extract_iocs(file_path_str)
                
                if ioc_result.status == "success":
                    report_data["iocs"] = ioc_result.data
                else:
                     report_data["logs"].append({
                        "tool": "extract_iocs",
                        "error_message": ioc_result.error_message
                    })
            except Exception as e:
                report_data["logs"].append({"tool": "extract_iocs", "error_message": str(e)})

            # 3. Save Report
            output_filename = f"{validated_path.stem}_submission.json"
            # Use the output directory from report_tools if available, otherwise workspace
            save_path = validated_path.parent / output_filename
            
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(report_data, indent=2, ensure_ascii=False))
                
            return json.dumps({
                "status": "success",
                "message": f"Submission JSON generated: {save_path.name}",
                "report_path": str(save_path),
                "summary": {
                    "filename": report_data["filename"],
                    "hashes": file_hashes,
                    "iocs_found": sum(len(v) for v in report_data.get("iocs", {}).values() if isinstance(v, list))
                }
            }, indent=2)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": f"Failed to generate submission: {str(e)}"
            })

    return report_tools
