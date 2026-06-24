"""
Malware Analysis Report Tools for Reversecore_MCP

Features:
- OS-level timestamp (no AI hallucination)
- Session tracking (start/end time, duration)
- Timezone support (UTC, local, custom)
- IOC collection during analysis
- Template-based report generation
- Environment variable support for email configuration
"""

import hashlib
import logging
import os
import platform
import uuid
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import aiofiles
import aiosmtplib

from reversecore_mcp.tools.report.email import (
    EmailConfig,
    load_quick_contacts_from_env,
)

# Use optimized JSON implementation (3-5x faster than standard json)
# Import session and email utilities from submodules
from reversecore_mcp.tools.report.session import (
    TIMEZONE_ABBRS,
    TIMEZONE_OFFSETS,
    AnalysisSession,
)

logger = logging.getLogger(__name__)


class ReportTools:
    """
    Malware Analysis Report Generation Tools

    Features:
    - OS-level accurate timestamps
    - Analysis session tracking
    - Multi-timezone support
    - Auto hash calculation
    - Template-based report generation
    - Email delivery support
    """

    def __init__(
        self,
        template_dir: Path,
        output_dir: Path,
        default_timezone: str = "UTC",
        email_config: EmailConfig | None = None,
    ):
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.default_timezone = default_timezone
        self.timezone_offset = TIMEZONE_OFFSETS.get(default_timezone, 0)

        # Active session management
        self.sessions: dict[str, AnalysisSession] = {}
        self.current_session_id: str | None = None

        # Email configuration
        self.email_config = email_config or EmailConfig()

        # Quick contacts list
        self.quick_contacts: dict[str, dict[str, str]] = {}

    # =========================================================================
    # Timezone Management
    # =========================================================================

    def set_timezone(self, tz: str) -> dict:
        """
        Set default timezone.

        Args:
            tz: Timezone name (UTC, Asia/Seoul, America/New_York, etc.)
        """
        if tz not in TIMEZONE_OFFSETS:
            return {
                "success": False,
                "error": f"Unknown timezone: {tz}",
                "available": list(TIMEZONE_OFFSETS.keys()),
            }

        offset = TIMEZONE_OFFSETS.get(tz, 0)
        return {
            "success": True,
            "timezone": tz,
            "utc_offset": f"UTC{'+' if offset >= 0 else ''}{offset}",
            "abbreviation": TIMEZONE_ABBRS.get(tz, ""),
            "current_time": self._format_time(datetime.now(timezone.utc), tz_name=tz),
        }

    def get_timezone_info(self) -> dict:
        """Return current timezone configuration info"""
        return {
            "current_timezone": self.default_timezone,
            "utc_offset": self.timezone_offset,
            "abbreviation": TIMEZONE_ABBRS.get(self.default_timezone, ""),
            "available_timezones": {
                name: {
                    "offset": f"UTC{'+' if offset >= 0 else ''}{offset}",
                    "abbreviation": TIMEZONE_ABBRS.get(name, ""),
                }
                for name, offset in TIMEZONE_OFFSETS.items()
            },
        }

    def _get_local_time(self) -> datetime:
        """Get current time in configured timezone"""
        utc_now = datetime.now(timezone.utc)
        local_tz = timezone(timedelta(hours=self.timezone_offset))
        return utc_now.astimezone(local_tz)

    def _format_time(
        self, dt: datetime, include_tz: bool = True, tz_name: str | None = None
    ) -> str:
        """Format datetime to configured timezone"""
        target_tz_name = tz_name or self.default_timezone
        offset = TIMEZONE_OFFSETS.get(target_tz_name, 0)

        local_tz = timezone(timedelta(hours=offset))
        local_dt = dt.astimezone(local_tz)

        if include_tz:
            abbr = TIMEZONE_ABBRS.get(target_tz_name, f"UTC{'+' if offset >= 0 else ''}{offset}")
            return f"{local_dt.strftime('%Y-%m-%d %H:%M:%S')} ({abbr})"
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")

    # =========================================================================
    # Timestamp Generation
    # =========================================================================

    def get_timestamp_data(self, tz_name: str | None = None) -> dict:
        """
        Generate accurate timestamp data at OS level.
        Provided directly from server to prevent AI from guessing dates.
        """
        target_tz_name = tz_name or self.default_timezone
        offset = TIMEZONE_OFFSETS.get(target_tz_name, 0)

        utc_now = datetime.now(timezone.utc)
        local_tz = timezone(timedelta(hours=offset))
        local_now = utc_now.astimezone(local_tz)
        abbr = TIMEZONE_ABBRS.get(target_tz_name, "")

        return {
            # For Report ID generation
            "report_id": f"MAR-{local_now.strftime('%Y%m%d-%H%M%S')}",
            # Date formats (ISO, localized)
            "date": local_now.strftime("%Y-%m-%d"),
            "date_long": local_now.strftime("%B %d, %Y"),  # December 05, 2025
            "date_short": local_now.strftime("%d %b %Y"),  # 05 Dec 2025
            "date_eu": local_now.strftime("%d/%m/%Y"),  # 05/12/2025
            "date_us": local_now.strftime("%m/%d/%Y"),  # 12/05/2025
            # Time formats
            "time": local_now.strftime("%H:%M:%S"),
            "time_12h": local_now.strftime("%I:%M:%S %p"),  # 02:30:45 PM
            "datetime": local_now.strftime("%Y-%m-%d %H:%M:%S"),
            "datetime_full": self._format_time(utc_now, tz_name=target_tz_name),
            "datetime_iso": local_now.isoformat(),
            # UTC based
            "datetime_utc": utc_now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "timestamp_unix": int(utc_now.timestamp()),
            # Individual fields
            "year": local_now.strftime("%Y"),
            "month": local_now.strftime("%m"),
            "month_name": local_now.strftime("%B"),  # December
            "month_name_short": local_now.strftime("%b"),  # Dec
            "day": local_now.strftime("%d"),
            "weekday": local_now.strftime("%A"),  # Thursday
            "weekday_short": local_now.strftime("%a"),  # Thu
            # Timezone info
            "timezone": target_tz_name,
            "timezone_abbr": abbr,
            "timezone_offset": f"UTC{'+' if offset >= 0 else ''}{offset}",
            # System info
            "hostname": platform.node(),
            "platform": platform.system(),
        }

    async def get_current_time(self) -> dict:
        """Return current system time info (for MCP Tool)"""
        return self.get_timestamp_data()

    # =========================================================================
    # Session Management
    # =========================================================================

    async def start_session(
        self,
        sample_path: str | None = None,
        analyst: str = "Security Researcher",
        severity: str = "medium",
        malware_family: str | None = None,
        tags: list[str] | None = None,
    ) -> dict:
        """
        Start a new analysis session.

        Args:
            sample_path: Path to the sample file
            analyst: Analyst name
            severity: Severity level (low, medium, high, critical)
            malware_family: Malware family name
            tags: Tag list

        Returns:
            Session information
        """
        session_id = f"SES-{uuid.uuid4().hex[:8].upper()}"

        session = AnalysisSession(
            session_id=session_id,
            sample_path=sample_path,
            sample_name=Path(sample_path).name if sample_path else None,
            analyst=analyst,
            severity=severity,
            malware_family=malware_family,
        )

        if tags:
            for tag in tags:
                session.add_tag(tag)

        session.start()

        # Auto-calculate sample hashes
        if sample_path:
            sample_info = await self._extract_sample_info(sample_path)
            session.findings["sample_info"] = sample_info

            # Auto-add hashes to IOC
            for hash_type in ["md5", "sha1", "sha256"]:
                if hash_type in sample_info:
                    session.add_ioc("hashes", f"{hash_type.upper()}: {sample_info[hash_type]}")

        self.sessions[session_id] = session
        self.current_session_id = session_id

        return {
            "success": True,
            "session_id": session_id,
            "started_at": self._format_time(session.started_at),
            "started_at_utc": session.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "sample": session.sample_name,
            "analyst": analyst,
            "severity": severity,
            "malware_family": malware_family,
            "message": f"Analysis session started. Use session_id '{session_id}' to track.",
        }

    async def end_session(
        self,
        session_id: str | None = None,
        status: str = "completed",
        summary: str | None = None,
    ) -> dict:
        """
        End an analysis session.

        Args:
            session_id: Session ID (uses current session if not provided)
            status: End status (completed, aborted)
            summary: Analysis summary
        """
        sid = session_id or self.current_session_id

        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session found"}

        session = self.sessions[sid]
        session.end(status)

        if summary:
            session.findings["summary"] = summary

        result = {
            "success": True,
            "session_id": sid,
            "status": status,
            "started_at": self._format_time(session.started_at),
            "ended_at": self._format_time(session.ended_at),
            "duration": session.get_duration_str(),
            "severity": session.severity,
            "malware_family": session.malware_family,
            "iocs_collected": sum(len(v) for v in session.iocs.values()),
            "mitre_techniques": len(session.mitre_techniques),
            "notes": len(session.notes),
            "tags": session.tags,
        }

        if sid == self.current_session_id:
            self.current_session_id = None

        return result

    async def get_session_info(self, session_id: str | None = None) -> dict:
        """Query session status"""
        sid = session_id or self.current_session_id

        if not sid or sid not in self.sessions:
            return {
                "success": False,
                "error": "No session found",
                "active_sessions": list(self.sessions.keys()),
            }

        session = self.sessions[sid]
        info = session.to_dict()

        # 포맷된 시간 추가
        if session.started_at:
            info["started_at_formatted"] = self._format_time(session.started_at)
        if session.ended_at:
            info["ended_at_formatted"] = self._format_time(session.ended_at)

        info["is_current"] = sid == self.current_session_id

        return {"success": True, "session": info}

    async def add_session_ioc(
        self, ioc_type: str, value: str, session_id: str | None = None
    ) -> dict:
        """Add IOC to session"""
        sid = session_id or self.current_session_id

        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}

        session = self.sessions[sid]
        valid_types = list(session.iocs.keys())

        if ioc_type not in valid_types:
            return {
                "success": False,
                "error": f"Invalid IOC type: {ioc_type}",
                "valid_types": valid_types,
            }

        added = session.add_ioc(ioc_type, value)

        return {
            "success": True,
            "added": added,
            "ioc": {"type": ioc_type, "value": value},
            "message": "IOC added" if added else "IOC already exists",
            "total_iocs": sum(len(v) for v in session.iocs.values()),
        }

    async def add_session_note(
        self, note: str, category: str = "general", session_id: str | None = None
    ) -> dict:
        """Add analysis note to session"""
        sid = session_id or self.current_session_id

        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}

        session = self.sessions[sid]
        session.add_note(note, category)

        return {
            "success": True,
            "note_added": note[:100] + "..." if len(note) > 100 else note,
            "category": category,
            "timestamp": self._format_time(datetime.now(timezone.utc)),
            "total_notes": len(session.notes),
        }

    async def add_session_mitre(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        session_id: str | None = None,
    ) -> dict:
        """Add MITRE ATT&CK technique to session"""
        sid = session_id or self.current_session_id

        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}

        session = self.sessions[sid]
        session.add_mitre(technique_id, technique_name, tactic)

        return {
            "success": True,
            "added": f"{technique_id} - {technique_name}",
            "tactic": tactic,
            "total_techniques": len(session.mitre_techniques),
        }

    async def add_session_tag(self, tag: str, session_id: str | None = None) -> dict:
        """Add tag to session"""
        sid = session_id or self.current_session_id

        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}

        session = self.sessions[sid]
        session.add_tag(tag)

        return {"success": True, "tag_added": tag, "all_tags": session.tags}

    async def set_session_severity(self, severity: str, session_id: str | None = None) -> dict:
        """Set session severity"""
        sid = session_id or self.current_session_id

        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}

        valid_severities = ["low", "medium", "high", "critical"]
        if severity.lower() not in valid_severities:
            return {
                "success": False,
                "error": f"Invalid severity: {severity}",
                "valid_severities": valid_severities,
            }

        session = self.sessions[sid]
        session.severity = severity.lower()

        return {"success": True, "severity": session.severity, "session_id": sid}

    async def list_sessions(self) -> dict:
        """List all sessions"""
        sessions_list = []

        for sid, session in self.sessions.items():
            sessions_list.append(
                {
                    "session_id": sid,
                    "sample": session.sample_name,
                    "status": session.status,
                    "severity": session.severity,
                    "malware_family": session.malware_family,
                    "started_at": (
                        self._format_time(session.started_at) if session.started_at else None
                    ),
                    "duration": session.get_duration_str(),
                    "iocs_count": sum(len(v) for v in session.iocs.values()),
                    "is_current": sid == self.current_session_id,
                }
            )

        return {
            "total": len(sessions_list),
            "current_session": self.current_session_id,
            "sessions": sessions_list,
        }

    # =========================================================================
    # Report Generation
    # =========================================================================

    async def create_report(
        self,
        template_type: str = "full_analysis",
        session_id: str | None = None,
        sample_path: str | None = None,
        analyst: str = "Security Researcher",
        classification: str = "TLP:AMBER",
        custom_fields: dict | None = None,
        output_format: str = "markdown",
        timezone: str | None = None,  # Add per-request timezone
    ) -> dict:
        """
        Generate an analysis report.
        If a session exists, session data is automatically included.
        """
        # 타임스탬프 생성 (서버 시간 기준, 타임존 지정 가능)
        ts = self.get_timestamp_data(tz_name=timezone)

        # 템플릿 로드
        template_path = self.template_dir / f"{template_type}.md"
        if not template_path.exists():
            available = [f.stem for f in self.template_dir.glob("*.md")]
            return {
                "success": False,
                "error": f"Template not found: {template_type}",
                "available_templates": available,
            }

        async with aiofiles.open(template_path, encoding="utf-8") as f:
            template = await f.read()

        # Basic fields
        fields = {
            "REPORT_ID": ts["report_id"],
            "DATE": ts["date"],
            "DATE_LONG": ts["date_long"],
            "DATE_SHORT": ts["date_short"],
            "DATE_EU": ts["date_eu"],
            "DATE_US": ts["date_us"],
            "DATETIME": ts["datetime"],
            "DATETIME_FULL": ts["datetime_full"],
            "DATETIME_UTC": ts["datetime_utc"],
            "TIMESTAMP": str(ts["timestamp_unix"]),
            "YEAR": ts["year"],
            "MONTH": ts["month"],
            "MONTH_NAME": ts["month_name"],
            "MONTH_NAME_SHORT": ts["month_name_short"],
            "DAY": ts["day"],
            "WEEKDAY": ts["weekday"],
            "WEEKDAY_SHORT": ts["weekday_short"],
            "TIME": ts["time"],
            "TIME_12H": ts["time_12h"],
            "TIMEZONE": ts["timezone"],
            "TIMEZONE_ABBR": ts["timezone_abbr"],
            "ANALYST": analyst,
            "CLASSIFICATION": classification,
            "GENERATED_BY": "Reversecore_MCP",
            "HOSTNAME": ts["hostname"],
        }

        # Merge session data
        sid = session_id or self.current_session_id
        session = self.sessions.get(sid) if sid else None

        if session:
            fields.update(
                {
                    "SESSION_ID": session.session_id,
                    "SESSION_STATUS": session.status,
                    "SEVERITY": session.severity.upper(),
                    "SEVERITY_EMOJI": self._get_severity_emoji(session.severity),
                    "MALWARE_FAMILY": session.malware_family or "Unknown",
                    "ANALYSIS_START": (
                        self._format_time(session.started_at) if session.started_at else "N/A"
                    ),
                    "ANALYSIS_END": (
                        self._format_time(session.ended_at) if session.ended_at else "In Progress"
                    ),
                    "ANALYSIS_DURATION": session.get_duration_str(),
                    "TAGS": ", ".join(session.tags) if session.tags else "None",
                }
            )

            # 세션에서 샘플 정보 가져오기
            if "sample_info" in session.findings:
                sample_info = session.findings["sample_info"]
                fields.update({k.upper(): str(v) for k, v in sample_info.items()})

            # IOC 블록 생성
            fields["IOCS_YAML"] = self._format_iocs_yaml(session.iocs)
            fields["IOCS_MARKDOWN"] = self._format_iocs_markdown(session.iocs)
            fields["IOCS_COUNT"] = str(sum(len(v) for v in session.iocs.values()))

            # MITRE 테이블 생성
            fields["MITRE_TABLE"] = self._format_mitre_table(session.mitre_techniques)
            fields["MITRE_COUNT"] = str(len(session.mitre_techniques))

            # 노트 섹션
            fields["ANALYSIS_NOTES"] = self._format_notes(session.notes)
            fields["NOTES_COUNT"] = str(len(session.notes))

            # 요약
            fields["SUMMARY"] = session.findings.get("summary", "_No summary provided._")

        # 샘플 정보 (세션 없이 직접 지정한 경우)
        elif sample_path:
            sample_info = await self._extract_sample_info(sample_path)
            fields.update({k.upper(): str(v) for k, v in sample_info.items()})

        # 커스텀 필드
        if custom_fields:
            fields.update({k.upper(): str(v) for k, v in custom_fields.items()})

        # 기본값 설정 (템플릿 변수가 치환되지 않은 경우)
        default_values = {
            "SEVERITY": "MEDIUM",
            "SEVERITY_EMOJI": "🟡",
            "MALWARE_FAMILY": "Unknown",
            "TAGS": "None",
            "IOCS_YAML": "# No IOCs collected",
            "IOCS_MARKDOWN": "_No IOCs collected._",
            "IOCS_COUNT": "0",
            "MITRE_TABLE": "| - | - | - |",
            "MITRE_COUNT": "0",
            "ANALYSIS_NOTES": "_No notes recorded._",
            "NOTES_COUNT": "0",
            "SUMMARY": "_No summary provided._",
            "SESSION_ID": "N/A",
            "SESSION_STATUS": "N/A",
            "ANALYSIS_START": "N/A",
            "ANALYSIS_END": "N/A",
            "ANALYSIS_DURATION": "N/A",
        }

        for key, default in default_values.items():
            if key not in fields:
                fields[key] = default

        # 템플릿 치환
        report = template
        for key, value in fields.items():
            report = report.replace(f"{{{{{key}}}}}", value)

        # 리포트 저장
        output_path = self.output_dir / f"{ts['report_id']}.md"
        async with aiofiles.open(output_path, mode="w", encoding="utf-8") as f:
            await f.write(report)

        return {
            "success": True,
            "report_id": ts["report_id"],
            "path": str(output_path),
            "template": template_type,
            "session_id": sid,
            "generated_at": ts["datetime_full"],
            "timezone": ts["timezone"],
            "fields_filled": len(fields),
            "report_content": report,  # 미리보기용
        }

    async def list_templates(self) -> dict:
        """List available templates"""
        templates = []

        for f in self.template_dir.glob("*.md"):
            async with aiofiles.open(f, encoding="utf-8") as tf:
                content = await tf.read()
            # 첫 줄에서 설명 추출 (<!-- description --> 형식)
            desc = ""
            if content.startswith("<!--"):
                end = content.find("-->")
                if end > 0:
                    desc = content[4:end].strip()

            templates.append({"name": f.stem, "description": desc, "path": str(f)})

        return {"total": len(templates), "templates": templates}

    async def get_report(self, report_id: str) -> dict:
        """Retrieve a generated report"""
        report_path = self.output_dir / f"{report_id}.md"

        if not report_path.exists():
            # 리포트 목록 반환
            reports = [f.stem for f in self.output_dir.glob("*.md")]
            return {
                "success": False,
                "error": f"Report not found: {report_id}",
                "available_reports": reports,
            }

        async with aiofiles.open(report_path, encoding="utf-8") as f:
            content = await f.read()

        return {
            "success": True,
            "report_id": report_id,
            "path": str(report_path),
            "content": content,
            "size": len(content),
        }

    async def list_reports(self) -> dict:
        """List generated reports"""
        reports = []

        for f in self.output_dir.glob("*.md"):
            stat = f.stat()
            reports.append(
                {
                    "report_id": f.stem,
                    "path": str(f),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            )

        # 최신순 정렬
        reports.sort(key=lambda x: x["created"], reverse=True)

        return {"total": len(reports), "reports": reports}

    # =========================================================================
    # Email / Delivery
    # =========================================================================

    async def get_email_status(self) -> dict:
        """Check email configuration status"""
        return {
            "configured": self.email_config.is_configured,
            "smtp_server": self.email_config.smtp_server or "(not set)",
            "smtp_port": self.email_config.smtp_port,
            "username": self.email_config.username or "(not set)",
            "use_tls": self.email_config.use_tls,
            "sender_name": self.email_config.sender_name,
            "quick_contacts_count": len(self.quick_contacts),
            "hint": (
                "Set environment variables or use configure_report_email tool"
                if not self.email_config.is_configured
                else None
            ),
        }

    async def configure_email(
        self,
        smtp_server: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        use_tls: bool = True,
        sender_name: str = "Reversecore_MCP",
    ) -> dict:
        """Configure email settings (runtime override, takes precedence over env vars)"""
        self.email_config = EmailConfig(
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            username=username,
            password=password,
            use_tls=use_tls,
            sender_name=sender_name,
        )

        return {
            "success": True,
            "smtp_server": smtp_server,
            "smtp_port": smtp_port,
            "use_tls": use_tls,
            "sender_name": sender_name,
            "configured": self.email_config.is_configured,
            "message": "Email configuration updated (runtime override)",
        }

    async def add_quick_contact(
        self, name: str, email: str, role: str = "Security Analyst"
    ) -> dict:
        """Add quick contact"""
        self.quick_contacts[name] = {"email": email, "role": role}

        return {
            "success": True,
            "contact": {"name": name, "email": email, "role": role},
            "total_contacts": len(self.quick_contacts),
        }

    async def list_quick_contacts(self) -> dict:
        """List quick contacts"""
        return {
            "total": len(self.quick_contacts),
            "contacts": [{"name": name, **info} for name, info in self.quick_contacts.items()],
        }

    async def send_report(
        self,
        report_id: str,
        recipients: list[str],
        subject: str | None = None,
        message: str | None = None,
        include_attachment: bool = True,
    ) -> dict:
        """
        Send a report via email.

        Args:
            report_id: Report ID to send
            recipients: List of recipient email addresses
            subject: Email subject (auto-generated by default)
            message: Email body
            include_attachment: Whether to attach the report file
        """
        # 리포트 확인
        report_path = self.output_dir / f"{report_id}.md"
        if not report_path.exists():
            return {"success": False, "error": f"Report not found: {report_id}"}

        # 이메일 설정 확인
        if not self.email_config.is_configured:
            return {
                "success": False,
                "error": "Email not configured. Set environment variables (REPORT_SMTP_SERVER, REPORT_SMTP_USERNAME, REPORT_SMTP_PASSWORD) or use configure_report_email tool.",
                "hint": "Copy .env.example to .env and fill in your SMTP settings",
            }

        # 빠른 연락처 이름을 이메일로 변환
        resolved_recipients = []
        for r in recipients:
            if r in self.quick_contacts:
                resolved_recipients.append(self.quick_contacts[r]["email"])
            else:
                resolved_recipients.append(r)

        async with aiofiles.open(report_path, encoding="utf-8") as f:
            report_content = await f.read()

        # 기본 제목
        if not subject:
            subject = f"[Malware Analysis Report] {report_id}"

        # 기본 메시지
        if not message:
            ts = self.get_timestamp_data()
            message = f"""안녕하세요,

새로운 악성코드 분석 리포트가 생성되었습니다.

리포트 ID: {report_id}
생성 시간: {ts["datetime_full"]}

상세 내용은 첨부 파일 또는 아래 내용을 확인해주세요.

---

{report_content[:2000]}{"...(truncated)" if len(report_content) > 2000 else ""}

---

이 리포트는 Reversecore_MCP에 의해 자동 생성되었습니다.
"""

        try:
            # 이메일 구성
            msg = MIMEMultipart()
            msg["From"] = self.email_config.username
            msg["To"] = ", ".join(resolved_recipients)
            msg["Subject"] = subject

            msg.attach(MIMEText(message, "plain", "utf-8"))

            # 첨부파일
            if include_attachment:
                attachment = MIMEBase("application", "octet-stream")
                attachment.set_payload(report_content.encode("utf-8"))
                encoders.encode_base64(attachment)
                attachment.add_header("Content-Disposition", f"attachment; filename={report_id}.md")
                msg.attach(attachment)

            # 전송 (Native async SMTP - no thread pool blocking)
            await aiosmtplib.send(
                msg,
                hostname=self.email_config.smtp_server,
                port=self.email_config.smtp_port,
                start_tls=self.email_config.use_tls,
                username=(self.email_config.username if self.email_config.username else None),
                password=(self.email_config.password if self.email_config.password else None),
            )

            return {
                "success": True,
                "report_id": report_id,
                "recipients": resolved_recipients,
                "subject": subject,
                "attachment_included": include_attachment,
                "sent_at": self._format_time(datetime.now(timezone.utc)),
            }

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return {
                "success": False,
                "error": str(e),
                "report_id": report_id,
                "recipients": resolved_recipients,
            }

    # =========================================================================
    # Helper Methods
    # =========================================================================

    async def _extract_sample_info(self, sample_path: str) -> dict:
        """Extract metadata from sample file"""
        path = Path(sample_path)

        if not path.exists():
            return {"filename": path.name, "error": "File not found"}

        # Stream file read to prevent memory explosion with large files
        md5_hash = hashlib.md5(usedforsecurity=False)
        sha1_hash = hashlib.sha1(usedforsecurity=False)
        sha256_hash = hashlib.sha256()

        file_size = 0
        first_chunk = b""

        async with aiofiles.open(path, mode="rb") as f:
            while chunk := await f.read(64 * 1024):  # 64KB chunks
                if not first_chunk:
                    first_chunk = chunk
                file_size += len(chunk)
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)

        stat = path.stat()

        info = {
            "filename": path.name,
            "filepath": str(path.absolute()),
            "filesize": file_size,
            "filesize_hr": self._human_readable_size(file_size),
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
            "file_created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "file_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }

        # 파일 타입 식별
        info["file_type"] = self._identify_file_type(first_chunk)

        return info

    @staticmethod
    def _identify_file_type(data: bytes) -> str:
        """Identify file type"""
        if len(data) < 4:
            return "Unknown (too small)"

        magic_bytes = {
            b"MZ": "PE Executable (Windows)",
            b"\x7fELF": "ELF Executable (Linux)",
            b"%PDF": "PDF Document",
            b"PK": "ZIP Archive / Office Document",
            b"\xd0\xcf\x11\xe0": "OLE Compound File (Office)",
            b"Rar!": "RAR Archive",
            b"\x1f\x8b": "GZIP Archive",
            b"BZ": "BZIP2 Archive",
            b"\x89PNG": "PNG Image",
            b"\xff\xd8\xff": "JPEG Image",
            b"GIF8": "GIF Image",
            b"<!DO": "HTML Document",
            b"<?xm": "XML Document",
            b"{\n  ": "JSON Document",
            b"#!": "Script (Shell/Python)",
        }

        for magic, file_type in magic_bytes.items():
            if data.startswith(magic):
                return file_type

        # ASCII 텍스트 체크
        try:
            data[:1000].decode("utf-8")
            return "Text/Script File"
        except UnicodeDecodeError:
            pass

        return "Unknown Binary"

    @staticmethod
    def _human_readable_size(size: int) -> str:
        """Convert bytes to human-readable format"""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:,.1f} {unit}"
            size /= 1024
        return f"{size:,.1f} TB"

    @staticmethod
    def _get_severity_emoji(severity: str) -> str:
        """Get severity emoji"""
        emojis = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
        return emojis.get(severity.lower(), "⚪")

    def _format_iocs_yaml(self, iocs: dict[str, list[str]]) -> str:
        """Format IOCs in YAML format"""
        lines = []
        for ioc_type, values in iocs.items():
            if values:
                lines.append(f"{ioc_type}:")
                for v in values:
                    lines.append(f"  - {v}")
        return "\n".join(lines) if lines else "# No IOCs collected"

    def _format_iocs_markdown(self, iocs: dict[str, list[str]]) -> str:
        """Format IOCs in Markdown format"""
        lines = []
        for ioc_type, values in iocs.items():
            if values:
                lines.append(f"### {ioc_type.title()}")
                for v in values:
                    lines.append(f"- `{v}`")
                lines.append("")
        return "\n".join(lines) if lines else "_No IOCs collected._"

    def _format_mitre_table(self, techniques: list[dict[str, str]]) -> str:
        """Format MITRE techniques as Markdown table"""
        if not techniques:
            return "| - | - | - |"

        lines = []
        for t in techniques:
            lines.append(f"| {t['tactic']} | {t['name']} | `{t['id']}` |")
        return "\n".join(lines)

    def _format_notes(self, notes: list[dict[str, str]]) -> str:
        """Format analysis notes"""
        if not notes:
            return "_No notes recorded._"

        lines = []
        for n in notes:
            ts = n["timestamp"][:19].replace("T", " ")  # ISO to readable
            category = n.get("category", "general")
            category_emoji = {
                "general": "📝",
                "finding": "🔍",
                "warning": "⚠️",
                "important": "❗",
                "behavior": "🎯",
            }.get(category, "📝")
            lines.append(f"- {category_emoji} **[{ts}]** {n['note']}")
        return "\n".join(lines)


# 싱글톤 인스턴스 (기본 경로)
_default_report_tools: ReportTools | None = None


def get_report_tools(
    template_dir: Path | None = None,
    output_dir: Path | None = None,
    default_timezone: str | None = None,
) -> ReportTools:
    """
    ReportTools 싱글톤 인스턴스 반환

    환경변수 지원:
    - REPORT_DEFAULT_TIMEZONE: 기본 타임존 (default: Asia/Seoul)
    - REPORT_SMTP_SERVER: SMTP 서버 주소
    - REPORT_SMTP_PORT: SMTP 포트 (default: 587)
    - REPORT_SMTP_USERNAME: 이메일 계정
    - REPORT_SMTP_PASSWORD: 이메일 비밀번호
    - REPORT_SMTP_USE_TLS: TLS 사용 여부 (default: true)
    - REPORT_SENDER_NAME: 발신자 이름 (default: Reversecore_MCP)
    - REPORT_QUICK_CONTACTS: 빠른 연락처 (format: name:email:role,...)
    - REPORT_DEFAULT_CLASSIFICATION: 기본 TLP 분류 (default: TLP:AMBER)
    - REPORT_DEFAULT_ANALYST: 기본 분석가 이름
    """
    global _default_report_tools

    if _default_report_tools is None:
        # 환경변수에서 설정 로드
        env_timezone = os.getenv("REPORT_DEFAULT_TIMEZONE", "Asia/Seoul")

        # 이메일 설정 로드
        email_config = EmailConfig.from_env()

        # ReportTools 인스턴스 생성
        _default_report_tools = ReportTools(
            template_dir=template_dir or Path("templates/reports"),
            output_dir=output_dir or Path("reports"),
            default_timezone=default_timezone or env_timezone,
            email_config=email_config,
        )

        # 환경변수에서 빠른 연락처 로드
        env_contacts = load_quick_contacts_from_env()
        _default_report_tools.quick_contacts.update(env_contacts)

        # 로그 출력
        logger.info("📋 ReportTools initialized:")
        logger.info(f"   - Timezone: {_default_report_tools.default_timezone}")
        logger.info(
            f"   - Email: {'✅ Configured' if email_config.is_configured else '❌ Not configured'}"
        )
        logger.info(f"   - Quick contacts: {len(_default_report_tools.quick_contacts)}")

    return _default_report_tools


def reset_report_tools() -> None:
    """ReportTools 싱글톤 인스턴스 리셋 (테스트용)"""
    global _default_report_tools
    _default_report_tools = None
