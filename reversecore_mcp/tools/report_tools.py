"""
Malware Analysis Report Tools for Reversecore_MCP

Features:
- OS-level timestamp (no AI hallucination)
- Session tracking (start/end time, duration)
- Timezone support (UTC, local, custom)
- IOC collection during analysis
- Template-based report generation
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import hashlib
import platform
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging

logger = logging.getLogger(__name__)


class TimezonePreset(Enum):
    """자주 사용되는 타임존 프리셋"""
    UTC = "UTC"
    KST = "Asia/Seoul"          # UTC+9
    JST = "Asia/Tokyo"          # UTC+9
    CST = "Asia/Shanghai"       # UTC+8
    EST = "America/New_York"    # UTC-5/-4
    PST = "America/Los_Angeles" # UTC-8/-7
    CET = "Europe/Paris"        # UTC+1/+2
    GMT = "Europe/London"       # UTC+0/+1


# 간단한 UTC 오프셋 매핑 (pytz 없이 동작)
TIMEZONE_OFFSETS: Dict[str, int] = {
    "UTC": 0,
    "Asia/Seoul": 9,
    "Asia/Tokyo": 9,
    "Asia/Shanghai": 8,
    "America/New_York": -5,
    "America/Los_Angeles": -8,
    "Europe/Paris": 1,
    "Europe/London": 0,
}

# 타임존 약어 매핑
TIMEZONE_ABBRS: Dict[str, str] = {
    "UTC": "UTC",
    "Asia/Seoul": "KST",
    "Asia/Tokyo": "JST",
    "Asia/Shanghai": "CST",
    "America/New_York": "EST",
    "America/Los_Angeles": "PST",
    "Europe/Paris": "CET",
    "Europe/London": "GMT",
}


@dataclass
class AnalysisSession:
    """분석 세션 정보를 추적하는 데이터 클래스"""
    session_id: str
    sample_path: Optional[str] = None
    sample_name: Optional[str] = None
    analyst: str = "Security Researcher"
    
    # 타임스탬프 (UTC 기준 저장)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    
    # 세션 상태
    status: str = "initialized"  # initialized, in_progress, completed, aborted
    
    # 분석 중 수집된 데이터
    findings: Dict[str, Any] = field(default_factory=dict)
    iocs: Dict[str, List[str]] = field(default_factory=lambda: {
        "hashes": [],
        "ips": [],
        "domains": [],
        "urls": [],
        "files": [],
        "registry": [],
        "mutexes": [],
        "emails": [],
    })
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    notes: List[Dict[str, str]] = field(default_factory=list)
    
    # 추가 메타데이터
    tags: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    malware_family: Optional[str] = None
    
    def start(self):
        """세션 시작"""
        self.started_at = datetime.now(timezone.utc)
        self.status = "in_progress"
    
    def end(self, status: str = "completed"):
        """세션 종료"""
        self.ended_at = datetime.now(timezone.utc)
        self.status = status
    
    def get_duration(self) -> Optional[timedelta]:
        """분석 소요 시간 계산"""
        if not self.started_at:
            return None
        end = self.ended_at or datetime.now(timezone.utc)
        return end - self.started_at
    
    def get_duration_str(self) -> str:
        """사람이 읽기 쉬운 소요 시간"""
        duration = self.get_duration()
        if duration is None:
            return "N/A"
        
        total_seconds = int(duration.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        parts = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        
        return " ".join(parts)
    
    def add_ioc(self, ioc_type: str, value: str) -> bool:
        """IOC 추가"""
        if ioc_type in self.iocs and value not in self.iocs[ioc_type]:
            self.iocs[ioc_type].append(value)
            return True
        return False
    
    def add_note(self, note: str, category: str = "general"):
        """분석 노트 추가"""
        timestamp = datetime.now(timezone.utc).isoformat()
        self.notes.append({
            "timestamp": timestamp,
            "note": note,
            "category": category
        })
    
    def add_mitre(self, technique_id: str, technique_name: str, tactic: str):
        """MITRE ATT&CK 기법 추가"""
        entry = {"id": technique_id, "name": technique_name, "tactic": tactic}
        if entry not in self.mitre_techniques:
            self.mitre_techniques.append(entry)
    
    def add_tag(self, tag: str):
        """태그 추가"""
        if tag not in self.tags:
            self.tags.append(tag)
    
    def to_dict(self) -> dict:
        """직렬화"""
        data = asdict(self)
        # datetime 객체 ISO 포맷으로 변환
        if self.started_at:
            data["started_at"] = self.started_at.isoformat()
        if self.ended_at:
            data["ended_at"] = self.ended_at.isoformat()
        data["duration"] = self.get_duration_str()
        return data


@dataclass
class EmailConfig:
    """이메일 설정"""
    smtp_server: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    default_recipients: List[str] = field(default_factory=list)


class ReportTools:
    """
    악성코드 분석 리포트 생성 도구
    
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
        email_config: Optional[EmailConfig] = None
    ):
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.default_timezone = default_timezone
        self.timezone_offset = TIMEZONE_OFFSETS.get(default_timezone, 0)
        
        # 활성 세션 관리
        self.sessions: Dict[str, AnalysisSession] = {}
        self.current_session_id: Optional[str] = None
        
        # 이메일 설정
        self.email_config = email_config or EmailConfig()
        
        # 빠른 연락처 목록
        self.quick_contacts: Dict[str, Dict[str, str]] = {}
    
    # =========================================================================
    # Timezone Management
    # =========================================================================
    
    def set_timezone(self, tz: str) -> dict:
        """
        기본 타임존을 설정합니다.
        
        Args:
            tz: 타임존 이름 (UTC, Asia/Seoul, America/New_York, etc.)
        """
        if tz not in TIMEZONE_OFFSETS:
            return {
                "success": False,
                "error": f"Unknown timezone: {tz}",
                "available": list(TIMEZONE_OFFSETS.keys())
            }
        
        self.default_timezone = tz
        self.timezone_offset = TIMEZONE_OFFSETS[tz]
        
        return {
            "success": True,
            "timezone": tz,
            "utc_offset": f"UTC{'+' if self.timezone_offset >= 0 else ''}{self.timezone_offset}",
            "abbreviation": TIMEZONE_ABBRS.get(tz, ""),
            "current_time": self._format_time(datetime.now(timezone.utc))
        }
    
    def get_timezone_info(self) -> dict:
        """현재 타임존 설정 정보 반환"""
        return {
            "current_timezone": self.default_timezone,
            "utc_offset": self.timezone_offset,
            "abbreviation": TIMEZONE_ABBRS.get(self.default_timezone, ""),
            "available_timezones": {
                name: {
                    "offset": f"UTC{'+' if offset >= 0 else ''}{offset}",
                    "abbreviation": TIMEZONE_ABBRS.get(name, "")
                }
                for name, offset in TIMEZONE_OFFSETS.items()
            }
        }
    
    def _get_local_time(self) -> datetime:
        """설정된 타임존의 현재 시간"""
        utc_now = datetime.now(timezone.utc)
        local_tz = timezone(timedelta(hours=self.timezone_offset))
        return utc_now.astimezone(local_tz)
    
    def _format_time(self, dt: datetime, include_tz: bool = True) -> str:
        """datetime을 설정된 타임존으로 포맷"""
        local_tz = timezone(timedelta(hours=self.timezone_offset))
        local_dt = dt.astimezone(local_tz)
        
        if include_tz:
            abbr = TIMEZONE_ABBRS.get(self.default_timezone, f"UTC{'+' if self.timezone_offset >= 0 else ''}{self.timezone_offset}")
            return f"{local_dt.strftime('%Y-%m-%d %H:%M:%S')} ({abbr})"
        return local_dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # =========================================================================
    # Timestamp Generation
    # =========================================================================
    
    def get_timestamp_data(self) -> dict:
        """
        OS 레벨에서 정확한 타임스탬프 데이터 생성
        AI가 날짜를 추측하지 않도록 서버에서 직접 제공
        """
        utc_now = datetime.now(timezone.utc)
        local_now = self._get_local_time()
        abbr = TIMEZONE_ABBRS.get(self.default_timezone, "")
        
        return {
            # Report ID 생성용
            "report_id": f"MAR-{local_now.strftime('%Y%m%d-%H%M%S')}",
            
            # 날짜 포맷들
            "date": local_now.strftime("%Y-%m-%d"),
            "date_kr": local_now.strftime("%Y년 %m월 %d일"),
            "date_us": local_now.strftime("%B %d, %Y"),
            
            # 시간 포맷들
            "time": local_now.strftime("%H:%M:%S"),
            "datetime": local_now.strftime("%Y-%m-%d %H:%M:%S"),
            "datetime_full": self._format_time(utc_now),
            "datetime_iso": local_now.isoformat(),
            
            # UTC 기준
            "datetime_utc": utc_now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "timestamp_unix": int(utc_now.timestamp()),
            
            # 개별 필드
            "year": local_now.strftime("%Y"),
            "month": local_now.strftime("%m"),
            "month_name": local_now.strftime("%B"),
            "month_name_kr": ["1월", "2월", "3월", "4월", "5월", "6월", 
                              "7월", "8월", "9월", "10월", "11월", "12월"][local_now.month - 1],
            "day": local_now.strftime("%d"),
            "weekday": local_now.strftime("%A"),
            "weekday_kr": ["월요일", "화요일", "수요일", "목요일", "금요일", "토요일", "일요일"][local_now.weekday()],
            
            # 타임존 정보
            "timezone": self.default_timezone,
            "timezone_abbr": abbr,
            "timezone_offset": f"UTC{'+' if self.timezone_offset >= 0 else ''}{self.timezone_offset}",
            
            # 시스템 정보
            "hostname": platform.node(),
            "platform": platform.system(),
        }
    
    async def get_current_time(self) -> dict:
        """현재 시스템 시간 정보를 반환 (MCP Tool용)"""
        return self.get_timestamp_data()
    
    # =========================================================================
    # Session Management
    # =========================================================================
    
    async def start_session(
        self,
        sample_path: Optional[str] = None,
        analyst: str = "Security Researcher",
        severity: str = "medium",
        malware_family: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> dict:
        """
        새 분석 세션을 시작합니다.
        
        Args:
            sample_path: 분석할 샘플 경로
            analyst: 분석가 이름
            severity: 심각도 (low, medium, high, critical)
            malware_family: 악성코드 패밀리 이름
            tags: 태그 목록
            
        Returns:
            세션 정보
        """
        session_id = f"SES-{uuid.uuid4().hex[:8].upper()}"
        
        session = AnalysisSession(
            session_id=session_id,
            sample_path=sample_path,
            sample_name=Path(sample_path).name if sample_path else None,
            analyst=analyst,
            severity=severity,
            malware_family=malware_family
        )
        
        if tags:
            for tag in tags:
                session.add_tag(tag)
        
        session.start()
        
        # 샘플 해시 자동 계산
        if sample_path:
            sample_info = await self._extract_sample_info(sample_path)
            session.findings["sample_info"] = sample_info
            
            # 해시를 IOC에 자동 추가
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
            "message": f"Analysis session started. Use session_id '{session_id}' to track."
        }
    
    async def end_session(
        self,
        session_id: Optional[str] = None,
        status: str = "completed",
        summary: Optional[str] = None
    ) -> dict:
        """
        분석 세션을 종료합니다.
        
        Args:
            session_id: 세션 ID (없으면 현재 세션)
            status: 종료 상태 (completed, aborted)
            summary: 분석 요약
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
            "tags": session.tags
        }
        
        if sid == self.current_session_id:
            self.current_session_id = None
        
        return result
    
    async def get_session_info(self, session_id: Optional[str] = None) -> dict:
        """세션 상태 조회"""
        sid = session_id or self.current_session_id
        
        if not sid or sid not in self.sessions:
            return {
                "success": False,
                "error": "No session found",
                "active_sessions": list(self.sessions.keys())
            }
        
        session = self.sessions[sid]
        info = session.to_dict()
        
        # 포맷된 시간 추가
        if session.started_at:
            info["started_at_formatted"] = self._format_time(session.started_at)
        if session.ended_at:
            info["ended_at_formatted"] = self._format_time(session.ended_at)
        
        info["is_current"] = (sid == self.current_session_id)
        
        return {"success": True, "session": info}
    
    async def add_session_ioc(
        self,
        ioc_type: str,
        value: str,
        session_id: Optional[str] = None
    ) -> dict:
        """세션에 IOC 추가"""
        sid = session_id or self.current_session_id
        
        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}
        
        session = self.sessions[sid]
        valid_types = list(session.iocs.keys())
        
        if ioc_type not in valid_types:
            return {
                "success": False,
                "error": f"Invalid IOC type: {ioc_type}",
                "valid_types": valid_types
            }
        
        added = session.add_ioc(ioc_type, value)
        
        return {
            "success": True,
            "added": added,
            "ioc": {"type": ioc_type, "value": value},
            "message": "IOC added" if added else "IOC already exists",
            "total_iocs": sum(len(v) for v in session.iocs.values())
        }
    
    async def add_session_note(
        self,
        note: str,
        category: str = "general",
        session_id: Optional[str] = None
    ) -> dict:
        """세션에 분석 노트 추가"""
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
            "total_notes": len(session.notes)
        }
    
    async def add_session_mitre(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        session_id: Optional[str] = None
    ) -> dict:
        """세션에 MITRE ATT&CK 기법 추가"""
        sid = session_id or self.current_session_id
        
        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}
        
        session = self.sessions[sid]
        session.add_mitre(technique_id, technique_name, tactic)
        
        return {
            "success": True,
            "added": f"{technique_id} - {technique_name}",
            "tactic": tactic,
            "total_techniques": len(session.mitre_techniques)
        }
    
    async def add_session_tag(
        self,
        tag: str,
        session_id: Optional[str] = None
    ) -> dict:
        """세션에 태그 추가"""
        sid = session_id or self.current_session_id
        
        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}
        
        session = self.sessions[sid]
        session.add_tag(tag)
        
        return {
            "success": True,
            "tag_added": tag,
            "all_tags": session.tags
        }
    
    async def set_session_severity(
        self,
        severity: str,
        session_id: Optional[str] = None
    ) -> dict:
        """세션 심각도 설정"""
        sid = session_id or self.current_session_id
        
        if not sid or sid not in self.sessions:
            return {"success": False, "error": "No active session"}
        
        valid_severities = ["low", "medium", "high", "critical"]
        if severity.lower() not in valid_severities:
            return {
                "success": False,
                "error": f"Invalid severity: {severity}",
                "valid_severities": valid_severities
            }
        
        session = self.sessions[sid]
        session.severity = severity.lower()
        
        return {
            "success": True,
            "severity": session.severity,
            "session_id": sid
        }
    
    async def list_sessions(self) -> dict:
        """모든 세션 목록 조회"""
        sessions_list = []
        
        for sid, session in self.sessions.items():
            sessions_list.append({
                "session_id": sid,
                "sample": session.sample_name,
                "status": session.status,
                "severity": session.severity,
                "malware_family": session.malware_family,
                "started_at": self._format_time(session.started_at) if session.started_at else None,
                "duration": session.get_duration_str(),
                "iocs_count": sum(len(v) for v in session.iocs.values()),
                "is_current": sid == self.current_session_id
            })
        
        return {
            "total": len(sessions_list),
            "current_session": self.current_session_id,
            "sessions": sessions_list
        }
    
    # =========================================================================
    # Report Generation
    # =========================================================================
    
    async def create_report(
        self,
        template_type: str = "full_analysis",
        session_id: Optional[str] = None,
        sample_path: Optional[str] = None,
        analyst: str = "Security Researcher",
        classification: str = "TLP:AMBER",
        custom_fields: Optional[dict] = None,
        output_format: str = "markdown"
    ) -> dict:
        """
        분석 리포트를 생성합니다.
        세션이 있으면 세션 데이터를 자동으로 포함합니다.
        """
        # 타임스탬프 생성 (서버 시간 기준)
        ts = self.get_timestamp_data()
        
        # 템플릿 로드
        template_path = self.template_dir / f"{template_type}.md"
        if not template_path.exists():
            available = [f.stem for f in self.template_dir.glob("*.md")]
            return {
                "success": False,
                "error": f"Template not found: {template_type}",
                "available_templates": available
            }
        
        template = template_path.read_text(encoding='utf-8')
        
        # 기본 필드
        fields = {
            "REPORT_ID": ts["report_id"],
            "DATE": ts["date"],
            "DATE_KR": ts["date_kr"],
            "DATE_US": ts["date_us"],
            "DATETIME": ts["datetime"],
            "DATETIME_FULL": ts["datetime_full"],
            "DATETIME_UTC": ts["datetime_utc"],
            "TIMESTAMP": str(ts["timestamp_unix"]),
            "YEAR": ts["year"],
            "MONTH": ts["month"],
            "MONTH_NAME": ts["month_name"],
            "MONTH_NAME_KR": ts["month_name_kr"],
            "DAY": ts["day"],
            "WEEKDAY": ts["weekday"],
            "WEEKDAY_KR": ts["weekday_kr"],
            "TIMEZONE": ts["timezone"],
            "TIMEZONE_ABBR": ts["timezone_abbr"],
            "ANALYST": analyst,
            "CLASSIFICATION": classification,
            "GENERATED_BY": "Reversecore_MCP",
            "HOSTNAME": ts["hostname"],
        }
        
        # 세션 데이터 통합
        sid = session_id or self.current_session_id
        session = self.sessions.get(sid) if sid else None
        
        if session:
            fields.update({
                "SESSION_ID": session.session_id,
                "SESSION_STATUS": session.status,
                "SEVERITY": session.severity.upper(),
                "SEVERITY_EMOJI": self._get_severity_emoji(session.severity),
                "MALWARE_FAMILY": session.malware_family or "Unknown",
                "ANALYSIS_START": self._format_time(session.started_at) if session.started_at else "N/A",
                "ANALYSIS_END": self._format_time(session.ended_at) if session.ended_at else "In Progress",
                "ANALYSIS_DURATION": session.get_duration_str(),
                "TAGS": ", ".join(session.tags) if session.tags else "None",
            })
            
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
        output_path.write_text(report, encoding='utf-8')
        
        return {
            "success": True,
            "report_id": ts["report_id"],
            "path": str(output_path),
            "template": template_type,
            "session_id": sid,
            "generated_at": ts["datetime_full"],
            "timezone": ts["timezone"],
            "fields_filled": len(fields),
            "report_content": report  # 미리보기용
        }
    
    async def list_templates(self) -> dict:
        """사용 가능한 템플릿 목록"""
        templates = []
        
        for f in self.template_dir.glob("*.md"):
            content = f.read_text(encoding='utf-8')
            # 첫 줄에서 설명 추출 (<!-- description --> 형식)
            desc = ""
            if content.startswith("<!--"):
                end = content.find("-->")
                if end > 0:
                    desc = content[4:end].strip()
            
            templates.append({
                "name": f.stem,
                "description": desc,
                "path": str(f)
            })
        
        return {
            "total": len(templates),
            "templates": templates
        }
    
    async def get_report(self, report_id: str) -> dict:
        """생성된 리포트 조회"""
        report_path = self.output_dir / f"{report_id}.md"
        
        if not report_path.exists():
            # 리포트 목록 반환
            reports = [f.stem for f in self.output_dir.glob("*.md")]
            return {
                "success": False,
                "error": f"Report not found: {report_id}",
                "available_reports": reports
            }
        
        content = report_path.read_text(encoding='utf-8')
        
        return {
            "success": True,
            "report_id": report_id,
            "path": str(report_path),
            "content": content,
            "size": len(content)
        }
    
    async def list_reports(self) -> dict:
        """생성된 리포트 목록"""
        reports = []
        
        for f in self.output_dir.glob("*.md"):
            stat = f.stat()
            reports.append({
                "report_id": f.stem,
                "path": str(f),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        
        # 최신순 정렬
        reports.sort(key=lambda x: x["created"], reverse=True)
        
        return {
            "total": len(reports),
            "reports": reports
        }
    
    # =========================================================================
    # Email / Delivery
    # =========================================================================
    
    async def configure_email(
        self,
        smtp_server: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        use_tls: bool = True
    ) -> dict:
        """이메일 설정 구성"""
        self.email_config = EmailConfig(
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            username=username,
            password=password,
            use_tls=use_tls
        )
        
        return {
            "success": True,
            "smtp_server": smtp_server,
            "smtp_port": smtp_port,
            "use_tls": use_tls,
            "message": "Email configuration updated"
        }
    
    async def add_quick_contact(
        self,
        name: str,
        email: str,
        role: str = "Security Analyst"
    ) -> dict:
        """빠른 연락처 추가"""
        self.quick_contacts[name] = {
            "email": email,
            "role": role
        }
        
        return {
            "success": True,
            "contact": {"name": name, "email": email, "role": role},
            "total_contacts": len(self.quick_contacts)
        }
    
    async def list_quick_contacts(self) -> dict:
        """빠른 연락처 목록"""
        return {
            "total": len(self.quick_contacts),
            "contacts": [
                {"name": name, **info}
                for name, info in self.quick_contacts.items()
            ]
        }
    
    async def send_report(
        self,
        report_id: str,
        recipients: List[str],
        subject: Optional[str] = None,
        message: Optional[str] = None,
        include_attachment: bool = True
    ) -> dict:
        """
        리포트를 이메일로 전송합니다.
        
        Args:
            report_id: 전송할 리포트 ID
            recipients: 수신자 이메일 목록
            subject: 이메일 제목 (기본값: 자동 생성)
            message: 이메일 본문
            include_attachment: 리포트 파일 첨부 여부
        """
        # 리포트 확인
        report_path = self.output_dir / f"{report_id}.md"
        if not report_path.exists():
            return {
                "success": False,
                "error": f"Report not found: {report_id}"
            }
        
        # 이메일 설정 확인
        if not self.email_config.smtp_server:
            return {
                "success": False,
                "error": "Email not configured. Use configure_email first."
            }
        
        # 빠른 연락처 이름을 이메일로 변환
        resolved_recipients = []
        for r in recipients:
            if r in self.quick_contacts:
                resolved_recipients.append(self.quick_contacts[r]["email"])
            else:
                resolved_recipients.append(r)
        
        report_content = report_path.read_text(encoding='utf-8')
        
        # 기본 제목
        if not subject:
            subject = f"[Malware Analysis Report] {report_id}"
        
        # 기본 메시지
        if not message:
            ts = self.get_timestamp_data()
            message = f"""안녕하세요,

새로운 악성코드 분석 리포트가 생성되었습니다.

리포트 ID: {report_id}
생성 시간: {ts['datetime_full']}

상세 내용은 첨부 파일 또는 아래 내용을 확인해주세요.

---

{report_content[:2000]}{'...(truncated)' if len(report_content) > 2000 else ''}

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
                attachment.set_payload(report_content.encode('utf-8'))
                encoders.encode_base64(attachment)
                attachment.add_header(
                    "Content-Disposition",
                    f"attachment; filename={report_id}.md"
                )
                msg.attach(attachment)
            
            # 전송
            with smtplib.SMTP(
                self.email_config.smtp_server,
                self.email_config.smtp_port
            ) as server:
                if self.email_config.use_tls:
                    server.starttls()
                if self.email_config.username and self.email_config.password:
                    server.login(
                        self.email_config.username,
                        self.email_config.password
                    )
                server.sendmail(
                    self.email_config.username,
                    resolved_recipients,
                    msg.as_string()
                )
            
            return {
                "success": True,
                "report_id": report_id,
                "recipients": resolved_recipients,
                "subject": subject,
                "attachment_included": include_attachment,
                "sent_at": self._format_time(datetime.now(timezone.utc))
            }
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return {
                "success": False,
                "error": str(e),
                "report_id": report_id,
                "recipients": resolved_recipients
            }
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    async def _extract_sample_info(self, sample_path: str) -> dict:
        """샘플 파일에서 메타데이터 추출"""
        path = Path(sample_path)
        
        if not path.exists():
            return {
                "filename": path.name,
                "error": "File not found"
            }
        
        data = path.read_bytes()
        stat = path.stat()
        
        info = {
            "filename": path.name,
            "filepath": str(path.absolute()),
            "filesize": len(data),
            "filesize_hr": self._human_readable_size(len(data)),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "file_created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "file_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }
        
        # 파일 타입 식별
        info["file_type"] = self._identify_file_type(data)
        
        return info
    
    @staticmethod
    def _identify_file_type(data: bytes) -> str:
        """파일 타입 식별"""
        if len(data) < 4:
            return "Unknown (too small)"
        
        magic_bytes = {
            b'MZ': "PE Executable (Windows)",
            b'\x7fELF': "ELF Executable (Linux)",
            b'%PDF': "PDF Document",
            b'PK': "ZIP Archive / Office Document",
            b'\xd0\xcf\x11\xe0': "OLE Compound File (Office)",
            b'Rar!': "RAR Archive",
            b'\x1f\x8b': "GZIP Archive",
            b'BZ': "BZIP2 Archive",
            b'\x89PNG': "PNG Image",
            b'\xff\xd8\xff': "JPEG Image",
            b'GIF8': "GIF Image",
            b'<!DO': "HTML Document",
            b'<?xm': "XML Document",
            b'{\n  ': "JSON Document",
            b'#!': "Script (Shell/Python)",
        }
        
        for magic, file_type in magic_bytes.items():
            if data.startswith(magic):
                return file_type
        
        # ASCII 텍스트 체크
        try:
            data[:1000].decode('utf-8')
            return "Text/Script File"
        except UnicodeDecodeError:
            pass
        
        return "Unknown Binary"
    
    @staticmethod
    def _human_readable_size(size: int) -> str:
        """바이트를 읽기 쉬운 형식으로"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:,.1f} {unit}"
            size /= 1024
        return f"{size:,.1f} TB"
    
    @staticmethod
    def _get_severity_emoji(severity: str) -> str:
        """심각도 이모지"""
        emojis = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴"
        }
        return emojis.get(severity.lower(), "⚪")
    
    def _format_iocs_yaml(self, iocs: Dict[str, List[str]]) -> str:
        """IOC를 YAML 형식으로 포맷"""
        lines = []
        for ioc_type, values in iocs.items():
            if values:
                lines.append(f"{ioc_type}:")
                for v in values:
                    lines.append(f"  - {v}")
        return "\n".join(lines) if lines else "# No IOCs collected"
    
    def _format_iocs_markdown(self, iocs: Dict[str, List[str]]) -> str:
        """IOC를 마크다운 형식으로 포맷"""
        lines = []
        for ioc_type, values in iocs.items():
            if values:
                lines.append(f"### {ioc_type.title()}")
                for v in values:
                    lines.append(f"- `{v}`")
                lines.append("")
        return "\n".join(lines) if lines else "_No IOCs collected._"
    
    def _format_mitre_table(self, techniques: List[Dict[str, str]]) -> str:
        """MITRE 기법을 마크다운 테이블로"""
        if not techniques:
            return "| - | - | - |"
        
        lines = []
        for t in techniques:
            lines.append(f"| {t['tactic']} | {t['name']} | `{t['id']}` |")
        return "\n".join(lines)
    
    def _format_notes(self, notes: List[Dict[str, str]]) -> str:
        """분석 노트 포맷"""
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
                "behavior": "🎯"
            }.get(category, "📝")
            lines.append(f"- {category_emoji} **[{ts}]** {n['note']}")
        return "\n".join(lines)


# 싱글톤 인스턴스 (기본 경로)
_default_report_tools: Optional[ReportTools] = None


def get_report_tools(
    template_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    default_timezone: str = "Asia/Seoul"
) -> ReportTools:
    """ReportTools 싱글톤 인스턴스 반환"""
    global _default_report_tools
    
    if _default_report_tools is None:
        _default_report_tools = ReportTools(
            template_dir=template_dir or Path("templates/reports"),
            output_dir=output_dir or Path("reports"),
            default_timezone=default_timezone
        )
    
    return _default_report_tools
