# Report Tools API Reference

::: reversecore_mcp.tools.report_tools
    options:
      show_source: true
      show_root_heading: true

## Overview

Report Tools provide professional malware analysis report generation with session tracking, IOC management, MITRE ATT&CK mapping, and multiple output formats.

## Session Management

### start_analysis_session

Start a new analysis session with automatic timestamp tracking.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `sample_path` | str | Yes | Path to the sample being analyzed |
| `analyst_name` | str | No | Name of the analyst |
| `session_id` | str | No | Custom session ID (auto-generated if not provided) |

**Returns:**
```json
{
  "status": "success",
  "session_id": "session_20251205_143052",
  "start_time": "2025-12-05T14:30:52Z",
  "sample_path": "/app/workspace/malware.exe"
}
```

### end_analysis_session

End an analysis session and calculate duration.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `session_id` | str | No | Session ID (uses current if not provided) |
| `summary` | str | No | Brief analysis summary |

**Returns:**
```json
{
  "status": "success",
  "session_id": "session_20251205_143052",
  "start_time": "2025-12-05T14:30:52Z",
  "end_time": "2025-12-05T15:45:30Z",
  "duration": "1h 14m 38s",
  "summary": "Ransomware variant with C2 communication"
}
```

### get_session_info

Get current session information.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `session_id` | str | No | Session ID (uses current if not provided) |

## Timestamp Tools

### get_system_time

Get accurate server timestamp in multiple formats.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `timezone` | str | No | Timezone (default: "UTC") |

**Supported Timezones:** UTC, KST, EST, PST, CET, JST, GMT

**Returns:**
```json
{
  "timezone": "UTC",
  "iso8601": "2025-12-05T14:30:52Z",
  "date_long": "December 05, 2025",
  "date_short": "05 Dec 2025",
  "date_eu": "05/12/2025",
  "date_us": "12/05/2025",
  "time_24h": "14:30:52",
  "time_12h": "02:30:52 PM",
  "weekday": "Friday",
  "weekday_short": "Fri",
  "month_name": "December",
  "month_name_short": "Dec",
  "unix_timestamp": 1733408452
}
```

## IOC Management

### add_session_ioc

Add an Indicator of Compromise to the session.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `ioc_type` | str | Yes | Type: "ips", "domains", "urls", "hashes", "emails", "files" |
| `value` | str | Yes | IOC value |
| `context` | str | No | Additional context |
| `session_id` | str | No | Session ID |

**Example:**
```python
add_session_ioc("ips", "192.168.1.100", context="C2 server")
add_session_ioc("urls", "http://evil.com/gate.php", context="Payload download")
add_session_ioc("hashes", "abc123...", context="Dropped file MD5")
```

### get_session_iocs

Get all IOCs from a session.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `session_id` | str | No | Session ID |

**Returns:**
```json
{
  "ips": [
    {"value": "192.168.1.100", "context": "C2 server", "timestamp": "..."}
  ],
  "urls": [
    {"value": "http://evil.com/gate.php", "context": "Payload download", "timestamp": "..."}
  ],
  "hashes": [...],
  "domains": [...],
  "files": [...]
}
```

## MITRE ATT&CK Mapping

### add_session_mitre

Add a MITRE ATT&CK technique to the session.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `technique_id` | str | Yes | Technique ID (e.g., "T1059.001") |
| `technique_name` | str | Yes | Technique name |
| `tactic` | str | Yes | Tactic category |
| `evidence` | str | No | Supporting evidence |
| `session_id` | str | No | Session ID |

**Example:**
```python
add_session_mitre(
    technique_id="T1059.001",
    technique_name="PowerShell",
    tactic="Execution",
    evidence="Found encoded PowerShell command in memory"
)
```

### get_session_mitre

Get all MITRE mappings from a session.

## Report Generation

### create_analysis_report

Generate a formatted analysis report.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `template_type` | str | No | Template: "full_analysis", "quick_triage", "ioc_summary", "executive_brief" |
| `session_id` | str | No | Session ID |
| `output_format` | str | No | Format: "markdown", "html", "json" |
| `include_iocs` | bool | No | Include IOC section (default: True) |
| `include_mitre` | bool | No | Include MITRE section (default: True) |

**Template Types:**

| Template | Description | Use Case |
|----------|-------------|----------|
| `full_analysis` | Comprehensive report with all sections | Complete malware analysis |
| `quick_triage` | Brief summary with key findings | Initial assessment |
| `ioc_summary` | IOC-focused report | Threat intelligence sharing |
| `executive_brief` | High-level summary for management | Stakeholder communication |

### list_report_templates

List available report templates.

### send_report

Send report via email.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `report_content` | str | Yes | Report content |
| `recipients` | list | Yes | Email addresses |
| `subject` | str | No | Email subject |
| `smtp_config` | dict | No | SMTP configuration |

**SMTP Configuration:**
```python
smtp_config = {
    "host": "smtp.company.com",
    "port": 587,
    "username": "analyst@company.com",
    "password": "...",  # Or use environment variable
    "use_tls": True
}
```

## Complete Workflow Example

```python
# 1. Start session
start_analysis_session(
    sample_path="/app/workspace/malware.exe",
    analyst_name="Security Team"
)

# 2. Perform analysis (using other tools)
# ... run_file, run_strings, ghost_trace, etc. ...

# 3. Add discovered IOCs
add_session_ioc("ips", "192.168.1.100", context="C2 server")
add_session_ioc("domains", "malware-c2.com", context="DNS resolution")
add_session_ioc("hashes", "abc123...", context="Sample MD5")

# 4. Add MITRE mappings
add_session_mitre("T1059.001", "PowerShell", "Execution")
add_session_mitre("T1071.001", "Web Protocols", "Command and Control")
add_session_mitre("T1486", "Data Encrypted for Impact", "Impact")

# 5. End session
end_analysis_session(summary="Ransomware variant with C2 communication")

# 6. Generate report
report = create_analysis_report(
    template_type="full_analysis",
    output_format="markdown"
)

# 7. Send to team
send_report(
    report_content=report,
    recipients=["soc@company.com", "ir@company.com"],
    subject="Malware Analysis Report - Ransomware Sample"
)
```

## Environment Variables

Configure email settings via environment:

```bash
REPORT_SMTP_HOST=smtp.company.com
REPORT_SMTP_PORT=587
REPORT_SMTP_USERNAME=analyst@company.com
REPORT_SMTP_PASSWORD=secure_password
REPORT_SMTP_USE_TLS=true
REPORT_DEFAULT_RECIPIENTS=soc@company.com,ir@company.com
```

## Related Tools

- [Trinity Defense](trinity-defense.md) - Automated analysis
- [CLI Tools](cli-tools.md) - Manual analysis
- [Ghost Trace](ghost-trace.md) - Hidden behavior detection
