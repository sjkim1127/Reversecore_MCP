"""Forensic artifact correlation, enrichment, and reporting pipeline.

Collects artifacts from memory, disk, and network forensics tools and
automatically correlates them against existing IoC databases and YARA rules.
Generates comprehensive forensics reports in the standard MCP report format.
"""

import datetime
import math
import re
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.malware.ioc_tools import extract_iocs

logger = get_logger(__name__)

# Artifact type identifiers
ARTIFACT_TYPES = {
    "process": "Running process from memory analysis",
    "injection": "Suspected code injection site",
    "network_conn": "Network connection or C2 indicator",
    "dns_query": "DNS query / domain lookup",
    "deleted_file": "Deleted or unallocated file",
    "extracted_file": "File extracted from disk image",
    "string": "Suspicious string extracted from memory",
    "hash": "File hash (MD5/SHA1/SHA256)",
    "ip": "IP address indicator",
    "url": "URL or domain indicator",
    "registry": "Registry key",
    "beacon": "C2 beaconing pattern",
    "dga_domain": "Possible DGA domain",
}
_EVENT_TIMESTAMP_FIELDS = ("timestamp", "mtime", "ctime", "atime", "crtime", "time")
_YARA_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _escape_yara_string(value: str) -> str:
    """Encode text as a safe YARA text-string literal body.

    YARA string literals represent bytes, so non-ASCII text is encoded as UTF-8
    and emitted with byte escapes. Quotes, backslashes, and control characters
    are escaped to keep artifact data inside the generated literal.
    """
    escaped: list[str] = []
    for byte in value.encode("utf-8"):
        if byte == ord('"'):
            escaped.append(r"\"")
        elif byte == ord("\\"):
            escaped.append(r"\\")
        elif byte == ord("\n"):
            escaped.append(r"\n")
        elif byte == ord("\r"):
            escaped.append(r"\r")
        elif byte == ord("\t"):
            escaped.append(r"\t")
        elif 32 <= byte < 127:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\x{byte:02x}")
    return "".join(escaped)


def _parse_timestamp(value: Any) -> datetime.datetime | None:
    """Parse a forensic timestamp and normalize it to UTC.

    Naive date-times are treated as UTC because their source timezone is unknown.
    Numeric values and numeric strings are Unix timestamps in seconds; values in
    the millisecond range are converted before parsing.
    """
    if isinstance(value, bool) or value is None:
        return None

    if isinstance(value, datetime.datetime):
        parsed = value
    elif isinstance(value, datetime.date):
        parsed = datetime.datetime.combine(value, datetime.time.min)
    elif isinstance(value, (int, float)):
        try:
            timestamp_seconds = float(value)
        except OverflowError:
            return None
        if not math.isfinite(timestamp_seconds):
            return None
        if abs(timestamp_seconds) >= 100_000_000_000:
            timestamp_seconds /= 1000
        try:
            return datetime.datetime.fromtimestamp(timestamp_seconds, datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            timestamp_seconds = float(text)
        except ValueError:
            normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
            try:
                parsed = datetime.datetime.fromisoformat(normalized)
            except ValueError:
                return None
        else:
            if not math.isfinite(timestamp_seconds):
                return None
            if abs(timestamp_seconds) >= 100_000_000_000:
                timestamp_seconds /= 1000
            try:
                return datetime.datetime.fromtimestamp(timestamp_seconds, datetime.timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
    else:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def _format_timestamp(timestamp: datetime.datetime) -> str:
    """Format a normalized timestamp as an ISO 8601 UTC value."""
    timespec = "microseconds" if timestamp.microsecond else "seconds"
    return timestamp.isoformat(timespec=timespec).replace("+00:00", "Z")


def _get_event_timestamp(
    artifact: dict[str, Any],
) -> tuple[datetime.datetime | None, str | None]:
    """Find an artifact's source timestamp, falling back to collection time."""
    metadata = artifact.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    for field in _EVENT_TIMESTAMP_FIELDS:
        for container, prefix in ((artifact, ""), (metadata, "metadata.")):
            timestamp = _parse_timestamp(container.get(field))
            if timestamp is not None:
                return timestamp, f"{prefix}{field}"

    for container, prefix in ((artifact, ""), (metadata, "metadata.")):
        timestamp = _parse_timestamp(container.get("collected_at"))
        if timestamp is not None:
            return timestamp, f"{prefix}collected_at"
    return None, None


def _normalize_artifact(artifact_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Normalize an artifact to a standard schema for correlation.

    Args:
        artifact_type: Type identifier from ARTIFACT_TYPES keys.
        data: Raw artifact data dictionary.

    Returns:
        Normalized artifact with standard 'value', 'source', and 'metadata' fields.
    """
    return {
        "type": artifact_type,
        "value": data.get("value") or data.get("name") or str(data),
        "source": data.get("source", "unknown"),
        "metadata": {k: v for k, v in data.items() if k not in ("value", "name", "source")},
        "collected_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }


@log_execution(tool_name="artifact_collect")
@track_metrics("artifact_collect")
@handle_tool_errors
async def artifact_collect(
    artifacts: list[dict[str, Any]],
    artifact_type: str = "string",
    source: str = "manual",
) -> ToolResult:
    """Collect and normalize forensic artifacts from analysis results.

    Use this tool to register artifacts discovered during memory, disk, or network
    analysis. Artifacts are normalized and stored for subsequent correlation with
    ``artifact_correlate_ioc`` and YARA rule generation via ``artifact_generate_yara``.

    Args:
        artifacts: List of artifact dictionaries. Each should have at least a 'value'
            or 'name' key. Additional fields are stored as metadata.
        artifact_type: Type of artifact (see ARTIFACT_TYPES for valid values).
        source: Human-readable source label (e.g., 'memory_malfind', 'pcap_c2_detect').

    Returns:
        ToolResult with normalized artifacts and collection summary.

    Example:
        >>> result = await artifact_collect(
        ...     artifacts=[{"value": "192.168.1.100", "port": 4444}],
        ...     artifact_type="ip",
        ...     source="pcap_extract_c2",
        ... )
    """
    if not artifacts:
        return failure(
            "EMPTY_INPUT",
            "No artifacts provided",
            hint="Pass a list of dicts with at least a 'value' or 'name' key.",
        )

    if artifact_type not in ARTIFACT_TYPES:
        return failure(
            "INVALID_TYPE",
            f"Unknown artifact type: '{artifact_type}'",
            hint=f"Valid types: {', '.join(ARTIFACT_TYPES.keys())}",
        )

    normalized = []
    for raw_item in artifacts:
        raw: Any = raw_item
        if not isinstance(raw, dict):
            logger.warning("Skipping non-dict artifact: %s", raw)
            continue
        raw["source"] = source
        normalized.append(_normalize_artifact(artifact_type, raw))

    return success(
        {
            "artifacts": normalized,
            "artifact_count": len(normalized),
            "artifact_type": artifact_type,
            "source": source,
            "valid_types": ARTIFACT_TYPES,
        }
    )


@log_execution(tool_name="artifact_correlate_ioc")
@track_metrics("artifact_correlate_ioc")
@handle_tool_errors
async def artifact_correlate_ioc(
    artifacts: list[dict[str, Any]],
    check_ips: bool = True,
    check_domains: bool = True,
    check_hashes: bool = True,
) -> ToolResult:
    """Correlate collected forensic artifacts against IoC patterns.

    Runs IoC extraction patterns (IP, URL, hash, CVE, registry) against all
    artifact values to automatically enrich them with threat intelligence signals.
    Uses the existing ``extract_iocs`` infrastructure from the malware module.

    Args:
        artifacts: List of normalized artifacts (from ``artifact_collect`` output).
        check_ips: Extract and flag suspicious IP addresses.
        check_domains: Extract and flag suspicious domains.
        check_hashes: Extract and flag file hashes (MD5/SHA1/SHA256).

    Returns:
        ToolResult with enriched artifacts, matched IoC indicators, and risk summary.

    Example:
        >>> result = await artifact_correlate_ioc(artifacts)
        >>> print(result.data["ioc_matches"])
    """
    if not artifacts:
        return failure("EMPTY_INPUT", "No artifacts to correlate")

    # Collect all artifact values into one text blob for IoC extraction
    combined_text = "\n".join(
        str(a.get("value", "")) + " " + str(a.get("metadata", "")) for a in artifacts
    )

    ioc_result = extract_iocs(
        text=combined_text,
        extract_ips=check_ips,
        extract_urls=check_domains,
        extract_hashes=check_hashes,
        extract_emails=False,
        extract_bitcoin=False,
        extract_others=True,
        limit=500,
    )

    if ioc_result.status == "error":
        return failure("IOC_EXTRACTION_FAILED", str(ioc_result))

    ioc_data = ioc_result.data if isinstance(ioc_result.data, dict) else {}

    # Enrich each artifact
    all_ioc_ips: set[str] = set(ioc_data.get("ips", []))
    all_ioc_urls: set[str] = set(ioc_data.get("urls", []))
    all_ioc_hashes: set[str] = set(
        ioc_data.get("md5_hashes", [])
        + ioc_data.get("sha1_hashes", [])
        + ioc_data.get("sha256_hashes", [])
    )

    enriched = []
    for artifact in artifacts:
        val = str(artifact.get("value", ""))
        ioc_tags: list[str] = []

        if check_ips and val in all_ioc_ips:
            ioc_tags.append("IP_IOC")
        if check_domains and any(val in url for url in all_ioc_urls):
            ioc_tags.append("URL_IOC")
        if check_hashes and val.lower() in {h.lower() for h in all_ioc_hashes}:
            ioc_tags.append("HASH_IOC")

        enriched.append({**artifact, "ioc_tags": ioc_tags, "flagged": bool(ioc_tags)})

    flagged = [a for a in enriched if a["flagged"]]
    total_iocs = len(all_ioc_ips) + len(all_ioc_urls) + len(all_ioc_hashes)

    return success(
        {
            "enriched_artifacts": enriched,
            "total_artifacts": len(enriched),
            "flagged_artifacts": flagged,
            "flagged_count": len(flagged),
            "extracted_iocs": {
                "ips": sorted(all_ioc_ips)[:100],
                "urls": sorted(all_ioc_urls)[:100],
                "hashes": sorted(all_ioc_hashes)[:50],
            },
            "total_ioc_count": total_iocs,
            "risk_level": ("CRITICAL" if len(flagged) > 10 else "HIGH" if flagged else "LOW"),
        }
    )


@log_execution(tool_name="artifact_generate_yara")
@track_metrics("artifact_generate_yara")
@handle_tool_errors
async def artifact_generate_yara(
    artifacts: list[dict[str, Any]],
    rule_name: str = "forensics_auto",
    output_path: str | None = None,
) -> ToolResult:
    """Auto-generate YARA rules from collected forensic artifacts.

    Integrates with the adaptive vaccine pipeline to create detection signatures
    from suspicious strings, process names, network indicators, and injection
    patterns found during forensics analysis.

    Args:
        artifacts: List of artifacts (from ``artifact_collect`` or ``artifact_correlate_ioc``).
        rule_name: Base name for the generated YARA rule (default: 'forensics_auto').
        output_path: Optional path to save the generated .yar rule file.
            If None, returns rule content only.

    Returns:
        ToolResult with generated YARA rule content, string patterns, and metadata.

    Example:
        >>> result = await artifact_generate_yara(artifacts, rule_name="malware_campaign_X")
        >>> print(result.data["yara_rule"])
    """
    if not artifacts:
        return failure("EMPTY_INPUT", "No artifacts provided for YARA rule generation")
    if not isinstance(rule_name, str) or not _YARA_IDENTIFIER_PATTERN.fullmatch(rule_name):
        return failure(
            "INVALID_RULE_NAME",
            "rule_name must start with an ASCII letter or underscore and contain only ASCII letters, digits, and underscores",
        )

    # Extract string values suitable for YARA patterns
    string_patterns: list[str] = []
    network_indicators: list[str] = []
    process_indicators: list[str] = []
    hash_indicators: list[str] = []

    for artifact in artifacts:
        atype = artifact.get("type", "")
        val = str(artifact.get("value", "")).strip()

        if not val or len(val) < 4:
            continue

        if atype in ("string", "injection"):
            string_patterns.append(val[:200])
        elif atype in (
            "ip",
            "url",
            "dns_query",
            "beacon",
            "dga_domain",
            "network_conn",
        ):
            if val and "/" not in val[:1]:  # skip IPv6/URL paths
                network_indicators.append(val[:200])
        elif atype == "process":
            if val.endswith(".exe") or val.endswith(".dll"):
                process_indicators.append(val[:200])
        elif atype == "hash":
            if len(val) in (32, 40, 64):  # MD5, SHA1, SHA256
                hash_indicators.append(val)

    if not string_patterns and not network_indicators:
        return failure(
            "INSUFFICIENT_ARTIFACTS",
            "Not enough string/network artifacts to generate meaningful YARA patterns",
            hint=(
                "Collect more artifacts using memory_extract_strings, "
                "pcap_extract_dns, or memory_detect_injections first."
            ),
        )

    # Build YARA rule
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"rule {rule_name} {{",
        "    meta:",
        '        description = "Auto-generated from forensics artifact correlation"',
        '        author = "Reversecore_MCP auto-generator"',
        f'        date = "{ts}"',
        f'        artifact_count = "{len(artifacts)}"',
        "    strings:",
    ]

    yara_strings: list[str] = []

    try:
        for i, pat in enumerate(string_patterns[:20]):
            var = f"$str{i}"
            yara_strings.append(var)
            lines.append(f'        {var} = "{_escape_yara_string(pat)}"')

        for i, net in enumerate(network_indicators[:10]):
            var = f"$net{i}"
            yara_strings.append(var)
            lines.append(f'        {var} = "{_escape_yara_string(net)}"')

        for i, proc in enumerate(process_indicators[:5]):
            var = f"$proc{i}"
            yara_strings.append(var)
            lines.append(f'        {var} = "{_escape_yara_string(proc)}" nocase')
    except UnicodeEncodeError:
        return failure(
            "INVALID_ARTIFACT_VALUE",
            "Artifact values used in YARA rules must contain valid Unicode text",
        )

    # Condition: any 1 of the patterns
    condition = (
        "any of them" if len(yara_strings) > 1 else yara_strings[0] if yara_strings else "false"
    )
    lines.append("    condition:")
    lines.append(f"        {condition}")
    lines.append("}")

    yara_rule = "\n".join(lines)

    try:
        import yara
    except ImportError:
        return failure(
            "YARA_DEPENDENCY_MISSING",
            "The yara-python package is required to validate generated rules",
        )
    try:
        yara.compile(source=yara_rule)
    except yara.Error as exc:
        logger.warning("Generated YARA rule failed compilation: %s", exc)
        return failure("YARA_COMPILE_ERROR", f"Generated YARA rule is invalid: {exc}")

    # Optionally save to file
    saved_path = None
    if output_path:
        from pathlib import Path

        out = Path(output_path)
        workspace = get_workspace_config().workspace.resolve()
        resolved_out = (out if out.is_absolute() else (workspace / out)).resolve()
        if not resolved_out.is_relative_to(workspace):
            return failure(
                "PATH_TRAVERSAL_DETECTED",
                f"output_path '{output_path}' must reside within the workspace directory",
            )
        resolved_out.parent.mkdir(parents=True, exist_ok=True)
        resolved_out.write_text(yara_rule, encoding="utf-8")
        saved_path = str(out)

    return success(
        {
            "rule_name": rule_name,
            "yara_rule": yara_rule,
            "string_patterns": string_patterns[:20],
            "network_indicators": network_indicators[:10],
            "process_indicators": process_indicators[:5],
            "hash_indicators": hash_indicators[:10],
            "pattern_count": len(yara_strings),
            "saved_path": saved_path,
        }
    )


@log_execution(tool_name="artifact_timeline")
@track_metrics("artifact_timeline")
@handle_tool_errors
async def artifact_timeline(
    artifacts: list[dict[str, Any]],
    sort_order: str = "asc",
) -> ToolResult:
    """Build a chronological event timeline from multi-source forensic artifacts.

    Aggregates artifacts from memory, disk (MFT timestamps), and network captures
    into a single unified timeline, sorted by timestamp.

    Args:
        artifacts: List of artifacts (from ``artifact_collect`` or ``artifact_correlate_ioc``).
            Source timestamps such as ``mtime`` are preferred; ``collected_at`` is
            retained separately and used only when no source timestamp is available.
            Timestamps without a timezone are interpreted as UTC.
        sort_order: Sort order — 'asc' (oldest first) or 'desc' (newest first).

    Returns:
        ToolResult with chronologically ordered events and pivot points. Event
        timestamps are normalized to UTC; each event keeps ``collected_at`` as
        separate provenance. Events with unknown timestamps appear last in either
        sort order.

    Example:
        >>> result = await artifact_timeline(all_artifacts)
        >>> for event in result.data["timeline"]:
        ...     print(event["timestamp"], event["event"])
    """
    if not artifacts:
        return failure("EMPTY_INPUT", "No artifacts to build timeline from")

    if sort_order not in ("asc", "desc"):
        return failure(
            "INVALID_PARAM",
            f"Invalid sort_order: '{sort_order}'",
            hint="Use 'asc' (oldest first) or 'desc' (newest first).",
        )

    timeline_entries: list[tuple[datetime.datetime | None, dict[str, Any]]] = []
    for artifact in artifacts:
        event_timestamp, timestamp_source = _get_event_timestamp(artifact)
        collected_at = artifact.get("collected_at")
        metadata = artifact.get("metadata")
        if collected_at is None and isinstance(metadata, dict):
            collected_at = metadata.get("collected_at")
        if collected_at is not None and not isinstance(collected_at, str):
            collected_at = str(collected_at)

        atype = artifact.get("type", "unknown")
        value = str(artifact.get("value", ""))
        source = artifact.get("source", "unknown")
        flagged = artifact.get("flagged", False)

        event_desc = {
            "process": f"Process observed: {value}",
            "injection": f"Injection detected at: {value}",
            "network_conn": f"Network connection: {value}",
            "dns_query": f"DNS query: {value}",
            "deleted_file": f"Deleted file found: {value}",
            "extracted_file": f"File extracted: {value}",
            "beacon": f"C2 beacon detected: {value}",
            "dga_domain": f"DGA domain queried: {value}",
            "hash": f"File hash: {value}",
            "ip": f"IP indicator: {value}",
        }.get(atype, f"Artifact ({atype}): {value}")

        event = {
            "timestamp": (
                _format_timestamp(event_timestamp) if event_timestamp is not None else "unknown"
            ),
            "timestamp_source": timestamp_source,
            "collected_at": collected_at,
            "event": event_desc,
            "type": atype,
            "source": source,
            "value": value,
            "flagged": flagged,
            "ioc_tags": artifact.get("ioc_tags", []),
        }
        timeline_entries.append((event_timestamp, event))

    # Sort known events by their normalized instant and append unknowns last for
    # both orders; reversing the whole list would incorrectly put unknowns first.
    known_entries = [
        (timestamp, event) for timestamp, event in timeline_entries if timestamp is not None
    ]
    unknown_entries = [entry for entry in timeline_entries if entry[0] is None]
    known_entries.sort(key=lambda entry: entry[0], reverse=(sort_order == "desc"))
    timeline_events = [event for _, event in known_entries + unknown_entries]

    # Identify pivot points (first/last flagged event)
    flagged_events = [e for e in timeline_events if e["flagged"]]
    pivot_points = {}
    if flagged_events:
        pivot_points["first_ioc"] = flagged_events[0]
        pivot_points["last_ioc"] = flagged_events[-1]

    return success(
        {
            "timeline": timeline_events,
            "total_events": len(timeline_events),
            "flagged_events": len(flagged_events),
            "sort_order": sort_order,
            "pivot_points": pivot_points,
        }
    )


@log_execution(tool_name="artifact_report")
@track_metrics("artifact_report")
@handle_tool_errors
async def artifact_report(
    artifacts: list[dict[str, Any]],
    case_name: str = "forensics_case",
    analyst: str = "AI Agent",
    include_yara: bool = True,
    output_path: str | None = None,
) -> ToolResult:
    """Export a comprehensive forensics investigation report.

    Combines artifact collection summary, IoC correlation results, timeline,
    and optionally auto-generated YARA rules into a structured Markdown report.

    Args:
        artifacts: All collected and enriched artifacts from the investigation.
        case_name: Name/identifier for this forensics case.
        analyst: Analyst name to include in the report header.
        include_yara: If True, auto-generate and include YARA rules in the report.
        output_path: Optional path to save the report as a Markdown file.

    Returns:
        ToolResult with the full report text and executive summary statistics.

    Example:
        >>> result = await artifact_report(
        ...     artifacts=enriched_artifacts,
        ...     case_name="incident_2024_001",
        ...     output_path="/app/workspace/reports/case_001.md",
        ... )
    """
    if not artifacts:
        return failure("EMPTY_INPUT", "No artifacts to generate report from")

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count by type
    type_counts: dict[str, int] = {}
    for a in artifacts:
        atype = a.get("type", "unknown")
        type_counts[atype] = type_counts.get(atype, 0) + 1

    flagged = [a for a in artifacts if a.get("flagged")]
    ioc_tags_all: list[str] = []
    for a in artifacts:
        ioc_tags_all.extend(a.get("ioc_tags", []))

    severity = (
        "CRITICAL"
        if len(flagged) > 10
        else "HIGH"
        if len(flagged) > 3
        else "MEDIUM"
        if flagged
        else "LOW"
    )

    # Generate YARA if requested
    yara_section = ""
    if include_yara:
        safe_case_name = re.sub(r"[^A-Za-z0-9_]", "_", case_name)[:80]
        if not safe_case_name or safe_case_name[0].isdigit():
            safe_case_name = f"_{safe_case_name}"
        yara_result = await artifact_generate_yara(
            artifacts,
            rule_name=f"{safe_case_name}_detection",
        )
        if yara_result.status == "success" and isinstance(yara_result.data, dict):
            yara_section = f"""
## Auto-Generated YARA Rule

```yara
{yara_result.data.get("yara_rule", "")}
```
"""

    # Build Markdown report
    report_lines = [
        "# Forensics Investigation Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Case | {case_name} |",
        f"| Analyst | {analyst} |",
        f"| Generated | {ts} |",
        f"| Overall Severity | **{severity}** |",
        "",
        "## Executive Summary",
        "",
        f"- **Total Artifacts Collected**: {len(artifacts)}",
        f"- **Flagged IoC Artifacts**: {len(flagged)}",
        f"- **Unique IoC Tags**: {len(set(ioc_tags_all))}",
        f"- **Severity Assessment**: {severity}",
        "",
        "## Artifact Breakdown",
        "",
        "| Type | Count |",
        "|---|---|",
    ]
    for atype, cnt in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        report_lines.append(f"| {atype} | {cnt} |")

    if flagged:
        report_lines.extend(
            [
                "",
                "## Flagged IoC Artifacts",
                "",
                "| Type | Value | IoC Tags | Source |",
                "|---|---|---|---|",
            ]
        )
        for a in flagged[:50]:
            tags = ", ".join(a.get("ioc_tags", []))
            val = str(a.get("value", ""))[:80]
            report_lines.append(
                f"| {a.get('type', '')} | `{val}` | {tags} | {a.get('source', '')} |"
            )

    if yara_section:
        report_lines.append(yara_section)

    report_md = "\n".join(report_lines)

    # Save report if path provided
    saved_path = None
    if output_path:
        from pathlib import Path

        out = Path(output_path)
        workspace = get_workspace_config().workspace.resolve()
        resolved_out = (out if out.is_absolute() else (workspace / out)).resolve()
        if not resolved_out.is_relative_to(workspace):
            return failure(
                "PATH_TRAVERSAL_DETECTED",
                f"output_path '{output_path}' must reside within the workspace directory",
            )
        resolved_out.parent.mkdir(parents=True, exist_ok=True)
        resolved_out.write_text(report_md, encoding="utf-8")
        saved_path = str(out)

    return success(
        {
            "case_name": case_name,
            "report_markdown": report_md,
            "summary": {
                "total_artifacts": len(artifacts),
                "flagged_count": len(flagged),
                "severity": severity,
                "artifact_types": type_counts,
            },
            "saved_path": saved_path,
        }
    )
