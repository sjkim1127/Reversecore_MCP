"""IOC (Indicators of Compromise) extraction tools using regex patterns."""

import os
import re

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success

# Pre-compile IOC extraction patterns for better performance
_IOC_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_IOC_URL_PATTERN = re.compile(
    r"https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
)
_IOC_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)


@log_execution(tool_name="extract_iocs")
@track_metrics("extract_iocs")
@handle_tool_errors
def extract_iocs(
    text: str,
    extract_ips: bool = True,
    extract_urls: bool = True,
    extract_emails: bool = True,
    limit: int = 100,
) -> ToolResult:
    """
    Extract Indicators of Compromise (IOCs) from text using regex.

    This tool automatically finds and extracts potential IOCs like IP addresses,
    URLs, and email addresses from any text input (e.g., strings output,
    decompiled code, logs).

    Args:
        text: The text to analyze for IOCs (or path to a file)
        extract_ips: Whether to extract IPv4 addresses (default: True)
        extract_urls: Whether to extract URLs (default: True)
        extract_emails: Whether to extract email addresses (default: True)
        limit: Maximum number of IOCs to return per category (default: 100)

    Returns:
        ToolResult with extracted IOCs in structured format
    """
    iocs = {}
    total_count = 0

    # Handle JSON input (e.g. ToolResult from another tool)
    if text.strip().startswith("{") and text.strip().endswith("}"):
        try:
            data = json.loads(text)
            # If it's a ToolResult structure, extract the 'data' or 'content'
            if isinstance(data, dict):
                if "data" in data:
                    # data can be string or dict
                    if isinstance(data["data"], str):
                        text = data["data"]
                    elif isinstance(data["data"], dict):
                        text = json.dumps(data["data"]) # Convert back to string for regex
                elif "content" in data: # Legacy or other format
                     if isinstance(data["content"], list):
                         text = "\n".join([c.get("text", "") for c in data["content"] if isinstance(c, dict)])
                     else:
                         text = str(data["content"])
        except json.JSONDecodeError:
            pass # Not valid JSON, treat as raw text

    # Handle file paths: if text is a valid file path, read its content
    # This handles cases where users pass a file path instead of content
    if len(text) < 260 and os.path.exists(text) and os.path.isfile(text):
        try:
            # Read file content, but limit size to avoid memory issues
            # 10MB limit for text analysis
            if os.path.getsize(text) > 10 * 1024 * 1024:
                return failure(
                    "FILE_TOO_LARGE",
                    f"File {text} is too large for regex analysis (>10MB).",
                    hint="Use 'run_strings' or 'grep' to filter content first."
                )
            with open(text, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception as e:
            return failure("FILE_READ_ERROR", f"Failed to read file: {str(e)}")

    # Optimization: If text is very large (>100KB), pre-filter lines to avoid token explosion
    # and regex performance issues.
    if len(text) > 100 * 1024:
        lines = text.split('\n')
        # Keep lines that look like they might contain IOCs (dots, @, http)
        # This is a rough heuristic to reduce data size before heavy regex
        filtered_lines = [
            line for line in lines 
            if len(line) < 500 and ('.' in line or '@' in line or ':' in line)
        ]
        # Limit to top 2000 suspicious lines to prevent memory issues
        text = '\n'.join(filtered_lines[:2000])


    # IPv4 Regex - use pre-compiled pattern
    if extract_ips:
        ips = list(set(_IOC_IPV4_PATTERN.findall(text)))
        if len(ips) > limit:
            ips = ips[:limit]
        iocs["ipv4"] = ips
        total_count += len(ips)

    # URL Regex - use pre-compiled pattern
    if extract_urls:
        raw_urls = _IOC_URL_PATTERN.findall(text)
        # Use set comprehension for better performance
        urls = list({url.rstrip(".,:;?!") for url in raw_urls})
        if len(urls) > limit:
            urls = urls[:limit]
        iocs["urls"] = urls
        total_count += len(urls)

    # Email Regex - use pre-compiled pattern
    if extract_emails:
        emails = list(set(_IOC_EMAIL_PATTERN.findall(text)))
        if len(emails) > limit:
            emails = emails[:limit]
        iocs["emails"] = emails
        total_count += len(emails)

    return success(
        iocs,
        ioc_count=total_count,
        description=f"Extracted {total_count} IOCs from text (limit: {limit} per category)",
    )
