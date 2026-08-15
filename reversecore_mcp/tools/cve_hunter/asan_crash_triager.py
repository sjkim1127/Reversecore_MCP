"""AddressSanitizer (ASan) and UBSan Crash Triager and Root Cause Analyzer."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure, success

logger = get_logger(__name__)

# ASan error line regex: ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
_ASAN_ERROR_PATTERN = re.compile(
    r"ERROR:\s+(?:AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|ThreadSanitizer):\s+([a-zA-Z0-9\-_]+)(?:\s+on\s+address\s+([0-9a-fA-Fx]+))?",
    re.IGNORECASE,
)

# Access type regex: READ of size 4 at 0x... thread T0 / WRITE of size 8 at 0x...
_ACCESS_PATTERN = re.compile(
    r"(READ|WRITE)\s+of\s+size\s+(\d+)\s+at\s+([0-9a-fA-Fx]+)",
    re.IGNORECASE,
)

# Stack frame regex: #0 0x555555555123 in parse_header /app/src/parser.c:45:12
_STACK_FRAME_PATTERN = re.compile(
    r"#(\d+)\s+([0-9a-fA-Fx]+)\s+in\s+([A-Za-z0-9_:\<\>\~]+)\s+(?:(\S+?):(\d+)(?::(\d+))?)?",
)

# CWE Mapping based on Sanitizer Error Type
CWE_MAP: dict[str, dict[str, Any]] = {
    "heap-buffer-overflow": {
        "cwe_id": "CWE-122",
        "cwe_name": "Heap-based Buffer Overflow",
        "base_severity": "HIGH",
    },
    "heap-use-after-free": {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free",
        "base_severity": "HIGH",
    },
    "use-after-free": {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free",
        "base_severity": "HIGH",
    },
    "double-free": {
        "cwe_id": "CWE-415",
        "cwe_name": "Double Free",
        "base_severity": "HIGH",
    },
    "bad-free": {
        "cwe_id": "CWE-761",
        "cwe_name": "Free of Pointer not on the Heap",
        "base_severity": "HIGH",
    },
    "global-buffer-overflow": {
        "cwe_id": "CWE-125",
        "cwe_name": "Out-of-bounds Read / Global Buffer Overflow",
        "base_severity": "MEDIUM",
    },
    "stack-buffer-overflow": {
        "cwe_id": "CWE-121",
        "cwe_name": "Stack-based Buffer Overflow",
        "base_severity": "HIGH",
    },
    "stack-use-after-return": {
        "cwe_id": "CWE-562",
        "cwe_name": "Use of Stack Variable After Return",
        "base_severity": "MEDIUM",
    },
    "null-dereference": {
        "cwe_id": "CWE-476",
        "cwe_name": "NULL Pointer Dereference",
        "base_severity": "MEDIUM",
    },
    "segv": {
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "base_severity": "MEDIUM",
    },
}


def parse_asan_stack_trace(lines: list[str]) -> list[dict[str, Any]]:
    """Extract individual stack frames from ASan log lines.

    Args:
        lines: Lines of the ASan crash log.

    Returns:
        List of parsed stack frame dictionaries.
    """
    frames: list[dict[str, Any]] = []
    for line in lines:
        match = _STACK_FRAME_PATTERN.search(line)
        if match:
            frame_num = int(match.group(1))
            pc_addr = match.group(2)
            symbol = match.group(3)
            source_file = match.group(4) or "unknown"
            line_num = int(match.group(5)) if match.group(5) else None

            # Skip ASan internal runtime wrappers in primary deduplication
            is_sanitizer_internal = any(
                sym in symbol.lower()
                for sym in ["__asan", "__interceptor", "__sanitizer", "asan_", "lsan_"]
            )

            frames.append(
                {
                    "frame": frame_num,
                    "address": pc_addr,
                    "symbol": symbol,
                    "source_file": source_file,
                    "line": line_num,
                    "is_sanitizer_internal": is_sanitizer_internal,
                }
            )
    return frames


def calculate_cvss_score(bug_type: str, access_type: str, access_size: int) -> dict[str, Any]:
    """Calculate CVSS v3.1 score and vector based on crash severity attributes.

    Args:
        bug_type: Sanitizer bug class (e.g. 'heap-buffer-overflow').
        access_type: 'READ' or 'WRITE'.
        access_size: Size in bytes of illegal memory access.

    Returns:
        Dictionary with CVSS score, severity rating, and vector string.
    """
    bug_lower = bug_type.lower()
    is_write = access_type.upper() == "WRITE"

    if "heap-buffer-overflow" in bug_lower or "use-after-free" in bug_lower:
        if is_write:
            score = 8.8
            rating = "HIGH"
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
        else:
            score = 6.5 if access_size >= 4 else 5.3
            rating = "MEDIUM"
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
    elif "double-free" in bug_lower or "bad-free" in bug_lower:
        score = 8.1
        rating = "HIGH"
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H"
    elif "stack-buffer-overflow" in bug_lower:
        score = 9.8 if is_write else 7.5
        rating = "CRITICAL" if is_write else "HIGH"
        vector = (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            if is_write
            else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"
        )
    else:
        score = 5.5
        rating = "MEDIUM"
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"

    return {
        "cvss_v31_score": score,
        "severity": rating,
        "cvss_vector": vector,
    }


def triage_asan_log(asan_output: str) -> dict[str, Any]:
    """Parse complete AddressSanitizer output into structured crash triage data.

    Args:
        asan_output: Raw stderr/stdout containing ASan crash trace.

    Returns:
        Structured triage dictionary with bug type, CWE, callstacks, and CVSS.
    """
    lines = asan_output.splitlines()

    bug_type = "unknown_crash"
    fault_address = "0x0"
    access_type = "UNKNOWN"
    access_size = 0

    # 1. Parse ERROR line
    for line in lines:
        m_err = _ASAN_ERROR_PATTERN.search(line)
        if m_err:
            bug_type = m_err.group(1).lower()
            if m_err.group(2):
                fault_address = m_err.group(2)
            break

    # 2. Parse Access type
    for line in lines:
        m_acc = _ACCESS_PATTERN.search(line)
        if m_acc:
            access_type = m_acc.group(1).upper()
            access_size = int(m_acc.group(2))
            fault_address = m_acc.group(3)
            break

    # 3. Split into sections: Crash trace, Allocation trace, Free trace
    crash_lines: list[str] = []
    alloc_lines: list[str] = []
    free_lines: list[str] = []

    current_section = "crash"
    for line in lines:
        if "allocated by thread" in line or "previously allocated by" in line:
            current_section = "alloc"
        elif "freed by thread" in line:
            current_section = "free"
        elif "SUMMARY: AddressSanitizer:" in line or "Shadow bytes around" in line:
            current_section = "other"

        if current_section == "crash":
            crash_lines.append(line)
        elif current_section == "alloc":
            alloc_lines.append(line)
        elif current_section == "free":
            free_lines.append(line)

    crash_frames = parse_asan_stack_trace(crash_lines)
    alloc_frames = parse_asan_stack_trace(alloc_lines)
    free_frames = parse_asan_stack_trace(free_lines)

    # 4. Generate deduplication crash signature hash
    # Based on top 3 non-sanitizer stack frames
    user_frames = [f for f in crash_frames if not f.get("is_sanitizer_internal")]
    sig_components = [
        f"{f.get('symbol')}@{f.get('source_file')}:{f.get('line')}" for f in user_frames[:3]
    ]
    if not sig_components:
        sig_components = [bug_type, fault_address]
    crash_signature = hashlib.sha256(":".join(sig_components).encode()).hexdigest()[:16]

    # 5. Determine CWE and CVSS
    cwe_info = CWE_MAP.get(
        bug_type,
        {
            "cwe_id": "CWE-119",
            "cwe_name": "Memory Corruption",
            "base_severity": "MEDIUM",
        },
    )
    cvss_info = calculate_cvss_score(bug_type, access_type, access_size)

    faulting_function = user_frames[0].get("symbol", "unknown") if user_frames else "unknown"
    faulting_source = (
        f"{user_frames[0].get('source_file', 'unknown')}:{user_frames[0].get('line', 0)}"
        if user_frames
        else "unknown"
    )

    return {
        "crash_signature_id": crash_signature,
        "bug_type": bug_type,
        "cwe_id": cwe_info["cwe_id"],
        "cwe_name": cwe_info["cwe_name"],
        "access_type": access_type,
        "access_size": access_size,
        "fault_address": fault_address,
        "faulting_function": faulting_function,
        "faulting_source_location": faulting_source,
        "cvss": cvss_info,
        "crash_callstack": crash_frames,
        "allocation_callstack": alloc_frames,
        "free_callstack": free_frames,
        "is_heap_corruption": "heap" in bug_type or "free" in bug_type,
        "exploitability_assessment": (
            "High likelihood of Remote Code Execution (RCE) via arbitrary memory write"
            if access_type == "WRITE" and ("heap" in bug_type or "stack" in bug_type)
            else "Potential Information Disclosure or Denial of Service (Crash)"
        ),
    }


async def triage_crash_impl(
    crash_log_or_text: str,
    timeout: int | None = None,
) -> ToolResult:
    """Triage and analyze AddressSanitizer crash log or text.

    Args:
        crash_log_or_text: Raw ASan log text or path to crash log file.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with structured crash diagnostics and CVSS assessment.
    """
    raw_text = crash_log_or_text.strip()
    if not raw_text:
        return failure("INVALID_INPUT", "Crash log content cannot be empty.")

    # Check if input is a file path
    if (
        len(raw_text) < 1024
        and "\n" not in raw_text
        and ("/" in raw_text or "\\" in raw_text or "." in raw_text)
    ):
        try:
            from reversecore_mcp.core.security import validate_file_path

            log_path = validate_file_path(raw_text)
            if log_path.exists() and log_path.is_file():
                raw_text = log_path.read_text(errors="ignore")
        except Exception:
            pass  # Treat as direct raw log string

    triage_result = triage_asan_log(raw_text)

    summary = (
        f"Triaged {triage_result['bug_type'].upper()} ({triage_result['cwe_id']}: {triage_result['cwe_name']}) "
        f"in {triage_result['faulting_function']} [{triage_result['faulting_source_location']}]. "
        f"CVSS v3.1: {triage_result['cvss']['cvss_v31_score']} ({triage_result['cvss']['severity']})."
    )

    triage_result["summary"] = summary
    return success(triage_result)
