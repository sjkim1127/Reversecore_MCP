"""Adaptive analysis hints: recommended_next_tools field generation.

Each tool can call the appropriate ``build_*_hints`` function after computing
its primary result and attach the returned list to the response payload under
the key ``"recommended_next_tools"``.

This lets AI clients (Claude, Gemini, etc.) autonomously decide whether to
follow up with additional analysis steps without hard-coding fixed pipelines.

Response field schema
---------------------
Each item in ``recommended_next_tools`` is a dict with:

    tool          : str   – MCP tool name to call next
    reason        : str   – human-readable justification
    confidence    : str   – "high" | "medium" | "low"
    suggested_args: dict  – ready-to-use kwargs for the next tool call
    priority      : int   – 1 (highest) … 5 (lowest); allows ordering
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

NextToolHint = dict[str, Any]
"""
{
    "tool": str,
    "reason": str,
    "confidence": "high" | "medium" | "low",
    "suggested_args": dict,
    "priority": int (1-5),
}
"""

# ---------------------------------------------------------------------------
# Dangerous API patterns used by r2_decompile hints
# ---------------------------------------------------------------------------

_DANGEROUS_MEMORY_APIS: frozenset[str] = frozenset(
    {
        "strcpy",
        "strcat",
        "gets",
        "sprintf",
        "vsprintf",
        "memcpy",
        "memmove",
        "strncpy",  # still dangerous when size comes from user
        "strncat",
        "wcscpy",
        "wcscat",
    }
)

_DANGEROUS_COMMAND_APIS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execve",
        "execl",
        "execlp",
        "execvp",
        "execvpe",
        "ShellExecute",
        "WinExec",
        "CreateProcess",
    }
)

_DANGEROUS_FORMAT_APIS: frozenset[str] = frozenset(
    {
        "printf",
        "fprintf",
        "syslog",
        "wprintf",
        "vprintf",
    }
)

_SYSCALL_PATTERN = re.compile(
    r"\b(syscall|int\s+0x80|svc\s+0x0|svc\s+#0|ecall|scall)\b",
    re.IGNORECASE,
)


def _find_dangerous_apis(source_code: str) -> tuple[list[str], list[str], list[str]]:
    """Scan decompiled source for dangerous API calls.

    Returns:
        Tuple of (memory_apis, command_apis, format_apis) found in source.
    """
    memory_hits: list[str] = []
    command_hits: list[str] = []
    format_hits: list[str] = []

    for api in _DANGEROUS_MEMORY_APIS:
        if re.search(rf"\b{re.escape(api)}\s*\(", source_code):
            memory_hits.append(api)

    for api in _DANGEROUS_COMMAND_APIS:
        if re.search(rf"\b{re.escape(api)}\s*\(", source_code):
            command_hits.append(api)

    for api in _DANGEROUS_FORMAT_APIS:
        if re.search(rf"\b{re.escape(api)}\s*\(", source_code):
            format_hits.append(api)

    return memory_hits, command_hits, format_hits


# ---------------------------------------------------------------------------
# Per-tool hint builders
# ---------------------------------------------------------------------------


def build_decompile_hints(
    file_path: str,
    function_name: str,
    source_code: str,
) -> list[NextToolHint]:
    """Generate hints based on r2_decompile output.

    Triggers:
    - Dangerous memory/command/format API → vulnerability_hunter + taint_trace
    - Syscall pattern → taint_trace
    """
    hints: list[NextToolHint] = []

    memory_apis, command_apis, format_apis = _find_dangerous_apis(source_code)
    has_syscall = bool(_SYSCALL_PATTERN.search(source_code))

    # Memory corruption sinks
    if memory_apis:
        hints.append(
            {
                "tool": "taint_trace",
                "reason": (
                    f"Dangerous memory API(s) detected in '{function_name}': "
                    f"{', '.join(memory_apis)}. "
                    "Taint analysis can confirm if user-controlled data reaches these sinks."
                ),
                "confidence": "high",
                "suggested_args": {
                    "file_path": file_path,
                    "verify_with_angr": True,
                },
                "priority": 1,
            }
        )
        hints.append(
            {
                "tool": "vulnerability_hunter",
                "reason": (
                    f"Unsafe function(s) {', '.join(memory_apis)} found in decompiled "
                    f"code of '{function_name}'. Static vulnerability scan recommended."
                ),
                "confidence": "high",
                "suggested_args": {"file_path": file_path},
                "priority": 2,
            }
        )

    # Command injection sinks
    if command_apis:
        hints.append(
            {
                "tool": "taint_trace",
                "reason": (
                    f"Command execution API(s) detected in '{function_name}': "
                    f"{', '.join(command_apis)} (potential CWE-78 OS command injection)."
                ),
                "confidence": "high",
                "suggested_args": {
                    "file_path": file_path,
                    "verify_with_angr": True,
                },
                "priority": 1,
            }
        )

    # Format string sinks
    if format_apis:
        hints.append(
            {
                "tool": "vulnerability_hunter",
                "reason": (
                    f"Format string API(s) detected in '{function_name}': "
                    f"{', '.join(format_apis)} (potential CWE-134 format string bug)."
                ),
                "confidence": "medium",
                "suggested_args": {"file_path": file_path},
                "priority": 3,
            }
        )

    # Syscall presence
    if has_syscall and not memory_apis and not command_apis:
        hints.append(
            {
                "tool": "taint_trace",
                "reason": (
                    f"Direct syscall(s) detected in '{function_name}'. "
                    "Taint analysis can reveal if user-controlled data drives syscall arguments."
                ),
                "confidence": "medium",
                "suggested_args": {
                    "file_path": file_path,
                    "verify_with_angr": False,
                },
                "priority": 2,
            }
        )

    return hints


def build_lief_hints(
    file_path: str,
    sections: list[dict[str, Any]],
) -> list[NextToolHint]:
    """Generate hints based on parse_binary_with_lief output.

    Triggers:
    - Any section with entropy > 7.0 → detect_packer_deep
    """
    hints: list[NextToolHint] = []

    high_entropy_sections = [
        s for s in sections if isinstance(s.get("entropy"), (int, float)) and s["entropy"] > 7.0
    ]

    if high_entropy_sections:
        section_names = [s.get("name", "?") for s in high_entropy_sections]
        max_entropy = max(s["entropy"] for s in high_entropy_sections)
        hints.append(
            {
                "tool": "detect_packer_deep",
                "reason": (
                    f"High-entropy section(s) detected: {', '.join(section_names)} "
                    f"(max entropy: {max_entropy:.2f}). "
                    "The binary may be packed, encrypted, or obfuscated."
                ),
                "confidence": "high" if max_entropy > 7.5 else "medium",
                "suggested_args": {"file_path": file_path},
                "priority": 1,
            }
        )

    return hints


def build_capa_hints(
    file_path: str,
    capabilities: list[str],
) -> list[NextToolHint]:
    """Generate hints based on run_capa output.

    Triggers:
    - "encrypts data" / "obfuscates data" → crypto_analysis_mode prompt
    - "create remote thread" / "inject" → dormant_detector
    - "persistence" / "registry" → static_analysis
    - "network" capability → extract_iocs
    """
    hints: list[NextToolHint] = []
    caps_lower = " ".join(capabilities).lower()

    # Encryption/obfuscation
    if any(kw in caps_lower for kw in ("encrypt", "obfuscat", "decrypt", "cipher", "xor")):
        hints.append(
            {
                "tool": "r2_decompile",
                "reason": (
                    "CAPA detected encryption/obfuscation capability. "
                    "Decompile the relevant function to identify the algorithm "
                    "(AES, RC4, XOR, custom)."
                ),
                "confidence": "high",
                "suggested_args": {"file_path": file_path, "function_address": "main"},
                "priority": 1,
            }
        )

    # Code injection / process hollowing
    if any(kw in caps_lower for kw in ("inject", "remote thread", "hollowing", "shellcode")):
        hints.append(
            {
                "tool": "dormant_detector",
                "reason": (
                    "CAPA detected code injection capability. "
                    "Dormant function detection can reveal hidden injection stubs."
                ),
                "confidence": "high",
                "suggested_args": {"file_path": file_path},
                "priority": 1,
            }
        )

    # Persistence mechanisms
    if any(kw in caps_lower for kw in ("persist", "registry", "startup", "service", "scheduled")):
        hints.append(
            {
                "tool": "vulnerability_hunter",
                "reason": (
                    "CAPA detected persistence capability. "
                    "Vulnerability scan may reveal exploitable persistence installation paths."
                ),
                "confidence": "medium",
                "suggested_args": {"file_path": file_path},
                "priority": 2,
            }
        )

    # Network/C2 communication
    if any(kw in caps_lower for kw in ("network", "http", "connect", "socket", "beacon", "c2")):
        hints.append(
            {
                "tool": "extract_iocs",
                "reason": (
                    "CAPA detected network communication capability. "
                    "Extract IOCs to identify C2 domains, IPs, and URLs."
                ),
                "confidence": "high",
                "suggested_args": {"file_path": file_path},
                "priority": 1,
            }
        )

    return hints


def build_dormant_hints(
    file_path: str,
    orphan_functions: list[dict[str, Any]],
) -> list[NextToolHint]:
    """Generate hints based on dormant_detector output.

    Triggers:
    - Orphan functions found → r2_decompile each one (up to 5)
    """
    hints: list[NextToolHint] = []

    if not orphan_functions:
        return hints

    # Suggest decompiling top-priority orphan functions (max 5)
    top_orphans = orphan_functions[:5]
    for func in top_orphans:
        addr = func.get("address") or func.get("offset") or func.get("fcn_addr", "")
        name = func.get("name") or func.get("function_name") or str(addr)

        if addr:
            hints.append(
                {
                    "tool": "r2_decompile",
                    "reason": (
                        f"Orphan function '{name}' at {addr} has no cross-references "
                        "to the main call graph — possible backdoor, anti-analysis stub, "
                        "or unused exploit payload. Decompile to inspect."
                    ),
                    "confidence": "high",
                    "suggested_args": {
                        "file_path": file_path,
                        "function_address": str(addr),
                    },
                    "priority": 1,
                }
            )

    # Also suggest taint analysis if there are several orphans
    if len(orphan_functions) >= 3:
        hints.append(
            {
                "tool": "taint_trace",
                "reason": (
                    f"Found {len(orphan_functions)} orphan function(s). "
                    "Taint analysis may reveal if network input can reach these hidden functions."
                ),
                "confidence": "medium",
                "suggested_args": {"file_path": file_path, "verify_with_angr": False},
                "priority": 3,
            }
        )

    return hints


def build_ioc_hints(
    file_path: str,
    iocs: dict[str, list[str]],
) -> list[NextToolHint]:
    """Generate hints based on extract_iocs output.

    Triggers:
    - IPs / URLs / hashes found → vt_lookup
    - Domain/URL found → extract_strings (deeper search)
    """
    hints: list[NextToolHint] = []

    ips = iocs.get("ips", []) or iocs.get("ip_addresses", [])
    urls = iocs.get("urls", [])
    domains = iocs.get("domains", [])
    hashes = iocs.get("hashes", []) or iocs.get("file_hashes", [])

    all_indicators = ips + urls + domains + hashes

    if all_indicators:
        # Build a flat list of indicators to pass to vt_lookup
        flat_iocs: list[str] = []
        flat_iocs.extend(ips[:5])
        flat_iocs.extend(urls[:5])
        flat_iocs.extend(hashes[:5])

        hints.append(
            {
                "tool": "vt_lookup",
                "reason": (
                    f"Found {len(ips)} IP(s), {len(urls)} URL(s), "
                    f"{len(domains)} domain(s), {len(hashes)} hash(es). "
                    "VirusTotal lookup can confirm malicious reputation."
                ),
                "confidence": "high",
                "suggested_args": {
                    "iocs": flat_iocs or all_indicators[:10],
                },
                "priority": 1,
            }
        )

    if urls or domains:
        hints.append(
            {
                "tool": "extract_strings",
                "reason": (
                    "Network indicators found. Additional string extraction "
                    "(min_length=6) may reveal obfuscated domains or encoded URLs."
                ),
                "confidence": "low",
                "suggested_args": {"file_path": file_path, "min_length": 6},
                "priority": 4,
            }
        )

    return hints


def build_vuln_hunter_hints(
    file_path: str,
    findings: list[dict[str, Any]],
) -> list[NextToolHint]:
    """Generate hints based on vulnerability_hunter output.

    Triggers:
    - Confirmed vuln found → generate_poc_exploit
    - Buffer overflow → build_rop_chain
    - Multiple high-severity findings → autonomous_vuln_hunt
    """
    hints: list[NextToolHint] = []

    if not findings:
        return hints

    high_sev = [
        f
        for f in findings
        if str(f.get("severity", "")).lower() in ("high", "critical")
        or str(f.get("confidence", "")).lower() in ("confirmed", "high")
    ]

    bof_findings = [
        f
        for f in findings
        if any(
            kw in str(f).lower()
            for kw in ("buffer_overflow", "stack_overflow", "bof", "cwe-120", "cwe-121", "cwe-122")
        )
    ]

    if high_sev:
        # Suggest PoC generation for the most severe finding
        top = high_sev[0]
        vuln_type = top.get("vulnerability_type") or top.get("vuln_type") or "buffer_overflow"
        hints.append(
            {
                "tool": "generate_poc_exploit",
                "reason": (
                    f"High-confidence vulnerability confirmed: {vuln_type}. "
                    "Generate a PoC to verify exploitability."
                ),
                "confidence": "high",
                "suggested_args": {
                    "file_path": file_path,
                    "vulnerability_class": vuln_type,
                },
                "priority": 1,
            }
        )

    if bof_findings:
        hints.append(
            {
                "tool": "build_rop_chain",
                "reason": (
                    "Buffer overflow finding detected. Build a ROP chain to "
                    "bypass NX/ASLR and achieve code execution."
                ),
                "confidence": "medium",
                "suggested_args": {
                    "file_path": file_path,
                    "objective": "shell",
                },
                "priority": 2,
            }
        )

    if len(high_sev) >= 3:
        hints.append(
            {
                "tool": "autonomous_vuln_hunt",
                "reason": (
                    f"{len(high_sev)} high-severity vulnerabilities found. "
                    "Full autonomous hunt will enumerate all functions and "
                    "attempt end-to-end exploit generation."
                ),
                "confidence": "medium",
                "suggested_args": {"file_path": file_path},
                "priority": 3,
            }
        )

    return hints


# ---------------------------------------------------------------------------
# Utility: deduplicate and sort hints
# ---------------------------------------------------------------------------


def finalize_hints(hints: list[NextToolHint]) -> list[NextToolHint]:
    """Deduplicate by tool name (keep highest-priority) and sort by priority."""
    seen: dict[str, NextToolHint] = {}
    for hint in hints:
        tool = hint["tool"]
        if tool not in seen or hint.get("priority", 5) < seen[tool].get("priority", 5):
            seen[tool] = hint
    return sorted(seen.values(), key=lambda h: h.get("priority", 5))
