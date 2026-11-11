"""Progressive Disclosure Layer 1 Meta-Tools for Reversecore_MCP.

Provides high-level, single-turn entrypoint tools for AI agents to obtain
comprehensive, actionable results without needing multi-turn tool chain calls:

1. analyze_binary: Unified binary inspection (format, architecture, sections,
   mitigations, entrypoint decompilation, risk strings, goal-specific triage).
2. triage_incident: Multi-source DFIR triage (PCAP traffic, memory dump injections,
   disk artifacts, IoC extraction, anomaly scoring).
3. investigate_vulnerability: Exploitability analysis (ASan/GDB crash triage,
   security mitigations, dangerous APIs, ROP/Heap potential, CWE mapping).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import execute_r2_command
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# Well-known dangerous C/C++ APIs and CWE mapping
_DANGEROUS_CALLS: dict[str, dict[str, str]] = {
    "strcpy": {"cwe": "CWE-120", "severity": "HIGH", "desc": "Unbounded string copy"},
    "strcat": {"cwe": "CWE-120", "severity": "HIGH", "desc": "Unbounded string concatenation"},
    "gets": {"cwe": "CWE-242", "severity": "CRITICAL", "desc": "Inherently dangerous input read"},
    "sprintf": {
        "cwe": "CWE-134",
        "severity": "HIGH",
        "desc": "Format string / unbounded buffer copy",
    },
    "vsprintf": {"cwe": "CWE-134", "severity": "HIGH", "desc": "Format string vulnerability"},
    "system": {"cwe": "CWE-78", "severity": "HIGH", "desc": "Command injection surface"},
    "popen": {"cwe": "CWE-78", "severity": "HIGH", "desc": "Command execution with pipe"},
    "scanf": {"cwe": "CWE-120", "severity": "MEDIUM", "desc": "Unchecked format input"},
    "mprotect": {
        "cwe": "CWE-732",
        "severity": "MEDIUM",
        "desc": "Memory permission modification (W^X bypass)",
    },
    "VirtualProtect": {
        "cwe": "CWE-732",
        "severity": "MEDIUM",
        "desc": "Windows page permission modification",
    },
}

# Suspicious anti-analysis and evasion APIs
_ANTI_ANALYSIS_APIS: set[str] = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "NtQueryInformationProcess",
    "ptrace",
    "getppid",
    "rdtsc",
}

# Suspicious string regex patterns
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9_\-\./:\?#&=%]+")
_CMD_PATTERN = re.compile(
    r"\b(?:cmd\.exe|powershell(?:\.exe)?|/bin/sh|/bin/bash|wget|curl)\b", re.IGNORECASE
)


def _calculate_hashes(path: Path) -> dict[str, str]:
    """Calculate MD5 and SHA256 hashes of a file in streaming chunks."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


# =============================================================================
# 1. Layer 1 Meta-Tool: analyze_binary
# =============================================================================
@log_execution(tool_name="analyze_binary")
@track_metrics("analyze_binary")
@handle_tool_errors
async def analyze_binary(
    file_path: str,
    goal: str = "general",
    decompile: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Perform a comprehensive, 1-turn binary analysis and orchestration summary.

    Combines file metadata, LIEF structure parsing, section entropy, security
    mitigations, dangerous functions, suspicious strings, and entrypoint
    decompilation into a single structured report with next-step tool guidance.

    Args:
        file_path: Absolute or workspace-relative path to the binary.
        goal: Target analysis goal ('general', 'malware', 'vuln'). Default is 'general'.
        decompile: If True, attempts pseudo-C decompilation of entrypoint or main.
        timeout: Execution timeout in seconds.

    Returns:
        ToolResult containing unified binary report and recommended follow-up tools.
    """
    validated_path = validate_file_path(file_path)
    file_stat = validated_path.stat()
    file_size = file_stat.st_size
    hashes = _calculate_hashes(validated_path)

    # 1. Run file CLI inspection
    file_type_str = "application/octet-stream"
    try:
        out, _ = await execute_subprocess_async(
            ["file", str(validated_path)], timeout=min(timeout, 15)
        )
        file_type_str = out.strip()
    except Exception as exc:
        logger.debug(f"file utility check failed: {exc}")

    # 2. LIEF / Header metadata
    binary_info: dict[str, Any] = {
        "file_name": validated_path.name,
        "file_path": str(validated_path),
        "size_bytes": file_size,
        "hashes": hashes,
        "file_type": file_type_str,
        "format": "UNKNOWN",
        "architecture": "UNKNOWN",
        "bitness": 0,
        "endianness": "UNKNOWN",
        "entrypoint": "0x0",
    }
    sections_summary: list[dict[str, Any]] = []
    high_entropy_sections: list[dict[str, Any]] = []
    mitigations: dict[str, Any] = {
        "nx": False,
        "pie": False,
        "canary": False,
        "relro": "none",
        "aslr": False,
        "authenticode": False,
    }
    imported_libraries: list[str] = []
    imported_functions: list[str] = []

    try:
        import lief

        parsed = lief.parse(str(validated_path))
        if parsed is not None:
            fmt_str = str(getattr(parsed, "format", "")).split(".")[-1].upper()
            binary_info["format"] = fmt_str
            binary_info["entrypoint"] = hex(getattr(parsed, "entrypoint", 0))

            header = getattr(parsed, "header", None)
            if header is not None:
                arch_str = str(getattr(header, "architecture", "UNKNOWN")).split(".")[-1]
                binary_info["architecture"] = arch_str

            # Parse sections and entropy
            if hasattr(parsed, "sections"):
                for sec in parsed.sections:
                    sec_name = getattr(sec, "name", "")
                    sec_size = getattr(sec, "size", 0)
                    sec_entropy = getattr(sec, "entropy", 0.0)
                    is_exec = False
                    if hasattr(sec, "has_characteristic"):
                        try:
                            char_enum = getattr(lief.PE, "SECTION_CHARACTERISTICS", None)
                            if char_enum is not None:
                                is_exec = bool(sec.has_characteristic(char_enum.MEM_EXECUTE))
                        except Exception:
                            pass
                    elif hasattr(sec, "flags"):
                        is_exec = bool(int(sec.flags) & 0x4)

                    sec_data = {
                        "name": sec_name,
                        "size": sec_size,
                        "entropy": round(float(sec_entropy), 3),
                        "executable": is_exec,
                    }
                    sections_summary.append(sec_data)
                    if sec_entropy >= 7.0:
                        high_entropy_sections.append(sec_data)

            # Security mitigations
            if fmt_str == "ELF":
                mitigations["nx"] = bool(getattr(parsed, "has_nx", False))
                mitigations["pie"] = bool(getattr(parsed, "is_pie", False))
                # RELRO & Canary detection
                for sec in getattr(parsed, "sections", []):
                    if getattr(sec, "name", "") == ".dynamic":
                        mitigations["relro"] = "partial"
                for imp in getattr(parsed, "imported_functions", []):
                    if "__stack_chk_fail" in str(imp):
                        mitigations["canary"] = True
            elif fmt_str == "PE":
                optional_hdr = getattr(parsed, "optional_header", None)
                if optional_hdr is not None:
                    dll_char = getattr(optional_hdr, "dll_characteristics", 0)
                    mitigations["nx"] = bool(
                        dll_char & 0x0100
                    )  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                    mitigations["aslr"] = bool(
                        dll_char & 0x0040
                    )  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                    mitigations["pie"] = mitigations["aslr"]
                mitigations["authenticode"] = bool(getattr(parsed, "has_signatures", False))
                for imp in getattr(parsed, "imported_functions", []):
                    if "__security_check_cookie" in str(imp) or "__GSHandlerCheck" in str(imp):
                        mitigations["canary"] = True

            # Libraries & imports
            if hasattr(parsed, "libraries"):
                imported_libraries = [str(lib) for lib in parsed.libraries][:15]
            if hasattr(parsed, "imported_functions"):
                imported_functions = [str(fn) for fn in parsed.imported_functions][:50]
    except Exception as exc:
        logger.debug(f"LIEF parsing skipped or failed: {exc}")

    # 3. Radare2 Fast Inspection & Strings
    r2_functions: list[dict[str, Any]] = []
    suspicious_strings: dict[str, list[str]] = {
        "ips": [],
        "urls": [],
        "commands": [],
        "interesting": [],
    }
    dangerous_found: list[dict[str, Any]] = []
    anti_analysis_found: list[str] = []
    decompilation_snippet: str | None = None

    try:
        # Query functions: aflj
        funcs_out, _ = await execute_r2_command(
            validated_path,
            ["aflj"],
            analysis_level="aa",
            base_timeout=min(timeout, 30),
        )
        try:
            parsed_funcs = json.loads(funcs_out.strip()) if funcs_out.strip() else []
            if isinstance(parsed_funcs, list):
                for fn in parsed_funcs[:25]:
                    r2_functions.append(
                        {
                            "name": fn.get("name", ""),
                            "offset": hex(fn.get("offset", 0)),
                            "size": fn.get("size", 0),
                            "nargs": fn.get("nargs", 0),
                        }
                    )
        except Exception:
            pass

        # Query strings: izj
        str_out, _ = await execute_r2_command(
            validated_path,
            ["izj"],
            analysis_level="-n",
            base_timeout=min(timeout, 20),
        )
        try:
            parsed_strs = json.loads(str_out.strip()) if str_out.strip() else []
            if isinstance(parsed_strs, list):
                seen_ips: set[str] = set()
                seen_urls: set[str] = set()
                for item in parsed_strs:
                    s_val = item.get("string", "")
                    if not s_val or len(s_val) < 4:
                        continue
                    # Match IPs
                    for ip in _IP_PATTERN.findall(s_val):
                        if (
                            ip not in seen_ips
                            and not ip.startswith("0.")
                            and not ip.startswith("127.")
                        ):
                            seen_ips.add(ip)
                            suspicious_strings["ips"].append(ip)
                    # Match URLs
                    for url in _URL_PATTERN.findall(s_val):
                        if url not in seen_urls:
                            seen_urls.add(url)
                            suspicious_strings["urls"].append(url)
                    # Match commands
                    if _CMD_PATTERN.search(s_val):
                        suspicious_strings["commands"].append(s_val[:120])
        except Exception:
            pass

        # Check dangerous calls in imported or r2 functions
        all_syms = set(imported_functions + [f["name"] for f in r2_functions])
        for call_name, meta in _DANGEROUS_CALLS.items():
            for sym in all_syms:
                if call_name in sym:
                    dangerous_found.append(
                        {
                            "function": sym,
                            "matched_api": call_name,
                            "cwe": meta["cwe"],
                            "severity": meta["severity"],
                            "description": meta["desc"],
                        }
                    )
                    break

        for api in _ANTI_ANALYSIS_APIS:
            for sym in all_syms:
                if api in sym:
                    anti_analysis_found.append(sym)
                    break

        # 4. Decompile entrypoint / main if requested
        if decompile:
            target_fn = "main"
            fn_names = [f["name"] for f in r2_functions]
            for candidate in ("main", "sym.main", "_main", "entry0"):
                if candidate in fn_names:
                    target_fn = candidate
                    break

            decomp_out, _ = await execute_r2_command(
                validated_path,
                ["pdgj " + target_fn],
                analysis_level="aa",
                base_timeout=min(timeout, 25),
            )
            clean_decomp = decomp_out.strip()
            if clean_decomp and not clean_decomp.startswith("Cannot"):
                lines = clean_decomp.splitlines()[:35]
                decompilation_snippet = "\n".join(lines)
            else:
                # Fallback to disassembly
                disasm_out, _ = await execute_r2_command(
                    validated_path,
                    ["pdf @" + target_fn],
                    analysis_level="aa",
                    base_timeout=min(timeout, 15),
                )
                disasm_lines = disasm_out.strip().splitlines()[:25]
                if disasm_lines:
                    decompilation_snippet = (
                        "/* Disassembly fallback for "
                        + target_fn
                        + " */\n"
                        + "\n".join(disasm_lines)
                    )

    except Exception as exc:
        logger.debug(f"Radare2 inspection step skipped or failed: {exc}")

    # Limit lists
    suspicious_strings["ips"] = suspicious_strings["ips"][:10]
    suspicious_strings["urls"] = suspicious_strings["urls"][:10]
    suspicious_strings["commands"] = suspicious_strings["commands"][:10]

    # Goal-oriented synthesis & recommendations
    goal_norm = goal.strip().lower()
    recommended_tools: list[dict[str, Any]] = []

    if goal_norm == "malware":
        packing_suspected = len(high_entropy_sections) > 0
        assessment = {
            "packing_suspected": packing_suspected,
            "high_entropy_sections_count": len(high_entropy_sections),
            "anti_analysis_detected": len(anti_analysis_found) > 0,
            "evasion_apis": anti_analysis_found,
            "extracted_iocs": {
                "ips": suspicious_strings["ips"],
                "urls": suspicious_strings["urls"],
            },
        }
        recommended_tools = [
            {"tool": "run_yara", "arguments": {"file_path": str(validated_path)}},
            {"tool": "detect_packer", "arguments": {"file_path": str(validated_path)}},
            {"tool": "extract_iocs", "arguments": {"file_path": str(validated_path)}},
            {
                "tool": "call_expert_agent",
                "arguments": {
                    "agent_name": "malware_analyst",
                    "task": "deep malware analysis",
                    "file_path": str(validated_path),
                },
            },
        ]
    elif goal_norm == "vuln":
        assessment = {
            "dangerous_functions_count": len(dangerous_found),
            "dangerous_functions": dangerous_found,
            "mitigations": mitigations,
            "exploitability_factors": {
                "no_nx": not mitigations["nx"],
                "no_pie": not mitigations["pie"],
                "no_canary": not mitigations["canary"],
            },
        }
        recommended_tools = [
            {"tool": "vulnerability_hunter", "arguments": {"file_path": str(validated_path)}},
            {"tool": "build_rop_chain", "arguments": {"file_path": str(validated_path)}},
            {
                "tool": "call_expert_agent",
                "arguments": {
                    "agent_name": "vulnerability_hunter",
                    "task": "audit dangerous APIs and ROP gadgets",
                    "file_path": str(validated_path),
                },
            },
        ]
    else:  # general
        assessment = {
            "summary": f"{binary_info['format']} {binary_info['architecture']} binary ({binary_info['file_name']}) with {len(r2_functions)} detected functions.",
            "total_functions": len(r2_functions),
            "total_sections": len(sections_summary),
            "high_entropy_sections": len(high_entropy_sections),
            "dangerous_functions_detected": len(dangerous_found),
            "mitigations": mitigations,
        }
        recommended_tools = [
            {
                "tool": "Radare2_decompile_function",
                "arguments": {"file_path": str(validated_path), "function_name": "main"},
            },
            {"tool": "create_analysis_report", "arguments": {"file_path": str(validated_path)}},
            {"tool": "search_tools", "arguments": {"query": "disasm or decompile"}},
        ]

    result_data = {
        "status": "success",
        "file": binary_info,
        "sections": sections_summary[:15],
        "high_entropy_sections": high_entropy_sections,
        "mitigations": mitigations,
        "imported_libraries": imported_libraries,
        "sample_functions": r2_functions[:15],
        "dangerous_apis": dangerous_found,
        "anti_analysis_apis": anti_analysis_found,
        "suspicious_strings": suspicious_strings,
        "decompilation_preview": decompilation_snippet,
        "goal_assessment": assessment,
        "recommended_tools": recommended_tools,
    }

    return success(
        data=result_data,
        message=(
            f"Completed binary analysis for '{validated_path.name}'. "
            f"Format: {binary_info['format']}/{binary_info['architecture']}, "
            f"Sections: {len(sections_summary)}, Functions: {len(r2_functions)}."
        ),
    )


# =============================================================================
# 2. Layer 1 Meta-Tool: triage_incident
# =============================================================================
@log_execution(tool_name="triage_incident")
@track_metrics("triage_incident")
@handle_tool_errors
async def triage_incident(
    artifact_path: str,
    artifact_type: str = "auto",
    focus: str = "auto",
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Triage digital incident artifacts (PCAP, Memory dump, or Disk image) in 1-turn.

    Automatically identifies artifact type, performs protocol/process/anomaly
    triage, extracts network and host IoCs, and assigns a preliminary threat score.

    Args:
        artifact_path: Path to capture file (.pcap/.pcapng), memory dump (.dmp/.raw/.vmem),
                       or disk image (.img/.vmdk/.E01).
        artifact_type: Artifact category ('auto', 'pcap', 'memory', 'disk').
        focus: Investigation focus ('auto', 'network_c2', 'injected_code', 'persistence').
        timeout: Execution timeout in seconds.

    Returns:
        ToolResult with incident triage findings, severity rating, and recommended next tools.
    """
    validated_path = validate_file_path(artifact_path)
    stat = validated_path.stat()
    file_size = stat.st_size
    path_str = str(validated_path)
    path_lower = path_str.lower()

    # Determine artifact type
    inferred_type = artifact_type.strip().lower()
    if inferred_type in ("auto", ""):
        if any(path_lower.endswith(ext) for ext in (".pcap", ".pcapng", ".cap")):
            inferred_type = "pcap"
        elif any(path_lower.endswith(ext) for ext in (".dmp", ".raw", ".vmem")):
            inferred_type = "memory"
        elif any(path_lower.endswith(ext) for ext in (".img", ".vmdk", ".e01", ".iso")):
            inferred_type = "disk"
        else:
            inferred_type = "pcap"  # fallback default

    anomalies: list[str] = []
    extracted_iocs: dict[str, list[str]] = {"ips": [], "domains": [], "hashes": []}
    triage_details: dict[str, Any] = {}
    severity = "INFORMATIONAL"
    recommended_tools: list[dict[str, Any]] = []

    # 1. PCAP Triage Workflow
    if inferred_type == "pcap":
        try:
            from reversecore_mcp.tools.forensics.network import (
                pcap_analyze,
                pcap_extract_c2,
                pcap_extract_dns,
            )

            pcap_res = await pcap_analyze(pcap_path=path_str)
            pcap_data = pcap_res.data if hasattr(pcap_res, "data") else {}

            c2_res = await pcap_extract_c2(pcap_path=path_str)
            c2_data = c2_res.data if hasattr(c2_res, "data") else {}

            dns_res = await pcap_extract_dns(pcap_path=path_str)
            dns_data = dns_res.data if hasattr(dns_res, "data") else {}

            total_packets = pcap_data.get("total_packets", 0)
            c2_candidates = c2_data.get("c2_candidates", []) or c2_data.get("candidates", [])
            dns_queries = dns_data.get("queries", []) or dns_data.get("dns_queries", [])

            triage_details = {
                "artifact_type": "network_pcap",
                "total_packets": total_packets,
                "protocols": pcap_data.get("protocols", {}),
                "top_conversations": pcap_data.get("top_conversations", [])[:5],
                "c2_candidates_count": len(c2_candidates),
                "dns_queries_count": len(dns_queries),
            }

            if c2_candidates:
                severity = "HIGH"
                for cand in c2_candidates[:5]:
                    dst = cand.get("dst_ip") or cand.get("ip") or cand.get("destination")
                    if dst:
                        extracted_iocs["ips"].append(str(dst))
                    anomalies.append(
                        f"Suspicious C2 beacon or non-standard port activity towards {dst}"
                    )

            for q in dns_queries[:10]:
                domain = q.get("query") or q.get("domain") or str(q)
                if len(domain) > 30 or any(
                    tld in domain for tld in (".xyz", ".top", ".cc", ".onion")
                ):
                    extracted_iocs["domains"].append(domain)
                    anomalies.append(f"High-risk or long DNS query: {domain}")

            recommended_tools = [
                {"tool": "pcap_export_payloads", "arguments": {"pcap_path": path_str}},
                {
                    "tool": "call_expert_agent",
                    "arguments": {
                        "agent_name": "forensics",
                        "task": "deep network C2 extraction",
                        "file_path": path_str,
                    },
                },
            ]
        except Exception as exc:
            logger.warning(f"PCAP triage partial failure: {exc}")
            triage_details["error"] = str(exc)

    # 2. Memory Dump Triage Workflow
    elif inferred_type == "memory":
        try:
            from reversecore_mcp.tools.forensics.memory import (
                memory_analyze,
                memory_detect_injections,
            )

            # pslist
            ps_res = await memory_analyze(dump_path=path_str, plugin="windows.pslist")
            ps_data = ps_res.data if hasattr(ps_res, "data") else {}

            # malfind / injections
            inj_res = await memory_detect_injections(dump_path=path_str)
            inj_data = inj_res.data if hasattr(inj_res, "data") else {}

            injections = inj_data.get("injections", []) or inj_data.get("results", [])
            processes = ps_data.get("processes", []) or ps_data.get("results", [])

            triage_details = {
                "artifact_type": "memory_dump",
                "processes_count": len(processes),
                "injected_regions_count": len(injections),
                "sample_processes": [
                    p.get("ImageFileName") or p.get("name") for p in processes[:10]
                ],
            }

            if injections:
                severity = "CRITICAL"
                anomalies.append(
                    f"Detected {len(injections)} injected or RWX unbacked code memory region(s)"
                )
                for inj in injections[:5]:
                    pid = inj.get("pid") or inj.get("PID")
                    proc = inj.get("process") or inj.get("ImageFileName")
                    anomalies.append(f"Injected process candidate: {proc} (PID {pid})")

            recommended_tools = [
                {"tool": "memory_dump_process", "arguments": {"dump_path": path_str, "pid": 0}},
                {
                    "tool": "call_expert_agent",
                    "arguments": {
                        "agent_name": "forensics",
                        "task": "memory code injection review",
                        "file_path": path_str,
                    },
                },
            ]
        except Exception as exc:
            logger.warning(f"Memory triage partial failure: {exc}")
            triage_details["error"] = str(exc)

    # 3. Disk Image Triage Workflow
    else:
        triage_details = {
            "artifact_type": "disk_image",
            "file_size": file_size,
        }
        recommended_tools = [
            {"tool": "disk_list_files", "arguments": {"image_path": path_str}},
            {"tool": "disk_analyze_mft", "arguments": {"image_path": path_str}},
        ]

    # Deduplicate IoCs
    extracted_iocs["ips"] = list(dict.fromkeys(extracted_iocs["ips"]))
    extracted_iocs["domains"] = list(dict.fromkeys(extracted_iocs["domains"]))

    report = {
        "status": "success",
        "artifact_path": path_str,
        "artifact_name": validated_path.name,
        "artifact_type": inferred_type,
        "file_size_bytes": file_size,
        "overall_severity": severity,
        "anomalies": anomalies,
        "extracted_iocs": extracted_iocs,
        "details": triage_details,
        "recommended_tools": recommended_tools,
    }

    return success(
        data=report,
        message=f"Completed incident triage for '{validated_path.name}' ({inferred_type}). Severity: {severity}.",
    )


# =============================================================================
# 3. Layer 1 Meta-Tool: investigate_vulnerability
# =============================================================================
@log_execution(tool_name="investigate_vulnerability")
@track_metrics("investigate_vulnerability")
@handle_tool_errors
async def investigate_vulnerability(
    binary_path: str,
    target: str | None = None,
    crash_log: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Analyze vulnerability exploitability, crash traces, and dangerous APIs in 1-turn.

    Combines crash analysis (ASan/GDB triage), binary mitigation posture,
    dangerous C/C++ API calls, and ROP/Heap exploitability assessment.

    Args:
        binary_path: Absolute or workspace-relative path to target binary.
        target: Optional function symbol or hex address to focus analysis on (e.g. 'main', '0x401122').
        crash_log: Optional crash trace string (ASan, UBSan, or GDB backtrace) or path to crash file.
        timeout: Execution timeout in seconds.

    Returns:
        ToolResult with exploitability scoring, CWE mapping, and remediation advice.
    """
    validated_path = validate_file_path(binary_path)
    path_str = str(validated_path)

    # 1. Binary Security Posture & Mitigations
    mitigations = {"nx": False, "pie": False, "canary": False, "relro": "none"}
    try:
        import lief

        parsed = lief.parse(path_str)
        if parsed is not None:
            fmt = str(getattr(parsed, "format", "")).split(".")[-1].upper()
            if fmt == "ELF":
                mitigations["nx"] = bool(getattr(parsed, "has_nx", False))
                mitigations["pie"] = bool(getattr(parsed, "is_pie", False))
                for imp in getattr(parsed, "imported_functions", []):
                    if "__stack_chk_fail" in str(imp):
                        mitigations["canary"] = True
            elif fmt == "PE":
                opt = getattr(parsed, "optional_header", None)
                if opt is not None:
                    dll_char = getattr(opt, "dll_characteristics", 0)
                    mitigations["nx"] = bool(dll_char & 0x0100)
                    mitigations["pie"] = bool(dll_char & 0x0040)
                for imp in getattr(parsed, "imported_functions", []):
                    if "__security_check_cookie" in str(imp):
                        mitigations["canary"] = True
    except Exception as exc:
        logger.debug(f"Mitigation extraction skipped: {exc}")

    # 2. Crash Triage Integration (if crash_log provided)
    crash_assessment: dict[str, Any] | None = None
    if crash_log and crash_log.strip():
        # First attempt file-based crash triage if it's an existing file
        log_str = crash_log.strip()
        try:
            from reversecore_mcp.tools.analysis.crash_triage import triage_crash

            crash_res = await triage_crash(binary_path=path_str, crash_file=log_str)
            if (
                hasattr(crash_res, "data")
                and isinstance(crash_res.data, dict)
                and getattr(crash_res, "status", "") == "success"
            ):
                crash_assessment = crash_res.data
        except Exception as exc:
            logger.debug(f"triage_crash attempt fallback: {exc}")

        # If not file-based or triage_crash did not return success, parse trace text directly
        if crash_assessment is None:
            trace_lower = log_str.lower()
            inferred_bug = "SEGV / Memory Corruption"
            cwe = "CWE-119"
            if "heap-use-after-free" in trace_lower:
                inferred_bug = "Heap Use-After-Free"
                cwe = "CWE-416"
            elif "heap-buffer-overflow" in trace_lower:
                inferred_bug = "Heap Buffer Overflow"
                cwe = "CWE-122"
            elif "stack-buffer-overflow" in trace_lower:
                inferred_bug = "Stack Buffer Overflow"
                cwe = "CWE-121"
            elif "null-dereference" in trace_lower:
                inferred_bug = "NULL Pointer Dereference"
                cwe = "CWE-476"

            crash_assessment = {
                "parsed_crash_type": inferred_bug,
                "cwe": cwe,
                "raw_snippet": log_str[:300],
            }

    # 3. Dangerous API Detection via radare2
    dangerous_calls_found: list[dict[str, Any]] = []
    target_function_details: dict[str, Any] | None = None

    try:
        # Search symbols: isj
        syms_out, _ = await execute_r2_command(
            validated_path,
            ["isj"],
            analysis_level="-n",
            base_timeout=min(timeout, 20),
        )
        try:
            parsed_syms = json.loads(syms_out.strip()) if syms_out.strip() else []
            if isinstance(parsed_syms, list):
                seen_apis: set[str] = set()
                for s in parsed_syms:
                    s_name = s.get("name", "")
                    for d_api, meta in _DANGEROUS_CALLS.items():
                        if d_api in s_name and d_api not in seen_apis:
                            seen_apis.add(d_api)
                            dangerous_calls_found.append(
                                {
                                    "api": d_api,
                                    "symbol": s_name,
                                    "cwe": meta["cwe"],
                                    "severity": meta["severity"],
                                    "description": meta["desc"],
                                }
                            )
        except Exception:
            pass

        # If a target function is requested, examine it with pdf / pdgj
        if target:
            target_clean = target.strip()
            pdf_out, _ = await execute_r2_command(
                validated_path,
                [f"pdf @{target_clean}"],
                analysis_level="aa",
                base_timeout=min(timeout, 15),
            )
            target_function_details = {
                "target": target_clean,
                "disassembly_snippet": "\n".join(pdf_out.strip().splitlines()[:25]),
            }
    except Exception as exc:
        logger.debug(f"Vulnerability search via r2 failed: {exc}")

    # 4. Exploitability Scoring (0.0 to 10.0 scale)
    score = 2.0  # Base line
    cwe_list: list[str] = []

    # Protections reduction / penalty
    if not mitigations["nx"]:
        score += 3.0  # Shellcode on stack/heap possible
    if not mitigations["pie"]:
        score += 2.0  # Fixed ROP addresses
    if not mitigations["canary"]:
        score += 1.5  # Direct return address overwrite

    if dangerous_calls_found:
        score += min(len(dangerous_calls_found) * 0.5, 2.0)
        cwe_list.extend([d["cwe"] for d in dangerous_calls_found])

    if crash_assessment:
        score += 2.0
        if "cwe" in crash_assessment:
            cwe_list.append(crash_assessment["cwe"])

    score = min(max(round(score, 1), 0.0), 10.0)

    # Rating category
    if score >= 8.5:
        rating = "CRITICAL"
    elif score >= 6.5:
        rating = "HIGH"
    elif score >= 4.0:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    # Remediation recommendations
    remediation: list[str] = []
    if not mitigations["nx"]:
        remediation.append(
            "Compile with NX/DEP enabled (-z noexecstack on GCC/Clang, /NXCOMPAT on MSVC)."
        )
    if not mitigations["pie"]:
        remediation.append(
            "Enable Position Independent Executable (-fPIE -pie on GCC/Clang, /DYNAMICBASE on MSVC)."
        )
    if not mitigations["canary"]:
        remediation.append(
            "Enable Stack Canaries (-fstack-protector-strong on GCC/Clang, /GS on MSVC)."
        )
    for d in dangerous_calls_found[:3]:
        remediation.append(
            f"Replace unsafe '{d['api']}' with bounds-checked alternatives (e.g. strncpy, snprintf)."
        )

    recommended_tools = [
        {"tool": "build_rop_chain", "arguments": {"file_path": path_str}},
        {"tool": "vulnerability_hunter", "arguments": {"file_path": path_str}},
        {"tool": "generate_poc_exploit", "arguments": {"file_path": path_str}},
        {
            "tool": "call_expert_agent",
            "arguments": {
                "agent_name": "vulnerability_hunter",
                "task": "investigate ROP and heap exploit paths",
                "file_path": path_str,
            },
        },
    ]

    report = {
        "status": "success",
        "binary_path": path_str,
        "binary_name": validated_path.name,
        "exploitability_score": score,
        "exploitability_rating": rating,
        "mitigations": mitigations,
        "identified_cwes": list(dict.fromkeys(cwe_list)),
        "dangerous_apis_found": dangerous_calls_found,
        "crash_triage": crash_assessment,
        "target_analysis": target_function_details,
        "remediation_recommendations": remediation,
        "recommended_tools": recommended_tools,
    }

    return success(
        data=report,
        message=f"Vulnerability assessment for '{validated_path.name}': Score {score}/10.0 ({rating}).",
    )
