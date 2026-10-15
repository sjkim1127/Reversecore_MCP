"""Goal-aware analysis planner and tool recommendation subsystem.

Generates depth-tiered (quick, standard, deep) execution plans composed of
strictly existing Reversecore MCP tools based on sample metadata, file format,
architecture, objective, resource/time budget, and tool availability.
"""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from reversecore_mcp.core.loader import TOOL_PROFILES
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Enums and Normalization
# ---------------------------------------------------------------------------


class AnalysisObjective:
    STATIC_TRIAGE = "static_triage"
    MALWARE_TRIAGE = "malware_triage"
    VULNERABILITY_RESEARCH = "vulnerability_research"
    UNPACKING_DEOBFUSCATION = "unpacking_deobfuscation"
    INCIDENT_RECONSTRUCTION = "incident_reconstruction"
    PATCH_REVIEW = "patch_review"
    FORENSICS = "forensics"

    ALL = {
        STATIC_TRIAGE,
        MALWARE_TRIAGE,
        VULNERABILITY_RESEARCH,
        UNPACKING_DEOBFUSCATION,
        INCIDENT_RECONSTRUCTION,
        PATCH_REVIEW,
        FORENSICS,
    }


class DepthTier:
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"

    ALL = {QUICK, STANDARD, DEEP}


class SampleFormat:
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    PCAP = "pcap"
    MEMORY = "memory"
    DISK = "disk"
    SOURCE = "source"
    GENERIC = "generic"

    ALL = {PE, ELF, MACHO, PCAP, MEMORY, DISK, SOURCE, GENERIC}


def normalize_objective(value: str | None) -> str:
    """Normalize user objective string to standard AnalysisObjective."""
    if not value:
        return AnalysisObjective.MALWARE_TRIAGE
    v = value.strip().lower().replace("-", "_").replace(" ", "_")
    if v in AnalysisObjective.ALL:
        return v
    if "malware" in v or "threat" in v or "ransomware" in v:
        return AnalysisObjective.MALWARE_TRIAGE
    if "static" in v or "triage" in v or "fingerprint" in v:
        return AnalysisObjective.STATIC_TRIAGE
    if "vuln" in v or "cve" in v or "exploit" in v or "fuzz" in v:
        return AnalysisObjective.VULNERABILITY_RESEARCH
    if "unpack" in v or "deobf" in v or "packer" in v or "obfus" in v:
        return AnalysisObjective.UNPACKING_DEOBFUSCATION
    if "incident" in v or "reconstruct" in v or "breach" in v:
        return AnalysisObjective.INCIDENT_RECONSTRUCTION
    if "patch" in v or "diff" in v or "1day" in v or "variant" in v or "regression" in v:
        return AnalysisObjective.PATCH_REVIEW
    if "forensic" in v or "disk" in v or "artifact" in v:
        return AnalysisObjective.FORENSICS
    return AnalysisObjective.MALWARE_TRIAGE


def normalize_depth(value: str | None, time_budget_seconds: int | None = None) -> str:
    """Normalize depth tier, taking optional time budget into account."""
    if time_budget_seconds is not None:
        if time_budget_seconds <= 45:
            return DepthTier.QUICK
        if time_budget_seconds <= 180:
            return DepthTier.STANDARD
        return DepthTier.DEEP

    if not value:
        return DepthTier.STANDARD
    v = value.strip().lower()
    if v in DepthTier.ALL:
        return v
    if "quick" in v or "fast" in v or "light" in v or "shallow" in v:
        return DepthTier.QUICK
    if "deep" in v or "full" in v or "exhaust" in v or "thorough" in v:
        return DepthTier.DEEP
    return DepthTier.STANDARD


def detect_sample_format(
    target_path: Path | str | None = None,
    explicit_format: str | None = None,
    sample_hint: str | None = None,
) -> str:
    """Detect format from file content, extension, or hint."""
    if explicit_format:
        fmt = explicit_format.strip().lower().replace("-", "_")
        if fmt in SampleFormat.ALL:
            return fmt
        if "pe" in fmt or "exe" in fmt or "dll" in fmt:
            return SampleFormat.PE
        if "elf" in fmt or "so" in fmt:
            return SampleFormat.ELF
        if "mach" in fmt or "dylib" in fmt:
            return SampleFormat.MACHO
        if "pcap" in fmt or "network" in fmt:
            return SampleFormat.PCAP
        if "mem" in fmt or "dmp" in fmt or "vmem" in fmt:
            return SampleFormat.MEMORY
        if "disk" in fmt or "img" in fmt or "vmdk" in fmt or "mft" in fmt:
            return SampleFormat.DISK
        if "src" in fmt or "source" in fmt or "c" == fmt or "cpp" == fmt:
            return SampleFormat.SOURCE

    path = Path(target_path) if target_path else None
    if path:
        suffix = path.suffix.lower()
        if suffix in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".py", ".go", ".rs", ".java"):
            return SampleFormat.SOURCE
        if suffix in (".pcap", ".pcapng", ".cap"):
            return SampleFormat.PCAP
        if suffix in (".dmp", ".raw", ".vmem") and "mem" in path.name.lower():
            return SampleFormat.MEMORY
        if suffix in (".img", ".iso", ".dd", ".vmdk"):
            return SampleFormat.DISK

        if path.exists() and path.is_file():
            try:
                with path.open("rb") as f:
                    header = f.read(16)
                if header.startswith(b"MZ"):
                    return SampleFormat.PE
                if header.startswith(b"\x7fELF"):
                    return SampleFormat.ELF
                if header.startswith(
                    (
                        b"\xfe\xed\xfa\xce",
                        b"\xfe\xed\xfa\xcf",
                        b"\xce\xfa\xed\xfe",
                        b"\xcf\xfa\xed\xfe",
                    )
                ):
                    return SampleFormat.MACHO
                if header.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\n\r\r\n")):
                    return SampleFormat.PCAP
            except OSError:
                pass

        if suffix in (".exe", ".dll", ".sys", ".scr", ".ocx"):
            return SampleFormat.PE
        if suffix in (".so", ".elf", ".bin"):
            return SampleFormat.ELF
        if suffix in (".dylib", ".macho"):
            return SampleFormat.MACHO

    if sample_hint:
        h = sample_hint.lower()
        if "source" in h or "c code" in h or "audit" in h:
            return SampleFormat.SOURCE
        if "pcap" in h or "packet" in h or "network" in h:
            return SampleFormat.PCAP
        if "mem" in h or "memory" in h or "ram" in h:
            return SampleFormat.MEMORY
        if "disk" in h or "filesystem" in h:
            return SampleFormat.DISK
        if "pe" in h or "exe" in h or "dll" in h:
            return SampleFormat.PE
        if "mach" in h or "macos" in h or "dylib" in h:
            return SampleFormat.MACHO
        if "elf" in h or "linux" in h or ".so" in h or "shared object" in h:
            return SampleFormat.ELF

    return SampleFormat.PE


# ---------------------------------------------------------------------------
# Tool Metadata & Dependency Registry
# ---------------------------------------------------------------------------

TOOL_PLUGIN_MAP: dict[str, str] = {
    # common_tools
    "run_file": "common_tools",
    "run_strings": "common_tools",
    "batch_execute": "common_tools",
    "explain_patch": "common_tools",
    "list_workspace": "common_tools",
    "copy_to_workspace": "common_tools",
    "create_directory": "common_tools",
    "scan_workspace": "common_tools",
    "transaction_begin": "common_tools",
    "transaction_commit": "common_tools",
    "transaction_rollback": "common_tools",
    "transaction_status": "common_tools",
    "transaction_undo": "common_tools",
    "transaction_redo": "common_tools",
    "recommend_analysis_plan": "common_tools",
    # server_tools
    "get_server_health": "server_tools",
    "get_tool_metrics": "server_tools",
    # analysis_tools
    "parse_binary_with_lief": "analysis_tools",
    "detect_packer": "analysis_tools",
    "detect_packer_deep": "analysis_tools",
    "packer_fingerprint": "analysis_tools",
    "run_capa": "analysis_tools",
    "run_capa_quick": "analysis_tools",
    "extract_iocs": "analysis_tools",
    "extract_rtti_info": "analysis_tools",
    "generate_signature": "analysis_tools",
    "diff_binaries": "analysis_tools",
    "analyze_patch_diff_auto": "analysis_tools",
    "patch_diff_1day": "analysis_tools",
    "analyze_variant_changes": "analysis_tools",
    "run_binwalk": "analysis_tools",
    "run_binwalk_extract": "analysis_tools",
    "scan_for_versions": "analysis_tools",
    "match_libraries": "analysis_tools",
    # source_auditor
    "audit_source_code": "source_auditor",
    # radare2_mcp_tools
    "run_radare2": "radare2_mcp_tools",
    "Radare2_open_file": "radare2_mcp_tools",
    "Radare2_close_file": "radare2_mcp_tools",
    "Radare2_analyze": "radare2_mcp_tools",
    "Radare2_disassemble": "radare2_mcp_tools",
    "Radare2_disassemble_function": "radare2_mcp_tools",
    "Radare2_decompile_function": "radare2_mcp_tools",
    "Radare2_list_functions": "radare2_mcp_tools",
    "Radare2_list_sections": "radare2_mcp_tools",
    "Radare2_list_imports": "radare2_mcp_tools",
    "Radare2_list_symbols": "radare2_mcp_tools",
    "Radare2_list_strings": "radare2_mcp_tools",
    "Radare2_list_classes": "radare2_mcp_tools",
    "Radare2_show_headers": "radare2_mcp_tools",
    "Radare2_xrefs_to": "radare2_mcp_tools",
    "r2_analyze_function": "radare2_mcp_tools",
    "r2_decompile": "radare2_mcp_tools",
    "r2_recover_structures": "radare2_mcp_tools",
    "r2_get_call_graph": "radare2_mcp_tools",
    "r2_read_memory": "radare2_mcp_tools",
    "r2_simulate_patch": "radare2_mcp_tools",
    "r2_list_types": "radare2_mcp_tools",
    "emulate_binary": "radare2_mcp_tools",
    # malware_tools
    "run_yara": "malware_tools",
    "generate_yara_rule": "malware_tools",
    "generate_enhanced_yara_rule": "malware_tools",
    "detect_anti_analysis": "malware_tools",
    "dormant_detector": "malware_tools",
    "adaptive_vaccine": "malware_tools",
    "vulnerability_hunter": "malware_tools",
    "build_rop_chain": "malware_tools",
    "generate_poc_exploit": "malware_tools",
    # deobfuscation_tools
    "run_deobfuscation_pipeline": "deobfuscation_tools",
    "deobfuscate_strings": "deobfuscation_tools",
    "resolve_api_hashes": "deobfuscation_tools",
    "eliminate_dead_code": "deobfuscation_tools",
    # cve_hunter_tools
    "hunt_cve_vulnerabilities": "cve_hunter_tools",
    "analyze_heap_exploit": "cve_hunter_tools",
    "cve_triage_crash": "cve_hunter_tools",
    "cve_synthesize_harness": "cve_hunter_tools",
    "cve_minimize_poc": "cve_hunter_tools",
    "cve_fuzz_target": "cve_hunter_tools",
    # forensics_tools
    "artifact_collect": "forensics_tools",
    "artifact_correlate_ioc": "forensics_tools",
    "artifact_timeline": "forensics_tools",
    "artifact_generate_yara": "forensics_tools",
    "pcap_analyze": "forensics_tools",
    "pcap_list_connections": "forensics_tools",
    "pcap_extract_dns": "forensics_tools",
    "pcap_extract_c2": "forensics_tools",
    "pcap_reconstruct_stream": "forensics_tools",
    "disk_list_partition": "forensics_tools",
    "disk_list_files": "forensics_tools",
    "disk_analyze_mft": "forensics_tools",
    "disk_extract_file": "forensics_tools",
    "disk_recover_deleted": "forensics_tools",
    "disk_hash_verify": "forensics_tools",
    # memory_tools
    "memory_analyze": "memory_tools",
    "memory_list_processes": "memory_tools",
    "memory_detect_injections": "memory_tools",
    "memory_dump_module": "memory_tools",
    # report_tools
    "create_analysis_report": "report_tools",
    "generate_vex_report": "report_tools",
    "generate_sigma_rule": "report_tools",
}

TOOL_DEPENDENCIES: dict[str, list[str]] = {
    "run_file": ["file"],
    "run_strings": ["strings"],
    "parse_binary_with_lief": ["lief"],
    "detect_packer": [],
    "detect_packer_deep": ["radare2"],
    "packer_fingerprint": [],
    "run_capa": ["capa"],
    "run_capa_quick": ["capa"],
    "run_yara": ["yara"],
    "generate_yara_rule": ["yara"],
    "generate_enhanced_yara_rule": ["yara"],
    "artifact_generate_yara": ["yara"],
    "detect_anti_analysis": [],
    "dormant_detector": ["radare2"],
    "adaptive_vaccine": [],
    "run_binwalk": ["binwalk"],
    "run_binwalk_extract": ["binwalk"],
    "Radare2_list_imports": ["radare2"],
    "Radare2_list_sections": ["radare2"],
    "Radare2_list_symbols": ["radare2"],
    "Radare2_list_functions": ["radare2"],
    "Radare2_show_headers": ["radare2"],
    "Radare2_xrefs_to": ["radare2"],
    "Radare2_list_classes": ["radare2"],
    "Radare2_disassemble_function": ["radare2"],
    "r2_analyze_function": ["radare2"],
    "r2_decompile": ["radare2"],
    "r2_recover_structures": ["radare2"],
    "r2_get_call_graph": ["radare2"],
    "r2_read_memory": ["radare2"],
    "r2_simulate_patch": ["radare2"],
    "r2_list_types": ["radare2"],
    "emulate_binary": ["radare2"],
    "diff_binaries": ["radare2"],
    "analyze_patch_diff_auto": ["radare2"],
    "patch_diff_1day": ["radare2"],
    "analyze_variant_changes": ["radare2"],
    "vulnerability_hunter": ["radare2"],
    "build_rop_chain": ["ropgadget"],
    "cve_fuzz_target": ["afl-fuzz"],
    "pcap_analyze": [],
    "memory_analyze": ["volatility"],
}

TOOL_FALLBACKS: dict[str, str] = {
    "run_capa_quick": "extract_iocs",
    "run_capa": "Radare2_list_imports",
    "detect_packer_deep": "detect_packer",
    "build_rop_chain": "Radare2_disassemble_function",
    "run_binwalk": "run_strings",
    "run_binwalk_extract": "run_strings",
    "r2_decompile": "Radare2_disassemble_function",
    "cve_fuzz_target": "hunt_cve_vulnerabilities",
    "memory_analyze": "memory_list_processes",
}


def check_dependency(dep: str) -> bool:
    """Check if external dependency or Python package is present."""
    d = dep.strip().lower()
    if d in ("radare2", "r2"):
        return shutil.which("radare2") is not None or shutil.which("r2") is not None
    if d == "lief":
        return importlib.util.find_spec("lief") is not None
    if d == "capa":
        return importlib.util.find_spec("capa") is not None or shutil.which("capa") is not None
    if d == "yara":
        return importlib.util.find_spec("yara") is not None or shutil.which("yara") is not None
    if d == "binwalk":
        return shutil.which("binwalk") is not None
    if d == "file":
        return shutil.which("file") is not None
    if d == "strings":
        return shutil.which("strings") is not None
    if d in ("ropgadget", "rop_gadget"):
        return shutil.which("ROPgadget") is not None
    if d in ("afl", "afl-fuzz"):
        return shutil.which("afl-fuzz") is not None
    if d in ("volatility", "vol"):
        return shutil.which("vol") is not None or shutil.which("volatility") is not None
    return True


def is_tool_allowed_in_profile(tool_name: str, profile: str | None = None) -> bool:
    """Check whether a tool is allowed under the given or default profile."""
    if not profile or profile == "full":
        return True
    prof = profile.strip().lower()
    allowed_plugins = TOOL_PROFILES.get(prof)
    if allowed_plugins is None:
        return True
    plugin = TOOL_PLUGIN_MAP.get(tool_name)
    if not plugin:
        return True
    return plugin in allowed_plugins


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PlanStep(BaseModel):
    step: int
    phase: str
    tool: str
    purpose: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    cost: str = "medium"  # low, medium, high
    required_dependencies: list[str] = Field(default_factory=list)
    available: bool = True
    missing_dependency: str | None = None
    alternative_tool: str | None = None


class PlanBranch(BaseModel):
    trigger_condition: str
    rationale: str
    recommended_tools: list[str]
    stop_condition: str


class AnalysisPlan(BaseModel):
    objective: str
    depth: str
    sample_format: str
    architecture: str
    active_profile: str
    estimated_budget_seconds: int
    primary_steps: list[PlanStep]
    conditional_branches: list[PlanBranch]
    stop_conditions: list[str]
    missing_dependencies: list[str]
    tool_coverage_summary: dict[str, int]


# ---------------------------------------------------------------------------
# Step Definitions & Pipelines
# ---------------------------------------------------------------------------

# Raw template definition: (tool, phase, purpose, cost, default_args_fn)
StepDef = tuple[str, str, str, str, dict[str, Any]]


def _build_step(
    step_num: int,
    tool: str,
    phase: str,
    purpose: str,
    cost: str,
    params: dict[str, Any],
    profile: str,
) -> PlanStep:
    req_deps = TOOL_DEPENDENCIES.get(tool, [])
    missing_dep: str | None = None
    available = True

    # Check profile membership
    if not is_tool_allowed_in_profile(tool, profile):
        available = False
        missing_dep = f"Tool '{tool}' not included in active profile '{profile}'"

    # Check external dependencies
    if available:
        for dep in req_deps:
            if not check_dependency(dep):
                available = False
                missing_dep = f"Missing required external dependency '{dep}'"
                break

    alt = TOOL_FALLBACKS.get(tool) if not available else None

    return PlanStep(
        step=step_num,
        phase=phase,
        tool=tool,
        purpose=purpose,
        parameters=params,
        cost=cost,
        required_dependencies=req_deps,
        available=available,
        missing_dependency=missing_dep,
        alternative_tool=alt,
    )


def _get_pipelines(
    fmt: str,
    obj: str,
    target_file: str,
) -> tuple[list[StepDef], list[StepDef], list[StepDef], list[PlanBranch], list[str]]:
    """Return (quick_steps, standard_additional_steps, deep_additional_steps, branches, stop_conditions).

    Nested scope invariant is guaranteed:
      quick    = quick_steps
      standard = quick_steps + standard_additional_steps
      deep     = quick_steps + standard_additional_steps + deep_additional_steps
    """
    farg: dict[str, Any] = {"file_path": target_file} if target_file else {}
    quick: list[StepDef] = []
    standard_add: list[StepDef] = []
    deep_add: list[StepDef] = []

    # 1. Specialized Non-Binary Formats
    if fmt == SampleFormat.SOURCE:
        quick = [
            (
                "audit_source_code",
                "identification",
                "Static audit of source files for dangerous functions and sinks",
                "low",
                {"source_path": target_file or "."},
            ),
            (
                "hunt_cve_vulnerabilities",
                "vulnerability",
                "Identify known CVE patterns and AST flaws in source tree",
                "low",
                {"target_path": target_file or "."},
            ),
        ]
        standard_add = [
            (
                "extract_iocs",
                "artifacts",
                "Extract embedded IPs, URLs, tokens, and hardcoded credentials",
                "low",
                farg,
            ),
            (
                "cve_synthesize_harness",
                "verification",
                "Synthesize reproducible fuzz harness for vulnerable sinks",
                "medium",
                {"source_file": target_file or "main.c"},
            ),
        ]
        deep_add = [
            (
                "cve_fuzz_target",
                "fuzzing",
                "Launch localized hybrid fuzzing to prove vulnerability reachability",
                "high",
                {"target": target_file or "a.out"},
            ),
            (
                "generate_poc_exploit",
                "exploit",
                "Synthesize weaponized or non-destructive PoC verification script",
                "high",
                {"vulnerability_details": "Buffer overflow in target function"},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate structured vulnerability audit and remediation report",
                "low",
                {"title": "Source Code Security Audit"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_critical_sink_identified",
                rationale="Unsafe memory manipulation or command execution sink found",
                recommended_tools=["cve_synthesize_harness", "generate_poc_exploit"],
                stop_condition="PoC reproducer verified or safe boundary patch proposed",
            )
        ]
        stop = [
            "Stop if source code clean and no high/critical CWE signatures found",
            "Stop when root cause of identified flaw is documented with diff",
        ]
        return quick, standard_add, deep_add, branches, stop

    if fmt == SampleFormat.PCAP:
        quick = [
            (
                "pcap_analyze",
                "identification",
                "Fast packet capture overview, protocol breakdown, and conversation summary",
                "low",
                {"pcap_path": target_file or "capture.pcap"},
            ),
            (
                "extract_iocs",
                "artifacts",
                "Carve IP addresses, hostnames, URIs, and user-agents from capture",
                "low",
                farg,
            ),
        ]
        standard_add = [
            (
                "pcap_list_connections",
                "traffic",
                "Enumerate TCP/UDP sessions, byte counters, and timing anomalies",
                "low",
                {"pcap_path": target_file or "capture.pcap"},
            ),
            (
                "pcap_extract_dns",
                "dns",
                "Extract DNS queries, NXDOMAIN patterns, and DGA indicators",
                "low",
                {"pcap_path": target_file or "capture.pcap"},
            ),
            (
                "artifact_timeline",
                "timeline",
                "Synthesize chronological network activity timeline",
                "medium",
                {"session_id": "current"},
            ),
        ]
        deep_add = [
            (
                "pcap_extract_c2",
                "c2",
                "Analyze beaconing intervals, periodic keepalives, and suspicious C2 handshakes",
                "medium",
                {"pcap_path": target_file or "capture.pcap"},
            ),
            (
                "pcap_reconstruct_stream",
                "reassembly",
                "Reconstruct and carve transmitted binaries or dropped payloads",
                "high",
                {"pcap_path": target_file or "capture.pcap", "stream_id": 0},
            ),
            (
                "run_file",
                "payload_triage",
                "Fingerprint carved payloads extracted from network streams",
                "low",
                {"file_path": "carved_payload.bin"},
            ),
            (
                "artifact_generate_yara",
                "signature",
                "Generate threat hunting YARA signatures from extracted network artifacts",
                "medium",
                {"artifact_type": "network"},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate formal incident network reconstruction report",
                "low",
                {"title": "PCAP Network Incident Triage"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_carved_payload_present",
                rationale="Reconstructed stream contains executable or script payload",
                recommended_tools=["run_file", "detect_packer", "run_capa_quick"],
                stop_condition="Carved payload extracted, hashed, and classified",
            ),
            PlanBranch(
                trigger_condition="if_dga_or_c2_confirmed",
                rationale="High-frequency DNS queries or repetitive TLS beacons detected",
                recommended_tools=["pcap_extract_c2", "artifact_generate_yara"],
                stop_condition="C2 infrastructure list documented",
            ),
        ]
        stop = [
            "Stop if capture consists entirely of authorized baseline protocols",
            "Stop when all external C2 endpoints and carved files are triaged",
        ]
        return quick, standard_add, deep_add, branches, stop

    if fmt == SampleFormat.MEMORY:
        quick = [
            (
                "memory_list_processes",
                "processes",
                "List running processes, parentage, PIDs, and command lines from dump",
                "medium",
                {"dump_path": target_file or "memory.raw"},
            ),
            (
                "extract_iocs",
                "artifacts",
                "Extract network and path indicators directly from memory dump",
                "low",
                farg,
            ),
        ]
        standard_add = [
            (
                "memory_analyze",
                "triage",
                "Execute Volatility kernel analysis and detect anomalous rootkits/hooks",
                "medium",
                {"dump_path": target_file or "memory.raw"},
            ),
            (
                "memory_detect_injections",
                "injection",
                "Scan for hollowed processes, injected DLLs, and RWX memory sections",
                "high",
                {"dump_path": target_file or "memory.raw"},
            ),
            (
                "artifact_timeline",
                "timeline",
                "Correlate process creation timestamps and thread lifecycles",
                "medium",
                {"session_id": "current"},
            ),
        ]
        deep_add = [
            (
                "memory_dump_module",
                "carving",
                "Dump suspicious hollowed process memory or injected PE to disk",
                "high",
                {"dump_path": target_file or "memory.raw", "pid": 0},
            ),
            (
                "run_file",
                "carved_triage",
                "Classify dumped injected module",
                "low",
                {"file_path": "dumped_module.bin"},
            ),
            (
                "detect_packer",
                "packing",
                "Determine if injected module is packed or encrypted",
                "low",
                {"file_path": "dumped_module.bin"},
            ),
            (
                "run_yara",
                "signature_scan",
                "Scan dumped processes with YARA rules for in-memory malware signatures",
                "medium",
                {"rule_path": "malware.yar", "target_path": "dumped_module.bin"},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate structured memory forensics incident report",
                "low",
                {"title": "Memory Forensics Triage"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_injected_code_detected",
                rationale="Process hollowing or reflective DLL injection detected in target PID",
                recommended_tools=["memory_dump_module", "run_file", "run_yara"],
                stop_condition="Injected module dumped and family identified",
            )
        ]
        stop = [
            "Stop if all processes and DLL signatures correspond to verified clean OS binaries",
            "Stop once suspicious memory regions are dumped and cataloged",
        ]
        return quick, standard_add, deep_add, branches, stop

    if fmt == SampleFormat.DISK:
        quick = [
            (
                "disk_hash_verify",
                "integrity",
                "Compute MD5/SHA256 image hashes and verify acquisition integrity",
                "low",
                {"image_path": target_file or "disk.img"},
            ),
            (
                "disk_list_partition",
                "partitioning",
                "Parse master boot record / GPT partition layout",
                "low",
                {"image_path": target_file or "disk.img"},
            ),
        ]
        standard_add = [
            (
                "disk_list_files",
                "file_system",
                "Enumerate filesystem directories, attributes, and file allocations",
                "medium",
                {"image_path": target_file or "disk.img", "path": "/"},
            ),
            (
                "disk_analyze_mft",
                "mft",
                "Parse NTFS MFT records for $STANDARD_INFORMATION and $FILE_NAME timestamps",
                "medium",
                {"image_path": target_file or "disk.img"},
            ),
            (
                "extract_iocs",
                "artifacts",
                "Carve indicators from master file table entries",
                "low",
                farg,
            ),
        ]
        deep_add = [
            (
                "disk_recover_deleted",
                "carving",
                "Recover deleted executables, documents, or event logs from unallocated sectors",
                "high",
                {"image_path": target_file or "disk.img", "inode": 0},
            ),
            (
                "run_file",
                "triage_recovered",
                "Identify file type of carved unallocated clusters",
                "low",
                {"file_path": "recovered.bin"},
            ),
            (
                "artifact_timeline",
                "timeline",
                "Synthesize filesystem super-timeline correlating MACB timestamps",
                "high",
                {"session_id": "current"},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate forensic disk examination report",
                "low",
                {"title": "Disk Forensics Artifact Analysis"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_deleted_malware_identified",
                rationale="Unallocated cluster contains executable signatures",
                recommended_tools=["disk_recover_deleted", "run_file", "extract_iocs"],
                stop_condition="Deleted artifact successfully carved and analyzed",
            )
        ]
        stop = [
            "Stop if no deleted or anomalous filesystem entries exist",
            "Stop when all target evidence inodes have been recovered",
        ]
        return quick, standard_add, deep_add, branches, stop

    # 2. Executable Formats (PE, ELF, MACHO, GENERIC) by Objective
    if obj == AnalysisObjective.STATIC_TRIAGE:
        quick = [
            (
                "run_file",
                "identification",
                "Determine binary format, architecture, bitness, endianness, and hashes",
                "low",
                farg,
            ),
            (
                "parse_binary_with_lief",
                "structure",
                "Parse headers, section boundaries, entrypoint, and data directories",
                "low",
                farg,
            ),
            (
                "run_strings",
                "strings",
                "Extract ASCII and UTF-16 strings to spot paths, URLs, and clues",
                "low",
                farg,
            ),
            (
                "extract_iocs",
                "artifacts",
                "Carve structured IOCs (IPs, URLs, domains, hashes)",
                "low",
                farg,
            ),
        ]
        standard_add = [
            (
                "Radare2_list_sections",
                "sections",
                "Analyze section permissions (RWX anomalies) and entropy",
                "low",
                farg,
            ),
            (
                "Radare2_list_imports",
                "imports",
                "Inspect imported API libraries to identify capabilities and intents",
                "low",
                farg,
            ),
            (
                "Radare2_list_symbols",
                "symbols",
                "Enumerate exported functions and symbols",
                "low",
                farg,
            ),
            (
                "Radare2_list_functions",
                "functions",
                "Catalog discovered function boundaries and call targets",
                "medium",
                farg,
            ),
            (
                "run_capa_quick",
                "capabilities",
                "Quick capability detection for ATT&CK techniques",
                "medium",
                farg,
            ),
        ]
        deep_add = [
            (
                "Radare2_show_headers",
                "headers",
                "Detailed header flags, optional header characteristics, and security mitigations",
                "low",
                farg,
            ),
            (
                "extract_rtti_info",
                "classes",
                "Recover C++ RTTI class hierarchies and vtables",
                "medium",
                farg,
            ),
            (
                "r2_list_types",
                "types",
                "Inspect discovered data structures, enums, and types",
                "low",
                farg,
            ),
            (
                "r2_recover_structures",
                "structures",
                "Automatically infer struct offsets and member alignments",
                "medium",
                farg,
            ),
            (
                "r2_decompile",
                "decompilation",
                "Decompile entrypoint and high-complexity functions via r2ghidra",
                "high",
                {"function": "main", **farg},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate comprehensive static triage report",
                "low",
                {"title": "Static Binary Triage Report"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_high_entropy_sections",
                rationale="Section entropy > 7.0 suggests packing or encrypted data",
                recommended_tools=["detect_packer", "run_binwalk"],
                stop_condition="Packing verified or payload identified",
            ),
            PlanBranch(
                trigger_condition="if_rtti_structures_detected",
                rationale="C++ virtual dispatch requires class mapping",
                recommended_tools=["extract_rtti_info", "Radare2_list_classes"],
                stop_condition="Object models and methods mapped",
            ),
        ]
        stop = [
            "Stop if binary is a standard non-malicious system utility",
            "Stop once sections, imports, and function lists are cataloged",
        ]
        return quick, standard_add, deep_add, branches, stop

    if obj == AnalysisObjective.VULNERABILITY_RESEARCH:
        quick = [
            (
                "run_file",
                "identification",
                "Inspect target binary architecture, bitness, and security mitigations",
                "low",
                farg,
            ),
            (
                "parse_binary_with_lief",
                "mitigations",
                "Check ASLR, DEP/NX, Stack Canaries, and SafeSEH protections",
                "low",
                farg,
            ),
            (
                "vulnerability_hunter",
                "sink_detection",
                "Scan for dangerous API sinks (strcpy, gets, sprintf, memcpy, system)",
                "low",
                farg,
            ),
            (
                "hunt_cve_vulnerabilities",
                "known_cves",
                "Match known public CVE patterns and vulnerable third-party components",
                "low",
                farg,
            ),
        ]
        standard_add = [
            (
                "Radare2_list_imports",
                "imports",
                "Catalog external library imports and dangerous memory/exec APIs",
                "low",
                farg,
            ),
            (
                "Radare2_list_functions",
                "functions",
                "Rank functions by cyclomatic complexity and cross-references",
                "medium",
                farg,
            ),
            (
                "analyze_heap_exploit",
                "heap_audit",
                "Assess heap layout, chunk management, and heap corruption primitives",
                "medium",
                farg,
            ),
            (
                "r2_analyze_function",
                "disassembly",
                "Analyze control flow graph of functions containing sinks",
                "medium",
                {"function": "main", **farg},
            ),
            (
                "r2_decompile",
                "decompilation",
                "Decompile candidate vulnerable functions for boundary audit",
                "high",
                {"function": "main", **farg},
            ),
        ]
        deep_add = [
            (
                "build_rop_chain",
                "exploitation",
                "Search for ROP gadgets to construct exploit payload chain",
                "high",
                farg,
            ),
            (
                "cve_synthesize_harness",
                "fuzzing_prep",
                "Generate automated fuzzing harness targeting vulnerable functions",
                "high",
                {"source_file": "harness.c"},
            ),
            (
                "cve_fuzz_target",
                "fuzzing",
                "Execute targeted hybrid fuzzing campaign to trigger crashes",
                "high",
                {"target": target_file or "target"},
            ),
            (
                "generate_poc_exploit",
                "poc",
                "Generate functional proof-of-concept exploit verifying the flaw",
                "high",
                {"vulnerability_details": "Stack buffer overflow"},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate vulnerability assessment and CVSS remediation report",
                "low",
                {"title": "Vulnerability Assessment Report"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_crash_reproduced",
                rationale="Crash dump or sanitizer fault triggered during analysis",
                recommended_tools=["cve_triage_crash", "cve_minimize_poc"],
                stop_condition="Crash root-caused and reproducible PoC created",
            ),
            PlanBranch(
                trigger_condition="if_memory_sink_reachable",
                rationale="Data flow from user input reaches unbounded memory copy",
                recommended_tools=[
                    "analyze_heap_exploit",
                    "build_rop_chain",
                    "generate_poc_exploit",
                ],
                stop_condition="Control flow hijack or information leak proven",
            ),
        ]
        stop = [
            "Stop if all input vectors strictly enforce length limits and sanitization",
            "Stop once reproducible PoC and CVSS severity score are established",
        ]
        return quick, standard_add, deep_add, branches, stop

    if obj == AnalysisObjective.UNPACKING_DEOBFUSCATION:
        quick = [
            (
                "run_file",
                "identification",
                "Inspect file headers, bitness, and initial characteristics",
                "low",
                farg,
            ),
            (
                "detect_packer",
                "packer_scan",
                "Scan binary against known packer signatures and section entropy",
                "low",
                farg,
            ),
            (
                "packer_fingerprint",
                "fingerprint",
                "Identify specific packer variant (UPX, Themida, VMProtect, ASPack)",
                "low",
                farg,
            ),
            (
                "parse_binary_with_lief",
                "sections",
                "Check entrypoint outside known code section or anomalous section names",
                "low",
                farg,
            ),
        ]
        standard_add = [
            (
                "detect_packer_deep",
                "deep_packing",
                "Perform deep heuristic unpacking inspection and stub analysis",
                "medium",
                farg,
            ),
            (
                "deobfuscate_strings",
                "string_decrypt",
                "Identify and decrypt XOR, RC4, or Base64 obfuscated strings",
                "medium",
                farg,
            ),
            (
                "resolve_api_hashes",
                "api_hashing",
                "Resolve ROR13, CRC32, Murmur, or custom API hashes to function names",
                "medium",
                farg,
            ),
            (
                "Radare2_list_sections",
                "entropy_map",
                "Map high-entropy sections and virtual/raw size discrepancies",
                "low",
                farg,
            ),
            (
                "run_binwalk",
                "overlay_scan",
                "Scan for compressed archives, payloads, or embedded executable overlays",
                "medium",
                farg,
            ),
        ]
        deep_add = [
            (
                "eliminate_dead_code",
                "control_flow",
                "Eliminate opaque predicates and unflatten obfuscated control flow",
                "high",
                farg,
            ),
            (
                "run_deobfuscation_pipeline",
                "pipeline",
                "Execute end-to-end string, API, and control flow deobfuscation",
                "high",
                farg,
            ),
            (
                "emulate_binary",
                "emulation",
                "Emulate unpacker stub execution in ESIL until OEP jump",
                "high",
                {"instructions": 5000, **farg},
            ),
            (
                "r2_read_memory",
                "dump_oep",
                "Dump unpacked memory pages from emulated process space",
                "medium",
                {"address": "0x400000", "size": 4096, **farg},
            ),
            (
                "run_binwalk_extract",
                "extraction",
                "Extract carved nested binaries and embedded files",
                "high",
                farg,
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate detailed unpacking and deobfuscation report",
                "low",
                {"title": "Unpacking and Deobfuscation Report"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_upx_or_standard_packer",
                rationale="Standard packer signature identified",
                recommended_tools=["detect_packer_deep", "run_binwalk_extract"],
                stop_condition="Payload unpacked and OEP recovered",
            ),
            PlanBranch(
                trigger_condition="if_api_hashing_detected",
                rationale="Dynamic API resolution via hash found in imports/strings",
                recommended_tools=["resolve_api_hashes", "deobfuscate_strings"],
                stop_condition="Target APIs resolved and renamed",
            ),
        ]
        stop = [
            "Stop if binary is confirmed non-packed plaintext executable",
            "Stop once Original Entry Point (OEP) is dumped and valid PE/ELF restored",
        ]
        return quick, standard_add, deep_add, branches, stop

    if obj == AnalysisObjective.PATCH_REVIEW:
        quick = [
            (
                "run_file",
                "identification",
                "Inspect target binary architecture and metadata",
                "low",
                farg,
            ),
            (
                "parse_binary_with_lief",
                "structure",
                "Verify section alignment and export tables",
                "low",
                farg,
            ),
            (
                "diff_binaries",
                "initial_diff",
                "Compute coarse binary diff, section changes, and byte similarity",
                "medium",
                {"file_a": target_file or "v1.bin", "file_b": "v2.bin"},
            ),
        ]
        standard_add = [
            (
                "analyze_patch_diff_auto",
                "patch_diff",
                "Perform automated function-level CFG diffing between pre/post patch",
                "high",
                {"file_a": target_file or "v1.bin", "file_b": "v2.bin"},
            ),
            (
                "patch_diff_1day",
                "1day_triage",
                "Evaluate 1-day vulnerability fix characteristics in modified basic blocks",
                "high",
                {"file_a": target_file or "v1.bin", "file_b": "v2.bin"},
            ),
            (
                "analyze_variant_changes",
                "variant_diff",
                "Analyze variant modifications across related target binaries",
                "medium",
                {"file_a": target_file or "v1.bin", "file_b": "v2.bin"},
            ),
            (
                "explain_patch",
                "explanation",
                "Provide human-readable explanation of security significance of patch",
                "low",
                {"patch_description": "Bounds check addition"},
            ),
        ]
        deep_add = [
            (
                "Radare2_disassemble_function",
                "disassembly",
                "Disassemble modified functions side-by-side",
                "medium",
                {"function": "patched_func", **farg},
            ),
            (
                "r2_decompile",
                "decompilation",
                "Decompile pre- and post-patch functions for source-level comparison",
                "high",
                {"function": "patched_func", **farg},
            ),
            (
                "r2_simulate_patch",
                "simulation",
                "Simulate patch semantics under ESIL to verify bug mitigation",
                "high",
                {"patch_hex": "9090", **farg},
            ),
            (
                "generate_signature",
                "signatures",
                "Generate robust function signatures for modified routines",
                "medium",
                farg,
            ),
            (
                "generate_vex_report",
                "vex",
                "Generate Vulnerability Exploitability eXchange (VEX) advisory",
                "low",
                {"vulnerability_id": "CVE-PENDING"},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate formal patch differential security review",
                "low",
                {"title": "Patch Differential Analysis Report"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_boundary_check_added",
                rationale="Newly inserted condition verifies pointer or array bound",
                recommended_tools=["explain_patch", "r2_simulate_patch", "generate_vex_report"],
                stop_condition="Vulnerability mechanism and exploitability determined",
            )
        ]
        stop = [
            "Stop if diff reveals only non-functional metadata or compiler flag variations",
            "Stop once patch fix efficacy is verified and VEX report generated",
        ]
        return quick, standard_add, deep_add, branches, stop

    if obj == AnalysisObjective.FORENSICS or obj == AnalysisObjective.INCIDENT_RECONSTRUCTION:
        quick = [
            (
                "run_file",
                "identification",
                "Fingerprint forensic sample, compute baseline hashes and file type",
                "low",
                farg,
            ),
            (
                "disk_hash_verify",
                "integrity",
                "Verify image/artifact hash integrity against custody chain",
                "low",
                {"image_path": target_file or "artifact.raw"},
            ),
            (
                "artifact_collect",
                "collection",
                "Collect file metadata, hashes, entropy, and triage signatures",
                "low",
                farg,
            ),
            (
                "extract_iocs",
                "artifacts",
                "Carve network IPs, domains, paths, and user indicators",
                "low",
                farg,
            ),
        ]
        standard_add = [
            (
                "disk_list_files",
                "filesystem",
                "Enumerate filesystem entries and timestamp metadata",
                "medium",
                {"image_path": target_file or "artifact.raw"},
            ),
            (
                "pcap_analyze",
                "network",
                "Analyze captured network sessions if PCAP evidence present",
                "medium",
                {"pcap_path": "capture.pcap"},
            ),
            (
                "memory_analyze",
                "memory",
                "Inspect memory artifacts for injected modules or anomalies",
                "medium",
                {"dump_path": "memory.raw"},
            ),
            (
                "artifact_timeline",
                "timeline",
                "Synthesize unified multi-source timeline of incident events",
                "medium",
                {"session_id": "current"},
            ),
            (
                "artifact_correlate_ioc",
                "correlation",
                "Correlate extracted indicators against known threat feeds",
                "low",
                {"ioc": "192.168.1.1"},
            ),
        ]
        deep_add = [
            (
                "disk_analyze_mft",
                "mft_analysis",
                "Deep NTFS MFT analysis of timestomping and deleted entries",
                "high",
                {"image_path": target_file or "artifact.raw"},
            ),
            (
                "disk_recover_deleted",
                "carving",
                "Recover deleted files from unallocated clusters",
                "high",
                {"image_path": target_file or "artifact.raw", "inode": 0},
            ),
            (
                "memory_detect_injections",
                "injection_hunt",
                "Hunt reflective DLL and shellcode injections in active processes",
                "high",
                {"dump_path": "memory.raw"},
            ),
            (
                "pcap_extract_c2",
                "c2_hunting",
                "Identify automated C2 beacons and encrypted communication channels",
                "medium",
                {"pcap_path": "capture.pcap"},
            ),
            (
                "artifact_generate_yara",
                "signature",
                "Generate threat hunting YARA signatures from incident artifacts",
                "medium",
                {"artifact_type": "disk"},
            ),
            (
                "generate_sigma_rule",
                "siem_rules",
                "Generate SIEM detection rules for identified adversary behavior",
                "low",
                {"title": "Incident Adversary Activity"},
            ),
            (
                "create_analysis_report",
                "reporting",
                "Generate comprehensive forensic incident reconstruction report",
                "low",
                {"title": "Digital Forensics Incident Report"},
            ),
        ]
        branches = [
            PlanBranch(
                trigger_condition="if_timestomping_detected",
                rationale="$STANDARD_INFORMATION timestamp precedes $FILE_NAME timestamp",
                recommended_tools=["disk_analyze_mft", "artifact_timeline"],
                stop_condition="True creation and modification timeline established",
            ),
            PlanBranch(
                trigger_condition="if_lateral_movement_observed",
                rationale="SMB/RPC or RDP connections to internal hosts identified",
                recommended_tools=["pcap_extract_c2", "generate_sigma_rule"],
                stop_condition="Compromise scope and infected endpoints cataloged",
            ),
        ]
        stop = [
            "Stop if evidence indicates false alarm or authorized administrative action",
            "Stop once attack path, initial access vector, and IOCs are compiled into report",
        ]
        return quick, standard_add, deep_add, branches, stop

    # Default: MALWARE_TRIAGE (PE, ELF, MACHO, GENERIC)
    # -----------------------------------------------------------------------
    quick = [
        (
            "run_file",
            "identification",
            "Inspect file headers, format, architecture, and cryptographic hashes",
            "low",
            farg,
        ),
        (
            "parse_binary_with_lief",
            "structure",
            "Parse PE/ELF/Mach-O headers, section layout, and import table",
            "low",
            farg,
        ),
        (
            "detect_packer",
            "packing",
            "Evaluate section entropy and scan for known packer signatures",
            "low",
            farg,
        ),
        (
            "run_capa_quick",
            "capabilities",
            "Identify high-level malware capabilities and MITRE ATT&CK techniques",
            "medium",
            farg,
        ),
        (
            "extract_iocs",
            "artifacts",
            "Carve embedded C2 IPs, domains, URLs, mutexes, and file paths",
            "low",
            farg,
        ),
        (
            "detect_anti_analysis",
            "evasion",
            "Scan for anti-debugging, VM evasion, and sandbox detection tricks",
            "low",
            farg,
        ),
    ]
    standard_add = [
        (
            "run_yara",
            "matching",
            "Match sample against malware family YARA signatures",
            "medium",
            {"target_path": target_file or "sample.bin", "rule_path": "malware.yar"},
        ),
        (
            "Radare2_list_imports",
            "imports",
            "Analyze imported APIs for injection, persistence, and network primitives",
            "low",
            farg,
        ),
        (
            "Radare2_list_sections",
            "sections",
            "Check section permissions (e.g. RWX sections) and entropy anomalies",
            "low",
            farg,
        ),
        (
            "r2_recover_structures",
            "structures",
            "Infer C/C++ structs, object layouts, and global data pointers",
            "medium",
            farg,
        ),
        (
            "dormant_detector",
            "triggers",
            "Detect delayed execution, sleeps, date triggers, and dormant routines",
            "medium",
            farg,
        ),
        (
            "generate_yara_rule",
            "signature",
            "Generate initial threat hunting YARA rule from extracted strings/bytes",
            "low",
            farg,
        ),
    ]
    deep_add = [
        (
            "detect_packer_deep",
            "deep_unpacking",
            "Deep heuristic unpacking analysis for complex multi-stage crypters",
            "high",
            farg,
        ),
        (
            "run_deobfuscation_pipeline",
            "deobfuscation",
            "Execute string decryption, API de-hashing, and dead code cleanup",
            "high",
            farg,
        ),
        (
            "r2_decompile",
            "decompilation",
            "Decompile suspicious main routine and C2 handlers via r2ghidra",
            "high",
            {"function": "main", **farg},
        ),
        (
            "vulnerability_hunter",
            "vulnerability",
            "Check if sample exploits or embeds local vulnerabilities",
            "medium",
            farg,
        ),
        (
            "adaptive_vaccine",
            "mitigation",
            "Generate host vaccine (killswitch domain, mutex lock, vaccine patch)",
            "medium",
            farg,
        ),
        (
            "create_analysis_report",
            "reporting",
            "Generate comprehensive malware triage and defense dossier",
            "low",
            {"title": "Malware Threat Analysis Report"},
        ),
    ]
    branches = [
        PlanBranch(
            trigger_condition="if_packed_or_high_entropy",
            rationale="Sample is protected by packer/crypter (entropy > 7.0 or packer signature)",
            recommended_tools=[
                "detect_packer_deep",
                "run_deobfuscation_pipeline",
                "run_binwalk_extract",
            ],
            stop_condition="Unpacked payload dumped or confirmed custom VM requiring dynamic instrumentation",
        ),
        PlanBranch(
            trigger_condition="if_network_or_process_iocs",
            rationale="C2 network communication or process injection APIs observed",
            recommended_tools=["Radare2_xrefs_to", "r2_decompile", "generate_enhanced_yara_rule"],
            stop_condition="C2 protocol and payload injection targets mapped",
        ),
        PlanBranch(
            trigger_condition="if_anti_analysis_detected",
            rationale="Debugger evasion or sandbox detection checks present",
            recommended_tools=["r2_analyze_function", "r2_simulate_patch"],
            stop_condition="Evasion logic identified and bypassed via simulated patching",
        ),
    ]
    stop = [
        "Stop if sample is confirmed clean benign binary from verified vendor",
        "Stop once threat family, C2 infrastructure, and YARA rule are generated",
    ]
    return quick, standard_add, deep_add, branches, stop


# ---------------------------------------------------------------------------
# Main Planning Engine
# ---------------------------------------------------------------------------


def generate_analysis_plan(
    target_file: str | None = None,
    file_format: str | None = None,
    architecture: str | None = None,
    objective: str = AnalysisObjective.MALWARE_TRIAGE,
    depth: str = DepthTier.STANDARD,
    profile: str | None = None,
    time_budget_seconds: int | None = None,
) -> AnalysisPlan:
    """Generate a goal-aware, depth-tiered analysis plan composed of existing MCP tools.

    Guarantees:
      1. Every tool belongs strictly to Reversecore MCP.
      2. quick ⊆ standard ⊆ deep (nested scope invariant).
      3. Missing dependencies and inactive profiles are detected and surfaced.
      4. Clear rationale, conditional branches, and stop conditions are provided.
    """
    obj = normalize_objective(objective)
    d_tier = normalize_depth(depth, time_budget_seconds=time_budget_seconds)
    fmt = detect_sample_format(target_file, file_format)
    arch = (architecture or "x86_64").strip().lower()
    active_prof = (profile or "full").strip().lower()

    # Budget calculation
    base_budgets = {
        DepthTier.QUICK: 30,
        DepthTier.STANDARD: 120,
        DepthTier.DEEP: 450,
    }
    budget = time_budget_seconds if time_budget_seconds is not None else base_budgets[d_tier]

    quick_steps, std_add, deep_add, branches, stop_conditions = _get_pipelines(
        fmt=fmt,
        obj=obj,
        target_file=target_file or "",
    )

    # Compose steps based on depth tier (preserving nested scope)
    selected_step_defs: list[StepDef] = list(quick_steps)
    if d_tier in (DepthTier.STANDARD, DepthTier.DEEP):
        selected_step_defs.extend(std_add)
    if d_tier == DepthTier.DEEP:
        selected_step_defs.extend(deep_add)

    plan_steps: list[PlanStep] = []
    missing_deps: set[str] = set()

    for idx, (tool, phase, purpose, cost, params) in enumerate(selected_step_defs, 1):
        step = _build_step(
            step_num=idx,
            tool=tool,
            phase=phase,
            purpose=purpose,
            cost=cost,
            params=params,
            profile=active_prof,
        )
        plan_steps.append(step)
        if not step.available and step.missing_dependency:
            missing_deps.add(step.missing_dependency)

    total_count = len(plan_steps)
    available_count = sum(1 for s in plan_steps if s.available)
    unavailable_count = total_count - available_count

    return AnalysisPlan(
        objective=obj,
        depth=d_tier,
        sample_format=fmt,
        architecture=arch,
        active_profile=active_prof,
        estimated_budget_seconds=budget,
        primary_steps=plan_steps,
        conditional_branches=branches,
        stop_conditions=stop_conditions,
        missing_dependencies=sorted(missing_deps),
        tool_coverage_summary={
            "total_recommended": total_count,
            "available": available_count,
            "unavailable": unavailable_count,
        },
    )
