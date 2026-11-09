"""Tiered Tools & Multi-Agent Mode for Reversecore_MCP.

Exposes a compact, high-efficiency daily toolset (~15 tools) to LLM clients
(Cursor, Claude Code, Windsurf, Claude Desktop, Antigravity, etc.) instead of
exposing all 179 tools simultaneously, reducing prompt context token consumption
by >90% while providing seamless on-demand access to all 179 specialized tools
via domain expert sub-agents and a universal execution router.
"""

from __future__ import annotations

import difflib
import json
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from fastmcp import FastMCP

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure, success

logger = get_logger(__name__)

# ==============================================================================
# Tier 1: Daily Essential Core Tools (12 tools)
# ==============================================================================
TIER1_CORE_TOOLS: list[str] = [
    "run_file",  # File type, arch, compiler, MIME
    "Radare2_open_file",  # Open binary session
    "Radare2_close_file",  # Close binary session
    "Radare2_list_functions",  # Enumerate functions & symbols
    "Radare2_disassemble_function",  # Disassemble assembly code
    "Radare2_decompile_function",  # Decompile pseudo-C via r2ghidra
    "Radare2_list_strings",  # Extract data strings
    "extract_iocs",  # Extract IP/URL/Domain/Host IOCs
    "run_yara",  # Scan against YARA detection rules
    "parse_binary_with_lief",  # Parse headers, imports, sections, security features
    "create_analysis_report",  # Generate structured summary report
    "get_server_health",  # Server health, uptime, workspace status
]

# ==============================================================================
# Tier 2: Tiered Router & Sub-Agent Tools (3 tools)
# ==============================================================================
TIER2_ROUTER_TOOLS: list[str] = [
    "call_expert_agent",  # High-level domain expert sub-agent dispatcher
    "search_tools",  # Dynamic capability search across all 179 tools
    "execute_domain_tool",  # Universal on-demand router to execute any tool
]

TIERED_TOOL_NAMES: set[str] = set(TIER1_CORE_TOOLS + TIER2_ROUTER_TOOLS)


# ==============================================================================
# Domain Sub-Agents
# ==============================================================================
class DomainSubAgent(ABC):
    """Abstract base class for a specialized domain sub-agent."""

    name: str
    display_name: str
    domain: str
    description: str
    primary_tools: list[str]

    @abstractmethod
    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute domain-specific analysis workflow."""
        pass


class VulnerabilityHunterAgent(DomainSubAgent):
    """Specialist sub-agent for vulnerability research, exploitability, ROP, heap, and crashes."""

    name = "vulnerability_hunter"
    display_name = "Vulnerability Research & Exploit Hunter"
    domain = "vulnerability_research"
    description = (
        "Specializes in dangerous API scanning, ROP gadget collection, heap exploit analysis, "
        "ASan/GDB crash triage, and automated vulnerability hunting."
    )
    primary_tools = [
        "vulnerability_hunter",
        "autonomous_vuln_hunt",
        "analyze_heap_exploit",
        "triage_crash",
        "build_rop_chain",
        "generate_poc_exploit",
    ]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params = parameters or {}
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []

        # 1. Run primary static vulnerability scan
        scan_res = await _call_tool_safe(
            server_mcp, "vulnerability_hunter", {"file_path": file_path}
        )
        invoked.append("vulnerability_hunter")
        findings.append({"step": "static_vulnerability_scan", "result": scan_res})

        # 2. Check for ROP gadgets if task suggests exploitability
        task_lower = task.lower()
        if any(w in task_lower for w in ("rop", "gadget", "exploit", "chain")):
            rop_res = await _call_tool_safe(server_mcp, "build_rop_chain", {"file_path": file_path})
            invoked.append("build_rop_chain")
            findings.append({"step": "rop_gadgets", "result": rop_res})

        # 3. Crash triage if crash log provided
        if "crash_log" in params or "crash" in task_lower:
            crash_args = {"file_path": file_path}
            if "crash_log" in params:
                crash_args["crash_log"] = params["crash_log"]
            crash_res = await _call_tool_safe(server_mcp, "triage_crash", crash_args)
            invoked.append("triage_crash")
            findings.append({"step": "crash_triage", "result": crash_res})

        # 4. Heap analysis if heap requested
        if "heap" in task_lower:
            heap_res = await _call_tool_safe(
                server_mcp, "analyze_heap_exploit", {"file_path": file_path}
            )
            invoked.append("analyze_heap_exploit")
            findings.append({"step": "heap_exploit_analysis", "result": heap_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed vulnerability assessment for {file_path}. Invoked tools: {', '.join(invoked)}.",
        }


class ForensicsAgent(DomainSubAgent):
    """Specialist sub-agent for network PCAP, memory dumps, and disk forensics."""

    name = "forensics"
    display_name = "Digital Forensics & Incident Response (DFIR) Agent"
    domain = "forensics"
    description = (
        "Specializes in PCAP network traffic analysis, C2 extraction, Volatility3 memory dumps, "
        "and SleuthKit disk partition and MFT analysis."
    )
    primary_tools = [
        "pcap_analyze",
        "pcap_extract_c2",
        "pcap_extract_dns",
        "memory_analyze",
        "memory_detect_injections",
        "disk_list_files",
        "disk_analyze_mft",
        "artifact_timeline",
    ]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params = parameters or {}
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []
        fp_lower = file_path.lower()
        task_lower = task.lower()

        # Network PCAP workflow
        if (
            any(fp_lower.endswith(ext) for ext in (".pcap", ".pcapng", ".cap"))
            or "pcap" in task_lower
        ):
            pcap_res = await _call_tool_safe(server_mcp, "pcap_analyze", {"pcap_path": file_path})
            invoked.append("pcap_analyze")
            findings.append({"step": "pcap_traffic_overview", "result": pcap_res})

            c2_res = await _call_tool_safe(server_mcp, "pcap_extract_c2", {"pcap_path": file_path})
            invoked.append("pcap_extract_c2")
            findings.append({"step": "c2_traffic_extraction", "result": c2_res})

            dns_res = await _call_tool_safe(
                server_mcp, "pcap_extract_dns", {"pcap_path": file_path}
            )
            invoked.append("pcap_extract_dns")
            findings.append({"step": "dns_queries_extraction", "result": dns_res})

        # Memory Dump workflow
        elif (
            any(fp_lower.endswith(ext) for ext in (".dmp", ".raw", ".vmem"))
            or "memory" in task_lower
        ):
            mem_res = await _call_tool_safe(
                server_mcp,
                "memory_analyze",
                {"dump_path": file_path, "plugin": params.get("plugin", "windows.pslist")},
            )
            invoked.append("memory_analyze")
            findings.append({"step": "memory_process_list", "result": mem_res})

            inj_res = await _call_tool_safe(
                server_mcp, "memory_detect_injections", {"dump_path": file_path}
            )
            invoked.append("memory_detect_injections")
            findings.append({"step": "code_injection_scan", "result": inj_res})

        # Disk & Filesystem workflow
        else:
            disk_res = await _call_tool_safe(
                server_mcp, "disk_list_files", {"image_path": file_path}
            )
            invoked.append("disk_list_files")
            findings.append({"step": "disk_files", "result": disk_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed forensic analysis for {file_path}. Invoked tools: {', '.join(invoked)}.",
        }


class MalwareSpecialistAgent(DomainSubAgent):
    """Specialist sub-agent for advanced malware triage, anti-analysis, and vaccine generation."""

    name = "malware_analyst"
    display_name = "Malware Triage & Threat Intelligence Agent"
    domain = "malware"
    description = (
        "Specializes in dormant backdoor discovery, CAPA capabilities mapping, anti-analysis evasion, "
        "and adaptive vaccine generation."
    )
    primary_tools = [
        "extract_iocs",
        "dormant_detector",
        "run_capa",
        "detect_anti_analysis",
        "adaptive_vaccine",
        "generate_advanced_yara_rule",
    ]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []

        # 1. Extract network & host IOCs
        iocs_res = await _call_tool_safe(server_mcp, "extract_iocs", {"file_path": file_path})
        invoked.append("extract_iocs")
        findings.append({"step": "iocs_extraction", "result": iocs_res})

        # 2. Check for anti-analysis / sandbox evasion
        anti_res = await _call_tool_safe(
            server_mcp, "detect_anti_analysis", {"file_path": file_path}
        )
        invoked.append("detect_anti_analysis")
        findings.append({"step": "anti_analysis_evasion", "result": anti_res})

        # 3. Check for dormant logic / time-bombs
        dorm_res = await _call_tool_safe(server_mcp, "dormant_detector", {"file_path": file_path})
        invoked.append("dormant_detector")
        findings.append({"step": "dormant_backdoors", "result": dorm_res})

        # 4. CAPA capabilities mapping
        capa_res = await _call_tool_safe(server_mcp, "run_capa_quick", {"file_path": file_path})
        invoked.append("run_capa_quick")
        findings.append({"step": "capa_capabilities", "result": capa_res})

        # 5. Adaptive vaccine generation if requested
        if "vaccine" in task.lower() or (parameters and parameters.get("generate_vaccine")):
            vac_res = await _call_tool_safe(
                server_mcp, "adaptive_vaccine", {"file_path": file_path}
            )
            invoked.append("adaptive_vaccine")
            findings.append({"step": "adaptive_vaccine", "result": vac_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed malware threat assessment for {file_path}. Invoked tools: {', '.join(invoked)}.",
        }


class DeobfuscationAgent(DomainSubAgent):
    """Specialist sub-agent for packing detection, string decoding, and control-flow recovery."""

    name = "deobfuscator"
    display_name = "Deobfuscation & Unpacking Specialist"
    domain = "deobfuscation"
    description = (
        "Specializes in packer detection (DIE), encrypted strings decoding, API hash resolution, "
        "and control flow unflattening."
    )
    primary_tools = [
        "detect_packer",
        "run_deobfuscation_pipeline",
        "deobfuscate_strings",
        "resolve_api_hashes",
        "eliminate_dead_code",
    ]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []

        # 1. Detect packer
        pack_res = await _call_tool_safe(server_mcp, "detect_packer", {"file_path": file_path})
        invoked.append("detect_packer")
        findings.append({"step": "packer_detection", "result": pack_res})

        # 2. Run deobfuscation pipeline or string decryption
        deobf_res = await _call_tool_safe(
            server_mcp, "run_deobfuscation_pipeline", {"file_path": file_path}
        )
        invoked.append("run_deobfuscation_pipeline")
        findings.append({"step": "deobfuscation_pipeline", "result": deobf_res})

        # 3. Resolve API hashes if requested or relevant
        if "hash" in task.lower() or "api" in task.lower():
            api_res = await _call_tool_safe(
                server_mcp, "resolve_api_hashes", {"file_path": file_path}
            )
            invoked.append("resolve_api_hashes")
            findings.append({"step": "api_hashing_resolution", "result": api_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed deobfuscation analysis for {file_path}. Invoked tools: {', '.join(invoked)}.",
        }


class SymbolicEngineAgent(DomainSubAgent):
    """Specialist sub-agent for symbolic execution, constraint solving, and taint analysis."""

    name = "symbolic_engine"
    display_name = "Symbolic Execution & Taint Analysis Engine"
    domain = "symbolic_execution"
    description = (
        "Specializes in path reachability proofs via angr, concrete argument synthesis, "
        "and dataflow taint tracking from sources to sinks."
    )
    primary_tools = [
        "verify_path_and_get_args",
        "taint_trace",
        "emulate_binary",
        "emulate_machine_code",
    ]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params = parameters or {}
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []

        if "taint" in task.lower():
            args = {"file_path": file_path}
            if "source" in params:
                args["source"] = params["source"]
            if "sink" in params:
                args["sink"] = params["sink"]
            taint_res = await _call_tool_safe(server_mcp, "taint_trace", args)
            invoked.append("taint_trace")
            findings.append({"step": "taint_tracing", "result": taint_res})
        else:
            args = {"file_path": file_path}
            if "target_address" in params:
                args["target_address"] = params["target_address"]
            symb_res = await _call_tool_safe(server_mcp, "verify_path_and_get_args", args)
            invoked.append("verify_path_and_get_args")
            findings.append({"step": "symbolic_path_verification", "result": symb_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed symbolic verification for {file_path}. Invoked tools: {', '.join(invoked)}.",
        }


class DiffAnalystAgent(DomainSubAgent):
    """Specialist sub-agent for semantic binary diffing, 1-day patch review, and transfer."""

    name = "diff_analyst"
    display_name = "Patch Diff & 1-Day Vulnerability Analyst"
    domain = "diff_analysis"
    description = (
        "Specializes in semantic binary diffing, variant change detection, 1-day vulnerability inference, "
        "and cross-binary annotation transfer."
    )
    primary_tools = [
        "diff_binaries",
        "analyze_variant_changes",
        "patch_diff_1day",
        "analyze_patch_diff_auto",
        "match_functions_across_binaries",
        "transfer_annotations_across_binaries",
    ]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params = parameters or {}
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []
        target_path = params.get("target_path") or params.get("file_b") or file_path

        diff_res = await _call_tool_safe(
            server_mcp, "patch_diff_1day", {"file_a": file_path, "file_b": target_path}
        )
        invoked.append("patch_diff_1day")
        findings.append({"step": "1day_patch_diff", "result": diff_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "target_path": target_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed binary diff analysis between {file_path} and {target_path}.",
        }


class SourceAuditorAgent(DomainSubAgent):
    """Specialist sub-agent for AST-based source code audits and feature reconstruction."""

    name = "source_auditor"
    display_name = "Static Source Code Security Auditor & Feature Reconstructor"
    domain = "source_audit"
    description = "Specializes in Python AST vulnerability scanning, C/C++ regex pattern security auditing, and feature code reconstruction."
    primary_tools = ["audit_source_code", "reconstruct_feature_code"]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []

        params = parameters or {}
        addr_or_sym = (
            params.get("address") or params.get("symbol") or params.get("address_or_symbol")
        )

        if addr_or_sym:
            recon_res = await _call_tool_safe(
                server_mcp,
                "reconstruct_feature_code",
                {
                    "file_path": file_path,
                    "address_or_symbol": addr_or_sym,
                    "target_language": params.get("target_language", "c"),
                    "test_inputs": params.get("test_inputs"),
                },
            )
            invoked.append("reconstruct_feature_code")
            findings.append({"step": "feature_reconstruction", "result": recon_res})
        else:
            audit_res = await _call_tool_safe(
                server_mcp, "audit_source_code", {"file_path": file_path}
            )
            invoked.append("audit_source_code")
            findings.append({"step": "source_code_audit", "result": audit_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed source code operation for {file_path}.",
        }


class ModernRuntimeAgent(DomainSubAgent):
    """Specialist sub-agent for Go/Rust binaries, Electron ASAR bundles, and Unity IL2CPP games."""

    name = "modern_runtime"
    display_name = "Modern Application Runtime Analyzer (Go/Rust, Electron ASAR, Unity IL2CPP)"
    domain = "modern_runtimes"
    description = (
        "Specializes in stripped Go/Rust symbol and crate recovery, Electron .asar unpacking "
        "and IPC auditing, and Unity IL2CPP global-metadata.dat analysis."
    )
    primary_tools = [
        "inspect_go_rust_binary",
        "inspect_electron_asar",
        "inspect_unity_il2cpp",
        "inspect_analysis_view",
        "search_guidance",
        "read_guidance_section",
    ]

    async def run(
        self,
        server_mcp: FastMCP,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params = parameters or {}
        invoked: list[str] = []
        findings: list[dict[str, Any]] = []
        fp_lower = file_path.lower()
        task_lower = task.lower()

        if fp_lower.endswith(".asar") or "asar" in task_lower or "electron" in task_lower:
            asar_res = await _call_tool_safe(
                server_mcp,
                "inspect_electron_asar",
                {
                    "file_path": file_path,
                    "extract_path": params.get("extract_path"),
                    "search_pattern": params.get("search_pattern"),
                    "detail": params.get("detail", "summary"),
                },
            )
            invoked.append("inspect_electron_asar")
            findings.append({"step": "electron_asar_inspection", "result": asar_res})
        elif (
            fp_lower.endswith("global-metadata.dat")
            or "il2cpp" in task_lower
            or "unity" in task_lower
        ):
            il2cpp_res = await _call_tool_safe(
                server_mcp,
                "inspect_unity_il2cpp",
                {
                    "metadata_path": file_path,
                    "binary_path": params.get("binary_path"),
                    "detail": params.get("detail", "summary"),
                },
            )
            invoked.append("inspect_unity_il2cpp")
            findings.append({"step": "unity_il2cpp_inspection", "result": il2cpp_res})
        else:
            gorust_res = await _call_tool_safe(
                server_mcp,
                "inspect_go_rust_binary",
                {
                    "file_path": file_path,
                    "detail": params.get("detail", "summary"),
                },
            )
            invoked.append("inspect_go_rust_binary")
            findings.append({"step": "go_rust_binary_inspection", "result": gorust_res})

        return {
            "agent": self.name,
            "display_name": self.display_name,
            "status": "success",
            "task": task,
            "file_path": file_path,
            "tools_invoked": invoked,
            "findings": findings,
            "summary": f"Completed modern runtime analysis for {file_path} via {', '.join(invoked)}.",
        }


# ==============================================================================
# Agent Registry
# ==============================================================================
class AgentRegistry:
    """Registry managing domain sub-agents and tool routing."""

    def __init__(self) -> None:
        self._agents: dict[str, DomainSubAgent] = {}
        self._alias_map: dict[str, str] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        agents: list[DomainSubAgent] = [
            VulnerabilityHunterAgent(),
            ForensicsAgent(),
            MalwareSpecialistAgent(),
            DeobfuscationAgent(),
            SymbolicEngineAgent(),
            DiffAnalystAgent(),
            SourceAuditorAgent(),
            ModernRuntimeAgent(),
        ]
        for a in agents:
            self.register(a)

        # Standard Aliases
        aliases = {
            "vuln": "vulnerability_hunter",
            "cve": "vulnerability_hunter",
            "exploit": "vulnerability_hunter",
            "vulnerability": "vulnerability_hunter",
            "dfir": "forensics",
            "memory": "forensics",
            "pcap": "forensics",
            "disk": "forensics",
            "malware": "malware_analyst",
            "threat": "malware_analyst",
            "threat_intel": "malware_analyst",
            "unpack": "deobfuscator",
            "deobfuscation": "deobfuscator",
            "symbolic": "symbolic_engine",
            "angr": "symbolic_engine",
            "taint": "symbolic_engine",
            "diff": "diff_analyst",
            "patch": "diff_analyst",
            "1day": "diff_analyst",
            "source": "source_auditor",
            "audit": "source_auditor",
            "sast": "source_auditor",
            "reconstruct": "source_auditor",
            "reconstruction": "source_auditor",
            "feature": "source_auditor",
            "decomp": "source_auditor",
            "go": "modern_runtime",
            "golang": "modern_runtime",
            "rust": "modern_runtime",
            "electron": "modern_runtime",
            "asar": "modern_runtime",
            "unity": "modern_runtime",
            "il2cpp": "modern_runtime",
            "runtime": "modern_runtime",
        }
        for alias, target in aliases.items():
            self._alias_map[alias.lower()] = target

    def register(self, agent: DomainSubAgent) -> None:
        self._agents[agent.name.lower()] = agent

    def get_agent(self, name_or_alias: str) -> DomainSubAgent | None:
        key = name_or_alias.strip().lower().replace("-", "_")
        target_name = self._alias_map.get(key, key)
        return self._agents.get(target_name)

    def list_agents(self) -> list[dict[str, Any]]:
        return [
            {
                "name": a.name,
                "display_name": a.display_name,
                "domain": a.domain,
                "description": a.description,
                "primary_tools": a.primary_tools,
            }
            for a in self._agents.values()
        ]


_GLOBAL_AGENT_REGISTRY = AgentRegistry()


# ==============================================================================
# Helper Functions
# ==============================================================================
async def _call_tool_safe(
    server_mcp: FastMCP, tool_name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    """Execute a tool on server_mcp and return dictionary result."""
    try:
        res = await server_mcp.call_tool(tool_name, arguments)
        if hasattr(res, "structured_content") and isinstance(res.structured_content, dict):
            return dict(res.structured_content)
        if hasattr(res, "content") and res.content:
            first = res.content[0]
            if hasattr(first, "text"):
                try:
                    loaded = json.loads(first.text)
                    if isinstance(loaded, dict):
                        return loaded
                    return {"result": loaded}
                except Exception:
                    return {"text": first.text}
        return {"result": str(res)}
    except Exception as exc:
        logger.warning(f"Tool {tool_name} failed during sub-agent run: {exc}")
        return {"error": str(exc), "status": "error"}


# ==============================================================================
# Tier 2 Tools: Implementation
# ==============================================================================
async def call_expert_agent(
    server_mcp: FastMCP,
    agent_name: str,
    task: str,
    file_path: str,
    parameters: dict[str, Any] | None = None,
) -> ToolResult:
    """Dispatch high-level analysis tasks to specialized domain sub-agents.

    Args:
        server_mcp: FastMCP instance.
        agent_name: Target agent name or alias (e.g. 'vulnerability_hunter', 'forensics',
                    'malware_analyst', 'deobfuscator', 'symbolic_engine', 'diff_analyst', 'source_auditor').
        task: Plain-text description of the analysis goal.
        file_path: Path to target binary, dump, or source file.
        parameters: Optional dictionary of fine-tuned parameters.

    Returns:
        ToolResult with structured findings and execution summary.
    """
    agent = _GLOBAL_AGENT_REGISTRY.get_agent(agent_name)
    if not agent:
        available = [a["name"] for a in _GLOBAL_AGENT_REGISTRY.list_agents()]
        return failure(
            "AGENT_NOT_FOUND",
            f"Expert agent '{agent_name}' not found. Available agents: {', '.join(available)}.",
        )

    try:
        result = await agent.run(server_mcp, task=task, file_path=file_path, parameters=parameters)
        return success(data=result, message=result.get("summary", "Analysis completed."))
    except Exception as exc:
        logger.error(f"Expert agent {agent_name} failed: {exc}", exc_info=True)
        return failure("AGENT_EXECUTION_ERROR", f"Agent '{agent_name}' failed: {exc}")


async def search_tools(
    server_mcp: FastMCP,
    query: str,
    domain: str | None = None,
    limit: int = 10,
) -> ToolResult:
    """Dynamically search and inspect any of Reversecore's 179 tools by keyword or domain.

    Args:
        server_mcp: FastMCP instance.
        query: Keyword query (e.g., 'rop', 'heap', 'pcap', 'mft', 'capa', 'firmware', 'unpacker').
        domain: Optional domain filter ('vulnerability', 'forensics', 'malware', 'radare2', etc.).
        limit: Maximum results to return (default: 10, max: 30).

    Returns:
        ToolResult with matching tools, descriptions, parameter schemas, and execution examples.
    """
    all_tools = await server_mcp._list_tools()
    query_lower = query.lower().strip()
    domain_lower = domain.lower().strip() if domain else None
    matches: list[dict[str, Any]] = []

    for t in all_tools:
        name = t.name
        desc = t.description or ""
        name_lower = name.lower()
        desc_lower = desc.lower()

        # Domain inference
        inferred_domain = "general"
        if name.startswith("Radare2_") or name.startswith("r2_"):
            inferred_domain = "radare2"
        elif any(w in name_lower for w in ("pcap", "disk", "memory", "artifact")):
            inferred_domain = "forensics"
        elif any(w in name_lower for w in ("vuln", "cve", "heap", "rop", "crash", "poc")):
            inferred_domain = "vulnerability"
        elif any(w in name_lower for w in ("yara", "ioc", "capa", "dormant", "vaccine", "malware")):
            inferred_domain = "malware"
        elif any(w in name_lower for w in ("deobf", "packer")):
            inferred_domain = "deobfuscation"
        elif any(w in name_lower for w in ("diff", "patch", "variant")):
            inferred_domain = "diff"
        elif any(w in name_lower for w in ("report", "vex", "sigma")):
            inferred_domain = "report"

        if domain_lower and domain_lower not in inferred_domain and domain_lower not in name_lower:
            continue

        score = 0
        if query_lower == name_lower:
            score = 100
        elif query_lower in name_lower:
            score = 50
        elif query_lower in desc_lower:
            score = 25

        if score > 0:
            params_schema = getattr(t, "parameters", {}) or {}
            props = params_schema.get("properties", {}) if isinstance(params_schema, dict) else {}
            req = params_schema.get("required", []) if isinstance(params_schema, dict) else []

            matches.append(
                {
                    "name": name,
                    "score": score,
                    "domain": inferred_domain,
                    "description": desc.split("\n")[0] if desc else "",
                    "required_parameters": req,
                    "optional_parameters": [p for p in props if p not in req],
                    "example_invocation": {
                        "tool_name": name,
                        "arguments": {p: f"<{p}>" for p in req},
                    },
                }
            )

    # Sort by score descending
    matches.sort(key=lambda x: x["score"], reverse=True)
    limit = max(1, min(limit, 30))
    truncated = matches[:limit]

    return success(
        data={
            "query": query,
            "total_matches": len(matches),
            "returned_matches": len(truncated),
            "tools": truncated,
        },
        message=f"Found {len(matches)} tool(s) matching '{query}'.",
    )


async def execute_domain_tool(
    server_mcp: FastMCP,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> ToolResult:
    """Execute any of Reversecore_MCP's 179 specialized tools on demand.

    Args:
        server_mcp: FastMCP instance.
        tool_name: Exact name of the specialized tool to run.
        arguments: Parameters dictionary to pass to the tool.

    Returns:
        ToolResult with the target tool's output.
    """
    if not tool_name or not tool_name.strip():
        return failure("INVALID_ARGUMENT", "tool_name is required.")

    target_name = tool_name.strip()
    all_tools = await server_mcp._list_tools()
    all_names = [t.name for t in all_tools]

    if target_name not in all_names:
        closest = difflib.get_close_matches(target_name, all_names, n=3, cutoff=0.4)
        msg = f"Tool '{target_name}' not found."
        if closest:
            msg += f" Did you mean: {', '.join(closest)}? Use 'search_tools' to discover tools."
        return failure("TOOL_NOT_FOUND", msg)

    try:
        res = await server_mcp.call_tool(target_name, arguments or {})
        # Extract structured content or text
        if hasattr(res, "structured_content") and res.structured_content:
            return success(
                data=res.structured_content,
                message=f"Successfully executed tool '{target_name}'.",
            )
        if hasattr(res, "content") and res.content:
            first = res.content[0]
            if hasattr(first, "text"):
                try:
                    loaded = json.loads(first.text)
                    return success(
                        data=loaded,
                        message=f"Successfully executed tool '{target_name}'.",
                    )
                except Exception:
                    return success(
                        data={"text": first.text},
                        message=f"Successfully executed tool '{target_name}'.",
                    )
        return success(
            data={"output": str(res)},
            message=f"Successfully executed tool '{target_name}'.",
        )
    except Exception as exc:
        logger.error(f"execute_domain_tool failed on {target_name}: {exc}", exc_info=True)
        return failure("EXECUTION_ERROR", f"Failed to execute '{target_name}': {exc}")


# ==============================================================================
# Setup Tiered Mode
# ==============================================================================
def setup_tiered_mode(mcp_server: FastMCP, profile: str | None = None) -> None:
    """Configure Tiered Tools and Multi-Agent Mode on the FastMCP instance.

    Args:
        mcp_server: The FastMCP server instance.
        profile: Active tool profile string. If in ('tiered', 'agents', 'core'),
                 tiered mode is activated, exposing only ~15 tools to clients while
                 keeping all 179 tools accessible via the router and sub-agents.
    """
    normalized = (profile or "").strip().lower()

    if normalized not in ("tiered", "agents", "core"):
        logger.debug(f"Tiered mode inactive (profile={profile})")
        return

    logger.info(
        "🚀 Activating Tiered Tools / Agents Mode: Reducing LLM context tokens by >90% "
        "(Exposing 12 Core Tools + 3 Router/Agent Tools)."
    )

    # 1. Register Tier-2 Tools on mcp_server
    async def _call_expert_agent(
        agent_name: str,
        task: str,
        file_path: str,
        parameters: dict[str, Any] | None = None,
    ) -> ToolResult:
        return await call_expert_agent(mcp_server, agent_name, task, file_path, parameters)

    async def _search_tools(
        query: str,
        domain: str | None = None,
        limit: int = 10,
    ) -> ToolResult:
        return await search_tools(mcp_server, query, domain, limit)

    async def _execute_domain_tool(
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> ToolResult:
        return await execute_domain_tool(mcp_server, tool_name, arguments)

    # Decorate tools on mcp_server
    mcp_server.tool(
        name="call_expert_agent",
        description=(
            "Dispatch high-level analysis tasks to specialized domain sub-agents: "
            "'vulnerability_hunter', 'forensics', 'malware_analyst', 'deobfuscator', "
            "'symbolic_engine', 'diff_analyst', 'source_auditor'."
        ),
    )(_call_expert_agent)

    mcp_server.tool(
        name="search_tools",
        description="Search across Reversecore_MCP's full catalog of 179 tools by keyword or domain to inspect parameter schemas.",
    )(_search_tools)

    mcp_server.tool(
        name="execute_domain_tool",
        description="Execute any of Reversecore_MCP's 179 specialized tools on demand with custom arguments.",
    )(_execute_domain_tool)

    # 2. Wrap list_tools on mcp_server to filter public visibility to Tier-1 + Tier-2
    orig_list_tools = mcp_server.list_tools

    async def tiered_list_tools(*args: Any, **kwargs: Any) -> Sequence[Any]:
        all_tools = await orig_list_tools(*args, **kwargs)
        # Return only the tools in TIERED_TOOL_NAMES
        filtered = [t for t in all_tools if t.name in TIERED_TOOL_NAMES]
        return filtered

    mcp_server.list_tools = tiered_list_tools  # type: ignore[method-assign]
