"""Evidence-driven analysis priority queue engine for agent workflows.

Provides deterministic ranking, explainable scoring with evidence breakdowns,
automated triage candidate extraction, and blocker resolution lifecycle.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from reversecore_mcp.core.case_state import (
    AnalysisTarget,
    CaseState,
    TargetPriority,
    TargetStatus,
)
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Base scoring weights per priority tier
PRIORITY_BASE_WEIGHTS: dict[str, float] = {
    TargetPriority.CRITICAL.value: 1000.0,
    TargetPriority.HIGH.value: 750.0,
    TargetPriority.MEDIUM.value: 500.0,
    TargetPriority.LOW.value: 250.0,
}

# Status adjustments
STATUS_WEIGHTS: dict[str, float] = {
    TargetStatus.ACTIVE.value: 120.0,
    TargetStatus.PENDING.value: 0.0,
    TargetStatus.BLOCKED.value: -400.0,
    TargetStatus.DEFERRED.value: -250.0,
    TargetStatus.COMPLETED.value: -5000.0,
    TargetStatus.REJECTED.value: -5000.0,
}

# Keyword evidence boost mappings
EVIDENCE_KEYWORD_BOOSTS: list[tuple[re.Pattern[str], float, str]] = [
    (
        re.compile(
            r"c2|beacon|command[_-]and[_-]control|exfiltrat|reverse_shell|botnet|dns_tunnel",
            re.I,
        ),
        160.0,
        "c2_network_indicator",
    ),
    (
        re.compile(
            r"inject|hollow|unbacked|rwx|remotethread|apc|shellcode|peb_walk",
            re.I,
        ),
        180.0,
        "process_injection_primitive",
    ),
    (
        re.compile(
            r"decrypt|crypt|aes|rc4|chacha|cipher|key_schedule|hash_algorithm",
            re.I,
        ),
        140.0,
        "cryptographic_primitive",
    ),
    (
        re.compile(
            r"anti[_-]debug|anti[_-]vm|isdebuggerpresent|sandbox|evas|timing_check|rdtsc",
            re.I,
        ),
        130.0,
        "anti_analysis_evasion",
    ),
    (
        re.compile(
            r"cve|vulnerab|overflow|use[_-]after[_-]free|uaf|rop|gadget|format_string",
            re.I,
        ),
        150.0,
        "vulnerability_exploit",
    ),
    (
        re.compile(
            r"patch|diff|modified_function|variant|delta|1day",
            re.I,
        ),
        120.0,
        "patch_diff_change",
    ),
    (
        re.compile(
            r"persistence|registry_run|service|schtasks|startup|autorun",
            re.I,
        ),
        110.0,
        "persistence_mechanism",
    ),
    (
        re.compile(
            r"high_entropy|packed|upx|section_entropy|compressed|encrypted_payload",
            re.I,
        ),
        110.0,
        "packing_or_entropy",
    ),
]

# Recommended tools based on kind and target characteristics
KIND_TOOL_MAP: dict[str, list[str]] = {
    "function": ["r2_decompile", "Radare2_disassemble_function", "analyze_xrefs"],
    "import": ["analyze_xrefs", "Radare2_list_imports", "trace_execution_path"],
    "string": ["verify_string_references", "Radare2_list_strings", "analyze_xrefs"],
    "diff": ["analyze_patch_diff_auto", "r2_decompile", "diff_binaries"],
    "patch": ["analyze_patch_diff_auto", "r2_simulate_patch", "r2_decompile"],
    "memory": ["memory_analyze", "memory_detect_injections", "memory_dump_module"],
    "pcap": ["pcap_analyze", "pcap_reconstruct_stream", "artifact_correlate_ioc"],
    "network": ["pcap_analyze", "pcap_list_connections", "artifact_correlate_ioc"],
    "section": ["run_binwalk", "parse_binary_with_lief", "Radare2_list_sections"],
    "hypothesis": ["get_case_state", "create_analysis_report", "recommend_analysis_plan"],
    "cve": ["cve_triage_crash", "cve_minimize_poc", "hunt_cve_vulnerabilities"],
}

# Suspicious API signatures to automatically extract from imports
SUSPICIOUS_API_CATALOG: list[tuple[re.Pattern[str], str, str, str, str]] = [
    # (Regex, Priority, Kind, Rationale, Expected next step)
    (
        re.compile(
            r"^(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|QueueUserAPC|NtCreateThreadEx|RtlCreateUserThread)$",
            re.I,
        ),
        TargetPriority.CRITICAL.value,
        "import",
        "Process injection primitive detected in import table",
        "locate xrefs to injection call and decompile caller",
    ),
    (
        re.compile(
            r"^(VirtualAlloc|VirtualProtect|VirtualProtectEx|NtProtectVirtualMemory)$", re.I
        ),
        TargetPriority.HIGH.value,
        "import",
        "Memory permission modification primitive (possible shellcode execution / unpacking)",
        "find xrefs to inspect memory flags (e.g. PAGE_EXECUTE_READWRITE)",
    ),
    (
        re.compile(r"^(LoadLibrary[AW]?|GetProcAddress|LdrLoadDll|LdrGetProcedureAddress)$", re.I),
        TargetPriority.HIGH.value,
        "import",
        "Dynamic API resolution mechanism (resolving unlisted APIs at runtime)",
        "trace callers to identify obfuscated or dynamic APIs",
    ),
    (
        re.compile(
            r"^(InternetOpen[AW]?|HttpSendRequest[AW]?|WinHttpSendRequest|WSAStartup|connect|socket|URLDownloadToFile[AW]?)$",
            re.I,
        ),
        TargetPriority.HIGH.value,
        "import",
        "Network communication API in imports (potential C2 beaconing)",
        "examine xrefs to discover C2 endpoints and protocol payload format",
    ),
    (
        re.compile(
            r"^(CryptDecrypt|CryptImportKey|BCryptDecrypt|AES_decrypt|EVP_DecryptInit|DES_ecb_encrypt)$",
            re.I,
        ),
        TargetPriority.HIGH.value,
        "import",
        "Cryptographic decryption primitive in imports",
        "decompile caller to recover encryption keys and decrypt payload",
    ),
    (
        re.compile(
            r"^(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString[AW]?)$",
            re.I,
        ),
        TargetPriority.MEDIUM.value,
        "import",
        "Anti-debugging API in imports",
        "analyze caller and identify bypass or patch opportunity",
    ),
    (
        re.compile(r"^(RegSetValueEx[AW]?|RegCreateKeyEx[AW]?|CreateService[AW]?|SchTasks)$", re.I),
        TargetPriority.HIGH.value,
        "import",
        "System persistence API in imports",
        "trace xrefs to identify persistence keys or installed service names",
    ),
]


@dataclass
class RankedTarget:
    """A prioritized target with computed score, explainable breakdown, and recommendations."""

    target: AnalysisTarget
    score: float
    score_breakdown: dict[str, float]
    recommended_tools: list[str]
    is_ready: bool
    unresolved_blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to serializable dictionary."""
        return {
            "id": self.target.id,
            "target": self.target.target,
            "kind": self.target.kind,
            "priority": self.target.priority,
            "status": self.target.status,
            "score": round(self.score, 2),
            "score_breakdown": {k: round(v, 2) for k, v in self.score_breakdown.items()},
            "reason": self.target.reason,
            "evidence_refs": self.target.evidence_refs,
            "expected_next_step": self.target.expected_next_step,
            "blockers": self.unresolved_blockers,
            "is_ready": self.is_ready,
            "recommended_tools": self.recommended_tools,
            "created_at": self.target.created_at,
            "updated_at": self.target.updated_at,
        }


class AnalysisPriorityQueue:
    """Engine for ranking, scoring, and maintaining evidence-driven analysis targets."""

    @staticmethod
    def calculate_target_score(
        target: AnalysisTarget,
        case: CaseState | None = None,
    ) -> tuple[float, dict[str, float], bool, list[str]]:
        """Calculate explainable priority score for an analysis target.

        Args:
            target: The analysis target to score.
            case: Optional parent case state for context.

        Returns:
            Tuple of (total_score, score_breakdown, is_ready, unresolved_blockers).
        """
        breakdown: dict[str, float] = {}

        # 1. Base tier weight
        base_weight = PRIORITY_BASE_WEIGHTS.get(
            target.priority.lower(),
            PRIORITY_BASE_WEIGHTS[TargetPriority.MEDIUM.value],
        )
        breakdown["base_priority"] = base_weight
        total = base_weight

        # 2. Status adjustment
        status_weight = STATUS_WEIGHTS.get(target.status.lower(), 0.0)
        breakdown["status_adjustment"] = status_weight
        total += status_weight

        # 3. Evidence references volume
        evidence_count = len(target.evidence_refs)
        evidence_score = min(evidence_count * 40.0, 200.0)
        if evidence_score > 0:
            breakdown["evidence_volume"] = evidence_score
            total += evidence_score

        # 4. Keyword evidence boost (semantic rationale matching)
        text_corpus = f"{target.target} {target.reason} {target.expected_next_step}".lower()
        applied_boosts = 0
        for pattern, boost, label in EVIDENCE_KEYWORD_BOOSTS:
            if pattern.search(text_corpus):
                breakdown[label] = boost
                total += boost
                applied_boosts += 1
                if applied_boosts >= 3:
                    break

        # 5. Hypothesis alignment boost
        if case and case.active_hypotheses:
            tgt_lower = target.target.lower()
            reason_lower = target.reason.lower()
            for hyp in case.active_hypotheses:
                if hyp.status == "active" and (
                    tgt_lower in hyp.title.lower()
                    or tgt_lower in hyp.rationale.lower()
                    or any(tgt_lower in ref.lower() for ref in hyp.evidence_refs)
                    or any(ref.lower() in reason_lower for ref in hyp.evidence_refs)
                ):
                    breakdown["hypothesis_alignment"] = 120.0
                    total += 120.0
                    break

        # 6. Blocker resolution and penalty
        unresolved_blockers: list[str] = []
        if target.blockers:
            # Check which blockers are still unresolved in the case
            if case:
                completed_target_names = {
                    t.target for t in case.next_targets if t.status == TargetStatus.COMPLETED.value
                } | {t.id for t in case.next_targets if t.status == TargetStatus.COMPLETED.value}
                for b in target.blockers:
                    if b not in completed_target_names:
                        unresolved_blockers.append(b)
            else:
                unresolved_blockers = list(target.blockers)

        if unresolved_blockers:
            penalty = -150.0 * len(unresolved_blockers)
            breakdown["unresolved_blockers_penalty"] = penalty
            total += penalty

        # Readiness determination
        is_terminal = target.status.lower() in (
            TargetStatus.COMPLETED.value,
            TargetStatus.REJECTED.value,
        )
        is_ready = (
            not is_terminal
            and target.status.lower() != TargetStatus.BLOCKED.value
            and len(unresolved_blockers) == 0
        )

        return total, breakdown, is_ready, unresolved_blockers

    @staticmethod
    def get_recommended_tools(target: AnalysisTarget) -> list[str]:
        """Determine recommended tools for an analysis target based on kind and heuristics."""
        kind = target.kind.lower()
        tools = list(KIND_TOOL_MAP.get(kind, ["r2_decompile", "analyze_xrefs"]))

        text_corpus = f"{target.target} {target.reason} {target.expected_next_step}".lower()

        # Context-specific tool additions
        if "anti_debug" in text_corpus or "evas" in text_corpus:
            if "r2_esil_simulator" not in tools:
                tools.insert(0, "r2_esil_simulator")
        if "taint" in text_corpus:
            if "taint_trace" not in tools:
                tools.append("taint_trace")
        if "c2" in text_corpus or "network" in text_corpus:
            if "pcap_analyze" not in tools:
                tools.append("pcap_analyze")
        if "diff" in text_corpus or "patch" in text_corpus:
            if "analyze_patch_diff_auto" not in tools:
                tools.insert(0, "analyze_patch_diff_auto")

        return tools

    @classmethod
    def rank_targets(
        cls,
        targets: list[AnalysisTarget],
        case: CaseState | None = None,
        include_completed: bool = False,
        include_blocked: bool = True,
        min_priority: str | None = None,
        limit: int | None = None,
    ) -> list[RankedTarget]:
        """Rank analysis targets deterministically with explainable scores.

        Ordering contract:
        1. Ready items first (is_ready=True comes before is_ready=False).
        2. Score descending (highest score first).
        3. Fewest unresolved blockers first.
        4. FIFO creation time ascending (older leads first).
        5. Target name alphabetical ascending for stable tie-breaking.

        Args:
            targets: Targets to rank.
            case: Parent case state.
            include_completed: Whether to include completed/rejected targets.
            include_blocked: Whether to include blocked targets.
            min_priority: Optional filter by minimum priority tier.
            limit: Maximum items to return.

        Returns:
            List of RankedTarget objects.
        """
        ranked_list: list[RankedTarget] = []

        min_rank = None
        if min_priority:
            from reversecore_mcp.core.case_state import PRIORITY_RANK

            min_rank = PRIORITY_RANK.get(min_priority.lower(), 99)

        for tgt in targets:
            # Filter completed/rejected
            if not include_completed and tgt.status.lower() in (
                TargetStatus.COMPLETED.value,
                TargetStatus.REJECTED.value,
            ):
                continue

            # Filter min_priority
            if min_rank is not None:
                from reversecore_mcp.core.case_state import PRIORITY_RANK

                tgt_rank = PRIORITY_RANK.get(tgt.priority.lower(), 99)
                if tgt_rank > min_rank:
                    continue

            score, breakdown, is_ready, unresolved_blockers = cls.calculate_target_score(
                tgt, case=case
            )

            # Filter blocked if requested
            if not include_blocked and not is_ready:
                continue

            recommended_tools = cls.get_recommended_tools(tgt)

            ranked_list.append(
                RankedTarget(
                    target=tgt,
                    score=score,
                    score_breakdown=breakdown,
                    recommended_tools=recommended_tools,
                    is_ready=is_ready,
                    unresolved_blockers=unresolved_blockers,
                )
            )

        # Deterministic sort
        ranked_list.sort(
            key=lambda r: (
                0 if r.is_ready else 1,
                -r.score,
                len(r.unresolved_blockers),
                r.target.created_at,
                r.target.target.lower(),
            )
        )

        if limit is not None and limit > 0:
            return ranked_list[:limit]
        return ranked_list

    @classmethod
    def extract_targets_from_triage(
        cls,
        triage_data: dict[str, Any],
        case: CaseState | None = None,
        max_items: int = 15,
    ) -> list[AnalysisTarget]:
        """Extract prioritized analysis targets from triage findings.

        Supports imports, strings, anti-analysis checks, diff changes, memory
        injections, network C2 correlations, and high-entropy sections.

        Avoids re-adding targets that are already completed in the case.

        Args:
            triage_data: Structured dictionary of triage findings.
            case: Optional CaseState to check against existing targets.
            max_items: Maximum new targets to extract.

        Returns:
            List of generated AnalysisTarget objects.
        """
        extracted: list[AnalysisTarget] = []
        seen_targets: set[str] = set()

        if case:
            # Existing targets and completed targets
            for t in case.next_targets:
                seen_targets.add(t.target.lower())

        def _add_candidate(
            target_name: str,
            kind: str,
            priority: str,
            reason: str,
            expected_next_step: str,
            evidence_refs: list[str] | None = None,
            blockers: list[str] | None = None,
        ) -> None:
            norm_name = target_name.strip()
            if not norm_name or norm_name.lower() in seen_targets:
                return
            if len(extracted) >= max_items:
                return

            seen_targets.add(norm_name.lower())
            extracted.append(
                AnalysisTarget(
                    id=f"tgt_{uuid.uuid4().hex[:8]}",
                    target=norm_name,
                    kind=kind,
                    priority=priority.lower(),
                    reason=reason,
                    evidence_refs=evidence_refs or [],
                    expected_next_step=expected_next_step,
                    blockers=blockers or [],
                    status=(
                        TargetStatus.BLOCKED.value
                        if (blockers and len(blockers) > 0)
                        else TargetStatus.PENDING.value
                    ),
                    created_at=_utc_now_iso(),
                    updated_at=_utc_now_iso(),
                )
            )

        # 1. Imports Analysis
        raw_imports = (
            triage_data.get("imports")
            or triage_data.get("imported_functions")
            or triage_data.get("import_table")
            or []
        )
        if isinstance(raw_imports, dict):
            # Formats like {"KERNEL32.dll": ["VirtualAlloc", "CreateFileA"]}
            for dll, funcs in raw_imports.items():
                if isinstance(funcs, list):
                    for fn in funcs:
                        fn_name = fn if isinstance(fn, str) else fn.get("name", "")
                        for pattern, prio, kind, rsn, step in SUSPICIOUS_API_CATALOG:
                            if pattern.search(fn_name):
                                _add_candidate(
                                    fn_name,
                                    kind,
                                    prio,
                                    f"{rsn} from {dll}",
                                    step,
                                    evidence_refs=[f"import:{dll}!{fn_name}"],
                                )
                                break
        elif isinstance(raw_imports, list):
            for item in raw_imports:
                fn_name = item if isinstance(item, str) else item.get("name", "")
                dll = item.get("lib", "") if isinstance(item, dict) else ""
                for pattern, prio, kind, rsn, step in SUSPICIOUS_API_CATALOG:
                    if pattern.search(fn_name):
                        ref = f"import:{dll}!{fn_name}" if dll else f"import:{fn_name}"
                        _add_candidate(
                            fn_name,
                            kind,
                            prio,
                            rsn,
                            step,
                            evidence_refs=[ref],
                        )
                        break

        # 2. Anti-Analysis / Evasion Findings
        anti_findings = (
            triage_data.get("anti_analysis")
            or triage_data.get("anti_analysis_findings")
            or triage_data.get("evasion")
            or []
        )
        if isinstance(anti_findings, list):
            for f in anti_findings:
                desc = f if isinstance(f, str) else f.get("description", str(f))
                addr = f.get("address", "") if isinstance(f, dict) else ""
                target_ident = addr or desc[:40]
                _add_candidate(
                    target_ident,
                    "function" if addr else "artifact",
                    TargetPriority.HIGH.value,
                    f"Anti-analysis mechanism detected: {desc}",
                    "simulate execution with r2_esil_simulator to test bypass logic",
                    evidence_refs=[f"anti_analysis:{target_ident}"],
                )

        # 3. Patch Diff Findings
        diff_findings = (
            triage_data.get("diff")
            or triage_data.get("modified_functions")
            or triage_data.get("patch_changes")
            or []
        )
        if isinstance(diff_findings, list):
            for item in diff_findings:
                fn = item if isinstance(item, str) else item.get("function", item.get("name", ""))
                if fn:
                    _add_candidate(
                        fn,
                        "diff",
                        TargetPriority.HIGH.value,
                        "Function modified between binary revisions in patch diff",
                        "analyze control flow changes and security ramifications",
                        evidence_refs=[f"diff_function:{fn}"],
                    )

        # 4. Memory Injection Findings
        memory_injections = (
            triage_data.get("injections")
            or triage_data.get("memory_injections")
            or triage_data.get("injected_threads")
            or []
        )
        if isinstance(memory_injections, list):
            for inj in memory_injections:
                desc = inj if isinstance(inj, str) else inj.get("details", str(inj))
                addr = inj.get("address", "") if isinstance(inj, dict) else ""
                target_name = addr or desc[:40]
                _add_candidate(
                    target_name,
                    "memory",
                    TargetPriority.CRITICAL.value,
                    f"Injected memory region or thread: {desc}",
                    "dump injected module and decompile entrypoint",
                    evidence_refs=[f"memory_injection:{target_name}"],
                )

        # 5. Network C2 / PCAP Correlations
        net_findings = (
            triage_data.get("network")
            or triage_data.get("c2_connections")
            or triage_data.get("suspicious_flows")
            or []
        )
        if isinstance(net_findings, list):
            for flow in net_findings:
                endpoint = (
                    flow if isinstance(flow, str) else flow.get("endpoint", flow.get("dst_ip", ""))
                )
                if endpoint:
                    _add_candidate(
                        endpoint,
                        "network",
                        TargetPriority.HIGH.value,
                        f"External C2 beaconing or communication channel: {endpoint}",
                        "reconstruct stream payload and decode exchanged commands",
                        evidence_refs=[f"pcap_flow:{endpoint}"],
                    )

        # 6. High-Entropy Sections
        sections = triage_data.get("sections") or []
        if isinstance(sections, list):
            for sec in sections:
                if isinstance(sec, dict):
                    entropy = float(sec.get("entropy", 0.0))
                    sec_name = sec.get("name", "")
                    if entropy >= 7.0 and sec_name:
                        _add_candidate(
                            sec_name,
                            "section",
                            TargetPriority.HIGH.value,
                            f"Section {sec_name} exhibits high entropy ({entropy:.2f}) indicating encrypted or packed code",
                            "inspect section entrypoint for unpacker loop or decryption routine",
                            evidence_refs=[f"section_entropy:{sec_name}:{entropy:.2f}"],
                        )

        # 7. Suspicious Strings (URLs, IPs, PowerShell)
        strings_list = triage_data.get("strings") or triage_data.get("suspicious_strings") or []
        if isinstance(strings_list, list):
            for s in strings_list:
                s_text = s if isinstance(s, str) else s.get("string", "")
                if re.search(r"https?://[a-zA-Z0-9.-]+", s_text):
                    _add_candidate(
                        s_text[:60],
                        "string",
                        TargetPriority.HIGH.value,
                        f"Embedded URL string: {s_text[:60]}",
                        "verify string cross-references to identify calling logic",
                        evidence_refs=[f"string_url:{s_text[:40]}"],
                    )
                elif re.search(r"powershell|cmd\.exe|wscript|certutil|bitsadmin", s_text, re.I):
                    _add_candidate(
                        s_text[:60],
                        "string",
                        TargetPriority.HIGH.value,
                        f"Command execution artifact string: {s_text[:60]}",
                        "trace xrefs to determine execution trigger",
                        evidence_refs=[f"string_cmd:{s_text[:40]}"],
                    )

        return extracted

    @classmethod
    def resolve_target_completion(
        cls,
        case: CaseState,
        target_id_or_name: str,
        findings: list[str] | None = None,
        reason: str | None = None,
    ) -> tuple[AnalysisTarget | None, list[str]]:
        """Mark a target completed, unblock dependent targets, and record history.

        Args:
            case: Parent CaseState instance.
            target_id_or_name: Target ID or target identifier.
            findings: Optional list of findings uncovered.
            reason: Optional explanation of completion.

        Returns:
            Tuple of (completed_target, list_of_unblocked_targets).
        """
        # Find and complete target
        completed_target = None
        for t in case.next_targets:
            if t.id == target_id_or_name or t.target == target_id_or_name:
                t.status = TargetStatus.COMPLETED.value
                if reason:
                    t.reason = f"{t.reason} | Completed: {reason}"
                t.updated_at = _utc_now_iso()
                completed_target = t
                break

        if not completed_target:
            return None, []

        completed_ident = completed_target.target
        completed_id = completed_target.id
        unblocked: list[str] = []

        # Unblock any dependent targets waiting on this item
        for other in case.next_targets:
            if (
                other.status == TargetStatus.COMPLETED.value
                or other.status == TargetStatus.REJECTED.value
            ):
                continue

            if completed_ident in other.blockers or completed_id in other.blockers:
                other.blockers = [
                    b for b in other.blockers if b != completed_ident and b != completed_id
                ]
                # If no remaining blockers, transition to pending
                if len(other.blockers) == 0 and other.status == TargetStatus.BLOCKED.value:
                    other.status = TargetStatus.PENDING.value
                    other.updated_at = _utc_now_iso()
                    unblocked.append(other.target)

        # Update case.blocked records
        case.blocked = [
            b
            for b in case.blocked
            if b.target != completed_ident and completed_ident not in b.blocked_by
        ]

        # Record completed step
        step_summary = f"Completed target: {completed_target.target} ({completed_target.kind})"
        if reason:
            step_summary += f" - {reason}"
        if findings:
            step_summary += f" (Findings: {len(findings)})"

        case.record_step(
            step_id=f"step_{uuid.uuid4().hex[:8]}",
            tool_name="priority_queue",
            summary=step_summary,
            phase=case.phase,
            output_summary={
                "target_id": completed_target.id,
                "target": completed_target.target,
                "findings": findings or [],
                "unblocked_targets": unblocked,
            },
        )

        case.last_updated = _utc_now_iso()
        return completed_target, unblocked
