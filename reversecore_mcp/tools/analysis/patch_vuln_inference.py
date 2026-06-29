"""Security Patch Diff Analysis: Automated vulnerability inference from binary patches.

This module extends ``patch_diff_1day`` with a security-focused pattern recognition
engine that can infer *what kind of vulnerability* was fixed from structural changes
in the binary. It is the core of the "1-day exploit" research pipeline.

Pattern recognition approach:
- Added basic blocks with comparison + conditional branch → bounds check added
- Removed calls to dangerous APIs (strcpy, gets, system) → injection fix
- New function calls to validation helpers → input validation added
- Increased function size + added early-return paths → null/error check added
- Changed argument count to known-safe variants (strcpy→strncpy) → safe API migration
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

from fastmcp import Context

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import execute_r2_command as _execute_r2_command
from reversecore_mcp.core.r2_helpers import parse_json_output as _parse_json_output
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# ---------------------------------------------------------------------------
# Vulnerability Inference Database
# ---------------------------------------------------------------------------

# Maps (pattern_name → inference) for security-relevant patch patterns.
# Each entry represents a commonly observed security fix pattern.


@dataclass
class PatchPattern:
    """Describes a recognisable security fix pattern and its inferred vulnerability."""

    name: str
    description: str
    vuln_class: str  # CWE category
    cwe_id: str
    severity: str  # critical / high / medium / low
    indicators: list[str]  # Strings to look for in diff output
    confidence: str  # high / medium / low


SECURITY_PATCH_PATTERNS: list[PatchPattern] = [
    PatchPattern(
        name="bounds_check_added",
        description="Added boundary/length check before buffer operation",
        vuln_class="Buffer Overflow",
        cwe_id="CWE-120",
        severity="critical",
        indicators=["cmp", "jbe", "jle", "jge", "jne", "test", "bounds", "size", "len", "limit"],
        confidence="high",
    ),
    PatchPattern(
        name="safe_api_migration",
        description="Dangerous API replaced with size-bounded variant",
        vuln_class="Buffer Overflow",
        cwe_id="CWE-120",
        severity="critical",
        indicators=[
            "strcpy",
            "strncpy",
            "gets",
            "fgets",
            "sprintf",
            "snprintf",
            "strcat",
            "strncat",
            "memcpy",
            "memmove",
        ],
        confidence="high",
    ),
    PatchPattern(
        name="null_check_added",
        description="Null pointer dereference prevention check added",
        vuln_class="Null Pointer Dereference",
        cwe_id="CWE-476",
        severity="high",
        indicators=["test rax", "test eax", "je", "jz", "null", "nullptr", "0x0"],
        confidence="medium",
    ),
    PatchPattern(
        name="integer_overflow_fix",
        description="Integer overflow check or safe arithmetic added",
        vuln_class="Integer Overflow",
        cwe_id="CWE-190",
        severity="high",
        indicators=[
            "overflow",
            "underflow",
            "wrap",
            "jo",
            "jno",
            "add",
            "mul",
            "imul",
            "unsigned",
            "size_t",
            "uint",
        ],
        confidence="medium",
    ),
    PatchPattern(
        name="command_injection_fix",
        description="Shell command injection fix — sanitization or safe API",
        vuln_class="Command Injection",
        cwe_id="CWE-78",
        severity="critical",
        indicators=[
            "system",
            "popen",
            "execve",
            "shell",
            "sanitize",
            "escape",
            "quote",
            "whitelist",
            "blacklist",
        ],
        confidence="high",
    ),
    PatchPattern(
        name="format_string_fix",
        description="Format string vulnerability fix — literal format added",
        vuln_class="Format String",
        cwe_id="CWE-134",
        severity="high",
        indicators=["printf", "fprintf", "sprintf", "syslog", "format", '"%s"'],
        confidence="medium",
    ),
    PatchPattern(
        name="use_after_free_fix",
        description="Use-after-free prevention — pointer zeroing after free",
        vuln_class="Use After Free",
        cwe_id="CWE-416",
        severity="critical",
        indicators=["free", "null", "nullptr", "zero", "mov.*0x0", "xor"],
        confidence="medium",
    ),
    PatchPattern(
        name="race_condition_fix",
        description="Race condition fix — locking or atomic operation added",
        vuln_class="Race Condition",
        cwe_id="CWE-362",
        severity="high",
        indicators=["lock", "mutex", "atomic", "pthread", "sync", "critical"],
        confidence="low",
    ),
    PatchPattern(
        name="input_validation_added",
        description="Input validation function called before processing",
        vuln_class="Improper Input Validation",
        cwe_id="CWE-20",
        severity="medium",
        indicators=[
            "validate",
            "sanitize",
            "check",
            "verify",
            "isvalid",
            "isdigit",
            "isalpha",
            "isprint",
        ],
        confidence="medium",
    ),
    PatchPattern(
        name="memory_allocation_check",
        description="Return value of malloc/calloc checked for NULL",
        vuln_class="Improper Check for Unusual Conditions",
        cwe_id="CWE-252",
        severity="medium",
        indicators=["malloc", "calloc", "realloc", "alloc", "je", "jz", "test"],
        confidence="low",
    ),
]

# ---------------------------------------------------------------------------
# Pattern matching helpers
# ---------------------------------------------------------------------------

_DANGEROUS_APIS = frozenset(
    {
        "strcpy",
        "strcat",
        "sprintf",
        "gets",
        "scanf",
        "vsprintf",
        "system",
        "popen",
        "execve",
        "execl",
        "execlp",
        "printf",
        "fprintf",
        "syslog",
    }
)

_SAFE_REPLACEMENTS: dict[str, str] = {
    "strcpy": "strncpy / strlcpy",
    "strcat": "strncat / strlcat",
    "sprintf": "snprintf",
    "gets": "fgets",
    "system": "execve with sanitized args",
    "popen": "execve with pipe",
}


def _match_patterns(
    diff_text: str,
    func_name: str,
    size_delta: int,
    block_delta: int,
) -> list[dict[str, Any]]:
    """Match security patch patterns against diff output.

    Args:
        diff_text: Raw radiff2 / disassembly diff output.
        func_name: Name of the function being analyzed.
        size_delta: Change in function size (positive = function grew).
        block_delta: Change in basic block count (positive = more blocks).

    Returns:
        List of matched pattern dicts sorted by severity.
    """
    matches: list[dict[str, Any]] = []
    text_lower = diff_text.lower()

    for pattern in SECURITY_PATCH_PATTERNS:
        score = 0
        matched_indicators: list[str] = []

        for indicator in pattern.indicators:
            if indicator.lower() in text_lower:
                score += 1
                matched_indicators.append(indicator)

        # Structural heuristics boost confidence
        if pattern.name == "bounds_check_added" and size_delta > 0 and block_delta > 0:
            score += 2
        if pattern.name == "null_check_added" and block_delta > 0:
            score += 1
        if pattern.name == "input_validation_added" and size_delta > 10:
            score += 1

        if score >= 2:
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            matches.append(
                {
                    "pattern": pattern.name,
                    "description": pattern.description,
                    "vuln_class": pattern.vuln_class,
                    "cwe_id": pattern.cwe_id,
                    "severity": pattern.severity,
                    "severity_score": severity_order.get(pattern.severity, 0),
                    "confidence": pattern.confidence,
                    "matched_indicators": matched_indicators,
                    "indicator_score": score,
                    "function": func_name,
                    "size_change": size_delta,
                    "block_count_change": block_delta,
                    "exploitation_hint": _get_exploitation_hint(pattern),
                }
            )

    matches.sort(key=lambda m: (m["severity_score"], m["indicator_score"]), reverse=True)
    return matches


def _get_exploitation_hint(pattern: PatchPattern) -> str:
    """Return a concise exploitation hint for a given patch pattern.

    Args:
        pattern: The matched security patch pattern.

    Returns:
        Human-readable hint for how to exploit the vulnerability in the *old* binary.
    """
    hints: dict[str, str] = {
        "bounds_check_added": (
            "Old binary lacks boundary check. Supply input longer than expected buffer "
            "to overflow stack/heap. Use cyclic(200) to find crash offset, then build_rop_chain()."
        ),
        "safe_api_migration": (
            "Old binary uses unbounded API. Craft oversized input to overflow adjacent memory. "
            "Check if strcpy/gets caller is user-reachable via vulnerability_hunter()."
        ),
        "null_check_added": (
            "Old binary dereferences pointer without null check. "
            "Supply NULL/0 for relevant input to trigger NULL deref crash (DoS or info leak)."
        ),
        "integer_overflow_fix": (
            "Old binary has integer overflow. Supply very large size values (e.g., SIZE_MAX-1) "
            "to cause wrap-around → subsequent allocation too small → heap overflow."
        ),
        "command_injection_fix": (
            "Old binary passes unsanitized input to shell. "
            "Inject shell metacharacters: ; | && ` $() to execute arbitrary commands."
        ),
        "format_string_fix": (
            "Old binary passes user input directly as printf format string. "
            "Use %n/%s/%x to leak stack/heap memory or write arbitrary values."
        ),
        "use_after_free_fix": (
            "Old binary may use freed memory. Trigger free then reallocate with controlled data "
            "to overwrite freed object → type confusion or code execution."
        ),
        "race_condition_fix": (
            "Old binary has TOCTOU or race condition. "
            "Use concurrent threads/processes to win the race for privilege escalation or bypass."
        ),
        "input_validation_added": (
            "Old binary accepts malformed input without validation. "
            "Try boundary values: empty string, very long string, negative integers, special chars."
        ),
        "memory_allocation_check": (
            "Old binary does not check malloc() return value. "
            "Trigger OOM (e.g., via ulimit) to cause NULL pointer dereference."
        ),
    }
    return hints.get(
        pattern.name, "Analyze the patched code diff to identify the vulnerability trigger."
    )


async def _get_function_metadata(
    binary_path: str,
    func_name: str,
    timeout: int,
) -> dict[str, Any]:
    """Get basic block count and size for a function via radare2.

    Args:
        binary_path: Path to binary.
        func_name: Function name.
        timeout: Command timeout.

    Returns:
        Dict with 'size', 'nbbs' (block count), 'address'.
    """
    try:
        output, _ = await _execute_r2_command(
            binary_path,
            [f"s {func_name}", "afij"],
            analysis_level="aa",
            max_output_size=1_000_000,
            base_timeout=timeout,
        )
        parsed = _parse_json_output(output)
        if isinstance(parsed, list) and parsed:
            info = parsed[0]
            return {
                "size": info.get("size", 0),
                "nbbs": info.get("nbbs", 0),
                "address": info.get("offset", 0),
                "name": info.get("name", func_name),
            }
    except Exception as exc:
        logger.debug("Could not get function info for %s: %s", func_name, exc)
    return {"size": 0, "nbbs": 0, "address": 0, "name": func_name}


async def _get_disasm_diff(
    func_name: str,
    path_a: str,
    path_b: str,
    timeout: int,
) -> str:
    """Get function-level disassembly diff between two binaries.

    Args:
        func_name: Function to diff.
        path_a: Path to old binary.
        path_b: Path to new binary.
        timeout: Subprocess timeout.

    Returns:
        Raw diff output string.
    """
    try:
        cmd = ["radiff2", "-g", func_name, path_a, path_b]
        output, _ = await execute_subprocess_async(cmd, max_output_size=5_000_000, timeout=timeout)
        return output
    except Exception as exc:
        logger.debug("radiff2 function diff failed for %s: %s", func_name, exc)
        return ""


# ---------------------------------------------------------------------------
# MCP Tool
# ---------------------------------------------------------------------------


@log_execution(tool_name="analyze_patch_diff_auto")
@track_metrics("analyze_patch_diff_auto")
@handle_tool_errors
async def analyze_patch_diff_auto(
    file_path_old: str,
    file_path_new: str,
    top_functions: int = 10,
    auto_infer_vuln: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    ctx: Context | None = None,
) -> ToolResult:
    """Automatically infer vulnerabilities from binary patch differences.

    This tool goes beyond structural binary diffing (``diff_binaries``,
    ``patch_diff_1day``) by applying a **security pattern recognition engine**
    to the changed functions. It answers: *"What vulnerability was fixed?"* and
    *"How can I exploit the old version?"*

    The workflow:
    1. Compute overall similarity and identify the most-changed functions via
       ``radiff2``.
    2. For each changed function, extract disassembly diffs and structural
       metadata (size change, basic block delta).
    3. Apply 10 security patch pattern rules (bounds check added, safe API
       migration, null check, integer overflow, command injection, etc.).
    4. Score matches by confidence and severity, generating per-function
       vulnerability inferences with exploitation hints.
    5. Return a ranked report with CVE-style vulnerability candidates and
       actionable next steps.

    Args:
        file_path_old: Path to the **pre-patch** (vulnerable) binary.
        file_path_new: Path to the **post-patch** binary.
        top_functions: Maximum number of changed functions to analyse in
            detail. Higher values are slower but more thorough. Default: 10.
        auto_infer_vuln: When ``True`` (default), runs the pattern recognition
            engine on each changed function. Set to ``False`` for raw diff only.
        timeout: Total analysis timeout in seconds. Default: 300.
        ctx: Optional FastMCP context for streaming progress.

    Returns:
        ToolResult containing:
        - ``similarity``: Float 0.0–1.0 overall binary similarity score.
        - ``patch_verdict``: High-level assessment (SECURITY_PATCH / FEATURE_UPDATE / REFACTOR).
        - ``vulnerability_candidates``: Ranked list of inferred vulnerability candidates.
        - ``top_vuln``: Highest-severity vulnerability candidate with exploitation hint.
        - ``changed_functions``: Per-function analysis with pattern matches.
        - ``dangerous_api_changes``: Dangerous APIs added or removed between versions.
        - ``next_steps``: Prioritised researcher action items.

    Raises:
        ValidationError: If either binary path is invalid.

    Example:
        >>> result = await analyze_patch_diff_auto(
        ...     "workspace/sqlite3_3531",
        ...     "workspace/sqlite3_3532",
        ...     top_functions=5,
        ... )
        >>> print(result.data["top_vuln"]["cwe_id"])
        'CWE-190'
    """
    validated_old = validate_file_path(file_path_old)
    validated_new = validate_file_path(file_path_new)

    if ctx:
        await ctx.info(f"🔍 Patch Diff Auto: {validated_old.name} → {validated_new.name}")
        await ctx.report_progress(5, 100)

    # ── Step 1: Compute overall similarity ──────────────────────────────────
    try:
        sim_cmd = ["radiff2", "-s", str(validated_old), str(validated_new)]
        sim_out, _ = await execute_subprocess_async(sim_cmd, max_output_size=1_000_000, timeout=60)
        similarity = 0.0
        m = re.search(r"similarity:\s*([\d.]+)", sim_out)
        if m:
            similarity = float(m.group(1))
    except Exception:
        similarity = 0.0

    if ctx:
        await ctx.info(f"   Similarity score: {similarity:.3f}")
        await ctx.report_progress(15, 100)

    # Quick bail-out for identical binaries
    if similarity > 0.999:
        return success(
            {
                "similarity": similarity,
                "patch_verdict": "IDENTICAL",
                "vulnerability_candidates": [],
                "top_vuln": None,
                "changed_functions": [],
                "dangerous_api_changes": {},
                "next_steps": ["Binaries are identical — no patch to analyse."],
            }
        )

    # ── Step 2: Enumerate changed functions ─────────────────────────────────
    try:
        diff_cmd = ["radiff2", "-C", str(validated_old), str(validated_new)]
        diff_out, _ = await execute_subprocess_async(
            diff_cmd, max_output_size=10_000_000, timeout=min(timeout, 120)
        )
    except Exception as exc:
        return failure("DIFF_ERROR", f"radiff2 failed: {exc}")

    if ctx:
        await ctx.report_progress(30, 100)

    # Parse changed function addresses from radiff2 -C output
    # Format: "addr_a addr_b type name_a name_b [similarity]"
    changed_funcs: list[dict[str, Any]] = []
    addr_pattern = re.compile(r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\w+)\s+(\S+)")

    for line in diff_out.splitlines():
        m = addr_pattern.search(line)
        if m:
            addr_a, addr_b, change_type, name = m.groups()
            if change_type not in ("MATCH", "same"):
                changed_funcs.append(
                    {
                        "addr_old": addr_a,
                        "addr_new": addr_b,
                        "change_type": change_type,
                        "name": name,
                    }
                )

    # If no structured output, try to extract function names heuristically
    if not changed_funcs:
        for line in diff_out.splitlines()[:200]:
            line = line.strip()
            if line and not line.startswith("#"):
                name_m = re.search(r"(sym\.\S+|fcn\.\S+|main|\w+_\w+)", line)
                if name_m:
                    changed_funcs.append(
                        {
                            "addr_old": "0x0",
                            "addr_new": "0x0",
                            "change_type": "modified",
                            "name": name_m.group(1),
                        }
                    )

    # Sort by "most changed first" (type != MATCH signals bigger changes)
    # Deduplicate by name
    seen_names: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for cf in changed_funcs:
        if cf["name"] not in seen_names:
            seen_names.add(cf["name"])
            deduped.append(cf)
    changed_funcs = deduped[:top_functions]

    if ctx:
        await ctx.info(f"   Found {len(changed_funcs)} changed functions")
        await ctx.report_progress(40, 100)

    # ── Step 3: Detect dangerous API changes ────────────────────────────────
    # Get import lists for both binaries
    async def _get_imports(path: str) -> set[str]:
        try:
            out, _ = await execute_subprocess_async(
                ["radiff2", "-i", path], max_output_size=1_000_000, timeout=30
            )
            names: set[str] = set()
            for ln in out.splitlines():
                for api in _DANGEROUS_APIS:
                    if api in ln.lower():
                        names.add(api)
            return names
        except Exception:
            return set()

    imports_old, imports_new = await asyncio.gather(
        _get_imports(str(validated_old)),
        _get_imports(str(validated_new)),
    )

    removed_apis = imports_old - imports_new
    added_apis = imports_new - imports_old

    dangerous_api_changes: dict[str, Any] = {
        "removed_dangerous_apis": list(removed_apis),
        "added_dangerous_apis": list(added_apis),
        "safe_replacements": {
            api: _SAFE_REPLACEMENTS.get(api, "safer alternative")
            for api in removed_apis
            if api in _SAFE_REPLACEMENTS
        },
    }

    if ctx:
        await ctx.report_progress(50, 100)

    # ── Step 4: Per-function analysis + pattern matching ────────────────────
    all_candidates: list[dict[str, Any]] = []
    analyzed_functions: list[dict[str, Any]] = []

    if auto_infer_vuln:
        for idx, func in enumerate(changed_funcs):
            func_name = func["name"]

            if ctx:
                await ctx.info(f"   Analysing function {idx + 1}/{len(changed_funcs)}: {func_name}")

            # Get size and block metadata for both versions
            meta_old, meta_new = await asyncio.gather(
                _get_function_metadata(str(validated_old), func_name, 30),
                _get_function_metadata(str(validated_new), func_name, 30),
            )

            size_delta = meta_new["size"] - meta_old["size"]
            block_delta = meta_new["nbbs"] - meta_old["nbbs"]

            # Get disassembly diff for this function
            disasm_diff = await _get_disasm_diff(
                func_name,
                str(validated_old),
                str(validated_new),
                timeout=30,
            )

            # Also include the raw radiff2 -C output for this function
            combined_diff = diff_out + "\n" + disasm_diff

            # Match security patterns
            pattern_matches = _match_patterns(combined_diff, func_name, size_delta, block_delta)

            func_analysis: dict[str, Any] = {
                "function": func_name,
                "change_type": func.get("change_type", "modified"),
                "addr_old": func.get("addr_old"),
                "addr_new": func.get("addr_new"),
                "size_old": meta_old["size"],
                "size_new": meta_new["size"],
                "size_delta": size_delta,
                "block_count_old": meta_old["nbbs"],
                "block_count_new": meta_new["nbbs"],
                "block_delta": block_delta,
                "pattern_matches": pattern_matches,
                "top_pattern": pattern_matches[0] if pattern_matches else None,
            }
            analyzed_functions.append(func_analysis)
            all_candidates.extend(pattern_matches)

            progress = 50 + int(45 * (idx + 1) / max(len(changed_funcs), 1))
            if ctx:
                await ctx.report_progress(progress, 100)

    # Remove API-removal candidates from imports (add them as simple candidates)
    for api in removed_apis:
        all_candidates.append(
            {
                "pattern": "safe_api_migration",
                "description": f"Dangerous API '{api}' removed in patch",
                "vuln_class": "Buffer Overflow / Command Injection",
                "cwe_id": "CWE-120",
                "severity": "critical",
                "severity_score": 4,
                "confidence": "high",
                "matched_indicators": [api],
                "indicator_score": 3,
                "function": "imports",
                "size_change": 0,
                "block_count_change": 0,
                "exploitation_hint": (
                    f"Old binary uses {api}. "
                    f"Replace with: {_SAFE_REPLACEMENTS.get(api, 'safer variant')}. "
                    "Supply oversized input to overflow adjacent memory."
                ),
            }
        )

    # Sort all candidates by severity + confidence
    all_candidates.sort(key=lambda c: (c["severity_score"], c["indicator_score"]), reverse=True)

    # Deduplicate by pattern+function
    seen_candidates: set[tuple[str, str]] = set()
    unique_candidates: list[dict[str, Any]] = []
    for cand in all_candidates:
        key = (cand["pattern"], cand["function"])
        if key not in seen_candidates:
            seen_candidates.add(key)
            unique_candidates.append(cand)

    # ── Step 5: Determine patch verdict ─────────────────────────────────────
    critical_count = sum(1 for c in unique_candidates if c["severity"] == "critical")
    high_count = sum(1 for c in unique_candidates if c["severity"] == "high")

    if critical_count >= 1 or removed_apis:
        patch_verdict = "SECURITY_PATCH"
    elif high_count >= 2:
        patch_verdict = "SECURITY_HARDENING"
    elif unique_candidates:
        patch_verdict = "POSSIBLE_SECURITY_FIX"
    else:
        patch_verdict = "FEATURE_UPDATE_OR_REFACTOR"

    # ── Next steps ──────────────────────────────────────────────────────────
    next_steps: list[str] = []
    if patch_verdict == "SECURITY_PATCH":
        next_steps.append(
            "[CRITICAL] Security patch detected. The old binary is likely exploitable. "
            "Run vulnerability_hunter() on the old binary to confirm."
        )
    if unique_candidates:
        top = unique_candidates[0]
        next_steps.append(
            f"[HIGH] Top candidate: {top['vuln_class']} ({top['cwe_id']}) in "
            f"function '{top['function']}'. "
            f"Exploitation hint: {top['exploitation_hint'][:120]}..."
        )
    if removed_apis:
        next_steps.append(
            f"[HIGH] Removed dangerous APIs: {', '.join(removed_apis)}. "
            "These functions in the OLD binary are primary exploit targets."
        )
    next_steps.append(
        "[INFO] Run run_fuzzing_campaign() on the OLD binary with seeds crafted for "
        "the identified vulnerability class to find a working crash."
    )

    if ctx:
        await ctx.report_progress(100, 100)
        await ctx.info(
            f"✅ Analysis complete — {patch_verdict}, "
            f"{len(unique_candidates)} vulnerability candidates"
        )

    return success(
        {
            "similarity": round(similarity, 4),
            "patch_verdict": patch_verdict,
            "vulnerability_candidates": unique_candidates[:20],
            "top_vuln": unique_candidates[0] if unique_candidates else None,
            "changed_functions": analyzed_functions,
            "dangerous_api_changes": dangerous_api_changes,
            "statistics": {
                "functions_changed": len(changed_funcs),
                "functions_analysed": len(analyzed_functions),
                "candidates_found": len(unique_candidates),
                "critical_candidates": critical_count,
                "high_candidates": high_count,
            },
            "next_steps": next_steps,
        }
    )
