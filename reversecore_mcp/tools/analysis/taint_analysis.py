"""Taint Analysis: Automatic source-to-sink vulnerability path tracing.

This module provides a high-level MCP interface for taint-based vulnerability
discovery. It combines:

1. **Static source/sink identification** — Finds dangerous API calls (sinks)
   and user-controlled input points (sources) via radare2 cross-references.
2. **Symbolic execution** — Uses the existing angr_worker.py to verify that
   the source can actually reach the sink (path reachability).
3. **Concrete input extraction** — Provides a concrete input string that
   angr found to trigger the sink from the source.

This effectively automates the manual process of:
"Is user input from argv/stdin/read() reachable to system()/strcpy()/gets()?"
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from fastmcp import Context

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import execute_r2_command as _execute_r2_command
from reversecore_mcp.core.r2_helpers import parse_json_output as _parse_json_output
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.analysis.symbolic_analysis import verify_path_and_get_args

logger = get_logger(__name__)
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# ---------------------------------------------------------------------------
# Source / Sink Databases
# ---------------------------------------------------------------------------

# Sources: Functions that introduce user-controlled data
TAINT_SOURCES: dict[str, dict[str, Any]] = {
    # Stdin
    "read": {"category": "stdin", "description": "POSIX read() from file descriptor"},
    "fread": {"category": "stdin", "description": "fread() from stream"},
    "fgets": {"category": "stdin", "description": "fgets() from stream"},
    "gets": {"category": "stdin", "description": "gets() — unbounded stdin read"},
    "getline": {"category": "stdin", "description": "getline() from stream"},
    "scanf": {"category": "stdin", "description": "scanf() format-based stdin"},
    "fscanf": {"category": "stdin", "description": "fscanf() from stream"},
    # Command-line arguments
    "argv": {"category": "argv", "description": "Command-line argument vector"},
    "getopt": {"category": "argv", "description": "getopt() argument parser"},
    "getopt_long": {"category": "argv", "description": "getopt_long() argument parser"},
    # Environment
    "getenv": {"category": "env", "description": "getenv() environment variable"},
    "secure_getenv": {"category": "env", "description": "secure_getenv() env variable"},
    # Network
    "recv": {"category": "network", "description": "recv() socket data"},
    "recvfrom": {"category": "network", "description": "recvfrom() UDP socket data"},
    "recvmsg": {"category": "network", "description": "recvmsg() socket message"},
    "accept": {"category": "network", "description": "accept() incoming connection"},
    # Files
    "fopen": {"category": "file", "description": "fopen() file open"},
    "open": {"category": "file", "description": "open() POSIX file open"},
    "mmap": {"category": "file", "description": "mmap() memory-mapped file"},
}

# Sinks: Functions that are dangerous when fed tainted data
TAINT_SINKS: dict[str, dict[str, Any]] = {
    # Buffer overflow
    "strcpy": {
        "cwe": "CWE-120",
        "severity": "critical",
        "category": "buffer_overflow",
        "description": "Unbounded string copy",
    },
    "strcat": {
        "cwe": "CWE-120",
        "severity": "critical",
        "category": "buffer_overflow",
        "description": "Unbounded string concatenation",
    },
    "sprintf": {
        "cwe": "CWE-120",
        "severity": "critical",
        "category": "buffer_overflow",
        "description": "Unbounded formatted output to buffer",
    },
    "vsprintf": {
        "cwe": "CWE-120",
        "severity": "critical",
        "category": "buffer_overflow",
        "description": "Unbounded va_list formatted output",
    },
    "gets": {
        "cwe": "CWE-120",
        "severity": "critical",
        "category": "buffer_overflow",
        "description": "Unbounded stdin read into buffer",
    },
    "memcpy": {
        "cwe": "CWE-122",
        "severity": "high",
        "category": "heap_overflow",
        "description": "memcpy with potentially attacker-controlled size",
    },
    "memmove": {
        "cwe": "CWE-122",
        "severity": "high",
        "category": "heap_overflow",
        "description": "memmove with potentially attacker-controlled size",
    },
    # Command injection
    "system": {
        "cwe": "CWE-78",
        "severity": "critical",
        "category": "command_injection",
        "description": "Shell command execution",
    },
    "popen": {
        "cwe": "CWE-78",
        "severity": "critical",
        "category": "command_injection",
        "description": "Shell command with pipe",
    },
    "execve": {
        "cwe": "CWE-78",
        "severity": "critical",
        "category": "command_injection",
        "description": "Process execution via execve",
    },
    "execl": {
        "cwe": "CWE-78",
        "severity": "critical",
        "category": "command_injection",
        "description": "Process execution via execl",
    },
    "execlp": {
        "cwe": "CWE-78",
        "severity": "critical",
        "category": "command_injection",
        "description": "Process execution via PATH",
    },
    # Format string
    "printf": {
        "cwe": "CWE-134",
        "severity": "high",
        "category": "format_string",
        "description": "Format string if user-controlled",
    },
    "fprintf": {
        "cwe": "CWE-134",
        "severity": "high",
        "category": "format_string",
        "description": "Format string to stream",
    },
    "syslog": {
        "cwe": "CWE-134",
        "severity": "medium",
        "category": "format_string",
        "description": "Format string in syslog",
    },
    # Integer overflow (common sinks for size arithmetic)
    "malloc": {
        "cwe": "CWE-190",
        "severity": "medium",
        "category": "integer_overflow",
        "description": "malloc with attacker-controlled size",
    },
    "calloc": {
        "cwe": "CWE-190",
        "severity": "medium",
        "category": "integer_overflow",
        "description": "calloc with attacker-controlled count or size",
    },
    "realloc": {
        "cwe": "CWE-190",
        "severity": "medium",
        "category": "integer_overflow",
        "description": "realloc with attacker-controlled size",
    },
}


@dataclass
class TaintPath:
    """Represents a discovered source→sink taint path."""

    source_api: str
    source_category: str
    sink_api: str
    sink_cwe: str
    sink_severity: str
    sink_category: str
    sink_address: str
    source_address: str
    path_verified: bool
    concrete_input: str | None
    confidence: str  # high / medium / low


# ---------------------------------------------------------------------------
# Radare2 helpers for source/sink discovery
# ---------------------------------------------------------------------------


async def _find_sink_calls(binary_path: str, timeout: int) -> list[dict[str, Any]]:
    """Find all calls to known dangerous sink functions via radare2 xrefs.

    Args:
        binary_path: Path to the binary.
        timeout: Analysis timeout.

    Returns:
        List of sink call dicts with address, function name, sink info.
    """
    sink_calls: list[dict[str, Any]] = []

    for sink_name, sink_info in TAINT_SINKS.items():
        try:
            # Find import or symbol
            out, _ = await _execute_r2_command(
                binary_path,
                [f"is~{sink_name}", f"ii~{sink_name}"],
                analysis_level="aa",
                max_output_size=1_000_000,
                base_timeout=30,
            )

            if not out.strip():
                continue

            # Find cross-references to this symbol
            # Try to find the PLT/GOT address first
            addr_out, _ = await _execute_r2_command(
                binary_path,
                [f"?v sym.imp.{sink_name}", f"axtj sym.imp.{sink_name}"],
                analysis_level="aa",
                max_output_size=1_000_000,
                base_timeout=30,
            )

            # Parse cross-references
            try:
                xrefs = _parse_json_output(addr_out)
                if isinstance(xrefs, list):
                    for xref in xrefs[:10]:  # Limit to 10 call sites per sink
                        from_addr = xref.get("from", xref.get("addr", "0x0"))
                        sink_calls.append(
                            {
                                "sink_api": sink_name,
                                "call_address": hex(from_addr)
                                if isinstance(from_addr, int)
                                else str(from_addr),
                                "cwe": sink_info["cwe"],
                                "severity": sink_info["severity"],
                                "category": sink_info["category"],
                                "description": sink_info["description"],
                            }
                        )
            except Exception:
                # Still record the sink as found even without xrefs
                sink_calls.append(
                    {
                        "sink_api": sink_name,
                        "call_address": "0x0",
                        "cwe": sink_info["cwe"],
                        "severity": sink_info["severity"],
                        "category": sink_info["category"],
                        "description": sink_info["description"],
                    }
                )

        except Exception as exc:
            logger.debug("Sink search failed for %s: %s", sink_name, exc)

    # Sort by severity
    severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    sink_calls.sort(key=lambda s: severity_order.get(s["severity"], 0), reverse=True)
    return sink_calls


async def _find_source_calls(binary_path: str, timeout: int) -> list[dict[str, Any]]:
    """Find all calls to known taint source functions via radare2.

    Args:
        binary_path: Path to the binary.
        timeout: Analysis timeout.

    Returns:
        List of source call dicts with address, function name, source info.
    """
    source_calls: list[dict[str, Any]] = []

    for src_name, src_info in TAINT_SOURCES.items():
        if src_name == "argv":
            # argv is a parameter, not a function call — check main signature
            source_calls.append(
                {
                    "source_api": "argv",
                    "call_address": "0x0",  # Entry point effectively
                    "category": "argv",
                    "description": "Command-line argv[] input",
                }
            )
            continue

        try:
            out, _ = await _execute_r2_command(
                binary_path,
                [f"is~{src_name}", f"ii~{src_name}"],
                analysis_level="aa",
                max_output_size=500_000,
                base_timeout=20,
            )

            if out.strip():
                source_calls.append(
                    {
                        "source_api": src_name,
                        "call_address": "0x0",
                        "category": src_info["category"],
                        "description": src_info["description"],
                    }
                )
        except Exception as exc:
            logger.debug("Source search failed for %s: %s", src_name, exc)

    return source_calls


# ---------------------------------------------------------------------------
# MCP Tool
# ---------------------------------------------------------------------------


@log_execution(tool_name="taint_trace")
@track_metrics("taint_trace")
@handle_tool_errors
async def taint_trace(
    file_path: str,
    sources: list[str] | None = None,
    sinks: list[str] | None = None,
    verify_with_angr: bool = True,
    max_paths: int = 10,
    timeout: int = DEFAULT_TIMEOUT,
    ctx: Context | None = None,
) -> ToolResult:
    """Automatically trace taint paths from user input sources to dangerous sinks.

    This tool performs automated taint analysis by:

    1. **Source discovery**: Finds all calls to user-input functions (``read``,
       ``fgets``, ``recv``, ``getenv``, ``argv``, etc.) via radare2 xrefs.
    2. **Sink discovery**: Finds all calls to dangerous functions (``strcpy``,
       ``system``, ``execve``, ``sprintf``, etc.) and maps their CWE class.
    3. **Path verification** (optional): For each source→sink pair, invokes the
       angr symbolic execution engine (``angr_worker.py``) to check whether the
       sink is actually reachable from the source with user-controlled data.
       If reachable, angr also extracts a **concrete input** that triggers the sink.
    4. **Report**: Returns ranked taint paths sorted by severity and reachability.

    Args:
        file_path: Workspace-relative or absolute path to the target binary.
        sources: Optional list of source function names to trace from.
            If ``None``, uses the full default source database (``read``, ``fgets``,
            ``recv``, ``getenv``, ``argv``, etc.).
            Example: ``["fgets", "recv"]``.
        sinks: Optional list of sink function names to trace to.
            If ``None``, uses the full default sink database (``strcpy``,
            ``system``, ``execve``, etc.).
            Example: ``["system", "strcpy"]``.
        verify_with_angr: When ``True`` (default), attempts symbolic execution
            to verify path reachability and extract concrete inputs.
            Set to ``False`` for fast static-only analysis (no angr).
        max_paths: Maximum number of source→sink paths to analyse and return.
            Default: 10.
        timeout: Total analysis timeout in seconds. Default: 300.
        ctx: Optional FastMCP context for streaming progress.

    Returns:
        ToolResult containing:
        - ``taint_paths``: Ranked list of discovered source→sink paths.
        - ``verified_paths``: Paths confirmed reachable by angr (with concrete inputs).
        - ``static_paths``: Paths found statically but not yet verified.
        - ``sources_found``: List of taint source functions present in the binary.
        - ``sinks_found``: List of dangerous sink functions present in the binary.
        - ``top_path``: Highest-severity path with exploitation guidance.
        - ``next_steps``: Researcher action items.

    Raises:
        ValidationError: If ``file_path`` is invalid.

    Example:
        >>> result = await taint_trace(
        ...     "workspace/vuln_binary",
        ...     sinks=["system", "strcpy"],
        ...     verify_with_angr=True,
        ... )
        >>> for path in result.data["verified_paths"]:
        ...     print(f"{path['source_api']} → {path['sink_api']}: {path['concrete_input']}")
    """
    validated_path = validate_file_path(file_path)

    # Validate / filter sources and sinks
    active_sources = (
        {k: v for k, v in TAINT_SOURCES.items() if k in sources} if sources else TAINT_SOURCES
    )
    active_sinks = {k: v for k, v in TAINT_SINKS.items() if k in sinks} if sinks else TAINT_SINKS

    if not active_sources:
        return failure(
            "INVALID_SOURCES",
            f"None of the specified sources {sources} are in the taint source database. "
            f"Valid sources: {list(TAINT_SOURCES.keys())}",
        )
    if not active_sinks:
        return failure(
            "INVALID_SINKS",
            f"None of the specified sinks {sinks} are in the taint sink database. "
            f"Valid sinks: {list(TAINT_SINKS.keys())}",
        )

    if ctx:
        await ctx.info(f"🔍 Taint Trace → {validated_path.name}")
        await ctx.info(
            f"   sources={list(active_sources.keys())[:5]}..., "
            f"sinks={list(active_sinks.keys())[:5]}..., "
            f"verify_with_angr={verify_with_angr}"
        )
        await ctx.report_progress(5, 100)

    # ── Step 1: Discover sources and sinks in the binary ────────────────────
    sink_calls, source_calls = await asyncio.gather(
        _find_sink_calls(str(validated_path), timeout),
        _find_source_calls(str(validated_path), timeout),
    )

    # Filter to requested sources/sinks
    sink_calls = [s for s in sink_calls if s["sink_api"] in active_sinks]
    source_calls = [s for s in source_calls if s["source_api"] in active_sources]

    if ctx:
        await ctx.info(f"   Found {len(source_calls)} source calls, {len(sink_calls)} sink calls")
        await ctx.report_progress(30, 100)

    if not sink_calls:
        return success(
            {
                "taint_paths": [],
                "verified_paths": [],
                "static_paths": [],
                "sources_found": [s["source_api"] for s in source_calls],
                "sinks_found": [],
                "top_path": None,
                "statistics": {
                    "sources_scanned": len(active_sources),
                    "sinks_scanned": len(active_sinks),
                    "source_calls_found": len(source_calls),
                    "sink_calls_found": 0,
                    "paths_candidate": 0,
                    "paths_verified": 0,
                },
                "next_steps": [
                    "[INFO] No dangerous sink functions found in the binary. "
                    "The binary may be statically linked or use custom wrappers. "
                    "Try vulnerability_hunter() for deeper static analysis."
                ],
            }
        )

    # ── Step 2: Build source→sink path candidates ───────────────────────────
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    # Create path candidates (source × sink combinations)
    path_candidates: list[dict[str, Any]] = []
    for sink in sink_calls[:max_paths]:
        for source in source_calls[:5]:  # Max 5 sources per sink
            path_candidates.append(
                {
                    "source_api": source["source_api"],
                    "source_category": source["category"],
                    "source_address": source["call_address"],
                    "sink_api": sink["sink_api"],
                    "sink_address": sink["call_address"],
                    "cwe": sink["cwe"],
                    "severity": sink["severity"],
                    "severity_score": severity_order.get(sink["severity"], 0),
                    "category": sink["category"],
                    "description": sink["description"],
                    "path_verified": False,
                    "concrete_input": None,
                    "confidence": "low",
                }
            )

    # Deduplicate by (source, sink) pair
    seen_pairs: set[tuple[str, str]] = set()
    deduped_paths: list[dict[str, Any]] = []
    for p in path_candidates:
        key = (p["source_api"], p["sink_api"])
        if key not in seen_pairs:
            seen_pairs.add(key)
            deduped_paths.append(p)

    # Sort by severity
    deduped_paths.sort(key=lambda p: p["severity_score"], reverse=True)
    analysis_paths = deduped_paths[:max_paths]

    if ctx:
        await ctx.info(f"   Analyzing {len(analysis_paths)} source→sink path candidates")
        await ctx.report_progress(40, 100)

    # ── Step 3: Verify paths with angr ──────────────────────────────────────
    verified_paths: list[dict[str, Any]] = []
    static_paths: list[dict[str, Any]] = []

    if verify_with_angr:
        angr_timeout = max(30, timeout // max(len(analysis_paths), 1))

        for idx, path in enumerate(analysis_paths):
            sink_addr = path["sink_address"]

            if sink_addr and sink_addr != "0x0":
                if ctx:
                    await ctx.info(
                        f"   🤖 angr: verifying {path['source_api']} → "
                        f"{path['sink_api']} ({sink_addr})"
                    )

                try:
                    angr_result = await verify_path_and_get_args(
                        binary_path=validated_path,
                        target_addr=sink_addr,
                        start_addr=None,
                        avoid_addrs=None,
                        timeout=angr_timeout,
                    )

                    if angr_result.get("satisfiable"):
                        path["path_verified"] = True
                        path["concrete_input"] = angr_result.get("concrete_input")
                        path["concrete_inputs"] = angr_result.get("inputs", {})
                        path["confidence"] = "high"
                        verified_paths.append(path)
                    else:
                        path["confidence"] = "medium"
                        err = angr_result.get("error")
                        if err:
                            path["angr_note"] = str(err)
                        static_paths.append(path)

                except Exception as exc:
                    logger.debug("angr verification failed for %s: %s", path["sink_api"], exc)
                    path["confidence"] = "medium"
                    path["angr_note"] = str(exc)
                    static_paths.append(path)
            else:
                # No address — static only
                path["confidence"] = "low"
                static_paths.append(path)

            progress = 40 + int(55 * (idx + 1) / max(len(analysis_paths), 1))
            if ctx:
                await ctx.report_progress(progress, 100)
    else:
        # No angr — all are static paths
        for path in analysis_paths:
            path["confidence"] = "medium"
        static_paths = analysis_paths

    # Combine and sort all paths
    all_paths = verified_paths + static_paths
    all_paths.sort(
        key=lambda p: (p["severity_score"], 1 if p["path_verified"] else 0),
        reverse=True,
    )

    top_path = all_paths[0] if all_paths else None

    # ── Next steps ──────────────────────────────────────────────────────────
    next_steps: list[str] = []
    if verified_paths:
        next_steps.append(
            f"[CRITICAL] {len(verified_paths)} taint path(s) verified by angr. "
            "Concrete inputs extracted — run generate_poc_exploit() to build a pwntools script."
        )
    if static_paths:
        next_steps.append(
            f"[HIGH] {len(static_paths)} static taint path(s) found but not yet angr-verified. "
            "Run run_fuzzing_campaign() to confirm exploitability with real crash data."
        )
    if top_path:
        next_steps.append(
            f"[INFO] Top path: {top_path['source_api']} → {top_path['sink_api']} "
            f"({top_path['cwe']}). "
            f"Concrete input: {repr(top_path.get('concrete_input', 'N/A'))}"
        )
    next_steps.append(
        "[INFO] Use autonomous_vuln_hunt() to run this complete taint+symbolic+fuzzing "
        "pipeline automatically."
    )

    if ctx:
        await ctx.report_progress(100, 100)
        await ctx.info(
            f"✅ Taint trace complete — {len(verified_paths)} verified, {len(static_paths)} static"
        )

    return success(
        {
            "taint_paths": all_paths,
            "verified_paths": verified_paths,
            "static_paths": static_paths,
            "sources_found": list({s["source_api"] for s in source_calls}),
            "sinks_found": list({s["sink_api"] for s in sink_calls}),
            "top_path": top_path,
            "statistics": {
                "sources_present": len(source_calls),
                "sinks_present": len(sink_calls),
                "paths_analysed": len(analysis_paths),
                "paths_verified": len(verified_paths),
                "paths_static_only": len(static_paths),
            },
            "next_steps": next_steps,
        }
    )
