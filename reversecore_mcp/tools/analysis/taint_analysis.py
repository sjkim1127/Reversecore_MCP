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
from pathlib import Path
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
    sink_address: str | None
    source_address: str | None
    path_verified: bool
    concrete_input: str | None
    confidence: str  # high / medium / low
    taint_verified: bool = False
    data_flow_confirmed: bool = False
    reachability_only: bool = False
    source_resolved: bool = True
    sink_resolved: bool = True
    angr_note: str | None = None


# ---------------------------------------------------------------------------
# Radare2 helpers for source/sink discovery
# ---------------------------------------------------------------------------


def normalize_symbol_name(name: str) -> str:
    """Normalize a symbol name by stripping prefixes, library versions, and decorators."""
    if not name:
        return ""
    clean = name.strip()
    # Remove library/version suffixes (e.g., @@GLIBC_2.2.5, @plt, @GLIBC_2.4)
    clean = clean.split("@")[0]
    # Remove compiler optimization suffixes
    for part in (".part.", ".isra.", ".cold"):
        if part in clean:
            clean = clean.split(part)[0]
    # Strip common symbol prefixes
    while True:
        stripped = False
        for prefix in ("sym.imp.", "imp.", "reloc.", "sym."):
            if clean.startswith(prefix):
                clean = clean[len(prefix) :]
                stripped = True
                break
        if not stripped:
            break
    # Strip Mach-O single leading underscore (preserving double underscores like __libc_start_main)
    if clean.startswith("_") and not clean.startswith("__"):
        clean = clean[1:]
    return clean.strip()


def _extract_symbols_from_output(output: str) -> set[str]:
    """Extract and normalize all symbol names from structured JSON or text radare2 output."""
    symbols: set[str] = set()
    if not output or not output.strip():
        return symbols

    # 1. Try structured JSON parsing (from iij or isj)
    try:
        data = _parse_json_output(output)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key in ("name", "realname", "flagname", "string", "symname"):
                        val = item.get(key)
                        if val:
                            norm = normalize_symbol_name(str(val))
                            if norm:
                                symbols.add(norm)
            if symbols:
                return symbols
    except Exception:
        pass

    # 2. Line-oriented text parsing (e.g., from is or ii text output)
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        tokens = line.split()
        for tok in tokens:
            norm = normalize_symbol_name(tok)
            if norm:
                symbols.add(norm)

    return symbols


def _parse_call_sites_from_xrefs(xrefs_output: str) -> list[str]:
    """Parse axtj cross-reference JSON output into unique, non-zero call site hex strings."""
    resolved: list[str] = []
    try:
        xrefs = _parse_json_output(xrefs_output)
        if isinstance(xrefs, list):
            for xref in xrefs:
                if not isinstance(xref, dict):
                    continue
                from_addr = xref.get("from", xref.get("addr"))
                if from_addr is not None and from_addr != 0 and from_addr != "0x0":
                    addr_str = hex(from_addr) if isinstance(from_addr, int) else str(from_addr)
                    if addr_str not in resolved and addr_str != "0x0":
                        resolved.append(addr_str)
    except Exception:
        pass
    return resolved


async def _find_sink_calls(binary_path: str, timeout: int) -> list[dict[str, Any]]:
    """Find all calls to known dangerous sink functions via radare2 xrefs.

    Args:
        binary_path: Path to the binary.
        timeout: Analysis timeout.

    Returns:
        List of sink call dicts with address, function name, sink info.
    """
    sink_calls: list[dict[str, Any]] = []
    bin_path = Path(binary_path)

    # Batch query: fetch imports and symbols once to discover which sinks exist
    try:
        sym_out, _ = await _execute_r2_command(
            bin_path,
            ["isj", "iij", "is~imp.", "ii"],
            analysis_level="aa",
            max_output_size=1_000_000,
            base_timeout=min(timeout, 30),
        )
    except Exception as exc:
        logger.debug("Batch symbol search failed: %s", exc)
        sym_out = ""

    symbols_in_binary = _extract_symbols_from_output(sym_out)

    # Filter candidate sinks to only those found in binary (or all if batch failed)
    candidate_sinks = [
        (sink_name, sink_info)
        for sink_name, sink_info in TAINT_SINKS.items()
        if not sym_out or sink_name in symbols_in_binary
    ]

    for sink_name, sink_info in candidate_sinks:
        try:
            # If batch output was unavailable, check this sink individually with exact match
            if not sym_out:
                out, _ = await _execute_r2_command(
                    bin_path,
                    [f"is~{sink_name}", f"ii~{sink_name}"],
                    analysis_level="aa",
                    max_output_size=1_000_000,
                    base_timeout=30,
                )
                single_syms = _extract_symbols_from_output(out)
                if sink_name not in single_syms:
                    continue

            # Find cross-references to this symbol
            addr_out, _ = await _execute_r2_command(
                bin_path,
                [
                    f"?v sym.imp.{sink_name}",
                    f"axtj sym.imp.{sink_name}",
                    f"axtj imp.{sink_name}",
                    f"axtj {sink_name}",
                ],
                analysis_level="aa",
                max_output_size=1_000_000,
                base_timeout=30,
            )

            resolved_call_sites = _parse_call_sites_from_xrefs(addr_out)

            if resolved_call_sites:
                for call_addr in resolved_call_sites[:10]:
                    sink_calls.append(
                        {
                            "sink_api": sink_name,
                            "call_address": call_addr,
                            "resolved": True,
                            "cwe": sink_info["cwe"],
                            "severity": sink_info["severity"],
                            "category": sink_info["category"],
                            "description": sink_info["description"],
                        }
                    )
            else:
                # Surface failed xref parsing as unresolved evidence rather than a fake 0x0
                sink_calls.append(
                    {
                        "sink_api": sink_name,
                        "call_address": None,
                        "resolved": False,
                        "unresolved_reason": "no_xrefs_found",
                        "evidence_type": "symbol_only",
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
    bin_path = Path(binary_path)

    # Resolve argv entry address if argv is in sources
    if "argv" in TAINT_SOURCES:
        argv_addr = None
        try:
            main_out, _ = await _execute_r2_command(
                bin_path,
                ["?v main", "?v sym.main", "iMj"],
                analysis_level="a",
                max_output_size=100_000,
                base_timeout=15,
            )
            try:
                main_json = _parse_json_output(main_out)
                if isinstance(main_json, dict) and main_json.get("vaddr"):
                    argv_addr = hex(main_json["vaddr"])
            except Exception:
                pass
            if not argv_addr and main_out.strip():
                for line in main_out.splitlines():
                    line = line.strip()
                    if line.startswith("0x") and line != "0x0":
                        argv_addr = line
                        break
        except Exception:
            pass

        if argv_addr and argv_addr != "0x0":
            source_calls.append(
                {
                    "source_api": "argv",
                    "call_address": argv_addr,
                    "resolved": True,
                    "category": "argv",
                    "description": "Command-line argv[] input at main",
                }
            )
        else:
            source_calls.append(
                {
                    "source_api": "argv",
                    "call_address": None,
                    "resolved": False,
                    "unresolved_reason": "main_not_found",
                    "evidence_type": "symbol_only",
                    "category": "argv",
                    "description": "Command-line argv[] input",
                }
            )

    # Batch query imports and symbols once
    try:
        sym_out, _ = await _execute_r2_command(
            bin_path,
            ["isj", "iij", "is~imp.", "ii"],
            analysis_level="aa",
            max_output_size=1_000_000,
            base_timeout=min(timeout, 20),
        )
    except Exception as exc:
        logger.debug("Batch source search failed: %s", exc)
        sym_out = ""

    symbols_in_binary = _extract_symbols_from_output(sym_out)

    for src_name, src_info in TAINT_SOURCES.items():
        if src_name == "argv":
            continue

        if sym_out and src_name not in symbols_in_binary:
            continue

        if not sym_out:
            try:
                out, _ = await _execute_r2_command(
                    bin_path,
                    [f"is~{src_name}", f"ii~{src_name}"],
                    analysis_level="aa",
                    max_output_size=500_000,
                    base_timeout=20,
                )
                single_syms = _extract_symbols_from_output(out)
                if src_name not in single_syms:
                    continue
            except Exception as exc:
                logger.debug("Source search failed for %s: %s", src_name, exc)
                continue

        # Resolve call-sites for source via xrefs
        try:
            addr_out, _ = await _execute_r2_command(
                bin_path,
                [
                    f"?v sym.imp.{src_name}",
                    f"axtj sym.imp.{src_name}",
                    f"axtj imp.{src_name}",
                    f"axtj {src_name}",
                ],
                analysis_level="aa",
                max_output_size=1_000_000,
                base_timeout=20,
            )
            resolved_call_sites = _parse_call_sites_from_xrefs(addr_out)

            if resolved_call_sites:
                for call_addr in resolved_call_sites[:10]:
                    source_calls.append(
                        {
                            "source_api": src_name,
                            "call_address": call_addr,
                            "resolved": True,
                            "category": src_info["category"],
                            "description": src_info["description"],
                        }
                    )
            else:
                source_calls.append(
                    {
                        "source_api": src_name,
                        "call_address": None,
                        "resolved": False,
                        "unresolved_reason": "no_xrefs_found",
                        "evidence_type": "symbol_only",
                        "category": src_info["category"],
                        "description": src_info["description"],
                    }
                )
        except Exception as exc:
            logger.debug("Source xref search failed for %s: %s", src_name, exc)
            source_calls.append(
                {
                    "source_api": src_name,
                    "call_address": None,
                    "resolved": False,
                    "unresolved_reason": "no_xrefs_found",
                    "evidence_type": "symbol_only",
                    "category": src_info["category"],
                    "description": src_info["description"],
                }
            )

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
                    "source_address": source.get("call_address"),
                    "source_resolved": source.get("resolved", bool(source.get("call_address"))),
                    "sink_api": sink["sink_api"],
                    "sink_address": sink.get("call_address"),
                    "sink_resolved": sink.get("resolved", bool(sink.get("call_address"))),
                    "cwe": sink["cwe"],
                    "severity": sink["severity"],
                    "severity_score": severity_order.get(sink["severity"], 0),
                    "category": sink["category"],
                    "description": sink["description"],
                    "path_verified": False,
                    "taint_verified": False,
                    "data_flow_confirmed": False,
                    "reachability_only": False,
                    "concrete_input": None,
                    "confidence": "low",
                }
            )

    # Sort candidates so resolved pairs appear first before unresolved
    path_candidates.sort(
        key=lambda p: (
            1 if (p.get("source_resolved") and p.get("sink_resolved")) else 0,
            p["severity_score"],
        ),
        reverse=True,
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
            sink_addr = path.get("sink_address")
            source_addr = path.get("source_address")
            sink_resolved = path.get("sink_resolved", False)
            source_resolved = path.get("source_resolved", False)

            can_verify = (
                isinstance(sink_addr, (str, int))
                and sink_addr != "0x0"
                and sink_resolved
                and isinstance(source_addr, (str, int))
                and source_addr != "0x0"
                and source_resolved
            )

            if (
                can_verify
                and isinstance(sink_addr, (str, int))
                and isinstance(source_addr, (str, int))
            ):
                if ctx:
                    await ctx.info(
                        f"   🤖 angr: verifying {path['source_api']} ({source_addr}) → "
                        f"{path['sink_api']} ({sink_addr})"
                    )

                try:
                    angr_result = await verify_path_and_get_args(
                        binary_path=validated_path,
                        target_addr=sink_addr,
                        start_addr=None,
                        avoid_addrs=None,
                        source_addr=source_addr,
                        source_api=path["source_api"],
                        sink_api=path["sink_api"],
                        check_taint=True,
                        timeout=angr_timeout,
                    )

                    if "taint_verified" in angr_result:
                        is_taint_verified = bool(angr_result["taint_verified"])
                    elif "data_flow_confirmed" in angr_result:
                        is_taint_verified = bool(angr_result["data_flow_confirmed"])
                    else:
                        is_taint_verified = bool(angr_result.get("satisfiable", False))

                    is_reachable = bool(angr_result.get("satisfiable", False))

                    path["taint_verified"] = is_taint_verified
                    path["data_flow_confirmed"] = is_taint_verified
                    path["path_verified"] = is_taint_verified
                    path["reachability_only"] = is_reachable and not is_taint_verified

                    if is_taint_verified:
                        path["confidence"] = "high"
                        path["concrete_input"] = angr_result.get("concrete_input")
                        path["concrete_inputs"] = angr_result.get("inputs", {})
                        verified_paths.append(path)
                    elif is_reachable:
                        path["confidence"] = "medium"
                        path["concrete_input"] = None
                        path["reachability_concrete_input"] = angr_result.get(
                            "reachability_concrete_input"
                        ) or angr_result.get("concrete_input")
                        path["angr_note"] = (
                            "Sink instruction is reachable via control flow, but no taint data "
                            f"dependency from {path['source_api']} to {path['sink_api']} was detected"
                        )
                        static_paths.append(path)
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
                # Unresolved address or symbol-only evidence
                path["confidence"] = "low"
                path["path_verified"] = False
                path["taint_verified"] = False
                path["reachability_only"] = False
                unres_reasons = []
                if not source_resolved:
                    unres_reasons.append(f"source {path['source_api']} call site unresolved")
                if not sink_resolved:
                    unres_reasons.append(f"sink {path['sink_api']} call site unresolved")
                path["angr_note"] = f"Symbol-only evidence: {'; '.join(unres_reasons)}"
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
                "paths_reachability_only": sum(
                    1 for p in static_paths if p.get("reachability_only")
                ),
                "paths_static_only": len(static_paths),
            },
            "next_steps": next_steps,
        }
    )
