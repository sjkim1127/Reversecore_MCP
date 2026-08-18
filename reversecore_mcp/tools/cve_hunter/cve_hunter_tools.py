"""FastMCP Tool Endpoints for Automated C/C++ CVE Hunting & Exploitability."""

from __future__ import annotations

from typing import Any

from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.result import ToolResult
from reversecore_mcp.tools.cve_hunter.asan_crash_triager import triage_crash_impl
from reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline import hunt_cve_pipeline_impl
from reversecore_mcp.tools.cve_hunter.harness_synthesizer import (
    synthesize_fuzz_harness_impl,
)
from reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator import (
    run_hybrid_fuzz_impl,
)
from reversecore_mcp.tools.cve_hunter.poc_minimizer import minimize_poc_impl


@handle_tool_errors
async def cve_synthesize_harness(
    header_or_binary_path: str,
    sample_file_path: str | None = None,
    target_function: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Synthesize LibFuzzer/AFL++ C/C++ test harness and format dictionary (.dict) for target parser.

    Analyzes target headers, exports, and sample files to extract candidate parser functions,
    magic byte signatures, and generate ready-to-compile LLVMFuzzerTestOneInput harness code.

    Args:
        header_or_binary_path: Path to target header (.h), source (.c/.cpp), or binary.
        sample_file_path: Optional path to a valid sample file to extract dictionary tokens.
        target_function: Optional target function name to fuzz.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with synthesized harness code and dictionary content.
    """
    return await synthesize_fuzz_harness_impl(
        header_or_binary_path=header_or_binary_path,
        sample_file_path=sample_file_path,
        target_function=target_function,
        timeout=timeout,
    )


@handle_tool_errors
async def cve_fuzz_target(
    target_binary_path: str,
    corpus_dir: str | None = None,
    dictionary_path: str | None = None,
    max_total_time_seconds: int = 20,
    enable_angr_concolic: bool = True,
    timeout: int | None = None,
) -> ToolResult:
    """Execute hybrid fuzzing campaign with Sanitizer tracking and angr concolic seed solver.

    Runs target fuzzer binary with AddressSanitizer, detects coverage stalls, and uses angr
    symbolic execution to solve magic byte constraints.

    Args:
        target_binary_path: Path to compiled fuzzer binary in workspace.
        corpus_dir: Optional directory with seed testcases.
        dictionary_path: Optional path to AFL++ dictionary file (.dict).
        max_total_time_seconds: Max fuzzing duration in seconds (default: 20s).
        enable_angr_concolic: Whether to trigger angr symbolic solving when stalled.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with fuzzing statistics, crash count, and triaged crash summaries.
    """
    return await run_hybrid_fuzz_impl(
        target_binary_path=target_binary_path,
        corpus_dir=corpus_dir,
        dictionary_path=dictionary_path,
        max_total_time_seconds=max_total_time_seconds,
        enable_angr_concolic=enable_angr_concolic,
        timeout=timeout,
    )


@handle_tool_errors
async def cve_triage_crash(
    crash_log_or_text: str,
    timeout: int | None = None,
) -> ToolResult:
    """Triage AddressSanitizer/UBSan crash log and compute CWE and CVSS v3.1 rating.

    Extracts bug class (heap-buffer-overflow, UAF, double-free), faulting PC, memory access type,
    allocation/free/crash callstacks, and calculates CVSS score and vector.

    Args:
        crash_log_or_text: Raw ASan log text or path to crash log file.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with structured crash diagnostics, CWE mapping, and CVSS v3.1 score.
    """
    return await triage_crash_impl(
        crash_log_or_text=crash_log_or_text,
        timeout=timeout,
    )


@handle_tool_errors
async def cve_minimize_poc(
    binary_path: str,
    crash_input_path: str,
    target_function: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Minimize crash testcase payload via delta-debugging and generate standalone PoC scripts.

    Bsects crash input to find the smallest reproducible byte sequence, and generates
    standalone Python (subprocess/pwntools) and C reproduction code.

    Args:
        binary_path: Path to target binary in workspace.
        crash_input_path: Path to crash-inducing input file.
        target_function: Optional target parser function name.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with minimized payload bytes and standalone PoC scripts.
    """
    return await minimize_poc_impl(
        binary_path=binary_path,
        crash_input_path=crash_input_path,
        target_function=target_function,
        timeout=timeout,
    )


@handle_tool_errors
async def hunt_cve_vulnerabilities(
    target_path: str,
    sample_file_path: str | None = None,
    options: dict[str, Any] | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """One-click automated CVE hunting pipeline for C/C++ libraries, parsers, and codecs.

    Performs end-to-end vulnerability discovery:
    1. Harness & Dictionary auto-synthesis
    2. Hybrid Fuzzing + angr concolic branch solving
    3. ASan crash triage, CWE mapping, and CVSS v3.1 scoring
    4. Testcase minimization & standalone PoC generation
    5. Vendor-ready Security Advisory Markdown report draft

    Args:
        target_path: Path to target header (.h), source (.c/.cpp), or compiled binary.
        sample_file_path: Optional path to a valid sample file.
        options: Optional configuration dictionary (e.g. fuzz_duration, target_function).
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with complete CVE discovery findings, triaged crashes, PoCs, and advisory report.
    """
    return await hunt_cve_pipeline_impl(
        target_path_str=target_path,
        sample_file_path=sample_file_path,
        options=options,
        timeout=timeout,
    )
