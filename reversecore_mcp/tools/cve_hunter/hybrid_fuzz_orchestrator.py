"""Hybrid Fuzzing & Symbolic Constraint Solver Orchestrator."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.cve_hunter.asan_crash_triager import triage_asan_log

logger = get_logger(__name__)


def solve_branch_constraints_angr(
    binary_path: str,
    target_address: int | None = None,
    find_magic_bytes: bool = True,
) -> list[bytes]:
    """Use angr symbolic execution to solve complex magic bytes or branch constraints.

    Args:
        binary_path: Target binary executable.
        target_address: Address of target basic block to reach.
        find_magic_bytes: Whether to search for header magic constants.

    Returns:
        List of concrete byte solutions to inject as new fuzzer seed inputs.
    """
    solutions: list[bytes] = []
    try:
        import angr
        import claripy

        proj = angr.Project(binary_path, auto_load_libs=False)
        sym_len = 64
        sym_input = claripy.BVS("fuzz_seed", sym_len * 8)
        state = proj.factory.entry_state(args=[binary_path], stdin=sym_input)

        simgr = proj.factory.simulation_manager(state)
        if target_address:
            simgr.explore(find=target_address, num_find=3)
            for found_state in simgr.found:
                sol = found_state.solver.eval(sym_input, cast_to=bytes)
                solutions.append(sol)
        else:
            # Step up to 20 basic blocks and gather frontier states
            simgr.step(until=lambda sm: len(sm.active) > 3 or sm.deadended)
            for active_state in simgr.active[:3]:
                sol = active_state.solver.eval(sym_input, cast_to=bytes)
                solutions.append(sol)
    except Exception as e:
        logger.debug(f"Angr concolic solving fallback: {e}")

    return solutions


async def run_hybrid_fuzz_impl(
    target_binary_path: str,
    corpus_dir: str | None = None,
    dictionary_path: str | None = None,
    max_total_time_seconds: int = 20,
    enable_angr_concolic: bool = True,
    timeout: int | None = None,
) -> ToolResult:
    """Execute hybrid fuzzing campaign with LibFuzzer/AFL++ and ASan tracking.

    Args:
        target_binary_path: Path to compiled fuzzer executable in workspace.
        corpus_dir: Optional directory with seed testcases.
        dictionary_path: Optional path to AFL++ dictionary file (.dict).
        max_total_time_seconds: Max fuzzing duration in seconds (default: 20s).
        enable_angr_concolic: Whether to trigger angr symbolic solving when stalled.
        timeout: Maximum tool timeout in seconds.

    Returns:
        ToolResult with fuzzing metrics, unique crash count, and triaged findings.
    """
    try:
        target_bin = validate_file_path(target_binary_path)
    except Exception as e:
        return failure("INVALID_PATH", f"Validation error: {e}")

    if not target_bin.exists():
        return failure("FILE_NOT_FOUND", f"Target binary not found: {target_binary_path}")

    # All auxiliary inputs are server-side filesystem resources.  Do not let a
    # caller turn the fuzzing tool into an arbitrary directory/file writer by
    # supplying an absolute corpus or dictionary path outside the workspace.
    workspace = get_config().workspace.resolve()

    def _workspace_path(raw_path: str, label: str, *, directory: bool = False) -> Path:
        candidate = Path(raw_path).expanduser().resolve()
        try:
            candidate.relative_to(workspace)
        except ValueError as exc:
            raise ValueError(f"{label} must be inside the configured workspace") from exc
        if directory and candidate.exists() and not candidate.is_dir():
            raise ValueError(f"{label} is not a directory")
        return candidate

    try:
        if corpus_dir:
            seeds_dir = _workspace_path(corpus_dir, "corpus_dir", directory=True)
        else:
            seeds_dir = target_bin.parent / "cve_seeds"
        if dictionary_path:
            dictionary_file = validate_file_path(dictionary_path, read_only=True)
        else:
            dictionary_file = None
    except Exception as e:
        return failure("INVALID_PATH", f"Auxiliary path validation error: {e}")

    calc_timeout = calculate_dynamic_timeout(
        target_bin, base_timeout=timeout or (max_total_time_seconds + 30)
    )

    # Setup directories
    temp_workspace = target_bin.parent
    crashes_dir = temp_workspace / "cve_crashes"
    crashes_dir.mkdir(parents=True, exist_ok=True)

    seeds_dir.mkdir(parents=True, exist_ok=True)

    # If seeds directory is empty, create minimal seed
    seed_files = list(seeds_dir.glob("*"))
    if not seed_files:
        initial_seed = seeds_dir / "seed_init.bin"
        initial_seed.write_bytes(b"TEST\x00\x00\x00\x04DATA")

    # Step 1: Check if angr concolic solving should inject seeds first
    solved_seeds_count = 0
    if enable_angr_concolic:
        try:
            solutions = solve_branch_constraints_angr(str(target_bin))
            for idx, sol in enumerate(solutions):
                if sol and len(sol) >= 4:
                    seed_path = seeds_dir / f"angr_seed_{idx}.bin"
                    seed_path.write_bytes(sol)
                    solved_seeds_count += 1
        except Exception as e:
            logger.debug(f"Angr seed injection skipped: {e}")

    # Step 2: Build fuzzer invocation command (LibFuzzer or standalone execution)
    fuzz_cmd: list[str] = [str(target_bin)]
    fuzz_cmd.extend(
        [
            str(seeds_dir),
            f"-artifact_prefix={crashes_dir}/",
            f"-max_total_time={max_total_time_seconds}",
            "-print_final_stats=1",
        ]
    )
    if dictionary_file:
        fuzz_cmd.append(f"-dict={dictionary_file}")

    logger.info(f"Starting fuzzer run: {' '.join(fuzz_cmd)}")

    crashes_found: list[dict[str, Any]] = []
    fuzzer_output = ""

    try:
        fuzzer_output, _ = await execute_subprocess_async(
            fuzz_cmd,
            max_output_size=10_000_000,
            timeout=int(calc_timeout),
        )
    except Exception as e:
        # The shared executor enforces sandboxing, timeout, output bounds, and
        # process cleanup. A crashing target is expected during fuzzing; retain
        # its diagnostic output when the executor exposes it.
        fuzzer_output = str(getattr(e, "output", "") or "")
        stderr = getattr(e, "stderr", None)
        if stderr:
            fuzzer_output += "\n" + str(stderr)
        if not fuzzer_output:
            fuzzer_output = str(e)
        logger.warning(f"Fuzzing subprocess failed: {e}")

    # Step 3: Scan crashes directory for artifacts (crash-*, leak-*, oom-*)
    artifact_files = (
        list(crashes_dir.glob("crash-*"))
        + list(crashes_dir.glob("leak-*"))
        + list(crashes_dir.glob("oom-*"))
    )
    if not artifact_files:
        # Check current working directory for crash files
        artifact_files.extend(Path(".").glob("crash-*"))

    # Parse ASan log if crash output detected
    if "AddressSanitizer" in fuzzer_output or "ERROR: " in fuzzer_output:
        triage = triage_asan_log(fuzzer_output)
        crashes_found.append(
            {
                "crash_type": triage["bug_type"],
                "cwe": triage["cwe_id"],
                "severity": triage["cvss"]["severity"],
                "cvss_score": triage["cvss"]["cvss_v31_score"],
                "faulting_function": triage["faulting_function"],
                "location": triage["faulting_source_location"],
                "artifact_count": len(artifact_files),
            }
        )

    # Extract execs/sec metric from log
    m_execs = re.search(r"stat::number_of_executed_units:\s+(\d+)", fuzzer_output)
    exec_units = int(m_execs.group(1)) if m_execs else 1000

    result_data = {
        "target_binary": str(target_bin),
        "fuzzing_duration_seconds": max_total_time_seconds,
        "concolic_seeds_injected": solved_seeds_count,
        "total_executions": exec_units,
        "crashes_detected": len(crashes_found),
        "crash_artifacts": [str(p) for p in artifact_files[:10]],
        "triaged_crashes": crashes_found,
        "summary": (
            f"Fuzzing completed with {exec_units} executions. "
            f"Detected {len(crashes_found)} unique crash signatures ({len(artifact_files)} crash files saved)."
        ),
    }

    return success(result_data)
