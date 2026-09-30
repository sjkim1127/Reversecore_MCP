"""Hybrid Fuzzing & Symbolic Constraint Solver Orchestrator."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.execution import execute_subprocess_async, prepare_sandbox_access
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.cve_hunter.asan_crash_triager import triage_asan_log

logger = get_logger(__name__)


def _hash_file(path: Path) -> str:
    """Hash a crash input incrementally so large testcases stay bounded in memory."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


def _find_crash_input(fuzzer_output: str, crashes_dir: Path, artifacts: list[Path]) -> Path | None:
    """Resolve the crash input reported by LibFuzzer within this run's artifact directory."""
    match = re.search(r"Test unit written to\s+([^\r\n]+)", fuzzer_output)
    if match:
        raw_path = match.group(1).strip().strip("'\"")
        candidate = Path(raw_path).expanduser().resolve()
        if candidate.is_relative_to(crashes_dir.resolve()) and candidate.is_file():
            return candidate
        return None
    if len(artifacts) == 1 and artifacts[0].is_file():
        return artifacts[0].resolve()
    return None


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
        corpus_dir: Optional seed corpus copied into this run's isolated directory.
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
        corpus_source = (
            _workspace_path(corpus_dir, "corpus_dir", directory=True) if corpus_dir else None
        )
        if corpus_source is not None and not corpus_source.is_dir():
            raise ValueError("corpus_dir must be an existing directory")
        if dictionary_path:
            dictionary_file = validate_file_path(dictionary_path, read_only=True)
        else:
            dictionary_file = None
    except Exception as e:
        return failure("INVALID_PATH", f"Auxiliary path validation error: {e}")

    calc_timeout = calculate_dynamic_timeout(
        target_bin, base_timeout=timeout or (max_total_time_seconds + 30)
    )

    # Keep all mutable fuzzing state in a unique workspace cache directory.
    cache_dir = workspace / ".cache"
    fuzz_runs_dir = cache_dir / "fuzz"
    run_workspace: Path | None = None
    try:
        if cache_dir.is_symlink() or fuzz_runs_dir.is_symlink():
            raise OSError("workspace cache paths must not be symbolic links")
        fuzz_runs_dir.mkdir(parents=True, exist_ok=True)
        prepare_sandbox_access(fuzz_runs_dir)
        run_workspace = Path(tempfile.mkdtemp(prefix="run_", dir=fuzz_runs_dir))
        prepare_sandbox_access(run_workspace)
        seeds_dir = run_workspace / "seeds"
        crashes_dir = run_workspace / "crashes"
        seeds_dir.mkdir()
        crashes_dir.mkdir()
        prepare_sandbox_access(seeds_dir)
        prepare_sandbox_access(crashes_dir)
    except Exception as e:
        if run_workspace is not None and not run_workspace.is_symlink():
            shutil.rmtree(run_workspace, ignore_errors=True)
        return failure("FUZZING_SETUP_FAILED", f"Could not create isolated fuzz run directory: {e}")
    assert run_workspace is not None

    def remove_run_workspace() -> None:
        try:
            if run_workspace is not None and not run_workspace.is_symlink():
                shutil.rmtree(run_workspace)
        except OSError:
            pass

    try:
        copied_seed_count = 0
        if corpus_source is not None and corpus_source.is_dir():
            for source_seed in sorted(corpus_source.iterdir()):
                if source_seed.is_symlink():
                    continue
                if not source_seed.is_file():
                    continue
                shutil.copyfile(source_seed, seeds_dir / source_seed.name)
                copied_seed_count += 1

        # An explicit corpus is copied into this run; default seeds are never shared.
        if copied_seed_count == 0:
            initial_seed = seeds_dir / "seed_init.bin"
            initial_seed.write_bytes(b"TEST\x00\x00\x00\x04DATA")
    except OSError as e:
        remove_run_workspace()
        return failure("FUZZING_SETUP_FAILED", f"Could not prepare the fuzzer seed corpus: {e}")

    # Step 1: Check if angr concolic solving should inject seeds first
    solved_seeds_count = 0
    if enable_angr_concolic:
        try:
            solutions = solve_branch_constraints_angr(str(target_bin))
            for idx, sol in enumerate(solutions):
                if sol and len(sol) >= 4:
                    seed_path = seeds_dir / f"angr_seed_{run_workspace.name}_{idx}.bin"
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

    fuzz_execution_status = "completed"
    try:
        fuzzer_output, _ = await execute_subprocess_async(
            fuzz_cmd,
            max_output_size=10_000_000,
            timeout=int(calc_timeout),
            capture_stderr=True,
        )
    except Exception as e:
        output = getattr(e, "output", None) or getattr(e, "stdout", None) or ""
        stderr = getattr(e, "stderr", None) or ""
        fuzzer_output = "\n".join(
            value.decode(errors="replace") if isinstance(value, bytes) else str(value)
            for value in (output, stderr)
            if value and (value is output or str(value) not in str(output))
        )
        triage = triage_asan_log(fuzzer_output)
        if not isinstance(e, subprocess.CalledProcessError) or not triage["is_sanitizer_report"]:
            remove_run_workspace()
            logger.warning("Fuzzing subprocess failed: %s", e)
            return failure(
                "FUZZING_FAILED",
                f"Fuzzing could not complete: {type(e).__name__}",
                hint="Check the fuzzer binary, its sanitizer runtime, and the configured timeout.",
            )
        fuzz_execution_status = "crash_detected"
        logger.info("Fuzzer exited after reporting a sanitizer crash")

    # Step 3: Scan crashes directory for artifacts (crash-*, leak-*, oom-*)
    artifact_files = (
        list(crashes_dir.glob("crash-*"))
        + list(crashes_dir.glob("leak-*"))
        + list(crashes_dir.glob("oom-*"))
    )
    triage = triage_asan_log(fuzzer_output)
    if triage["is_sanitizer_report"]:
        fuzz_execution_status = "crash_detected"
        crash_input = _find_crash_input(fuzzer_output, crashes_dir, artifact_files)
        if crash_input is None:
            if not artifact_files:
                remove_run_workspace()
            return failure(
                "CRASH_EVIDENCE_INCOMPLETE",
                "Sanitizer output was recognized, but its crash input could not be linked to this fuzz run.",
                hint="Preserve the LibFuzzer crash artifact and its 'Test unit written to' path.",
            )
        try:
            crash_input_sha256 = _hash_file(crash_input)
        except OSError as e:
            return failure(
                "CRASH_EVIDENCE_INCOMPLETE",
                f"Could not read the crash input artifact: {type(e).__name__}",
            )
        cvss = triage.get("cvss") or {}
        triage.update(
            {
                "crash_type": triage["bug_type"],
                "cwe": triage["cwe_id"],
                "severity": cvss.get("severity"),
                "cvss_score": cvss.get("cvss_v31_score"),
                "location": triage["faulting_source_location"],
                "artifact_count": len(artifact_files),
                "evidence_source": "hybrid_fuzzer",
                "crash_log_sha256": hashlib.sha256(fuzzer_output.encode()).hexdigest(),
                "crash_input_path": str(crash_input),
                "crash_input_sha256": crash_input_sha256,
            }
        )
        crashes_found.append(triage)
    elif artifact_files:
        return failure(
            "CRASH_TRIAGE_INCOMPLETE",
            "Fuzzer produced crash artifacts without a recognized sanitizer report.",
            hint="Inspect the crash artifacts and sanitizer configuration before reporting findings.",
        )

    if fuzz_execution_status == "crash_detected" and not crashes_found:
        return failure("CRASH_TRIAGE_INCOMPLETE", "Sanitizer output could not be triaged.")

    if not crashes_found and not artifact_files:
        remove_run_workspace()

    # Extract execs/sec metric from log
    m_execs = re.search(r"stat::number_of_executed_units:\s+(\d+)", fuzzer_output)
    exec_units = int(m_execs.group(1)) if m_execs else 0
    if fuzz_execution_status == "completed" and (m_execs is None or exec_units == 0):
        remove_run_workspace()
        return failure(
            "FUZZING_INCOMPLETE",
            "Fuzzer exited successfully without reporting any executed input units.",
            hint="Confirm the target is a LibFuzzer-compatible binary, provide a non-empty corpus, and rerun the campaign.",
        )

    result_data = {
        "target_binary": str(target_bin),
        "fuzzing_duration_seconds": max_total_time_seconds,
        "concolic_seeds_injected": solved_seeds_count,
        "total_executions": exec_units,
        "crashes_detected": len(crashes_found),
        "execution_status": fuzz_execution_status,
        "crash_artifacts": [str(p) for p in artifact_files[:10]],
        "triaged_crashes": crashes_found,
        "summary": (
            f"Fuzzing stopped after a sanitizer crash with {exec_units} executed units reported. "
            f"Detected {len(crashes_found)} unique crash signatures ({len(artifact_files)} crash files saved)."
            if fuzz_execution_status == "crash_detected"
            else f"Fuzzing completed with {exec_units} executions. "
            f"Detected {len(crashes_found)} unique crash signatures ({len(artifact_files)} crash files saved)."
        ),
    }

    return success(result_data)
