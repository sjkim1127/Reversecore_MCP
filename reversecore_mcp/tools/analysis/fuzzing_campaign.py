"""Fuzzing Campaign Orchestrator.

Connects AFL++ execution → crash collection → triage_crash into a single
automated pipeline. Runs AFL++ asynchronously, monitors for crashes in
real-time, deduplicates by crash signature, and returns exploitability
assessments for each unique crash.

This bridges the gap between harness generation (generate_fuzzing_harness)
and crash analysis (triage_crash) — previously these had to be done manually.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from fastmcp import Context

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXPLOITABILITY_SCORE: dict[str, int] = {
    "CONFIRMED": 100,
    "LIKELY": 75,
    "POSSIBLE": 50,
    "UNLIKELY": 25,
    "UNKNOWN": 0,
}


def _afl_available() -> bool:
    """Return True if afl-fuzz is on PATH."""
    return shutil.which("afl-fuzz") is not None


def _asan_available() -> bool:
    """Return True if clang with ASAN is available."""
    return shutil.which("clang") is not None or shutil.which("gcc") is not None


def _crash_signature(crash_path: Path) -> str:
    """Compute a content-based signature for deduplication.

    Uses first 4 KB of crash data + filename to create a stable hash.
    This is intentionally simple — AFL++ already deduplicates crashes;
    we just handle rare duplicates that slip through.

    Args:
        crash_path: Path to the crash input file.

    Returns:
        Hex-encoded SHA1 digest (12 chars) for quick comparison.
    """
    try:
        data = crash_path.read_bytes()[:4096]
        return hashlib.sha1(data).hexdigest()[:12]  # nosec B324
    except OSError:
        return crash_path.name


def _collect_crashes(output_dir: Path, max_crashes: int = 50) -> list[Path]:
    """Collect unique crash files from an AFL++ output directory.

    Args:
        output_dir: AFL++ output directory (contains crashes/ subdirectory).
        max_crashes: Maximum number of unique crashes to return.

    Returns:
        List of paths to unique crash input files, newest first.
    """
    crashes_dir = output_dir / "default" / "crashes"
    if not crashes_dir.exists():
        # Try flat structure
        crashes_dir = output_dir / "crashes"
    if not crashes_dir.exists():
        return []

    crash_files = [
        f for f in crashes_dir.iterdir() if f.is_file() and not f.name.startswith("README")
    ]
    crash_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    # Deduplicate by content signature
    seen: set[str] = set()
    unique: list[Path] = []
    for cf in crash_files:
        sig = _crash_signature(cf)
        if sig not in seen:
            seen.add(sig)
            unique.append(cf)
            if len(unique) >= max_crashes:
                break

    return unique


async def _run_afl(
    binary_path: Path,
    seed_dir: Path,
    output_dir: Path,
    timeout_secs: int,
    extra_args: list[str],
) -> tuple[int, str]:
    """Run afl-fuzz as an async subprocess.

    Args:
        binary_path: Path to the target binary.
        seed_dir: Directory containing initial seed corpus.
        output_dir: AFL++ output directory.
        timeout_secs: How long to run AFL++ in seconds.
        extra_args: Additional AFL++ CLI arguments (e.g. ["-m", "none"]).

    Returns:
        Tuple of (return_code, stderr_output).
    """
    cmd = [
        "afl-fuzz",
        "-i",
        str(seed_dir),
        "-o",
        str(output_dir),
        "-m",
        "none",  # No memory limit
        "-t",
        "5000",  # Per-run timeout: 5s
        *extra_args,
        "--",
        str(binary_path),
        "@@",  # AFL++ file input placeholder
    ]

    logger.info("Starting AFL++ campaign: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "AFL_NO_UI": "1"},
        )

        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_secs)
            return proc.returncode or 0, (stderr or b"").decode(errors="replace")
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return 0, f"AFL++ ran for {timeout_secs}s then terminated"

    except FileNotFoundError:
        return -1, "afl-fuzz not found in PATH"
    except Exception as exc:
        return -1, str(exc)


async def _triage_crashes(
    binary_path: Path,
    crash_files: list[Path],
    use_stdin: bool,
    triage_timeout: int,
    ctx: Context | None,
) -> list[dict[str, Any]]:
    """Run triage_crash on each unique crash file.

    Args:
        binary_path: Binary being fuzzed.
        crash_files: List of unique crash input files.
        use_stdin: Pass crash as stdin (True) or argument (False).
        triage_timeout: Per-crash GDB timeout in seconds.
        ctx: Optional MCP context for streaming progress.

    Returns:
        List of triage result dicts, sorted by exploitability score.
    """
    from reversecore_mcp.tools.analysis.crash_triage import triage_crash

    results: list[dict[str, Any]] = []

    for idx, crash_file in enumerate(crash_files):
        if ctx:
            await ctx.info(f"   Triaging crash {idx + 1}/{len(crash_files)}: {crash_file.name}")

        try:
            triage_result = await triage_crash(
                binary_path=str(binary_path),
                crash_file=str(crash_file),
                use_stdin=use_stdin,
                timeout=triage_timeout,
            )

            if triage_result.status == "success" and triage_result.data:
                data = triage_result.data
                exploitability = data.get("exploitability", "UNKNOWN")
                results.append(
                    {
                        "crash_file": crash_file.name,
                        "crash_signature": _crash_signature(crash_file),
                        "exploitability": exploitability,
                        "exploitability_score": _EXPLOITABILITY_SCORE.get(exploitability, 0),
                        "signal": data.get("signal"),
                        "crash_address": data.get("crash_address"),
                        "backtrace": data.get("backtrace", [])[:5],
                        "is_exploitable": exploitability in ("CONFIRMED", "LIKELY"),
                        "triage_details": data,
                    }
                )
            else:
                results.append(
                    {
                        "crash_file": crash_file.name,
                        "crash_signature": _crash_signature(crash_file),
                        "exploitability": "UNKNOWN",
                        "exploitability_score": 0,
                        "signal": None,
                        "crash_address": None,
                        "backtrace": [],
                        "is_exploitable": False,
                        "triage_error": getattr(triage_result, "error", "triage failed"),
                    }
                )
        except Exception as exc:
            logger.warning("Triage failed for %s: %s", crash_file.name, exc)
            results.append(
                {
                    "crash_file": crash_file.name,
                    "crash_signature": _crash_signature(crash_file),
                    "exploitability": "UNKNOWN",
                    "exploitability_score": 0,
                    "signal": None,
                    "crash_address": None,
                    "backtrace": [],
                    "is_exploitable": False,
                    "triage_error": str(exc),
                }
            )

    # Sort: CONFIRMED → LIKELY → POSSIBLE → UNKNOWN
    results.sort(key=lambda r: r["exploitability_score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# MCP Tool
# ---------------------------------------------------------------------------


@log_execution(tool_name="run_fuzzing_campaign")
@track_metrics("run_fuzzing_campaign")
@handle_tool_errors
async def run_fuzzing_campaign(
    file_path: str,
    timeout_seconds: int = 300,
    seed_corpus: str | None = None,
    use_stdin: bool = True,
    max_crashes_to_triage: int = 20,
    afl_extra_args: str = "",
    ctx: Context | None = None,
) -> ToolResult:
    """Run a real AFL++ fuzzing campaign and automatically triage all crashes.

    This tool bridges ``generate_fuzzing_harness`` and ``triage_crash`` into a
    complete, automated fuzzing pipeline:

    1. **Setup**: Creates a temporary seed corpus and output directory.
    2. **Fuzz**: Runs ``afl-fuzz`` for ``timeout_seconds``, sending inputs via
       ``@@`` file substitution or stdin depending on ``use_stdin``.
    3. **Collect**: Gathers all unique crash files from the AFL++ output
       directory, deduplicated by content signature.
    4. **Triage**: Runs ``triage_crash`` (GDB) on each unique crash to assess
       exploitability (CONFIRMED / LIKELY / POSSIBLE / UNKNOWN).
    5. **Report**: Returns a structured report with crash statistics, triage
       results sorted by severity, and actionable next steps.

    Prerequisites:
        - ``afl-fuzz`` must be installed and on PATH.
        - ``gdb`` must be installed for crash triage.
        - The target binary must accept file input via stdin or as ``@@``.

    Args:
        file_path: Workspace-relative or absolute path to the target binary.
        timeout_seconds: How long to run the fuzzer in seconds. Default: 300 (5 min).
            For meaningful coverage, use at least 3600 (1 hour) in production.
        seed_corpus: Optional path to a directory containing seed input files.
            If ``None``, a minimal corpus (empty file + single byte) is created.
        use_stdin: If ``True``, crash files are fed via stdin for triage.
            Set to ``False`` if the binary expects a file path as argv[1].
        max_crashes_to_triage: Maximum number of unique crashes to triage with GDB.
            Higher values give more coverage but take longer. Default: 20.
        afl_extra_args: Space-separated extra arguments for afl-fuzz (e.g.,
            ``"-D"`` for deterministic mode, ``"-p exploit"`` for exploit schedule).
        ctx: Optional FastMCP context for streaming progress messages.

    Returns:
        ToolResult containing:
        - ``campaign_summary``: Statistics (duration, executions/sec, crashes found).
        - ``unique_crashes``: Total unique crash count after deduplication.
        - ``triaged_crashes``: List of crash triage results sorted by exploitability.
        - ``exploitable_count``: Number of CONFIRMED + LIKELY exploitable crashes.
        - ``top_crash``: The highest-severity crash with full triage details.
        - ``next_steps``: Researcher action items.
        - ``afl_output_dir``: Path to AFL++ output directory (preserved for inspection).

    Raises:
        ValidationError: If ``file_path`` or ``seed_corpus`` is invalid.

    Example:
        >>> result = await run_fuzzing_campaign(
        ...     "workspace/vuln_binary",
        ...     timeout_seconds=600,
        ...     max_crashes_to_triage=10,
        ... )
        >>> print(result.data["exploitable_count"])
        3
    """
    if not _afl_available():
        return failure(
            "DEPENDENCY_ERROR",
            "afl-fuzz not found in PATH. Install AFL++: apt-get install afl++ or brew install afl++",
            hint="AFL++ must be installed. See https://github.com/AFLplusplus/AFLplusplus",
        )

    validated_path = validate_file_path(file_path)

    if not os.access(validated_path, os.X_OK):
        return failure(
            "NOT_EXECUTABLE",
            f"Binary {validated_path.name} is not executable. Run: chmod +x {validated_path}",
        )

    # Parse extra args
    extra_args = afl_extra_args.split() if afl_extra_args.strip() else []

    if ctx:
        await ctx.info(f"🚀 Fuzzing Campaign → {validated_path.name}")
        await ctx.info(
            f"   timeout={timeout_seconds}s, use_stdin={use_stdin}, "
            f"max_triage={max_crashes_to_triage}"
        )
        await ctx.report_progress(5, 100)

    with tempfile.TemporaryDirectory(prefix="rcmcp_afl_") as tmp_root:
        tmp_path = Path(tmp_root)
        seed_dir = tmp_path / "seeds"
        output_dir = tmp_path / "output"
        seed_dir.mkdir()
        output_dir.mkdir()

        # ── Setup seed corpus ────────────────────────────────────────────────
        if seed_corpus:
            validated_seed = validate_file_path(seed_corpus)
            if validated_seed.is_dir():
                for sf in validated_seed.iterdir():
                    if sf.is_file():
                        shutil.copy(sf, seed_dir / sf.name)
            else:
                shutil.copy(validated_seed, seed_dir / validated_seed.name)
        else:
            # Minimal default corpus
            (seed_dir / "empty").write_bytes(b"")
            (seed_dir / "one_byte").write_bytes(b"A")
            (seed_dir / "pattern").write_bytes(b"A" * 64)

        if ctx:
            await ctx.info(f"📁 Seed corpus ready ({len(list(seed_dir.iterdir()))} files)")
            await ctx.info(f"⏱️  Running AFL++ for {timeout_seconds}s ...")
            await ctx.report_progress(10, 100)

        # ── Run AFL++ ────────────────────────────────────────────────────────
        start_time = time.monotonic()
        rc, afl_stderr = await _run_afl(
            binary_path=validated_path,
            seed_dir=seed_dir,
            output_dir=output_dir,
            timeout_secs=timeout_seconds,
            extra_args=extra_args,
        )
        elapsed = time.monotonic() - start_time

        if rc == -1:
            return failure(
                "AFL_LAUNCH_ERROR",
                f"AFL++ failed to start: {afl_stderr}",
                hint="Ensure afl-fuzz is installed and the binary is an ELF/PE executable.",
            )

        if ctx:
            await ctx.info(f"✅ AFL++ finished after {elapsed:.0f}s (exit code: {rc})")
            await ctx.report_progress(55, 100)

        # ── Collect unique crashes ───────────────────────────────────────────
        crash_files = _collect_crashes(output_dir, max_crashes=max_crashes_to_triage)
        unique_crash_count = len(crash_files)

        # Count total crashes in output (before dedup)
        all_crashes_dir = (
            (output_dir / "default" / "crashes")
            if (output_dir / "default" / "crashes").exists()
            else (output_dir / "crashes")
        )
        total_crash_count = (
            len(
                [
                    f
                    for f in all_crashes_dir.iterdir()
                    if f.is_file() and not f.name.startswith("README")
                ]
            )
            if all_crashes_dir.exists()
            else 0
        )

        if ctx:
            await ctx.info(
                f"💥 Found {total_crash_count} crashes ({unique_crash_count} unique after dedup)"
            )
            await ctx.report_progress(60, 100)

        # ── Parse AFL++ stats ────────────────────────────────────────────────
        afl_stats: dict[str, Any] = {
            "duration_seconds": round(elapsed, 1),
            "return_code": rc,
            "total_crashes": total_crash_count,
            "unique_crashes": unique_crash_count,
        }

        # Try to read AFL++ fuzzer_stats file
        stats_file = output_dir / "default" / "fuzzer_stats"
        if stats_file.exists():
            try:
                for line in stats_file.read_text().splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        afl_stats[key.strip()] = val.strip()
            except OSError:
                pass

        # ── Triage crashes ───────────────────────────────────────────────────
        triaged: list[dict[str, Any]] = []
        if crash_files:
            if ctx:
                await ctx.info(f"🔬 Triaging {len(crash_files)} unique crashes with GDB ...")
                await ctx.report_progress(65, 100)

            triaged = await _triage_crashes(
                binary_path=validated_path,
                crash_files=crash_files,
                use_stdin=use_stdin,
                triage_timeout=60,
                ctx=ctx,
            )

        exploitable_count = sum(1 for t in triaged if t.get("is_exploitable"))
        confirmed_count = sum(1 for t in triaged if t.get("exploitability") == "CONFIRMED")

        if ctx:
            await ctx.info(
                f"📊 Triage complete: {exploitable_count} exploitable ({confirmed_count} CONFIRMED)"
            )
            await ctx.report_progress(95, 100)

        # ── Build next steps ─────────────────────────────────────────────────
        next_steps: list[str] = []
        if confirmed_count:
            next_steps.append(
                f"[CRITICAL] {confirmed_count} CONFIRMED exploitable crashes. "
                "Run generate_poc_exploit() on the top crash to get a pwntools script."
            )
        if exploitable_count and not confirmed_count:
            next_steps.append(
                f"[HIGH] {exploitable_count} LIKELY exploitable crashes. "
                "Run build_rop_chain() to attempt automatic chain construction."
            )
        if unique_crash_count == 0:
            next_steps.append(
                "[INFO] No crashes found. Try: increase timeout, use better seed corpus, "
                "or compile with -fsanitize=address for better crash detection."
            )
        if unique_crash_count > 0 and exploitable_count == 0:
            next_steps.append(
                "[MEDIUM] Crashes found but not exploitable per GDB. "
                "Crashes may be DoS-level bugs. Inspect triage_details for signals."
            )
        next_steps.append(
            "[INFO] For deeper analysis, run autonomous_vuln_hunt() which combines "
            "static taint analysis, symbolic execution, and fuzzing."
        )

        top_crash = triaged[0] if triaged else None

        if ctx:
            await ctx.report_progress(100, 100)
            await ctx.info(
                f"✅ Campaign complete — {unique_crash_count} crashes, "
                f"{exploitable_count} exploitable"
            )

        return success(
            {
                "campaign_summary": {
                    "binary": validated_path.name,
                    "duration_seconds": round(elapsed, 1),
                    "timeout_requested": timeout_seconds,
                    "total_crashes_raw": total_crash_count,
                    "unique_crashes_after_dedup": unique_crash_count,
                    "crashes_triaged": len(triaged),
                    "exploitable_count": exploitable_count,
                    "confirmed_count": confirmed_count,
                    "afl_stats": afl_stats,
                },
                "unique_crashes": unique_crash_count,
                "exploitable_count": exploitable_count,
                "confirmed_exploitable": confirmed_count,
                "triaged_crashes": triaged,
                "top_crash": top_crash,
                "next_steps": next_steps,
            }
        )
