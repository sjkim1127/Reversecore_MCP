#!/usr/bin/env python3
"""Unified Benchmark Suite CLI Runner for Reversecore_MCP.

Executes end-to-end automated 0-day/N-day vulnerability discovery,
Layer 1 meta-tool triage evaluation, dynamic sandbox containment tracing,
and multi-engine (Radare2 vs Fission vs Mock) comparative benchmarking.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader  # noqa: E402
from reversecore_mcp.benchmarks.dynamic_benchmark import DynamicSandboxBenchmarkRunner  # noqa: E402
from reversecore_mcp.benchmarks.engine_adapter import (  # noqa: E402
    EngineBenchmarkRunner,
    FissionEngineAdapter,
    MockEngineAdapter,
    Radare2EngineAdapter,
)
from reversecore_mcp.benchmarks.models import (  # noqa: E402
    ExecutionOptions,
    UnifiedBenchmarkScorecardSummary,
)
from reversecore_mcp.benchmarks.reporter import (  # noqa: E402
    BenchmarkReporter,
    UnifiedBenchmarkReporter,
)
from reversecore_mcp.benchmarks.runner import BenchmarkRunner  # noqa: E402
from reversecore_mcp.benchmarks.triage_benchmark import TriageBenchmarkRunner  # noqa: E402


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run automated multi-domain benchmarks for Reversecore_MCP."
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="cve",
        choices=["cve", "triage", "dynamic", "engine", "all"],
        help="Benchmark domain to evaluate: 'cve', 'triage', 'dynamic', 'engine', or 'all' (default: cve).",
    )
    parser.add_argument(
        "--corpus-dir",
        type=str,
        default="tests/fixtures/benchmarks",
        help="Path to benchmark corpus directory (default: tests/fixtures/benchmarks).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="artifacts/benchmarks",
        help="Directory where benchmark report and summary are stored (default: artifacts/benchmarks).",
    )
    parser.add_argument(
        "--output-format",
        type=str,
        default="both",
        choices=["both", "markdown", "json", "md", "stdout"],
        help="Output report format (default: both).",
    )
    parser.add_argument(
        "--targets",
        type=str,
        nargs="+",
        default=None,
        help="Specific target names or IDs to evaluate (e.g. sqlite_fts5 libpng_ihdr).",
    )
    parser.add_argument(
        "--cwe",
        type=str,
        nargs="+",
        default=None,
        help="CWE identifier filter (e.g. CWE-122).",
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Category filter (e.g. database_engine).",
    )
    parser.add_argument(
        "--mock",
        "--mock-mode",
        dest="mock",
        action="store_true",
        default=False,
        help="Run in offline mock evaluation mode.",
    )
    parser.add_argument(
        "--live",
        dest="live",
        action="store_true",
        default=False,
        help="Force live execution mode with dynamic compiler/sanitizer.",
    )
    parser.add_argument(
        "--clang-path",
        type=str,
        default=None,
        help="Custom path to Clang compiler executable.",
    )
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        default=False,
        help="Disable automatic fallback to mock fixtures if live execution fails.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds per target (default: 30s).",
    )
    parser.add_argument(
        "--fuzz-duration",
        type=int,
        default=5,
        help="Fuzzing duration in seconds per target (default: 5s).",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=2,
        help="Concurrency level for parallel target evaluation (default: 2).",
    )
    parser.add_argument(
        "--fail-under-tpr",
        type=float,
        default=None,
        help="Minimum required True Positive Rate percentage (e.g. 80.0).",
    )
    parser.add_argument(
        "--fail-under-cwe",
        type=float,
        default=None,
        help="Minimum required CWE Exact Match Rate percentage.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )
    return parser.parse_args(args)


async def async_main(args: argparse.Namespace) -> int:
    """Main async benchmark execution routine."""
    corpus_path = Path(args.corpus_dir)
    if not corpus_path.exists():
        print(f"[-] Corpus error: directory not found at {corpus_path}", file=sys.stderr)
        return 1

    start_total_time = time.perf_counter()
    corpus_loader = CorpusLoader(corpus_dir=corpus_path)
    mock_mode = args.mock or (not args.live)

    unified = UnifiedBenchmarkScorecardSummary()

    # 1. Mode: CVE Discovery & Reproduction
    if args.mode in ("cve", "all"):
        try:
            corpus_loader.load_corpus()
        except Exception as e:
            print(f"[-] Corpus error: {e}", file=sys.stderr)
            return 1

        options = ExecutionOptions(
            fuzz_duration_seconds=args.fuzz_duration,
            parallel_workers=args.parallel,
            concurrency=args.parallel,
            timeout_seconds=args.timeout,
            mock_mode=args.mock,
            auto_fallback=not args.no_fallback,
            clang_path=args.clang_path,
            category_filter=args.category or "all",
        )
        runner = BenchmarkRunner(
            corpus_dir=corpus_path,
            mock_mode=args.mock,
            timeout_per_target=args.timeout,
        )
        target_filter = args.targets if args.targets else "all"
        cwe_filter = args.cwe if args.cwe else "all"

        cve_scorecard = await runner.run_suite(
            target_filter=target_filter,
            cwe_filter=cwe_filter,
            options=options,
        )
        unified.cve_summary = cve_scorecard

    # 2. Mode: Layer 1 Meta-tool Triage
    if args.mode in ("triage", "all"):
        triage_runner = TriageBenchmarkRunner(
            mock_mode=mock_mode,
            timeout_seconds=args.timeout,
        )
        triage_targets = corpus_loader.load_triage_corpus()
        if triage_targets:
            triage_summary = await triage_runner.run_suite(
                triage_targets,
                workspace_dir=PROJECT_ROOT,
            )
            unified.triage_summary = triage_summary

    # 3. Mode: Dynamic Execution Sandbox
    if args.mode in ("dynamic", "all"):
        dyn_runner = DynamicSandboxBenchmarkRunner(
            mock_mode=mock_mode,
            timeout_seconds=min(args.timeout, 15),
        )
        dyn_targets = corpus_loader.load_dynamic_corpus()
        if dyn_targets:
            dyn_summary = await dyn_runner.run_suite(
                dyn_targets,
                workspace_dir=PROJECT_ROOT,
            )
            unified.dynamic_summary = dyn_summary

    # 4. Mode: Multi-Engine Benchmark (Radare2 vs Fission vs Mock)
    if args.mode in ("engine", "all"):
        engine_runner = EngineBenchmarkRunner(
            [
                Radare2EngineAdapter(),
                FissionEngineAdapter(),
                MockEngineAdapter(),
            ]
        )
        test_bin = PROJECT_ROOT / "tests/fixtures/workspace/binaries/pe/mingw_x86.exe"
        if test_bin.exists():
            engine_targets = [(test_bin, ["main", "_start"])]
        else:
            engine_targets = [(Path("/bin/ls"), ["main"])]

        engine_summary = await engine_runner.run_comparison(engine_targets)
        unified.engine_summary = engine_summary

    unified.total_duration_seconds = round(time.perf_counter() - start_total_time, 3)

    # 5. Output / Reporting
    if args.mode == "cve" and unified.cve_summary:
        # Standard CVE output for backwards compatibility
        scorecard = unified.cve_summary
        md_report = BenchmarkReporter.to_markdown(scorecard)
        if args.output_format == "stdout" or args.verbose:
            print(md_report)
        else:
            print("\n" + "=" * 70)
            print("BENCHMARK SCORECARD SUMMARY (CVE)")
            print("=" * 70)
            print(f"Total Targets Evaluated: {scorecard.total_targets}")
            print(
                f"Vulnerabilities Discovered (TPR): {scorecard.discovered_count}/{scorecard.total_targets} ({scorecard.discovery_rate_tpr_pct:.1f}%)"
            )
            print(f"CWE Classification Accuracy: {scorecard.cwe_exact_match_rate_pct:.1f}%")
            print(f"CVSS Scoring Alignment: {scorecard.cvss_tolerance_match_rate_pct:.1f}%")
            print(f"Average PoC Reduction: {scorecard.avg_poc_reduction_pct:.1f}%")
            print(f"Mean Time-to-Crash: {scorecard.mean_time_to_crash_seconds:.3f}s")
            print("=" * 70)

        if args.output_format != "stdout":
            saved = BenchmarkReporter.save_reports(
                summary=scorecard,
                output_dir=args.output_dir,
                output_format=args.output_format,
            )
            for fmt, path in saved.items():
                print(f"[+] Saved {fmt.capitalize()} Report: {path}")

        # Threshold checks
        if (
            args.fail_under_tpr is not None
            and scorecard.discovery_rate_tpr_pct < args.fail_under_tpr
        ):
            print(
                f"[-] Threshold failure: TPR {scorecard.discovery_rate_tpr_pct:.1f}% < {args.fail_under_tpr:.1f}%",
                file=sys.stderr,
            )
            return 2
        if (
            args.fail_under_cwe is not None
            and scorecard.cwe_exact_match_rate_pct < args.fail_under_cwe
        ):
            print(
                f"[-] Threshold failure: CWE {scorecard.cwe_exact_match_rate_pct:.1f}% < {args.fail_under_cwe:.1f}%",
                file=sys.stderr,
            )
            return 2
    else:
        # Unified Report
        md_report = UnifiedBenchmarkReporter.to_markdown(unified)
        if args.output_format == "stdout" or args.verbose:
            print(md_report)
        else:
            print("\n" + "=" * 70)
            print(f"UNIFIED BENCHMARK REPORT (Mode: {args.mode.upper()})")
            print("=" * 70)
            if unified.cve_summary:
                print(f"• CVE Discovery TPR: {unified.cve_summary.discovery_rate_tpr_pct:.1f}%")
            if unified.triage_summary:
                print(
                    f"• Triage Accuracy: {unified.triage_summary.triage_accuracy_pct:.1f}% ({unified.triage_summary.mean_latency_seconds:.3f}s latency)"
                )
            if unified.dynamic_summary:
                print(
                    f"• Dynamic Containment: {unified.dynamic_summary.containment_enforcement_rate_pct:.1f}% (Syscall Cov: {unified.dynamic_summary.avg_syscall_coverage_pct:.1f}%)"
                )
            if unified.engine_summary:
                print(
                    f"• Multi-Engine Compared: {', '.join(unified.engine_summary.engines_evaluated)}"
                )
            print(f"• Total Duration: {unified.total_duration_seconds:.2f}s")
            print("=" * 70)

        if args.output_format != "stdout":
            saved = UnifiedBenchmarkReporter.save_reports(
                summary=unified,
                output_dir=args.output_dir,
                output_format=args.output_format,
            )
            for fmt, path in saved.items():
                print(f"[+] Saved Unified {fmt.capitalize()} Report: {path}")

    print("PASS: Benchmark evaluation completed successfully.")
    return 0


def main() -> None:
    """CLI sync entrypoint."""
    args = parse_args()
    code = asyncio.run(async_main(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
