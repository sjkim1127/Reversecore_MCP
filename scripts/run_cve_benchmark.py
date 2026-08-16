#!/usr/bin/env python3
"""CVE Benchmark Suite CLI Runner for Reversecore_MCP.

Executes end-to-end automated 0-day/N-day vulnerability discovery, reproduction,
and scoring against benchmark targets (SQLite FTS5, LibPNG, LibXML2, LibArchive).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader  # noqa: E402
from reversecore_mcp.benchmarks.models import ExecutionOptions  # noqa: E402
from reversecore_mcp.benchmarks.reporter import BenchmarkReporter  # noqa: E402
from reversecore_mcp.benchmarks.runner import BenchmarkRunner  # noqa: E402


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run automated CVE discovery benchmark suite against C/C++ targets."
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
        action="store_true",
        default=False,
        help="Run in offline mock evaluation mode.",
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
        print(
            f"[-] Corpus error: directory not found at {corpus_path}",
            file=sys.stderr,
        )
        return 1

    # 1. Initialize Corpus Loader
    corpus_loader = CorpusLoader(corpus_dir=corpus_path)
    try:
        targets = corpus_loader.load_corpus()
    except Exception as e:
        print(f"[-] Corpus error: {e}", file=sys.stderr)
        return 1

    if not targets:
        print(
            f"[-] Corpus error: No benchmark targets found in {corpus_path}",
            file=sys.stderr,
        )
        return 1

    if args.targets:
        target_filter_set = set(args.targets)
        matched_targets = [
            t
            for t in targets
            if t.target_id in target_filter_set or t.target_name in target_filter_set
        ]
        if not matched_targets:
            print(
                f"[-] Error: None of the specified targets {args.targets} were found.",
                file=sys.stderr,
            )
            return 1

    # 2. Configure Benchmark Runner
    options = ExecutionOptions(
        fuzz_duration_seconds=args.fuzz_duration,
        concurrency=args.parallel,
        timeout_seconds=args.timeout,
        mock_mode=args.mock,
        category_filter=args.category or "all",
    )
    runner = BenchmarkRunner(
        corpus_dir=corpus_path,
        mock_mode=args.mock,
        timeout_per_target=args.timeout,
    )

    target_filter = args.targets if args.targets else "all"
    cwe_filter = args.cwe if args.cwe else "all"

    scorecard = await runner.run_suite(
        target_filter=target_filter,
        cwe_filter=cwe_filter,
        options=options,
    )

    # 3. Print Summary / Markdown to stdout
    md_report = BenchmarkReporter.to_markdown(scorecard)
    if args.output_format == "stdout" or args.verbose:
        print(md_report)
    else:
        print("\n" + "=" * 70)
        print("📊 BENCHMARK SCORECARD SUMMARY")
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

    # 4. Export JSON and Markdown Reports
    if args.output_format != "stdout":
        saved_reports = BenchmarkReporter.save_reports(
            summary=scorecard,
            output_dir=args.output_dir,
            output_format=args.output_format,
        )
        for fmt, path in saved_reports.items():
            print(f"[+] Saved {fmt.capitalize()} Report: {path}")

    # 5. Threshold Enforcement
    if args.fail_under_tpr is not None:
        if scorecard.discovery_rate_tpr_pct < args.fail_under_tpr:
            print(
                f"[-] Threshold failure: Discovery rate TPR {scorecard.discovery_rate_tpr_pct:.1f}% is below required {args.fail_under_tpr:.1f}%",
                file=sys.stderr,
            )
            return 2

    if args.fail_under_cwe is not None:
        if scorecard.cwe_exact_match_rate_pct < args.fail_under_cwe:
            print(
                f"[-] Threshold failure: CWE exact match rate {scorecard.cwe_exact_match_rate_pct:.1f}% is below required {args.fail_under_cwe:.1f}%",
                file=sys.stderr,
            )
            return 2

    print("✅ PASS: All benchmark targets evaluated successfully.")
    return 0


def main() -> None:
    """CLI sync entrypoint."""
    args = parse_args()
    code = asyncio.run(async_main(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
