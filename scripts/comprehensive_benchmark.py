#!/usr/bin/env python3
"""
Comprehensive Performance Benchmark

Benchmarks all analysis tools and optimizations.
"""

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


class ComprehensiveBenchmark:
    """Run comprehensive performance benchmarks."""

    def __init__(self, output_dir: Path = None):
        """Initialize benchmark."""
        self.output_dir = output_dir or Path("artifacts/benchmarks")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}

    def run_tool_benchmark(self, tool_script: str, timeout: int = 120) -> dict[str, Any]:
        """Run individual tool benchmark."""
        print(f"\n📊 Running: {tool_script}")
        print("-" * 70)

        start_time = time.time()
        try:
            result = subprocess.run(
                ["python3", tool_script],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(Path(__file__).parent.parent),
            )
            elapsed = time.time() - start_time

            success = result.returncode == 0

            return {
                "script": tool_script,
                "success": success,
                "execution_time": elapsed,
                "returncode": result.returncode,
                "output_lines": len(result.stdout.split("\n")),
                "error_lines": len(result.stderr.split("\n")) if result.stderr else 0,
            }
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return {
                "script": tool_script,
                "success": False,
                "execution_time": elapsed,
                "returncode": -1,
                "output_lines": 0,
                "error_lines": 1,
                "error": "Timeout",
            }
        except Exception as e:
            elapsed = time.time() - start_time
            return {
                "script": tool_script,
                "success": False,
                "execution_time": elapsed,
                "returncode": -1,
                "output_lines": 0,
                "error_lines": 1,
                "error": str(e),
            }

    def run_all_benchmarks(self) -> dict[str, Any]:
        """Run all benchmarks."""
        benchmarks = [
            ("scripts/extended-tool-analysis.py", "Extended Tool Analysis"),
            ("scripts/benchmark-analysis-tools.py", "Tool Performance Benchmark"),
            ("scripts/parallel_analysis_framework.py", "Parallel Analysis Framework"),
            ("scripts/yara_malware_scanner.py", "YARA Malware Scanner"),
            ("scripts/binwalk_firmware_analyzer.py", "Binwalk Firmware Analyzer"),
        ]

        print("\n" + "=" * 70)
        print("COMPREHENSIVE PERFORMANCE BENCHMARK")
        print("=" * 70)
        print(f"Started: {datetime.now().isoformat()}")

        results = {}
        total_start = time.time()

        for script, name in benchmarks:
            script_path = Path(__file__).parent.parent / script
            if script_path.exists():
                result = self.run_tool_benchmark(script)
                results[name] = result

                if result["success"]:
                    print(f"✅ {name}: {result['execution_time']:.3f}s")
                else:
                    print(f"⚠️  {name}: {result['execution_time']:.3f}s (failed)")
            else:
                print(f"⚠️  {script} not found")

        total_time = time.time() - total_start

        return {
            "timestamp": datetime.now().isoformat(),
            "total_time": total_time,
            "benchmarks": results,
        }

    def generate_report(self, benchmark_results: dict[str, Any]) -> Path:
        """Generate comprehensive benchmark report."""
        output_file = self.output_dir / "comprehensive_benchmark.json"

        # Calculate statistics
        successful = sum(
            1 for r in benchmark_results["benchmarks"].values() if r.get("success", False)
        )
        total_benchmarks = len(benchmark_results["benchmarks"])

        summary = {
            "timestamp": benchmark_results["timestamp"],
            "total_execution_time": benchmark_results["total_time"],
            "benchmarks_run": total_benchmarks,
            "successful": successful,
            "failed": total_benchmarks - successful,
            "success_rate": (
                f"{(successful / total_benchmarks * 100):.1f}%" if total_benchmarks > 0 else "N/A"
            ),
            "details": benchmark_results["benchmarks"],
        }

        with open(output_file, "w") as f:
            json.dump(summary, f, indent=2)

        return output_file

    def load_analysis_reports(self) -> dict[str, Any]:
        """Load analysis reports from artifacts."""
        reports = {}

        report_files = [
            (
                "extended_analysis",
                "artifacts/extended_analysis/extended_analysis_report.json",
            ),
            (
                "parallel_analysis",
                "artifacts/parallel_analysis/parallel_analysis_report.json",
            ),
            ("yara_scan", "artifacts/yara_scan_report.json"),
            ("binwalk_analysis", "artifacts/firmware_analysis/binwalk_report.json"),
        ]

        for name, path in report_files:
            report_path = Path(path)
            if report_path.exists():
                try:
                    with open(report_path) as f:
                        reports[name] = json.load(f)
                    print(f"✅ Loaded: {name}")
                except Exception as e:
                    print(f"⚠️  Failed to load {name}: {e}")

        return reports

    def print_comprehensive_summary(
        self, benchmark_results: dict[str, Any], analysis_reports: dict[str, Any]
    ):
        """Print comprehensive summary."""
        print("\n" + "=" * 70)
        print("COMPREHENSIVE PERFORMANCE SUMMARY")
        print("=" * 70)

        # Benchmark summary
        print("\n📊 BENCHMARK RESULTS:")
        print("-" * 70)
        total_benchmarks = len(benchmark_results["benchmarks"])
        successful = sum(
            1 for r in benchmark_results["benchmarks"].values() if r.get("success", False)
        )

        print(f"Total Benchmarks: {total_benchmarks}")
        print(f"Successful: {successful}/{total_benchmarks}")
        print(f"Total Time: {benchmark_results['total_time']:.3f}s")

        for name, result in benchmark_results["benchmarks"].items():
            status = "✅" if result.get("success") else "❌"
            time_str = f"{result.get('execution_time', 0):.3f}s"
            print(f"  {status} {name}: {time_str}")

        # Analysis reports summary
        if analysis_reports:
            print("\n📈 ANALYSIS RESULTS:")
            print("-" * 70)

            for name, report in analysis_reports.items():
                if "statistics" in report:
                    stats = report["statistics"]
                    print(f"\n{name}:")
                    for key, value in stats.items():
                        print(f"  - {key}: {value}")

        print("\n" + "=" * 70)


def main():
    """Run comprehensive benchmark."""
    benchmark = ComprehensiveBenchmark()

    # Run benchmarks
    print("🚀 Starting comprehensive performance benchmark...")
    benchmark_results = benchmark.run_all_benchmarks()

    # Generate report
    report_path = benchmark.generate_report(benchmark_results)
    print(f"\n✅ Benchmark report saved to: {report_path}")

    # Load analysis reports
    print("\n📊 Loading analysis reports...")
    analysis_reports = benchmark.load_analysis_reports()

    # Print summary
    benchmark.print_comprehensive_summary(benchmark_results, analysis_reports)

    print("\n✅ Comprehensive benchmark completed!")


if __name__ == "__main__":
    main()
