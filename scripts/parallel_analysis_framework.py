#!/usr/bin/env python3
"""
Parallel Binary Analysis Framework

Optimized parallel execution of multiple analysis tools for performance.
"""

import json
import multiprocessing
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class AnalysisTask:
    """Single analysis task."""

    tool_name: str
    binary_path: str
    command: list[str]
    timeout: int = 30


@dataclass
class AnalysisResult:
    """Result of single analysis task."""

    tool_name: str
    binary_name: str
    success: bool
    output_lines: int
    output_size: int
    execution_time: float
    error: str = None


def run_analysis_task(task: AnalysisTask) -> AnalysisResult:
    """Run a single analysis task."""
    start_time = time.time()

    try:
        result = subprocess.run(
            task.command + [task.binary_path], capture_output=True, text=True, timeout=task.timeout
        )

        elapsed = time.time() - start_time
        output = result.stdout + result.stderr

        return AnalysisResult(
            tool_name=task.tool_name,
            binary_name=Path(task.binary_path).name,
            success=result.returncode == 0,
            output_lines=len(output.split("\n")),
            output_size=len(output.encode("utf-8")),
            execution_time=elapsed,
            error=None if result.returncode == 0 else result.stderr,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        return AnalysisResult(
            tool_name=task.tool_name,
            binary_name=Path(task.binary_path).name,
            success=False,
            output_lines=0,
            output_size=0,
            execution_time=elapsed,
            error=f"Timeout after {task.timeout}s",
        )
    except Exception as e:
        elapsed = time.time() - start_time
        return AnalysisResult(
            tool_name=task.tool_name,
            binary_name=Path(task.binary_path).name,
            success=False,
            output_lines=0,
            output_size=0,
            execution_time=elapsed,
            error=str(e),
        )


@dataclass
class ParallelAnalysisConfig:
    """Configuration for parallel analysis."""

    use_threads: bool = True
    max_workers: int = None
    timeout_per_task: int = 30
    batch_size: int = 10


class ParallelBinaryAnalyzer:
    """Parallel binary analysis framework."""

    def __init__(self, config: ParallelAnalysisConfig = None, output_dir: Path = None):
        """Initialize parallel analyzer."""
        self.config = config or ParallelAnalysisConfig()
        self.output_dir = output_dir or Path("artifacts/parallel_analysis")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Auto-detect optimal worker count
        if self.config.max_workers is None:
            self.config.max_workers = min(4, multiprocessing.cpu_count())

    def create_analysis_tasks(
        self, binaries: list[str], tools: dict[str, list[str]]
    ) -> list[AnalysisTask]:
        """Create analysis tasks for binaries and tools."""
        tasks = []

        for binary in binaries:
            for tool_name, args in tools.items():
                task = AnalysisTask(
                    tool_name=tool_name,
                    binary_path=binary,
                    command=[tool_name] + args,
                    timeout=self.config.timeout_per_task,
                )
                tasks.append(task)

        return tasks

    def run_tasks_sequential(self, tasks: list[AnalysisTask]) -> list[AnalysisResult]:
        """Run tasks sequentially."""
        print(f"Running {len(tasks)} tasks sequentially...")
        results = []

        for i, task in enumerate(tasks, 1):
            print(f"  [{i}/{len(tasks)}] {task.tool_name} on {Path(task.binary_path).name}")
            result = run_analysis_task(task)
            results.append(result)

        return results

    def run_tasks_parallel(self, tasks: list[AnalysisTask]) -> list[AnalysisResult]:
        """Run tasks in parallel using threads or processes."""
        executor_class = ThreadPoolExecutor if self.config.use_threads else ProcessPoolExecutor
        results = []
        completed = 0

        with executor_class(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            futures = {executor.submit(run_analysis_task, task): task for task in tasks}

            total = len(futures)
            print(f"Running {total} tasks in parallel ({self.config.max_workers} workers)...")

            # Process completed tasks
            for future in as_completed(futures):
                completed += 1
                task = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    status = "✅" if result.success else "❌"
                    print(
                        f"  [{completed}/{total}] {status} {task.tool_name} ({result.execution_time:.3f}s)"
                    )
                except Exception as e:
                    print(f"  [{completed}/{total}] ❌ {task.tool_name} - Error: {e}")

        return results

    def benchmark_sequential_vs_parallel(
        self, binaries: list[str], tools: dict[str, list[str]]
    ) -> dict[str, Any]:
        """Benchmark sequential vs parallel execution."""
        tasks = self.create_analysis_tasks(binaries, tools)

        print("\n" + "=" * 70)
        print("SEQUENTIAL EXECUTION")
        print("=" * 70)
        start = time.time()
        self.run_tasks_sequential(tasks)
        seq_time = time.time() - start

        print("\n" + "=" * 70)
        print("PARALLEL EXECUTION")
        print("=" * 70)
        start = time.time()
        self.run_tasks_parallel(tasks)
        par_time = time.time() - start

        # Calculate speedup
        speedup = seq_time / par_time if par_time > 0 else 0
        efficiency = (speedup / self.config.max_workers * 100) if self.config.max_workers > 0 else 0

        return {
            "sequential_time": seq_time,
            "parallel_time": par_time,
            "speedup": speedup,
            "efficiency": f"{efficiency:.1f}%",
            "tasks_run": len(tasks),
            "workers": self.config.max_workers,
            "use_threads": self.config.use_threads,
        }

    def generate_performance_report(
        self,
        results: list[AnalysisResult],
        benchmark: dict[str, Any] = None,
        output_file: Path = None,
    ) -> Path:
        """Generate performance analysis report."""
        output_file = output_file or self.output_dir / "parallel_analysis_report.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Calculate statistics
        total_tasks = len(results)
        successful = sum(1 for r in results if r.success)
        total_time = sum(r.execution_time for r in results)
        avg_time = total_time / total_tasks if total_tasks > 0 else 0

        # Group by tool
        by_tool = {}
        for result in results:
            if result.tool_name not in by_tool:
                by_tool[result.tool_name] = {"success": 0, "total": 0, "avg_time": 0, "times": []}
            by_tool[result.tool_name]["total"] += 1
            by_tool[result.tool_name]["times"].append(result.execution_time)
            if result.success:
                by_tool[result.tool_name]["success"] += 1

        # Calculate averages
        for tool in by_tool:
            times = by_tool[tool]["times"]
            by_tool[tool]["avg_time"] = sum(times) / len(times) if times else 0
            del by_tool[tool]["times"]

        report = {
            "timestamp": datetime.now().isoformat(),
            "statistics": {
                "total_tasks": total_tasks,
                "successful": successful,
                "failed": total_tasks - successful,
                "success_rate": f"{(successful / total_tasks * 100):.1f}%",
                "total_time": f"{total_time:.3f}s",
                "avg_time": f"{avg_time:.3f}s",
            },
            "by_tool": by_tool,
            "benchmark": benchmark,
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        return output_file

    def print_summary(self, results: list[AnalysisResult], benchmark: dict[str, Any] = None):
        """Print analysis summary."""
        print("\n" + "=" * 70)
        print("PARALLEL ANALYSIS SUMMARY")
        print("=" * 70)

        total = len(results)
        successful = sum(1 for r in results if r.success)
        failed = total - successful

        print(f"\nTotal Tasks: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(successful / total * 100):.1f}%")

        total_time = sum(r.execution_time for r in results)
        print(f"\nTotal Time: {total_time:.3f}s")
        print(f"Avg Time per Task: {(total_time / total):.3f}s" if total > 0 else "N/A")

        if benchmark:
            print("\nPerformance Comparison:")
            print(f"  Sequential: {benchmark['sequential_time']:.3f}s")
            print(f"  Parallel: {benchmark['parallel_time']:.3f}s")
            print(f"  Speedup: {benchmark['speedup']:.2f}x")
            print(f"  Efficiency: {benchmark['efficiency']}")

        print("\n" + "=" * 70)


def main():
    """Run parallel analysis benchmark."""
    from pathlib import Path

    # Find binaries
    binaries_dir = Path("tests/fixtures/workspace/binaries")
    if not binaries_dir.exists():
        print(f"⚠️  Binaries directory not found: {binaries_dir}")
        return

    binaries = [str(b) for b in binaries_dir.glob("*") if b.is_file()]
    if not binaries:
        print("⚠️  No binaries found")
        return

    print(f"📁 Found {len(binaries)} binaries")

    # Define analysis tools
    tools = {
        "file": ["-b"],
        "strings": [],
        "nm": ["-a"],
    }

    # Configure parallel analyzer
    config = ParallelAnalysisConfig(use_threads=True, max_workers=4, timeout_per_task=30)

    analyzer = ParallelBinaryAnalyzer(config)

    # Run benchmark
    benchmark = analyzer.benchmark_sequential_vs_parallel(binaries, tools)

    # Generate report
    tasks = analyzer.create_analysis_tasks(binaries, tools)
    results = analyzer.run_tasks_parallel(tasks)

    report_path = analyzer.generate_performance_report(results, benchmark=benchmark)
    print(f"\n✅ Report saved to: {report_path}")

    # Print summary
    analyzer.print_summary(results, benchmark)


if __name__ == "__main__":
    main()
