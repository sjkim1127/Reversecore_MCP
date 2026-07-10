#!/usr/bin/env python3
"""
Performance benchmarking for analysis tools.

Measures execution time, memory usage, and accuracy for various tools.
"""

import json
import shutil
import statistics
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class BenchmarkResult:
    """Benchmark result for a single tool run."""

    tool_name: str
    binary_name: str
    binary_size: int
    execution_time: float
    memory_peak: int
    success: bool
    error: str | None = None
    details: dict = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class AnalysisToolBenchmark:
    """Benchmark analysis tools."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("artifacts/benchmarks")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[BenchmarkResult] = []

    def benchmark_tool(
        self, tool: str, binary_path: str, args: list[str] = None, timeout: int = 60
    ) -> BenchmarkResult:
        """Benchmark a single tool on a binary."""
        if args is None:
            args = []

        binary_size = Path(binary_path).stat().st_size if Path(binary_path).exists() else 0

        start_time = time.time()
        try:
            result = subprocess.run(
                [tool] + args + [binary_path],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            elapsed = time.time() - start_time

            return BenchmarkResult(
                tool_name=tool,
                binary_name=Path(binary_path).name,
                binary_size=binary_size,
                execution_time=elapsed,
                memory_peak=0,  # Would need psutil for actual memory
                success=result.returncode == 0,
                error=result.stderr if result.returncode != 0 else None,
                details={
                    "returncode": result.returncode,
                    "stdout_lines": len(result.stdout.splitlines()),
                },
            )
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return BenchmarkResult(
                tool_name=tool,
                binary_name=Path(binary_path).name,
                binary_size=binary_size,
                execution_time=elapsed,
                memory_peak=0,
                success=False,
                error=f"Timeout after {timeout}s",
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return BenchmarkResult(
                tool_name=tool,
                binary_name=Path(binary_path).name,
                binary_size=binary_size,
                execution_time=elapsed,
                memory_peak=0,
                success=False,
                error=str(e),
            )

    def benchmark_file_command(self, binary_path: str) -> BenchmarkResult:
        """Benchmark 'file' command."""
        return self.benchmark_tool("file", binary_path, ["-b"])

    def benchmark_strings(self, binary_path: str) -> BenchmarkResult:
        """Benchmark 'strings' command."""
        return self.benchmark_tool("strings", binary_path)

    def benchmark_objdump(self, binary_path: str) -> BenchmarkResult:
        """Benchmark 'objdump' command."""
        return self.benchmark_tool("objdump", binary_path, ["-d", "--all-headers"])

    def benchmark_radare2(self, binary_path: str) -> BenchmarkResult:
        """Benchmark radare2 analysis."""
        return self.benchmark_tool("r2", binary_path, ["-q", "-c", "afl;q"])

    def benchmark_capstone(self, binary_path: str) -> BenchmarkResult:
        """Benchmark Capstone disassembly."""
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError:
            return BenchmarkResult(
                tool_name="capstone",
                binary_name=Path(binary_path).name,
                binary_size=0,
                execution_time=0,
                memory_peak=0,
                success=False,
                error="Capstone not installed",
            )

        binary_size = Path(binary_path).stat().st_size if Path(binary_path).exists() else 0
        start_time = time.time()

        try:
            with open(binary_path, "rb") as f:
                code = f.read()

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            instructions = list(md.disasm(code, 0))

            elapsed = time.time() - start_time
            return BenchmarkResult(
                tool_name="capstone",
                binary_name=Path(binary_path).name,
                binary_size=binary_size,
                execution_time=elapsed,
                memory_peak=0,
                success=True,
                details={"instructions_disassembled": len(instructions)},
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return BenchmarkResult(
                tool_name="capstone",
                binary_name=Path(binary_path).name,
                binary_size=binary_size,
                execution_time=elapsed,
                memory_peak=0,
                success=False,
                error=str(e),
            )

    def benchmark_all_tools(self, binary_path: str) -> list[BenchmarkResult]:
        """Benchmark all available tools."""
        results = []

        # Core tools
        for tool, method in [
            ("file", self.benchmark_file_command),
            ("strings", self.benchmark_strings),
            ("objdump", self.benchmark_objdump),
        ]:
            if shutil.which(tool):
                results.append(method(binary_path))

        # Optional tools
        if shutil.which("r2"):
            results.append(self.benchmark_radare2(binary_path))

        results.append(self.benchmark_capstone(binary_path))

        self.results.extend(results)
        return results

    def generate_report(self, filename: str = "benchmark_report.json") -> Path:
        """Generate benchmark report."""
        report_path = self.output_dir / filename

        # Calculate statistics
        by_tool = {}
        for result in self.results:
            if result.tool_name not in by_tool:
                by_tool[result.tool_name] = []
            by_tool[result.tool_name].append(result.execution_time)

        stats = {}
        for tool, times in by_tool.items():
            stats[tool] = {
                "avg_time": statistics.mean(times),
                "min_time": min(times),
                "max_time": max(times),
                "stdev": statistics.stdev(times) if len(times) > 1 else 0,
                "runs": len(times),
            }

        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_runs": len(self.results),
            "statistics": stats,
            "results": [asdict(r) for r in self.results],
        }

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        return report_path

    def print_summary(self):
        """Print benchmark summary."""
        print("\n" + "=" * 70)
        print("BENCHMARK SUMMARY")
        print("=" * 70)

        by_tool = {}
        for result in self.results:
            if result.tool_name not in by_tool:
                by_tool[result.tool_name] = []
            by_tool[result.tool_name].append(result)

        for tool, results in sorted(by_tool.items()):
            success = sum(1 for r in results if r.success)
            times = [r.execution_time for r in results]
            avg_time = statistics.mean(times)

            print(f"\n{tool}:")
            print(f"  Success rate: {success}/{len(results)}")
            print(f"  Avg time: {avg_time:.3f}s")
            print(f"  Min time: {min(times):.3f}s")
            print(f"  Max time: {max(times):.3f}s")

        print("\n" + "=" * 70)


def main():
    """Run benchmarks on test binaries."""
    import sys

    # Find test binaries
    binaries_dir = Path("tests/fixtures/workspace/binaries")
    if not binaries_dir.exists():
        print(f"Error: {binaries_dir} not found. Run generate-test-binaries.sh first.")
        sys.exit(1)

    binaries = list(binaries_dir.glob("*_x64*"))
    if not binaries:
        print("No test binaries found")
        sys.exit(1)

    print(f"Found {len(binaries)} binaries:")
    for b in binaries:
        print(f"  - {b.name}")

    # Run benchmarks
    benchmark = AnalysisToolBenchmark()

    for binary in binaries:
        print(f"\nBenchmarking {binary.name}...")
        results = benchmark.benchmark_all_tools(str(binary))
        for result in results:
            status = "✓" if result.success else "✗"
            print(f"  {status} {result.tool_name}: {result.execution_time:.3f}s")

    # Generate report
    report_path = benchmark.generate_report()
    print(f"\nReport saved to: {report_path}")

    benchmark.print_summary()


if __name__ == "__main__":
    main()
