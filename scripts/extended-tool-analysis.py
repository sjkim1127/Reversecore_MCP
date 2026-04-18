#!/usr/bin/env python3
"""
Extended tool analysis and comparison framework.

Comprehensive analysis of all available binary analysis tools.
"""

import subprocess
import json
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import shutil
from datetime import datetime


@dataclass
class ToolAnalysisResult:
    """Result of tool analysis."""
    tool_name: str
    available: bool
    executable_path: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ToolComparison:
    """Comparison result for tool analysis."""
    tool_name: str
    binary_name: str
    analysis_type: str
    success: bool
    execution_time: float
    output_lines: int
    output_size: int
    error: Optional[str] = None


class ExtendedToolAnalyzer:
    """Analyze extended set of binary analysis tools."""

    # Tools to test
    TOOLS = {
        # Basic tools (always available)
        "file": {"args": ["-b"], "type": "file_info"},
        "strings": {"args": [], "type": "string_extraction"},
        "objdump": {"args": ["-d", "--all-headers"], "type": "disassembly"},
        "nm": {"args": ["-a"], "type": "symbol_analysis"},

        # macOS tools
        "otool": {"args": ["-h"], "type": "header_analysis"},

        # Linux tools
        "readelf": {"args": ["-h"], "type": "header_analysis"},
        "ldd": {"args": [], "type": "dependency_analysis"},

        # Binary tracing tools
        "strace": {"args": ["-e", "trace=exit"], "type": "system_trace"},
        "ltrace": {"args": ["-e", "exit"], "type": "library_trace"},

        # Pattern matching tools
        "radare2": {"args": ["-q", "-c", "afl;q"], "type": "advanced_analysis"},
    }

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("artifacts/extended_analysis")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ToolAnalysisResult] = []
        self.comparisons: List[ToolComparison] = []

    def check_tool_availability(self) -> Dict[str, ToolAnalysisResult]:
        """Check availability of all tools."""
        print("\n" + "=" * 70)
        print("CHECKING TOOL AVAILABILITY")
        print("=" * 70)

        results = {}
        for tool_name in self.TOOLS.keys():
            path = shutil.which(tool_name)
            available = path is not None

            result = ToolAnalysisResult(
                tool_name=tool_name,
                available=available,
                executable_path=path,
            )

            if available:
                # Try to get version
                try:
                    version_result = subprocess.run(
                        [tool_name, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if version_result.returncode == 0:
                        result.version = version_result.stdout.split('\n')[0]
                except:
                    pass

                status = "✅"
            else:
                status = "❌"

            print(f"{status} {tool_name:12} {'(available)' if available else '(not found)'}")
            if result.version:
                print(f"           Version: {result.version}")

            self.results.append(result)
            results[tool_name] = result

        return results

    def analyze_binary_with_tool(
        self,
        tool_name: str,
        binary_path: str,
        args: List[str] = None,
        timeout: int = 30
    ) -> ToolComparison:
        """Analyze binary with specific tool."""
        if args is None:
            args = []

        start_time = time.time()
        try:
            result = subprocess.run(
                [tool_name] + args + [binary_path],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            elapsed = time.time() - start_time

            output = result.stdout + result.stderr
            output_lines = len(output.split('\n'))
            output_size = len(output.encode('utf-8'))

            return ToolComparison(
                tool_name=tool_name,
                binary_name=Path(binary_path).name,
                analysis_type=self.TOOLS[tool_name]["type"],
                success=result.returncode == 0,
                execution_time=elapsed,
                output_lines=output_lines,
                output_size=output_size,
                error=result.stderr if result.returncode != 0 else None,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return ToolComparison(
                tool_name=tool_name,
                binary_name=Path(binary_path).name,
                analysis_type=self.TOOLS[tool_name]["type"],
                success=False,
                execution_time=elapsed,
                output_lines=0,
                output_size=0,
                error=f"Timeout after {timeout}s",
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return ToolComparison(
                tool_name=tool_name,
                binary_name=Path(binary_path).name,
                analysis_type=self.TOOLS[tool_name]["type"],
                success=False,
                execution_time=elapsed,
                output_lines=0,
                output_size=0,
                error=str(e),
            )

    def analyze_binary(self, binary_path: str) -> List[ToolComparison]:
        """Analyze binary with all available tools."""
        results = []

        print(f"\nAnalyzing: {Path(binary_path).name}")
        print("-" * 70)

        for tool_name, tool_config in self.TOOLS.items():
            if not shutil.which(tool_name):
                continue

            comparison = self.analyze_binary_with_tool(
                tool_name,
                binary_path,
                args=tool_config["args"],
                timeout=30
            )

            status = "✅" if comparison.success else "❌"
            print(f"{status} {tool_name:12} {comparison.execution_time:.3f}s "
                  f"({comparison.output_lines} lines, {comparison.output_size} bytes)")

            self.comparisons.append(comparison)
            results.append(comparison)

        return results

    def generate_report(self) -> Path:
        """Generate comprehensive analysis report."""
        report_path = self.output_dir / "extended_analysis_report.json"

        # Group by tool
        by_tool = {}
        for comp in self.comparisons:
            if comp.tool_name not in by_tool:
                by_tool[comp.tool_name] = []
            by_tool[comp.tool_name].append(asdict(comp))

        # Generate statistics
        stats = {}
        for tool_name, analyses in by_tool.items():
            success_count = sum(1 for a in analyses if a["success"])
            times = [a["execution_time"] for a in analyses]
            avg_time = sum(times) / len(times) if times else 0
            total_output = sum(a["output_size"] for a in analyses)

            stats[tool_name] = {
                "success_rate": f"{success_count}/{len(analyses)}",
                "avg_time": f"{avg_time:.3f}s",
                "min_time": f"{min(times):.3f}s" if times else "N/A",
                "max_time": f"{max(times):.3f}s" if times else "N/A",
                "total_output": total_output,
                "analysis_count": len(analyses),
            }

        report = {
            "timestamp": datetime.now().isoformat(),
            "tool_availability": [asdict(r) for r in self.results],
            "statistics": stats,
            "detailed_results": by_tool,
        }

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        return report_path

    def print_summary(self):
        """Print analysis summary."""
        print("\n" + "=" * 70)
        print("ANALYSIS SUMMARY")
        print("=" * 70)

        # Tool availability
        available = sum(1 for r in self.results if r.available)
        total = len(self.results)
        print(f"\nTool Availability: {available}/{total}")

        # Analysis statistics
        by_tool = {}
        for comp in self.comparisons:
            if comp.tool_name not in by_tool:
                by_tool[comp.tool_name] = {"success": 0, "total": 0, "times": []}
            by_tool[comp.tool_name]["total"] += 1
            by_tool[comp.tool_name]["times"].append(comp.execution_time)
            if comp.success:
                by_tool[comp.tool_name]["success"] += 1

        print("\nTool Performance:")
        print("-" * 70)
        for tool_name, stats in sorted(by_tool.items()):
            success_rate = f"{stats['success']}/{stats['total']}"
            avg_time = sum(stats['times']) / len(stats['times']) if stats['times'] else 0
            print(f"{tool_name:12} {success_rate:6} {avg_time:.3f}s avg")

        print("\n" + "=" * 70)


def main():
    """Run extended tool analysis."""
    import sys

    # Find test binaries
    binaries_dir = Path("tests/fixtures/workspace/binaries")
    if not binaries_dir.exists():
        print(f"Error: {binaries_dir} not found. Run generate-test-binaries.sh first.")
        sys.exit(1)

    binaries = list(binaries_dir.glob("*_x64*")) + list(binaries_dir.glob("*.exe"))
    if not binaries:
        print("No test binaries found")
        sys.exit(1)

    print(f"Found {len(binaries)} binaries:")
    for b in binaries:
        print(f"  - {b.name}")

    # Run analysis
    analyzer = ExtendedToolAnalyzer()

    print("\n1. Checking Tool Availability")
    print("=" * 70)
    availability = analyzer.check_tool_availability()

    print("\n2. Running Analysis on Binaries")
    print("=" * 70)
    for binary in binaries:
        analyzer.analyze_binary(str(binary))

    # Generate reports
    report_path = analyzer.generate_report()
    print(f"\n✅ Report saved to: {report_path}")

    analyzer.print_summary()


if __name__ == "__main__":
    main()
