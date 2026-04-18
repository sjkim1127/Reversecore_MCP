#!/usr/bin/env python3
"""
Binwalk Firmware Analysis Integration

Analyzes firmware images for embedded files and components.
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import tempfile
import shutil


@dataclass
class BinwalkSignature:
    """Binwalk signature match."""
    offset: int
    description: str
    file_type: str


@dataclass
class BinwalkResult:
    """Result of binwalk scan."""
    binary_path: str
    scan_time: float
    signatures_found: int
    signatures: List[Dict]
    extracted_files: List[str] = None
    error: Optional[str] = None


class BinwalkFirmwareAnalyzer:
    """Firmware analysis using binwalk."""

    def __init__(self, output_dir: Path = None):
        """Initialize analyzer."""
        self.output_dir = output_dir or Path("artifacts/firmware_analysis")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.binwalk_available = self._check_binwalk()

    def _check_binwalk(self) -> bool:
        """Check if binwalk is available."""
        # First check if binwalk CLI exists
        if shutil.which("binwalk"):
            return True

        # Then check if Python library is available
        try:
            import binwalk
            return True
        except ImportError:
            return False

    def scan_binary_cli(self, binary_path: str) -> BinwalkResult:
        """Scan using binwalk CLI."""
        if not shutil.which("binwalk"):
            return BinwalkResult(
                binary_path=binary_path,
                scan_time=0,
                signatures_found=0,
                signatures=[],
                error="binwalk CLI not available"
            )

        if not Path(binary_path).exists():
            return BinwalkResult(
                binary_path=binary_path,
                scan_time=0,
                signatures_found=0,
                signatures=[],
                error=f"Binary not found: {binary_path}"
            )

        start_time = time.time()
        try:
            result = subprocess.run(
                ["binwalk", "-j", binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            scan_time = time.time() - start_time

            signatures = []
            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    results_list = data.get("results", [])
                    if results_list:
                        for entry in results_list[0].get("results", []):
                            signatures.append({
                                "offset": hex(entry.get("offset", 0)),
                                "description": entry.get("description", ""),
                                "valid": entry.get("valid", False)
                            })
                except json.JSONDecodeError:
                    pass

            return BinwalkResult(
                binary_path=binary_path,
                scan_time=scan_time,
                signatures_found=len(signatures),
                signatures=signatures,
                error=None
            )
        except subprocess.TimeoutExpired:
            scan_time = time.time() - start_time
            return BinwalkResult(
                binary_path=binary_path,
                scan_time=scan_time,
                signatures_found=0,
                signatures=[],
                error="Scan timeout"
            )
        except Exception as e:
            scan_time = time.time() - start_time
            return BinwalkResult(
                binary_path=binary_path,
                scan_time=scan_time,
                signatures_found=0,
                signatures=[],
                error=str(e)
            )

    def scan_binary_library(self, binary_path: str) -> BinwalkResult:
        """Scan using binwalk Python library."""
        try:
            import binwalk
        except ImportError:
            return BinwalkResult(
                binary_path=binary_path,
                scan_time=0,
                signatures_found=0,
                signatures=[],
                error="binwalk Python library not available"
            )

        if not Path(binary_path).exists():
            return BinwalkResult(
                binary_path=binary_path,
                scan_time=0,
                signatures_found=0,
                signatures=[],
                error=f"Binary not found: {binary_path}"
            )

        start_time = time.time()
        try:
            scan = binwalk.scan(str(binary_path), signature=True, quiet=True)
            scan_time = time.time() - start_time

            signatures = []
            for module in scan.modules:
                if hasattr(module, 'results'):
                    for result in module.results:
                        signatures.append({
                            "offset": hex(result.offset),
                            "description": result.description,
                        })

            return BinwalkResult(
                binary_path=binary_path,
                scan_time=scan_time,
                signatures_found=len(signatures),
                signatures=signatures,
                error=None
            )
        except Exception as e:
            scan_time = time.time() - start_time
            return BinwalkResult(
                binary_path=binary_path,
                scan_time=scan_time,
                signatures_found=0,
                signatures=[],
                error=str(e)
            )

    def scan_binary(self, binary_path: str) -> BinwalkResult:
        """Scan binary with binwalk."""
        # Try CLI first if available
        if shutil.which("binwalk"):
            return self.scan_binary_cli(binary_path)
        # Fall back to library
        return self.scan_binary_library(binary_path)

    def extract_firmware(self, binary_path: str) -> Tuple[bool, str, List[str]]:
        """Extract firmware components."""
        if not shutil.which("binwalk"):
            return False, "binwalk CLI not available", []

        if not Path(binary_path).exists():
            return False, f"Binary not found: {binary_path}", []

        # Create extraction directory
        extract_dir = self.output_dir / Path(binary_path).stem / "_extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                ["binwalk", "-e", "-C", str(extract_dir), binary_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                # List extracted files
                extracted_files = []
                if extract_dir.exists():
                    for f in extract_dir.rglob("*"):
                        if f.is_file():
                            extracted_files.append(str(f.relative_to(extract_dir)))

                return True, "Extraction successful", extracted_files
            else:
                return False, result.stderr, []
        except subprocess.TimeoutExpired:
            return False, "Extraction timeout", []
        except Exception as e:
            return False, str(e), []

    def generate_report(self, results: List[BinwalkResult], output_file: Path = None) -> Path:
        """Generate binwalk analysis report."""
        output_file = output_file or self.output_dir / "binwalk_report.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Aggregate statistics
        total_scans = len(results)
        total_signatures = sum(r.signatures_found for r in results)
        total_time = sum(r.scan_time for r in results)
        avg_time = total_time / total_scans if total_scans > 0 else 0

        # Group by signature type
        by_type = {}
        for result in results:
            for sig in result.signatures:
                desc = sig.get("description", "unknown")
                if desc not in by_type:
                    by_type[desc] = 0
                by_type[desc] += 1

        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "statistics": {
                "total_scans": total_scans,
                "total_signatures": total_signatures,
                "total_time": f"{total_time:.3f}s",
                "avg_time": f"{avg_time:.3f}s",
            },
            "signature_types": by_type,
            "detailed_results": [asdict(r) for r in results if r.signatures_found > 0]
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        return output_file

    def print_summary(self, results: List[BinwalkResult]):
        """Print analysis summary."""
        print("\n" + "=" * 70)
        print("BINWALK FIRMWARE ANALYSIS SUMMARY")
        print("=" * 70)

        total_scans = len(results)
        total_signatures = sum(r.signatures_found for r in results)
        total_time = sum(r.scan_time for r in results)

        print(f"\nTotal Scans: {total_scans}")
        print(f"Total Signatures Found: {total_signatures}")
        print(f"Total Time: {total_time:.3f}s")

        if total_signatures > 0:
            print("\n📦 Firmware Components Found:")
            for result in results:
                if result.signatures_found > 0:
                    print(f"\n  {Path(result.binary_path).name}: {result.signatures_found} signature(s)")
                    for sig in result.signatures:
                        offset = sig.get("offset", "unknown")
                        desc = sig.get("description", "unknown")
                        print(f"    - {offset}: {desc}")

        print("\n" + "=" * 70)


def main():
    """Run firmware analysis."""
    import sys

    # Check if binwalk is available
    analyzer = BinwalkFirmwareAnalyzer()

    if not analyzer.binwalk_available:
        print("⚠️  binwalk not installed. Installing...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "binwalk"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            print(f"❌ Failed to install binwalk: {result.stderr}")
            # Continue anyway - will try CLI
        else:
            print("✅ binwalk installed successfully")

    # Scan binaries
    binaries_dir = Path("tests/fixtures/workspace/binaries")
    if not binaries_dir.exists():
        print(f"⚠️  Binaries directory not found: {binaries_dir}")
        sys.exit(1)

    binaries = list(binaries_dir.glob("*"))
    if not binaries:
        print("⚠️  No binaries found")
        sys.exit(1)

    print(f"📁 Scanning {len(binaries)} binaries for firmware signatures...")
    results = []
    for binary in binaries:
        if binary.is_file():
            result = analyzer.scan_binary(str(binary))
            results.append(result)
            status = "✅" if result.error is None else "⚠️"
            print(f"{status} {binary.name}: {result.signatures_found} signatures")

    # Generate report
    report_path = analyzer.generate_report(results)
    print(f"\n✅ Report saved to: {report_path}")

    # Print summary
    analyzer.print_summary(results)


if __name__ == "__main__":
    main()
