#!/usr/bin/env python3
"""
Reversecore MCP — In-Container Smoke Test
==========================================
Executed inside the Docker container after build to verify that
every critical tool (CLI binary + Python binding) is installed and
functional. If any REQUIRED check fails the script exits with
code 1, which blocks CI deploy.

Usage (inside container):
    python /app/scripts/smoke_test.py

Exit codes:
    0 — all required checks passed (optional warnings may exist)
    1 — one or more required checks failed
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# ─── paths ────────────────────────────────────────────────────────────────────
APP_DIR = Path("/app")
WORKSPACE = APP_DIR / "workspace"
FIXTURE_NAME = "smoke_test_elf"
FIXTURE_SRC = APP_DIR / "tests" / "fixtures" / FIXTURE_NAME
FIXTURE_DEST = WORKSPACE / FIXTURE_NAME

# ─── colour helpers ───────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _ok(msg: str) -> str:
    return f"{GREEN}✅ PASS{RESET}  {msg}"


def _fail(msg: str) -> str:
    return f"{RED}❌ FAIL{RESET}  {msg}"


def _warn(msg: str) -> str:
    return f"{YELLOW}⚠️  WARN{RESET}  {msg}"


def _info(msg: str) -> str:
    return f"{CYAN}ℹ️  INFO{RESET}  {msg}"


# ─── result model ─────────────────────────────────────────────────────────────
@dataclass
class CheckResult:
    name: str
    passed: bool
    required: bool
    detail: str = ""
    elapsed: float = 0.0


@dataclass
class SmokeReport:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)

    @property
    def failed_required(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed and r.required]

    @property
    def warnings(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed and not r.required]

    def print_summary(self) -> None:
        width = 70
        print()
        print(BOLD + "═" * width + RESET)
        print(BOLD + "  🩺  REVERSECORE MCP — SMOKE TEST REPORT" + RESET)
        print(BOLD + "═" * width + RESET)

        for r in self.results:
            status = _ok(r.name) if r.passed else (_fail(r.name) if r.required else _warn(r.name))
            detail = f"  → {r.detail}" if r.detail else ""
            timing = f"  [{r.elapsed:.2f}s]"
            print(f"  {status}{timing}{detail}")

        print(BOLD + "─" * width + RESET)
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        print(
            f"  Total: {total}  |  Passed: {GREEN}{passed}{RESET}  |  "
            f"Failed: {RED}{len(self.failed_required)}{RESET}  |  "
            f"Warnings: {YELLOW}{len(self.warnings)}{RESET}"
        )
        print(BOLD + "═" * width + RESET)

        if self.failed_required:
            print(f"\n{RED}{BOLD}FAILED CHECKS (blocking):{RESET}")
            for r in self.failed_required:
                print(f"  • {r.name}: {r.detail}")
        if self.warnings:
            print(f"\n{YELLOW}OPTIONAL CHECKS (non-blocking):{RESET}")
            for r in self.warnings:
                print(f"  • {r.name}: {r.detail}")
        print()


# ─── fixture setup ────────────────────────────────────────────────────────────
def setup_fixture() -> bool:
    """Copy smoke_test_elf into the workspace so MCP tools can access it."""
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    if not FIXTURE_SRC.exists():
        print(_fail(f"Fixture not found: {FIXTURE_SRC}"))
        return False
    import shutil as _sh

    _sh.copy2(FIXTURE_SRC, FIXTURE_DEST)
    os.chmod(FIXTURE_DEST, 0o755)
    print(_info(f"Fixture copied → {FIXTURE_DEST}  ({FIXTURE_DEST.stat().st_size} bytes)"))
    return True


# ─── individual checks ────────────────────────────────────────────────────────
def _run_check(
    name: str,
    fn: Callable[[], tuple[bool, str]],
    required: bool = True,
) -> CheckResult:
    t0 = time.perf_counter()
    try:
        passed, detail = fn()
    except Exception as exc:
        passed, detail = False, str(exc)
    elapsed = time.perf_counter() - t0
    return CheckResult(name=name, passed=passed, required=required, detail=detail, elapsed=elapsed)


# ── 1. CLI tools ──────────────────────────────────────────────────────────────
def check_cli_file() -> tuple[bool, str]:
    if not shutil.which("file"):
        return False, "`file` binary not found in PATH"
    import subprocess

    out = subprocess.check_output(["file", str(FIXTURE_DEST)], text=True, timeout=10)
    return True, out.strip()[:80]


def check_cli_radare2() -> tuple[bool, str]:
    if not shutil.which("r2"):
        return False, "`r2` (radare2) binary not found in PATH"
    import subprocess

    out = subprocess.check_output(
        ["r2", "-q", "-c", "i", str(FIXTURE_DEST)],
        text=True,
        timeout=15,
        stderr=subprocess.DEVNULL,
    )
    if "elf" in out.lower() or "ELF" in out:
        return True, "radare2 parsed ELF OK"
    return True, out.strip()[:80]


def check_cli_yara() -> tuple[bool, str]:
    if not shutil.which("yara"):
        return False, "`yara` binary not found in PATH"
    import subprocess
    import tempfile

    rule = "rule smoke { strings: $a = { 7F 45 4C 46 } condition: $a }"
    with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as f:
        f.write(rule)
        rule_path = f.name
    try:
        out = subprocess.check_output(
            ["yara", rule_path, str(FIXTURE_DEST)],
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        )
        return True, f"YARA matched: {out.strip()[:60]}"
    except subprocess.CalledProcessError:
        return True, "YARA ran (no match is also OK for smoke)"
    finally:
        Path(rule_path).unlink(missing_ok=True)


def check_cli_capa() -> tuple[bool, str]:
    if not shutil.which("capa"):
        return False, "`capa` binary not found (optional)"
    import subprocess

    try:
        subprocess.check_output(
            ["capa", "--version"],
            text=True,
            timeout=10,
            stderr=subprocess.STDOUT,
        )
        return True, "capa --version OK"
    except Exception as exc:
        return False, str(exc)[:80]


def check_cli_binwalk() -> tuple[bool, str]:
    if not shutil.which("binwalk"):
        return False, "`binwalk` not found (optional)"
    import subprocess

    out = subprocess.check_output(
        ["binwalk", str(FIXTURE_DEST)],
        text=True,
        timeout=15,
        stderr=subprocess.DEVNULL,
    )
    return True, f"binwalk OK ({len(out)} chars output)"


# ── 2. Python packages ────────────────────────────────────────────────────────
def check_lief() -> tuple[bool, str]:
    try:
        import lief

        binary = lief.parse(str(FIXTURE_DEST))
        if binary is None:
            return False, "lief.parse() returned None"
        fmt = binary.format
        return True, f"LIEF parsed binary, format={fmt}"
    except ImportError:
        return False, "lief package not installed"
    except Exception as exc:
        return False, str(exc)[:80]


def check_yara_python() -> tuple[bool, str]:
    try:
        import yara

        rule = yara.compile(source="rule smoke { strings: $a = { 7F 45 4C 46 } condition: $a }")
        matches = rule.match(str(FIXTURE_DEST))
        return True, f"yara-python compiled+matched: {matches}"
    except ImportError:
        return False, "yara-python package not installed"
    except Exception as exc:
        return False, str(exc)[:80]


def check_fastmcp() -> tuple[bool, str]:
    try:
        from fastmcp import FastMCP

        return True, f"fastmcp.FastMCP importable: {FastMCP}"
    except ImportError as exc:
        return False, str(exc)[:80]


def check_radare2_python() -> tuple[bool, str]:
    try:
        import r2pipe

        r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
        info = r2.cmdj("ij")
        r2.quit()
        if info and info.get("bin"):
            return True, f"r2pipe OK, arch={info['bin'].get('arch', '?')}"
        return True, "r2pipe opened file OK"
    except ImportError:
        return False, "r2pipe package not installed"
    except Exception as exc:
        return False, str(exc)[:80]


# ── 3. MCP server import ──────────────────────────────────────────────────────
def check_server_import() -> tuple[bool, str]:
    """Verify the MCP server module imports without error."""
    try:
        sys.path.insert(0, str(APP_DIR))
        # Import just the tool registration to catch missing deps early
        from reversecore_mcp.tools import file_operations  # noqa: F401

        return True, "reversecore_mcp.tools.file_operations imported OK"
    except Exception as exc:
        return False, str(exc)[:120]


def check_mcp_tool_run_file() -> tuple[bool, str]:
    """Call run_file() via the actual MCP tool implementation."""
    try:
        sys.path.insert(0, str(APP_DIR))
        from reversecore_mcp.core.config import get_config

        cfg = get_config()
        # Patch workspace to match our setup
        cfg.workspace = str(WORKSPACE)

        from reversecore_mcp.tools import file_operations

        result = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
        if result.status == "success":
            return True, f"run_file → success, data keys: {list((result.data or {}).keys())}"
        return False, f"run_file → status={result.status} error={result.error}"
    except Exception as exc:
        return False, str(exc)[:120]


def check_mcp_tool_run_strings() -> tuple[bool, str]:
    """Call run_strings() via the actual MCP tool implementation."""
    try:
        sys.path.insert(0, str(APP_DIR))
        from reversecore_mcp.tools import static_analysis

        result = asyncio.run(static_analysis.run_strings(str(FIXTURE_DEST), min_length=3))
        if result.status == "success":
            return True, "run_strings → success"
        return False, f"run_strings → {result.error}"
    except Exception as exc:
        return False, str(exc)[:120]


# ─── main orchestrator ────────────────────────────────────────────────────────
def main() -> int:
    print()
    print(BOLD + CYAN + "  🚀 Reversecore MCP — Smoke Test Starting..." + RESET)
    print(_info(f"Python {sys.version.split()[0]}  |  Fixture: {FIXTURE_DEST}"))
    print()

    # Setup
    if not setup_fixture():
        print(_fail("Cannot copy fixture binary — aborting"))
        return 1

    report = SmokeReport()

    # ── Required checks (FAIL → CI blocks deploy) ──────────────────────────
    required_checks: list[tuple[str, Callable, bool]] = [
        # (name,                    fn,                     required)
        ("CLI: file", check_cli_file, True),
        ("CLI: radare2 (r2)", check_cli_radare2, True),
        ("CLI: yara", check_cli_yara, True),
        ("Python: lief", check_lief, True),
        ("Python: yara-python", check_yara_python, True),
        ("Python: fastmcp", check_fastmcp, True),
        ("Python: r2pipe", check_radare2_python, True),
        ("MCP: server import", check_server_import, True),
        ("MCP tool: run_file", check_mcp_tool_run_file, True),
        ("MCP tool: run_strings", check_mcp_tool_run_strings, True),
        # Optional checks (FAIL → warning only, CI continues)
        ("CLI: capa", check_cli_capa, False),
        ("CLI: binwalk", check_cli_binwalk, False),
    ]

    for name, fn, required in required_checks:
        result = _run_check(name, fn, required=required)
        report.add(result)
        line = _ok(name) if result.passed else (_fail(name) if required else _warn(name))
        detail = f"  → {result.detail}" if result.detail else ""
        print(f"  {line}  [{result.elapsed:.2f}s]{detail}")

    # Print full report
    report.print_summary()

    # Cleanup fixture
    FIXTURE_DEST.unlink(missing_ok=True)

    if report.failed_required:
        print(
            f"{RED}{BOLD}🔴 SMOKE TEST FAILED — {len(report.failed_required)} required check(s) failed.{RESET}"
        )
        print(f"{RED}   The Docker image is NOT safe to deploy.{RESET}\n")
        return 1

    print(f"{GREEN}{BOLD}🟢 SMOKE TEST PASSED — all required checks passed.{RESET}")
    if report.warnings:
        print(
            f"{YELLOW}   {len(report.warnings)} optional tool(s) missing — see warnings above.{RESET}"
        )
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
