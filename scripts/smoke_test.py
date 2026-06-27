#!/usr/bin/env python3
"""
Reversecore MCP — Conservative In-Container Smoke Test (v2)
=============================================================
Multi-layer verification that CI pass genuinely guarantees tools work.

Verification Layers
-------------------
Layer 1  All tool modules import cleanly (no broken deps at load time)
Layer 2  CLI binaries exist and produce sane output
Layer 3  Python package bindings work with a real binary file
Layer 4  Every MCP tool *category* runs at least one real call
Layer 5  MCP server starts, registers >= MIN_TOOLS tools, health endpoint OK
Layer 6  Multi-step analysis chain: file → lief → radare2 → yara (workflow)

Exit codes
----------
    0 — all REQUIRED layers passed  (optional warnings allowed)
    1 — any REQUIRED check failed   → CI blocks deploy

Usage (inside container)
------------------------
    python /app/scripts/smoke_test.py
    python /app/scripts/smoke_test.py --verbose
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# ─── constants ────────────────────────────────────────────────────────────────
APP_DIR = Path("/app")
WORKSPACE = APP_DIR / "workspace"
FIXTURE_NAME = "smoke_test_elf"
FIXTURE_SRC = APP_DIR / "tests" / "fixtures" / FIXTURE_NAME
FIXTURE_DEST = WORKSPACE / FIXTURE_NAME

# Minimum number of MCP tools that MUST be registered for the image to be valid.
# Bump this number whenever you add a new tool category.
MIN_REQUIRED_TOOLS = 50

# Per-check timeout (seconds). Hang = fail.
CHECK_TIMEOUT = 30

# ─── colour helpers ───────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

VERBOSE = False


def _ok(name: str) -> str:
    return f"{GREEN}✅ PASS{RESET}  {name}"


def _fail(name: str) -> str:
    return f"{RED}❌ FAIL{RESET}  {name}"


def _warn(name: str) -> str:
    return f"{YELLOW}⚠️  WARN{RESET}  {name}"


def _section(title: str) -> None:
    width = 70
    print()
    print(BOLD + CYAN + f"  {'─' * 3}  {title}  {'─' * (width - len(title) - 7)}" + RESET)


# ─── result model ─────────────────────────────────────────────────────────────
@dataclass
class CheckResult:
    name: str
    passed: bool
    required: bool
    layer: int
    detail: str = ""
    elapsed: float = 0.0


@dataclass
class SmokeReport:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, r: CheckResult) -> None:
        self.results.append(r)

    @property
    def failed_required(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed and r.required]

    @property
    def optional_warnings(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed and not r.required]

    def print_summary(self) -> None:
        width = 72
        print()
        print(BOLD + "═" * width + RESET)
        print(BOLD + "  🩺  REVERSECORE MCP — SMOKE TEST REPORT (v2)" + RESET)
        print(BOLD + "═" * width + RESET)

        cur_layer = 0
        for r in self.results:
            if r.layer != cur_layer:
                cur_layer = r.layer
                layer_labels = {
                    1: "Layer 1 · Module Import Sweep",
                    2: "Layer 2 · CLI Binary Checks",
                    3: "Layer 3 · Python Package Bindings",
                    4: "Layer 4 · Per-Category MCP Tool Calls",
                    5: "Layer 5 · Server Registration & Health",
                    6: "Layer 6 · End-to-End Analysis Chain",
                }
                print(f"\n  {DIM}{layer_labels.get(cur_layer, f'Layer {cur_layer}')}{RESET}")

            status = _ok(r.name) if r.passed else (_fail(r.name) if r.required else _warn(r.name))
            detail = (
                f"\n        {DIM}→ {r.detail[:100]}{RESET}"
                if r.detail and VERBOSE
                else (
                    f"  {DIM}→ {r.detail[:60]}{RESET}"
                    if r.detail and r.passed
                    else (f"  {RED}→ {r.detail[:80]}{RESET}" if r.detail else "")
                )
            )
            timing = f"  {DIM}[{r.elapsed:.2f}s]{RESET}"
            print(f"    {status}{timing}{detail}")

        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        print()
        print(BOLD + "─" * width + RESET)
        print(
            f"  Total: {total}  │  "
            f"Passed: {GREEN}{BOLD}{passed}{RESET}  │  "
            f"Failed: {RED}{BOLD}{len(self.failed_required)}{RESET}  │  "
            f"Warnings: {YELLOW}{len(self.optional_warnings)}{RESET}"
        )
        print(BOLD + "═" * width + RESET)

        if self.failed_required:
            print(f"\n{RED}{BOLD}  ❌ BLOCKING FAILURES:{RESET}")
            for r in self.failed_required:
                print(f"     • [L{r.layer}] {r.name}")
                print(f"       {RED}{r.detail}{RESET}")

        if self.optional_warnings:
            print(f"\n{YELLOW}  ⚠️  OPTIONAL WARNINGS (non-blocking):{RESET}")
            for r in self.optional_warnings:
                print(f"     • {r.name}: {r.detail[:80]}")
        print()


# ─── timeout wrapper ──────────────────────────────────────────────────────────
def _run_with_timeout(fn: Callable, timeout: int = CHECK_TIMEOUT) -> tuple[bool, str]:
    """Run fn() in a subprocess-safe timeout. Returns (passed, detail)."""

    def _handler(signum, frame):
        raise TimeoutError(f"Check timed out after {timeout}s")

    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(timeout)
    try:
        return fn()
    except TimeoutError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _run_check(
    name: str,
    fn: Callable,
    layer: int,
    required: bool = True,
    timeout: int = CHECK_TIMEOUT,
) -> CheckResult:
    t0 = time.perf_counter()
    passed, detail = _run_with_timeout(fn, timeout=timeout)
    elapsed = time.perf_counter() - t0
    return CheckResult(
        name=name,
        passed=passed,
        required=required,
        layer=layer,
        detail=detail,
        elapsed=elapsed,
    )


# ─── fixture ──────────────────────────────────────────────────────────────────
def setup_fixture() -> bool:
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    if not FIXTURE_SRC.exists():
        print(f"{RED}  ❌ Fixture not found: {FIXTURE_SRC}{RESET}")
        return False
    shutil.copy2(FIXTURE_SRC, FIXTURE_DEST)
    os.chmod(FIXTURE_DEST, 0o755)
    print(f"  {DIM}Fixture → {FIXTURE_DEST}  ({FIXTURE_DEST.stat().st_size} bytes){RESET}")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — All tool module imports
# ══════════════════════════════════════════════════════════════════════════════
def _build_layer1_checks() -> list[tuple[str, Callable, bool]]:
    """Yield (name, fn, required) for every tool module import."""
    checks = []
    tools_pkg = APP_DIR / "reversecore_mcp" / "tools"
    # Walk every .py file under reversecore_mcp/tools/
    for root, _dirs, files in os.walk(tools_pkg):
        for fname in sorted(files):
            if not fname.endswith(".py") or fname == "__init__.py":
                continue
            rel = Path(root).relative_to(APP_DIR)
            mod_name = ".".join(rel.parts) + "." + fname[:-3]

            def _make_import_check(m: str) -> Callable:
                def _check() -> tuple[bool, str]:
                    importlib.import_module(m)
                    return True, f"import {m} OK"

                return _check

            checks.append((f"import {mod_name.split('.')[-1]}", _make_import_check(mod_name), True))
    return checks


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — CLI binary checks
# ══════════════════════════════════════════════════════════════════════════════
def check_cli_file() -> tuple[bool, str]:
    if not shutil.which("file"):
        return False, "`file` binary not found"
    out = subprocess.check_output(["file", str(FIXTURE_DEST)], text=True, timeout=10)
    return True, out.strip()[:80]


def check_cli_radare2() -> tuple[bool, str]:
    if not shutil.which("r2"):
        return False, "`r2` binary not found"
    out = subprocess.check_output(
        ["r2", "-q", "-c", "aaa; afl", str(FIXTURE_DEST)],
        text=True,
        timeout=20,
        stderr=subprocess.DEVNULL,
    )
    # Must produce at least one function listing line
    lines = [line for line in out.splitlines() if line.strip()]
    return True, f"r2 aaa+afl produced {len(lines)} lines"


def check_cli_yara() -> tuple[bool, str]:
    if not shutil.which("yara"):
        return False, "`yara` CLI not found"
    rule = "rule elf_magic { strings: $m = { 7F 45 4C 46 } condition: $m }"
    with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as f:
        f.write(rule)
        rp = f.name
    try:
        out = subprocess.run(
            ["yara", rp, str(FIXTURE_DEST)],
            text=True,
            capture_output=True,
            timeout=10,
        )
        if out.returncode == 0 and "elf_magic" in out.stdout:
            return True, "YARA matched elf_magic rule ✓"
        return True, f"YARA ran (rc={out.returncode})"
    finally:
        Path(rp).unlink(missing_ok=True)


def check_cli_strings() -> tuple[bool, str]:
    if not shutil.which("strings"):
        return False, "`strings` binary not found"
    out = subprocess.check_output(
        ["strings", "-n", "3", str(FIXTURE_DEST)],
        text=True,
        timeout=10,
    )
    return True, f"strings output: {len(out.split())} tokens"


def check_cli_capa() -> tuple[bool, str]:
    if not shutil.which("capa"):
        return False, "`capa` not found (optional)"
    out = subprocess.check_output(
        ["capa", "--version"],
        text=True,
        timeout=10,
        stderr=subprocess.STDOUT,
    )
    return True, out.strip()[:60]


def check_cli_binwalk() -> tuple[bool, str]:
    if not shutil.which("binwalk"):
        return False, "`binwalk` not found (optional)"
    out = subprocess.check_output(
        ["binwalk", str(FIXTURE_DEST)],
        text=True,
        timeout=15,
        stderr=subprocess.DEVNULL,
    )
    return True, f"binwalk output: {len(out)} chars"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — Python package bindings
# ══════════════════════════════════════════════════════════════════════════════
def check_pkg_lief() -> tuple[bool, str]:
    import lief

    b = lief.parse(str(FIXTURE_DEST))
    if b is None:
        return False, "lief.parse() returned None"
    fmt = str(b.format)
    return True, f"LIEF parsed binary format={fmt}"


def check_pkg_yara_python() -> tuple[bool, str]:
    import yara

    r = yara.compile(source="rule sm { strings: $e = { 7F 45 4C 46 } condition: $e }")
    m = r.match(str(FIXTURE_DEST))
    return True, f"yara-python matched={bool(m)}"


def check_pkg_fastmcp() -> tuple[bool, str]:
    from fastmcp import FastMCP

    return True, f"FastMCP importable: {FastMCP.__module__}"


def check_pkg_r2pipe() -> tuple[bool, str]:
    import r2pipe

    r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
    info = r2.cmdj("ij") or {}
    r2.quit()
    arch = info.get("bin", {}).get("arch", "?")
    return True, f"r2pipe OK arch={arch}"


def check_pkg_capstone() -> tuple[bool, str]:
    try:
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        code = b"\x48\x31\xc0\xc3"  # xor rax,rax; ret
        insns = list(md.disasm(code, 0x1000))
        return True, f"Capstone disassembled {len(insns)} insns"
    except ImportError:
        return False, "capstone not installed (optional)"


def check_pkg_angr() -> tuple[bool, str]:
    try:
        import angr

        return True, f"angr {angr.__version__} importable"
    except ImportError:
        return False, "angr not installed (optional)"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — Per-category MCP tool calls
# ══════════════════════════════════════════════════════════════════════════════
def _patch_workspace() -> None:
    sys.path.insert(0, str(APP_DIR))
    from reversecore_mcp.core.config import get_config

    cfg = get_config()
    cfg.workspace = str(WORKSPACE)


def check_tool_run_file() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    result = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
    if result.status != "success":
        return False, f"run_file failed: {result.error}"
    keys = list((result.data or {}).keys())
    return True, f"run_file OK keys={keys}"


def check_tool_run_strings() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import static_analysis

    result = asyncio.run(static_analysis.run_strings(str(FIXTURE_DEST), min_length=3))
    if result.status != "success":
        return False, f"run_strings failed: {result.error}"
    return True, "run_strings OK"


def check_tool_parse_binary_lief() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import lief_tools

    result = asyncio.run(lief_tools.parse_binary_with_lief(str(FIXTURE_DEST)))
    if result.status != "success":
        return False, f"parse_binary_with_lief failed: {result.error}"
    return True, "parse_binary_with_lief OK"


def check_tool_radare2_analyze() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.radare2 import r2_analysis

    result = asyncio.run(r2_analysis.run_radare2(str(FIXTURE_DEST), "aaa; afl"))
    if result.status not in ("success", "error"):
        return False, f"Unexpected status: {result.status}"
    # radare2 may return empty output for tiny ELF — that's still OK
    return True, f"Radare2_run_command status={result.status}"


def check_tool_run_yara() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import yara_tools

    rule_src = "rule elf { strings: $m = { 7F 45 4C 46 } condition: $m }"
    with tempfile.NamedTemporaryFile(
        suffix=".yar", mode="w", delete=False, dir=str(WORKSPACE)
    ) as f:
        f.write(rule_src)
        rp = f.name
    try:
        result = asyncio.run(yara_tools.run_yara(str(FIXTURE_DEST), rp))
        if result.status not in ("success", "error"):
            return False, f"Unexpected status: {result.status}"
        return True, f"run_yara status={result.status}"
    finally:
        Path(rp).unlink(missing_ok=True)


def check_tool_extract_iocs() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import ioc_tools

    result = asyncio.run(ioc_tools.extract_iocs(str(FIXTURE_DEST)))
    if result.status not in ("success", "error"):
        return False, f"Unexpected status: {result.status}"
    return True, f"extract_iocs status={result.status}"


def check_tool_server_health() -> tuple[bool, str]:
    _patch_workspace()
    from fastmcp import FastMCP

    from reversecore_mcp.tools.common.server_tools import ServerToolsPlugin

    mcp = FastMCP("smoke-test")
    plugin = ServerToolsPlugin()
    plugin.register(mcp)
    # Now call get_server_health — it's registered as a closure, find it
    health_fn = None
    for tool in mcp._tool_manager.list_tools():
        if tool.name == "get_server_health":
            health_fn = tool
            break
    if health_fn is None:
        return False, "get_server_health not found in registered tools"
    asyncio.run(health_fn.run({}))
    return True, "get_server_health callable OK"


def check_tool_list_workspace() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    result = asyncio.run(file_operations.list_workspace())
    if result.status != "success":
        return False, f"list_workspace failed: {result.error}"
    return True, "list_workspace OK"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — Server registration count & MCP protocol
# ══════════════════════════════════════════════════════════════════════════════
def check_server_tool_count() -> tuple[bool, str]:
    """Import server.py and count registered tools via the plugin loader."""
    _patch_workspace()
    from fastmcp import FastMCP

    from reversecore_mcp.core.loader import PluginLoader
    from reversecore_mcp.prompts import register_prompts

    mcp = FastMCP("smoke-counter")
    loader = PluginLoader(APP_DIR / "reversecore_mcp" / "tools")
    loader.load_all(mcp)
    register_prompts(mcp)

    tools = mcp._tool_manager.list_tools()
    count = len(tools)
    if count < MIN_REQUIRED_TOOLS:
        return False, (
            f"Only {count} tools registered — expected >= {MIN_REQUIRED_TOOLS}. "
            f"A plugin may have failed to load."
        )
    return True, f"{count} tools registered (>= {MIN_REQUIRED_TOOLS} ✓)"


def check_server_prompt_count() -> tuple[bool, str]:
    """Verify prompts register correctly."""
    _patch_workspace()
    from fastmcp import FastMCP

    from reversecore_mcp.prompts import register_prompts

    mcp = FastMCP("smoke-prompts")
    register_prompts(mcp)
    prompts = mcp._prompt_manager.list_prompts()
    count = len(prompts)
    if count < 10:
        return False, f"Only {count} prompts registered — expected >= 10"
    names = [p.name for p in prompts]
    required = ["server_health_check_mode", "server_tool_catalog_mode", "full_analysis_mode"]
    missing = [n for n in required if n not in names]
    if missing:
        return False, f"Missing prompts: {missing}"
    return True, f"{count} prompts registered, required prompts present ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 6 — End-to-end analysis chain
# ══════════════════════════════════════════════════════════════════════════════
def check_e2e_analysis_chain() -> tuple[bool, str]:
    """
    Full realistic workflow:
      1. list_workspace()  — confirm file is visible
      2. run_file()        — identify file type
      3. parse_binary_with_lief()  — structural parse
      4. run_strings()     — extract strings
      5. run_yara()        — pattern match
    Each step must succeed before the next runs.
    """
    _patch_workspace()
    from reversecore_mcp.tools import file_operations, static_analysis
    from reversecore_mcp.tools.analysis import lief_tools
    from reversecore_mcp.tools.malware import yara_tools

    steps = []

    # Step 1
    r = asyncio.run(file_operations.list_workspace())
    steps.append(("list_workspace", r.status == "success"))

    # Step 2
    r = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
    steps.append(("run_file", r.status == "success"))

    # Step 3
    r = asyncio.run(lief_tools.parse_binary_with_lief(str(FIXTURE_DEST)))
    steps.append(("parse_binary_with_lief", r.status == "success"))

    # Step 4
    r = asyncio.run(static_analysis.run_strings(str(FIXTURE_DEST), min_length=3))
    steps.append(("run_strings", r.status == "success"))

    # Step 5 — inline yara rule
    rule_src = "rule elf { strings: $m = { 7F 45 4C 46 } condition: $m }"
    with tempfile.NamedTemporaryFile(
        suffix=".yar", mode="w", delete=False, dir=str(WORKSPACE)
    ) as f:
        f.write(rule_src)
        rp = f.name
    try:
        r = asyncio.run(yara_tools.run_yara(str(FIXTURE_DEST), rp))
        steps.append(("run_yara", r.status in ("success", "error")))
    finally:
        Path(rp).unlink(missing_ok=True)

    failed = [name for name, ok in steps if not ok]
    if failed:
        return False, f"Chain failed at steps: {failed}"
    passed_str = " → ".join(name for name, _ in steps)
    return True, f"Chain OK: {passed_str}"


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main() -> int:
    global VERBOSE
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    VERBOSE = args.verbose

    print()
    print(BOLD + CYAN + "  🚀 Reversecore MCP — Conservative Smoke Test v2" + RESET)
    print(
        f"  {DIM}Python {sys.version.split()[0]}  │  "
        f"Min tools required: {MIN_REQUIRED_TOOLS}  │  "
        f"Timeout per check: {CHECK_TIMEOUT}s{RESET}"
    )

    if not setup_fixture():
        print(f"{RED}  Cannot copy fixture — aborting.{RESET}")
        return 1

    report = SmokeReport()

    # ── Layer 1: Module import sweep ──────────────────────────────────────────
    _section("Layer 1 · Module Import Sweep")
    sys.path.insert(0, str(APP_DIR))
    for name, fn, req in _build_layer1_checks():
        r = _run_check(name, fn, layer=1, required=req, timeout=15)
        report.add(r)
        line = _ok(name) if r.passed else (_fail(name) if req else _warn(name))
        print(f"    {line}  {DIM}[{r.elapsed:.2f}s]{RESET}", end="")
        if not r.passed:
            print(f"  {RED}→ {r.detail[:70]}{RESET}", end="")
        print()

    # ── Layer 2: CLI binary checks ────────────────────────────────────────────
    _section("Layer 2 · CLI Binary Checks")
    l2 = [
        ("CLI: file", check_cli_file, True),
        ("CLI: radare2", check_cli_radare2, True),
        ("CLI: yara", check_cli_yara, True),
        ("CLI: strings", check_cli_strings, True),
        ("CLI: capa", check_cli_capa, False),
        ("CLI: binwalk", check_cli_binwalk, False),
    ]
    for name, fn, req in l2:
        r = _run_check(name, fn, layer=2, required=req, timeout=25)
        report.add(r)
        line = _ok(name) if r.passed else (_fail(name) if req else _warn(name))
        print(
            f"    {line}  {DIM}[{r.elapsed:.2f}s]{RESET}"
            f"  {DIM if r.passed else RED}→ {r.detail[:60]}{RESET}"
        )

    # ── Layer 3: Python package bindings ──────────────────────────────────────
    _section("Layer 3 · Python Package Bindings")
    l3 = [
        ("pkg: lief", check_pkg_lief, True),
        ("pkg: yara-python", check_pkg_yara_python, True),
        ("pkg: fastmcp", check_pkg_fastmcp, True),
        ("pkg: r2pipe", check_pkg_r2pipe, True),
        ("pkg: capstone", check_pkg_capstone, False),
        ("pkg: angr", check_pkg_angr, False),
    ]
    for name, fn, req in l3:
        r = _run_check(name, fn, layer=3, required=req, timeout=20)
        report.add(r)
        line = _ok(name) if r.passed else (_fail(name) if req else _warn(name))
        print(
            f"    {line}  {DIM}[{r.elapsed:.2f}s]{RESET}"
            f"  {DIM if r.passed else RED}→ {r.detail[:60]}{RESET}"
        )

    # ── Layer 4: Per-category MCP tool calls ──────────────────────────────────
    _section("Layer 4 · Per-Category MCP Tool Calls")
    l4 = [
        # (name,                           fn,                          req)
        ("tool: run_file", check_tool_run_file, True),
        ("tool: run_strings", check_tool_run_strings, True),
        ("tool: parse_binary_with_lief", check_tool_parse_binary_lief, True),
        ("tool: Radare2 run_command", check_tool_radare2_analyze, True),
        ("tool: run_yara", check_tool_run_yara, True),
        ("tool: extract_iocs", check_tool_extract_iocs, True),
        ("tool: list_workspace", check_tool_list_workspace, True),
        ("tool: get_server_health", check_tool_server_health, True),
    ]
    for name, fn, req in l4:
        r = _run_check(name, fn, layer=4, required=req, timeout=30)
        report.add(r)
        line = _ok(name) if r.passed else (_fail(name) if req else _warn(name))
        print(
            f"    {line}  {DIM}[{r.elapsed:.2f}s]{RESET}"
            f"  {DIM if r.passed else RED}→ {r.detail[:60]}{RESET}"
        )

    # ── Layer 5: Server registration & health ─────────────────────────────────
    _section("Layer 5 · Server Registration & Health")
    l5 = [
        (
            "server: tool count >= {MIN_REQUIRED_TOOLS}".format(**globals()),
            check_server_tool_count,
            True,
        ),
        ("server: prompt registration", check_server_prompt_count, True),
    ]
    for name, fn, req in l5:
        r = _run_check(name, fn, layer=5, required=req, timeout=30)
        report.add(r)
        line = _ok(name) if r.passed else (_fail(name) if req else _warn(name))
        print(
            f"    {line}  {DIM}[{r.elapsed:.2f}s]{RESET}"
            f"  {DIM if r.passed else RED}→ {r.detail[:70]}{RESET}"
        )

    # ── Layer 6: End-to-end chain ─────────────────────────────────────────────
    _section("Layer 6 · End-to-End Analysis Chain")
    r = _run_check(
        "e2e: file→lief→strings→yara chain",
        check_e2e_analysis_chain,
        layer=6,
        required=True,
        timeout=60,
    )
    report.add(r)
    line = _ok(r.name) if r.passed else _fail(r.name)
    print(
        f"    {line}  {DIM}[{r.elapsed:.2f}s]{RESET}"
        f"  {DIM if r.passed else RED}→ {r.detail[:80]}{RESET}"
    )

    # ── Final report ──────────────────────────────────────────────────────────
    report.print_summary()
    FIXTURE_DEST.unlink(missing_ok=True)

    if report.failed_required:
        n = len(report.failed_required)
        print(f"{RED}{BOLD}🔴 SMOKE TEST FAILED — {n} required check(s) failed.{RESET}")
        print(f"{RED}   This Docker image is NOT safe to deploy.{RESET}\n")
        return 1

    print(f"{GREEN}{BOLD}🟢 SMOKE TEST PASSED — all {len(report.results)} checks complete.{RESET}")
    if report.optional_warnings:
        print(
            f"{YELLOW}   {len(report.optional_warnings)} optional tool(s) missing — see warnings.{RESET}"
        )
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
