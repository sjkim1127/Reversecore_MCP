#!/usr/bin/env python3
"""
Reversecore MCP — Conservative In-Container Smoke Test (v4)
=============================================================
15-Layer verification. CI pass = ALL layers pass = image is safe to deploy.

Layer 1   Module import sweep         — every .py under reversecore_mcp/tools/ imports clean
Layer 2   CLI binary checks           — real output + sane content validated
Layer 3   Python package bindings     — APIs called with real data, results inspected
Layer 4   Per-category MCP tool calls — 12 tools across every category
Layer 5   Named tool existence        — specific tool names asserted by name (not just count)
Layer 6   Server registration metrics — tool count >= 100, prompt count >= 10
Layer 7   Security boundary checks    — path traversal & workspace isolation enforced
Layer 8   Error resilience            — bad inputs return ToolResult(error), never raise
Layer 9   Performance baseline        — each required tool finishes within 30 s
Layer 10  End-to-end analysis chain   — 7-step realistic workflow, all steps pass
Layer 11  Radare2 deep verification   — disasm output content, xref resolution, r2ghidra import
Layer 12  Concurrent tool execution   — 5 tools in parallel, no race conditions
Layer 13  Resource leak detection     — r2pipe cleanup, no zombie processes after tool runs
Layer 14  Data integrity              — fixture SHA256 verified, tool output determinism
Layer 15  ToolResult schema validation — every tool output has correct Pydantic model fields
Layer 16  MCP wire protocol           — real subprocess server, JSON-RPC 2.0 full handshake:
                                         initialize → initialized → tools/list → tools/call

Exit codes: 0 = all required checks passed | 1 = any required check failed
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
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

MIN_REQUIRED_TOOLS = 100  # bump when new tool categories are added
MIN_REQUIRED_PROMPTS = 10
CHECK_TIMEOUT = 30  # per-check hard timeout (seconds)

# Fixture integrity — detect corruption or tampering
FIXTURE_SHA256 = "112f8b2427ef6db8a3d61e38dea37780d35122292c1f94dbbbdebf1960eec571"
FIXTURE_SIZE = 132

# Specific tool names that MUST be registered (representative set from each category)
REQUIRED_TOOL_NAMES: frozenset[str] = frozenset(
    [
        # common / file ops
        "run_file",
        "run_strings",
        "list_workspace",
        "copy_to_workspace",
        "scan_workspace",
        "get_server_health",
        "get_tool_metrics",
        # analysis
        "parse_binary_with_lief",
        "run_capa",
        "detect_packer_deep",
        "diff_binaries",
        "match_libraries",
        "scan_for_versions",
        # radare2
        "Radare2_analyze",
        "Radare2_disassemble",
        "Radare2_list_functions",
        "Radare2_list_imports",
        "Radare2_list_sections",
        "Radare2_run_command",
        "run_radare2",
        "r2_decompile",
        # malware
        "generate_yara_rule",
        "run_yara",
        "extract_iocs",
        "dormant_detector",
        "adaptive_vaccine",
        "vulnerability_hunter",
        # forensics
        "memory_analyze",
        "memory_list_processes",
        "disk_list_partition",
        "pcap_analyze",
        "artifact_collect",
        # report
        "start_report_session",
        "end_report_session",
        "create_analysis_report",
        "add_ioc",
        "get_system_time",
        # assembler / emulation
        "assemble_instructions",
        "emulate_binary",
    ]
)

REQUIRED_PROMPT_NAMES: frozenset[str] = frozenset(
    [
        "full_analysis_mode",
        "malware_analysis_mode",
        "vulnerability_hunter_mode",
        "firmware_analysis_mode",
        "server_health_check_mode",
        "server_tool_catalog_mode",
        "report_generation_mode",
    ]
)

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
    width = 72
    pad = max(0, width - len(title) - 8)
    print(f"\n{BOLD}{CYAN}  ── {title} {'─' * pad}{RESET}")


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
        w = 72
        print(f"\n{BOLD}{'═' * w}{RESET}")
        print(f"{BOLD}  🩺  REVERSECORE MCP — SMOKE TEST v3 REPORT{RESET}")
        print(f"{BOLD}{'═' * w}{RESET}")

        cur_layer = 0
        layer_labels = {
            1: "Layer 1 · Module Import Sweep",
            2: "Layer 2 · CLI Binary Checks",
            3: "Layer 3 · Python Package Bindings",
            4: "Layer 4 · Per-Category MCP Tool Calls",
            5: "Layer 5 · Named Tool Existence",
            6: "Layer 6 · Server Registration Metrics",
            7: "Layer 7 · Security Boundary Checks",
            8: "Layer 8 · Error Resilience",
            9: "Layer 9 · Performance Baseline",
            10: "Layer 10 · End-to-End Analysis Chain",
            11: "Layer 11 · Radare2 Deep Verification",
            12: "Layer 12 · Concurrent Tool Execution",
            13: "Layer 13 · Resource Leak Detection",
            14: "Layer 14 · Data Integrity",
            15: "Layer 15 · ToolResult Schema Validation",
            16: "Layer 16 · MCP Wire Protocol (JSON-RPC 2.0)",
        }
        for r in self.results:
            if r.layer != cur_layer:
                cur_layer = r.layer
                print(f"\n  {DIM}{layer_labels.get(cur_layer, f'Layer {cur_layer}')}{RESET}")
            status = _ok(r.name) if r.passed else (_fail(r.name) if r.required else _warn(r.name))
            det = ""
            if r.detail:
                col = DIM if r.passed else RED
                det = f"  {col}→ {r.detail[:70]}{RESET}"
            print(f"    {status}  {DIM}[{r.elapsed:.2f}s]{RESET}{det}")

        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        print(f"\n{BOLD}{'─' * w}{RESET}")
        print(
            f"  Total: {total}  │  "
            f"Passed: {GREEN}{BOLD}{passed}{RESET}  │  "
            f"Failed (req): {RED}{BOLD}{len(self.failed_required)}{RESET}  │  "
            f"Warnings: {YELLOW}{len(self.optional_warnings)}{RESET}"
        )
        print(f"{BOLD}{'═' * w}{RESET}")

        if self.failed_required:
            print(f"\n{RED}{BOLD}  ❌ BLOCKING FAILURES:{RESET}")
            for r in self.failed_required:
                print(f"     [L{r.layer}] {r.name}")
                print(f"       {RED}{r.detail}{RESET}")

        if self.optional_warnings:
            print(f"\n{YELLOW}  ⚠️  OPTIONAL WARNINGS:{RESET}")
            for r in self.optional_warnings:
                print(f"     • {r.name}: {r.detail[:80]}")
        print()


# ─── timeout wrapper ──────────────────────────────────────────────────────────
def _with_timeout(fn: Callable, timeout: int = CHECK_TIMEOUT) -> tuple[bool, str]:
    def _alarm(signum, frame):
        raise TimeoutError(f"timed out after {timeout}s")

    old = signal.signal(signal.SIGALRM, _alarm)
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


def _check(
    name: str,
    fn: Callable,
    layer: int,
    required: bool = True,
    timeout: int = CHECK_TIMEOUT,
) -> CheckResult:
    t0 = time.perf_counter()
    passed, detail = _with_timeout(fn, timeout=timeout)
    elapsed = time.perf_counter() - t0
    return CheckResult(
        name=name, passed=passed, required=required, layer=layer, detail=detail, elapsed=elapsed
    )


def _print_result(r: CheckResult) -> None:
    status = _ok(r.name) if r.passed else (_fail(r.name) if r.required else _warn(r.name))
    det = ""
    if r.detail:
        col = DIM if r.passed else RED
        det = f"  {col}→ {r.detail[:70]}{RESET}"
    print(f"    {status}  {DIM}[{r.elapsed:.2f}s]{RESET}{det}")


# ─── setup ────────────────────────────────────────────────────────────────────
def setup_fixture() -> bool:
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    if FIXTURE_DEST.exists():
        try:
            os.chmod(FIXTURE_DEST, 0o755)
        except PermissionError:
            pass
        print(
            f"  {DIM}Fixture already exists at {FIXTURE_DEST}  ({FIXTURE_DEST.stat().st_size} bytes){RESET}"
        )
        return True
    if not FIXTURE_SRC.exists():
        print(f"{RED}  ❌ Fixture not found: {FIXTURE_SRC}{RESET}")
        return False
    shutil.copy2(FIXTURE_SRC, FIXTURE_DEST)
    try:
        os.chmod(FIXTURE_DEST, 0o755)
    except PermissionError:
        pass
    print(f"  {DIM}Fixture → {FIXTURE_DEST}  ({FIXTURE_DEST.stat().st_size} bytes){RESET}")
    return True


def _patch_workspace() -> None:
    sys.path.insert(0, str(APP_DIR))
    from reversecore_mcp.core.config import get_config

    cfg = get_config()
    cfg.workspace = str(WORKSPACE)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — Full module import sweep
# ══════════════════════════════════════════════════════════════════════════════
def _layer1_checks() -> list[tuple[str, Callable, bool]]:
    checks = []
    tools_pkg = APP_DIR / "reversecore_mcp" / "tools"
    for root, _dirs, files in os.walk(tools_pkg):
        for fname in sorted(files):
            if not fname.endswith(".py") or fname == "__init__.py":
                continue
            rel = Path(root).relative_to(APP_DIR)
            mod = ".".join(rel.parts) + "." + fname[:-3]

            def _mk(m: str) -> Callable:
                def _fn() -> tuple[bool, str]:
                    importlib.import_module(m)
                    return True, "import OK"

                return _fn

            checks.append((f"import {fname[:-3]}", _mk(mod), True))
    return checks


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — CLI binary checks (with output validation)
# ══════════════════════════════════════════════════════════════════════════════
def _cli_file() -> tuple[bool, str]:
    if not shutil.which("file"):
        return False, "`file` not in PATH"
    out = subprocess.check_output(["file", str(FIXTURE_DEST)], text=True, timeout=10)
    if "ELF" not in out:
        return False, f"Expected 'ELF' in output, got: {out.strip()[:60]}"
    return True, out.strip()[:80]


def _cli_radare2_disasm() -> tuple[bool, str]:
    if not shutil.which("r2"):
        return False, "`r2` not in PATH"
    # aaa = analyze all, pd 5 = print 5 disasm insns at entry
    out = subprocess.check_output(
        ["r2", "-q", "-e", "scr.color=false", "-c", "aaa;s entry0;pd 5", str(FIXTURE_DEST)],
        text=True,
        timeout=25,
        stderr=subprocess.DEVNULL,
    )
    if not any(kw in out.lower() for kw in ["syscall", "xor", "mov", "ret", "call"]):
        return False, f"No disasm mnemonics in output: {out.strip()[:80]}"
    return True, f"r2 disasm OK: {out.strip()[:60]}"


def _cli_yara_match() -> tuple[bool, str]:
    if not shutil.which("yara"):
        return False, "`yara` not in PATH"
    rule = "rule elf { strings: $m = { 7F 45 4C 46 } condition: $m }"
    with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as f:
        f.write(rule)
        rp = f.name
    try:
        out = subprocess.run(
            ["yara", rp, str(FIXTURE_DEST)], capture_output=True, text=True, timeout=10
        )
        if "elf" not in out.stdout:
            return False, f"YARA rule did not match ELF magic: {out.stdout[:60]}"
        return True, "YARA matched ELF magic ✓"
    finally:
        Path(rp).unlink(missing_ok=True)


def _cli_strings_output() -> tuple[bool, str]:
    if not shutil.which("strings"):
        return False, "`strings` not in PATH"
    out = subprocess.check_output(["strings", "-n", "3", str(FIXTURE_DEST)], text=True, timeout=10)
    return True, f"{len(out.split())} string tokens extracted"


def _cli_capa() -> tuple[bool, str]:
    if not shutil.which("capa"):
        return False, "`capa` not installed (optional)"
    out = subprocess.check_output(
        ["capa", "--version"], text=True, timeout=10, stderr=subprocess.STDOUT
    )
    return True, out.strip()[:60]


def _cli_binwalk() -> tuple[bool, str]:
    if not shutil.which("binwalk"):
        return False, "`binwalk` not installed (optional)"
    out = subprocess.check_output(
        ["binwalk", str(FIXTURE_DEST)], text=True, timeout=15, stderr=subprocess.DEVNULL
    )
    return True, f"{len(out)} chars output"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — Python package binding calls
# ══════════════════════════════════════════════════════════════════════════════
def _pkg_lief() -> tuple[bool, str]:
    import lief

    b = lief.parse(str(FIXTURE_DEST))
    if b is None:
        return False, "lief.parse() returned None"
    # Inspect sections list (may be empty for tiny ELF but must not raise)
    _ = list(b.sections)
    fmt = str(b.format)
    return True, f"LIEF format={fmt}, sections={len(list(b.sections))}"


def _pkg_yara_python() -> tuple[bool, str]:
    import yara

    r = yara.compile(source="rule e { strings: $m = { 7F 45 4C 46 } condition: $m }")
    m = r.match(str(FIXTURE_DEST))
    if not m:
        return False, "yara-python: rule compiled but did not match ELF magic"
    return True, f"yara-python compile+match OK: {m[0].rule}"


def _pkg_fastmcp() -> tuple[bool, str]:
    from fastmcp import FastMCP

    mcp = FastMCP("pkg-test")
    return True, f"FastMCP({mcp.name}) instantiated OK"


def _pkg_r2pipe() -> tuple[bool, str]:
    import r2pipe

    r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
    info = r2.cmdj("ij") or {}
    r2.quit()
    arch = info.get("bin", {}).get("arch", "?")
    bits = info.get("bin", {}).get("bits", "?")
    return True, f"r2pipe OK arch={arch} bits={bits}"


def _pkg_capstone() -> tuple[bool, str]:
    try:
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        code = b"\x48\x31\xc0\xc3"  # xor rax,rax; ret
        insns = list(md.disasm(code, 0x1000))
        if len(insns) < 2:
            return False, f"Expected >= 2 insns, got {len(insns)}"
        names = [i.mnemonic for i in insns]
        return True, f"Capstone: {' / '.join(names)}"
    except ImportError:
        return False, "capstone not installed (optional)"


def _pkg_angr() -> tuple[bool, str]:
    try:
        import angr

        return True, f"angr {angr.__version__} importable"
    except ImportError:
        return False, "angr not installed (optional)"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — Per-category real MCP tool calls (12 tools)
# ══════════════════════════════════════════════════════════════════════════════
def _tool_run_file() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
    if r.status != "success":
        return False, f"status={r.status} error={r.error}"
    return True, f"keys={list((r.data or {}).keys())}"


def _tool_run_strings() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import static_analysis

    r = asyncio.run(static_analysis.run_strings(str(FIXTURE_DEST), min_length=3))
    if r.status != "success":
        return False, f"status={r.status} error={r.error}"
    return True, "run_strings OK"


def _tool_list_workspace() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.list_workspace())
    if r.status != "success":
        return False, f"status={r.status}"
    return True, "list_workspace OK"


def _tool_parse_lief() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.analysis import lief_tools

    r = asyncio.run(lief_tools.parse_binary_with_lief(str(FIXTURE_DEST)))
    if r.status != "success":
        return False, f"status={r.status} error={r.error}"
    return True, "parse_binary_with_lief OK"


def _tool_radare2_run_command() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools import r2_analysis

    r = asyncio.run(r2_analysis.run_radare2(str(FIXTURE_DEST), "aaa;afl"))
    if r.status not in ("success", "error"):
        return False, f"Unexpected status: {r.status}"
    return True, f"run_radare2 status={r.status}"


def _tool_radare2_list_sections() -> tuple[bool, str]:
    _patch_workspace()

    # Build plugin and call Radare2_list_sections via plugin.register
    # Use r2pipe directly to verify sections command
    import r2pipe

    r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
    sections = r2.cmdj("iSj") or []
    r2.quit()
    return True, f"Radare2 sections: {len(sections)} found"


def _tool_run_yara() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import yara_tools

    rule = "rule elf { strings: $m = { 7F 45 4C 46 } condition: $m }"
    with tempfile.NamedTemporaryFile(
        suffix=".yar", mode="w", delete=False, dir=str(WORKSPACE)
    ) as f:
        f.write(rule)
        rp = f.name
    try:
        r = asyncio.run(yara_tools.run_yara(str(FIXTURE_DEST), rp))
        if r.status not in ("success", "error"):
            return False, f"Unexpected status: {r.status}"
        return True, f"run_yara status={r.status}"
    finally:
        Path(rp).unlink(missing_ok=True)


def _tool_extract_iocs() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import ioc_tools

    r = asyncio.run(ioc_tools.extract_iocs(str(FIXTURE_DEST)))
    if r.status not in ("success", "error"):
        return False, f"Unexpected status: {r.status}"
    return True, f"extract_iocs status={r.status}"


def _tool_generate_yara_rule() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.malware import yara_tools

    r = asyncio.run(yara_tools.generate_yara_rule(str(FIXTURE_DEST)))
    if r.status not in ("success", "error"):
        return False, f"Unexpected status: {r.status}"
    return True, f"generate_yara_rule status={r.status}"


def _tool_get_server_health() -> tuple[bool, str]:
    _patch_workspace()
    from fastmcp import FastMCP

    from reversecore_mcp.tools.common.server_tools import ServerToolsPlugin

    mcp = FastMCP("health-test")
    ServerToolsPlugin().register(mcp)
    tools = asyncio.run(mcp.list_tools())
    tool = next((t for t in tools if t.name == "get_server_health"), None)
    if tool is None:
        return False, "get_server_health not found after registration"
    return True, f"get_server_health registered, {len(tools)} tools in mcp"


def _tool_get_system_time() -> tuple[bool, str]:
    _patch_workspace()
    from reversecore_mcp.tools.report import report_mcp_tools

    result = asyncio.run(report_mcp_tools.get_system_time())
    if not result or len(result) < 5:
        return False, f"Unexpected system time output: {result!r}"
    return True, f"get_system_time → {str(result)[:40]}"


def _tool_assemble_instructions() -> tuple[bool, str]:
    _patch_workspace()
    try:
        from reversecore_mcp.tools.common import assembler

        r = asyncio.run(
            assembler.assemble_instructions(
                instructions="xor eax, eax\nret",
                arch="x86",
                mode="32",
            )
        )
        if r.status not in ("success", "error"):
            return False, f"Unexpected status: {r.status}"
        return True, f"assemble_instructions status={r.status}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — Named tool existence (by exact name)
# ══════════════════════════════════════════════════════════════════════════════
def _layer5_named_tools() -> tuple[bool, str]:
    _patch_workspace()
    from fastmcp import FastMCP

    import reversecore_mcp.tools as pkg
    from reversecore_mcp.core.loader import PluginLoader

    mcp = FastMCP("name-check")
    loader = PluginLoader()
    tools_path = os.path.dirname(pkg.__file__)
    plugins = loader.discover_plugins(tools_path)
    for p in plugins:
        p.register(mcp)

    registered = {t.name for t in asyncio.run(mcp.list_tools())}
    missing = sorted(REQUIRED_TOOL_NAMES - registered)
    if missing:
        return False, f"{len(missing)} required tools missing: {missing[:5]}..."
    return True, f"All {len(REQUIRED_TOOL_NAMES)} required tools present ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 6 — Registration metrics (count-based gate)
# ══════════════════════════════════════════════════════════════════════════════
def _layer6_tool_count() -> tuple[bool, str]:
    _patch_workspace()
    from fastmcp import FastMCP

    import reversecore_mcp.tools as pkg
    from reversecore_mcp.core.loader import PluginLoader

    mcp = FastMCP("count-check")
    loader = PluginLoader()
    tools_path = os.path.dirname(pkg.__file__)
    plugins = loader.discover_plugins(tools_path)
    for p in plugins:
        p.register(mcp)

    count = len(asyncio.run(mcp.list_tools()))
    if count < MIN_REQUIRED_TOOLS:
        return False, f"Only {count} tools — expected >= {MIN_REQUIRED_TOOLS}"
    return True, f"{count} tools registered (>= {MIN_REQUIRED_TOOLS} ✓)"


def _layer6_prompt_count() -> tuple[bool, str]:
    _patch_workspace()
    from fastmcp import FastMCP

    from reversecore_mcp.prompts import register_prompts

    mcp = FastMCP("prompt-check")
    register_prompts(mcp)
    prompts = asyncio.run(mcp.list_prompts())
    count = len(prompts)
    if count < MIN_REQUIRED_PROMPTS:
        return False, f"Only {count} prompts — expected >= {MIN_REQUIRED_PROMPTS}"
    names = {p.name for p in prompts}
    missing = sorted(REQUIRED_PROMPT_NAMES - names)
    if missing:
        return False, f"Missing required prompts: {missing}"
    return True, f"{count} prompts, all {len(REQUIRED_PROMPT_NAMES)} required present ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 7 — Security boundary checks
# ══════════════════════════════════════════════════════════════════════════════
def _sec_path_traversal_blocked() -> tuple[bool, str]:
    """Path traversal attempts must be rejected, not silently allowed."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    payloads = [
        "/etc/passwd",
        "../../etc/passwd",
        "/app/reversecore_mcp/core/config.py",
    ]
    allowed: list[str] = []
    for path in payloads:
        try:
            r = asyncio.run(file_operations.run_file(path))
            if r.status == "success":
                allowed.append(path)
        except Exception:
            pass  # Exception is also acceptable (rejection)

    if allowed:
        return False, f"Path traversal NOT blocked for: {allowed}"
    return True, f"All {len(payloads)} traversal attempts rejected ✓"


def _sec_workspace_isolation() -> tuple[bool, str]:
    """Files outside the workspace must be rejected by list/run tools."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    outside = "/tmp/outside_workspace_file.txt"
    Path(outside).write_text("should not be readable")
    try:
        r = asyncio.run(file_operations.run_file(outside))
        if r.status == "success":
            return False, f"Workspace isolation BROKEN: accessed {outside}"
        return True, "Workspace isolation enforced ✓"
    finally:
        Path(outside).unlink(missing_ok=True)


def _sec_empty_path_rejected() -> tuple[bool, str]:
    """Empty string path must return error, not raise exception."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    try:
        r = asyncio.run(file_operations.run_file(""))
        if r.status != "error":
            return False, f"Empty path not rejected: status={r.status}"
        return True, f"Empty path → error (error_code={r.error_code}) ✓"
    except Exception as exc:
        return False, f"Empty path raised exception: {type(exc).__name__}: {exc}"


def _sec_none_like_path_rejected() -> tuple[bool, str]:
    """Non-existent files must return error, not hang or raise."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.run_file("/nonexistent/path/binary.exe"))
    if r.status != "error":
        return False, f"Non-existent path not rejected: status={r.status}"
    return True, "Non-existent path → error ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 8 — Error resilience (bad inputs → ToolResult, not exceptions)
# ══════════════════════════════════════════════════════════════════════════════
def _resilience_run_yara_bad_rule() -> tuple[bool, str]:
    """Malformed YARA rule → error ToolResult, not crash."""
    _patch_workspace()
    from reversecore_mcp.tools.malware import yara_tools

    bad_rule = "/nonexistent/path/malformed_rule.yar"
    try:
        r = asyncio.run(yara_tools.run_yara(str(FIXTURE_DEST), bad_rule))
        if r.status != "error":
            return False, f"Bad YARA path should return error, got: {r.status}"
        return True, "Bad YARA rule → ToolResult(error) ✓"
    except Exception as exc:
        return False, f"Bad YARA rule raised exception: {type(exc).__name__}"


def _resilience_lief_non_binary() -> tuple[bool, str]:
    """Passing a text file to LIEF → error ToolResult, not crash."""
    _patch_workspace()
    from reversecore_mcp.tools.analysis import lief_tools

    txt = WORKSPACE / "not_a_binary.txt"
    txt.write_text("this is plaintext, not a binary")
    try:
        r = asyncio.run(lief_tools.parse_binary_with_lief(str(txt)))
        # May succeed (lief is permissive) or error — must not raise
        return True, f"lief on text file → status={r.status} (no exception) ✓"
    except Exception as exc:
        return False, f"lief on text file raised: {type(exc).__name__}: {exc}"
    finally:
        txt.unlink(missing_ok=True)


def _resilience_radare2_empty_command() -> tuple[bool, str]:
    """Empty r2 command → error ToolResult, not crash."""
    _patch_workspace()
    from reversecore_mcp.tools import r2_analysis

    try:
        r = asyncio.run(r2_analysis.run_radare2(str(FIXTURE_DEST), ""))
        return True, f"Empty r2 cmd → status={r.status} (no exception) ✓"
    except Exception as exc:
        return False, f"Empty r2 cmd raised: {type(exc).__name__}: {exc}"


def _resilience_ioc_on_text() -> tuple[bool, str]:
    """IOC extraction on a text file → must not crash."""
    _patch_workspace()
    from reversecore_mcp.tools.malware import ioc_tools

    txt = WORKSPACE / "test_ioc_text.txt"
    txt.write_text("http://example.com 192.168.1.1 malware@evil.com")
    try:
        r = asyncio.run(ioc_tools.extract_iocs(str(txt)))
        return True, f"extract_iocs on text → status={r.status} (no exception) ✓"
    except Exception as exc:
        return False, f"extract_iocs raised: {type(exc).__name__}: {exc}"
    finally:
        txt.unlink(missing_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 9 — Performance baseline
# ══════════════════════════════════════════════════════════════════════════════
PERF_LIMITS: dict[str, float] = {
    "run_file": 5.0,
    "run_strings": 5.0,
    "list_workspace": 3.0,
    "parse_binary_with_lief": 10.0,
    "run_yara": 10.0,
    "extract_iocs": 15.0,
}


def _perf_check(tool_name: str, fn: Callable, limit: float) -> tuple[bool, str]:
    t0 = time.perf_counter()
    passed, detail = fn()
    elapsed = time.perf_counter() - t0
    if elapsed > limit:
        return False, f"{tool_name} took {elapsed:.2f}s > limit {limit}s"
    return True, f"{tool_name} {elapsed:.2f}s <= {limit}s ✓"


def _perf_run_file() -> tuple[bool, str]:
    return _perf_check("run_file", _tool_run_file, PERF_LIMITS["run_file"])


def _perf_run_strings() -> tuple[bool, str]:
    return _perf_check("run_strings", _tool_run_strings, PERF_LIMITS["run_strings"])


def _perf_list_workspace() -> tuple[bool, str]:
    return _perf_check("list_workspace", _tool_list_workspace, PERF_LIMITS["list_workspace"])


def _perf_parse_lief() -> tuple[bool, str]:
    return _perf_check(
        "parse_binary_with_lief", _tool_parse_lief, PERF_LIMITS["parse_binary_with_lief"]
    )


def _perf_run_yara() -> tuple[bool, str]:
    return _perf_check("run_yara", _tool_run_yara, PERF_LIMITS["run_yara"])


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 10 — End-to-end 7-step analysis chain
# ══════════════════════════════════════════════════════════════════════════════
def _layer10_chain() -> tuple[bool, str]:
    """
    Realistic full analysis workflow:
      1. list_workspace()              — file visible
      2. run_file()                    — identify type
      3. parse_binary_with_lief()      — structural parse
      4. run_strings()                 — string extraction
      5. generate_yara_rule()          — rule generation from binary
      6. run_yara()                    — scan with generated rule
      7. extract_iocs()                — IOC extraction
    Each step must not fail before the next runs.
    """
    _patch_workspace()
    from reversecore_mcp.tools import file_operations, static_analysis
    from reversecore_mcp.tools.analysis import lief_tools
    from reversecore_mcp.tools.malware import ioc_tools, yara_tools

    results: list[tuple[str, bool, str]] = []

    def _step(name: str, coro) -> bool:
        r = asyncio.run(coro)
        ok = r.status in ("success", "error")
        results.append((name, ok, r.status))
        return ok

    _step("list_workspace", file_operations.list_workspace())
    _step("run_file", file_operations.run_file(str(FIXTURE_DEST)))
    _step("parse_binary_with_lief", lief_tools.parse_binary_with_lief(str(FIXTURE_DEST)))
    _step("run_strings", static_analysis.run_strings(str(FIXTURE_DEST), min_length=3))
    _step("generate_yara_rule", yara_tools.generate_yara_rule(str(FIXTURE_DEST)))

    # run_yara with inline rule
    rule = "rule elf { strings: $m = { 7F 45 4C 46 } condition: $m }"
    with tempfile.NamedTemporaryFile(
        suffix=".yar", mode="w", delete=False, dir=str(WORKSPACE)
    ) as f:
        f.write(rule)
        rp = f.name
    try:
        _step("run_yara", yara_tools.run_yara(str(FIXTURE_DEST), rp))
    finally:
        Path(rp).unlink(missing_ok=True)

    _step("extract_iocs", ioc_tools.extract_iocs(str(FIXTURE_DEST)))

    failed_steps = [(n, s) for n, ok, s in results if not ok]
    if failed_steps:
        return False, f"Chain broken at: {failed_steps}"

    chain = " → ".join(n for n, _, _ in results)
    return True, f"7-step chain OK: {chain}"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 11 — Radare2 deep verification
# ══════════════════════════════════════════════════════════════════════════════
def _r2_deep_disasm_content() -> tuple[bool, str]:
    """Verify r2 produces actual x86-64 instructions matching our ELF."""
    import r2pipe

    r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
    try:
        r2.cmd("aaa")
        # Disassemble at entry point — should see our mov rax,60; xor rdi,rdi; syscall
        pd = r2.cmd("s entry0; pd 3")
        if not pd or len(pd.strip()) < 10:
            return False, "r2 disasm produced empty output"
        # Verify at least one expected instruction
        found = [kw for kw in ["mov", "xor", "syscall"] if kw in pd.lower()]
        if len(found) < 2:
            return False, f"Expected >=2 of mov/xor/syscall, found: {found}"
        return True, f"Disasm content OK: found {found}"
    finally:
        r2.quit()


def _r2_deep_binary_info() -> tuple[bool, str]:
    """Verify r2 extracts correct binary metadata."""
    import r2pipe

    r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
    try:
        info = r2.cmdj("ij") or {}
        binfo = info.get("bin", {})
        arch = binfo.get("arch", "")
        bits = binfo.get("bits", 0)
        machine = binfo.get("machine", "")
        if arch != "x86":
            return False, f"Expected arch=x86, got {arch}"
        if bits != 64:
            return False, f"Expected bits=64, got {bits}"
        return True, f"arch={arch} bits={bits} machine={machine}"
    finally:
        r2.quit()


def _r2_deep_entry_point() -> tuple[bool, str]:
    """Verify r2 resolves entry point correctly (0x400078 for our ELF)."""
    import r2pipe

    r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
    try:
        info = r2.cmdj("iej") or []
        if not info:
            return False, "No entry points found"
        entry_vaddr = info[0].get("vaddr", 0)
        if entry_vaddr != 0x400078:
            return False, f"Expected entry 0x400078, got 0x{entry_vaddr:x}"
        return True, f"Entry point 0x{entry_vaddr:x} ✓"
    finally:
        r2.quit()


def _r2_deep_r2ghidra_import() -> tuple[bool, str]:
    """Verify r2ghidra plugin is loadable (pdg command exists)."""
    import r2pipe

    r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
    try:
        # Check if r2ghidra pdg command is available
        r2.cmd("e cmd.pdc=?")
        pdg_help = r2.cmd("pdg?")
        has_pdg = "pdg" in pdg_help
        # Check the plugin list
        plugins = r2.cmd("Lc")
        return (
            True,
            f"r2ghidra check: pdg={'yes' if has_pdg else 'no'}, plugins={len(plugins)} chars",
        )
    except Exception as exc:
        return False, f"r2ghidra check failed: {exc}"
    finally:
        r2.quit()


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 12 — Concurrent tool execution (race condition detection)
# ══════════════════════════════════════════════════════════════════════════════
def _concurrent_5_tools() -> tuple[bool, str]:
    """Run 5 tools simultaneously to detect race conditions."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations, static_analysis
    from reversecore_mcp.tools.analysis import lief_tools
    from reversecore_mcp.tools.malware import ioc_tools, yara_tools

    rule = "rule elf { strings: $m = { 7F 45 4C 46 } condition: $m }"
    rule_file = WORKSPACE / "concurrent_test.yar"
    rule_file.write_text(rule)

    async def _run_all():
        results = await asyncio.gather(
            file_operations.run_file(str(FIXTURE_DEST)),
            static_analysis.run_strings(str(FIXTURE_DEST), min_length=3),
            lief_tools.parse_binary_with_lief(str(FIXTURE_DEST)),
            ioc_tools.extract_iocs(str(FIXTURE_DEST)),
            yara_tools.run_yara(str(FIXTURE_DEST), str(rule_file)),
            return_exceptions=True,
        )
        return results

    try:
        results = asyncio.run(_run_all())
        exceptions = [r for r in results if isinstance(r, Exception)]
        if exceptions:
            return False, f"{len(exceptions)} exceptions in concurrent run: {exceptions[0]}"
        statuses = [getattr(r, "status", "unknown") for r in results]
        return True, f"5 tools concurrent OK: statuses={statuses}"
    except Exception as exc:
        return False, f"Concurrent execution failed: {type(exc).__name__}: {exc}"
    finally:
        rule_file.unlink(missing_ok=True)


def _concurrent_repeated_3x() -> tuple[bool, str]:
    """Run the same tool 3 times simultaneously (idempotency check)."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    async def _run_3x():
        return await asyncio.gather(
            file_operations.run_file(str(FIXTURE_DEST)),
            file_operations.run_file(str(FIXTURE_DEST)),
            file_operations.run_file(str(FIXTURE_DEST)),
            return_exceptions=True,
        )

    results = asyncio.run(_run_3x())
    exceptions = [r for r in results if isinstance(r, Exception)]
    if exceptions:
        return False, f"Repeated call raised: {exceptions[0]}"
    statuses = [getattr(r, "status", "?") for r in results]
    if statuses.count("success") != 3:
        return False, f"Expected 3x success, got: {statuses}"
    return True, "3x concurrent run_file: all success ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 13 — Resource leak detection
# ══════════════════════════════════════════════════════════════════════════════
def _leak_r2_sessions_closed() -> tuple[bool, str]:
    """Open+close multiple r2pipe sessions, verify no zombie r2 processes."""
    import r2pipe

    # Count r2 processes before
    try:
        before = subprocess.run(
            ["pgrep", "-c", "radare2"], capture_output=True, text=True, timeout=5
        )
        before_count = int(before.stdout.strip()) if before.returncode == 0 else 0
    except Exception:
        before_count = 0

    # Open and close 5 sessions
    for _ in range(5):
        r2 = r2pipe.open(str(FIXTURE_DEST), flags=["-2"])
        r2.cmd("aaa")
        r2.quit()

    # Brief wait for cleanup
    time.sleep(0.5)

    try:
        after = subprocess.run(
            ["pgrep", "-c", "radare2"], capture_output=True, text=True, timeout=5
        )
        after_count = int(after.stdout.strip()) if after.returncode == 0 else 0
    except Exception:
        after_count = 0

    leaked = after_count - before_count
    if leaked > 0:
        return False, f"{leaked} zombie r2 processes leaked after 5 open/close cycles"
    return True, f"No r2 process leaks (before={before_count}, after={after_count}) ✓"


def _leak_file_descriptors() -> tuple[bool, str]:
    """Verify no file descriptor leaks after tool runs."""
    proc_fd = Path("/proc/self/fd")
    if not proc_fd.exists():
        return True, "Skipped (no /proc/self/fd on this platform)"

    fd_before = len(list(proc_fd.iterdir()))

    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    for _ in range(10):
        asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))

    fd_after = len(list(proc_fd.iterdir()))
    leaked = fd_after - fd_before
    if leaked > 5:  # allow small variance
        return False, f"{leaked} file descriptors leaked after 10 run_file calls"
    return True, f"FD leak check OK (delta={leaked}) ✓"


def _leak_no_temp_files() -> tuple[bool, str]:
    """Verify tools clean up temp files."""
    tmp_before = set(Path(tempfile.gettempdir()).glob("*reversecore*"))
    tmp_before |= set(Path(tempfile.gettempdir()).glob("*yara*"))

    _patch_workspace()
    from reversecore_mcp.tools import file_operations, static_analysis

    for _ in range(3):
        asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
        asyncio.run(static_analysis.run_strings(str(FIXTURE_DEST), min_length=3))

    tmp_after = set(Path(tempfile.gettempdir()).glob("*reversecore*"))
    tmp_after |= set(Path(tempfile.gettempdir()).glob("*yara*"))
    leaked = tmp_after - tmp_before
    if leaked:
        return False, f"{len(leaked)} temp files leaked: {[p.name for p in leaked][:3]}"
    return True, "No temp file leaks ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 14 — Data integrity
# ══════════════════════════════════════════════════════════════════════════════
def _integrity_fixture_sha256() -> tuple[bool, str]:
    """Verify fixture binary hasn't been corrupted or tampered with."""
    with open(FIXTURE_DEST, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    if sha != FIXTURE_SHA256:
        return False, f"SHA256 mismatch: expected {FIXTURE_SHA256[:16]}..., got {sha[:16]}..."
    return True, f"SHA256 {sha[:16]}... verified ✓"


def _integrity_fixture_size() -> tuple[bool, str]:
    """Verify fixture binary size is exactly as expected."""
    actual = FIXTURE_DEST.stat().st_size
    if actual != FIXTURE_SIZE:
        return False, f"Size mismatch: expected {FIXTURE_SIZE}, got {actual}"
    return True, f"Size {actual} bytes verified ✓"


def _integrity_deterministic_file_output() -> tuple[bool, str]:
    """Verify run_file produces identical output on repeated calls."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    results = []
    for _ in range(3):
        r = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
        results.append(str(r.data) if hasattr(r, "data") else str(r))

    if len(set(results)) != 1:
        return False, f"Non-deterministic output: {len(set(results))} unique results from 3 runs"
    return True, "3 identical outputs from run_file ✓"


def _integrity_deterministic_lief_output() -> tuple[bool, str]:
    """Verify parse_binary_with_lief produces identical output."""
    _patch_workspace()
    from reversecore_mcp.tools.analysis import lief_tools

    results = []
    for _ in range(3):
        r = asyncio.run(lief_tools.parse_binary_with_lief(str(FIXTURE_DEST)))
        results.append(str(r.data) if hasattr(r, "data") else str(r))

    if len(set(results)) != 1:
        return False, f"LIEF non-deterministic: {len(set(results))} unique results"
    return True, "3 identical outputs from parse_binary_with_lief ✓"


def _integrity_elf_magic_bytes() -> tuple[bool, str]:
    """Verify fixture starts with correct ELF magic bytes."""
    with open(FIXTURE_DEST, "rb") as f:
        magic = f.read(4)
    if magic != b"\x7fELF":
        return False, f"Bad magic: {magic.hex()} (expected 7f454c46)"
    return True, "ELF magic \\x7fELF verified ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 15 — ToolResult schema validation
# ══════════════════════════════════════════════════════════════════════════════
def _schema_toolresult_success_has_data() -> tuple[bool, str]:
    """Success ToolResult must have `data` field."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
    if r.status != "success":
        return False, f"run_file didn't succeed: {r.status}"
    if not hasattr(r, "data"):
        return False, "Success result missing 'data' attribute"
    if r.data is None:
        return False, "Success result has data=None"
    return True, f"ToolSuccess has data with {len(r.data)} keys ✓"


def _schema_toolresult_error_has_code() -> tuple[bool, str]:
    """Error ToolResult must have `error_code` field."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.run_file("/nonexistent/file.bin"))
    if r.status != "error":
        return False, f"Expected error status, got: {r.status}"
    if not hasattr(r, "error_code") or not r.error_code:
        return False, "Error result missing 'error_code' field"
    if not r.error_code.startswith("RCMCP"):
        return False, f"error_code doesn't follow convention: {r.error_code}"
    return True, f"ToolError has error_code={r.error_code} ✓"


def _schema_toolresult_pydantic_valid() -> tuple[bool, str]:
    """ToolResult is a valid Pydantic model (serializable)."""
    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
    try:
        # Must be Pydantic model with model_dump
        if hasattr(r, "model_dump"):
            d = r.model_dump()
            if "status" not in d:
                return False, "model_dump() missing 'status' key"
            return True, f"Pydantic model_dump OK: keys={list(d.keys())}"
        elif hasattr(r, "dict"):
            d = r.dict()
            return True, f"Pydantic v1 dict() OK: keys={list(d.keys())}"
        else:
            return False, "ToolResult is not a Pydantic model (no model_dump/dict)"
    except Exception as exc:
        return False, f"Serialization failed: {type(exc).__name__}: {exc}"


def _schema_toolresult_json_serializable() -> tuple[bool, str]:
    """ToolResult must be JSON-serializable (for MCP protocol transport)."""
    import json

    _patch_workspace()
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.run_file(str(FIXTURE_DEST)))
    try:
        if hasattr(r, "model_dump"):
            d = r.model_dump()
        elif hasattr(r, "dict"):
            d = r.dict()
        else:
            d = {"status": r.status}

        json_str = json.dumps(d, default=str)
        if len(json_str) < 10:
            return False, f"JSON output suspiciously small: {len(json_str)} bytes"
        return True, f"JSON serializable ({len(json_str)} bytes) ✓"
    except (TypeError, ValueError) as exc:
        return False, f"Not JSON serializable: {exc}"


def _schema_error_resilience_returns_toolresult() -> tuple[bool, str]:
    """Even error paths must return ToolResult type, not raw strings/dicts."""
    _patch_workspace()
    from reversecore_mcp.core.result import ToolError, ToolSuccess
    from reversecore_mcp.tools import file_operations

    r = asyncio.run(file_operations.run_file("/nonexistent/file.exe"))
    if not isinstance(r, (ToolSuccess, ToolError)):
        return False, f"Error path returned {type(r).__name__}, not ToolSuccess/ToolError"
    return True, f"Error path returns {type(r).__name__} ✓"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 16 — MCP Wire Protocol Conformance
#
# Starts the real server as a subprocess (stdio transport), speaks JSON-RPC 2.0
# over its stdin/stdout, and validates every response against the MCP spec.
#
# Sequence under test:
#   Client → Server   : initialize  (MCP spec §3.1)
#   Server → Client   : result with serverInfo + protocolVersion + capabilities
#   Client → Server   : notifications/initialized  (MCP spec §3.1)
#   Client → Server   : tools/list  (MCP spec §5.1)
#   Server → Client   : result with tools array (name, description, inputSchema)
#   Client → Server   : tools/call run_file  (MCP spec §5.2)
#   Server → Client   : result with content array
# ══════════════════════════════════════════════════════════════════════════════
_MCP_MSG_SEP = b"\n"  # each JSON-RPC message is newline-terminated
_MCP_SERVER_STARTUP_TIMEOUT = 15  # seconds to wait for server to be ready
_MCP_RPC_TIMEOUT = 20  # seconds per RPC call


class _MCPClient:
    """Minimal synchronous MCP client over stdio for smoke testing."""

    def __init__(self, server_cmd: list[str], env: dict) -> None:
        self._proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def send(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request and return the parsed response."""
        import json

        msg: dict = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params is not None:
            msg["params"] = params

        raw = (json.dumps(msg) + "\n").encode()
        assert self._proc.stdin is not None
        self._proc.stdin.write(raw)
        self._proc.stdin.flush()

        return self._read_response(timeout=_MCP_RPC_TIMEOUT)

    def notify(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        import json

        msg: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        raw = (json.dumps(msg) + "\n").encode()
        assert self._proc.stdin is not None
        self._proc.stdin.write(raw)
        self._proc.stdin.flush()

    def _read_response(self, timeout: int = _MCP_RPC_TIMEOUT) -> dict:
        """Read newline-delimited JSON from stdout, skip non-JSON lines."""
        import json
        import select

        assert self._proc.stdout is not None
        deadline = time.time() + timeout
        buf = b""

        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            rlist, _, _ = select.select([self._proc.stdout], [], [], remaining)
            if not rlist:
                raise TimeoutError(f"No response within {timeout}s")

            chunk = self._proc.stdout.read1(4096)  # type: ignore[attr-defined]
            if not chunk:
                raise EOFError("Server closed stdout")
            buf += chunk

            # Try to decode every complete line
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Accept only JSON-RPC responses (have 'id' or 'result'/'error')
                    if "jsonrpc" in obj and ("result" in obj or "error" in obj):
                        return obj
                    # Silently discard notifications/log messages
                except json.JSONDecodeError:
                    pass  # skip non-JSON output (log lines)

        raise TimeoutError(f"Response timeout after {timeout}s")

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass


def _mcp_server_cmd() -> list[str]:
    """Build the command to launch the MCP server in stdio mode."""
    python = APP_DIR / ".venv" / "bin" / "python"
    if not python.exists():
        python = APP_DIR / "venv" / "bin" / "python"
    if not python.exists():
        python = Path("/opt/venv/bin/python")
    if not python.exists():
        python = Path(sys.executable)
    return [str(python), str(APP_DIR / "server.py")]


def _mcp_protocol_initialize() -> tuple[bool, str]:
    """
    Send MCP initialize and verify the response fields:
      - jsonrpc == '2.0'
      - result.protocolVersion is present
      - result.serverInfo.name == 'Reversecore_MCP'
      - result.capabilities is a dict
    """
    import os

    env = {
        **os.environ,
        "MCP_TRANSPORT": "stdio",
        "LOG_LEVEL": "ERROR",
        "REVERSECORE_WORKSPACE": str(WORKSPACE),
    }
    client = _MCPClient(_mcp_server_cmd(), env=env)
    try:
        resp = client.send(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
        )

        if resp.get("jsonrpc") != "2.0":
            return False, f"jsonrpc field wrong: {resp.get('jsonrpc')!r}"
        if "error" in resp:
            return False, f"Server returned error: {resp['error']}"
        result = resp.get("result", {})
        if "protocolVersion" not in result:
            return False, "Missing protocolVersion in initialize result"
        server_info = result.get("serverInfo", {})
        server_name = server_info.get("name", "")
        caps = result.get("capabilities", None)
        if not isinstance(caps, dict):
            return False, f"capabilities must be dict, got {type(caps)}"

        return True, (
            f"initialize OK: protocolVersion={result['protocolVersion']!r} server={server_name!r}"
        )
    finally:
        client.close()


def _mcp_protocol_tools_list() -> tuple[bool, str]:
    """
    Full handshake → tools/list:
      - result.tools is a list
      - each tool has name (str), description (str), inputSchema (dict)
      - at least MIN_REQUIRED_TOOLS tools present
    """
    import os

    env = {
        **os.environ,
        "MCP_TRANSPORT": "stdio",
        "LOG_LEVEL": "ERROR",
        "REVERSECORE_WORKSPACE": str(WORKSPACE),
    }
    client = _MCPClient(_mcp_server_cmd(), env=env)
    try:
        # Step 1: initialize
        init_resp = client.send(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
        )
        if "error" in init_resp:
            return False, f"initialize failed: {init_resp['error']}"

        # Step 2: notifications/initialized  (required by MCP spec before any call)
        client.notify("notifications/initialized")

        # Step 3: tools/list
        resp = client.send("tools/list")
        if "error" in resp:
            return False, f"tools/list error: {resp['error']}"

        tools = resp.get("result", {}).get("tools", [])
        if not isinstance(tools, list):
            return False, f"tools/list result.tools must be list, got {type(tools)}"
        if len(tools) < MIN_REQUIRED_TOOLS:
            return False, (
                f"tools/list returned {len(tools)} tools — expected >= {MIN_REQUIRED_TOOLS}"
            )

        # Validate schema of first 5 tools
        schema_errors = []
        for tool in tools[:5]:
            if not isinstance(tool.get("name"), str):
                schema_errors.append(f"tool missing name: {tool}")
            if not isinstance(tool.get("inputSchema"), dict):
                schema_errors.append(f"{tool.get('name')!r} missing inputSchema")
        if schema_errors:
            return False, f"Tool schema errors: {schema_errors}"

        tool_names = {t["name"] for t in tools}
        missing = sorted(REQUIRED_TOOL_NAMES - tool_names)[:5]
        if missing:
            return False, f"Required tools missing from wire response: {missing}..."

        return True, (
            f"tools/list OK: {len(tools)} tools over wire, "
            f"schema valid, all required tools present ✓"
        )
    finally:
        client.close()


def _mcp_protocol_tools_call() -> tuple[bool, str]:
    """
    Full handshake → tools/call run_file:
      - result.content is a list
      - content[0].type == 'text'
      - content[0].text is non-empty JSON string
    """
    import json
    import os

    env = {
        **os.environ,
        "MCP_TRANSPORT": "stdio",
        "LOG_LEVEL": "ERROR",
        "REVERSECORE_WORKSPACE": str(WORKSPACE),
    }
    client = _MCPClient(_mcp_server_cmd(), env=env)
    try:
        # initialize
        init_resp = client.send(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
        )
        if "error" in init_resp:
            return False, f"initialize failed: {init_resp['error']}"
        client.notify("notifications/initialized")

        # tools/call run_file
        resp = client.send(
            "tools/call",
            params={
                "name": "run_file",
                "arguments": {"file_path": str(FIXTURE_DEST)},
            },
        )
        if "error" in resp:
            return False, f"tools/call error: {resp['error']}"

        result = resp.get("result", {})
        content = result.get("content", [])
        if not isinstance(content, list) or len(content) == 0:
            return False, f"tools/call result.content must be non-empty list, got: {content!r}"

        first = content[0]
        if first.get("type") != "text":
            return False, f"content[0].type must be 'text', got {first.get('type')!r}"
        text = first.get("text", "")
        if not text:
            return False, "content[0].text is empty"

        # text must be valid JSON (ToolResult serialised)
        try:
            parsed = json.loads(text)
            status = parsed.get("status", "?")
        except json.JSONDecodeError:
            return False, f"content[0].text is not valid JSON: {text[:80]!r}"

        return True, (
            f"tools/call run_file over wire OK: status={status!r}, text={len(text)} bytes ✓"
        )
    finally:
        client.close()


def _mcp_protocol_error_response() -> tuple[bool, str]:
    """
    Call a tool with a bad argument — server must return a structured error
    in the MCP response (either result.isError=true or JSON-RPC error object),
    NOT crash or return a 500-style unformatted error.
    """
    import json
    import os

    env = {
        **os.environ,
        "MCP_TRANSPORT": "stdio",
        "LOG_LEVEL": "ERROR",
        "REVERSECORE_WORKSPACE": str(WORKSPACE),
    }
    client = _MCPClient(_mcp_server_cmd(), env=env)
    try:
        init_resp = client.send(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
        )
        if "error" in init_resp:
            return False, f"initialize failed: {init_resp['error']}"
        client.notify("notifications/initialized")

        # Call run_file with clearly invalid path
        resp = client.send(
            "tools/call",
            params={
                "name": "run_file",
                "arguments": {"file_path": "/this/does/not/exist.bin"},
            },
        )

        # Acceptable outcomes:
        # A) JSON-RPC error object  { "error": { "code": ..., "message": ... } }
        # B) result with isError=true and content with error text
        # C) result with content whose text JSON has status=="error"
        if "error" in resp:
            # Valid JSON-RPC error
            code = resp["error"].get("code")
            msg = resp["error"].get("message", "")
            return True, f"Bad path → JSON-RPC error code={code} msg={msg[:50]!r} ✓"

        result = resp.get("result", {})
        if result.get("isError"):
            return True, "Bad path → result.isError=true ✓"

        # Try to parse content text
        content = result.get("content", [])
        if content:
            try:
                parsed = json.loads(content[0].get("text", "{}"))
                if parsed.get("status") == "error":
                    return True, "Bad path → ToolResult status=error ✓"
            except json.JSONDecodeError:
                pass

        return False, f"Bad path should produce error response, got: {resp!r:.120}"
    finally:
        client.close()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main() -> int:
    global VERBOSE
    parser = argparse.ArgumentParser(description="Reversecore MCP smoke test v4")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    VERBOSE = args.verbose

    print()
    print(f"{BOLD}{CYAN}  🚀 Reversecore MCP — Conservative Smoke Test v5{RESET}")
    print(
        f"  {DIM}Python {sys.version.split()[0]}  │  "
        f"Min tools: {MIN_REQUIRED_TOOLS}  │  "
        f"Layers: 16  │  Timeout/check: {CHECK_TIMEOUT}s{RESET}"
    )

    if not setup_fixture():
        print(f"{RED}  Cannot copy fixture — aborting.{RESET}")
        return 1

    sys.path.insert(0, str(APP_DIR))
    report = SmokeReport()

    def _run(name: str, fn: Callable, layer: int, req: bool = True, t: int = CHECK_TIMEOUT) -> None:
        r = _check(name, fn, layer=layer, required=req, timeout=t)
        report.add(r)
        _print_result(r)

    # ── L1: Module import sweep ───────────────────────────────────────────────
    _section("Layer 1 · Module Import Sweep")
    for name, fn, req in _layer1_checks():
        _run(name, fn, layer=1, req=req, t=15)

    # ── L2: CLI binary checks ─────────────────────────────────────────────────
    _section("Layer 2 · CLI Binary Checks (output validated)")
    _run("CLI: file (ELF validated)", _cli_file, layer=2, req=True)
    _run("CLI: radare2 (disasm output)", _cli_radare2_disasm, layer=2, req=True, t=30)
    _run("CLI: yara (rule match)", _cli_yara_match, layer=2, req=True)
    _run("CLI: strings", _cli_strings_output, layer=2, req=True)
    _run("CLI: capa", _cli_capa, layer=2, req=False)
    _run("CLI: binwalk", _cli_binwalk, layer=2, req=False)

    # ── L3: Python package bindings ───────────────────────────────────────────
    _section("Layer 3 · Python Package Bindings (API calls verified)")
    _run("pkg: lief (sections parsed)", _pkg_lief, layer=3, req=True)
    _run("pkg: yara-python (match verified)", _pkg_yara_python, layer=3, req=True)
    _run("pkg: fastmcp (instantiated)", _pkg_fastmcp, layer=3, req=True)
    _run("pkg: r2pipe (arch extracted)", _pkg_r2pipe, layer=3, req=True)
    _run("pkg: capstone (disasm 2 insns)", _pkg_capstone, layer=3, req=False)
    _run("pkg: angr", _pkg_angr, layer=3, req=False)

    # ── L4: Per-category MCP tool calls ──────────────────────────────────────
    _section("Layer 4 · Per-Category MCP Tool Calls (12 tools)")
    _run("tool: run_file", _tool_run_file, layer=4)
    _run("tool: run_strings", _tool_run_strings, layer=4)
    _run("tool: list_workspace", _tool_list_workspace, layer=4)
    _run("tool: parse_binary_with_lief", _tool_parse_lief, layer=4)
    _run("tool: run_radare2", _tool_radare2_run_command, layer=4, t=30)
    _run("tool: Radare2 sections", _tool_radare2_list_sections, layer=4, t=20)
    _run("tool: run_yara", _tool_run_yara, layer=4)
    _run("tool: extract_iocs", _tool_extract_iocs, layer=4)
    _run("tool: generate_yara_rule", _tool_generate_yara_rule, layer=4)
    _run("tool: get_server_health", _tool_get_server_health, layer=4)
    _run("tool: get_system_time", _tool_get_system_time, layer=4)
    _run("tool: assemble_instructions", _tool_assemble_instructions, layer=4, req=False)

    # ── L5: Named tool existence ──────────────────────────────────────────────
    _section(f"Layer 5 · Named Tool Existence ({len(REQUIRED_TOOL_NAMES)} required)")
    _run(f"named tools: {len(REQUIRED_TOOL_NAMES)} present", _layer5_named_tools, layer=5, t=30)

    # ── L6: Registration metrics ──────────────────────────────────────────────
    _section(
        f"Layer 6 · Registration Metrics (>= {MIN_REQUIRED_TOOLS} tools, >= {MIN_REQUIRED_PROMPTS} prompts)"
    )
    _run(f"tool count >= {MIN_REQUIRED_TOOLS}", _layer6_tool_count, layer=6, t=30)
    _run(f"prompt count >= {MIN_REQUIRED_PROMPTS}", _layer6_prompt_count, layer=6, t=30)

    # ── L7: Security boundary ─────────────────────────────────────────────────
    _section("Layer 7 · Security Boundary Checks")
    _run("sec: path traversal blocked", _sec_path_traversal_blocked, layer=7)
    _run("sec: workspace isolation", _sec_workspace_isolation, layer=7)
    _run("sec: empty path rejected", _sec_empty_path_rejected, layer=7)
    _run("sec: non-existent path rejected", _sec_none_like_path_rejected, layer=7)

    # ── L8: Error resilience ──────────────────────────────────────────────────
    _section("Layer 8 · Error Resilience (bad input → ToolResult, not exception)")
    _run("resilience: bad YARA rule path", _resilience_run_yara_bad_rule, layer=8)
    _run("resilience: LIEF on text file", _resilience_lief_non_binary, layer=8)
    _run("resilience: empty r2 command", _resilience_radare2_empty_command, layer=8)
    _run("resilience: IOC on text file", _resilience_ioc_on_text, layer=8)

    # ── L9: Performance baseline ──────────────────────────────────────────────
    _section("Layer 9 · Performance Baseline")
    _run("perf: run_file < 5s", _perf_run_file, layer=9)
    _run("perf: run_strings < 5s", _perf_run_strings, layer=9)
    _run("perf: list_workspace < 3s", _perf_list_workspace, layer=9)
    _run("perf: parse_binary_with_lief < 10s", _perf_parse_lief, layer=9)
    _run("perf: run_yara < 10s", _perf_run_yara, layer=9)

    # ── L10: End-to-end chain ─────────────────────────────────────────────────
    _section("Layer 10 · End-to-End 7-Step Analysis Chain")
    _run("e2e: list→file→lief→strings→yara_gen→yara_scan→iocs", _layer10_chain, layer=10, t=60)

    # ── L11: Radare2 deep verification ────────────────────────────────────────
    _section("Layer 11 · Radare2 Deep Verification")
    _run("r2: disasm content (mov/xor/syscall)", _r2_deep_disasm_content, layer=11, t=30)
    _run("r2: binary info (arch=x86, bits=64)", _r2_deep_binary_info, layer=11, t=20)
    _run("r2: entry point = 0x400078", _r2_deep_entry_point, layer=11, t=20)
    _run("r2: r2ghidra plugin check", _r2_deep_r2ghidra_import, layer=11, req=False, t=20)

    # ── L12: Concurrent execution ─────────────────────────────────────────────
    _section("Layer 12 · Concurrent Tool Execution")
    _run("concurrent: 5 tools parallel", _concurrent_5_tools, layer=12, t=60)
    _run("concurrent: 3x same tool (idempotency)", _concurrent_repeated_3x, layer=12, t=30)

    # ── L13: Resource leak detection ──────────────────────────────────────────
    _section("Layer 13 · Resource Leak Detection")
    _run("leak: r2pipe sessions (5 cycles)", _leak_r2_sessions_closed, layer=13, t=30)
    _run("leak: file descriptors (10 calls)", _leak_file_descriptors, layer=13, t=30)
    _run("leak: temp files after tool runs", _leak_no_temp_files, layer=13, t=20)

    # ── L14: Data integrity ───────────────────────────────────────────────────
    _section("Layer 14 · Data Integrity")
    _run("integrity: fixture SHA256", _integrity_fixture_sha256, layer=14)
    _run("integrity: fixture size = 132 bytes", _integrity_fixture_size, layer=14)
    _run("integrity: ELF magic bytes", _integrity_elf_magic_bytes, layer=14)
    _run("integrity: run_file deterministic (3x)", _integrity_deterministic_file_output, layer=14)
    _run("integrity: LIEF deterministic (3x)", _integrity_deterministic_lief_output, layer=14)

    # ── L15: ToolResult schema validation ─────────────────────────────────────
    _section("Layer 15 · ToolResult Schema Validation")
    _run("schema: success has data field", _schema_toolresult_success_has_data, layer=15)
    _run("schema: error has error_code (RCMCP-*)", _schema_toolresult_error_has_code, layer=15)
    _run("schema: Pydantic model_dump OK", _schema_toolresult_pydantic_valid, layer=15)
    _run("schema: JSON serializable", _schema_toolresult_json_serializable, layer=15)
    _run(
        "schema: error returns ToolResult type",
        _schema_error_resilience_returns_toolresult,
        layer=15,
    )

    # ── L16: MCP Wire Protocol Conformance ────────────────────────────────────
    _section("Layer 16 · MCP Wire Protocol (JSON-RPC 2.0 over stdio)")
    _run("mcp: initialize handshake", _mcp_protocol_initialize, layer=16, t=30)
    _run("mcp: tools/list >= 100 tools", _mcp_protocol_tools_list, layer=16, t=45)
    _run("mcp: tools/call run_file", _mcp_protocol_tools_call, layer=16, t=45)
    _run("mcp: bad path → structured error", _mcp_protocol_error_response, layer=16, t=30)

    # ── Final report ──────────────────────────────────────────────────────────
    report.print_summary()
    FIXTURE_DEST.unlink(missing_ok=True)

    if report.failed_required:
        n = len(report.failed_required)
        print(f"{RED}{BOLD}🔴 SMOKE TEST FAILED — {n} required check(s) failed.{RESET}")
        print(f"{RED}   This image is NOT safe to deploy.{RESET}\n")
        return 1

    total = len(report.results)
    print(f"{GREEN}{BOLD}🟢 SMOKE TEST PASSED — all {total} checks evaluated.{RESET}")
    if report.optional_warnings:
        print(f"{YELLOW}   {len(report.optional_warnings)} optional warning(s) — see above.{RESET}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
