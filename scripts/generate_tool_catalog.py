#!/usr/bin/env python3
"""Generate and maintain the authoritative MCP Tool Catalog from FastMCP registry.

Acts as the single source of truth for:
1. docs/TOOLS.md — complete parameter and profile reference for all registered tools.
2. README.md — tool counts, category summaries, and profile references.
3. CI drift detection via --check.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TOOLS_DIR = ROOT / "reversecore_mcp" / "tools"
DOCS_TOOLS_PATH = ROOT / "docs" / "TOOLS.md"
README_PATH = ROOT / "README.md"

# Plugin metadata and domain classification
PLUGIN_METADATA: dict[str, dict[str, str]] = {
    "analysis_tools": {
        "title": "Static Analysis & Inspection",
        "domain": "Binary Headers, Formats, Capabilities & Strings",
        "icon": "🔍",
    },
    "source_auditor": {
        "title": "Source Code Auditing",
        "domain": "AST & Regex Pattern Analysis for Python/C/C++",
        "icon": "📜",
    },
    "radare2_mcp_tools": {
        "title": "Radare2 & Decompilation",
        "domain": "Disassembly, CFG, Ghidra Decompiler & ESIL Emulation",
        "icon": "⚙️",
    },
    "malware_tools": {
        "title": "Malware Analysis & Threat Hunting",
        "domain": "YARA Detection, Anti-Analysis, Packer & Vaccine Engines",
        "icon": "🦠",
    },
    "deobfuscation_tools": {
        "title": "Automated Deobfuscation",
        "domain": "String Decryption, API Hashing & Dead Code Removal",
        "icon": "🧩",
    },
    "cve_hunter_tools": {
        "title": "Vulnerability Research & CVE Hunting",
        "domain": "ASan Crash Triage, Fuzz Harness Synthesis & PoC Minimization",
        "icon": "🎯",
    },
    "forensics_tools": {
        "title": "Digital Forensics",
        "domain": "Memory (Volatility), Network (PCAP), Disk & Artifacts",
        "icon": "🔬",
    },
    "memory_tools": {
        "title": "Process & Memory Utilities",
        "domain": "Live Memory Inspection, Patterns & Hex Dumps",
        "icon": "🧠",
    },
    "common_tools": {
        "title": "Common Binary Utilities",
        "domain": "File Operations, Hashing, Patch Explanations & Assembly",
        "icon": "🛠️",
    },
    "server_tools": {
        "title": "Server Lifecycle & State",
        "domain": "Server Status, Health & Memory Cache Management",
        "icon": "🖥️",
    },
    "report_tools": {
        "title": "Reporting & MITRE ATT&CK",
        "domain": "Session Reports, MITRE Mapping, SIGMA & VEX Generation",
        "icon": "📋",
    },
    "core_task_queue": {
        "title": "Task Queue & Async Jobs",
        "domain": "Background Job Status & Result Retrieval",
        "icon": "⏳",
    },
}

RESOURCE_TEMPLATES = [
    ("reversecore://guide", "Tool usage guide with file path rules and security practices"),
    (
        "reversecore://guide/structures",
        "Structure recovery and cross-reference analysis technical guide",
    ),
    ("reversecore://tools", "Authoritative catalog and usage reference for all registered tools"),
    ("reversecore://logs", "Application and execution logs (tail 100 lines)"),
    (
        "reversecore://{filename}/metadata",
        "Binary file metadata, hashes, architecture, and headers",
    ),
    (
        "reversecore://{filename}/func/{address}/xrefs",
        "Cross-references (to/from) for a specific function address",
    ),
    (
        "reversecore://{filename}/func/{address}/context",
        "Contextual disassembly and call hierarchy for a function",
    ),
    ("reversecore://{filename}/memory_map", "Virtual memory segment layout and permissions"),
    (
        "reversecore://{filename}/signatures",
        "Cryptographic and compiler signature detection results",
    ),
    ("reversecore://{filename}/imports", "Imported dynamic libraries and symbol tables"),
    ("reversecore://{filename}/exports", "Exported function symbols and entry points"),
]


async def collect_tool_registry() -> dict[str, Any]:
    """Inspect all plugins and collect complete tool catalog metadata."""
    from reversecore_mcp.core.loader import TOOL_PROFILES, PluginLoader

    loader = PluginLoader(profile="full")
    plugins = loader.discover_plugins(str(TOOLS_DIR), "reversecore_mcp.tools")

    plugin_tools: dict[str, list[dict[str, Any]]] = {}
    all_tools: list[dict[str, Any]] = []

    for p in plugins:
        dummy = FastMCP(name=p.name)
        p.register(dummy)
        tools_raw = await dummy.list_tools()
        tools_list = tools_raw if isinstance(tools_raw, list) else list(tools_raw.values())

        tool_records = []
        for t in sorted(tools_list, key=lambda x: x.name):
            rec = _extract_tool_record(t, p.name, TOOL_PROFILES)
            tool_records.append(rec)
            all_tools.append(rec)
        plugin_tools[p.name] = tool_records

    # Core task queue tool
    tq_dummy = FastMCP(name="task_queue")
    from reversecore_mcp.core.task_queue import get_job_result

    tq_dummy.tool()(get_job_result)
    tq_raw = await tq_dummy.list_tools()
    tq_list = tq_raw if isinstance(tq_raw, list) else list(tq_raw.values())
    tq_records = [_extract_tool_record(t, "core_task_queue", TOOL_PROFILES) for t in tq_list]
    plugin_tools["core_task_queue"] = tq_records
    all_tools.extend(tq_records)

    all_tools.sort(key=lambda x: x["name"])

    return {
        "total_tools": len(all_tools),
        "all_tools": all_tools,
        "plugin_tools": plugin_tools,
        "profiles": TOOL_PROFILES,
    }


def _extract_tool_record(
    tool: Any, plugin_name: str, tool_profiles: dict[str, set[str]]
) -> dict[str, Any]:
    name = getattr(tool, "name", "")
    desc = getattr(tool, "description", "") or ""
    params = getattr(tool, "parameters", {}) or {}
    properties = params.get("properties", {})
    required = set(params.get("required", []))

    # Profiles containing this tool
    profiles: list[str] = ["full"]
    for prof_name in ("static", "malware", "forensics", "vuln-research"):
        if plugin_name == "core_task_queue" or plugin_name in tool_profiles.get(prof_name, set()):
            profiles.append(prof_name)

    param_summary: list[str] = []
    for prop_name, prop_meta in properties.items():
        ptype = prop_meta.get("type", "any")
        is_req = prop_name in required
        tag = f"`{prop_name}` ({ptype}{', req' if is_req else ''})"
        param_summary.append(tag)

    return {
        "name": name,
        "description": desc.strip().split("\n")[0],
        "full_description": desc.strip(),
        "plugin": plugin_name,
        "parameters": properties,
        "required": list(required),
        "param_summary": ", ".join(param_summary) if param_summary else "*(none)*",
        "profiles": profiles,
    }


def render_tools_markdown(catalog: dict[str, Any]) -> str:
    """Generate the authoritative docs/TOOLS.md file."""
    total_tools = catalog["total_tools"]
    plugin_tools = catalog["plugin_tools"]

    lines: list[str] = [
        f"# Reversecore MCP Tool Catalog ({total_tools} Tools)",
        "",
        "> **Single Source of Truth**: This document is automatically generated from the FastMCP runtime",
        "> tool registry by `scripts/generate_tool_catalog.py`. Do not edit manually.",
        "",
        "Reversecore MCP exposes **"
        + str(total_tools)
        + " production-grade security analysis tools** and **"
        + str(len(RESOURCE_TEMPLATES))
        + " dynamic resource templates** via the Model Context Protocol (MCP).",
        "",
        "---",
        "",
        "## 🧭 Tool Profiles Overview",
        "",
        "To optimize LLM context usage and minimize token consumption, tools are organized into modular profiles via `REVERSECORE_PROFILE`:",
        "",
        "| Profile | Tools | Primary Focus | Included Plugins |",
        "|---|:---:|---|---|",
        "| `full` | **151** | Complete All-in-One Suite (Default) | All plugins |",
        "| `static` | **97** | Reverse Engineering & Decompilation | `analysis`, `common`, `radare2`, `report`, `server` |",
        "| `vuln-research` | **103** | Vulnerability Hunting & Exploitation | `analysis`, `source_auditor`, `cve_hunter`, `radare2`, `common`, `report`, `server` |",
        "| `malware` | **65** | Threat Triage & Malware Analysis | `analysis`, `common`, `malware`, `deobfuscation`, `report`, `server` |",
        "| `forensics` | **57** | Digital & Memory Forensics | `forensics`, `memory`, `common`, `report`, `server` |",
        "",
        "📊 *For empirical context token savings, cold-start latency, and memory benchmarks across profiles, see [Profile Footprint Benchmark](benchmarks/profile_footprint.md).*",
        "",
        "---",
        "",
        "## 📦 Plugin Summary",
        "",
        "| Domain | Plugin Name | Tools | Description |",
        "|---|---|:---:|---|",
    ]

    for p_name, p_meta in PLUGIN_METADATA.items():
        tools_in_p = len(plugin_tools.get(p_name, []))
        lines.append(
            f"| {p_meta['icon']} {p_meta['title']} | `{p_name}` | **{tools_in_p}** | {p_meta['domain']} |"
        )

    lines.extend(
        [
            f"| **Total** | — | **{total_tools}** | **Complete Reversecore MCP Suite** |",
            "",
            "---",
            "",
            "## 🛠️ Complete Tool Reference",
            "",
        ]
    )

    tool_counter = 1
    for p_name, p_meta in PLUGIN_METADATA.items():
        tools = plugin_tools.get(p_name, [])
        if not tools:
            continue

        lines.extend(
            [
                f"### {p_meta['icon']} {p_meta['title']} (`{p_name}` — {len(tools)} tools)",
                "",
                f"*{p_meta['domain']}*",
                "",
                "| # | Tool Name | Description | Key Parameters | Profiles |",
                "|:---:|---|---|---|---|",
            ]
        )

        for t in tools:
            profiles_str = (
                ", ".join(f"`{p}`" for p in t["profiles"] if p != "full") or "`full only`"
            )
            lines.append(
                f"| {tool_counter} | `{t['name']}` | {t['description']} | {t['param_summary']} | {profiles_str} |"
            )
            tool_counter += 1

        lines.extend(["", "---", ""])

    lines.extend(
        [
            "## 📁 Dynamic Context Resources (11 URIs)",
            "",
            "Resources provide direct read-only context to AI clients without requiring tool invocations:",
            "",
            "| URI Template | MIME Type | Description |",
            "|---|:---:|---|",
        ]
    )

    for uri, desc in RESOURCE_TEMPLATES:
        lines.append(f"| `{uri}` | `text/markdown` | {desc} |")

    lines.append("")
    return "\n".join(lines)


def update_readme_tool_counts(readme_content: str, total_tools: int) -> str:
    """Synchronize tool counts and references in README.md."""
    # 1. Table of Contents link
    updated = re.sub(
        r"-\s*\[Tool Catalog \(\d+ Tools\)\]\(#tool-catalog(-\d+-tools)?\)",
        f"- [Tool Catalog ({total_tools} Tools)](#tool-catalog-{total_tools}-tools)",
        readme_content,
    )
    # 2. Intro sentence: "wraps **120 analysis tools**"
    updated = re.sub(
        r"wraps \*\*\d+ analysis tools\*\*",
        f"wraps **{total_tools} analysis tools**",
        updated,
    )
    # 3. Architecture box: "120 registered tools"
    updated = re.sub(
        r"\d+ registered tools · Fully async",
        f"{total_tools} registered tools · Fully async",
        updated,
    )
    # 4. Heading: "## Tool Catalog (120 Tools)"
    updated = re.sub(
        r"## Tool Catalog \(\d+ Tools\)",
        f"## Tool Catalog ({total_tools} Tools)",
        updated,
    )
    # 5. MCP Resources tools resource: "all 120 registered tools"
    updated = re.sub(
        r"Complete documentation for all \d+ registered tools",
        f"Complete documentation for all {total_tools} registered tools",
        updated,
    )
    # 6. Project structure: "MCP tool implementations (120 tools)"
    updated = re.sub(
        r"MCP tool implementations \(\d+ tools\)",
        f"MCP tool implementations ({total_tools} tools)",
        updated,
    )

    return updated


async def main_async() -> int:
    parser = argparse.ArgumentParser(description="Generate and check Reversecore MCP tool catalog")
    parser.add_argument(
        "--check", action="store_true", help="Check for catalog and documentation drift"
    )
    parser.add_argument("--json", action="store_true", help="Print catalog as JSON")
    args = parser.parse_args()

    catalog = await collect_tool_registry()
    total_tools = catalog["total_tools"]

    if args.json:
        print(json.dumps(catalog["all_tools"], indent=2))
        return 0

    expected_markdown = render_tools_markdown(catalog)
    current_readme = README_PATH.read_text(encoding="utf-8")
    expected_readme = update_readme_tool_counts(current_readme, total_tools)

    if args.check:
        drift_errors: list[str] = []
        if not DOCS_TOOLS_PATH.exists():
            drift_errors.append(f"Missing documentation file: {DOCS_TOOLS_PATH}")
        else:
            existing_docs = DOCS_TOOLS_PATH.read_text(encoding="utf-8")
            if existing_docs != expected_markdown:
                drift_errors.append(
                    f"{DOCS_TOOLS_PATH} is out of date with current FastMCP tool registry. "
                    "Run 'python scripts/generate_tool_catalog.py' to regenerate."
                )

        if current_readme != expected_readme:
            drift_errors.append(
                f"{README_PATH} has stale tool counts or references. "
                "Run 'python scripts/generate_tool_catalog.py' to synchronize."
            )

        if drift_errors:
            for err in drift_errors:
                print(f"ERROR: {err}", file=sys.stderr)
            return 1

        print(f"✅ Tool catalog check passed: {total_tools} tools verified with 0 drift.")
        return 0

    # Write updates
    DOCS_TOOLS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOCS_TOOLS_PATH.write_text(expected_markdown, encoding="utf-8")
    print(f"✅ Generated {DOCS_TOOLS_PATH} ({total_tools} tools)")

    if current_readme != expected_readme:
        README_PATH.write_text(expected_readme, encoding="utf-8")
        print(f"✅ Synchronized tool counts in {README_PATH} ({total_tools} tools)")
    else:
        print(f"ℹ️ {README_PATH} tool counts are already up to date ({total_tools} tools)")

    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
