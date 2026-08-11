<div align="center">

<img src="icon.png" alt="Reversecore MCP" width="480" />

# Reversecore MCP

[![MCP Toplist](https://mcptoplist.com/badge/io.github.sjkim1127%2Freversecore-mcp.svg)](https://mcptoplist.com/server/io.github.sjkim1127%2Freversecore-mcp)

**AI-Powered Reverse Engineering & Security Analysis via Model Context Protocol**

*An MCP server that gives AI assistants like Claude and Cursor the ability to perform reverse engineering, malware analysis, vulnerability research, digital forensics, and source code auditing through natural language.*

---

[![CI/CD](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml/badge.svg)](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1957%20passed-brightgreen)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-87%25-green)](#testing)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.4.4-purple)](https://github.com/jlowin/fastmcp)
[![PyPI](https://img.shields.io/pypi/v/reversecore-mcp)](https://pypi.org/project/reversecore-mcp/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/sjkim1127/Reversecore_MCP/pkgs/container/reversecore_mcp)

[![Watch the Demo](https://img.shields.io/badge/▶_Watch_Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)
[![SafeSkill Verified](https://img.shields.io/badge/SafeSkill-93%2F100_Verified_Safe-brightgreen?style=for-the-badge)](https://safeskill.dev/scan/sjkim1127-reversecore-mcp)

</div>

---

## Table of Contents

- [What is Reversecore MCP?](#what-is-reversecore-mcp)
- [Architecture](#architecture)
- [Tool Catalog (120 Tools)](#tool-catalog-120-tools)
- [Guided Analysis Prompts (22 Modes)](#guided-analysis-prompts-22-modes)
- [MCP Resources (11 URIs)](#mcp-resources-11-uris)
- [Quick Start](#quick-start)
- [Connect to Your AI Client](#connect-to-your-ai-client)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Development](#development)
- [CI/CD Pipeline](#cicd-pipeline)
- [Docker Build Architecture](#docker-build-architecture)
- [System Requirements](#system-requirements)
- [Project Structure](#project-structure)
- [Error Handling](#error-handling)
- [Adding New Tools](#adding-new-tools)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [License](#license)

---

## What is Reversecore MCP?

Reversecore MCP is a [Model Context Protocol](https://modelcontextprotocol.io/) server that wraps **120 analysis tools** into a single interface that AI assistants can call through natural language.

Instead of learning the command-line syntax for a dozen different tools, you describe what you want:

```
"Decompile the main function of this malware sample, extract all network IOCs,
 map the behavior to MITRE ATT&CK, and generate a triage report."
```

The AI assistant breaks this into tool calls:

```
r2_decompile("sample.exe", "main")
  → extract_iocs("sample.exe")
    → add_mitre_technique(technique_id="T1071.001", ...)
      → create_analysis_report(template_type="quick_triage")
```

Each tool returns a structured `ToolResult` (either `ToolSuccess` or `ToolError`) with typed data that the AI can reason about, chain into follow-up queries, or render for the user.

### What it covers

| Domain | What you can do |
|---|---|
| **Static analysis** | Disassembly, decompilation (r2ghidra), binary parsing (LIEF), packer detection (DIE), capability detection (CAPA), string extraction, firmware scanning (binwalk) |
| **Dynamic & symbolic** | ESIL emulation, angr symbolic execution, taint analysis, fuzzing harness generation |
| **Malware analysis** | IOC extraction, YARA scanning, dormant backdoor detection, adaptive vaccine generation, autonomous vulnerability hunting |
| **Vulnerability research** | Dangerous API detection, ROP gadget discovery, heap exploit analysis, crash triage, PoC generation |
| **Digital forensics** | Memory forensics (Volatility3), PCAP analysis (Scapy), disk forensics (Sleuth Kit), artifact correlation |
| **Source code audit** | Python AST scanning, C/C++ regex pattern scanning |
| **Reporting** | Session-based reports with MITRE ATT&CK mapping, SIGMA rule generation, VEX reports, email delivery |

---

## Architecture

```
AI Client (Claude / Cursor / any MCP-compatible client)
        │  MCP Protocol (stdio or HTTP/SSE)
        ▼
┌──────────────────────────────────────────────────────┐
│                   FastMCP 3.4.4 Server               │
│          120 registered tools · Fully async          │
│                  Python 3.10–3.12                    │
├────────────────────┬─────────────────────────────────┤
│   Guided Prompts   │  Dynamic Resources              │
│  (22 analysis      │  (11 URI-based: per-binary      │
│   modes)           │   strings, IOCs, ASM, CFG, …)   │
├────────────────────┴─────────────────────────────────┤
│                  Core Infrastructure                 │
│  Config · Security · Validators · Exceptions (17)    │
│  R2 Pool · Metrics · Memory (SQLite) · Task Queue    │
│  MITRE Mapper · Evidence Engine · Resilience Layer   │
│  Arch Registry (x86/ARM/MIPS/RISC-V/PPC)            │
│  Result Cache (SHA256) · Analysis Cache (Redis+SQL)  │
│  SAST (Python AST + C/C++ Regex) · Plugin System     │
├──────────────────────────────────────────────────────┤
│                 Analysis Engines                     │
│  Radare2 6.0.4     │  YARA 4.3.1 · LIEF · Capstone  │
│  r2ghidra           │  CAPA · angr · Qiling          │
│  Volatility3 · Scapy│ DIE · Binwalk · Sleuth Kit    │
│  pwntools · ROPgadget│ Keystone (assembler)          │
└──────────────────────────────────────────────────────┘
```

### Core Infrastructure (37 modules)

The `reversecore_mcp/core/` directory contains the shared infrastructure that all tools build on:

| Module | Purpose |
|---|---|
| `config.py` | Pydantic BaseSettings with 34+ environment variables |
| `security.py` | Input sanitization, command argument validation |
| `validators.py` | File and binary path validation with TOCTOU mitigation, symlink resolution |
| `r2_pool.py` | Thread-safe Radare2 connection pool with configurable size |
| `r2_helpers.py` | Structured Radare2 output parsing |
| `metrics.py` | Per-tool execution times, call counts, error rates, cache statistics |
| `memory.py` | Async SQLite-backed AI memory store for persisting analysis findings across sessions |
| `mitre_mapper.py` | MITRE ATT&CK technique ID mapping engine |
| `evidence.py` | Evidence classification system: `OBSERVED`, `INFERRED`, `POSSIBLE` |
| `resilience.py` | Retry, circuit-breaker, and timeout decorator patterns |
| `task_queue.py` | Background task queue via Redis + arq |
| `extension_registry.py` | Plugin registration and lifecycle management |
| `arch_registry.py` | Multi-architecture mapping (x86, x86_64, ARM32, ARM64, MIPS, RISC-V, PPC → r2 arch/bits/registers) |
| `result_cache.py` | SHA256-based tool result caching decorator (`@cache_tool_result`) |
| `analysis_cache.py` | Multi-level decompilation cache (L1: Redis, L2: SQLite) |
| `result.py` | `ToolSuccess` / `ToolError` Pydantic models |
| `exceptions.py` | 17 exception classes with `RCMCP-E*` error codes |
| `decorators.py` | `@log_execution`, `@track_metrics` |
| `error_handling.py` | `@handle_tool_errors` decorator |
| `error_formatting.py` | Structured error response formatting |
| `execution.py` | Safe subprocess execution with timeout and output limits |
| `command_spec.py` | Command specification for subprocess calls |
| `loader.py` | Dynamic tool module loader |
| `plugin.py` | Plugin base class |
| `extension.py` | Extension base class |
| `container.py` | Container/sandbox execution support |
| `audit.py` | Audit logging |
| `binary_cache.py` | Binary file caching |
| `json_utils.py` | JSON serialization via orjson (3-5x faster than stdlib json) |
| `logging_config.py` | Loguru-based structured logging |
| `report_generator.py` | Report rendering engine (Markdown, PDF via xhtml2pdf) |
| `resource_manager.py` | MCP resource lifecycle management |
| `sast/python_ast_scanner.py` | Python AST-based vulnerability scanner |
| `sast/regex_scanner.py` | C/C++ regex-based vulnerability scanner |
| `sast/rule_manager.py` | SAST rule loading and management |

---

## Tool Catalog (120 Tools)

Every tool returns a structured `ToolResult` — either a `ToolSuccess` with typed `data` or a `ToolError` with an `RCMCP-E*` error code. Tools are organized into 8 plugins.

---

### 🔍 Static Analysis Plugin (24 tools)

| # | Tool | Backend | Description |
|---|---|---|---|
| 1 | `run_strings` | `strings` CLI | ASCII/Unicode string extraction with configurable min-length |
| 2 | `run_binwalk` | Binwalk | Firmware deep-scan for embedded signatures and filesystems |
| 3 | `run_binwalk_extract` | Binwalk | Extract embedded files discovered by binwalk |
| 4 | `parse_binary_with_lief` | LIEF | Full PE/ELF/Mach-O header, section, import/export, TLS parsing |
| 5 | `detect_packer` | DIE | Quick packer/compiler detection |
| 6 | `detect_packer_deep` | DIE (`diec`) | Deep packer/protector analysis via Detect It Easy |
| 7 | `run_capa` | CAPA (Mandiant FLARE) | Capability detection — "encrypts data", "creates persistence", etc. |
| 8 | `run_capa_quick` | CAPA | Quick capability scan with a rule subset |
| 9 | `generate_signature` | Radare2 | Generate binary signatures for identification |
| 10 | `generate_yara_rule` | Radare2 + YARA | Generate YARA detection rules from binary patterns |
| 11 | `generate_advanced_yara_rule` | Radare2 + YARA | Advanced YARA rules with behavioral indicators |
| 12 | `scan_for_versions` | LIEF + strings | Scan binary for embedded version strings |
| 13 | `extract_rtti_info` | Radare2 | Extract C++ RTTI (Run-Time Type Information) |
| 14 | `diff_binaries` | Radare2 | Semantic binary diff between two file versions |
| 15 | `analyze_variant_changes` | Radare2 | Analyze changes between binary variants |
| 16 | `match_libraries` | Radare2 | Identify statically linked libraries by function fingerprint |
| 17 | `patch_diff_1day` | Radare2 + heuristics | Automated patch diff analysis for 1-day vulnerability research |
| 18 | `analyze_patch_diff_auto` | Radare2 + inference | Automated patch vulnerability inference |
| 19 | `emulate_binary` | Radare2 ESIL | Register/memory-traced code emulation |
| 20 | `generate_fuzzing_harness` | Qiling + AFL++ | Generate a fuzzing harness targeting a specific function |
| 21 | `run_fuzzing_campaign` | AFL++ | Run a full fuzzing campaign with crash collection |
| 22 | `triage_crash` | GDB | Crash parsing and exploitability assessment |
| 23 | `verify_path_and_get_args` | angr | Symbolic execution — prove path reachability and compute concrete inputs |
| 24 | `taint_trace` | Radare2 + angr | Data-flow taint analysis from sources to sinks |

---

### 🔐 Source Code Audit Plugin (1 tool)

| # | Tool | Backend | Description |
|---|---|---|---|
| 25 | `audit_source_code` | AST + Regex | Python AST scanning + C/C++ regex scanning for dangerous patterns |

---

### 🛠️ Common Utilities Plugin (20 tools)

**File Operations (5 tools)**

| # | Tool | Description |
|---|---|---|
| 26 | `run_file` | File type, architecture, and compiler fingerprinting |
| 27 | `copy_to_workspace` | Copy a file into the analysis workspace |
| 28 | `create_directory` | Create a directory in the workspace |
| 29 | `list_workspace` | List all files in the workspace |
| 30 | `scan_workspace` | Full workspace scan with file metadata |

**Patch Explanation (1 tool)**

| # | Tool | Description |
|---|---|---|
| 31 | `explain_patch` | Explain a binary patch in natural language |

**Assembler (1 tool)**

| # | Tool | Backend | Description |
|---|---|---|---|
| 32 | `assemble_instructions` | Keystone | Assemble instructions to machine code (x86, ARM, MIPS, etc.) |

**AI Memory Management (11 tools)**

These tools let the AI persist and recall findings across analysis sessions using an async SQLite database:

| # | Tool | Description |
|---|---|---|
| 33 | `create_memory_session` | Start a new memory session for an analysis |
| 34 | `store_analysis_finding` | Persist an analysis finding with tags |
| 35 | `query_analysis_memories` | Search past findings by query |
| 36 | `get_binary_analysis_context` | Retrieve all context for a specific binary |
| 37 | `tag_analysis_session` | Add tags to a session for organization |
| 38 | `search_memories_by_tag` | Find sessions/findings by tag |
| 39 | `delete_analysis_session` | Remove a session and its findings |
| 40 | `cleanup_expired_sessions` | Remove sessions older than a threshold |
| 41 | `list_analysis_sessions` | List all active sessions |
| 42 | `export_memory_store` | Export all memories to a portable format |
| 43 | `import_memory_store` | Import memories from an export file |

**Server Monitoring (2 tools)**

| # | Tool | Description |
|---|---|---|
| 44 | `get_server_health` | Uptime, memory usage, loaded tools, Python version |
| 45 | `get_tool_metrics` | Per-tool call counts, mean execution times, error rates, cache hit/miss |

---

### ⚙️ Radare2 & r2ghidra Plugin (30 tools)

All Radare2 tools use a thread-safe connection pool (`r2_pool.py`) that automatically manages r2pipe sessions.

| # | Tool | Description |
|---|---|---|
| 46 | `Radare2_open_file` | Open a binary file in Radare2 |
| 47 | `Radare2_close_file` | Close a Radare2 session |
| 48 | `Radare2_list_open_files` | List currently open files |
| 49 | `Radare2_analyze_binary` | Run full auto-analysis (`aaa`) |
| 50 | `Radare2_list_functions` | List all detected functions |
| 51 | `Radare2_disassemble_function` | Disassemble a specific function |
| 52 | `Radare2_disassemble_address` | Disassemble at a specific address |
| 53 | `Radare2_decompile_function` | Decompile via r2ghidra (Ghidra engine embedded in r2, no JVM needed) |
| 54 | `Radare2_list_exports` | List exported symbols |
| 55 | `Radare2_list_imports` | List imported functions |
| 56 | `Radare2_list_sections` | List binary sections with entropy |
| 57 | `Radare2_list_strings` | List strings found in the binary |
| 58 | `Radare2_find_cross_references` | Track function calls and data references |
| 59 | `Radare2_search_bytes` | Search for byte patterns in the binary |
| 60 | `Radare2_get_binary_info` | Get binary metadata (arch, format, endianness) |
| 61 | `Radare2_execute_command` | Execute a raw Radare2 command |
| 62 | `Radare2_esil_emulate` | ESIL emulation at a specific address |
| 63 | `Radare2_get_hexdump` | Hex dump at a virtual address |
| 64 | `Radare2_get_cfg_data` | Extract control flow graph data |
| 65 | `Radare2_generate_cfg_png` | Generate CFG as PNG image |
| 66 | `Radare2_generate_callgraph` | Generate function call graph |
| 67 | `Radare2_recover_structures` | Auto-recover C structs and persist to annotation database |
| 68 | `Radare2_decompile_with_r2ghidra` | High-quality C decompilation with caching |
| 69 | `Radare2_annotate_binary` | Add annotations to the binary |
| 70 | `Radare2_get_annotations` | Retrieve annotations |
| 71 | `Radare2_export_annotations` | Export annotations to file |
| 72 | `Radare2_import_annotations` | Import annotations from file |
| 73 | `Radare2_detect_crypto_constants` | Detect cryptographic constants (AES S-box, etc.) |
| 74 | `Radare2_find_gadgets` | Find ROP/JOP gadgets |
| 75 | `Radare2_calculate_entropy` | Calculate per-section entropy |

---

### 🦠 Malware Analysis Plugin (9 tools)

| # | Tool | Backend | Description |
|---|---|---|---|
| 76 | `dormant_detector` | Radare2 + heuristics | Find hidden backdoors, orphan functions, time-bombs, logic bombs |
| 77 | `adaptive_vaccine` | YARA + Radare2 | Generate detection YARA rules + binary patches to neutralize threats |
| 78 | `vulnerability_hunter` | Radare2 + analysis | Detect dangerous API patterns (strcpy, sprintf) and ROP gadget chains |
| 79 | `extract_iocs` | Regex + LIEF | Extract IPs, URLs, domains, hashes, registry keys, crypto addresses |
| 80 | `run_yara` | YARA | Scan with custom rule files and built-in rulesets |
| 81 | `generate_poc_exploit` | pwntools | Generate proof-of-concept exploit code |
| 82 | `build_rop_chain` | ROPgadget + pwntools | Automated ROP chain construction |
| 83 | `autonomous_vuln_hunt` | Radare2 + angr | Autonomous vulnerability hunting pipeline |
| 84 | `analyze_heap_exploit` | Radare2 + heuristics | Heap exploitation analysis (UAF, double-free, overflow) |

---

### 🕵️ Digital Forensics Plugin (22 tools)

**Memory Forensics (6 tools)**

| # | Tool | Backend | Description |
|---|---|---|---|
| 85 | `memory_analyze` | Volatility3 | Full memory dump analysis |
| 86 | `memory_list_processes` | Volatility3 | List running processes from memory dump |
| 87 | `memory_detect_injections` | Volatility3 | Detect code injection in process memory |
| 88 | `memory_extract_strings` | Volatility3 | Extract strings from process memory |
| 89 | `memory_dump_module` | Volatility3 | Dump a loaded module from memory |
| 90 | `memory_list_symbols` | Volatility3 | List symbols from memory |

**Disk Forensics (6 tools)**

| # | Tool | Backend | Description |
|---|---|---|---|
| 91 | `disk_list_partition` | Sleuth Kit | List disk partitions |
| 92 | `disk_list_files` | Sleuth Kit | List files in a disk image |
| 93 | `disk_recover_deleted` | Sleuth Kit | Recover deleted files |
| 94 | `disk_analyze_mft` | Sleuth Kit | Analyze NTFS Master File Table |
| 95 | `disk_extract_file` | Sleuth Kit | Extract a file from disk image |
| 96 | `disk_hash_verify` | Sleuth Kit | Verify file integrity via hash |

**Network Forensics (5 tools)**

| # | Tool | Backend | Description |
|---|---|---|---|
| 97 | `pcap_analyze` | Scapy | PCAP analysis: protocol breakdown, anomalies |
| 98 | `pcap_list_connections` | Scapy | List all network connections |
| 99 | `pcap_extract_dns` | Scapy | Extract DNS queries and responses |
| 100 | `pcap_extract_c2` | Scapy | Identify potential C2 communication |
| 101 | `pcap_reconstruct_stream` | Scapy | Reconstruct TCP streams |

**Artifact Analysis (5 tools)**

| # | Tool | Backend | Description |
|---|---|---|---|
| 102 | `artifact_collect` | Custom parsers | Collect browser history, registry hives, event logs, prefetch |
| 103 | `artifact_correlate_ioc` | Custom parsers | Correlate artifacts with known IOCs |
| 104 | `artifact_generate_yara` | YARA | Generate YARA rules from artifact patterns |
| 105 | `artifact_timeline` | Custom parsers | Build timeline from multiple artifact sources |
| 106 | `artifact_report` | Custom parsers | Generate artifact analysis report |

---

### 📝 Report Generation Plugin (14 tools)

| # | Tool | Description |
|---|---|---|
| 107 | `get_system_time` | Get server timestamp (prevents AI from hallucinating dates) |
| 108 | `set_timezone` | Set the reporting timezone |
| 109 | `get_timezone_info` | Get current timezone information |
| 110 | `start_report_session` | Start a timed analysis session with unique ID |
| 111 | `end_report_session` | Finalize session: compute duration, lock IOC/ATT&CK lists |
| 112 | `get_report_session_status` | Check session status |
| 113 | `list_report_sessions` | List all active/completed sessions |
| 114 | `add_ioc` | Collect and tag IOCs during a live session |
| 115 | `add_analysis_note` | Add categorized notes (finding, warning, behavior) |
| 116 | `add_mitre_technique` | Document MITRE ATT&CK technique IDs |
| 117 | `set_severity` | Set session severity (low/medium/high/critical) |
| 118 | `create_analysis_report` | Render report in 4 modes: `full_analysis`, `quick_triage`, `ioc_summary`, `executive_brief` |
| 119 | `generate_vex_report` | Generate a VEX (Vulnerability Exploitability eXchange) report |
| 120 | `generate_sigma_rule` | Generate SIGMA detection rules |

---

## Guided Analysis Prompts (22 Modes)

Prompts are pre-built analysis workflows that prime the AI with a structured persona, step-by-step tool usage sequences, and evidence classification rules. You activate them by referencing the prompt name in your AI client.

### Malware Analysis (9 prompts)

| Prompt | Use Case |
|---|---|
| `full_analysis_mode` | 6-phase comprehensive analysis: triage → disassembly → behavior → network → persistence → report |
| `malware_analysis_mode` | Focused malware analysis with threat classification |
| `basic_analysis_mode` | Rapid triage for initial assessment and quick verdicts |
| `apt_hunting_mode` | APT-specific hunting: lateral movement, persistence, data exfiltration |
| `malware_defense_mode` | Defense-oriented: generate detection rules and mitigations |
| `unpacking_mode` | Analyze and bypass packing/obfuscation (Themida, VMProtect, UPX) |
| `c2_extraction_mode` | Extract and analyze C2 communication infrastructure |
| `ransomware_triage_mode` | Ransomware-specific triage: encryption analysis, key recovery assessment |
| `code_similarity_mode` | Compare binaries for code similarity and shared lineage |

### Security Research (6 prompts)

| Prompt | Use Case |
|---|---|
| `vulnerability_research_mode` | Bug hunting: buffer overflows, UAF, command injection |
| `crypto_analysis_mode` | Cryptographic implementation analysis and weakness detection |
| `firmware_analysis_mode` | IoT/embedded firmware: binwalk extraction, UART strings, hardcoded credentials |
| `patch_analysis_mode` | Security patch analysis and regression testing |
| `source_code_audit_mode` | Source code security audit (Python, C, C++) |
| `autonomous_vuln_hunt_mode` | Autonomous vulnerability hunting pipeline |

### CVE Research & Exploit Development (5 prompts)

| Prompt | Use Case |
|---|---|
| `taint_analysis_mode` | Data-flow taint analysis: automated source→sink path discovery |
| `heap_exploit_mode` | Heap exploitation analysis and PoC generation |
| `fuzzing_mode` | Fuzzing campaign setup and crash triage |
| `patch_diff_auto_mode` | Automated patch diff for 1-day vulnerability research |
| `cve_discovery_pipeline_mode` | Full CVE discovery pipeline: from patch diff to working exploit |

### Other (2 prompts)

| Prompt | Use Case |
|---|---|
| `game_analysis_mode` | Game client analysis: anti-cheat detection, protocol RE, memory inspection |
| `report_generation_mode` | Structured session workflow with MITRE ATT&CK technique mapping |

> **How prompts work:** Each prompt primes the AI with a structured analysis persona. It includes Chain-of-Thought reasoning checkpoints (where the AI must stop and evaluate before proceeding) and evidence classification rules that prevent the AI from stating speculation as fact. Every finding must be labeled as `OBSERVED` (directly verified), `INFERRED` (logically derived from static analysis), or `POSSIBLE` (requires further verification).

---

## MCP Resources (11 URIs)

Resources are read-only data endpoints that AI clients can access through URI templates. They complement tools by providing structured data without requiring explicit tool calls.

### Static Resources

| URI | Description |
|---|---|
| `reversecore://guide` | Tool usage guide with file path rules and best practices |
| `reversecore://guide/structures` | Structure recovery and cross-reference analysis technical guide |
| `reversecore://tools` | Complete documentation for all 120 registered tools |
| `reversecore://logs` | Application logs (last 100 lines) |

### Dynamic Resources (Per-Binary Virtual Filesystem)

These URIs resolve per-binary and invoke the corresponding analysis tools on demand:

| URI Template | Description |
|---|---|
| `reversecore://{filename}/strings` | Extract all strings from a binary |
| `reversecore://{filename}/iocs` | Extract IOCs (IPs, URLs, emails, hashes) |
| `reversecore://{filename}/func/{address}/code` | Decompiled pseudo-C code for a function |
| `reversecore://{filename}/func/{address}/asm` | Disassembly for a function |
| `reversecore://{filename}/func/{address}/cfg` | Control flow graph in Mermaid format |
| `reversecore://{filename}/functions` | List of all functions in the binary |
| `reversecore://{filename}/dormant_detector` | Dormant detector analysis results |

---

## Quick Start

### Option 1 — PyPI (Simplest)

```bash
pip install reversecore-mcp
reversecore-mcp
```

> **Prerequisites:** Radare2 must be installed on your system (`r2 --version`). YARA is installed automatically via `yara-python`.

### Option 2 — Docker (Recommended for Full Functionality)

All analysis engines (Radare2, r2ghidra, YARA, Binwalk, Sleuth Kit, GDB, etc.) come pre-installed:

```bash
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

### Option 3 — Build from Source (Docker Compose)

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
./scripts/run-docker.sh        # auto-detects Intel / Apple Silicon
```

Or manually:
```bash
docker compose --profile x86 up -d    # Intel/AMD
docker compose --profile arm64 up -d  # Apple Silicon (M1/M2/M3)
```

### Option 4 — Python (Local Development)

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m reversecore_mcp.server
```

> **Prerequisites for local mode:** Radare2 must be installed on your system (`r2 --version`). Individual tool backends (YARA, LIEF, Capstone, etc.) are installed via pip. For full forensics support, you'll also need Volatility3, Scapy, and Sleuth Kit.

---

## Connect to Your AI Client

Add the server configuration to your IDE client settings (e.g., `~/.cursor/mcp.json` or `claude_desktop_config.json`).

### ⚡ Option 1: Docker Exec Mode (Recommended)

If you have the container running via Docker Compose, this mode channels stdio directly into the running container. Zero startup latency, persistent memory, and full tool availability.

```json
{
  "mcpServers": {
    "Reversecore_MCP": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "reversecore-mcp-arm64",
        "python",
        "-m",
        "reversecore_mcp.server"
      ]
    }
  }
}
```

> Replace `reversecore-mcp-arm64` with `reversecore-mcp` if you are on Intel/AMD.

---

### 🌐 Option 2: SSE HTTP Mode

For network-based streaming (Server-Sent Events):

```json
{
  "mcpServers": {
    "Reversecore_MCP": {
      "url": "http://localhost:8000/mcp/sse"
    }
  }
}
```

---

### 📦 Option 3: Stdio Mode (Docker-on-Demand)

Runs a fresh, isolated container for every session:

<details>
<summary>🍎 macOS</summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/Users/YOUR_USERNAME/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:latest"
      ]
    }
  }
}
```

</details>

<details>
<summary>🐧 Linux</summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/YOUR_USERNAME/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:latest"
      ]
    }
  }
}
```

</details>

<details>
<summary>🪟 Windows</summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "C:/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:latest"
      ]
    }
  }
}
```

</details>

> **⚠️ Important — File Paths Inside Docker**
>
> Your local folder is mounted to `/app/workspace` inside the container.
> Always reference files by **filename only**, not by your local full path.
>
> | ❌ Wrong | ✅ Correct |
> |---|---|
> | `r2_decompile("/Users/john/samples/mal.exe")` | `r2_decompile("mal.exe")` |

---

## Configuration

All settings can be provided via environment variables or a `.env` file (see [`.env.example`](.env.example)). Settings are managed via Pydantic BaseSettings with the `REVERSECORE_` prefix.

### Core Settings

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `REVERSECORE_WORKSPACE` | `./` (cwd) | Analysis workspace directory |
| `REVERSECORE_READ_DIRS` | `""` | Comma-separated list of additional read-only directories |
| `REVERSECORE_STRICT_PATHS` | `false` | Raise errors for missing paths instead of warnings |
| `REVERSECORE_STRUCTURED_ERRORS` | `false` | Enable structured error responses with error codes |
| `REVERSECORE_DEFAULT_TOOL_TIMEOUT` | `120` | Default tool execution timeout in seconds |
| `REVERSECORE_MAX_OUTPUT_SIZE` | `10000000` | Maximum output size for tools (bytes) |

### HTTP Mode Settings

| Variable | Default | Description |
|---|---|---|
| `MCP_HOST` | `0.0.0.0` | Host interface to bind (auto-overrides to `127.0.0.1` if no API key) |
| `MCP_PORT` | `8000` | Port for HTTP server |
| `MCP_API_KEY` | *(unset)* | API key for HTTP authentication (`X-API-Key` or `Authorization: Bearer`) |
| `REVERSECORE_RATE_LIMIT` | `60` | Max requests per minute (HTTP mode only, via slowapi) |
| `MAX_UPLOAD_SIZE` | `100000000` | Maximum upload size (100 MB default) |
| `FILE_RETENTION_MINUTES` | `1440` | Retention period for uploaded files (24h default) |

### Radare2 Settings

| Variable | Default | Description |
|---|---|---|
| `REVERSECORE_R2_POOL_SIZE` | `3` | Number of Radare2 connections in the pool |
| `REVERSECORE_R2_POOL_TIMEOUT` | `30` | Timeout for acquiring a connection from the pool |
| `REVERSECORE_R2_EXTENSIONS` | `""` | Comma-separated list of r2 extension classes (`module:ClassName`) |
| `REVERSECORE_GHIDRA_MAX_PROJECTS` | `3` | Max cached r2ghidra decompiler projects |
| `REVERSECORE_GHIDRA_EXTENSIONS` | `""` | Comma-separated list of Ghidra extension classes |
| `MAX_EMULATION_INSTRUCTIONS` | `1000` | Maximum ESIL emulation instructions |

### Sandbox Settings

| Variable | Default | Description |
|---|---|---|
| `REVERSECORE_SANDBOX_ENABLED` | `false` | Enable sandbox execution for dynamic analysis tools |
| `REVERSECORE_SANDBOX_MODE` | `auto` | Sandbox mode: `auto`, `host`, `container`, `disabled` |
| `REVERSECORE_SANDBOX_DOCKER_IMAGE` | `reversecore-sandbox:latest` | Docker image for sandbox execution |
| `REVERSECORE_SANDBOX_CPU_LIMIT` | `1.0` | CPU core limit for sandbox containers |
| `REVERSECORE_SANDBOX_MEMORY_LIMIT` | `512m` | Memory limit for sandbox containers |
| `REVERSECORE_SANDBOX_PIDS_LIMIT` | `100` | PID limit for sandbox containers |
| `REVERSECORE_SANDBOX_USER` | `nobody` | Non-root user for sandbox execution |

### Storage & Queue

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL for task queue and result caching |
| `MEMORY_DB_PATH` | `~/.reversecore_mcp/memory.db` | Path to AI memory SQLite database |
| `REVERSECORE_LIEF_MAX_FILE_SIZE` | `1000000000` | Maximum file size for LIEF parsing (1 GB) |

### Logging

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LOG_FILE` | `<tempdir>/reversecore/app.log` | Path to log file |
| `LOG_FORMAT` | `human` | Log format: `human` (readable) or `json` (structured) |

### Plugins & SAST

| Variable | Default | Description |
|---|---|---|
| `REVERSECORE_PLUGIN_DIRS` | `""` | Comma-separated directories to scan for extension plugins |
| `REVERSECORE_SAST_RULES_PATH` | `""` | Path to custom YAML SAST rules file |

---

## Security Model

Security is implemented as defense-in-depth, with protections at multiple layers:

### Input & Path Safety

| Control | Implementation |
|---|---|
| **No shell injection** | All subprocess calls use list arguments, never shell strings (`execution.py`) |
| **Path traversal prevention** | `validate_file_path()` and `validate_binary_path()` resolve symlinks and confine access to the workspace (`validators.py`) |
| **TOCTOU mitigation** | `bypass_cache=True` flag re-validates paths to prevent race conditions |
| **Input sanitization** | All parameters sanitized before execution (`security.py`) |
| **CSRF protection** | Dashboard forms require token-based CSRF validation (`dashboard/__init__.py`) |

### Network & Authentication

| Control | Implementation |
|---|---|
| **Timing-attack-safe auth** | `secrets.compare_digest()` for API key comparison (`web/auth.py`) |
| **Restricted auth vectors** | Only `X-API-Key` and `Authorization: Bearer` headers accepted; no query params or cookies |
| **Loopback-only fallback** | Without `MCP_API_KEY`, HTTP access restricted to `127.0.0.1` (`web/middleware.py`) |
| **Rate limiting** | Configurable per-minute limits via slowapi |
| **Security headers** | HSTS, X-Content-Type-Options, X-Frame-Options, CSP on all HTTP responses (`web/middleware.py`) |
| **Minimized `/health`** | Public endpoint returns only `{"status": "alive"}`; details behind authentication (`web/endpoints.py`) |

### Container & Runtime

| Control | Implementation |
|---|---|
| **Non-root execution** | Runs as `appuser` (UID 1000) with minimal capabilities |
| **Resource limits** | Docker Compose enforces CPU (2.0) and memory (4 GB) limits |
| **Sandbox isolation** | Optional container-based sandboxing for dynamic analysis tools |

### CI/CD Security Gates

| Control | Implementation |
|---|---|
| **Secrets scanning** | Gitleaks runs on every commit (pre-commit hook + CI) |
| **SAST** | Bandit scans all Python code on every commit |
| **CodeQL** | GitHub CodeQL static analysis on every push to `main` |
| **Dependency auditing** | pip-audit on every push — no unreviewed CVEs |
| **Container scanning** | Trivy scans Docker images for vulnerabilities (LOW through CRITICAL) |
| **Exploit safety gate** | POC templates scanned with Bandit; Hypothesis DAST fuzzing; container isolation verified |

### Structured Error Handling

All 17 exception classes carry `RCMCP-E*` error codes for programmatic handling. See [Error Handling](#error-handling) for the full hierarchy.

---

## Development

### Setup

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install   # installs Ruff, Bandit, Gitleaks hooks
```

### Testing

```bash
# Full test suite with coverage report
pytest tests/ -v

# Unit tests only (fast, no external dependencies)
pytest tests/unit/ -v

# Integration tests (requires Docker)
pytest tests/integration/ -v

# Run with coverage threshold enforcement
pytest tests/unit/ --cov=reversecore_mcp --cov-fail-under=80

# Run a specific test
pytest tests/unit/test_cli_tools.py::TestRunFile::test_success -v

# Security boundary tests
pytest tests/ -m security -v

# Benchmarks
pytest tests/ -m benchmark -v
```

**Test status:**
- ✅ **1,957 unit tests** passing across Python 3.10 / 3.11 / 3.12
- 📊 **87% code coverage** (80% minimum enforced in CI)
- 🔒 Zero Bandit findings
- ⚡ Fully async test suite via `pytest-asyncio`

**Test markers:**

| Marker | Purpose |
|---|---|
| `@pytest.mark.unit` | Fast unit tests |
| `@pytest.mark.integration` | Tests requiring Docker or external tools |
| `@pytest.mark.slow` | Long-running tests |
| `@pytest.mark.benchmark` | Performance benchmarks |
| `@pytest.mark.security` | Security boundary validation tests |

### Code Quality

```bash
ruff check reversecore_mcp/      # Lint (E, W, F, I, B, C4, UP rules)
ruff format reversecore_mcp/     # Format
mypy reversecore_mcp/            # Type check (0 errors across 108 files)
bandit -r reversecore_mcp/       # Security scan (all severities)
pip-audit                        # Dependency CVE scan
```

### Pre-commit Hooks

The following hooks run automatically on every commit:

1. **Ruff** — lint with auto-fix + format check
2. **trailing-whitespace** — remove trailing whitespace
3. **end-of-file-fixer** — ensure files end with newline
4. **check-yaml / check-json** — validate YAML/JSON syntax
5. **check-added-large-files** — block files > 1 MB
6. **check-merge-conflict** — detect unresolved merge markers
7. **detect-private-key** — prevent accidental key commits
8. **Bandit** — Python security scanning

---

## CI/CD Pipeline

Every push to `main` triggers 11 pipeline jobs. All must pass before deployment.

```
 Lint & Security Gate              Unit Tests (Python Matrix)
   ├─ Gitleaks (secret scan)         ├─ pytest 3.10 --cov-fail-under=80
   ├─ Hadolint (Dockerfile lint)     ├─ pytest 3.11 --cov-fail-under=80
   ├─ Ruff check + format            └─ pytest 3.12 --cov-fail-under=80
   ├─ Mypy type check (108 files)
   ├─ Bandit (all severities)      Wheel Smoke Test
   ├─ pip-audit (no CVEs)            └─ Build wheel → install in /tmp
   └─ Security boundary tests            → verify plugin discovery
                                          → assert __file__ under sys.prefix
 CodeQL Analysis
   └─ Python SAST                  Docker Verification
                                     ├─ Build reversecore-mcp:ci
 Exploit Safety Gate                 ├─ Trivy container scan
   ├─ Bandit on POC templates        ├─ Image size check (< 5 GB)
   ├─ Hypothesis DAST fuzzing        ├─ CLI tool verification
   ├─ Performance benchmarks         ├─ Integration tests in container
   └─ Container isolation test       └─ E2E tool invocation

 In-Container Smoke Test           Build Base Image (amd64 + arm64)
   ├─ Copy test ELF into container   ├─ Compile YARA 4.3.1
   └─ Run scripts/smoke_test.py     ├─ Compile Radare2 6.0.4
                                     ├─ Compile r2ghidra
 Deploy (amd64 + arm64)             └─ Push to GHCR
   ├─ Build app image
   ├─ Push to GHCR                 Merge Manifests
   └─ Trivy rescan on published     └─ Multi-arch manifest → :latest
```

> **Zero-bypass policy:** CI/CD failures are never resolved by modifying pipeline configuration. Root causes are always fixed directly in source code or dependencies.

---

## Docker Build Architecture

The Docker build uses a two-layer approach to keep build times manageable:

### Layer 1: Base Image (`Dockerfile.base`)

A multi-stage build that compiles all slow-to-build, rarely-changing dependencies from source:

```
compiler-toolchain (python:3.12-slim-bookworm + build tools)
    ├── compiler-yara      (YARA 4.3.1 from source)     [parallel]
    ├── compiler-r2        (Radare2 6.0.4 from source)   [parallel]
    │     └── compiler-r2ghidra  (r2ghidra plugin)       [sequential]
    └── compiler-pip       (pip install into /opt/venv)  [parallel]

base (final runtime: python:3.12-slim-bookworm)
    ├── Runtime packages: file, binutils, gdb, binwalk, graphviz, nasm, sleuthkit
    ├── /opt/yara (compiled YARA)
    ├── /opt/radare2 (compiled r2 + r2ghidra)
    ├── /opt/venv (Python packages)
    └── Non-root user: appuser (UID 1000)
```

This image is rebuilt only when tool versions change. Build time: ~12 minutes.

### Layer 2: Application Image (`Dockerfile`)

Inherits from the base image and copies application code:

```
FROM base image
    ├── COPY reversecore_mcp/ (application code)
    ├── COPY scripts/ (smoke test, benchmarks)
    ├── pip install any new requirements
    ├── Security package upgrades
    └── CMD ["python", "-m", "reversecore_mcp.server"]
```

Build time: ~60 seconds.

### Docker Compose

Three services with architecture-specific profiles:

| Service | Profile | Description |
|---|---|---|
| `reversecore-mcp` | `default`, `x86` | Intel/AMD x86_64 |
| `reversecore-mcp-arm64` | `arm64`, `macos` | Apple Silicon ARM64 |
| `redis` | all profiles | Redis 7 Alpine for task queue and caching |

Resource limits: 2.0 CPU cores, 4 GB memory per container.

---

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Storage | 20 GB | 50 GB SSD |
| OS | Linux / macOS | Docker environment (any OS) |
| Docker | 20.10+ | 24.0+ |
| Python (local mode) | 3.10 | 3.11 or 3.12 |

---

## Project Structure

```
reversecore_mcp/
├── core/                          # Infrastructure layer (37 modules)
│   ├── config.py                  # Pydantic BaseSettings (34+ env vars)
│   ├── exceptions.py              # Exception hierarchy (17 classes, RCMCP-E* codes)
│   ├── security.py                # Input sanitization & command arg validation
│   ├── validators.py              # Path validators (TOCTOU-hardened, symlink-safe)
│   ├── r2_pool.py                 # Thread-safe Radare2 connection pool
│   ├── r2_helpers.py              # Structured Radare2 output parsing
│   ├── metrics.py                 # Per-tool timing, counts, error rates, cache stats
│   ├── decorators.py              # @log_execution, @track_metrics
│   ├── error_handling.py          # @handle_tool_errors decorator
│   ├── error_formatting.py        # Structured error formatting
│   ├── execution.py               # Safe subprocess with timeout/output limits
│   ├── command_spec.py            # Command specifications
│   ├── memory.py                  # Async SQLite AI memory store
│   ├── mitre_mapper.py            # MITRE ATT&CK mapping engine
│   ├── evidence.py                # Evidence classification (OBSERVED/INFERRED/POSSIBLE)
│   ├── resilience.py              # Retry, circuit-breaker, timeout patterns
│   ├── task_queue.py              # Background task queue (Redis + arq)
│   ├── extension_registry.py      # Plugin registration system
│   ├── arch_registry.py           # Multi-arch mapping (x86/ARM/MIPS/RISC-V/PPC)
│   ├── result_cache.py            # SHA256-based tool result caching
│   ├── analysis_cache.py          # Multi-level decompilation cache (Redis + SQLite)
│   ├── result.py                  # ToolSuccess / ToolError Pydantic models
│   ├── loader.py                  # Dynamic tool module loader
│   ├── plugin.py                  # Plugin base class
│   ├── extension.py               # Extension base class
│   ├── container.py               # Container/sandbox execution
│   ├── audit.py                   # Audit logging
│   ├── binary_cache.py            # Binary file caching
│   ├── json_utils.py              # orjson-backed JSON (3-5x faster)
│   ├── logging_config.py          # Loguru logging configuration
│   ├── report_generator.py        # Report rendering (Markdown, PDF)
│   ├── resource_manager.py        # MCP resource lifecycle
│   └── sast/                      # Source code scanners
│       ├── python_ast_scanner.py  # Python AST vulnerability scanner
│       ├── regex_scanner.py       # C/C++ regex vulnerability scanner
│       ├── rule_manager.py        # SAST rule loader
│       └── default_rules.yaml     # Default scanning rules
│
├── tools/                         # MCP tool implementations (120 tools)
│   ├── analysis/                  # Static analysis (24 tools)
│   │   ├── static_analysis.py     # file, strings, binwalk
│   │   ├── lief_tools.py          # LIEF binary parser
│   │   ├── capa_tools.py          # CAPA capability detection
│   │   ├── die_tools.py           # Detect It Easy packer detection
│   │   ├── diff_tools.py          # Binary diffing
│   │   ├── emulation_tools.py     # ESIL emulation
│   │   ├── fuzz_tools.py          # Fuzzing harness generator
│   │   ├── fuzzing_campaign.py    # Full fuzzing campaign runner
│   │   ├── symbolic_analysis.py   # angr symbolic execution
│   │   ├── signature_tools.py     # Library signature matching
│   │   ├── source_auditor.py      # SAST (Python + C/C++)
│   │   ├── crash_triage.py        # GDB crash triage
│   │   ├── taint_analysis.py      # Source→sink taint tracing
│   │   ├── advanced_yara.py       # Advanced YARA generation
│   │   ├── patch_vuln_inference.py # Patch vulnerability inference
│   │   └── cache_tools.py         # Analysis cache management
│   │
│   ├── radare2/                   # Disassembly & decompilation (30 tools)
│   │   ├── radare2_mcp_tools.py   # Core Radare2 tool set
│   │   ├── r2ghidra_tools.py      # r2ghidra decompiler (cached)
│   │   ├── r2_analysis.py         # Deep function analysis
│   │   ├── r2_db.py               # SQLite annotation + cache DB
│   │   ├── r2_esil_simulator.py   # Multi-arch ESIL simulator
│   │   └── r2_session.py          # Stateful analysis sessions
│   │
│   ├── malware/                   # Threat detection (9 tools)
│   │   ├── dormant_detector.py    # Backdoor/logic bomb detection
│   │   ├── ioc_tools.py           # IOC extraction
│   │   ├── yara_tools.py          # YARA scanning
│   │   ├── adaptive_vaccine.py    # YARA rule + patch generation
│   │   ├── vulnerability_hunter.py # Dangerous API detection
│   │   ├── autonomous_hunter.py   # Autonomous vuln hunting pipeline
│   │   ├── heap_exploit.py        # Heap exploitation analysis
│   │   ├── poc_generator.py       # PoC exploit generation
│   │   └── rop_builder.py         # ROP chain construction
│   │
│   ├── forensics/                 # Digital forensics (22 tools)
│   │   ├── memory.py              # Volatility3 memory forensics
│   │   ├── network.py             # Scapy PCAP analysis
│   │   ├── disk.py                # Sleuth Kit disk forensics
│   │   └── artifact.py            # Browser/registry/event log analysis
│   │
│   ├── report/                    # Report generation (14 tools)
│   │   ├── report_mcp_tools.py    # MCP-registered report tools
│   │   ├── report_tools.py        # Report rendering logic
│   │   ├── session.py             # Session state management
│   │   ├── converter.py           # Format conversion (Markdown → PDF/HTML)
│   │   ├── email.py               # SMTP report delivery
│   │   ├── sigma_generator.py     # SIGMA rule generation
│   │   └── vex_generator.py       # VEX report generation
│   │
│   └── common/                    # Shared utilities (20 tools)
│       ├── file_operations.py     # File ops, workspace management
│       ├── server_tools.py        # Server health, tool metrics
│       ├── memory_tools.py        # AI memory management (11 tools)
│       ├── patch_explainer.py     # Binary patch explanation
│       └── assembler.py           # Keystone assembler
│
├── prompts/                       # AI reasoning prompts (22 modes)
│   ├── malware.py                 # 9 malware analysis prompts
│   ├── security.py                # 6 security research prompts
│   ├── cve_research.py            # 5 CVE/exploit research prompts
│   ├── game.py                    # Game client analysis prompt
│   ├── report.py                  # Report generation prompt
│   ├── server_health.py           # Server inspection prompts
│   └── common.py                  # Shared constants (DOCKER_PATH_RULE, LANGUAGE_RULE)
│
├── dashboard/                     # Web dashboard (FastAPI + HTMX)
│   ├── templates/                 # Jinja2 templates with HTMX fragments
│   └── static/                    # htmx.min.js (local, CSP-compliant)
│
├── web/                           # HTTP transport layer
│   ├── auth.py                    # API key authentication middleware
│   ├── middleware.py              # Security headers, loopback restriction
│   └── endpoints.py               # /health, file upload, dashboard routes
│
├── resources.py                   # 11 MCP resources (static + dynamic per-binary)
└── server.py                      # FastMCP server entry point
```

**Other directories:**

```
tests/
├── unit/                          # 1,957 unit tests
├── integration/                   # Docker-based integration tests
├── fixtures/                      # Test binaries, YARA rules, sample data
└── conftest.py                    # Shared pytest fixtures

scripts/
├── smoke_test.py                  # Multi-layer in-container smoke test
├── check_release_metadata.py      # Version consistency validation
├── fetch_test_binaries.py         # Download test fixtures
├── run-docker.sh                  # Auto-detect architecture and start
└── ...                            # Benchmarks, analysis scripts

docs/
├── getting-started/               # Installation guide
├── development/                   # Architecture, contributing, testing guides
├── api/                           # Tool and module reference
└── user-guide/                    # Analysis workflows
```

---

## Error Handling

All custom exceptions inherit from `ReversecoreError` and carry structured error codes:

| Exception | Code | Type | When |
|---|---|---|---|
| `ReversecoreError` | `RCMCP-E000` | `UNKNOWN_ERROR` | Base class for all errors |
| `ValidationError` | `RCMCP-E001` | `VALIDATION_ERROR` | Invalid input, bad parameters |
| `ExecutionTimeoutError` | `RCMCP-E002` | `TIMEOUT_ERROR` | Tool exceeded timeout |
| `ToolNotFoundError` | `RCMCP-E003` | `TOOL_ERROR` | Required CLI tool not installed |
| `OutputLimitExceededError` | `RCMCP-E004` | `OUTPUT_ERROR` | Output exceeded max size |
| `ToolExecutionError` | `RCMCP-E005` | `EXECUTION_ERROR` | Subprocess returned non-zero |
| `BinaryAnalysisError` | `RCMCP-E100` | `BINARY_ANALYSIS_ERROR` | General binary analysis failure |
| `DecompilationError` | `RCMCP-E101` | `DECOMPILATION_ERROR` | r2ghidra decompilation failed |
| `DisassemblyError` | `RCMCP-E102` | `DISASSEMBLY_ERROR` | Radare2 disassembly failed |
| `StructureRecoveryError` | `RCMCP-E103` | `STRUCTURE_RECOVERY_ERROR` | C struct recovery failed |
| `SignatureGenerationError` | `RCMCP-E104` | `SIGNATURE_GENERATION_ERROR` | YARA/signature generation failed |
| `EmulationError` | `RCMCP-E105` | `EMULATION_ERROR` | ESIL emulation failed |
| `ToolTimeoutError` | `RCMCP-E200` | `TOOL_TIMEOUT_ERROR` | External tool timed out |
| `GhidraConnectionError` | `RCMCP-E201` | `GHIDRA_CONNECTION_ERROR` | r2ghidra connection issue |
| `Radare2Error` | `RCMCP-E202` | `RADARE2_ERROR` | Radare2 command failed |
| `WorkspaceError` | `RCMCP-E300` | `WORKSPACE_ERROR` | Workspace file access error |
| `SecurityViolationError` | `RCMCP-E301` | `SECURITY_VIOLATION` | Security policy violation |
| `PathTraversalError` | `RCMCP-E302` | `PATH_TRAVERSAL` | Path traversal attempt detected |

AI clients can use the `error_code` field to programmatically handle failures and decide whether to retry, try an alternative tool, or report the error to the user.

---

## Adding New Tools

Follow this pattern to add a new MCP tool:

```python
# reversecore_mcp/tools/analysis/my_tool.py

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path


@log_execution()
async def my_analysis_tool(
    file_path: str,
    option: str | None = None,
) -> ToolResult:
    """Analyze a binary for X.

    Args:
        file_path: Path to the binary file (relative to workspace).
        option: Optional analysis option.

    Returns:
        ToolResult with status='success' and structured content.
    """
    try:
        safe_path = validate_file_path(file_path)
        result = await perform_analysis(safe_path)
        return success({"result": result})
    except Exception as e:
        return failure(
            error_code="RCMCP-E100",
            message=str(e),
            hint="Check that the file exists and is a valid binary.",
        )
```

Then register it in the appropriate plugin's `__init__.py` and add tests in `tests/unit/`.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests alongside your code — coverage must not drop below 80%
4. Ensure all gates pass: `pytest`, `ruff check`, `mypy`, `bandit`
5. Open a pull request with a clear description

Please read the [Contributing Guide](docs/development/contributing.md) for code standards, docstring conventions (Google-style), and the pull request checklist.

---

## Documentation

| Document | Description |
|---|---|
| [Installation Guide](docs/getting-started/installation.md) | Detailed setup for all environments |
| [Architecture Guide](docs/development/architecture.md) | System design & component details |
| [Contributing Guide](docs/development/contributing.md) | Code standards, docstrings, PR workflow |
| [Testing Guide](docs/development/testing.md) | Test patterns, fixtures, and coverage |
| [API Reference](docs/api/) | Tool and module reference |
| [User Guide](docs/user-guide/) | Analysis workflows |

---

## Usage Examples

### Example 1: Basic Malware Triage

```
User: "Analyze this suspicious file sample.exe"

AI calls:
  1. run_file("sample.exe")           → PE32 executable, x86, MSVC
  2. detect_packer("sample.exe")      → Not packed
  3. extract_iocs("sample.exe")       → 3 IPs, 2 URLs, 1 mutex
  4. run_capa("sample.exe")           → "creates persistence", "encrypts data"
  5. dormant_detector("sample.exe")   → 2 orphan functions with network calls
  6. generate_yara_rule("sample.exe") → Detection rule generated

AI response: "This PE32 binary shows ransomware-like behavior. CAPA detected
encryption and persistence capabilities. I found 2 hidden network functions
that may serve as a backup C2 channel. Here's a YARA rule for detection..."
```

### Example 2: Vulnerability Research with Taint Analysis

```
User: "Find exploitable bugs in this network daemon"

AI activates: taint_analysis_mode

AI calls:
  1. taint_trace("daemon", verify_with_angr=True)
     → Found 3 source→sink paths:
       recv() → strcpy()   [CWE-120, CONFIRMED by angr]
       read() → sprintf()  [CWE-134, LIKELY]
       getenv() → system() [CWE-78, POSSIBLE]

  2. vulnerability_hunter("daemon")
     → 12 dangerous API calls, 4 exploitable patterns

  3. generate_poc_exploit(target="daemon", vuln_type="bof", offset=128)
     → Python exploit script generated

AI response: "I found a confirmed stack buffer overflow where recv() data
flows directly into strcpy() at 0x40123C. angr proved the path is reachable.
Here's a working PoC..."
```

### Example 3: Digital Forensics Investigation

```
User: "Analyze this memory dump from a compromised server"

AI calls:
  1. memory_list_processes("memdump.raw")
     → 47 processes, 2 with suspicious names

  2. memory_detect_injections("memdump.raw")
     → Code injection detected in PID 1842 (svchost.exe)

  3. memory_extract_strings("memdump.raw", pid=1842)
     → C2 domain strings extracted

  4. artifact_correlate_ioc(artifacts={"domains": ["evil-c2.com"]})
     → Matches known APT group IOCs

  5. create_analysis_report(template_type="full_analysis")
     → PDF report with timeline and MITRE ATT&CK mapping
```

### Example 4: Patch Diffing for 1-day Research

```
User: "Compare the patched and unpatched versions to find what was fixed"

AI activates: patch_diff_auto_mode

AI calls:
  1. diff_binaries("libfoo-1.0.so", "libfoo-1.1.so")
     → 3 functions changed, 1 new function

  2. patch_diff_1day("libfoo-1.0.so", "libfoo-1.1.so")
     → Automated analysis: bounds check added at parse_header()

  3. r2_decompile("libfoo-1.0.so", "parse_header")
     → Decompiled vulnerable version (no bounds check)

  4. r2_decompile("libfoo-1.1.so", "parse_header")
     → Decompiled patched version (memcpy size limited)

AI response: "The patch adds a bounds check in parse_header() at 0x12340.
The old version copies user-controlled length bytes via memcpy without
validation, creating a heap buffer overflow (CWE-122)."
```

---

## Multi-Architecture Support

The `arch_registry.py` module maps architecture names to Radare2 configuration parameters, enabling tools to work across different CPU architectures without manual configuration:

| Architecture | Key | r2 Arch | Bit Widths | PC Register | SP Register |
|---|---|---|---|---|---|
| Intel 32-bit | `x86` | `x86` | 32 | `eip` | `esp` |
| Intel/AMD 64-bit | `x86_64` | `x86` | 64 | `rip` | `rsp` |
| ARM 32-bit / Thumb | `arm32` | `arm` | 16, 32 | `r15` | `r13` |
| ARM 64-bit (AArch64) | `arm64` | `arm` | 64 | `pc` | `sp` |
| MIPS | `mips` | `mips` | 32, 64 | `pc` | `sp` |
| RISC-V | `riscv` | `riscv` | 32, 64 | `pc` | `sp` |
| PowerPC | `ppc` | `ppc` | 32, 64 | `pc` | `r1` |

**Alias resolution** is handled automatically:
- `amd64` → `x86_64`
- `aarch64` → `arm64`
- `arm` with `bits=64` → `arm64`
- `arm` with `bits=16` or `bits=32` → `arm32`

Tools like `Radare2_esil_emulate`, `assemble_instructions`, and `r2_simulate_patch` use this registry to configure the analysis environment correctly for any target binary.

---

## Result Cache System

Two caching layers minimize redundant computation:

### Tool Result Cache (`result_cache.py`)

The `@cache_tool_result` decorator caches any tool's output based on a SHA256 hash of the binary file and the tool's keyword arguments:

```
Cache key = SHA256( "<tool_name>::{sorted_json_kwargs}" )
```

**Storage backend:** SQLite database via `r2_db.py`, accessible through `get_cached_result()` and `set_cached_result()` tools.

**Metrics:** Cache hits and misses are tracked via `metrics_collector.record_cache_hit()` and `record_cache_miss()`, visible through the `get_tool_metrics` tool.

### Analysis Cache (`analysis_cache.py`)

A multi-level cache specifically for decompilation results (which are expensive to compute):

| Level | Backend | Key Format | TTL | Purpose |
|---|---|---|---|---|
| L1 | Redis | `ghidra:decompile:{file_hash}:{function_address}:{decompiler}` | 1 hour (3600s) | Fast, shared across sessions |
| L2 | SQLite | Table `decompilation_cache` | Persistent | Survives Redis restarts |

**Import/Export:** The `export_analysis_cache` and `import_analysis_cache` tools allow saving cache state to/from `rcpack` files for sharing between environments.

---

## AI Memory System

The AI memory system (`memory_tools.py` + `core/memory.py`) provides persistent, queryable storage for analysis findings across sessions. This allows the AI to:

- **Remember** what it previously found about a binary
- **Cross-reference** findings between different samples
- **Tag** and **search** sessions by topic, malware family, or technique

### How It Works

```
create_memory_session("analysis of ransomware sample")
    │
    ├── store_analysis_finding("Found AES-256 encryption at 0x401000", tags=["crypto", "ransomware"])
    ├── store_analysis_finding("C2 beacon interval: 30 seconds", tags=["c2", "network"])
    └── tag_analysis_session(tags=["ransomware", "financial-sector"])

# Later, in a different session:
query_analysis_memories("ransomware encryption")
    → Returns previous findings about ransomware encryption patterns

get_binary_analysis_context("sample.exe")
    → Returns all findings ever recorded for this binary
```

**Storage:** Async SQLite database at the path configured by `MEMORY_DB_PATH` (default: `~/.reversecore_mcp/memory.db`).

**Portability:** Use `export_memory_store` and `import_memory_store` to transfer the entire memory database between environments.

---

## Web Dashboard

When running in HTTP mode (`MCP_TRANSPORT=http`), a web dashboard is available at `http://localhost:8000/dashboard`. It provides:

- Binary upload with drag-and-drop
- Real-time analysis status
- Interactive function list and disassembly view
- IOC extraction results
- Server health monitoring

**Tech stack:** FastAPI + Jinja2 templates + HTMX (loaded locally from `dashboard/static/`, no CDN dependency for CSP compliance).

**Security features:**
- CSRF tokens on all state-changing forms
- Jinja2 auto-escaping enabled
- All user input sanitized via `html.escape()` before display
- Path traversal protection via `validate_file_path()`

---

## Deployment

### Production Checklist

Before deploying to production:

| Item | How |
|---|---|
| Set API key | `MCP_API_KEY=<strong-random-key>` |
| Use non-root user | Built-in: container runs as `appuser` (UID 1000) |
| Set resource limits | Default: 2 CPU / 4 GB RAM in `docker-compose.yml` |
| Enable structured logging | `LOG_FORMAT=json` for log aggregation |
| Configure Redis | `REDIS_URL=redis://<host>:6379/0` for task queue and caching |
| Set workspace path | `REVERSECORE_WORKSPACE=/path/to/isolated/directory` |
| Review rate limits | `REVERSECORE_RATE_LIMIT=60` (requests/min, adjust as needed) |
| Enable sandbox | `REVERSECORE_SANDBOX_ENABLED=true` for dynamic analysis isolation |

### Health Checks

The server provides HTTP health check endpoints for orchestration:

```bash
# Liveness (always 200 if process is running)
curl http://localhost:8000/health/live

# Readiness (checks tool availability)
curl http://localhost:8000/health/ready

# Full health (requires API key if configured)
curl -H "X-API-Key: <key>" http://localhost:8000/health
```

These endpoints are exempted from API key authentication so load balancers and container orchestrators can probe them.

### Container Healthcheck

The Docker image includes a built-in `HEALTHCHECK` instruction that verifies TCP connectivity to port 8000 every 30 seconds. Docker and Kubernetes will automatically restart unhealthy containers.

---

## Troubleshooting

### Common Issues

<details>
<summary><b>Tool returns RCMCP-E003: Tool not found</b></summary>

The required CLI tool is not installed in the environment.

**Solution:** If using Docker, verify the tool is in the base image:
```bash
docker exec reversecore-mcp-arm64 which r2 yara binwalk tsk_recover gdb
```

If using local Python installation, install the missing tool:
```bash
# macOS
brew install radare2 yara binwalk sleuthkit

# Ubuntu/Debian
apt install radare2 yara binwalk sleuthkit
```
</details>

<details>
<summary><b>Timeout error (RCMCP-E002 / RCMCP-E200)</b></summary>

Analysis exceeded the configured timeout.

**Solution:** Increase the timeout:
```bash
export REVERSECORE_DEFAULT_TOOL_TIMEOUT=300  # 5 minutes
```

For large binaries (>100 MB), consider using quick-scan variants:
- `run_capa_quick` instead of `run_capa`
- `detect_packer` instead of `detect_packer_deep`
</details>

<details>
<summary><b>Path traversal error (RCMCP-E302)</b></summary>

You referenced a file outside the workspace directory.

**Solution:** Copy the file into the workspace first:
```
copy_to_workspace("/path/to/file.exe")
```

Or mount additional directories as read-only:
```bash
export REVERSECORE_READ_DIRS=/opt/samples,/mnt/evidence
```
</details>

<details>
<summary><b>Docker container won't start on Apple Silicon</b></summary>

Make sure you're using the ARM64 profile:
```bash
docker compose --profile arm64 up -d
```

Or use the auto-detection script:
```bash
./scripts/run-docker.sh
```
</details>

<details>
<summary><b>Redis connection refused</b></summary>

The task queue requires a running Redis instance.

**Solution:** Start Redis alongside the main service:
```bash
docker compose --profile arm64 up -d   # Starts both reversecore and redis
```

Or disable Redis-dependent features by not setting `REDIS_URL`.
</details>

<details>
<summary><b>r2ghidra decompilation produces empty output</b></summary>

This usually means the function wasn't analyzed first.

**Solution:** Run analysis before decompilation:
```
Radare2_analyze_binary("sample.exe")
Radare2_decompile_function("sample.exe", "main")
```
</details>

---

## FAQ

<details>
<summary><b>Does this replace Ghidra or IDA Pro?</b></summary>

No. This project is a complement, not a replacement. It uses r2ghidra (the Ghidra decompiler engine embedded in Radare2) for decompilation. It does not provide a GUI, and it does not have the interactive analysis workflow of a full disassembler. Its purpose is to let AI assistants perform analysis tasks programmatically.
</details>

<details>
<summary><b>Is a separate Ghidra or JDK installation needed?</b></summary>

No. The r2ghidra plugin embeds the Ghidra decompiler engine directly inside Radare2. No JDK, no Ghidra installation, no Ghidra project files. Just `r2` with the `r2ghidra` plugin compiled in.
</details>

<details>
<summary><b>What MCP clients are supported?</b></summary>

Any client that implements the [Model Context Protocol](https://modelcontextprotocol.io/) specification. Tested with: Claude Desktop, Cursor, Windsurf, and Google Antigravity. The server supports both stdio and HTTP/SSE transports.
</details>

<details>
<summary><b>Can I analyze Windows PE files on Linux/macOS?</b></summary>

Yes. Static analysis (disassembly, decompilation, string extraction, IOC extraction, YARA scanning) works on any file format regardless of host OS. Dynamic analysis (emulation, fuzzing) may have limitations depending on the target architecture.
</details>

<details>
<summary><b>How safe is it to analyze malware with this tool?</b></summary>

The Docker container provides isolation: non-root user, no network by default in CI, resource limits. For live malware analysis, we recommend running in a dedicated VM or using the sandbox feature (`REVERSECORE_SANDBOX_ENABLED=true`). Static analysis tools (r2, YARA, strings) never execute the target binary.
</details>

<details>
<summary><b>What's the maximum file size?</b></summary>

Default limits:
- Upload: 100 MB (`MAX_UPLOAD_SIZE`)
- LIEF parsing: 1 GB (`REVERSECORE_LIEF_MAX_FILE_SIZE`)
- Tool output: 10 MB (`REVERSECORE_MAX_OUTPUT_SIZE`)

All limits are configurable via environment variables.
</details>

---

## Acknowledgments

This project is built on the work of many open-source projects:

| Project | Role in Reversecore MCP |
|---|---|
| [Radare2](https://radare.org/) | Disassembly, emulation, binary analysis |
| [r2ghidra](https://github.com/radareorg/r2ghidra) | Ghidra decompiler engine for Radare2 |
| [FastMCP](https://github.com/jlowin/fastmcp) | MCP server framework |
| [YARA](https://virustotal.github.io/yara/) | Pattern matching for malware detection |
| [LIEF](https://lief-project.github.io/) | Binary format parsing (PE, ELF, Mach-O) |
| [CAPA](https://github.com/mandiant/capa) | Mandiant FLARE capability detection |
| [angr](https://angr.io/) | Symbolic execution engine |
| [Capstone](https://www.capstone-engine.org/) | Disassembly framework |
| [Keystone](https://www.keystone-engine.org/) | Assembly framework |
| [pwntools](https://github.com/Gallopsled/pwntools) | Exploit development toolkit |
| [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) | ROP gadget finder |
| [Volatility3](https://github.com/volatilityfoundation/volatility3) | Memory forensics framework |
| [Scapy](https://scapy.net/) | Network packet analysis |
| [Sleuth Kit](https://sleuthkit.org/) | Disk forensics toolkit |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Firmware analysis |
| [Detect It Easy](https://github.com/horsicq/DIE-engine) | Packer/compiler detection |

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**[GitHub](https://github.com/sjkim1127/Reversecore_MCP)** · **[PyPI](https://pypi.org/project/reversecore-mcp/)** · **[FastMCP Docs](https://github.com/jlowin/fastmcp)** · **[MCP Spec](https://modelcontextprotocol.io/)** · **[Radare2](https://radare.org/)** · **[YARA](https://virustotal.github.io/yara/)**

</div>
