<div align="center">

<img src="icon.png" alt="Reversecore MCP" width="300" />

# Reversecore MCP

**AI-Powered Reverse Engineering & Security Analysis via Model Context Protocol**

*Enterprise-grade integrated static & dynamic analysis server — speak natural language, get expert-level reverse engineering, vulnerability triage, malware analysis, and forensics.*

---

[![CI/CD](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml/badge.svg)](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1520%20passed-brightgreen)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-82%25-green)](#testing)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13+-purple)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/sjkim1127/Reversecore_MCP/pkgs/container/reversecore_mcp)

[![Watch the Demo](https://img.shields.io/badge/▶_Watch_Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)
[![SafeSkill Verified](https://img.shields.io/badge/SafeSkill-93%2F100_Verified_Safe-brightgreen?style=for-the-badge)](https://safeskill.dev/scan/sjkim1127-reversecore-mcp)

</div>

---

## Table of Contents

- [What is Reversecore MCP?](#what-is-reversecore-mcp)
- [Architecture](#architecture)
- [Tool Catalog (50+ Tools)](#tool-catalog)
- [Guided Analysis Prompts](#guided-analysis-prompts)
- [Quick Start](#quick-start)
- [Connect to Your AI Client](#connect-to-your-ai-client)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Development](#development)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## What is Reversecore MCP?

Reversecore MCP is an enterprise-grade **[Model Context Protocol](https://modelcontextprotocol.io/)** server that transforms AI assistants like Claude and Cursor into expert-level security research workstations.

It goes far beyond binary disassembly. Reversecore MCP integrates **50+ analysis tools** spanning:

- 🔬 **Static analysis** — disassembly, decompilation, binary parsing
- 💥 **Dynamic triage** — GDB crash parsing, exploitability assessment
- 🦠 **Malware analysis** — capability detection, IOC extraction, threat hunting
- 🧬 **Vulnerability research** — symbolic execution, fuzzing, ROP gadget detection
- 🔏 **SAST** — source code auditing for Python, C, and C++
- 🕵️ **Digital forensics** — memory, disk, network, and artifact analysis
- 📊 **Reporting** — MITRE ATT&CK-mapped structured reports

Instead of learning complex tools by hand, you simply **describe what you want in natural language**:

```
"Decompile the main function of this malware sample, extract all network IOCs,
 map the behavior to MITRE ATT&CK, and generate a triage report."
```

↓

*Reversecore MCP automatically invokes `r2_decompile` → `extract_iocs` → `add_session_mitre` → `create_analysis_report`, returning structured analyst-grade output.*

---

## Architecture

```
AI Client (Claude / Cursor / any MCP-compatible client)
        │  MCP Protocol (stdio or HTTP/SSE)
        ▼
┌──────────────────────────────────────────────────────┐
│                   FastMCP Server                     │
│            50+ registered tools · Async              │
│                  Python 3.10–3.12                    │
├────────────────────┬─────────────────────────────────┤
│   Guided Prompts   │  Dynamic Resources              │
│  (5 expert modes)  │  (workspace, metrics, health)   │
├────────────────────┴─────────────────────────────────┤
│                  Core Infrastructure                 │
│  Config · Security · Validators · Exception Hierarchy│
│  R2 Pool · Metrics · Memory (SQLite) · Task Queue   │
│  MITRE Mapper · Evidence Engine · Resilience Layer  │
├──────────────────────────────────────────────────────┤
│                 Analysis Engines                     │
│  Radare2 + r2ghidra  │  YARA · LIEF · Capstone      │
│  CAPA (Mandiant)     │  angr (Symbolic Execution)   │
│  Volatility3 · Scapy │  DIE · Qiling · Binwalk      │
└──────────────────────────────────────────────────────┘
```

### Core Infrastructure Modules

| Module | Purpose |
|---|---|
| `core/config.py` | Centralized environment-aware configuration |
| `core/security.py` | Input sanitization & path validation |
| `core/validators.py` | File & binary path validators |
| `core/r2_pool.py` | Thread-safe Radare2 connection pool |
| `core/r2_helpers.py` | Structured Radare2 output utilities |
| `core/metrics.py` | Per-tool execution times & error rates |
| `core/memory.py` | Async SQLite AI memory store |
| `core/mitre_mapper.py` | MITRE ATT&CK technique mapping engine |
| `core/evidence.py` | Evidence classification (OBSERVED/INFERRED/POSSIBLE) |
| `core/resilience.py` | Retry, circuit-breaker, timeout patterns |
| `core/task_queue.py` | Background task queue (Redis + arq) |
| `core/extension_registry.py` | Plugin/extension registration system |
| `core/sast/` | Python AST scanner + C/C++ regex scanner |

---

## Tool Catalog

> Reversecore MCP exposes **50+ tools** across 7 categories. Every tool returns a structured `ToolResult` with `status`, `content`, and optional `error` fields.

### 🔍 Static Analysis

| Tool | Backend | Description |
|---|---|---|
| `run_file` | `file` CLI | File type, architecture, and compiler fingerprinting |
| `run_strings` | `strings` CLI | ASCII/Unicode string extraction with configurable min-length and limits |
| `run_binwalk` | Binwalk | Firmware deep-scan: embedded signatures, filesystems, compressed blobs |
| `parse_binary_with_lief` | LIEF | Full PE / ELF / Mach-O header, section, import/export, and TLS parsing |
| `detect_compiler_and_packer` | DIE (`diec`) | Compiler, linker, packer, and protector detection via Detect It Easy |
| `run_capa` | CAPA (Mandiant FLARE) | High-level capability detection — "encrypts data", "creates persistence", etc. |
| `audit_source_code` | AST + Regex SAST | Python AST scanner + C/C++ regex scanner for dangerous patterns |

### ⚙️ Disassembly & Decompilation

| Tool | Backend | Description |
|---|---|---|
| `run_radare2` | r2pipe | Raw Radare2 command execution with connection pooling |
| `Radare2_disassemble` | Radare2 | Function disassembly with full auto-analysis (`aaa`) |
| `r2_decompile` | r2ghidra | High-quality C decompilation (Ghidra engine embedded in r2, no JVM) |
| `r2_recover_structures` | r2ghidra + SQLite | Auto-recover C structs and persist to annotation database |
| `r2_analyze_function` | Radare2 | Deep single-function analysis with type inference and variable tracking |
| `r2_get_call_graph` | Radare2 | Call graph extraction for a given function address |
| `r2_simulate_patch` | Radare2 | Preview binary patch effects before applying to disk |
| `r2_session` | Radare2 | Stateful multi-command analysis sessions |
| `disassemble_with_capstone` | Capstone | Multi-arch disassembly: x86/x64, ARM, MIPS, PPC, SPARC |

### 🔗 Cross-Reference & Binary Annotation

| Tool | Backend | Description |
|---|---|---|
| `analyze_xrefs` | Radare2 | Track function calls, data references, and control flow |
| `r2_read_memory` | Radare2 | Read raw bytes from a given virtual address |
| `r2_list_structures` | SQLite | List all annotated C structs from the persistent annotation DB |
| `r2_create_structure` | SQLite | Create and persist a new struct annotation |
| `r2_add_bookmark` | SQLite | Annotate an address with a persistent comment |
| `r2_list_bookmarks` | SQLite | List all address bookmarks across the workspace |
| `r2_list_types` | Radare2 | List all known types in the current binary analysis |

### 🧬 Dynamic & Symbolic Analysis

| Tool | Backend | Description |
|---|---|---|
| `emulate_machine_code` | Radare2 ESIL | Register/memory-traced code emulation without running the binary |
| `verify_path_and_get_args` | angr | Symbolic execution — prove path reachability and compute concrete inputs |
| `generate_fuzzing_harness` | Qiling + AFL++ | Auto-generate a Qiling-based fuzzing harness targeting a specific function |
| `diff_binaries` | Radare2 | Semantic binary diff to track patch changes between versions |
| `match_libraries` | Radare2 | Identify statically linked libraries by function fingerprint matching |

### 🦠 Malware Analysis & Threat Detection

| Tool | Backend | Description |
|---|---|---|
| `dormant_detector` | Radare2 + heuristics | Find hidden backdoors, orphan functions, time-bombs, and logic bombs |
| `extract_iocs` | Regex + LIEF | Extract IPs, URLs, domains, hashes, registry keys, crypto addresses |
| `run_yara` | YARA | YARA rule scanning with custom rule files and built-in rulesets |
| `adaptive_vaccine` | YARA + Radare2 | Generate detection YARA rules + binary patches to neutralize a threat |
| `vulnerability_hunter` | Radare2 + analysis | Detect dangerous API patterns (strcpy, sprintf) and ROP gadget chains |

### 📝 Session Tracking & Report Generation

| Tool | Description |
|---|---|
| `start_analysis_session` | Start a timed analysis session with unique session ID |
| `add_session_ioc` | Collect and tag IOCs during a live session |
| `add_session_mitre` | Document MITRE ATT&CK technique IDs during analysis |
| `end_analysis_session` | Finalize session: computes duration, locks IOC/ATT&CK lists |
| `create_analysis_report` | Render session report in 4 modes: `full` / `triage` / `ioc_summary` / `executive` |
| `generate_malware_submission` | One-shot standardized JSON submission report |
| `send_report_email` | Deliver rendered report via SMTP |

### 🕵️ Digital Forensics

| Tool | Backend | Description |
|---|---|---|
| `analyze_memory_dump` | Volatility3 | Full memory forensics: process list, network connections, injected code, handles |
| `analyze_network_capture` | Scapy | PCAP analysis: protocol breakdown, DNS queries, HTTP payloads, anomalies |
| `analyze_disk_image` | The Sleuth Kit | Filesystem forensics: deleted files, timeline reconstruction, metadata |
| `analyze_artifacts` | Custom parsers | Browser history, Windows registry hives, event logs, prefetch files |

### 📊 Server Health & Workspace

| Tool | Description |
|---|---|
| `get_server_health` | Uptime, memory usage, loaded tools, and operational status |
| `get_tool_metrics` | Per-tool call counts, mean execution times, and error rates |
| `list_workspace` | List all files available in the analysis workspace |
| `get_file_info` | Metadata for a specific workspace file (size, hash, type) |

---

## Guided Analysis Prompts

Activate expert analysis modes by referencing these prompts in your AI client:

| Prompt | Use Case |
|---|---|
| `full_analysis_mode` | 6-phase comprehensive analysis: triage → disassembly → behavior → network → persistence → report |
| `basic_analysis_mode` | Rapid triage for initial assessment and quick verdicts |
| `game_analysis_mode` | Game client analysis with anti-cheat detection and memory inspection |
| `firmware_analysis_mode` | IoT/embedded firmware: binwalk extraction, UART strings, hardcoded credentials |
| `report_generation_mode` | Structured session workflow with MITRE ATT&CK technique mapping |

> **How prompts work:** Each prompt primes the AI with an expert persona, structured Chain-of-Thought checkpoints, and evidence classification (`OBSERVED` / `INFERRED` / `POSSIBLE`). This produces analyst-grade output, not just raw tool output.

---

## Quick Start

### Option 1 — Docker (Recommended)

The fastest way to get started with zero dependency installation:

```bash
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

### Option 2 — Build from Source

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

### Option 3 — Python (Local Development)

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python server.py
```

> **Prerequisites for local mode:** Radare2 must be installed on your system (`r2 --version`). YARA is installed automatically via `yara-python`.

---

## Connect to Your AI Client

Add to `~/.cursor/mcp.json` or `claude_desktop_config.json`:

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

All settings can be provided via environment variables or a `.env` file (see [`.env.example`](.env.example)):

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `http` | Transport mode: `stdio` or `http` |
| `REVERSECORE_WORKSPACE` | `/app/workspace` | Analysis workspace directory |
| `REVERSECORE_READ_DIRS` | `""` | Additional colon-separated read-only directories |
| `LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `MCP_API_KEY` | *(unset)* | API key for HTTP mode authentication (optional) |
| `RATE_LIMIT` | `60` | Max requests per minute (HTTP mode only) |
| `TOOL_TIMEOUT` | `300` | Default tool execution timeout in seconds |
| `R2_POOL_SIZE` | `4` | Radare2 connection pool size |
| `REDIS_URL` | `redis://localhost:6379` | Redis URL for background task queue |
| `SMTP_HOST` | *(unset)* | SMTP host for report email delivery |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | *(unset)* | SMTP username |
| `SMTP_PASSWORD` | *(unset)* | SMTP password |

---

## Security Model

Security is a first-class concern. Reversecore MCP was designed to safely analyze **untrusted malware samples** without risk to the host system.

| Control | Implementation |
|---|---|
| **No shell injection** | All subprocess calls use list arguments, never shell strings |
| **Path traversal prevention** | All file access validated and confined to configured workspace |
| **Input sanitization** | All parameters sanitized via `core/security.py` before execution |
| **Rate limiting** | Configurable per-minute request limits in HTTP mode (via slowapi) |
| **Container isolation** | Runs as non-root `appuser` (UID 1000) with minimal Linux capabilities |
| **Secrets scanning** | Gitleaks runs on every commit — no credentials ever reach the repo |
| **SAST in CI** | Bandit (all severities) + CodeQL on every push to `main` |
| **Dependency auditing** | pip-audit on every push — zero known CVEs enforced |
| **Container scanning** | Trivy scans final Docker image — LOW through CRITICAL findings reviewed |
| **Error codes** | Structured exception hierarchy with `RCMCP-E*` codes for AI-parseable errors |

---

## Development

### Setup

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install   # installs Gitleaks, Ruff, Bandit hooks
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
```

**Test status:**
- ✅ **1,520 unit tests** passing across Python 3.10 / 3.11 / 3.12
- 📊 **82% code coverage** (80% minimum enforced in CI)
- 🔒 Zero Bandit findings · Zero pip-audit CVEs · Zero container vulnerabilities
- ⚡ Fully async test suite via `pytest-asyncio`

### Code Quality

```bash
ruff check reversecore_mcp/      # Lint (E, W, F, I, B, C4, UP rules)
ruff format reversecore_mcp/     # Format
mypy reversecore_mcp/            # Type check (0 errors across 87 files)
bandit -r reversecore_mcp/       # Security scan (all severities)
pip-audit                        # Dependency CVE scan
```

### CI/CD Pipeline

Every push to `main` runs the following gates — **all must pass before deployment**:

```
Lint & Security Gate            Unit Tests (Python Matrix)
  ├─ Gitleaks (secret scan)       ├─ pytest 3.10 --cov-fail-under=80
  ├─ Hadolint (Dockerfile)        ├─ pytest 3.11 --cov-fail-under=80
  ├─ Ruff check + format          └─ pytest 3.12 --cov-fail-under=80
  ├─ Mypy type check (87 files)
  ├─ Bandit (all severities)    Docker Verification
  └─ pip-audit (zero CVE)         ├─ Build multi-arch image (amd64/arm64)
                                  ├─ Trivy container scan (LOW→CRITICAL)
CodeQL Analysis                   ├─ Integration tests (inside container)
  └─ Python SAST                  └─ E2E MCP tool invocation

Deploy (main branch only)
  └─ Push to GHCR + Trivy rescan on published image
```

> **Zero-bypass policy:** CI/CD failures are **never** resolved by modifying pipeline configuration. Root causes are always fixed directly in source code or dependencies.

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
├── core/                      # Infrastructure layer
│   ├── config.py              # Centralized configuration
│   ├── exceptions.py          # Exception hierarchy (RCMCP-E* codes)
│   ├── security.py            # Input sanitization & path validation
│   ├── validators.py          # File & binary path validators
│   ├── r2_pool.py             # Thread-safe Radare2 connection pool
│   ├── r2_helpers.py          # Structured Radare2 output utilities
│   ├── metrics.py             # Tool execution metrics
│   ├── decorators.py          # @log_execution, @track_metrics
│   ├── error_handling.py      # @handle_tool_errors decorator
│   ├── memory.py              # Async SQLite AI memory store
│   ├── mitre_mapper.py        # MITRE ATT&CK mapping engine
│   ├── evidence.py            # Evidence classification system
│   ├── resilience.py          # Retry, circuit-breaker, timeout
│   ├── task_queue.py          # Background task queue (Redis/arq)
│   ├── extension_registry.py  # Plugin registration system
│   └── sast/                  # Python AST + C/C++ scanners
│
├── tools/                     # MCP tool implementations
│   ├── analysis/              # Static analysis
│   │   ├── static_analysis.py # file, strings, binwalk
│   │   ├── lief_tools.py      # LIEF binary parser
│   │   ├── capa_tools.py      # CAPA capability detection
│   │   ├── die_tools.py       # DIE packer/compiler detection
│   │   ├── diff_tools.py      # Binary diffing
│   │   ├── emulation_tools.py # ESIL emulation
│   │   ├── fuzz_tools.py      # Fuzzing harness generator
│   │   ├── symbolic_analysis.py # angr symbolic execution
│   │   ├── signature_tools.py # Library signature matching
│   │   └── source_auditor.py  # SAST (Python + C/C++)
│   │
│   ├── radare2/               # Radare2 & decompilation
│   │   ├── radare2_mcp_tools.py # Core r2 tool set
│   │   ├── r2ghidra_tools.py  # Ghidra decompiler (r2ghidra)
│   │   ├── r2_analysis.py     # Deep function analysis
│   │   ├── r2_db.py           # SQLite annotation database
│   │   └── r2_session.py      # Stateful analysis sessions
│   │
│   ├── malware/               # Threat detection & defense
│   │   ├── dormant_detector.py # Backdoor/logic bomb detection
│   │   ├── ioc_tools.py       # IOC extraction
│   │   ├── yara_tools.py      # YARA scanning
│   │   ├── adaptive_vaccine.py # YARA rule + patch generation
│   │   └── vulnerability_hunter.py # Vuln pattern detection
│   │
│   ├── forensics/             # Digital forensics
│   │   ├── memory.py          # Volatility3 memory forensics
│   │   ├── network.py         # Scapy PCAP analysis
│   │   ├── disk.py            # Sleuth Kit disk forensics
│   │   └── artifact.py        # Browser/registry/event log
│   │
│   ├── report/                # Report generation
│   └── common/                # File ops, server health
│
├── prompts/                   # AI reasoning prompts (5 modes)
├── resources.py               # Dynamic MCP resources
└── server.py                  # FastMCP server entrypoint (50+ tools registered)
```

---

## Adding New Tools

Follow this pattern to add a new MCP tool:

```python
# reversecore_mcp/tools/analysis/my_tool.py
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path

@log_execution()
async def my_analysis_tool(file_path: str, option: str | None = None) -> ToolResult:
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
        return failure(str(e))
```

Then register it in [`server.py`](server.py) and add tests in `tests/unit/`.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests alongside your code — coverage must not drop below 80%
4. Ensure all gates pass: `pytest`, `ruff check`, `mypy`, `bandit`
5. Open a pull request with a clear description

Please read the [Contributing Guide](docs/development/contributing.md) for code standards, docstring conventions, and the pull request checklist.

---

## Documentation

| Document | Description |
|---|---|
| [Installation Guide](docs/getting-started/installation.md) | Detailed setup for all environments |
| [Architecture Guide](docs/development/architecture.md) | System design & component deep-dive |
| [Contributing Guide](docs/development/contributing.md) | Code standards, docstrings, PR workflow |
| [Testing Guide](docs/development/testing.md) | Test patterns, fixtures, and coverage |
| [API Reference](docs/api/) | Tool and module reference |
| [User Guide](docs/user-guide/) | End-user analysis workflows |

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**[GitHub](https://github.com/sjkim1127/Reversecore_MCP)** · **[FastMCP Docs](https://github.com/jlowin/fastmcp)** · **[MCP Spec](https://modelcontextprotocol.io/)** · **[Radare2](https://radare.org/)** · **[YARA](https://virustotal.github.io/yara/)**

</div>
