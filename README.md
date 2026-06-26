<div align="center">

<img src="icon.png" alt="Reversecore MCP" width="120" />

# Reversecore MCP

**AI-Powered Reverse Engineering via Model Context Protocol**

*Enterprise-grade binary analysis server — speak natural language, get expert-level reverse engineering.*

---

[![CI/CD](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml/badge.svg)](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1520%20passed-brightgreen)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-82%25-green)](#testing)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.2.0-purple)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/sjkim1127/Reversecore_MCP/pkgs/container/reversecore_mcp)

[![Watch the Demo](https://img.shields.io/badge/▶_Watch_Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)
[![SafeSkill Verified](https://img.shields.io/badge/SafeSkill-93%2F100_Verified_Safe-brightgreen?style=for-the-badge)](https://safeskill.dev/scan/sjkim1127-reversecore-mcp)

[🇰🇷 한국어](README_KR.md)

</div>

---

## What is Reversecore MCP?

Reversecore MCP is an enterprise-grade **[Model Context Protocol](https://modelcontextprotocol.io/)** server that transforms AI assistants like Claude and Cursor into expert reverse engineering workstations.

Instead of learning complex tools like Radare2 or writing YARA rules by hand, you simply **describe what you want in natural language** — and the AI executes the analysis for you.

```
"Decompile the main function of this malware sample and identify
 what network connections it's trying to establish."
```

↓

*Reversecore MCP invokes `r2_decompile`, `extract_iocs`, `analyze_xrefs` automatically, returning structured results the AI interprets for you.*

---

## Architecture at a Glance

```
AI Client (Claude / Cursor)
        │  MCP Protocol (stdio or HTTP)
        ▼
┌─────────────────────────────┐
│      FastMCP Server         │  Python 3.10–3.12
│   50+ registered tools      │  Async, fully typed
├──────────────────┬──────────┤
│   Prompts        │ Resources│  Guided analysis modes
├──────────────────┴──────────┤
│        Core Infrastructure  │
│  Config · Security · Metrics│
│  R2 Pool · Exception Hier.  │
├─────────────────────────────┤
│  Radare2 + r2ghidra plugin  │  Binary analysis engine
│  YARA · LIEF · Capstone     │  Detection & parsing
│  Volatility3 · Scapy        │  Forensics & network
└─────────────────────────────┘
```

---

## Quick Start

### Option 1 — Docker (Recommended)

```bash
# Pull and run the pre-built image
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

---

## Connect to Your AI Client

### Cursor / Claude Desktop

Add to `~/.cursor/mcp.json` (or `claude_desktop_config.json`):

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
> Always reference files by **filename only**, not by full local path.
>
> | ❌ Wrong | ✅ Correct |
> |---|---|
> | `r2_decompile("/Users/john/samples/mal.exe")` | `r2_decompile("mal.exe")` |

---

## Tool Reference

### 🔍 Static Analysis

| Tool | Description |
|---|---|
| `run_file` | File type, architecture, and compiler fingerprinting |
| `run_strings` | ASCII/Unicode string extraction with configurable limits |
| `run_binwalk` | Firmware deep-scan for embedded signatures and filesystems |
| `parse_binary_with_lief` | Full PE / ELF / Mach-O header and section parsing |
| `audit_source_code` | SAST via Python AST scanner + C/C++ regex scanner |

### ⚙️ Disassembly & Decompilation

| Tool | Description |
|---|---|
| `run_radare2` | Raw Radare2 command execution with connection pooling |
| `Radare2_disassemble` | Function disassembly with auto-analysis |
| `r2_decompile` | High-quality C decompilation via r2ghidra (Ghidra engine, no JVM) |
| `r2_recover_structures` | Auto-recover C structs and persist to SQLite annotation DB |
| `r2_analyze_function` | Deep single-function analysis with type inference |
| `r2_get_call_graph` | Call graph extraction for a function |
| `r2_simulate_patch` | Preview the effect of a binary patch before applying |
| `disassemble_with_capstone` | Multi-arch disassembly (x86/ARM/MIPS/PPC) via Capstone |

### 🔗 Cross-Reference & Memory

| Tool | Description |
|---|---|
| `analyze_xrefs` | Track function calls, data references, and control flow |
| `r2_read_memory` | Read raw bytes from a given address |
| `r2_list_structures` | List all annotated structures from the SQLite DB |
| `r2_create_structure` | Create and persist a new struct annotation |
| `r2_add_bookmark` | Annotate an address with a comment |
| `r2_list_bookmarks` | List all address bookmarks |
| `r2_list_types` | List all known types in the current binary |

### 🧬 Dynamic Analysis & Emulation

| Tool | Description |
|---|---|
| `emulate_machine_code` | ESIL-based code emulation with register/memory tracing |
| `diff_binaries` | Semantic binary diff to track patch changes |
| `match_libraries` | Identify statically linked libraries by function fingerprint |

### 🦠 Malware Analysis

| Tool | Description |
|---|---|
| `dormant_detector` | Find hidden backdoors, orphan functions, and logic bombs |
| `extract_iocs` | Extract IPs, URLs, domains, hashes, crypto addresses |
| `run_yara` | YARA rule scanning with custom rule support |
| `adaptive_vaccine` | Generate YARA rules + binary patches for a threat |
| `vulnerability_hunter` | Detect dangerous API patterns and ROP gadget chains |

### 📝 Report Generation

| Tool | Description |
|---|---|
| `generate_malware_submission` | One-shot standardized JSON report |
| `start_analysis_session` | Start a timed analysis session |
| `add_session_ioc` | Collect IOCs during a session |
| `add_session_mitre` | Document MITRE ATT&CK techniques |
| `end_analysis_session` | Finalize session with duration calculation |
| `create_analysis_report` | Render report (full / triage / IOC summary / executive) |
| `send_report_email` | Deliver report via SMTP |

### 🛡️ Forensics

| Tool | Description |
|---|---|
| `analyze_memory_dump` | Volatility3-based memory forensics |
| `analyze_network_capture` | Scapy-based PCAP analysis |
| `analyze_disk_image` | Sleuth Kit filesystem forensics |
| `analyze_artifacts` | Browser history, registry, event log parsing |

### 📊 Server & Monitoring

| Tool | Description |
|---|---|
| `get_server_health` | Uptime, memory, and operational status |
| `get_tool_metrics` | Per-tool execution times, call counts, error rates |
| `list_workspace` | List files available in the analysis workspace |
| `get_file_info` | Metadata for a specific workspace file |

---

## Guided Analysis Prompts

Activate expert-level analysis modes by referencing these prompts in your AI client:

| Prompt | Use Case |
|---|---|
| `full_analysis_mode` | 6-phase comprehensive malware analysis with evidence classification |
| `basic_analysis_mode` | Rapid triage for initial assessment |
| `game_analysis_mode` | Game client analysis with anti-cheat detection |
| `firmware_analysis_mode` | IoT/embedded firmware security review |
| `report_generation_mode` | Structured report workflow with MITRE ATT&CK mapping |

> **How prompts work:** Each prompt primes the AI with an expert persona, Chain-of-Thought checkpoints, and evidence classification (`OBSERVED` / `INFERRED` / `POSSIBLE`). This produces analyst-grade output, not just tool output.

---

## Security Model

| Control | Detail |
|---|---|
| **No shell injection** | All subprocess calls use list arguments, never shell strings |
| **Path validation** | All file access restricted to the configured workspace |
| **Input sanitization** | All parameters validated before execution |
| **Rate limiting** | Configurable per-minute request limits (HTTP mode) |
| **Zero-Trust CI/CD** | Gitleaks (secrets), Bandit (SAST), pip-audit (CVEs), Trivy (container), CodeQL |
| **Workspace isolation** | Container runs as non-root `appuser` (UID 1000) |

---

## Development

### Setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install
```

### Testing

```bash
# Run full unit test suite with coverage
pytest tests/unit/ --cov=reversecore_mcp --cov-fail-under=80

# Run all tests
pytest tests/ -v
```

**Test status:**
- ✅ **1,520 unit tests** passing across Python 3.10 / 3.11 / 3.12
- 📊 **82% code coverage** (80% minimum enforced in CI)
- 🔒 Zero Bandit findings · Zero pip-audit CVEs · Zero container vulnerabilities

### Code Quality

```bash
ruff check reversecore_mcp/      # Lint
ruff format reversecore_mcp/     # Format
mypy reversecore_mcp/            # Type check  (0 errors in 87 files)
bandit -r reversecore_mcp/       # Security scan
```

### CI/CD Pipeline

Every push to `main` runs the following gates — **all must pass before deployment**:

```
Lint & Security          Unit Tests (3.10 / 3.11 / 3.12)
  ├─ Gitleaks              ├─ pytest --cov-fail-under=80
  ├─ Hadolint              └─ (all 3 matrix versions must pass)
  ├─ Ruff check + format
  ├─ Mypy type check    Docker Verification
  ├─ Bandit (all sev.)    ├─ Trivy container scan (LOW→CRITICAL)
  └─ pip-audit            ├─ Integration tests (inside container)
                          └─ E2E MCP tool invocation

CodeQL Analysis       Deploy (main branch only)
  └─ Python SAST          └─ Push to GHCR + Trivy rescan
```

> **Zero-bypass policy:** CI/CD failures are **never** resolved by modifying the pipeline configuration. Root causes are always fixed in source code or dependencies.

---

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `http` | Transport mode: `stdio` or `http` |
| `REVERSECORE_WORKSPACE` | `/app/workspace` | Analysis workspace path |
| `REVERSECORE_READ_DIRS` | `""` | Additional read-only directories |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `MCP_API_KEY` | *(unset)* | API key for HTTP mode (optional) |
| `RATE_LIMIT` | `60` | Max requests per minute (HTTP mode) |

---

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Storage | 20 GB | 50 GB SSD |
| OS | Linux / macOS | Docker environment |

---

## Project Structure

```
reversecore_mcp/
├── core/                    # Infrastructure
│   ├── config.py            # Centralized configuration
│   ├── exceptions.py        # Exception hierarchy (RCMCP-E* codes)
│   ├── security.py          # Input sanitization & path validation
│   ├── validators.py        # File & binary path validators
│   ├── r2_pool.py           # Radare2 connection pool
│   ├── r2_helpers.py        # Radare2 helper utilities
│   ├── metrics.py           # Tool execution metrics
│   ├── decorators.py        # @log_execution, @track_metrics
│   ├── error_handling.py    # @handle_tool_errors
│   ├── memory.py            # AI memory store (async SQLite)
│   ├── mitre_mapper.py      # MITRE ATT&CK mapping
│   └── sast/                # Source code scanners
│
├── tools/                   # MCP Tool implementations
│   ├── analysis/            # Static analysis, LIEF, diff, SAST
│   ├── radare2/             # Disassembly, decompilation, SQLite DB
│   ├── malware/             # Threat detection & defense
│   ├── forensics/           # Memory, disk, network forensics
│   ├── report/              # Report generation & email
│   └── common/              # File ops, server health
│
├── prompts/                 # AI reasoning prompts (5 modes)
├── resources.py             # Dynamic MCP resources
└── server.py                # FastMCP server entrypoint
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests alongside your code
4. Ensure `pytest`, `ruff check`, `mypy`, and `bandit` all pass
5. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**[GitHub](https://github.com/sjkim1127/Reversecore_MCP)** · **[FastMCP Docs](https://github.com/jlowin/fastmcp)** · **[MCP Spec](https://modelcontextprotocol.io/)**

</div>
