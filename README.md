# Reversecore_MCP

![Icon](icon.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13.1-green)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/tests-852%20passed-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-76%25-green)](htmlcov/)

[![Watch the Demo](https://img.shields.io/badge/Watch_Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)

[🇰🇷 한국어 (Korean)](README_KR.md)

An enterprise-grade MCP (Model Context Protocol) server for AI-powered reverse engineering. Enables AI agents to perform comprehensive binary analysis through natural language commands.

## 📋 Prerequisites

### Ghidra (Required for Decompilation)

Ghidra is required for advanced decompilation features. The installation scripts automatically install Ghidra to `<project>/Tools` directory.

**Option 1: Automatic Installation (Recommended)**

```powershell
# Windows (PowerShell)
.\scripts\install-ghidra.ps1

# With custom version/path (optional)
.\scripts\install-ghidra.ps1 -Version "11.4.3" -InstallDir "C:\CustomPath"
```

```bash
# Linux/macOS
chmod +x ./scripts/install-ghidra.sh
./scripts/install-ghidra.sh

# With custom version/path (optional)
./scripts/install-ghidra.sh -v 11.4.3 -d /custom/path
```

**What the scripts do:**
- Downloads Ghidra 11.4.3 from GitHub (~400MB)
- Extracts to `<project>/Tools/ghidra_11.4.3_PUBLIC_YYYYMMDD`
- Sets `GHIDRA_INSTALL_DIR` environment variable
- Updates project `.env` file

**Option 2: Manual Installation**

1. **Download**: [Ghidra 11.4.3](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.4.3_build)
2. **Extract** to `<project>/Tools/` or any directory
3. **Set environment variable**:
   ```bash
   # Linux/macOS (~/.bashrc or ~/.zshrc)
   export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.3_PUBLIC_YYYYMMDD

   # Windows (PowerShell - permanent)
   [Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", "C:\path\to\ghidra", "User")
   ```
   Or add to `.env` file (copy from `.env.example`)

> ⚠️ **Note**: JDK 17+ is required for Ghidra. Download from [Adoptium](https://adoptium.net/) if needed.

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Auto-detect architecture (Intel/AMD or Apple Silicon)
./scripts/run-docker.sh

# Or manually:
# Intel/AMD
docker compose --profile x86 up -d

# Apple Silicon (M1/M2/M3/M4)
docker compose --profile arm64 up -d
```

### MCP Client Configuration (Cursor AI)

**Step 1: Build Docker Image**

```bash
# macOS Apple Silicon (M1/M2/M3/M4)
docker build -f Dockerfile.arm64 -t reversecore-mcp:arm64 .

# macOS Intel / Linux / Windows (x86_64)
docker build -f Dockerfile -t reversecore-mcp:latest .
```

**Step 2: Configure MCP Client**

Add to `~/.cursor/mcp.json`:

<details>
<summary>🍎 <b>macOS Apple Silicon (M1/M2/M3/M4)</b></summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/Users/YOUR_USERNAME/Reversecore_Workspace:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp:arm64"
      ]
    }
  }
}
```
</details>

<details>
<summary>🖥️ <b>macOS Intel / Linux (x86_64)</b></summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/path/to/workspace:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp:latest"
      ]
    }
  }
}
```
</details>

<details>
<summary>🪟 <b>Windows (x86_64)</b></summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "C:/Reversecore_Workspace:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp:latest"
      ]
    }
  }
}
```
</details>

> ⚠️ **IMPORTANT: File Path Usage in Docker**
>
> The MCP server runs inside a Docker container. When using analysis tools, **use only the filename, not the full local path**.
>
> | ❌ Wrong | ✅ Correct |
> |----------|-----------|
> | `run_file("/Users/john/Reversecore_Workspace/sample.exe")` | `run_file("sample.exe")` |
>
> **Why?** Your local path (e.g., `/Users/.../Reversecore_Workspace/`) is mounted to `/app/workspace/` inside the container. Tools automatically look for files in the workspace directory.
>
> **Tip:** Use `list_workspace()` to see all available files in your workspace.

## ✨ Key Features

### 🔱 Trinity Defense System

Fully automated threat detection and neutralization pipeline:

- **Phase 1 (DISCOVER)**: Ghost Trace scans for hidden threats
- **Phase 2 (UNDERSTAND)**: Neural Decompiler analyzes intent
- **Phase 3 (NEUTRALIZE)**: Adaptive Vaccine generates defenses

### 👻 Ghost Trace

Detects "Logic Bombs" and "Dormant Malware" that evade sandbox detection:

- Orphan function detection (hidden backdoors)
- Magic value trigger identification
- AI-driven partial emulation

### 🧠 Neural Decompiler

Transforms raw decompiled code into human-readable format:

- Semantic variable renaming (\`iVar1\` → \`sock_fd\`)
- Structure inference from pointer arithmetic
- Smart annotation with explanatory comments

### 🎮 Game Security Analysis

Specialized tools for game client reverse engineering:

- **Cheat Point Finder**: Automated detection of speed hacks, teleport, god mode, item duplication, wallhack
- **Anti-Cheat Profiler**: Identifies GameGuard, XIGNCODE, EAC, VAC patterns
- **Protocol Analyzer**: Korean MMO protocol pattern detection (CS_/SC_, MSG_/PKT_)
- **Function Pattern Matching**: Speed multiplier, coordinate manipulation, health modification detection

### � Server Health & Monitoring (NEW!)

Built-in observability tools for enterprise environments:

- **Health Check**: Monitor uptime, memory usage, and operational status (`get_server_health`)
- **Performance Metrics**: Track tool execution times, error rates, and call counts (`get_tool_metrics`)
- **Auto-Recovery**: Automatic retry mechanism with exponential backoff for transient failures

### �📝 Report Generation Tools (NEW!)

Professional malware analysis report generation with accurate timestamps:

- **One-Shot Submission**: Generate standardized JSON reports with a single command (`generate_malware_submission`)
- **Session Tracking**: Start/end analysis sessions with automatic duration calculation
- **IOC Collection**: Collect and organize indicators during analysis (hashes, IPs, domains, URLs)
- **MITRE ATT&CK Mapping**: Document techniques with proper framework references
- **Email Delivery**: Send reports directly to security teams (SMTP support)

```python
# Example 1: One-Shot JSON Submission
generate_malware_submission(
    file_path="wannacry.exe",
    analyst_name="Hunter",
    tags="ransomware,critical"
)

# Example 2: Interactive Session
get_system_time()
start_analysis_session(sample_path="malware.exe")
add_session_ioc("ips", "192.168.1.100")
add_session_mitre("T1059.001", "PowerShell", "Execution")
end_analysis_session(summary="Ransomware detected")
create_analysis_report(template_type="full_analysis")
```

### ⚡ Performance & Reliability (v3.1)

- **Resource Management**:
  - **Zombie Killer**: Guaranteed subprocess termination with `try...finally` blocks
  - **Memory Guard**: Strict 2MB limit on `strings` output to prevent OOM
  - **Crash Isolation**: LIEF parser runs in isolated process to handle segfaults safely
- **Optimizations**:
  - **Dynamic Timeout**: Auto-scales with file size (base + 2s/MB, max +600s)
  - **Ghidra JVM**: 16GB heap for modern systems (24-32GB RAM)
  - **Sink-Aware Pruning**: 39 dangerous sink APIs for intelligent path prioritization
  - **Trace Depth Optimization**: Reduced from 3 to 2 for faster execution path analysis
- **Infrastructure**:
  - **Stateless Reports**: Timezone-aware reporting without global state mutation
  - **Robust Retries**: Decorators now correctly propagate exceptions for auto-recovery
  - **Config-Driven**: Validation limits synchronized with central configuration

### 🛠️ Core Tools

| Category | Tools |
|----------|-------|
| **Basic Analysis** | \`run_file\`, \`run_strings\`, \`run_binwalk\` |
| **Disassembly** | \`run_radare2\`, \`disassemble_with_capstone\` |
| **Decompilation** | \`smart_decompile\`, \`get_pseudo_code\` (Ghidra/r2) |
| **Advanced** | \`analyze_xrefs\`, \`recover_structures\`, \`emulate_machine_code\` |
| **Malware Analysis & Vaccine** | \`dormant_detector\`, \`adaptive_vaccine\`, \`vulnerability_hunter\`, \`extract_iocs\`, \`run_yara\` |
| **Binary Parsing** | \`parse_binary_with_lief\` |
| **Diffing** | \`diff_binaries\`, \`match_libraries\` |
| **Game Analysis** | \`find_cheat_points\`, \`analyze_game_protocol\` |
| **Reporting** | \`get_system_time\`, \`start_analysis_session\`, \`create_analysis_report\` |

## 📊 Analysis Workflow

```
📥 Upload → 🔍 Triage → 🔗 X-Refs → 🏗️ Structures → 📝 Decompile → 🛡️ Defense
```

**Use built-in prompts for guided analysis:**

- \`full_analysis_mode\` - Comprehensive malware analysis with **6-phase expert reasoning**
- \`basic_analysis_mode\` - Quick triage
- \`game_analysis_mode\` - Game client analysis with **cheat detection heuristics**
- \`firmware_analysis_mode\` - IoT/Firmware analysis
- \`report_generation_mode\` - Professional report generation workflow **(NEW!)**

> 💡 **AI Reasoning Enhancement**: Prompts use expert persona priming, Chain-of-Thought checkpoints, and structured reasoning to maximize AI analysis capabilities.

## 🏗️ Architecture

```
reversecore_mcp/
├── core/                 # Infrastructure
│   ├── config.py         # Configuration management
│   ├── container.py      # Dependency injection
│   ├── ghidra.py         # Ghidra integration (16GB JVM heap)
│   ├── r2_helpers.py     # Radare2 utilities
│   ├── result.py         # ToolSuccess/ToolError models
│   └── security.py       # Input validation
├── tools/                # MCP Tools
│   ├── cli_tools.py      # CLI wrappers
│   ├── decompilation.py  # Decompilers
│   ├── game_analysis.py  # Game security analysis (NEW!)
│   ├── ghost_trace.py    # Hidden threat detection
│   ├── r2_analysis.py    # R2 analysis (v3.0 optimized)
│   ├── trinity_defense.py # Automated defense
│   └── ...
├── prompts.py            # AI reasoning prompts (enhanced)
└── resources.py          # Dynamic resources
```

## 🐳 Docker Deployment

### Multi-Architecture Support

| File | Architecture | Use Case |
|------|--------------|----------|
| `Dockerfile` | Multi-Arch (x86_64, ARM64) | All platforms |

### Run Commands

```bash
# Using convenience script (auto-detects architecture)
./scripts/run-docker.sh              # Start
./scripts/run-docker.sh stop         # Stop
./scripts/run-docker.sh logs         # View logs
./scripts/run-docker.sh shell        # Shell access

# Manual Docker build commands
# Apple Silicon (M1/M2/M3/M4)
docker build -f Dockerfile -t reversecore-mcp:arm64 .

# Intel/AMD (x86_64)
docker build -f Dockerfile -t reversecore-mcp:latest .
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| \`MCP_TRANSPORT\` | \`http\` | Transport mode (\`stdio\` or \`http\`) |
| \`REVERSECORE_WORKSPACE\` | \`/app/workspace\` | Analysis workspace path |
| \`LOG_LEVEL\` | \`INFO\` | Logging level |
| \`GHIDRA_INSTALL_DIR\` | \`/opt/ghidra\` | Ghidra installation path |

## 🔒 Security

- **No shell injection**: All subprocess calls use list arguments
- **Path validation**: Workspace-restricted file access
- **Input sanitization**: All parameters validated
- **Rate limiting**: Configurable request limits (HTTP mode)

## 🧪 Development

```bash
# Install dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=reversecore_mcp --cov-fail-under=72

# Code quality
ruff check reversecore_mcp/
black reversecore_mcp/
```

### Test Status

- ✅ **852 tests passed**
- 📊 **75% coverage**
- ⏱️ ~14 seconds execution time

## 📚 API Reference

### Tool Response Format

All tools return structured \`ToolResult\`:

```json
{
  "status": "success",
  "data": "...",
  "metadata": { "bytes_read": 1024 }
}
```

```json
{
  "status": "error",
  "error_code": "VALIDATION_ERROR",
  "message": "File not found",
  "hint": "Check file path"
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| \`VALIDATION_ERROR\` | Invalid input parameters |
| \`TIMEOUT\` | Operation exceeded time limit |
| \`PARSE_ERROR\` | Failed to parse tool output |
| \`TOOL_NOT_FOUND\` | Required CLI tool missing |

## 💻 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 16 GB | 32 GB |
| **Storage** | 512 GB SSD | 1 TB NVMe |
| **OS** | Linux/macOS | Docker environment |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run \`pytest\` and \`ruff check\`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [GitHub Repository](https://github.com/sjkim1127/Reversecore_MCP)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
