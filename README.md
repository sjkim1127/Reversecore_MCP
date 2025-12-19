# Reversecore_MCP

![Icon](icon.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
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

The unified Dockerfile automatically detects your system architecture:

```bash
# Automatic architecture detection (works for all platforms)
docker build -t reversecore-mcp:latest .

# Or use the convenience script
./scripts/run-docker.sh
```

**Step 2: Configure MCP Client**

Add to `~/.cursor/mcp.json`:

<details>
<summary>🍎 <b>macOS (All Processors)</b></summary>

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
        "reversecore-mcp:latest"
      ]
    }
  }
}
```
</details>

<details>
<summary>🐧 <b>Linux</b></summary>

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
<summary>🪟 <b>Windows</b></summary>

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

### 🔍 Static Analysis

Comprehensive file analysis and metadata extraction:

- **File Type Detection**: Identify binary format, architecture, and compiler information (`run_file`)
- **String Extraction**: Extract ASCII/Unicode strings with configurable limits (`run_strings`)
- **Firmware Analysis**: Deep scan for embedded files and signatures (`run_binwalk`)
- **Binary Parsing**: Parse PE/ELF/Mach-O headers and sections with LIEF (`parse_binary_with_lief`)

### ⚙️ Disassembly & Decompilation

Multi-architecture binary analysis with intelligent tooling:

- **Radare2 Integration**: Full r2 command access with connection pooling (`run_radare2`, `Radare2_disassemble`)
- **Ghidra Decompilation**: Enterprise-grade decompilation with 16GB JVM heap (`smart_decompile`, `get_pseudo_code`)
- **Multi-Architecture Support**: x86, x86-64, ARM, ARM64, MIPS, PowerPC via Capstone (`disassemble_with_capstone`)
- **Smart Fallback**: Automatic Ghidra-first, r2-fallback strategy for best results

### 🧬 Advanced Analysis

Deep code analysis and behavior understanding:

- **Cross-Reference Analysis**: Track function calls, data references, and control flow (`analyze_xrefs`)
- **Structure Recovery**: Infer data structures from pointer arithmetic and memory access patterns (`recover_structures`)
- **Emulation**: ESIL-based code emulation for dynamic behavior analysis (`emulate_machine_code`)
- **Binary Comparison**: Diff binaries and match library functions (`diff_binaries`, `match_libraries`)

### 🦠 Malware Analysis & Defense

Specialized tools for threat detection and mitigation:

- **Dormant Threat Detection**: Find hidden backdoors, orphan functions, and logic bombs (`dormant_detector`)
- **IOC Extraction**: Automatically extract IPs, URLs, domains, emails, hashes, and crypto addresses (`extract_iocs`)
- **YARA Scanning**: Pattern-based malware detection with custom rules (`run_yara`)
- **Adaptive Vaccine**: Generate defensive measures (YARA rules, binary patches, NOP injection) (`adaptive_vaccine`)
- **Vulnerability Hunter**: Detect dangerous API patterns and exploit paths (`vulnerability_hunter`)

### 📊 Server Health & Monitoring

Built-in observability tools for enterprise environments:

- **Health Check**: Monitor uptime, memory usage, and operational status (`get_server_health`)
- **Performance Metrics**: Track tool execution times, error rates, and call counts (`get_tool_metrics`)
- **Auto-Recovery**: Automatic retry mechanism with exponential backoff for transient failures

### 🖥️ Web Dashboard (NEW)

Visual interface for binary analysis without LLM:

```bash
# Start server in HTTP mode
MCP_TRANSPORT=http MCP_API_KEY=your-secret-key python server.py

# Access dashboard
open http://localhost:8000/dashboard/
```

**Features:**
- **Overview**: File list with upload stats
- **Analysis**: Functions list, disassembly viewer
- **IOCs**: Extracted URLs, IPs, emails, strings

**Security:**
- XSS protection with HTML sanitization
- Path traversal prevention
- API key authentication (optional)

### 📝 Report Generation (v3.1)

Professional malware analysis report generation with accurate timestamps:

- **One-Shot Submission**: Generate standardized JSON reports with a single command (`generate_malware_submission`)
- **Session Tracking**: Start/end analysis sessions with automatic duration calculation (`start_analysis_session`, `end_analysis_session`)
- **IOC Collection**: Collect and organize indicators during analysis (`add_session_ioc`)
- **MITRE ATT&CK Mapping**: Document techniques with proper framework references (`add_session_mitre`)
- **Email Delivery**: Send reports directly to security teams with SMTP support (`send_report_email`)
- **Multiple Templates**: Full analysis, quick triage, IOC summary, executive brief

```python
# Example 1: One-Shot JSON Submission
generate_malware_submission(
    file_path="wannacry.exe",
    analyst_name="Hunter",
    tags="ransomware,critical"
)

# Example 2: Interactive Session Workflow
get_system_time()
start_analysis_session(sample_path="malware.exe")
add_session_ioc("ips", "192.168.1.100")
add_session_mitre("T1059.001", "PowerShell", "Execution")
end_analysis_session(summary="Ransomware detected")
create_analysis_report(template_type="full_analysis")
send_report_email(to="security-team@company.com")
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
| **File Operations** | `list_workspace`, `get_file_info` |
| **Static Analysis** | `run_file`, `run_strings`, `run_binwalk` |
| **Disassembly** | `run_radare2`, `Radare2_disassemble`, `disassemble_with_capstone` |
| **Decompilation** | `smart_decompile`, `get_pseudo_code` |
| **Advanced Analysis** | `analyze_xrefs`, `recover_structures`, `emulate_machine_code` |
| **Binary Parsing** | `parse_binary_with_lief` |
| **Binary Comparison** | `diff_binaries`, `match_libraries` |
| **Malware Analysis** | `dormant_detector`, `extract_iocs`, `run_yara`, `adaptive_vaccine`, `vulnerability_hunter` |
| **Report Generation** | `get_system_time`, `set_timezone`, `start_analysis_session`, `add_session_ioc`, `add_session_mitre`, `end_analysis_session`, `create_analysis_report`, `send_report_email`, `generate_malware_submission` |
| **Server Management** | `get_server_health`, `get_tool_metrics` |

## 📊 Analysis Workflow

```
📥 Upload → 🔍 Triage → 🔗 X-Refs → 🏗️ Structures → 📝 Decompile → 🛡️ Defense
```

**Use built-in prompts for guided analysis:**

- `full_analysis_mode` - Comprehensive malware analysis with **6-phase expert reasoning** and evidence classification
- `basic_analysis_mode` - Quick triage for fast initial assessment
- `game_analysis_mode` - Game client analysis with cheat detection guidance
- `firmware_analysis_mode` - IoT/Firmware security analysis with embedded system focus
- `report_generation_mode` - Professional report generation workflow with MITRE ATT&CK mapping

> 💡 **AI Reasoning Enhancement**: Analysis prompts use expert persona priming, Chain-of-Thought checkpoints, structured reasoning phases, and evidence classification (OBSERVED/INFERRED/POSSIBLE) to maximize AI analysis capabilities and ensure thorough documentation.

## 🏗️ Architecture

```
reversecore_mcp/
├── core/                           # Infrastructure & Services
│   ├── config.py                   # Configuration management
│   ├── ghidra.py, ghidra_manager.py, ghidra_helper.py  # Ghidra integration (16GB JVM)
│   ├── r2_helpers.py, r2_pool.py   # Radare2 connection pooling
│   ├── security.py                 # Path validation & input sanitization
│   ├── result.py                   # ToolSuccess/ToolError response models
│   ├── metrics.py                  # Tool execution metrics
│   ├── report_generator.py         # Report generation service
│   ├── plugin.py                   # Plugin interface for extensibility
│   ├── decorators.py               # @log_execution, @track_metrics
│   ├── error_handling.py           # @handle_tool_errors decorator
│   ├── logging_config.py           # Structured logging setup
│   ├── memory.py                   # AI memory store (async SQLite)
│   ├── mitre_mapper.py             # MITRE ATT&CK framework mapping
│   ├── resource_manager.py         # Subprocess lifecycle management
│   └── validators.py               # Input validation
│
├── tools/                          # MCP Tool Implementations
│   ├── analysis/                   # Basic analysis tools
│   │   ├── static_analysis.py      # file, strings, binwalk
│   │   ├── lief_tools.py           # PE/ELF/Mach-O parsing
│   │   ├── diff_tools.py           # Binary comparison
│   │   └── signature_tools.py      # YARA scanning
│   │
│   ├── radare2/                    # Radare2 integration
│   │   ├── r2_analysis.py          # Core r2 analysis
│   │   ├── radare2_mcp_tools.py    # Advanced r2 tools (CFG, ESIL)
│   │   ├── r2_session.py           # Session management
│   │   └── r2_pool.py              # Connection pooling
│   │
│   ├── ghidra/                     # Ghidra decompilation
│   │   ├── decompilation.py        # smart_decompile, pseudo-code
│   │   └── ghidra_tools.py         # Structure/Enum management
│   │
│   ├── malware/                    # Malware analysis & defense
│   │   ├── dormant_detector.py     # Hidden threat detection
│   │   ├── adaptive_vaccine.py     # Defense generation
│   │   ├── vulnerability_hunter.py # Vulnerability detection
│   │   ├── ioc_tools.py            # IOC extraction
│   │   └── yara_tools.py           # YARA rule management
│   │
│   ├── common/                     # Cross-cutting concerns
│   │   ├── file_operations.py      # Workspace file management
│   │   ├── server_tools.py         # Health checks, metrics
│   │   └── memory_tools.py         # AI memory operations
│   │
│   └── report/                     # Report generation (v3.1)
│       ├── report_tools.py         # Core report engine
│       ├── report_mcp_tools.py     # MCP tool registration
│       ├── session.py              # Analysis session tracking
│       └── email.py                # SMTP integration
│
├── prompts.py                      # AI reasoning prompts (5 modes)
├── resources.py                    # Dynamic MCP resources (reversecore:// URIs)
└── server.py                       # FastMCP server initialization & HTTP setup
```

## 🐳 Docker Deployment

### Multi-Architecture Support

The unified `Dockerfile` automatically detects your system architecture:

| Architecture | Auto-Detected | Support |
|--------------|---------------|---------|
| x86_64 (Intel/AMD) | ✅ | Full support |
| ARM64 (Apple Silicon M1-M4) | ✅ | Full support |

### Run Commands

```bash
# Using convenience script (auto-detects architecture)
./scripts/run-docker.sh              # Start
./scripts/run-docker.sh stop         # Stop
./scripts/run-docker.sh logs         # View logs
./scripts/run-docker.sh shell        # Shell access

# Manual Docker build (works for all architectures)
docker build -t reversecore-mcp:latest .

# Or using Docker Compose
docker compose up -d
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
- 📊 **76% coverage**
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
