# Reversecore_MCP

![Icon](icon.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13.1-green)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/tests-852%20passed-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-75%25-green)](htmlcov/)

[🇰🇷 한국어 (Korean)](README_KR.md)

An enterprise-grade MCP (Model Context Protocol) server for AI-powered reverse engineering. Enables AI agents to perform comprehensive binary analysis through natural language commands.

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

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/path/to/workspace:/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp"
      ]
    }
  }
}
```

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

### 🛠️ Core Tools

| Category | Tools |
|----------|-------|
| **Basic Analysis** | \`run_file\`, \`run_strings\`, \`run_binwalk\` |
| **Disassembly** | \`run_radare2\`, \`disassemble_with_capstone\` |
| **Decompilation** | \`smart_decompile\`, \`get_pseudo_code\` (Ghidra/r2) |
| **Advanced** | \`analyze_xrefs\`, \`recover_structures\`, \`emulate_machine_code\` |
| **Defense** | \`generate_yara_rule\`, \`adaptive_vaccine\` |
| **Binary Parsing** | \`parse_binary_with_lief\`, \`extract_iocs\` |
| **Diffing** | \`diff_binaries\`, \`match_libraries\` |

## 📊 Analysis Workflow

```
📥 Upload → 🔍 Triage → 🔗 X-Refs → 🏗️ Structures → 📝 Decompile → 🛡️ Defense
```

**Use built-in prompts for guided analysis:**

- \`full_analysis_mode\` - Comprehensive malware analysis
- \`basic_analysis_mode\` - Quick triage
- \`game_analysis_mode\` - Game client reverse engineering
- \`firmware_analysis_mode\` - IoT/Firmware analysis

## 🏗️ Architecture

```
reversecore_mcp/
├── core/                 # Infrastructure
│   ├── config.py         # Configuration management
│   ├── container.py      # Dependency injection
│   ├── ghidra.py         # Ghidra integration
│   ├── r2_helpers.py     # Radare2 utilities
│   ├── result.py         # ToolSuccess/ToolError models
│   └── security.py       # Input validation
├── tools/                # MCP Tools
│   ├── cli_tools.py      # CLI wrappers
│   ├── decompilation.py  # Decompilers
│   ├── ghost_trace.py    # Hidden threat detection
│   ├── trinity_defense.py # Automated defense
│   └── ...
├── prompts.py            # Analysis prompts
└── resources.py          # Dynamic resources
```

## 🐳 Docker Deployment

### Multi-Architecture Support

| File | Architecture | Use Case |
|------|--------------|----------|
| \`Dockerfile\` | x86_64 (Intel/AMD) | Linux servers, Intel Macs |
| \`Dockerfile.arm64\` | ARM64 | Apple Silicon Macs |

### Run Commands

```bash
# Using convenience script (auto-detects architecture)
./scripts/run-docker.sh              # Start
./scripts/run-docker.sh stop         # Stop
./scripts/run-docker.sh logs         # View logs
./scripts/run-docker.sh shell        # Shell access

# Manual Docker commands
docker build -t reversecore-mcp .
docker run -it -p 8000:8000 \
  -v \$(pwd)/workspace:/app/workspace \
  reversecore-mcp
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
