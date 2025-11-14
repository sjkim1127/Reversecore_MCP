# Reversecore_MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-0.1.0%2B-green)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)

An enterprise-grade MCP (Model Context Protocol) server that empowers AI agents to perform reverse engineering tasks through natural language commands. This server provides a secure, performant, and standardized interface to common reverse engineering CLI tools and Python libraries, enabling AI assistants to conduct automated malware triage, binary analysis, and security research workflows.

## 🌟 Key Features

- **🔒 Security-First Design**: No shell=True, comprehensive input validation, path sanitization
- **⚡ High Performance**: Streaming output for large files, configurable limits, adaptive polling
- **🛠️ Comprehensive Toolset**: Radare2, strings, binwalk, YARA, Capstone, LIEF support
- **🐳 Docker Ready**: Pre-configured containerized deployment with all dependencies
- **🔌 MCP Compatible**: Works with Cursor AI, Claude Desktop, and other MCP clients
- **📊 Production Ready**: Extensive error handling, logging, rate limiting, and monitoring

## 📑 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [Project Structure](#project-structure)
  - [Design Principles](#design-principles)
- [Technical Decisions](#technical-decisions)
  - [Security: Command Injection Prevention](#security-command-injection-prevention)
  - [Scalability: FastMCP Modular Architecture](#scalability-fastmcp-modular-architecture)
  - [Performance: Large Output Handling](#performance-large-output-handling)
  - [Dependencies: Version Management Strategy](#dependencies-version-management-strategy)
- [Installation](#installation)
  - [Using Docker (Recommended)](#using-docker-recommended)
  - [Local Installation](#local-installation)
- [MCP Client Integration](#mcp-client-integration)
  - [Cursor AI Setup](#cursor-ai-setup-http-standard-connection)
  - [Claude Desktop Setup](#claude-desktop-setup)
  - [Other MCP Clients](#other-mcp-clients)
- [Usage](#usage)
  - [Project Goal](#project-goal)
  - [API Examples](#api-examples)
- [Available Tools](#available-tools)
- [Performance](#performance)
- [Security](#security)
- [Error Handling](#error-handling)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

## Overview

### What is MCP?

The Model Context Protocol (MCP) is an open standard that enables AI applications to securely connect to external data sources and tools. It provides a universal interface for AI assistants to interact with various services while maintaining security and performance.

### What is Reversecore_MCP?

Reversecore_MCP is a specialized MCP server designed for reverse engineering and malware analysis workflows. It provides a secure, standardized interface for AI agents to interact with industry-standard reverse engineering tools:

#### CLI Tools
- **`file`**: Identify file types and metadata
- **`strings`**: Extract printable strings from binaries
- **`radare2`**: Disassemble and analyze binary executables
- **`binwalk`**: Analyze and extract embedded files from firmware

#### Python Libraries
- **`yara-python`**: Pattern matching and malware detection
- **`capstone`**: Multi-architecture disassembly engine
- **`lief`**: Binary parsing and analysis (PE, ELF, Mach-O)

### Why Reversecore_MCP?

Traditional reverse engineering workflows require:
- Manual tool invocation and output parsing
- Deep knowledge of tool-specific command syntax
- Careful handling of security concerns
- Performance optimization for large files

Reversecore_MCP handles all of this automatically, allowing AI agents to focus on analysis rather than tool management. The server provides:
- ✅ **Automatic security validation** of all inputs
- ✅ **Streaming output** for large files (preventing OOM)
- ✅ **Graceful error handling** with user-friendly messages
- ✅ **Performance optimization** with configurable limits
- ✅ **Comprehensive logging** for debugging and auditing

## Architecture

### Project Structure

```
Reversecore_MCP/
├── reversecore_mcp/
│   ├── __init__.py
│   ├── server.py              # FastMCP server initialization
│   ├── tools/                 # Tool definitions
│   │   ├── __init__.py
│   │   ├── cli_tools.py       # CLI tool wrappers
│   │   └── lib_tools.py       # Library wrappers
│   └── core/                  # Core utilities
│       ├── __init__.py
│       ├── security.py        # Input validation
│       ├── execution.py       # Safe subprocess execution
│       └── exceptions.py      # Custom exceptions
├── Dockerfile                 # Containerized deployment
├── requirements.txt           # Python dependencies
└── README.md
```

### Design Principles

#### 1. Modularity
- Tools are organized by category (CLI vs. library) in separate modules
- Each tool module exports a registration function that registers tools with the FastMCP server
- `server.py` acts as the central registration point, importing and registering all tool modules

#### 2. Security First
- **No `shell=True`**: All subprocess calls use list-based arguments, never shell commands
- **No `shlex.quote()` on list arguments**: When using `subprocess.run(["cmd", arg1, arg2])`, arguments are passed directly to the process without shell interpretation, so quoting is unnecessary and would break commands
- **Input validation**: File paths and command strings are validated before use
- **Path resolution**: All file paths are resolved to absolute paths to prevent directory traversal

#### 3. Robustness
- Comprehensive error handling: All tool functions catch exceptions and return user-friendly error messages
- Never raise unhandled exceptions to the MCP layer
- Graceful degradation: Tools return error strings instead of crashing

#### 4. Performance
- **Streaming output**: Large outputs are streamed in chunks to prevent OOM
- **Configurable limits**: Output size and execution time limits are configurable per tool
- **Truncation warnings**: When output is truncated, a warning is included in the response

## Technical Decisions

### Security: Command Injection Prevention

**Decision**: Do NOT use `shlex.quote()` when passing arguments as a list to `subprocess.run()`.

**Rationale**:
- When using `subprocess.run(["r2", "-q", "-c", r2_command, file_path])`, arguments are passed directly to the process without shell interpretation
- `shlex.quote()` is only needed when constructing shell commands (with `shell=True`)
- Using `shlex.quote()` on list arguments would break commands like `"pdf @ main"` by adding quotes that radare2 would interpret literally
- **Best Practice**: Always use list arguments, never `shell=True`, validate and sanitize user input at the application layer

**Implementation**:
- All subprocess calls use list-based arguments
- Input validation functions in `core/security.py` validate file paths and command strings
- File paths are resolved to absolute paths and checked against allowed directories (if configured)

### Scalability: FastMCP Modular Architecture

**Decision**: Use registration functions pattern for tool organization.

**Rationale**:
- FastMCP does not have a router system like FastAPI's APIRouter
- FastMCP supports `MCPMixin` for component-based organization, but a simpler pattern is sufficient for this use case
- Each tool module exports a `register_*_tools(mcp: FastMCP)` function that registers all tools in that module

**Implementation Pattern**:
```python
# tools/cli_tools.py
def register_cli_tools(mcp: FastMCP) -> None:
    mcp.tool(run_strings)
    mcp.tool(run_radare2)

# server.py
from reversecore_mcp.tools import cli_tools, lib_tools

mcp = FastMCP(name="Reversecore_MCP")
cli_tools.register_cli_tools(mcp)
lib_tools.register_lib_tools(mcp)
```

### Performance: Large Output Handling

**Decision**: Implement streaming subprocess execution with configurable output limits.

**Rationale**:
- Large files (GB-scale) can cause OOM when using `capture_output=True`
- Need to support both streaming (for large outputs) and full capture (for small outputs)
- Should provide configurable max output size limits

**Implementation**:
- `core/execution.py` provides `execute_subprocess_streaming()` function
- Uses `subprocess.Popen` with `stdout=subprocess.PIPE`
- Reads output in 8KB chunks with size limits
- Returns truncated output with warning when limit is reached
- Tools like `run_strings` accept `max_output_size` parameter

### Dependencies: Version Management Strategy

**Decision**: Use Dockerfile with pinned package versions + r2pipe for radare2 integration.

**Rationale**:
- **Subprocess approach**: Simple but fragile - CLI output format changes between versions
- **r2pipe approach**: More stable API, better error handling, structured data access
- **Hybrid approach**: Use r2pipe for radare2 (primary), keep subprocess as fallback
- Pin versions in Dockerfile to ensure reproducibility

**Implementation**:
- Dockerfile installs system packages from Debian repos (latest stable versions)
- Python dependencies are specified in `requirements.txt` with version constraints
- `r2pipe` is used for radare2 operations (when implemented)
- Subprocess-based radare2 wrapper is kept as fallback

## Installation

### Using Docker (Recommended)

#### Build the Docker Image

```bash
# Build the Docker image
docker build -t reversecore-mcp .
```

#### Run the Server

Reversecore_MCP supports two transport modes, but starting with v1.1 the documentation “standard” is HTTP mode. The standard HTTP endpoint is `http://127.0.0.1:8000/mcp`.

**HTTP Mode (Standard/Recommended):**

```bash
# Run with HTTP transport on port 8000
# Mount your samples directory to /app/workspace
docker run -d \
  -p 8000:8000 \
  -v ./my_samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  --name reversecore-mcp \
  reversecore-mcp
```

**Stdio Mode (for local development):**

```bash
# Run with stdio transport (for local AI clients like Cursor)
docker run -it \
  -v ./my_samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  reversecore-mcp
```

**Important Notes:**
- All files to be analyzed must be placed in the mounted workspace directory (`/app/workspace`)
- The `REVERSECORE_WORKSPACE` environment variable sets the allowed workspace path
- YARA rule files can be placed in `/app/rules` (read-only) or in the workspace directory

### Local Installation

1. Install system dependencies:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install radare2 yara libyara-dev binutils
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the server:
   ```bash
   # HTTP mode (Standard)
   MCP_TRANSPORT=http python server.py

   # (Optional) Stdio mode
   MCP_TRANSPORT=stdio python server.py
   ```

## MCP Client Integration

Reversecore_MCP works with MCP-compatible clients. This guide focuses on Cursor AI and Claude Desktop, which are the most commonly used.

### Cursor AI setup (HTTP standard connection)

#### 1) Run the server

First, run the Reversecore_MCP server in HTTP mode.

```bash
docker run -d \
  -p 8000:8000 \
  -v ./my_samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  --name reversecore-mcp \
  reversecore-mcp
```

If the server is running correctly, you should be able to open `http://127.0.0.1:8000/docs` in your browser.

#### 2) Add the MCP server in Cursor

- Cursor → Settings → Cursor Settings → MCP → Add new global MCP server
- Add the following to `~/.cursor/mcp.json` (Windows: `C:\Users\<USER>\.cursor\mcp.json`).

```json
{
  "mcpServers": {
    "reversecore": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

To add it per-project instead, create a `.cursor/mcp.json` file in your project root with the same contents.

#### 3) Verify

- From the Cursor command palette or MCP panel, run “List available tools for server reversecore”
- If you see the tools listed (e.g., “Found N tools ...”), the connection is working

#### (Optional) Let Cursor manage a container/remote without running the server yourself

You can register the server using `command`/`args` so that Cursor starts it for you.

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-p", "8000:8000",
        "-v", "E:/Reversecore_Workspace:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=http",
        "reversecore-mcp"
      ]
    }
  }
}
```

### Claude Desktop setup

To set up Claude Desktop to use Reversecore_MCP, configure the MCP server in your Claude Desktop settings.

#### Setup steps

1) Run the Reversecore_MCP server in HTTP mode (same as “Run the server” above for Cursor).

2) In Claude Desktop → Settings → MCP Servers (or Developer), add a new server and set the URL to `http://127.0.0.1:8000/mcp`.

If you prefer to edit the settings file manually, use a configuration like the following:

**HTTP Transport (standard):**

```json
{
  "mcpServers": {
    "reversecore": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

Menu names and paths may vary slightly by Claude Desktop version. If there’s no UI to add an MCP server, edit the settings file directly.

#### Configuration File Location

Alternatively, you can directly edit the configuration file at:

**macOS:**
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

#### Important Notes

- Ensure Docker is installed and the `reversecore-mcp` image is built (`docker build -t reversecore-mcp .`).
- In HTTP mode, the server must be running before the client connects.
- Security: Analysis files must be located inside the workspace (`/app/workspace`); files outside this directory are inaccessible.
- Read-only YARA rules can be placed under `/app/rules`, or add extra read paths via the `REVERSECORE_READ_DIRS` environment variable.

#### Verification

After configuration:

1. Restart Claude Desktop completely
2. Look for the MCP server connection indicator in Claude Desktop (typically shown in the settings or as a connection status icon)
3. You should see "reversecore" listed as an available tool server
4. Test with a simple query: "What tools do you have available for reverse engineering?"
5. Try analyzing a file: "Can you identify the file type of sample.exe in my workspace?"

#### Troubleshooting

**Issue:** Claude Desktop shows "Connection failed" or cannot connect to the MCP server

- Verify Docker is running: `docker ps`
- Check that the image exists: `docker images | grep reversecore-mcp`
- If the image doesn't exist, build it: `docker build -t reversecore-mcp .`
- Review Docker logs: `docker logs reversecore-mcp` (if using HTTP mode with named container)
- Verify the absolute path in the configuration is correct and accessible

**Issue:** "File not found" errors when trying to analyze files

- Ensure files are in the mounted workspace directory on your host system
- Check the path mapping in the Docker command: `/host/path:/app/workspace`
- Verify the file path uses the container path (`/app/workspace/filename`) not the host path
- Confirm the `REVERSECORE_WORKSPACE` environment variable matches the mounted directory

**Issue:** Permission denied errors

- Ensure Docker has permission to access the mounted directory
- On Linux/macOS, check directory permissions: `ls -la /path/to/your/samples`
- On Windows, ensure the path is accessible to Docker Desktop

### Other MCP Clients

Reversecore_MCP follows the standard MCP protocol and should work with any MCP-compatible client. Configure the client to connect to:

- HTTP mode (standard): start the server in HTTP mode and point the client to `http://127.0.0.1:8000/mcp` (or your configured host/port)
- Stdio mode: provided for local development convenience. Start with `MCP_TRANSPORT=stdio` and use a client that supports stdio transport

For clients that support MCP over HTTP, ensure the Reversecore_MCP server is running in HTTP mode and accessible at the configured endpoint.

## Usage

### Project Goal

Reversecore_MCP is designed to enable AI agents to perform reverse engineering tasks through natural language commands. The server wraps common reverse engineering CLI tools and Python libraries, making them accessible to AI assistants for automated triage and analysis workflows.

### Real-World Use Cases

#### 🔍 Malware Triage
Quickly identify suspicious files and extract indicators of compromise (IOCs):
```
AI Agent: "Analyze sample.exe in my workspace. What type of file is it and does it contain any suspicious strings?"
→ Uses run_file + run_strings to identify PE executable and extract URLs, IPs, suspicious API calls
```

#### 🛡️ Security Research
Automate detection of known malware families using YARA rules:
```
AI Agent: "Scan all files in workspace with my malware detection rules"
→ Uses run_yara to match against custom rulesets and identify threats
```

#### 🔬 Binary Analysis
Deep dive into executable structure and behavior:
```
AI Agent: "Disassemble the main function and identify what APIs it calls"
→ Uses run_radare2 to disassemble code and extract function calls
```

#### 📊 Firmware Analysis
Analyze embedded systems and extract firmware components:
```
AI Agent: "What file systems are embedded in this firmware image?"
→ Uses run_binwalk to identify embedded file systems, bootloaders, etc.
```

### API Examples

The server exposes tools that can be called by AI agents via the MCP protocol. Below are examples of how to use each tool:

#### 1. Identify File Type (`run_file`)

**Tool Call:**
```json
{
  "tool": "run_file",
  "arguments": {
    "file_path": "/app/workspace/sample.exe"
  }
}
```

**Response:**
```
PE32 executable (GUI) Intel 80386, for MS Windows
```

**Use Case**: Initial file identification during triage

#### 2. Extract Strings (`run_strings`)

**Tool Call:**
```json
{
  "tool": "run_strings",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "min_length": 4,
    "max_output_size": 10000000,
    "timeout": 300
  }
}
```

**Response:**
```
Hello World
GetProcAddress
LoadLibraryA
kernel32.dll
http://malicious-domain.com/payload
C:\Windows\System32\cmd.exe
...
```

**Use Case**: Extract URLs, file paths, API names, debug strings for IOC extraction

#### 3. Disassemble with radare2 (`run_radare2`)

**Tool Call:**
```json
{
  "tool": "run_radare2",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "r2_command": "pdf @ main",
    "max_output_size": 10000000,
    "timeout": 300
  }
}
```

**Response:**
```
            ;-- main:
/ (fcn) sym.main 42
|   sym.main ();
|           0x00401000      55             push rbp
|           0x00401001      4889e5         mov rbp, rsp
|           0x00401004      4883ec20       sub rsp, 0x20
|           0x00401008      488d0d...      lea rcx, str.Hello_World
|           0x0040100f      e8...          call sym.imp.printf
...
```

**Use Case**: Analyze function behavior, control flow, identify malicious code patterns

**Common Commands**:
- `pdf @ main` - Disassemble main function
- `afl` - List all functions
- `ii` - List imports
- `iz` - List strings in data section
- `afi @ main` - Show function info

#### 4. Scan with YARA (`run_yara`)

**Tool Call:**
```json
{
  "tool": "run_yara",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "rule_file": "/app/rules/malware.yar",
    "timeout": 300
  }
}
```

**Response:**
```json
[
  {
    "rule": "SuspiciousPE",
    "namespace": "default",
    "tags": ["malware", "trojan"],
    "meta": {"author": "analyst", "description": "Detects suspicious PE behavior"},
    "strings": [
      {
        "identifier": "$s1",
        "offset": 1024,
        "matched_data": "48656c6c6f20576f726c64"
      },
      {
        "identifier": "$api1",
        "offset": 2048,
        "matched_data": "437265617465526d6f746554687265616445"
      }
    ]
  }
]
```

**Use Case**: Automated malware family detection, compliance scanning, threat hunting

#### 5. Disassemble with Capstone (`disassemble_with_capstone`)

**Tool Call:**
```json
{
  "tool": "disassemble_with_capstone",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "offset": 0,
    "size": 1024,
    "arch": "x86",
    "mode": "64"
  }
}
```

**Response:**
```
0x0:	push	rbp
0x1:	mov	rbp, rsp
0x4:	sub	rsp, 0x20
0x8:	lea	rcx, [rip + 0x100]
0xf:	call	0x200
...
```

**Use Case**: Quick disassembly of specific code sections, shellcode analysis

**Supported Architectures**:
- x86 (32-bit and 64-bit)
- ARM, ARM64
- MIPS, PowerPC, SPARC
- And more...

#### 6. Parse Binary with LIEF (`parse_binary_with_lief`)

**Tool Call:**
```json
{
  "tool": "parse_binary_with_lief",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "timeout": 300
  }
}
```

**Response:**
```json
{
  "format": "PE",
  "architecture": "x86-64",
  "entrypoint": "0x1400",
  "sections": [
    {
      "name": ".text",
      "virtual_address": "0x1000",
      "size": 16384,
      "entropy": 6.42
    },
    {
      "name": ".data",
      "virtual_address": "0x5000",
      "size": 4096,
      "entropy": 3.21
    }
  ],
  "imports": [
    {
      "library": "kernel32.dll",
      "functions": ["CreateFileA", "ReadFile", "WriteFile"]
    }
  ],
  "exports": [],
  "security_features": {
    "has_nx": true,
    "has_aslr": true,
    "has_pie": false,
    "has_canary": true
  }
}
```

**Use Case**: Extract metadata, analyze binary structure, identify security features

### Natural Language Interaction

When using with AI assistants, you can use natural language instead of direct API calls:

**Example Conversations**:

```
User: "I have a suspicious executable called malware.exe in my workspace. 
       Can you analyze it and tell me what it does?"

AI Agent: 
1. Uses run_file to identify file type
2. Uses run_strings to extract IOCs
3. Uses run_yara to check against known malware signatures
4. Uses run_radare2 to analyze main function
5. Provides comprehensive report with findings
```

```
User: "Scan all PE files in my workspace for ransomware indicators"

AI Agent:
1. Lists files in workspace
2. For each PE file:
   - Uses run_yara with ransomware rules
   - Uses run_strings to look for ransom notes
   - Checks for suspicious API calls
3. Summarizes results with risk assessment
```

```
User: "What security features are enabled in this binary?"

AI Agent:
1. Uses parse_binary_with_lief to extract security info
2. Reports ASLR, DEP/NX, stack canaries, code signing status
3. Provides recommendations based on findings
```

### Best Practices

#### For AI Agents
- **Start broad, then narrow**: Use `run_file` for identification, then targeted tools
- **Set appropriate timeouts**: Large files may need 5-10 minutes
- **Use output limits**: Prevent overwhelming responses with `max_output_size`
- **Combine tools**: Multiple tools provide better context than any single tool

#### For Users
- **Organize workspace**: Keep samples in organized directories
- **Use YARA rules**: Build a library of rules for common threats
- **Review logs**: Check logs for errors and performance issues
- **Isolate environment**: Always analyze malware in isolated systems

## Available Tools

### CLI Tools

- **`run_file`**: Identify file type using the `file` command
  - Returns file type, encoding, architecture information
  - Fast identification for initial triage
  - Example: `PE32 executable (GUI) Intel 80386, for MS Windows`

- **`run_strings`**: Extract printable strings from binary files
  - Configurable minimum string length
  - Streaming support for large files
  - Configurable output size limits (default: 10MB)
  - Example use: Extract URLs, file paths, debug strings

- **`run_radare2`**: Execute radare2 commands on binary files
  - Disassemble functions, analyze control flow
  - Extract function signatures and symbols
  - Configurable output limits and timeouts
  - Example: `pdf @ main` to disassemble main function

- **`run_binwalk`**: Analyze and extract embedded files from firmware/images
  - Identify embedded file systems and archives
  - Entropy analysis for packed sections
  - Signature-based file detection
  - Note: Extraction not enabled in v1.0 (analysis only)

### Library Tools

- **`run_yara`**: Scan files using YARA rules
  - Supports custom rule files
  - Returns detailed match information (rule, namespace, tags, strings)
  - JSON-formatted output for easy parsing
  - Configurable timeout (default: 300s)

- **`disassemble_with_capstone`**: Disassemble binary code using Capstone
  - Multi-architecture support: x86, x86-64, ARM, ARM64, MIPS, etc.
  - Configurable offset and size
  - Returns formatted assembly with addresses
  - Example: Disassemble shellcode or specific code sections

- **`parse_binary_with_lief`**: Parse binary files with LIEF
  - Supports PE, ELF, and Mach-O formats
  - Extract headers, sections, imports, exports
  - Identify security features (ASLR, DEP, code signing)
  - Maximum file size: 1GB (configurable)

## Performance

Reversecore_MCP is optimized for production workloads and large-scale analysis:

### Key Performance Features

#### 🚀 Streaming Output Processing
- Handles files up to GB scale without memory issues
- 8KB chunk-based reading with configurable limits
- Automatic truncation with warnings when limits exceeded
- Default max output: 10MB per tool invocation

#### ⚡ Adaptive Polling (Windows)
- Reduces CPU usage by 50% for long-running operations
- Starts at 50ms polling interval, adapts to 100ms max
- Resets to 50ms when data is received
- Maintains responsiveness while minimizing resource usage

#### 🎯 Optimized Path Validation
- 75% reduction in path conversion overhead
- Cached string conversions for repeated validations
- Early returns for common cases
- Efficient directory checks with minimal filesystem calls

#### 📊 YARA Processing Improvements
- 60% faster match processing for large result sets
- Eliminates redundant attribute lookups
- Optimized type checking with `isinstance()`
- Can process 2,500+ string matches in under 1 second

#### 💾 Memory-Efficient Operations
- Enumerate-based iteration instead of list slicing
- No intermediate list creation for large datasets
- Lazy evaluation where possible
- Configurable limits prevent OOM conditions

### Performance Benchmarks

| Operation | Performance | Notes |
|-----------|-------------|-------|
| File Type Detection | < 100ms | For typical binaries |
| String Extraction | Streaming | No memory limit with streaming |
| YARA Scanning | 2,500 matches/sec | Large ruleset performance |
| Path Validation | 1,000 validations/sec | Cached conversions |
| Disassembly | Depends on size | Configurable output limits |

### Configuration

Performance can be tuned via environment variables:

```bash
# Maximum output size per tool (bytes)
TOOL_MAX_OUTPUT_SIZE=10485760  # 10MB default

# LIEF maximum file size (bytes)
LIEF_MAX_FILE_SIZE=1000000000  # 1GB default

# Tool timeouts (seconds)
TOOL_TIMEOUT=300  # 5 minutes default

# Rate limiting (requests per minute, HTTP mode only)
RATE_LIMIT=60  # 60 requests/minute default
```

For detailed performance optimization documentation, see [docs/PERFORMANCE_OPTIMIZATIONS.md](docs/PERFORMANCE_OPTIMIZATIONS.md).

## Security

Security is a top priority in Reversecore_MCP. The server implements multiple layers of protection:

### 🔒 Security Features

#### Command Injection Prevention
- **No shell=True**: All subprocess calls use list-based arguments
- **No shell interpretation**: Arguments passed directly to processes
- **No shlex.quote()**: Not needed with list arguments (would break commands)
- **Validated commands**: All user inputs validated before execution

#### Path Traversal Protection
- **Absolute path resolution**: All paths converted to absolute form
- **Directory whitelisting**: Only workspace and read-only dirs accessible
- **Path validation**: Checked against allowed directories before access
- **Symlink handling**: Paths resolved to prevent symlink attacks

#### Input Validation
- **Type checking**: All parameters validated for correct types
- **Range validation**: Numeric parameters checked for valid ranges
- **Command sanitization**: Radare2 commands validated against safe patterns
- **File existence checks**: Verified before tool execution

#### Resource Limits
- **Output size limits**: Prevent memory exhaustion (default: 10MB)
- **Execution timeouts**: Prevent runaway processes (default: 300s)
- **Rate limiting**: HTTP mode rate limiting (default: 60 req/min)
- **File size limits**: LIEF parsing limited to 1GB

### Security Best Practices

When deploying Reversecore_MCP:

1. **Use Docker**: Containerization provides process isolation
2. **Mount minimal directories**: Only mount necessary workspace paths
3. **Read-only rules**: Place YARA rules in read-only directories
4. **Network isolation**: In HTTP mode, use firewall rules or reverse proxy
5. **Monitor logs**: Enable logging to detect suspicious activity
6. **Keep updated**: Regularly update base image and dependencies

### Workspace Configuration

```bash
# Recommended Docker configuration
docker run -d \
  -p 127.0.0.1:8000:8000 \  # Bind to localhost only
  -v ./samples:/app/workspace:ro \  # Read-only if possible
  -v ./rules:/app/rules:ro \  # YARA rules read-only
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e REVERSECORE_READ_DIRS=/app/rules \
  --security-opt=no-new-privileges \  # Additional security
  --cap-drop=ALL \  # Drop all capabilities
  --name reversecore-mcp \
  reversecore-mcp
```

### Security Auditing

- ✅ No `shell=True` usage anywhere in codebase
- ✅ All file paths validated before access
- ✅ No arbitrary code execution capabilities
- ✅ Comprehensive input validation
- ✅ Error messages don't leak sensitive information
- ✅ CodeQL security scanning enabled (see [PERFORMANCE_SUMMARY.md](PERFORMANCE_SUMMARY.md))

For security issues, please see our security policy or contact the maintainers directly.

## Error Handling

### Result Type System (Internal)

All tools internally use a Result type system for structured error handling, which provides:
- Type-safe success/failure responses
- Consistent error codes and messages
- Optional hints for error resolution
- Metadata for debugging

**Internal Result Structure:**
```python
# Success result
{
    "status": "success",
    "data": "tool output...",  # Can be string or dict
    "metadata": {
        "bytes_read": 1024,
        "execution_time": 1.5
    }
}

# Failure result
{
    "status": "error",
    "error_code": "TOOL_NOT_FOUND",
    "message": "strings command not found",
    "hint": "Install with: apt-get install binutils"
}
```

### Public API Response Format

For backward compatibility, all tools return error messages as strings. Tools that return structured data (like YARA) will return JSON strings. Error messages include:
- Tool not found errors
- Timeout errors
- Invalid input errors
- Command execution failures

Example error response:
```
Error: File not found
Hint: Ensure the file exists in the workspace directory
```

Example YARA success response:
```json
{
  "matches": [
    {
      "rule": "malware_rule",
      "namespace": "default",
      "tags": ["trojan"],
      "strings": [
        {
          "identifier": "$suspicious_string",
          "offset": 1234,
          "matched_data": "48656c6c6f"
        }
      ]
    }
  ],
  "match_count": 1
}
```

## Development

### System Requirements

- **Python**: 3.11 or higher
- **Operating System**: Linux (recommended), macOS, or Windows
- **Memory**: 4GB minimum, 8GB+ recommended for large files
- **Disk**: 2GB for dependencies, plus space for analysis files

### Adding New Tools

1. **Create tool function** in the appropriate module:
   - `reversecore_mcp/tools/cli_tools.py` for CLI tools
   - `reversecore_mcp/tools/lib_tools.py` for library-based tools

2. **Follow the pattern**:
```python
@log_execution(tool_name="my_tool")
def my_tool(file_path: str, param: str, timeout: int = 300) -> str:
    """
    Tool description for MCP clients.
    
    Args:
        file_path: Path to file to analyze
        param: Tool-specific parameter
        timeout: Maximum execution time in seconds
        
    Returns:
        Tool output as string
    """
    try:
        # Validate inputs
        validate_file_path(file_path)
        
        # Execute tool
        result = execute_subprocess_streaming(
            ["tool", "arg1", file_path],
            timeout=timeout
        )
        
        return result
    except Exception as e:
        return format_error(e, "my_tool")
```

3. **Register the tool** in the module's registration function:
```python
def register_cli_tools(mcp: FastMCP) -> None:
    mcp.tool(run_file)
    mcp.tool(run_strings)
    mcp.tool(my_tool)  # Add your tool here
```

4. **Test your tool**:
```bash
pytest tests/unit/test_cli_tools.py -k test_my_tool
```

### Testing

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=reversecore_mcp --cov-report=html

# Run specific test file
pytest tests/unit/test_cli_tools.py

# Run with verbose output
pytest tests/ -v
```

### Code Quality

```bash
# Format code with black
black reversecore_mcp/ tests/

# Lint with ruff
ruff check reversecore_mcp/ tests/

# Type checking with mypy
mypy reversecore_mcp/

# Security scanning with bandit
bandit -r reversecore_mcp/
```

### Building Docker Image

```bash
# Build the image
docker build -t reversecore-mcp:dev .

# Test the image
docker run --rm reversecore-mcp:dev python -c "import reversecore_mcp; print('OK')"

# Run tests in container
docker run --rm reversecore-mcp:dev pytest /app/tests/
```

## Troubleshooting

### Common Issues and Solutions

#### 🔴 "Connection failed" in MCP client

**Symptoms**: Claude Desktop or Cursor shows connection error

**Solutions**:
1. Verify Docker is running: `docker ps`
2. Check if container is running: `docker ps | grep reversecore`
3. View logs: `docker logs reversecore-mcp`
4. Restart container: `docker restart reversecore-mcp`
5. Check port binding: `netstat -an | grep 8000` (should show LISTENING)

For stdio mode:
```bash
# Test the command directly
MCP_TRANSPORT=stdio python -m reversecore_mcp.server
# Should not exit immediately, wait for input
```

#### 🔴 "File not found" when analyzing files

**Symptoms**: Tool returns file not found error

**Solutions**:
1. Ensure file is in mounted workspace:
   ```bash
   ls -la /path/to/your/samples/
   ```
2. Check Docker volume mount:
   ```bash
   docker inspect reversecore-mcp | grep -A 10 Mounts
   ```
3. Verify file path uses container path:
   - ✅ Correct: `/app/workspace/sample.exe`
   - ❌ Wrong: `/home/user/samples/sample.exe`
4. Check REVERSECORE_WORKSPACE environment variable:
   ```bash
   docker exec reversecore-mcp env | grep REVERSECORE
   ```

#### 🔴 "Permission denied" errors

**Symptoms**: Cannot access files or directories

**Solutions**:
1. Check directory permissions on host:
   ```bash
   ls -la /path/to/samples/
   # Should be readable by all or by UID 1000 (typical Docker user)
   ```
2. Fix permissions if needed:
   ```bash
   chmod -R 755 /path/to/samples/
   ```
3. On Linux, check SELinux/AppArmor:
   ```bash
   # Add :z flag to docker run for SELinux
   -v ./samples:/app/workspace:z
   ```

#### 🔴 High CPU usage

**Symptoms**: Container consuming excessive CPU

**Solutions**:
1. Check for runaway processes:
   ```bash
   docker exec reversecore-mcp ps aux
   ```
2. Review tool timeout settings:
   ```bash
   # Reduce timeouts if needed
   docker run -e TOOL_TIMEOUT=60 ...
   ```
3. Enable rate limiting (HTTP mode):
   ```bash
   docker run -e RATE_LIMIT=30 ...
   ```
4. Review logs for repeated errors:
   ```bash
   docker logs reversecore-mcp --tail 100
   ```

#### 🔴 "Module not found" errors

**Symptoms**: Import errors when starting server

**Solutions**:
1. Verify Python dependencies:
   ```bash
   docker exec reversecore-mcp pip list
   ```
2. Rebuild Docker image:
   ```bash
   docker build --no-cache -t reversecore-mcp .
   ```
3. For local installation, check PYTHONPATH:
   ```bash
   export PYTHONPATH=/path/to/Reversecore_MCP:$PYTHONPATH
   ```
   See [docs/pythonpath_setup.md](docs/pythonpath_setup.md) for details.

#### 🔴 Radare2 command failures

**Symptoms**: r2 commands return errors or unexpected output

**Solutions**:
1. Test command manually:
   ```bash
   r2 -q -c "pdf @ main" /path/to/binary
   ```
2. Check command syntax (no shell metacharacters):
   - ✅ Correct: `pdf @ main`
   - ❌ Wrong: `pdf @ main && echo done`
3. Verify file is a supported format:
   ```bash
   file /path/to/binary
   ```
4. Increase timeout for large binaries:
   ```json
   {"timeout": 600}
   ```

#### 🔴 YARA scanning issues

**Symptoms**: YARA returns no matches or errors

**Solutions**:
1. Verify rule file syntax:
   ```bash
   yara -c /path/to/rules.yar
   ```
2. Check rule file location:
   - Rules in workspace: `/app/workspace/rules.yar`
   - Rules in read-only dir: `/app/rules/rules.yar`
3. Test rule manually:
   ```bash
   yara /path/to/rules.yar /path/to/sample
   ```
4. Review rule file permissions:
   ```bash
   ls -la /path/to/rules.yar
   ```

#### 🔴 Large file processing slow

**Symptoms**: Tools timeout or hang on large files

**Solutions**:
1. Increase timeout:
   ```json
   {"timeout": 900}  // 15 minutes
   ```
2. Reduce output size limits if applicable:
   ```json
   {"max_output_size": 5242880}  // 5MB
   ```
3. Use targeted analysis:
   - For strings: increase min_length to reduce output
   - For r2: use specific commands instead of full analysis
   - For LIEF: extract specific sections only
4. Enable streaming where available

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
# HTTP mode with debug logging
docker run -d \
  -p 8000:8000 \
  -v ./samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  -e LOG_LEVEL=DEBUG \
  -e LOG_FORMAT=json \
  --name reversecore-mcp \
  reversecore-mcp

# View logs
docker logs -f reversecore-mcp
```

### Getting Help

If you encounter issues not covered here:

1. Check [GitHub Issues](https://github.com/sjkim1127/Reversecore_MCP/issues)
2. Review [Performance Documentation](docs/PERFORMANCE_OPTIMIZATIONS.md)
3. Enable debug logging and review output
4. Create a new issue with:
   - Detailed description of the problem
   - Steps to reproduce
   - Log output (with sensitive data removed)
   - Environment details (OS, Docker version, etc.)

## FAQ

### General Questions

**Q: What is MCP and why should I use it?**

A: MCP (Model Context Protocol) is a standardized protocol for connecting AI assistants to external tools and data sources. Using Reversecore_MCP allows AI agents to perform reverse engineering tasks without requiring manual tool invocation or output parsing. It's particularly useful for automating malware triage, binary analysis, and security research workflows.

**Q: Is Reversecore_MCP free to use?**

A: Yes, Reversecore_MCP is open source under the MIT license. You can use it for personal, academic, or commercial purposes.

**Q: What AI assistants are compatible?**

A: Reversecore_MCP works with any MCP-compatible client. Tested clients include:
- Cursor AI (via HTTP or stdio)
- Claude Desktop (via HTTP)
- Custom MCP clients following the protocol specification

**Q: Can I use this for malware analysis?**

A: Yes, that's one of the primary use cases. The server is designed with security in mind (sandboxing, input validation, no code execution) and provides tools commonly used in malware analysis workflows. However, always analyze malware in an isolated environment.

### Installation & Setup

**Q: Should I use Docker or local installation?**

A: Docker is strongly recommended because:
- All dependencies pre-installed and version-locked
- Isolated environment for malware analysis
- Consistent behavior across platforms
- Easy to update and redeploy

Use local installation only for development or if Docker isn't available.

**Q: Can I run this on Windows?**

A: Yes, through Docker Desktop. Native Windows installation is possible but requires manual installation of tools (radare2, binwalk) which may have Windows-specific issues. Docker provides the most consistent experience.

**Q: How much disk space do I need?**

A: Approximately:
- 500MB for Docker image
- 1GB for Docker layer cache
- Additional space for your analysis files
- Optional: Space for log files

**Q: What Python version do I need?**

A: Python 3.11 or higher. The project uses modern Python features and type hints that require 3.11+.

### Usage & Features

**Q: What's the maximum file size I can analyze?**

A: It depends on the tool:
- **file, strings, radare2**: No hard limit, but output is limited (default 10MB)
- **YARA**: No file size limit, scans use memory-efficient methods
- **Capstone**: Specify offset and size, no practical limit
- **LIEF**: 1GB default limit (configurable via LIEF_MAX_FILE_SIZE)

For very large files, use streaming tools (strings, radare2) and specify output limits.

**Q: Can I analyze multiple files at once?**

A: Currently, each tool invocation analyzes one file. To analyze multiple files:
- Make multiple tool calls (AI agent handles this)
- Implement a custom script that calls tools in sequence
- Use batch processing features (planned for future release)

**Q: How do I add custom YARA rules?**

A: Place YARA rule files in:
1. Workspace directory: `/app/workspace/rules/` (read-write)
2. Rules directory: `/app/rules/` (read-only, recommended)

Mount additional directories via REVERSECORE_READ_DIRS:
```bash
docker run -e REVERSECORE_READ_DIRS=/app/rules,/app/custom_rules ...
```

**Q: Can I extract files with binwalk?**

A: Currently, binwalk is analysis-only (no extraction) for security reasons. This prevents uncontrolled file creation in the workspace. File extraction may be added in a future release with appropriate safeguards.

**Q: What radare2 commands are supported?**

A: Read-only commands only, validated against a whitelist. Supported commands include:
- Disassembly: `pdf`, `pd`, `pdc`
- Analysis: `aaa`, `afl`, `afi`, `afv`
- Information: `iI`, `iz`, `ii`
- Hexdump: `px`, `pxw`, `pxq`

Commands that modify files or execute code are blocked.

### Performance & Optimization

**Q: Why is my analysis slow?**

A: Common causes:
- Large files with default timeout (increase timeout)
- Expensive radare2 commands (use targeted commands)
- Large output (reduce max_output_size or increase min_length for strings)
- First-time container startup (subsequent runs are faster)

See [Performance](#performance) section for optimization tips.

**Q: How many requests can it handle?**

A: In HTTP mode:
- Default rate limit: 60 requests/minute per client
- No concurrency limit (limited by system resources)
- Tested with multiple simultaneous clients

For higher throughput, increase RATE_LIMIT or deploy multiple instances.

**Q: Will it run out of memory?**

A: No, with proper configuration:
- Streaming output prevents OOM on large files
- Configurable output limits (default 10MB)
- Tools use memory-efficient processing
- LIEF has 1GB file size limit

### Security & Safety

**Q: Is it safe to analyze malware with this tool?**

A: The tool provides several safety features:
- No arbitrary code execution
- Input validation and path sanitization
- Sandboxed in Docker container
- No write access to arbitrary locations

However, always analyze malware in a dedicated, isolated environment (VM, air-gapped system).

**Q: Can AI agents execute arbitrary commands?**

A: No. The server:
- Uses allow-list approach for commands
- No shell=True anywhere in code
- Validates all inputs before execution
- Blocks commands with shell metacharacters
- Restricts file access to workspace only

**Q: How are secrets handled?**

A: No secrets or credentials are required. File access is controlled via:
- Docker volume mounts (read-only where possible)
- Environment variables for path configuration
- No network access to external resources (by design)

**Q: What data is logged?**

A: Configurable via LOG_LEVEL:
- INFO: Tool invocations, errors, performance metrics
- DEBUG: Full command arguments, output sizes, timing details
- Logs don't include file contents or sensitive analysis results
- Structured JSON logging available (LOG_FORMAT=json)

### Troubleshooting

**Q: Claude Desktop won't connect, what should I check?**

A: Follow this checklist:
1. Is Docker running? (`docker ps`)
2. Is the container running? (`docker ps | grep reversecore`)
3. Can you access http://127.0.0.1:8000/docs in a browser?
4. Is the config file correct? (check `claude_desktop_config.json`)
5. Did you restart Claude Desktop after config change?

**Q: I get "file not found" but the file exists**

A: Check path mapping:
- Host path: `/home/user/samples/file.exe`
- Container path: `/app/workspace/file.exe` (use this in tool calls)
- Mount in docker run: `-v /home/user/samples:/app/workspace`

**Q: How do I see what the tool is actually doing?**

A: Enable debug logging:
```bash
docker run -e LOG_LEVEL=DEBUG ...
docker logs -f reversecore-mcp
```

This shows full command lines, timing, and output sizes.

### Development

**Q: How do I add a new tool?**

A: See [Development](#development) section for detailed steps. In summary:
1. Add function to appropriate module (cli_tools.py or lib_tools.py)
2. Use @log_execution decorator
3. Follow error handling patterns
4. Register in register_*_tools() function
5. Add tests

**Q: How do I contribute?**

A: See [Contributing](#contributing) section. We welcome:
- Bug reports and feature requests
- Documentation improvements
- New tool implementations
- Performance optimizations
- Security enhancements

**Q: Where can I get help with development?**

A: Check:
- Existing code for patterns and examples
- Tests for usage examples
- Documentation in docs/ directory
- GitHub Issues for discussions
- Inline code comments for implementation details

## Contributing

We welcome contributions to Reversecore_MCP! Here's how you can help:

### Ways to Contribute

- 🐛 **Report Bugs**: Open an issue with detailed reproduction steps
- 💡 **Suggest Features**: Propose new tools or enhancements
- 📝 **Improve Documentation**: Fix typos, add examples, clarify instructions
- 🔧 **Submit Code**: Add new tools, fix bugs, optimize performance
- 🧪 **Write Tests**: Improve test coverage and quality
- 🔒 **Security**: Report security issues responsibly (see security policy)

### Contribution Guidelines

1. **Fork and Clone**:
```bash
# Fork the repository under your GitHub account first, then clone your fork
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
```

2. **Create a Branch**:
```bash
git checkout -b feature/your-feature-name
```

3. **Make Changes**:
   - Follow existing code style and patterns
   - Add tests for new functionality
   - Update documentation as needed
   - Run linters and tests

4. **Test Your Changes**:
```bash
# Run tests
pytest tests/

# Run linters
ruff check reversecore_mcp/ tests/
black --check reversecore_mcp/ tests/

# Test Docker build
docker build -t reversecore-mcp:test .
```

5. **Commit and Push**:
```bash
git add .
git commit -m "Add: descriptive commit message"
git push origin feature/your-feature-name
```

6. **Open Pull Request**:
   - Describe your changes clearly
   - Reference related issues
   - Include test results
   - Wait for review

### Code Standards

- **Security First**: Never use `shell=True`, always validate inputs
- **Error Handling**: Return error strings, don't raise to MCP layer
- **Performance**: Use streaming for large outputs, respect limits
- **Documentation**: Add docstrings and update README for new features
- **Testing**: Write unit tests for new code paths
- **Type Hints**: Use type annotations for all function signatures

### Testing Requirements

All PRs must:
- ✅ Pass all existing tests
- ✅ Include tests for new functionality
- ✅ Maintain or improve test coverage
- ✅ Pass linting checks (ruff, black)
- ✅ Pass security scans (CodeQL, if applicable)

### Review Process

1. Automated tests run on PR submission
2. Maintainer reviews code and provides feedback
3. Address feedback and update PR
4. Once approved, maintainer merges PR

### Questions?

Feel free to:
- Open a discussion in GitHub Discussions
- Comment on related issues
- Reach out to maintainers

Thank you for contributing! 🙏

## License

MIT License - see [LICENSE](LICENSE) file for details.

### Third-Party Dependencies

This project uses several open-source tools and libraries:

- **Radare2**: LGPL-3.0 ([radare.org](https://radare.org))
- **YARA**: Apache 2.0 ([virustotal.github.io/yara](https://virustotal.github.io/yara/))
- **Capstone**: BSD License ([capstone-engine.org](https://www.capstone-engine.org/))
- **LIEF**: Apache 2.0 ([lief-project.github.io](https://lief-project.github.io/))
- **FastMCP**: Apache 2.0 ([github.com/jlowin/fastmcp](https://github.com/jlowin/fastmcp))
- **binwalk**: MIT License ([github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk))

Please review and comply with each dependency's license terms.

---

## Additional Resources

### Documentation
- [Performance Optimizations](docs/PERFORMANCE_OPTIMIZATIONS.md) - Detailed performance benchmarks and optimization techniques
- [Python Path Setup](docs/pythonpath_setup.md) - Configuration guide for local development
- [Performance Summary](PERFORMANCE_SUMMARY.md) - Recent performance improvements and impact

### External Links
- [Model Context Protocol](https://modelcontextprotocol.io/) - Official MCP specification
- [FastMCP Documentation](https://github.com/jlowin/fastmcp) - FastMCP framework docs
- [Radare2 Book](https://book.rada.re/) - Comprehensive radare2 guide
- [YARA Documentation](https://yara.readthedocs.io/) - YARA rule writing guide

### Community
- [GitHub Repository](https://github.com/sjkim1127/Reversecore_MCP) - Source code and issues
- [GitHub Discussions](https://github.com/sjkim1127/Reversecore_MCP/discussions) - Questions and ideas
- [Issue Tracker](https://github.com/sjkim1127/Reversecore_MCP/issues) - Bug reports and feature requests

---

## Acknowledgments

Special thanks to:
- The Radare2 team for their powerful reverse engineering framework
- The YARA project for pattern matching capabilities
- The Capstone team for multi-architecture disassembly
- The LIEF project for binary parsing utilities
- The FastMCP maintainers for the MCP framework
- All contributors and users of Reversecore_MCP

---

**Built with ❤️ for the reverse engineering and security research community**

