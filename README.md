# Reversecore_MCP

An MCP (Model Context Protocol) server that enables AI agents to perform reverse engineering tasks through natural language commands. This server wraps common reverse engineering CLI tools and Python libraries, making them accessible to AI assistants for automated triage and analysis workflows.

## Overview

Reversecore_MCP provides a standardized interface for AI agents to interact with reverse engineering tools such as:
- **CLI Tools**: `file`, `strings`, `radare2`, `binwalk`
- **Python Libraries**: `yara-python`, `capstone`

The server handles security, error handling, and performance optimization (streaming, output limits) automatically, allowing AI agents to focus on analysis rather than tool management.

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

The server supports two transport modes: **stdio** (for local AI clients) and **http** (for network-based AI agents).

**HTTP Mode (Default in Docker):**

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
   # Stdio mode (default)
   python -m reversecore_mcp.server
   
   # HTTP mode
   MCP_TRANSPORT=http python -m reversecore_mcp.server
   ```

## MCP Client Integration

Reversecore_MCP supports integration with various MCP-compatible AI clients. Below are setup instructions for popular clients.

### Example 1: Claude Desktop

To set up Claude Desktop to use Reversecore_MCP, configure the MCP server in your Claude Desktop settings.

#### Configuration Steps

1. Open Claude Desktop
2. Navigate to `Claude` → `Settings` → `Developer` → `Edit Config`
3. Add the following configuration to `claude_desktop_config.json`:

**For Stdio Transport (Recommended for local use):**

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "/ABSOLUTE_PATH_TO_YOUR_SAMPLES:/app/workspace",
        "-e",
        "REVERSECORE_WORKSPACE=/app/workspace",
        "-e",
        "MCP_TRANSPORT=stdio",
        "reversecore-mcp"
      ]
    }
  }
}
```

**For HTTP Transport (Advanced - for remote/networked use):**

First, start the Reversecore_MCP server:

```bash
docker run -d \
  -p 8000:8000 \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  --name reversecore-mcp \
  reversecore-mcp
```

Then configure Claude Desktop to connect via HTTP. Note that Claude Desktop may require additional configuration or a custom HTTP client script for HTTP transport mode. For most users, stdio mode (above) is recommended.

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

- Replace `/ABSOLUTE_PATH_TO_YOUR_SAMPLES` with the actual absolute path to your binary samples directory
- Ensure Docker is installed and the `reversecore-mcp` image is built (run `docker build -t reversecore-mcp .`)
- For stdio mode, Claude Desktop will automatically start/stop the container for each session
- For HTTP mode, the server must be running before starting Claude Desktop
- **Security**: All files must be placed in the mounted workspace directory (`/app/workspace`) for security. Files outside this directory cannot be accessed.
- The workspace directory restriction prevents unauthorized file access and path traversal attacks
- For read-only YARA rules, you can mount an additional directory to `/app/rules` and set `REVERSECORE_READ_DIRS` environment variable

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

### Example 2: Other MCP Clients

Reversecore_MCP follows the standard MCP protocol and should work with any MCP-compatible client. Configure the client to connect to:

- **Stdio mode**: Use the Docker command as shown in Example 1 (Claude Desktop stdio configuration)
- **HTTP mode**: Point to `http://localhost:8000` (or your configured host/port) after starting the server with HTTP transport

For clients that support MCP over HTTP, ensure the Reversecore_MCP server is running in HTTP mode and accessible at the configured endpoint.

## Usage

### Project Goal

Reversecore_MCP is designed to enable AI agents to perform reverse engineering tasks through natural language commands. The server wraps common reverse engineering CLI tools and Python libraries, making them accessible to AI assistants for automated triage and analysis workflows.

### API Examples

The server exposes tools that can be called by AI agents via the MCP protocol. Below are examples of how to use each tool:

#### 1. Identify File Type (`run_file`)

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

#### 2. Extract Strings (`run_strings`)

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
...
```

#### 3. Disassemble with radare2 (`run_radare2`)

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
...
```

#### 4. Scan with YARA (`run_yara`)

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
    "tags": ["malware"],
    "meta": {"author": "analyst"},
    "strings": [
      {
        "identifier": "$s1",
        "offset": 1024,
        "matched_data": "48656c6c6f"
      }
    ]
  }
]
```

#### 5. Disassemble with Capstone (`disassemble_with_capstone`)

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
...
```

## Available Tools

### CLI Tools

- **`run_file`**: Identify file type using the `file` command
- **`run_strings`**: Extract printable strings from binary files
- **`run_radare2`**: Execute radare2 commands on binary files
- **`run_binwalk`**: Analyze and extract embedded files from firmware/images (analysis only in v1.0)

### Library Tools

- **`run_yara`**: Scan files using YARA rules
- **`disassemble_with_capstone`**: Disassemble binary code using Capstone (supports x86, ARM, ARM64)

## Error Handling

All tools return error messages as strings instead of raising exceptions. Error messages are formatted for AI consumption and include:
- Tool not found errors
- Timeout errors
- Invalid input errors
- Command execution failures

## Development

### Adding New Tools

1. Create a tool function in the appropriate module (`cli_tools.py` or `lib_tools.py`)
2. Add the tool registration in the module's `register_*_tools()` function
3. The tool will be automatically registered when the server starts

### Testing

```bash
# Run tests (when implemented)
pytest tests/
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure that:
- All subprocess calls use list-based arguments (never `shell=True`)
- All tools handle errors gracefully and return error strings
- New tools follow the existing patterns for security and error handling

