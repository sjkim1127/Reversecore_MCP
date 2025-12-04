# Architecture Overview

This document describes the internal architecture of Reversecore MCP.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AI Assistant                                 │
│                  (Claude, GPT, Cursor, etc.)                        │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              │ MCP Protocol (JSON-RPC)
                              │
┌─────────────────────────────▼───────────────────────────────────────┐
│                      Reversecore MCP Server                          │
│                         (server.py)                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │    Prompts      │  │    Resources    │  │      Tools      │     │
│  │  (prompts.py)   │  │ (resources.py)  │  │   (tools/*.py)  │     │
│  └─────────────────┘  └─────────────────┘  └────────┬────────┘     │
│                                                      │              │
│  ┌──────────────────────────────────────────────────▼──────────┐   │
│  │                      Core Layer                              │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │   │
│  │  │  Config  │ │ Security │ │  Result  │ │  Errors  │       │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │   │
│  │  │  Ghidra  │ │ R2 Pool  │ │Validators│ │ Metrics  │       │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   Radare2     │   │    Ghidra     │   │  CLI Tools    │
│               │   │               │   │ (file, strings│
│  Disassembly  │   │ Decompilation │   │  YARA, etc.)  │
│  Emulation    │   │  Type Recovery│   │               │
└───────────────┘   └───────────────┘   └───────────────┘
```

## Directory Structure

```
reversecore_mcp/
├── __init__.py           # Package initialization
├── prompts.py            # AI reasoning prompts
├── resources.py          # Dynamic resources
├── core/                 # Infrastructure layer
│   ├── __init__.py
│   ├── config.py         # Configuration management
│   ├── security.py       # Input validation & sanitization
│   ├── result.py         # ToolResult models
│   ├── exceptions.py     # Custom exceptions
│   ├── error_handling.py # Error formatting
│   ├── validators.py     # Path & input validators
│   ├── ghidra_helper.py  # Ghidra integration
│   ├── ghidra_manager.py # Ghidra process management
│   ├── r2_pool.py        # Radare2 connection pool
│   ├── metrics.py        # Performance metrics
│   └── logging_config.py # Logging setup
└── tools/                # MCP tool implementations
    ├── __init__.py       # Tool registration
    ├── cli_tools.py      # CLI wrapper tools
    ├── lib_tools.py      # Library-based tools
    ├── ghost_trace.py    # Hidden behavior detection
    ├── neural_decompiler.py  # AI-enhanced decompilation
    ├── trinity_defense.py    # Automated defense pipeline
    ├── adaptive_vaccine.py   # Defense generation
    └── report_tools.py       # Report generation
```

## Core Components

### Configuration (config.py)

Centralized configuration management:

```python
from reversecore_mcp.core.config import Config

config = Config()
workspace = config.workspace  # /app/workspace
timeout = config.default_timeout  # 300
ghidra_path = config.ghidra_install_dir  # /opt/ghidra
```

Environment variables:
- `REVERSECORE_WORKSPACE` - Workspace directory
- `GHIDRA_INSTALL_DIR` - Ghidra installation path
- `LOG_LEVEL` - Logging verbosity

### Security (security.py)

Input validation and path security:

```python
from reversecore_mcp.core.security import validate_path, sanitize_input

# Path validation (prevents traversal)
safe_path = validate_path("/app/workspace/../etc/passwd")
# Raises: SecurityError

# Input sanitization
clean = sanitize_input(user_input)
```

### Result Models (result.py)

Standardized tool response format:

```python
from reversecore_mcp.core.result import ToolSuccess, ToolError

# Success response
return ToolSuccess(
    data={"functions": [...]},
    metadata={"execution_time": 1.5}
)

# Error response
return ToolError(
    error_code="TIMEOUT",
    message="Analysis exceeded timeout",
    hint="Try increasing timeout or using fast_mode"
)
```

### Ghidra Integration

```
┌────────────────────────────────────────────────────┐
│                  GhidraManager                      │
│                                                    │
│  ┌──────────────────────────────────────────────┐ │
│  │              GhidraHelper                     │ │
│  │  ┌────────┐  ┌────────┐  ┌────────┐         │ │
│  │  │Decompile│  │ Types  │  │ Xrefs  │         │ │
│  │  └────────┘  └────────┘  └────────┘         │ │
│  └──────────────────────────────────────────────┘ │
│                        │                          │
│                        ▼                          │
│  ┌──────────────────────────────────────────────┐ │
│  │           Ghidra Headless                    │ │
│  │           (analyzeHeadless)                  │ │
│  │           JVM: 16GB heap                     │ │
│  └──────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────┘
```

### Radare2 Pool (r2_pool.py)

Connection pooling for Radare2:

```python
from reversecore_mcp.core.r2_pool import R2Pool

pool = R2Pool(max_connections=5)

# Get connection from pool
with pool.get_connection(file_path) as r2:
    result = r2.cmd("afl")
```

## Tool Architecture

### Tool Registration

Tools are registered with FastMCP:

```python
# server.py
from fastmcp import FastMCP
from reversecore_mcp.tools import register_all_tools

mcp = FastMCP("reversecore")
register_all_tools(mcp)

# tools/__init__.py
def register_all_tools(mcp):
    from .cli_tools import run_file, run_strings
    from .lib_tools import parse_binary_with_lief
    
    mcp.tool(run_file)
    mcp.tool(run_strings)
    mcp.tool(parse_binary_with_lief)
    # ...
```

### Tool Implementation Pattern

```python
from reversecore_mcp.core.result import ToolResult, ToolSuccess, ToolError
from reversecore_mcp.core.security import validate_path
from reversecore_mcp.core.config import Config

def my_tool(file_path: str, timeout: int = 300) -> ToolResult:
    """Tool description.
    
    Args:
        file_path: Path to file
        timeout: Execution timeout
        
    Returns:
        ToolResult with analysis data
    """
    config = Config()
    
    # 1. Validate input
    try:
        safe_path = validate_path(file_path, config.workspace)
    except SecurityError as e:
        return ToolError(
            error_code="VALIDATION_ERROR",
            message=str(e)
        )
    
    # 2. Execute analysis
    try:
        result = do_analysis(safe_path, timeout)
        return ToolSuccess(data=result)
    except TimeoutError:
        return ToolError(
            error_code="TIMEOUT",
            message="Analysis timed out"
        )
    except Exception as e:
        return ToolError(
            error_code="ANALYSIS_ERROR",
            message=str(e)
        )
```

## Data Flow

### Request Processing

```
1. AI sends tool request via MCP
   ↓
2. FastMCP routes to tool function
   ↓
3. Input validation (security.py)
   ↓
4. Tool execution (tools/*.py)
   ↓
5. Result formatting (result.py)
   ↓
6. Response to AI via MCP
```

### Trinity Defense Pipeline

```
                    ┌─────────────────┐
                    │  trinity_defense │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   PHASE 1     │   │   PHASE 2     │   │   PHASE 3     │
│   DISCOVER    │   │  UNDERSTAND   │   │  NEUTRALIZE   │
│               │   │               │   │               │
│  ghost_trace  │ → │neural_decompile│ → │adaptive_vaccine│
└───────────────┘   └───────────────┘   └───────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
 Hidden behaviors     AI analysis         YARA rules
 Logic bombs          Intent mapping      Binary patches
 Backdoors            Code explanation    IOC extraction
```

## Performance Optimizations

### Dynamic Timeout

Timeout scales with file size:

```python
def calculate_timeout(file_size: int, base: int = 300) -> int:
    """Calculate timeout based on file size."""
    mb = file_size / (1024 * 1024)
    additional = min(mb * 2, 600)  # 2s per MB, max 600s
    return base + int(additional)
```

### Ghidra JVM Configuration

```
JAVA_OPTS:
  -Xmx16g          # 16GB max heap
  -XX:+UseG1GC     # G1 garbage collector
  -XX:MaxGCPauseMillis=200
```

### Caching

Binary analysis results are cached:

```python
from reversecore_mcp.core.binary_cache import BinaryCache

cache = BinaryCache()

# Check cache
if cached := cache.get(file_hash, "functions"):
    return cached

# Compute and cache
result = analyze_functions(file_path)
cache.set(file_hash, "functions", result, ttl=3600)
```

## Error Handling

### Error Categories

| Code | Category | Example |
|------|----------|---------|
| `VALIDATION_ERROR` | Input validation | Invalid path |
| `FILE_NOT_FOUND` | File system | Missing file |
| `TIMEOUT` | Execution | Analysis took too long |
| `TOOL_NOT_FOUND` | Dependencies | Radare2 not installed |
| `PARSE_ERROR` | Output parsing | Malformed JSON |
| `SECURITY_ERROR` | Security | Path traversal attempt |

### Error Response Format

```json
{
  "status": "error",
  "error_code": "TIMEOUT",
  "message": "Analysis exceeded timeout of 300 seconds",
  "hint": "Try using fast_mode=True or increasing timeout",
  "details": {
    "elapsed": 300.5,
    "file_size": "50MB"
  }
}
```

## Extending the Architecture

### Adding New Tools

1. Create tool function in `tools/`
2. Register in `tools/__init__.py`
3. Add tests in `tests/`
4. Document in `docs/api/tools/`

### Adding New Backends

1. Create helper in `core/`
2. Add configuration options
3. Integrate with existing tools
4. Update Docker images if needed
