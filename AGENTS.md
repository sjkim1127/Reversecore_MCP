# Agent Customizations for Reversecore_MCP

This guide helps AI agents understand the codebase structure and be immediately productive.

## Project Overview

**Reversecore_MCP** is an enterprise-grade MCP (Model Context Protocol) server for AI-powered reverse engineering. It enables AI agents to perform comprehensive binary analysis through natural language commands using Radare2, r2ghidra, and other industry-standard tools.

- **Language**: Python 3.10+
- **Framework**: [FastMCP](https://github.com/jlowin/fastmcp) 2.13.1+
- **Architecture**: Layered (Prompts → Tools → Core Infrastructure → External Tools)
- **Test Coverage**: 55%+ with 700+ tests
- **Key External Dependencies**: Radare2 (disassembly/emulation), YARA (detection)

## Quick Commands

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks (enforces code standards)
pre-commit install
```

### Building & Running

```bash
# Start MCP server (development mode)
python server.py

# Docker (auto-detects architecture: Intel/ARM)
docker compose --profile x86 up -d    # Intel/AMD
docker compose --profile arm64 up -d  # Apple Silicon
./scripts/run-docker.sh                # Auto-detect

# Install external tools
./scripts/install-ghidra.sh            # Linux/macOS
.\scripts\install-ghidra.ps1           # Windows
```

### Testing

```bash
# All tests (generates coverage report)
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# Specific test with coverage
pytest tests/unit/test_cli_tools.py::TestRunFile::test_success -v

# Check coverage threshold (must exceed 54%)
pytest --cov-report=term-missing
```

### Code Quality

```bash
# Lint with Ruff
ruff check reversecore_mcp/

# Format with Black
black reversecore_mcp/

# Sort imports with isort
isort reversecore_mcp/

# Auto-fix all issues
ruff check --fix reversecore_mcp/
black reversecore_mcp/
```

## Architecture

### High-Level Design

```
AI Agent → MCP Protocol → Reversecore Server (FastMCP)
                              ↓
                    [Prompts] [Resources] [Tools]
                              ↓
                    Core Infrastructure Layer
                (Config, Security, Radare2, Metrics)
                              ↓
                     Radare2  │  CLI Tools
             (disasm/r2ghidra)│ (YARA, file, etc.)
```

### Key Directories

- **`reversecore_mcp/core/`**: Infrastructure (config, exceptions, security, validation, tool management)
- **`reversecore_mcp/tools/`**: Tool implementations organized by category
  - `analysis/`: Binary analysis (signatures, LIEF, diff, static analysis)
  - `radare2/`: Disassembly, emulation, r2ghidra decompiler, SQLite annotation DB
  - `malware/`: Threat detection (vaccine generation, dormant detector, vulnerability hunter)
  - `report/`: Report generation
  - `common/`: File operations, patch explanation
- **`reversecore_mcp/prompts.py`**: AI reasoning prompts for different analysis tasks
- **`reversecore_mcp/resources.py`**: Dynamic resources exposed to AI agents
- **`server.py`**: FastMCP server entry point

See [Architecture Documentation](docs/development/architecture.md) for details.

## Code Patterns & Conventions

### Tool Implementation Pattern

All MCP tools follow this structure:

```python
@server.tool()
async def my_analysis_tool(file_path: str, options: str | None = None) -> ToolResult:
    """Brief description of what this tool does.

    Args:
        file_path: Path to the binary file.
        options: Optional analysis options.

    Returns:
        ToolResult with status='success'/'error' and appropriate content/error fields.
    """
    try:
        # Validate inputs
        validated_path = validate_file_path(file_path)

        # Perform analysis
        result = await perform_analysis(validated_path)

        # Return success
        return ToolResult(
            status="success",
            content=[{"type": "text", "text": json.dumps(result, indent=2)}]
        )
    except ValidationError as e:
        return ToolResult(status="error", error=str(e))
    except ExecutionTimeoutError as e:
        logger.error(f"Timeout: {e}")
        return ToolResult(status="error", error=str(e))
```

### Exception Handling

All custom exceptions inherit from `ReversecoreError`:

```python
from reversecore_mcp.core.exceptions import ReversecoreError, ValidationError, ExecutionTimeoutError

# Exceptions have error codes (RCMCP-E*) and error types for categorization
class ValidationError(ReversecoreError):
    error_code = "RCMCP-E001"
    error_type = "VALIDATION_ERROR"
```

### Input Validation

Always validate file paths and inputs:

```python
from reversecore_mcp.core.validators import validate_file_path, validate_binary_path

# Validates path exists, is readable, and within workspace
safe_path = validate_file_path(user_input)

# Validates it's actually a binary file
binary_path = validate_binary_path(user_input)
```

### Result Models

Use TypedDict for structured results (in `reversecore_mcp/core/result.py`):

```python
class DisassemblyResult(TypedDict):
    address: str
    mnemonic: str
    operands: str
    bytes: NotRequired[str]
    comment: NotRequired[str]
```

### Docstring Style

Always use Google-style docstrings with Args, Returns, Raises, and Examples:

```python
def analyze_binary(file_path: str, timeout: int = 300) -> ToolResult:
    """Analyze a binary file for threats.

    Args:
        file_path: Path to the binary file to analyze.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult containing analysis data or error.

    Raises:
        ValidationError: If file_path is invalid.
        ExecutionTimeoutError: If analysis exceeds timeout.

    Example:
        >>> result = analyze_binary("/app/workspace/sample.exe")
        >>> print(result.status)
        'success'
    """
```

### Type Hints

Always use comprehensive type hints:

```python
from typing import Optional, List, Dict, Any

async def process_data(
    data: Dict[str, Any],
    filters: Optional[List[str]] = None
) -> Dict[str, Any]:
    ...
```

## Common Task Patterns

### Adding a New Tool

1. Create a new file in the appropriate `reversecore_mcp/tools/` subdirectory
2. Implement the tool function with `@server.tool()` decorator
3. Register it in `reversecore_mcp/tools/__init__.py`
4. Add unit tests in `tests/unit/test_*.py`
5. Update docs if it's a significant new feature

### Working with r2ghidra

- Decompilation is powered by the `r2ghidra` plugin (which embeds the Ghidra decompiler engine directly inside radare2).
- Use `r2_decompile` or `r2_recover_structures` tools located in `reversecore_mcp/tools/radare2/r2ghidra_tools.py`.
- No separate JDK or Ghidra installation is required.

### Working with Radare2

- Use `reversecore_mcp.core.r2_pool.R2Pool` for connection pooling
- All r2 commands return structured data via `r2_helpers` module
- Pool automatically manages lifecycle (no manual cleanup needed)
- Check [R2 Helpers](reversecore_mcp/core/r2_helpers.py) for common operations

### Configuration & Environment

- Configuration is centralized in `reversecore_mcp/core/config.py`
- Use `get_config()` to access settings
- Environment variables override defaults (see `.env.example`)
- Key paths: `workspace`, `binary_cache`, `tool_timeout`, `log_level`

### Logging

```python
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)
logger.info("Message")
logger.error(f"Error: {e}")  # Auto-includes stack trace
```

## Testing Guidelines

- Use `pytest` with fixtures in `tests/conftest.py`
- Mark tests with `@pytest.mark.unit` or `@pytest.mark.integration`
- Slow tests should be marked `@pytest.mark.slow`
- Test data goes in `tests/fixtures/` (binary samples, YARA rules, etc.)
- Minimum coverage threshold is 54% (enforced in `pytest.ini`)

See [Testing Guide](docs/development/testing.md) for detailed test patterns.

## Common Pitfalls

1. **Timeout Handling**: External tools (r2, YARA) can hang. Always use the configured timeout and wrap in try/except.

2. **Path Validation**: Never trust user input paths. Always validate with `validate_file_path()` or `validate_binary_path()`.

3. **Resource Cleanup**: Radare2 connections are pooled. Don't manually manage lifecycle—use provided managers.

4. **Async/Await**: Server is fully async. Use `async def` for I/O-bound operations and `await` for external calls.

5. **Error Codes**: Always set error_code and error_type on exceptions. This helps AI agents understand failure categories.

6. **JSON Serialization**: Use `orjson` (faster) not `json` for serializing results to JSON.

7. **CI/CD Bypassing**: Never modify the CI/CD workflow (`main.yml`, `pytest.ini`, etc.) to bypass test failures, lint errors, security warnings, or coverage limits. You must always address and fix the root cause directly in the source code or configurations.

## Important Files to Know

| File | Purpose |
|------|---------|
| [server.py](server.py) | FastMCP server initialization & lifecycle |
| [reversecore_mcp/core/config.py](reversecore_mcp/core/config.py) | Configuration management |
| [reversecore_mcp/core/exceptions.py](reversecore_mcp/core/exceptions.py) | Exception hierarchy |
| [reversecore_mcp/core/security.py](reversecore_mcp/core/security.py) | Input sanitization |
| [reversecore_mcp/core/validators.py](reversecore_mcp/core/validators.py) | Path & input validation |
| [reversecore_mcp/tools/__init__.py](reversecore_mcp/tools/__init__.py) | Tool registration |
| [reversecore_mcp/prompts.py](reversecore_mcp/prompts.py) | AI reasoning prompts |
| [tests/conftest.py](tests/conftest.py) | Pytest fixtures & shared test setup |
| [pytest.ini](pytest.ini) | Test configuration |
| [.pre-commit-config.yaml](.pre-commit-config.yaml) | Code quality hooks |

## Documentation Structure

- [Installation Guide](docs/getting-started/installation.md): Setup for development & deployment
- [Contributing Guide](docs/development/contributing.md): Code standards and workflow
- [Architecture Guide](docs/development/architecture.md): System design & component details
- [Testing Guide](docs/development/testing.md): Test patterns and practices
- [API Documentation](docs/api/): Tool and module reference
- [User Guide](docs/user-guide/): End-user analysis workflows

## External Resources

- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [MCP Protocol Spec](https://modelcontextprotocol.io/)
- [Radare2 Documentation](https://radare.org/n/)
- [YARA Documentation](https://virustotal.github.io/yara/)
