# Contributing Guide

Thank you for contributing to Reversecore MCP! This guide outlines setup instructions, coding conventions, testing requirements, and pull request procedures.

---

## 💻 Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/Reversecore_MCP.git
cd Reversecore_MCP
```

### 2. Set Up a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### 3. Install Package and Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 4. Enable Pre-commit Hooks

We use pre-commit hooks to automatically check for secret leaks (Gitleaks), format code (Ruff), and run security scans (Bandit) before each commit:

```bash
pre-commit install
```

---

## 📏 Coding Standards

### Python Code Style

We enforce standard PEP 8 compliance via **Ruff** for both linting and formatting.

Run checks locally:
```bash
# Run linter
ruff check reversecore_mcp/

# Run formatter check
ruff format --check reversecore_mcp/
```

Auto-fix issues:
```bash
ruff check --fix reversecore_mcp/
ruff format reversecore_mcp/
```

### Docstring Conventions

We use **Google-style docstrings**. Every public function, class, and tool must have a clear docstring documenting arguments, types, return structures, and exceptions:

```python
def analyze_binary(file_path: str, timeout: int = 300) -> ToolResult:
    """Analyze a binary file for capabilities.

    Args:
        file_path: Path to the binary file to analyze.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult containing analysis data or error.

    Raises:
        ValidationError: If file_path is invalid.
        ExecutionTimeoutError: If analysis exceeds timeout.

    Example:
        >>> result = analyze_binary("sample.exe")
        >>> print(result.status)
        'success'
    """
```

---

## 🧪 Testing Guidelines

Write unit tests for any new features or bug fixes. Unit tests should go under `tests/unit/` and mock all external commands.

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run unit tests only
pytest tests/unit/ -v

# Run with coverage report
pytest tests/unit/ --cov=reversecore_mcp --cov-report=html
```

### Coverage Threshold

We enforce a strict **80% minimum coverage gate** in our CI/CD pipelines. Ensure your tests keep code coverage above this threshold:

```bash
# Fail if code coverage falls below 80%
pytest tests/unit/ --cov=reversecore_mcp --cov-fail-under=80
```

---

## 🔌 Adding New Tools

To add a new tool to the MCP server:

### 1. Implement Tool Function
Add your tool function to the correct package under `reversecore_mcp/tools/`. Ensure you use validation and error handlers:

```python
# reversecore_mcp/tools/analysis/my_tool.py
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path

@log_execution()
async def my_new_tool(file_path: str) -> ToolResult:
    """Describe the tool behavior clearly for the AI.

    Args:
        file_path: Relative path to target file in workspace.

    Returns:
        ToolResult with analysis dict.
    """
    try:
        # Validate path isolation boundary
        safe_path = validate_file_path(file_path)

        # Implement your tool logic
        data = await perform_custom_task(safe_path)
        return success(data)
    except Exception as e:
        return failure(str(e))
```

### 2. Register in Plugin
Add the tool registration inside the corresponding `Plugin` class (e.g. `AnalysisToolsPlugin` under `reversecore_mcp/tools/analysis/__init__.py`):

```python
# reversecore_mcp/tools/analysis/__init__.py
class AnalysisToolsPlugin(Plugin):
    def register(self, mcp_server: Any) -> None:
        # Import your tool
        from reversecore_mcp.tools.analysis.my_tool import my_new_tool

        # Register it with FastMCP
        mcp_server.tool(my_new_tool)
```

---

## 🚀 Pull Request Checklist

Before submitting a Pull Request, ensure:
1. `pytest tests/unit/ --cov-fail-under=80` passes.
2. `ruff check reversecore_mcp/` has zero errors.
3. `mypy reversecore_mcp/` has zero typing errors.
4. `bandit -r reversecore_mcp/` reports no security warnings.
5. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat: add my tool`, `fix: handle null bytes`).
