# Contributing Guide

Thank you for your interest in contributing to Reversecore MCP! This guide will help you get started.

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/Reversecore_MCP.git
cd Reversecore_MCP
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 4. Install Pre-commit Hooks

```bash
pre-commit install
```

## Code Standards

### Python Style

We follow PEP 8 with these tools:

- **Ruff**: Linting and formatting
- **Black**: Code formatting
- **isort**: Import sorting

Run checks:
```bash
ruff check reversecore_mcp/
black --check reversecore_mcp/
```

Auto-fix:
```bash
ruff check --fix reversecore_mcp/
black reversecore_mcp/
```

### Docstrings

Use Google-style docstrings:

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
        TimeoutError: If analysis exceeds timeout.
        
    Example:
        >>> result = analyze_binary("/app/workspace/sample.exe")
        >>> print(result.status)
        'success'
    """
```

### Type Hints

Always use type hints:

```python
from typing import Optional, List, Dict, Any

def process_data(
    data: Dict[str, Any],
    filters: Optional[List[str]] = None
) -> Dict[str, Any]:
    ...
```

## Testing

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific module
pytest tests/unit/test_cli_tools.py -v

# With coverage
pytest tests/ --cov=reversecore_mcp --cov-report=html
```

### Writing Tests

Place tests in appropriate directories:

```
tests/
├── unit/           # Unit tests (mocked dependencies)
├── integration/    # Integration tests (real tools)
└── fixtures/       # Test data and samples
```

Example test:

```python
import pytest
from reversecore_mcp.tools.cli_tools import run_file

class TestRunFile:
    def test_run_file_success(self, sample_exe):
        """Test successful file identification."""
        result = run_file(file_path=sample_exe)
        assert result["status"] == "success"
        assert "PE32" in result["data"]
    
    def test_run_file_not_found(self):
        """Test error handling for missing file."""
        result = run_file(file_path="/nonexistent/file.exe")
        assert result["status"] == "error"
        assert result["error_code"] == "FILE_NOT_FOUND"
```

### Test Coverage

Minimum coverage: **72%**

```bash
pytest tests/ --cov=reversecore_mcp --cov-fail-under=72
```

## Pull Request Process

### 1. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Write code following style guidelines
- Add tests for new functionality
- Update documentation if needed

### 3. Run Checks

```bash
# Linting
ruff check reversecore_mcp/

# Formatting
black --check reversecore_mcp/

# Tests
pytest tests/ -v --cov=reversecore_mcp
```

### 4. Commit

Use conventional commits:

```bash
git commit -m "feat: add new analysis tool"
git commit -m "fix: resolve timeout issue in ghost_trace"
git commit -m "docs: update API reference"
git commit -m "test: add unit tests for report_tools"
```

Prefixes:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Code refactoring
- `perf:` - Performance improvement
- `ci:` - CI/CD changes

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow convention
- [ ] No merge conflicts

## Adding New Tools

### 1. Create Tool Function

```python
# reversecore_mcp/tools/my_tools.py

from reversecore_mcp.core.result import ToolResult, ToolSuccess, ToolError
from reversecore_mcp.core.validators import validate_file_path

def my_new_tool(file_path: str, option: str = "default") -> ToolResult:
    """Short description of the tool.
    
    Args:
        file_path: Path to the file to process.
        option: Processing option.
        
    Returns:
        ToolResult with processed data.
    """
    # Validate input
    if not validate_file_path(file_path):
        return ToolError(
            error_code="VALIDATION_ERROR",
            message="Invalid file path"
        )
    
    try:
        # Tool logic here
        result = process_file(file_path, option)
        return ToolSuccess(data=result)
    except Exception as e:
        return ToolError(
            error_code="PROCESSING_ERROR",
            message=str(e)
        )
```

### 2. Register with MCP

```python
# reversecore_mcp/tools/__init__.py

from .my_tools import my_new_tool

def register_tools(mcp):
    # ... existing tools ...
    mcp.tool(my_new_tool)
```

### 3. Add Tests

```python
# tests/unit/test_my_tools.py

import pytest
from reversecore_mcp.tools.my_tools import my_new_tool

class TestMyNewTool:
    def test_success(self, sample_file):
        result = my_new_tool(file_path=sample_file)
        assert result["status"] == "success"
    
    def test_invalid_path(self):
        result = my_new_tool(file_path="/invalid/path")
        assert result["status"] == "error"
```

### 4. Document

Add documentation in `docs/api/tools/`.

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Check existing issues before creating new ones

Thank you for contributing! 🎉
