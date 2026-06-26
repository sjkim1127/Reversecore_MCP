# Testing Guide

This guide details testing procedures, folder structures, and best practices for developing on the Reversecore MCP platform.

---

## 📁 Directory Structure

Tests are organized to separate pure unit tests (isolated using mocks) from integration tests (which call external binary utilities on mock data):

```
tests/
├── __init__.py
├── conftest.py              # Shared pytest fixtures (workspace, config, logs)
├── fixtures/                # Static test data (malware rules, tiny binaries)
│
├── unit/                    # Unit tests (Mocked subprocesses and system calls)
│   ├── core/                # Core infrastructure tests
│   │   ├── test_config.py
│   │   ├── test_security.py
│   │   ├── test_validators.py
│   │   ├── test_r2_pool.py
│   │   └── ...
│   └── tools/               # Modular tool tests
│       ├── test_static_analysis.py
│       ├── test_yara_tools.py
│       ├── test_memory.py
│       └── ...
│
└── integration/             # Integration tests (verifies local tool installations)
    ├── test_tool_installation.py
    └── ...
```

---

## 🚀 Running Tests

### Running the Entire Suite

```bash
pytest tests/ -v
```

### Running Specific Test Paths

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v

# Run tests in a specific file
pytest tests/unit/core/test_security.py -v
```

### Enforcing Code Coverage Gates

Our CI/CD pipeline enforces an **80% minimum code coverage gate**. To run tests locally and generate a coverage report:

```bash
# Fail if code coverage falls below 80%
pytest tests/unit/ --cov=reversecore_mcp --cov-fail-under=80

# Generate HTML report
pytest tests/unit/ --cov=reversecore_mcp --cov-report=html
open htmlcov/index.html  # View coverage lines in browser
```

---

## 📝 Writing Tests

### 1. Simple Unit Test

Test validators or helper functions without external dependencies:

```python
# tests/unit/core/test_validators.py
from reversecore_mcp.core.validators import validate_file_path
import pytest

def test_validate_file_path_safe():
    assert validate_file_path("sample.exe") == True

def test_validate_file_path_traversal():
    assert validate_file_path("../../../etc/passwd") == False
```

### 2. Mocking Subprocesses (CLI Wrapper Testing)

For tools that invoke command-line utilities (like `file` or `strings`), mock the async command executor to keep tests fast and platform-independent:

```python
# tests/unit/tools/test_static_analysis.py
import pytest
from unittest.mock import patch, AsyncMock
from reversecore_mcp.tools.analysis.static_analysis import run_file

@pytest.mark.asyncio
@patch("reversecore_mcp.core.execution.execute_subprocess_async")
async def test_run_file_success(mock_execute):
    # Setup mock subprocess output
    mock_execute.return_value = ("PE32+ executable (GUI) x86-64", "")

    result = await run_file("sample.exe")

    assert result.status == "success"
    assert "PE32+" in result.data["file_type"]
    mock_execute.assert_called_once()
```

### 3. Parametrized Inputs

Test multiple edge cases efficiently:

```python
import pytest
from reversecore_mcp.core.validators import validate_file_path

@pytest.mark.parametrize("input_path,expected", [
    ("malware.elf", True),
    ("tmp/sub/file.bin", True),
    ("../../etc/shadow", False),
    ("sample.exe\x00", False),
])
def test_path_inputs(input_path, expected):
    assert validate_file_path(input_path) == expected
```

---

## 🏷️ Test Categories (Markers)

We use pytest markers to segment tests:
- `@pytest.mark.unit`: Pure logic unit tests.
- `@pytest.mark.integration`: Requires external executables (`radare2`, `yara`, `file`) installed on the host.
- `@pytest.mark.slow`: Long-running symbolic or emulation tests.

Run only fast unit tests:
```bash
pytest tests/ -v -m "not slow and not integration"
```
