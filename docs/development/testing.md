# Testing Guide

This guide covers testing practices and procedures for Reversecore MCP.

## Test Structure

```
tests/
├── __init__.py
├── conftest.py          # Shared fixtures
├── fixtures/            # Test data
│   ├── samples/         # Binary samples
│   ├── rules/           # YARA rules
│   └── workspace/       # Test workspace
├── unit/                # Unit tests
│   ├── test_cli_tools.py
│   ├── test_lib_tools.py
│   ├── test_ghost_trace.py
│   └── ...
└── integration/         # Integration tests
    ├── test_cli_tools.py
    └── ...
```

## Running Tests

### All Tests

```bash
pytest tests/ -v
```

### Unit Tests Only

```bash
pytest tests/unit/ -v
```

### Integration Tests

```bash
pytest tests/integration/ -v
```

### Specific Test File

```bash
pytest tests/unit/test_cli_tools.py -v
```

### Specific Test Function

```bash
pytest tests/unit/test_cli_tools.py::TestRunFile::test_success -v
```

### With Coverage

```bash
# Generate coverage report
pytest tests/ --cov=reversecore_mcp --cov-report=html

# Open report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

### Fail Under Coverage Threshold

```bash
pytest tests/ --cov=reversecore_mcp --cov-fail-under=72
```

## Writing Tests

### Basic Test Structure

```python
import pytest
from reversecore_mcp.tools.cli_tools import run_file

class TestRunFile:
    """Tests for run_file tool."""
    
    def test_success(self, sample_exe):
        """Test successful file identification."""
        result = run_file(file_path=sample_exe)
        assert result["status"] == "success"
        assert "PE32" in result["data"]
    
    def test_file_not_found(self):
        """Test error handling for missing file."""
        result = run_file(file_path="/nonexistent/file.exe")
        assert result["status"] == "error"
        assert result["error_code"] == "FILE_NOT_FOUND"
    
    def test_invalid_path(self):
        """Test validation of file path."""
        result = run_file(file_path="../../../etc/passwd")
        assert result["status"] == "error"
        assert result["error_code"] == "VALIDATION_ERROR"
```

### Using Fixtures

#### Shared Fixtures (conftest.py)

```python
# tests/conftest.py

import pytest
import tempfile
import os

@pytest.fixture
def workspace():
    """Create temporary workspace directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

@pytest.fixture
def sample_exe(workspace):
    """Create a minimal PE file for testing."""
    pe_path = os.path.join(workspace, "sample.exe")
    # Minimal PE header
    pe_data = bytes([
        0x4D, 0x5A,  # MZ signature
        # ... PE header bytes ...
    ])
    with open(pe_path, "wb") as f:
        f.write(pe_data)
    return pe_path

@pytest.fixture
def sample_elf(workspace):
    """Create a minimal ELF file for testing."""
    elf_path = os.path.join(workspace, "sample.elf")
    elf_data = bytes([
        0x7F, 0x45, 0x4C, 0x46,  # ELF signature
        # ... ELF header bytes ...
    ])
    with open(elf_path, "wb") as f:
        f.write(elf_data)
    return elf_path
```

#### Using Fixtures

```python
def test_analyze_pe(sample_exe):
    """Test PE file analysis."""
    result = analyze(sample_exe)
    assert result["format"] == "PE"

def test_analyze_elf(sample_elf):
    """Test ELF file analysis."""
    result = analyze(sample_elf)
    assert result["format"] == "ELF"
```

### Mocking External Dependencies

```python
from unittest.mock import patch, MagicMock

class TestGhidraDecompile:
    @patch('reversecore_mcp.core.ghidra_helper.GhidraHelper')
    def test_decompile_success(self, mock_ghidra):
        """Test decompilation with mocked Ghidra."""
        # Setup mock
        mock_instance = MagicMock()
        mock_instance.decompile.return_value = "int main() { return 0; }"
        mock_ghidra.return_value = mock_instance
        
        # Test
        result = decompile("/app/workspace/test.exe", "main")
        
        assert result["status"] == "success"
        assert "int main()" in result["code"]
    
    @patch('subprocess.run')
    def test_radare2_command(self, mock_run):
        """Test Radare2 command execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="function list here"
        )
        
        result = run_radare2("/app/workspace/test.exe", "afl")
        
        assert result["status"] == "success"
        mock_run.assert_called_once()
```

### Parametrized Tests

```python
import pytest

@pytest.mark.parametrize("file_type,expected", [
    ("sample.exe", "PE32"),
    ("sample.elf", "ELF"),
    ("sample.dll", "PE32"),
    ("sample.so", "ELF"),
])
def test_file_identification(workspace, file_type, expected):
    """Test file type identification for various formats."""
    file_path = create_sample(workspace, file_type)
    result = run_file(file_path)
    assert expected in result["data"]

@pytest.mark.parametrize("timeout,should_timeout", [
    (1, True),    # Very short timeout
    (300, False), # Normal timeout
])
def test_timeout_handling(sample_exe, timeout, should_timeout):
    """Test timeout behavior."""
    result = analyze(sample_exe, timeout=timeout)
    if should_timeout:
        assert result["error_code"] == "TIMEOUT"
    else:
        assert result["status"] == "success"
```

### Testing Async Code

```python
import pytest
import asyncio

@pytest.mark.asyncio
async def test_async_analysis():
    """Test asynchronous analysis function."""
    result = await async_analyze("/app/workspace/sample.exe")
    assert result["status"] == "success"
```

## Test Categories

### Unit Tests

Test individual functions in isolation:

```python
# tests/unit/test_validators.py

from reversecore_mcp.core.validators import validate_file_path

class TestValidateFilePath:
    def test_valid_path(self):
        assert validate_file_path("/app/workspace/sample.exe") == True
    
    def test_path_traversal(self):
        assert validate_file_path("../../../etc/passwd") == False
    
    def test_null_bytes(self):
        assert validate_file_path("/app/workspace/sample\x00.exe") == False
```

### Integration Tests

Test tool integration with real dependencies:

```python
# tests/integration/test_cli_tools.py

import pytest

@pytest.mark.integration
class TestRadare2Integration:
    def test_real_radare2(self, sample_exe):
        """Test with actual Radare2 installation."""
        result = run_radare2(sample_exe, "afl")
        assert result["status"] == "success"
```

### Slow Tests

Mark slow tests for optional execution:

```python
@pytest.mark.slow
def test_large_binary_analysis():
    """Test analysis of large binary (may take minutes)."""
    result = analyze("/app/workspace/large_game.exe")
    assert result["status"] == "success"
```

Run without slow tests:
```bash
pytest tests/ -v -m "not slow"
```

## CI/CD Integration

### GitHub Actions

Tests run automatically on:
- Push to main branch
- Pull requests
- Manual trigger

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: pytest tests/ -v --cov=reversecore_mcp
```

## Best Practices

1. **Test one thing per test**: Each test should verify a single behavior
2. **Use descriptive names**: `test_run_file_returns_error_for_missing_file`
3. **Arrange-Act-Assert**: Structure tests clearly
4. **Don't test implementation**: Test behavior, not internal details
5. **Keep tests fast**: Mock slow external dependencies
6. **Clean up resources**: Use fixtures with cleanup
7. **Test edge cases**: Empty inputs, large files, invalid data

## Debugging Tests

### Verbose Output

```bash
pytest tests/ -v -s  # -s shows print statements
```

### Drop into Debugger

```bash
pytest tests/ --pdb  # Drop into pdb on failure
```

### Run Last Failed

```bash
pytest tests/ --lf  # Run only last failed tests
```
