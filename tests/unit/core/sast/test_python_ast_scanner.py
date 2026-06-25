"""Unit tests for Python AST Scanner."""

import pytest

from reversecore_mcp.core.sast.python_ast_scanner import PythonASTScanner
from reversecore_mcp.core.sast.rule_manager import SASTRule


@pytest.fixture
def test_rules():
    """Sample rules for testing."""
    return [
        SASTRule(
            id="PY-001",
            language="python",
            severity="critical",
            pattern="eval",
            match_type="ast",
            category="Code Execution",
            message="eval call",
        ),
        SASTRule(
            id="PY-002",
            language="python",
            severity="critical",
            pattern="exec",
            match_type="ast",
            category="Code Execution",
            message="exec call",
        ),
        SASTRule(
            id="PY-003",
            language="python",
            severity="high",
            pattern="subprocess.Popen",
            match_type="ast",
            category="Command Injection",
            message="subprocess call",
        ),
        SASTRule(
            id="PY-004",
            language="python",
            severity="high",
            pattern="yaml.load",
            match_type="ast",
            category="Deserialization",
            message="yaml.load call",
        ),
        SASTRule(
            id="C-001",
            language="c",
            severity="critical",
            pattern="strcpy",
            match_type="regex",
            category="Memory Safety",
            message="strcpy call",
        ),
    ]


def test_eval_exec_scanning(test_rules):
    """Test that eval and exec function calls are flagged."""
    code = """
def test_func():
    eval("print('hello')")
    exec("import os")
    print("eval") # String argument, not a call
"""
    scanner = PythonASTScanner()
    findings = scanner.scan(code, test_rules)

    assert len(findings) == 2
    rule_ids = [f["rule_id"] for f in findings]
    assert "PY-001" in rule_ids
    assert "PY-002" in rule_ids
    assert findings[0]["line"] == 3
    assert findings[1]["line"] == 4


def test_subprocess_shell_checking(test_rules):
    """Test that subprocess calls are only flagged when shell=True."""
    code = """
import subprocess
subprocess.Popen(["ls"], shell=True) # Flagged
subprocess.Popen(["ls"], shell=False) # Not flagged
subprocess.Popen(["ls"]) # Not flagged
"""
    scanner = PythonASTScanner()
    findings = scanner.scan(code, test_rules)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PY-003"
    assert findings[0]["line"] == 3


def test_yaml_loader_checking(test_rules):
    """Test that yaml.load is flagged except when using SafeLoader."""
    code = """
import yaml
yaml.load(stream) # Flagged
yaml.load(stream, Loader=yaml.Loader) # Flagged
yaml.load(stream, Loader=yaml.SafeLoader) # Not flagged
"""
    scanner = PythonASTScanner()
    findings = scanner.scan(code, test_rules)

    assert len(findings) == 2
    assert findings[0]["line"] == 3
    assert findings[1]["line"] == 4


def test_syntax_error_graceful_handling(test_rules):
    """Test that syntax errors in Python code return empty findings instead of crashing."""
    code = """
def broken_syntax(
    eval("test")
"""
    scanner = PythonASTScanner()
    findings = scanner.scan(code, test_rules)

    # AST parsing fails, returns empty findings, letting fallback regex scanner handle it
    assert findings == []


def test_python_ast_unresolved_name(test_rules):
    """Test when call target name is not resolvable (e.g. lambda or immediate call)."""
    code = "(lambda: eval)('test')"
    scanner = PythonASTScanner()
    findings = scanner.scan(code, test_rules)
    assert findings == []


def test_python_ast_nested_attribute_calls(test_rules):
    """Test attribute calls that are not Name or Attribute (nested calls/indexing)."""
    code = "obj[index].call()"
    scanner = PythonASTScanner()
    findings = scanner.scan(code, test_rules)
    assert findings == []
