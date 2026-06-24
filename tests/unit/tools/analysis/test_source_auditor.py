"""Unit tests for the Source Code Auditor tool."""

from unittest.mock import patch

import pytest

from reversecore_mcp.tools.analysis.source_auditor import audit_source_code


@pytest.mark.asyncio
async def test_audit_source_code_c(tmp_path):
    """Test auditing a C file using regex-based scanning."""
    c_code = """
#include <stdio.h>
#include <string.h>

int main() {
    char dest[10];
    strcpy(dest, "unbounded input");
    return 0;
}
"""
    test_file = tmp_path / "test.c"
    test_file.write_text(c_code, encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path", return_value=test_file
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "success"
    # Verify the findings contain the strcpy warning
    findings = result.metadata.get("static_findings", {})
    assert "Buffer Overflow" in findings
    assert any("strcpy" in f for f in findings["Buffer Overflow"])


@pytest.mark.asyncio
async def test_audit_source_code_python(tmp_path):
    """Test auditing a Python file using AST-based scanning."""
    python_code = """
import os
import subprocess

def run_command(cmd):
    eval(cmd)
    subprocess.Popen(cmd, shell=True)
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(python_code, encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path", return_value=test_file
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "success"
    findings = result.metadata.get("static_findings", {})
    assert "Code Execution" in findings
    assert "Command Injection" in findings


@pytest.mark.asyncio
async def test_audit_source_code_python_syntax_error_fallback(tmp_path):
    """Test Python AST scan failure falls back to regex scanning."""
    broken_python_code = """
def run_command(cmd)
    eval(cmd)
"""
    test_file = tmp_path / "test.py"
    test_file.write_text(broken_python_code, encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path", return_value=test_file
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "success"
    findings = result.metadata.get("static_findings", {})
    # Should still find eval via regex fallback
    assert "Code Execution" in findings
    assert any("eval" in f for f in findings["Code Execution"])


@pytest.mark.asyncio
async def test_audit_source_code_file_too_large(tmp_path):
    """Test that files exceeding the size limit fail with FILE_TOO_LARGE."""
    test_file = tmp_path / "large_file.c"
    test_file.write_bytes(b"A" * 6_000_000)  # 6MB, exceeds 5MB limit

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path", return_value=test_file
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "error"
    assert result.error_code == "FILE_TOO_LARGE"
