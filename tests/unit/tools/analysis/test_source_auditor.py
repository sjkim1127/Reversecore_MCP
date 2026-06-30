"""Unit tests for the Source Code Auditor tool."""

from unittest.mock import MagicMock, patch

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
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "success"
    # Verify the findings contain the strcpy warning
    findings = result.metadata.get("static_findings", {})
    assert "Buffer Overflow" in findings
    assert any("strcpy" in f for f in findings["Buffer Overflow"])


@pytest.mark.asyncio
async def test_audit_source_code_c_detects_missing_lower_bound_check(tmp_path):
    """Detect libcue-style upper-only validation before indexed memory access."""
    c_code = """
#define MAXINDEX 99
typedef struct Track {
    long index[MAXINDEX + 1];
} Track;

void track_set_index(Track *track, int i, long ind)
{
    if (i > MAXINDEX) {
        return;
    }

    track->index[i] = ind;
}
"""
    test_file = tmp_path / "bounds.c"
    test_file.write_text(c_code, encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "success"
    findings = result.metadata.get("static_findings", {})
    assert "Bounds Check" in findings
    assert any("RCMCP-SAST-C-012" in f and "i" in f for f in findings["Bounds Check"])


@pytest.mark.asyncio
async def test_audit_source_code_c_accepts_lower_and_upper_bound_check(tmp_path):
    """Do not flag an index when both lower and upper guards are present."""
    c_code = """
#define MAXINDEX 99
typedef struct Track {
    long index[MAXINDEX + 1];
} Track;

void track_set_index(Track *track, int i, long ind)
{
    if (i < 0 || i > MAXINDEX) {
        return;
    }

    track->index[i] = ind;
}
"""
    test_file = tmp_path / "bounds_ok.c"
    test_file.write_text(c_code, encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "success"
    findings = result.metadata.get("static_findings", {})
    assert "Bounds Check" not in findings


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
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
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
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
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
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "error"
    assert result.error_code == "FILE_TOO_LARGE"


@pytest.mark.asyncio
async def test_audit_source_code_size_check_os_error(tmp_path):
    """Test when file size check raises OSError."""
    test_file = tmp_path / "error_file.c"
    test_file.write_text("void main() {}", encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
    ):
        with patch("os.path.getsize", side_effect=OSError("Permission denied")):
            result = await audit_source_code(str(test_file))

    assert result.status == "error"
    assert result.error_code == "FILE_ERROR"


@pytest.mark.asyncio
async def test_audit_source_code_read_exception(tmp_path):
    """Test when file reading raises an exception."""
    test_file = tmp_path / "read_error_file.c"
    test_file.write_text("void main() {}", encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
    ):
        # mock open to raise exception
        with patch("builtins.open", side_effect=OSError("Read failure")):
            result = await audit_source_code(str(test_file))

    assert result.status == "error"
    assert result.error_code == "READ_ERROR"


@pytest.mark.asyncio
async def test_audit_source_code_truncation(tmp_path):
    """Test that source code is truncated if it exceeds 2000 lines."""
    # Write a file with 2005 lines
    lines = ["// line comment"] * 2005
    c_code = "\n".join(lines)

    test_file = tmp_path / "long_file.c"
    test_file.write_text(c_code, encoding="utf-8")

    with patch(
        "reversecore_mcp.tools.analysis.source_auditor.validate_file_path",
        return_value=test_file,
    ):
        result = await audit_source_code(str(test_file))

    assert result.status == "success"
    assert result.metadata.get("is_truncated") is True
    # The returned data should have the truncation note
    assert "[Truncated 5 lines]" in result.data


def test_source_auditor_plugin_register():
    """Test registering the SourceAuditorPlugin with the MCP server."""
    from reversecore_mcp.tools.analysis.source_auditor import SourceAuditorPlugin

    plugin = SourceAuditorPlugin()
    assert plugin.name == "source_auditor"

    mock_server = MagicMock()
    # Mock tool decorator behavior
    mock_server.tool = MagicMock(return_value=lambda x: x)
    plugin.register(mock_server)
    mock_server.tool.assert_called_once()
