"""Unit tests for Progressive Disclosure Layer 1 Meta-Tools.

Tests analyze_binary, triage_incident, and investigate_vulnerability.
"""

from __future__ import annotations

import pytest

from reversecore_mcp.core.result import ToolResult
from reversecore_mcp.tools.common.meta_tools import (
    analyze_binary,
    investigate_vulnerability,
    triage_incident,
)


@pytest.fixture
def mock_elf_binary(workspace_dir):
    """Create a minimal mock ELF binary in workspace."""
    sample = workspace_dir / "test_sample.elf"
    # Minimal 64-bit ELF header + some strings
    content = (
        b"\x7fELF\x02\x01\x01\x00"
        + b"\x00" * 8
        + b"\x02\x00\x3e\x00\x01\x00\x00\x00"
        + b"\x40\x10\x40\x00\x00\x00\x00\x00"
        + b"strcpy\x00system\x00http://malicious.example.com/c2\x00"
        + b"192.168.1.100\x00/bin/sh\x00"
        + b"\x90" * 64
    )
    sample.write_bytes(content)
    return sample


@pytest.fixture
def mock_pcap_file(workspace_dir):
    """Create a mock PCAP file in workspace."""
    pcap = workspace_dir / "capture.pcap"
    # Standard libpcap magic header (TCPDUMP)
    header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    pcap.write_bytes(header)
    return pcap


@pytest.fixture
def mock_memory_file(workspace_dir):
    """Create a mock memory dump file in workspace."""
    mem = workspace_dir / "memdump.raw"
    mem.write_bytes(b"\x00" * 4096)
    return mem


@pytest.mark.asyncio
async def test_analyze_binary_general(mock_elf_binary, patched_workspace_config):
    """Test analyze_binary with default general goal."""
    res = await analyze_binary(str(mock_elf_binary), goal="general", decompile=False)
    assert isinstance(res, ToolResult)
    assert res.status == "success"
    data = res.data
    assert data["status"] == "success"
    assert "file" in data
    assert data["file"]["file_name"] == "test_sample.elf"
    assert "hashes" in data["file"]
    assert "sha256" in data["file"]["hashes"]
    assert "mitigations" in data
    assert "goal_assessment" in data
    assert "recommended_tools" in data
    assert len(data["recommended_tools"]) > 0


@pytest.mark.asyncio
async def test_analyze_binary_malware_goal(mock_elf_binary, patched_workspace_config):
    """Test analyze_binary with malware goal."""
    res = await analyze_binary(str(mock_elf_binary), goal="malware", decompile=False)
    assert res.status == "success"
    data = res.data
    assert "goal_assessment" in data
    assert "extracted_iocs" in data["goal_assessment"]
    # Check recommended tools contain yara / packer
    tool_names = [t["tool"] for t in data["recommended_tools"]]
    assert any("yara" in name for name in tool_names)


@pytest.mark.asyncio
async def test_analyze_binary_vuln_goal(mock_elf_binary, patched_workspace_config):
    """Test analyze_binary with vuln goal."""
    res = await analyze_binary(str(mock_elf_binary), goal="vuln", decompile=False)
    assert res.status == "success"
    data = res.data
    assert "goal_assessment" in data
    assert "dangerous_functions" in data["goal_assessment"]
    tool_names = [t["tool"] for t in data["recommended_tools"]]
    assert any("vuln" in name or "rop" in name for name in tool_names)


@pytest.mark.asyncio
async def test_analyze_binary_invalid_path(patched_workspace_config):
    """Test analyze_binary fails properly with non-existent file."""
    res = await analyze_binary("/non/existent/path/file.bin")
    assert res.status == "error"
    assert res.error is not None


@pytest.mark.asyncio
async def test_triage_incident_pcap(mock_pcap_file, patched_workspace_config):
    """Test triage_incident with PCAP file."""
    res = await triage_incident(str(mock_pcap_file))
    assert res.status == "success"
    data = res.data
    assert data["artifact_type"] == "pcap"
    assert "anomalies" in data
    assert "extracted_iocs" in data
    assert "overall_severity" in data
    assert len(data["recommended_tools"]) > 0


@pytest.mark.asyncio
async def test_triage_incident_memory(mock_memory_file, patched_workspace_config):
    """Test triage_incident with memory dump file."""
    res = await triage_incident(str(mock_memory_file), artifact_type="memory")
    assert res.status == "success"
    data = res.data
    assert data["artifact_type"] == "memory"
    assert "details" in data
    assert "recommended_tools" in data


@pytest.mark.asyncio
async def test_investigate_vulnerability_basic(mock_elf_binary, patched_workspace_config):
    """Test investigate_vulnerability basic run."""
    res = await investigate_vulnerability(str(mock_elf_binary))
    assert res.status == "success"
    data = res.data
    assert "exploitability_score" in data
    assert 0.0 <= data["exploitability_score"] <= 10.0
    assert data["exploitability_rating"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert "mitigations" in data
    assert "remediation_recommendations" in data
    assert len(data["recommended_tools"]) > 0


@pytest.mark.asyncio
async def test_investigate_vulnerability_with_crash_log(mock_elf_binary, patched_workspace_config):
    """Test investigate_vulnerability with crash log trace."""
    crash_trace = (
        "==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010\n"
        "READ of size 4 at 0x602000000010 thread T0\n"
        "    #0 0x401234 in process_request /app/main.c:42\n"
    )
    res = await investigate_vulnerability(str(mock_elf_binary), crash_log=crash_trace)
    assert res.status == "success"
    data = res.data
    assert data["crash_triage"] is not None
    assert "CWE-416" in data["identified_cwes"]
    assert data["exploitability_score"] >= 4.0
