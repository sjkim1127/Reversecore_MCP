"""Unit tests for Dynamic Analysis tools (trace_execution, dump_process_memory, capture_network_traffic, generate_seccomp_profile)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest

from reversecore_mcp.core.result import ToolResult
from reversecore_mcp.tools.dynamic.memory_dumper import dump_process_memory
from reversecore_mcp.tools.dynamic.network_capture import (
    _summarize_packets,
    capture_network_traffic,
)
from reversecore_mcp.tools.dynamic.sandbox_tracer import trace_execution
from reversecore_mcp.tools.dynamic.seccomp_profiles import (
    generate_seccomp_profile,
)


@pytest.fixture
def mock_exec_binary(workspace_dir):
    """Create a minimal runnable shell script acting as an executable binary."""
    sample = workspace_dir / "target_prog.sh"
    content = (
        "#!/bin/sh\n"
        "echo 'HELLO DYNAMIC SANDBOX'\n"
        "if [ \"$1\" = 'drop' ]; then\n"
        "  echo 'dropped payload' > dropped.txt\n"
        "fi\n"
        "if [ \"$1\" = 'hang' ]; then\n"
        "  sleep 10\n"
        "fi\n"
        "exit 0\n"
    )
    sample.write_text(content)
    sample.chmod(0o755)
    return sample


@pytest.mark.asyncio
async def test_trace_execution_basic(mock_exec_binary, patched_workspace_config):
    """Test standard trace execution capturing stdout and exit code."""
    res = await trace_execution(str(mock_exec_binary), timeout=5)
    assert isinstance(res, ToolResult)
    assert res.status == "success"
    data = res.data
    assert data["exit_code"] == 0
    assert "HELLO DYNAMIC SANDBOX" in data["stdout"]
    assert data["timed_out"] is False
    assert data["execution_duration_ms"] >= 0


@pytest.mark.asyncio
async def test_trace_execution_file_activity(mock_exec_binary, patched_workspace_config):
    """Test trace execution detects created files in workspace."""
    res = await trace_execution(str(mock_exec_binary), arguments=["drop"], timeout=5)
    assert res.status == "success"
    data = res.data
    assert "created_files" in data["file_activity"]
    # Check dropped.txt was detected
    created = [os.path.basename(f) for f in data["file_activity"]["created_files"]]
    assert "dropped.txt" in created
    assert any("dropped" in a for a in data["anomalies"])


@pytest.mark.asyncio
async def test_trace_execution_timeout(mock_exec_binary, patched_workspace_config):
    """Test trace execution handles timeouts properly."""
    res = await trace_execution(str(mock_exec_binary), arguments=["hang"], timeout=1)
    assert res.status == "success"
    data = res.data
    assert data["timed_out"] is True
    assert any("timed out" in a.lower() for a in data["anomalies"])


@pytest.mark.asyncio
async def test_trace_execution_invalid_path(patched_workspace_config):
    """Test trace execution fails with non-existent file."""
    res = await trace_execution("/non/existent/target.bin")
    assert res.status == "error"
    assert res.error is not None


@pytest.mark.asyncio
async def test_trace_execution_with_pcap_and_seccomp(mock_exec_binary, patched_workspace_config):
    """Test trace execution with seccomp profile and PCAP capture enabled."""
    res = await trace_execution(
        str(mock_exec_binary),
        capture_pcap=True,
        seccomp_profile="no_network",
        timeout=5,
    )
    assert res.status == "success"
    data = res.data
    assert "seccomp_profile" in data
    assert data["seccomp_profile"]["profile_name"] == "no_network"
    assert "socket" in data["seccomp_profile"]["blocked_syscalls"]
    assert "pcap_capture" in data
    assert "pcap_file" in data["pcap_capture"]


@pytest.mark.asyncio
async def test_dump_process_memory_basic(mock_exec_binary, patched_workspace_config):
    """Test dump_process_memory spawns, inspects, and creates dump segments."""
    res = await dump_process_memory(
        str(mock_exec_binary), wait_ms=50, filter_permissions="all", timeout=5
    )
    assert isinstance(res, ToolResult)
    assert res.status == "success"
    data = res.data
    assert data["status"] == "success"
    assert "dumped_files" in data
    assert len(data["dumped_files"]) > 0
    assert data["fission_pipeline_ready"] is True
    first_dump = data["dumped_files"][0]
    assert "file_path" in first_dump
    assert "entropy" in first_dump
    assert "sha256" in first_dump


@pytest.mark.asyncio
async def test_dump_process_memory_with_pcap(mock_exec_binary, patched_workspace_config):
    """Test dump_process_memory with PCAP logging."""
    res = await dump_process_memory(
        str(mock_exec_binary),
        wait_ms=50,
        filter_permissions="all",
        capture_pcap=True,
        timeout=5,
    )
    assert res.status == "success"
    data = res.data
    assert "pcap_capture" in data
    assert "pcap_file" in data["pcap_capture"]


@pytest.mark.asyncio
async def test_dump_process_memory_invalid_path(patched_workspace_config):
    """Test dump_process_memory error handling for invalid path."""
    res = await dump_process_memory("/non/existent/target.bin")
    assert res.status == "error"
    assert res.error is not None


@pytest.mark.asyncio
async def test_capture_network_traffic_basic(patched_workspace_config):
    """Test capture_network_traffic creates a PCAP file and returns summary."""
    res = await capture_network_traffic(duration_seconds=1)
    assert isinstance(res, ToolResult)
    assert res.status == "success"
    data = res.data
    assert "pcap_file" in data
    assert "total_packets" in data
    assert "protocol_breakdown" in data
    assert os.path.exists(data["pcap_path"])


def test_summarize_packets_helper():
    """Test packet summary extraction logic."""
    mock_pkt_tcp = MagicMock()
    mock_pkt_tcp.haslayer.side_effect = lambda layer: layer in ("IP", "TCP")
    mock_ip = MagicMock(src="192.168.1.10", dst="10.0.0.1")
    mock_tcp = MagicMock(sport=12345, dport=4444)
    mock_pkt_tcp.getlayer.side_effect = lambda layer: mock_ip if layer == "IP" else mock_tcp

    mock_pkt_dns = MagicMock()
    mock_pkt_dns.haslayer.side_effect = lambda layer: layer in ("IP", "UDP", "DNSQR")
    mock_dnsqr = MagicMock(qname=b"malware-c2.evil.com.")
    mock_pkt_dns.getlayer.side_effect = lambda layer: (
        mock_dnsqr if layer == "DNSQR" else MagicMock(sport=53, dport=53)
    )

    summary = _summarize_packets([mock_pkt_tcp, mock_pkt_dns])
    assert summary["total_packets"] == 2
    assert summary["protocol_breakdown"]["TCP"] == 1
    assert summary["protocol_breakdown"]["UDP"] == 1
    assert "192.168.1.10" in summary["unique_ips"]
    assert "malware-c2.evil.com" in summary["dns_queries"]
    assert len(summary["suspicious_flows"]) == 1
    assert summary["suspicious_flows"][0]["dst_port"] == 4444


@pytest.mark.asyncio
async def test_generate_seccomp_profile_oci_json(patched_workspace_config):
    """Test generate_seccomp_profile in OCI JSON format."""
    res = await generate_seccomp_profile(
        profile_type="no_network",
        custom_blocked_syscalls=["custom_sc"],
        output_format="oci_json",
    )
    assert res.status == "success"
    data = res.data
    assert data["profile_type"] == "no_network"
    assert data["format"] == "oci_json"
    assert "custom_sc" in data["blocked_syscalls"]
    assert os.path.exists(data["profile_path"])

    # Verify JSON content
    with open(data["profile_path"], encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["defaultAction"] == "SCMP_ACT_ALLOW"
    assert any("socket" in s["names"] for s in doc["syscalls"])
    assert any("custom_sc" in s["names"] for s in doc["syscalls"])


@pytest.mark.asyncio
async def test_generate_seccomp_profile_systemd(patched_workspace_config):
    """Test generate_seccomp_profile in systemd filter format."""
    res = await generate_seccomp_profile(
        profile_type="read_only",
        output_format="systemd",
    )
    assert res.status == "success"
    data = res.data
    assert data["format"] == "systemd"
    assert os.path.exists(data["profile_path"])

    with open(data["profile_path"], encoding="utf-8") as f:
        content = f.read()
    assert "SystemCallFilter=~" in content
    assert "unlink" in content


@pytest.mark.asyncio
async def test_generate_seccomp_profile_invalid_type(patched_workspace_config):
    """Test error handling for unknown profile type."""
    res = await generate_seccomp_profile(profile_type="invalid_unknown_type")
    assert res.status == "error"
    assert res.error is not None


@pytest.mark.asyncio
async def test_generate_api_hook_library_basic(patched_workspace_config):
    """Test generating user-space API hooking library."""
    from reversecore_mcp.tools.dynamic.api_hooker import generate_api_hook_library

    res = await generate_api_hook_library()
    assert isinstance(res, ToolResult)
    assert res.status in ("success", "warning")
    data = res.data
    assert "c_source_path" in data
    assert os.path.exists(data["c_source_path"])
    assert "supported_apis" in data
    assert "fopen" in data["supported_apis"]


@pytest.mark.asyncio
async def test_trace_execution_with_api_hooking(mock_exec_binary, patched_workspace_config):
    """Test trace execution with api_hooking flag enabled."""
    res = await trace_execution(str(mock_exec_binary), api_hooking=True, timeout=5)
    assert res.status == "success"
    data = res.data
    assert "api_activity" in data
    assert data["api_activity"]["hooking_enabled"] is True


@pytest.mark.asyncio
async def test_trace_execution_bwrap_handling(mock_exec_binary, patched_workspace_config):
    """Test trace execution with isolation backend bwrap."""
    # When bwrap is not installed, requesting it explicitly returns an error
    import shutil

    has_bwrap = shutil.which("bwrap") is not None
    res = await trace_execution(str(mock_exec_binary), isolation_backend="bwrap", timeout=5)
    if has_bwrap:
        assert res.status == "success"
        assert res.data["isolation_backend"] == "bwrap"
    else:
        assert res.status == "error"
        assert "bwrap" in str(res.error).lower()
