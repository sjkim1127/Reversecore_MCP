"""Unit tests for network forensics tools (network.py).

Tests cover happy path with mocked Scapy PCAP reads
and edge cases: missing Scapy, empty PCAP, malformed packets.
"""

from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.forensics.network import (
    pcap_analyze,
    pcap_extract_c2,
    pcap_extract_dns,
    pcap_list_connections,
    pcap_reconstruct_stream,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_pcap(workspace_dir, patched_workspace_config):
    """Create a minimal fake PCAP file inside the allowed workspace."""
    pcap = workspace_dir / "test.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # PCAP magic header
    return str(pcap)


# ── pcap_analyze ───────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_analyze_success(tmp_pcap):
    """Happy path: PCAP analyzed and summary returned."""
    mock_pkts = []
    for i in range(5):
        pkt = MagicMock()
        pkt.time = float(1620000000 + i)
        pkt.__len__ = lambda _, x=i: 100 + x
        pkt.haslayer = lambda layer: layer in ("IP", "TCP")
        ip_mock = MagicMock()
        ip_mock.src = f"192.168.1.{i + 1}"
        ip_mock.dst = "10.0.0.1"
        tcp_mock = MagicMock()
        tcp_mock.dport = 80
        tcp_mock.sport = 50000 + i
        pkt.__getitem__ = lambda _, key, ip=ip_mock, tcp=tcp_mock: ip if key == "IP" else tcp
        mock_pkts.append(pkt)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = mock_pkts
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_analyze(tmp_pcap)

    assert result.status == "success"
    assert result.data["total_packets"] == 5


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_analyze_no_scapy(tmp_pcap):
    """Edge case: Scapy not installed."""
    with patch(
        "reversecore_mcp.tools.forensics.network._import_scapy",
        side_effect=ImportError("scapy is not installed"),
    ):
        result = await pcap_analyze(tmp_pcap)

    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_analyze_empty_pcap(tmp_pcap):
    """Edge case: PCAP file is empty (zero packets)."""
    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = []
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_analyze(tmp_pcap)

    assert result.status == "success"
    assert result.data["total_packets"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_analyze_invalid_file(tmp_pcap):
    """Edge case: PCAP file is malformed/corrupted."""
    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.side_effect = Exception("Not a PCAP file")
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_analyze(tmp_pcap)

    assert result.status == "error"
    assert result.error_code == "PCAP_PARSE_ERROR"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_analyze_nonexistent_path():
    """Edge case: PCAP path does not exist."""
    result = await pcap_analyze("/nonexistent/capture.pcap")
    assert result.status == "error"


# ── pcap_list_connections ──────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_list_connections_success(tmp_pcap):
    """Happy path: connections extracted including suspicious ports."""
    mock_pkts = []
    for dport in [80, 443, 4444]:  # 4444 = suspicious
        pkt = MagicMock()
        pkt.haslayer = lambda layer, p=dport: layer in ("IP", "TCP")
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.1"
        ip_mock.dst = "10.0.0.1"
        tcp_mock = MagicMock()
        tcp_mock.sport = 50000
        tcp_mock.dport = dport
        pkt.__getitem__ = lambda _, key, ip=ip_mock, tcp=tcp_mock: ip if key == "IP" else tcp
        mock_pkts.append(pkt)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = mock_pkts
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_list_connections(tmp_pcap)

    assert result.status == "success"
    assert result.data["total_connections"] >= 1
    # At least one suspicious connection on port 4444
    assert result.data["suspicious_count"] >= 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_list_connections_no_scapy(tmp_pcap):
    """Edge case: Scapy not installed."""
    with patch(
        "reversecore_mcp.tools.forensics.network._import_scapy",
        side_effect=ImportError,
    ):
        result = await pcap_list_connections(tmp_pcap)

    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


# ── pcap_extract_dns ───────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_dns_no_dns_packets(tmp_pcap):
    """Edge case: PCAP has no DNS packets."""
    pkt = MagicMock()
    pkt.haslayer = lambda layer: layer == "IP"

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = [pkt]
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_extract_dns(tmp_pcap)

    assert result.status == "success"
    assert result.data["total_queries"] == 0
    assert result.data["unique_domain_count"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_dns_empty_pcap(tmp_pcap):
    """Edge case: empty PCAP returns zero DNS queries."""
    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = []
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_extract_dns(tmp_pcap)

    assert result.status == "success"
    assert result.data["total_queries"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_dns_no_scapy(tmp_pcap):
    """Edge case: Scapy not installed."""
    with patch(
        "reversecore_mcp.tools.forensics.network._import_scapy",
        side_effect=ImportError,
    ):
        result = await pcap_extract_dns(tmp_pcap)

    assert result.status == "error"


# ── pcap_extract_c2 ────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_no_beacons(tmp_pcap):
    """Happy path: no C2 patterns detected (low risk)."""
    # Packets with irregular intervals
    mock_pkts = []
    for ts in [0, 100, 500, 2000]:
        pkt = MagicMock()
        pkt.time = float(ts)
        pkt.haslayer = lambda layer: layer in ("IP", "TCP")
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.1"
        ip_mock.dst = "10.0.0.1"
        tcp_mock = MagicMock()
        tcp_mock.dport = 443
        tcp_mock.sport = 50000
        pkt.__getitem__ = lambda _, key, ip=ip_mock, tcp=tcp_mock: ip if key == "IP" else tcp
        mock_pkts.append(pkt)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = mock_pkts
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_extract_c2(tmp_pcap)

    assert result.status == "success"
    # Irregular intervals should not be flagged as beaconing
    assert result.data["risk_level"] in ("LOW", "HIGH", "CRITICAL")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_empty_pcap(tmp_pcap):
    """Edge case: empty PCAP returns clean result."""
    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = []
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_extract_c2(tmp_pcap)

    assert result.status == "success"
    assert "message" in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_suspicious_port(tmp_pcap):
    """Happy path: connection to port 4444 flagged as suspicious."""
    mock_pkts = []
    for i in range(3):
        pkt = MagicMock()
        pkt.time = float(i * 10)
        pkt.haslayer = lambda layer: layer in ("IP", "TCP")
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.2"
        ip_mock.dst = "185.199.1.1"
        tcp_mock = MagicMock()
        tcp_mock.dport = 4444  # Known suspicious port
        tcp_mock.sport = 55000
        pkt.__getitem__ = lambda _, key, ip=ip_mock, tcp=tcp_mock: ip if key == "IP" else tcp
        mock_pkts.append(pkt)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = mock_pkts
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_extract_c2(tmp_pcap)

    assert result.status == "success"
    assert result.data["suspicious_port_count"] >= 1


# ── pcap_reconstruct_stream ────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_reconstruct_stream_no_match(tmp_pcap):
    """Edge case: no packets matching the specified stream."""
    pkt = MagicMock()
    pkt.haslayer = lambda layer: layer in ("IP", "TCP")
    ip_mock = MagicMock()
    ip_mock.src = "10.10.10.10"
    ip_mock.dst = "20.20.20.20"
    tcp_mock = MagicMock()
    tcp_mock.sport = 9999
    tcp_mock.dport = 8080
    pkt.__getitem__ = lambda _, key, ip=ip_mock, tcp=tcp_mock: ip if key == "IP" else tcp

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = [pkt]
        mock_scapy_import.return_value = mock_scapy

        result = await pcap_reconstruct_stream(
            tmp_pcap, src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=4444
        )

    assert result.status == "success"
    assert "message" in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_reconstruct_stream_no_scapy(tmp_pcap):
    """Edge case: Scapy not installed."""
    with patch(
        "reversecore_mcp.tools.forensics.network._import_scapy",
        side_effect=ImportError,
    ):
        result = await pcap_reconstruct_stream(tmp_pcap, "1.2.3.4", "5.6.7.8", 4444)

    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"
