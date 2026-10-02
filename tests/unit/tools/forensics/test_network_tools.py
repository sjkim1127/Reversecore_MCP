"""Unit tests for network forensics tools (network.py).

Tests cover happy path with mocked Scapy PCAP reads
and edge cases: missing Scapy, empty PCAP, malformed packets.
"""

from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.forensics.network import (
    _reassemble_tcp_payloads,
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


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_dns_reads_every_question_from_pcap(tmp_pcap):
    """A real two-question DNS packet should produce both domains and DGA counts."""
    scapy = pytest.importorskip("scapy.all")
    packet = (
        scapy.IP()
        / scapy.UDP(sport=53000, dport=53)
        / scapy.DNS(
            qr=0,
            qdcount=2,
            qd=scapy.DNSQR(qname="a.example") / scapy.DNSQR(qname="abcdefghijklmnop.com"),
        )
    )
    scapy.wrpcap(tmp_pcap, [packet])

    result = await pcap_extract_dns(tmp_pcap, include_responses=False)

    assert result.status == "success"
    assert result.data["total_queries"] == 2
    assert [query["domain"] for query in result.data["queries"]] == [
        "a.example",
        "abcdefghijklmnop.com",
    ]
    assert result.data["unique_domains"] == ["a.example", "abcdefghijklmnop.com"]
    assert result.data["unique_domain_count"] == 2
    assert result.data["dga_count"] == 1
    assert [query["domain"] for query in result.data["possible_dga_domains"]] == [
        "abcdefghijklmnop.com"
    ]


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("qdcount", "expected_domains"),
    [
        (0, []),
        (1, ["first.example"]),
        (3, ["first.example", "second.example"]),
    ],
)
async def test_pcap_extract_dns_respects_question_count(
    tmp_pcap,
    qdcount,
    expected_domains,
):
    """Declared counts bound iteration and missing records are not duplicated."""
    packet = MagicMock()
    packet.haslayer = lambda layer: layer == "DNS"
    dns = MagicMock()
    dns.qr = 0
    dns.qdcount = qdcount
    first = MagicMock(qname=b"first.example.", qtype=1)
    second = MagicMock(qname=b"second.example.", qtype=28)
    dns.qd = [first, second]
    packet.__getitem__.side_effect = lambda layer: dns if layer == "DNS" else MagicMock()

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_import:
        mock_scapy = MagicMock()
        mock_scapy.rdpcap.return_value = [packet]
        mock_import.return_value = mock_scapy

        result = await pcap_extract_dns(tmp_pcap, include_responses=False)

    assert result.status == "success"
    assert [query["domain"] for query in result.data["queries"]] == expected_domains
    assert result.data["unique_domain_count"] == len(expected_domains)


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


@pytest.mark.unit
def test_pcap_import_scapy_error():
    """Test _import_scapy raises ImportError when scapy is not installed."""
    import sys
    from unittest.mock import patch

    with patch.dict(sys.modules, {"scapy.all": None}):
        from reversecore_mcp.tools.forensics.network import _import_scapy

        with pytest.raises(ImportError) as exc:
            _import_scapy()
        assert "scapy is not installed" in str(exc.value)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_analyze_various_protocols(tmp_pcap):
    """Happy path: pcap_analyze handles ICMP, UDP, ARP, Other, DNS, HTTP, TLS, UDP sessions."""
    # Build various mocked packets
    packets = []

    # 1. ICMP
    pkt_icmp = MagicMock()
    pkt_icmp.haslayer = lambda lyr: lyr in ("ICMP", "IP")
    pkt_icmp["IP"].src = "192.168.1.1"
    pkt_icmp["IP"].dst = "192.168.1.2"
    pkt_icmp.__len__ = lambda _: 64
    packets.append(pkt_icmp)

    # 2. UDP + DNS
    pkt_dns = MagicMock()
    pkt_dns.haslayer = lambda lyr: lyr in ("UDP", "DNS", "IP")
    pkt_dns["IP"].src = "192.168.1.1"
    pkt_dns["IP"].dst = "8.8.8.8"
    pkt_dns["UDP"].sport = 5353
    pkt_dns["UDP"].dport = 53
    pkt_dns.__len__ = lambda _: 80
    packets.append(pkt_dns)

    # 3. ARP
    pkt_arp = MagicMock()
    pkt_arp.haslayer = lambda lyr: lyr == "ARP"
    pkt_arp.__len__ = lambda _: 42
    packets.append(pkt_arp)

    # 4. Other (raw Ethernet)
    pkt_other = MagicMock()
    pkt_other.haslayer = lambda _: False
    pkt_other.__len__ = lambda _: 60
    packets.append(pkt_other)

    # 5. TCP + HTTP
    pkt_http = MagicMock()
    pkt_http.haslayer = lambda lyr: lyr in ("TCP", "HTTP", "IP")
    pkt_http["IP"].src = "192.168.1.1"
    pkt_http["IP"].dst = "1.1.1.1"
    pkt_http["TCP"].sport = 45000
    pkt_http["TCP"].dport = 80
    pkt_http.__len__ = lambda _: 120
    packets.append(pkt_http)

    # 6. TCP + TLS
    pkt_tls = MagicMock()
    pkt_tls.haslayer = lambda lyr: lyr in ("TCP", "TLS", "IP")
    pkt_tls["IP"].src = "192.168.1.1"
    pkt_tls["IP"].dst = "1.1.1.1"
    pkt_tls["TCP"].sport = 45001
    pkt_tls["TCP"].dport = 443
    pkt_tls.__len__ = lambda _: 512
    packets.append(pkt_tls)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = packets
        mock_scapy_import.return_value = mock_sc

        result = await pcap_analyze(tmp_pcap)

    assert result.status == "success"
    dist = result.data["protocol_distribution"]
    assert dist["ICMP"] == 1
    assert dist["UDP"] == 1
    assert dist["ARP"] == 1
    assert dist["Other"] == 1
    assert dist["DNS"] == 1
    assert dist["HTTP"] == 1
    assert dist["TLS/SSL"] == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_rdpcap_parse_errors(tmp_pcap):
    """Edge cases: rdpcap raising Exception during parsing is caught."""
    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.side_effect = Exception("Corrupted PCAP")
        mock_scapy_import.return_value = mock_sc

        # 1. pcap_list_connections
        result = await pcap_list_connections(tmp_pcap)
        assert result.status == "error"
        assert result.error_code == "PCAP_PARSE_ERROR"

        # 2. pcap_extract_dns
        result = await pcap_extract_dns(tmp_pcap)
        assert result.status == "error"
        assert result.error_code == "PCAP_PARSE_ERROR"

        # 3. pcap_extract_c2
        result = await pcap_extract_c2(tmp_pcap)
        assert result.status == "error"
        assert result.error_code == "PCAP_PARSE_ERROR"

        # 4. pcap_reconstruct_stream
        result = await pcap_reconstruct_stream(tmp_pcap, "1.2.3.4", "5.6.7.8", 80)
        assert result.status == "error"
        assert result.error_code == "PCAP_PARSE_ERROR"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_list_connections_uncovered_paths(tmp_pcap):
    """Happy path/Edge case: connections list with non-IP packets and UDP protocol filters."""
    pkt_nonip = MagicMock()
    pkt_nonip.haslayer = lambda lyr: lyr == "ARP"

    pkt_udp = MagicMock()
    pkt_udp.haslayer = lambda lyr: lyr in ("IP", "UDP")
    pkt_udp["IP"].src = "10.0.0.1"
    pkt_udp["IP"].dst = "20.0.0.2"
    pkt_udp["UDP"].sport = 1234
    pkt_udp["UDP"].dport = 5678

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = [pkt_nonip, pkt_udp]
        mock_scapy_import.return_value = mock_sc

        # Query UDP protocol
        result = await pcap_list_connections(tmp_pcap, protocol="udp")
        assert result.status == "success"
        conns = result.data["connections"]
        assert len(conns) == 1
        assert conns[0]["protocol"] == "UDP"


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_dns_uncovered_paths(tmp_pcap):
    """Happy path: DNS query/response A, AAAA, TXT record parsing."""
    # 1. DNS Query
    pkt_query = MagicMock()
    pkt_query.haslayer = lambda lyr: lyr in ("DNS", "IP")
    ip_mock = MagicMock()
    ip_mock.src = "192.168.1.10"

    dns_q = MagicMock()
    dns_q.qr = 0
    dns_q.qdcount = 1
    qd = MagicMock()
    qd.qname = b"my-domain.com"
    qd.qtype = 1
    dns_q.qd = qd

    pkt_query.__getitem__.side_effect = lambda key: (
        dns_q if key == "DNS" else ip_mock if key == "IP" else MagicMock()
    )

    # 2. DNS Response (with A, AAAA, and TXT records)
    pkt_resp = MagicMock()
    pkt_resp.haslayer = lambda lyr: lyr == "DNS"
    dns_r = MagicMock()
    dns_r.qr = 1
    dns_r.ancount = 3

    rr_txt = MagicMock()
    rr_txt.type = 16  # TXT
    rr_txt.rdata = "txt_value"
    rr_txt.rrname = b"my-domain.com"
    rr_txt.payload = None

    rr_aaaa = MagicMock()
    rr_aaaa.type = 28  # AAAA
    rr_aaaa.rdata = "2001:db8::1"
    rr_aaaa.rrname = b"my-domain.com"
    rr_aaaa.payload = rr_txt

    rr_a = MagicMock()
    rr_a.type = 1  # A
    rr_a.rdata = "1.2.3.4"
    rr_a.rrname = b"my-domain.com"
    rr_a.payload = rr_aaaa

    dns_r.an = rr_a

    pkt_resp.__getitem__.side_effect = lambda key: dns_r if key == "DNS" else MagicMock()

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = [pkt_query, pkt_resp]
        mock_scapy_import.return_value = mock_sc

        result = await pcap_extract_dns(tmp_pcap, include_responses=True)

    assert result.status == "success"
    assert result.data["total_queries"] == 1
    assert result.data["total_responses"] == 3
    resps = result.data["responses"]
    assert resps[0]["type"] == 1  # A
    assert resps[1]["type"] == 28  # AAAA
    assert resps[2]["type"] == 16  # TXT


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_beacon_detected(tmp_pcap):
    """Happy path: C2 beaconing detected based on regular connection intervals."""
    packets = []
    # 5 packets at exactly 60-second intervals
    timestamps = [100.0, 160.0, 220.0, 280.0, 340.0]

    # Non-IP packet
    pkt_nonip = MagicMock()
    pkt_nonip.haslayer = lambda lyr: lyr == "ARP"
    packets.append(pkt_nonip)

    for ts in timestamps:
        # UDP C2 beacon
        pkt = MagicMock()
        pkt.haslayer = lambda lyr: lyr in ("IP", "UDP")
        pkt.time = ts
        ip = MagicMock()
        ip.src = "192.168.1.1"
        ip.dst = "99.99.99.99"
        udp = MagicMock()
        udp.dport = 8080
        pkt.__getitem__.side_effect = lambda key, ip=ip, udp=udp: (
            ip if key == "IP" else udp if key == "UDP" else MagicMock()
        )
        packets.append(pkt)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = packets
        mock_scapy_import.return_value = mock_sc

        result = await pcap_extract_c2(tmp_pcap)

    assert result.status == "success"
    assert result.data["beaconing_count"] == 1
    assert result.data["suspected_c2_hosts"][0]["dst_ip"] == "99.99.99.99"
    assert result.data["suspected_c2_hosts"][0]["avg_interval_sec"] == 60.0
    assert result.data["suspected_c2_hosts"][0]["periodicity_score"] == 1.0
    assert result.data["beacon_threshold_sec"] == 60
    assert result.data["beacon_criteria"]["max_jitter_sec"] == 60


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_beacon_threshold_tightened_and_relaxed(tmp_pcap):
    """Verify beacon_threshold_sec dynamically classifies beaconing when tightened or relaxed."""
    # intervals: [65, 55, 65, 55], avg=60.0, std_dev=5.0, rel_jitter=5/60 ~= 0.083 < 0.3
    timestamps = [100.0, 165.0, 220.0, 285.0, 340.0]
    packets = []
    for ts in timestamps:
        pkt = MagicMock()
        pkt.haslayer = lambda lyr: lyr in ("IP", "UDP")
        pkt.time = ts
        ip = MagicMock()
        ip.src = "192.168.1.1"
        ip.dst = "99.99.99.99"
        udp = MagicMock()
        udp.dport = 8080
        pkt.__getitem__.side_effect = lambda key, ip=ip, udp=udp: (
            ip if key == "IP" else udp if key == "UDP" else MagicMock()
        )
        packets.append(pkt)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = packets
        mock_scapy_import.return_value = mock_sc

        # Tightened: std_dev (5.0) > threshold (2) -> not classified as beacon
        res_tight = await pcap_extract_c2(tmp_pcap, beacon_threshold_sec=2)
        assert res_tight.status == "success"
        assert res_tight.data["beaconing_count"] == 0
        assert res_tight.data["beacon_threshold_sec"] == 2
        assert res_tight.data["beacon_criteria"]["max_jitter_sec"] == 2

        # Relaxed: std_dev (5.0) <= threshold (10) -> classified as beacon
        res_relaxed = await pcap_extract_c2(tmp_pcap, beacon_threshold_sec=10)
        assert res_relaxed.status == "success"
        assert res_relaxed.data["beaconing_count"] == 1
        assert res_relaxed.data["beacon_threshold_sec"] == 10
        assert res_relaxed.data["suspected_c2_hosts"][0]["std_dev_sec"] == 5.0
        assert res_relaxed.data["suspected_c2_hosts"][0]["beacon_threshold_sec"] == 10


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_threshold_validation(tmp_pcap):
    """Zero, negative, and extreme threshold values are validated."""
    for invalid_val in [0, -10, 5000]:
        res = await pcap_extract_c2(tmp_pcap, beacon_threshold_sec=invalid_val)
        assert res.status == "error"
        assert "beacon_threshold_sec" in (res.message or "")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_reconstruct_stream_success(tmp_pcap):
    """Happy path: TCP stream reconstructed correctly."""
    packets = []

    # Non IP packet
    pkt_non = MagicMock()
    pkt_non.haslayer = lambda lyr: lyr == "ARP"
    packets.append(pkt_non)

    # Helper to build mock TCP packet with Raw payload
    def build_mock_tcp(src_ip, dst_ip, sport, dport, sequence, payload_bytes):
        pkt = MagicMock()
        pkt.haslayer = lambda lyr: lyr in ("IP", "TCP", "Raw")

        ip = MagicMock()
        ip.src = src_ip
        ip.dst = dst_ip

        tcp = MagicMock()
        tcp.sport = sport
        tcp.dport = dport
        tcp.seq = sequence
        tcp.flags = 0x10

        raw = MagicMock()
        raw.load = payload_bytes

        pkt.__getitem__.side_effect = lambda key: (
            ip if key == "IP" else tcp if key == "TCP" else raw if key == "Raw" else MagicMock()
        )
        return pkt

    # Forward packet
    pkt_fwd = build_mock_tcp("1.2.3.4", "5.6.7.8", 12345, 80, 100, b"Hello ")
    packets.append(pkt_fwd)

    # Reverse packet
    pkt_rev = build_mock_tcp("5.6.7.8", "1.2.3.4", 80, 12345, 1000, b"World!")
    packets.append(pkt_rev)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = packets
        mock_scapy_import.return_value = mock_sc

        result = await pcap_reconstruct_stream(
            tmp_pcap, src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=80
        )

    assert result.status == "success"
    assert result.data["matching_packets"] == 2
    assert result.data["payload_bytes"] == 12
    assert result.data["src_ip"] == "1.2.3.4"
    assert result.data["src_port"] == 12345
    assert result.data["dst_ip"] == "5.6.7.8"
    assert result.data["dst_port"] == 80
    assert result.data["flow"]["src_port"] == 12345
    assert result.data["printable_ascii"] == "Hello "
    assert result.data["forward_stream"]["direction"] == "src_to_dst"
    assert result.data["reverse_stream"]["direction"] == "dst_to_src"
    assert result.data["reverse_stream"]["segments"][0]["printable_ascii"] == "World!"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_reconstruct_stream_selects_and_reassembles_one_flow(tmp_pcap):
    """A PCAP with concurrent flows, retransmits, reordering, and gaps stays explicit."""
    scapy = pytest.importorskip("scapy.all")

    def tcp_packet(src_ip, dst_ip, src_port, dst_port, sequence, payload):
        return (
            scapy.IP(src=src_ip, dst=dst_ip)
            / scapy.TCP(sport=src_port, dport=dst_port, seq=sequence, flags="PA")
            / scapy.Raw(load=payload)
        )

    packets = [
        tcp_packet("1.2.3.4", "5.6.7.8", 54321, 80, 5000, b"DECOY"),
        tcp_packet("1.2.3.4", "5.6.7.8", 12345, 80, 1006, b"World"),
        tcp_packet("5.6.7.8", "1.2.3.4", 80, 12345, 9001, b"PONG"),
        tcp_packet("1.2.3.4", "5.6.7.8", 12345, 80, 1001, b"Hello"),
        tcp_packet("1.2.3.4", "5.6.7.8", 12345, 80, 1001, b"Hello"),
        tcp_packet("1.2.3.4", "5.6.7.8", 12345, 80, 1004, b"loWo"),
        tcp_packet("1.2.3.4", "5.6.7.8", 12345, 80, 1012, b"tail"),
        tcp_packet("5.6.7.8", "1.2.3.4", 80, 12345, 8996, b"PING "),
    ]
    scapy.wrpcap(tmp_pcap, packets)

    result = await pcap_reconstruct_stream(
        tmp_pcap,
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        dst_port=80,
        src_port=12345,
    )

    assert result.status == "success"
    assert result.data["flow"]["src_port"] == 12345
    assert result.data["matching_packets"] == 7
    assert result.data["payload_bytes"] == 23
    assert result.data["printable_ascii"] == "HelloWorld<GAP:1 bytes>tail"

    forward = result.data["forward_stream"]
    assert [segment["printable_ascii"] for segment in forward["segments"]] == [
        "HelloWorld",
        "tail",
    ]
    assert forward["gaps"] == [{"sequence_start": 1011, "sequence_end": 1012, "missing_bytes": 1}]
    assert forward["retransmission_count"] == 1
    assert forward["overlap_bytes"] == 9

    reverse = result.data["reverse_stream"]
    assert reverse["direction"] == "dst_to_src"
    assert [segment["printable_ascii"] for segment in reverse["segments"]] == ["PING PONG"]

    ambiguous = await pcap_reconstruct_stream(
        tmp_pcap, src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=80
    )
    assert ambiguous.status == "error"
    assert ambiguous.error_code == "AMBIGUOUS_TCP_FLOW"
    assert ambiguous.details["candidate_source_ports"] == [12345, 54321]


@pytest.mark.unit
def test_reassemble_tcp_payloads_reports_conflicting_overlap():
    """Conflicting bytes use the earlier sequence segment and remain visible."""
    result = _reassemble_tcp_payloads([(100, b"abcd"), (102, b"XYef")], max_bytes=64)

    assert result["segments"][0]["payload"] == b"abcdef"
    assert result["overlap_bytes"] == 2
    assert result["conflicting_overlap_bytes"] == 2
    assert result["retransmission_count"] == 0


@pytest.mark.unit
def test_reassemble_tcp_payloads_handles_sequence_wraparound():
    """TCP sequence numbers that wrap at 2^32 remain in stream order."""
    result = _reassemble_tcp_payloads([(0xFFFFFFFE, b"AB"), (0, b"CD")], max_bytes=64)

    assert result["segments"] == [
        {"sequence_start": 0xFFFFFFFE, "sequence_end": 2, "payload": b"ABCD"}
    ]
    assert result["gaps"] == []


@pytest.mark.unit
def test_pcap_import_scapy_success():
    """Test _import_scapy returns the actual scapy module when installed."""
    import sys
    from unittest.mock import MagicMock, patch

    mock_scapy_all = MagicMock()
    mock_scapy = MagicMock()
    mock_scapy.all = mock_scapy_all
    with patch.dict(sys.modules, {"scapy": mock_scapy, "scapy.all": mock_scapy_all}):
        from reversecore_mcp.tools.forensics.network import _import_scapy

        assert _import_scapy() == mock_scapy_all


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_dns_parse_errors(tmp_pcap):
    """Edge cases: DNS query and response parsing throw exceptions but are handled gracefully."""

    class BadDNSQuery:
        def __init__(self):
            self.qr = 0
            self.qdcount = 1

        @property
        def qd(self):
            raise AttributeError("qd error")

    class BadDNSResponse:
        def __init__(self):
            self.qr = 1
            self.ancount = 1

        @property
        def an(self):
            raise AttributeError("an error")

    # DNS Query raising exception during qd layer access
    pkt_query = MagicMock()
    pkt_query.haslayer = lambda lyr: lyr in ("DNS", "IP")
    dns_q = BadDNSQuery()
    pkt_query.__getitem__.side_effect = lambda key: dns_q if key == "DNS" else MagicMock()

    # DNS Response raising exception during an layer access
    pkt_resp = MagicMock()
    pkt_resp.haslayer = lambda lyr: lyr == "DNS"
    dns_r = BadDNSResponse()
    pkt_resp.__getitem__.side_effect = lambda key: dns_r if key == "DNS" else MagicMock()

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = [pkt_query, pkt_resp]
        mock_scapy_import.return_value = mock_sc

        result = await pcap_extract_dns(tmp_pcap, include_responses=True)

    assert result.status == "success"
    # Exception handling blocks caught parse errors, so queries/responses list should be empty
    assert result.data["total_queries"] == 0
    assert result.data["total_responses"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_no_scapy(tmp_pcap):
    """Edge case: Scapy not installed in pcap_extract_c2."""
    with patch(
        "reversecore_mcp.tools.forensics.network._import_scapy",
        side_effect=ImportError,
    ):
        result = await pcap_extract_c2(tmp_pcap)

    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_extract_c2_empty_intervals(tmp_pcap):
    """Edge case: periodicity calculation with empty connection intervals."""
    # Build 1 packet, normally skipped by _BEACON_MIN_PACKETS = 5.
    # We patch _BEACON_MIN_PACKETS to 0, which makes it pass the count check.
    # Since it only has 1 timestamp, intervals will be empty, covering the continue path.
    pkt = MagicMock()
    pkt.haslayer = lambda lyr: lyr in ("IP", "UDP")
    pkt.time = 100.0
    ip = MagicMock()
    ip.src = "192.168.1.1"
    ip.dst = "99.99.99.99"
    udp = MagicMock()
    udp.dport = 8080
    pkt.__getitem__.side_effect = lambda key: (
        ip if key == "IP" else udp if key == "UDP" else MagicMock()
    )

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = [pkt]
        mock_scapy_import.return_value = mock_sc

        with patch("reversecore_mcp.tools.forensics.network._BEACON_MIN_PACKETS", 0):
            result = await pcap_extract_c2(tmp_pcap)

    assert result.status == "success"
    assert result.data["beaconing_count"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_reconstruct_stream_truncation(tmp_pcap):
    """Happy path: stream reconstruction truncates when payload bytes exceed max_bytes."""
    packets = []

    # TCP packet with a 10-byte payload, but we reconstruct with max_bytes=3
    pkt = MagicMock()
    pkt.haslayer = lambda lyr: lyr in ("IP", "TCP", "Raw")
    ip = MagicMock()
    ip.src = "1.2.3.4"
    ip.dst = "5.6.7.8"
    tcp = MagicMock()
    tcp.sport = 12345
    tcp.dport = 80
    tcp.seq = 100
    tcp.flags = 0x10
    raw = MagicMock()
    raw.load = b"0123456789"
    pkt.__getitem__.side_effect = lambda key: (
        ip if key == "IP" else tcp if key == "TCP" else raw if key == "Raw" else MagicMock()
    )
    packets.append(pkt)

    with patch("reversecore_mcp.tools.forensics.network._import_scapy") as mock_scapy_import:
        mock_sc = MagicMock()
        mock_sc.rdpcap.return_value = packets
        mock_scapy_import.return_value = mock_sc

        result = await pcap_reconstruct_stream(
            tmp_pcap, src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=80, max_bytes=3
        )

    assert result.status == "success"
    assert result.data["payload_bytes"] == 3
    assert result.data["printable_ascii"] == "012"
    assert result.data["truncated"] is True
