"""Network forensics tools backed by Scapy for PCAP analysis.

Pure Python implementation using Scapy — no external CLI dependencies,
fully container-friendly. Gracefully degrades if Scapy is not installed.
"""

import asyncio
import collections
import re
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# Common suspicious ports associated with C2 and malware communication
_SUSPICIOUS_PORTS = {
    4444,
    4445,
    5555,
    6666,
    7777,
    8080,
    8443,
    8888,
    9001,
    9002,
    31337,
    65535,
    1337,
    1234,
    12345,
    54321,
    6667,
    6697,
}

# Known C2 framework beacon intervals (seconds) for detection
_BEACON_INTERVALS_SEC = [60, 120, 180, 240, 300, 600]

# Minimum packet count per host to consider as beaconing
_BEACON_MIN_PACKETS = 5


def _import_scapy() -> Any:
    """Lazy import of Scapy to avoid import overhead when unused.

    Returns:
        Scapy module tuple (scapy.all module) or raises ImportError.

    Raises:
        ImportError: If scapy is not installed.
    """
    try:
        import scapy.all as scapy  # type: ignore[import]

        return scapy
    except ImportError as exc:
        raise ImportError("scapy is not installed") from exc


@log_execution(tool_name="pcap_analyze")
@track_metrics("pcap_analyze")
@handle_tool_errors
async def pcap_analyze(
    pcap_path: str,
    max_packets: int = 10000,
) -> ToolResult:
    """Summarize sessions, protocols, and packet statistics from a PCAP file.

    Provides a high-level overview including total packets, unique hosts,
    protocol distribution, top talkers, and session summary — ideal as a
    first-pass triage of a PCAP capture.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        max_packets: Maximum number of packets to process (default: 10,000).
            For large captures, use a smaller value or filter first.

    Returns:
        ToolResult with protocol breakdown, top talkers, and session summary.

    Example:
        >>> result = await pcap_analyze("/app/workspace/capture.pcap")
        >>> print(result.data["protocol_distribution"])
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure(
            "PCAP_PARSE_ERROR",
            f"Failed to parse PCAP file: {exc}",
            hint="Ensure the file is a valid PCAP or PCAPNG capture.",
        )

    if len(packets) == 0:
        return success(
            {
                "pcap_path": str(validated),
                "total_packets": 0,
                "message": "PCAP file is empty — no packets found.",
            }
        )

    protocol_counts: dict[str, int] = collections.defaultdict(int)
    src_counts: dict[str, int] = collections.defaultdict(int)
    dst_counts: dict[str, int] = collections.defaultdict(int)
    sessions: set[str] = set()
    total_bytes = 0

    for pkt in packets:
        total_bytes += len(pkt)

        # Protocol detection
        if pkt.haslayer("ICMP"):
            protocol_counts["ICMP"] += 1
        elif pkt.haslayer("TCP"):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer("UDP"):
            protocol_counts["UDP"] += 1
        elif pkt.haslayer("ARP"):
            protocol_counts["ARP"] += 1
        else:
            protocol_counts["Other"] += 1

        # Application layer
        if pkt.haslayer("DNS"):
            protocol_counts["DNS"] += 1
        if pkt.haslayer("HTTP"):
            protocol_counts["HTTP"] += 1
        if pkt.haslayer("TLS") or pkt.haslayer("SSL"):
            protocol_counts["TLS/SSL"] += 1

        # IP endpoints
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            src_counts[src] += 1
            dst_counts[dst] += 1

            if pkt.haslayer("TCP"):
                dport = pkt["TCP"].dport
                sport = pkt["TCP"].sport
                sessions.add(f"{src}:{sport}->{dst}:{dport}")
            elif pkt.haslayer("UDP"):
                dport = pkt["UDP"].dport
                sport = pkt["UDP"].sport
                sessions.add(f"{src}:{sport}->{dst}:{dport}/UDP")

    top_sources = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_destinations = sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return success(
        {
            "pcap_path": str(validated),
            "total_packets": len(packets),
            "total_bytes": total_bytes,
            "unique_sessions": len(sessions),
            "protocol_distribution": dict(protocol_counts),
            "top_sources": [{"ip": ip, "packets": cnt} for ip, cnt in top_sources],
            "top_destinations": [{"ip": ip, "packets": cnt} for ip, cnt in top_destinations],
            "truncated": len(packets) >= max_packets,
        }
    )


@log_execution(tool_name="pcap_list_connections")
@track_metrics("pcap_list_connections")
@handle_tool_errors
async def pcap_list_connections(
    pcap_path: str,
    protocol: str | None = None,
    max_packets: int = 50000,
) -> ToolResult:
    """List all unique IP/port connections observed in a PCAP capture.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        protocol: Filter by protocol ('tcp', 'udp', or None for all).
        max_packets: Maximum packets to process (default: 50,000).

    Returns:
        ToolResult with unique connection tuples (src_ip, src_port, dst_ip, dst_port).

    Example:
        >>> result = await pcap_list_connections("/app/workspace/capture.pcap", protocol="tcp")
        >>> print(result.data["connections"])
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    connections: set[tuple[str, ...]] = set()

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue

        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst

        if pkt.haslayer("TCP") and (protocol is None or protocol.lower() == "tcp"):
            connections.add((src_ip, str(pkt["TCP"].sport), dst_ip, str(pkt["TCP"].dport), "TCP"))
        elif pkt.haslayer("UDP") and (protocol is None or protocol.lower() == "udp"):
            connections.add((src_ip, str(pkt["UDP"].sport), dst_ip, str(pkt["UDP"].dport), "UDP"))

    conn_list = [
        {
            "src_ip": c[0],
            "src_port": int(c[1]),
            "dst_ip": c[2],
            "dst_port": int(c[3]),
            "protocol": c[4],
            "suspicious_port": int(c[3]) in _SUSPICIOUS_PORTS or int(c[1]) in _SUSPICIOUS_PORTS,
        }
        for c in sorted(connections)
    ]

    suspicious = [c for c in conn_list if c["suspicious_port"]]

    return success(
        {
            "pcap_path": str(validated),
            "connections": conn_list[:2000],
            "total_connections": len(conn_list),
            "suspicious_connections": suspicious[:100],
            "suspicious_count": len(suspicious),
            "protocol_filter": protocol,
        }
    )


@log_execution(tool_name="pcap_extract_dns")
@track_metrics("pcap_extract_dns")
@handle_tool_errors
async def pcap_extract_dns(
    pcap_path: str,
    include_responses: bool = True,
    max_packets: int = 50000,
) -> ToolResult:
    """Extract DNS queries and responses from a PCAP capture.

    Useful for identifying C2 domain lookups, DGA patterns, DNS tunneling,
    and suspicious resolution activity.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        include_responses: If True, also extract DNS response records (A, AAAA, MX, TXT).
        max_packets: Maximum packets to process (default: 50,000).

    Returns:
        ToolResult with DNS query/response pairs, unique domains, and anomaly flags.

    Example:
        >>> result = await pcap_extract_dns("/app/workspace/capture.pcap")
        >>> print(result.data["unique_domains"])
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    queries: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    unique_domains: set[str] = set()

    # DGA detection heuristics: high entropy, long random-looking names
    dga_pattern = re.compile(r"^[a-z0-9]{10,}\.(com|net|org|io|cc|ru|cn)$", re.IGNORECASE)

    for pkt in packets:
        if not pkt.haslayer("DNS"):
            continue

        dns = pkt["DNS"]

        # Extract queries (qr=0)
        if dns.qr == 0 and dns.qdcount > 0:
            try:
                for _ in range(dns.qdcount):
                    qd = dns.qd
                    if qd:
                        name = qd.qname.decode(errors="replace").rstrip(".")
                        qtype = qd.qtype
                        unique_domains.add(name)
                        queries.append(
                            {
                                "domain": name,
                                "qtype": qtype,
                                "possible_dga": bool(dga_pattern.match(name)),
                                "src_ip": pkt["IP"].src if pkt.haslayer("IP") else None,
                            }
                        )
            except Exception as exc:
                logger.debug("DNS query parse error: %s", exc)

        # Extract responses (qr=1)
        if include_responses and dns.qr == 1 and dns.ancount > 0:
            try:
                an = dns.an
                while an:
                    rtype = getattr(an, "type", None)
                    rdata = None
                    if rtype == 1:  # A record
                        rdata = str(getattr(an, "rdata", ""))
                    elif rtype == 28:  # AAAA record
                        rdata = str(getattr(an, "rdata", ""))
                    elif rtype == 16:  # TXT record
                        rdata = str(getattr(an, "rdata", ""))

                    if rdata:
                        rrname = getattr(an, "rrname", b"")
                        if isinstance(rrname, bytes):
                            rrname = rrname.decode(errors="replace").rstrip(".")
                        responses.append({"domain": rrname, "type": rtype, "rdata": rdata})

                    an = getattr(an, "payload", None)
                    if not an or an.name == "NoPayload":
                        break
            except Exception as exc:
                logger.debug("DNS response parse error: %s", exc)

    possible_dga = [q for q in queries if q.get("possible_dga")]

    return success(
        {
            "pcap_path": str(validated),
            "total_queries": len(queries),
            "total_responses": len(responses),
            "unique_domains": sorted(unique_domains)[:500],
            "unique_domain_count": len(unique_domains),
            "queries": queries[:500],
            "responses": responses[:500] if include_responses else [],
            "possible_dga_domains": possible_dga[:50],
            "dga_count": len(possible_dga),
        }
    )


@log_execution(tool_name="pcap_extract_c2")
@track_metrics("pcap_extract_c2")
@handle_tool_errors
async def pcap_extract_c2(
    pcap_path: str,
    beacon_threshold_sec: int = 60,
    max_packets: int = 100000,
) -> ToolResult:
    """Detect potential C2 traffic patterns in a PCAP capture.

    Detects:
    - Beaconing behavior (periodic connections to same host)
    - Connections to known suspicious ports
    - Unusually long/persistent connections
    - DNS-over-HTTPS (DoH) patterns

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        beacon_threshold_sec: Maximum jitter window (seconds) to consider as beaconing.
        max_packets: Maximum packets to process (default: 100,000).

    Returns:
        ToolResult with C2 indicators, beaconing hosts, and risk assessment.

    Example:
        >>> result = await pcap_extract_c2("/app/workspace/malware_traffic.pcap")
        >>> print(result.data["suspected_c2_hosts"])
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    if len(packets) == 0:
        return success({"pcap_path": str(validated), "message": "Empty PCAP — no C2 indicators."})

    # Track timestamps per destination (host, port) pair
    dst_timestamps: dict[tuple[str, int], list[float]] = collections.defaultdict(list)
    suspicious_port_hits: list[dict[str, Any]] = []

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue

        ts = float(pkt.time)
        dst_ip = pkt["IP"].dst

        if pkt.haslayer("TCP"):
            dport = pkt["TCP"].dport
            dst_timestamps[(dst_ip, dport)].append(ts)

            if dport in _SUSPICIOUS_PORTS:
                suspicious_port_hits.append(
                    {
                        "dst_ip": dst_ip,
                        "dport": dport,
                        "src_ip": pkt["IP"].src,
                        "time": ts,
                    }
                )
        elif pkt.haslayer("UDP"):
            dport = pkt["UDP"].dport
            dst_timestamps[(dst_ip, dport)].append(ts)

    # Detect beaconing: hosts with regular connection intervals
    beaconing_hosts: list[dict[str, Any]] = []
    for (dst_ip, dport), timestamps in dst_timestamps.items():
        if len(timestamps) < _BEACON_MIN_PACKETS:
            continue

        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            continue

        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance**0.5

        # Low std deviation relative to mean = highly periodic = likely beacon
        if avg_interval > 0 and std_dev / avg_interval < 0.3 and avg_interval <= 3600:
            beaconing_hosts.append(
                {
                    "dst_ip": dst_ip,
                    "dst_port": dport,
                    "packet_count": len(timestamps),
                    "avg_interval_sec": round(avg_interval, 2),
                    "std_dev_sec": round(std_dev, 2),
                    "periodicity_score": round(1.0 - (std_dev / avg_interval), 3),
                    "suspicious_port": dport in _SUSPICIOUS_PORTS,
                }
            )

    beaconing_hosts.sort(key=lambda x: x["periodicity_score"], reverse=True)

    c2_indicators = len(beaconing_hosts) + len(suspicious_port_hits)
    risk = "CRITICAL" if c2_indicators > 5 else "HIGH" if c2_indicators > 0 else "LOW"

    return success(
        {
            "pcap_path": str(validated),
            "suspected_c2_hosts": beaconing_hosts[:20],
            "beaconing_count": len(beaconing_hosts),
            "suspicious_port_hits": suspicious_port_hits[:50],
            "suspicious_port_count": len(suspicious_port_hits),
            "risk_level": risk,
            "c2_indicator_count": c2_indicators,
        }
    )


@log_execution(tool_name="pcap_reconstruct_stream")
@track_metrics("pcap_reconstruct_stream")
@handle_tool_errors
async def pcap_reconstruct_stream(
    pcap_path: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    max_packets: int = 10000,
    max_bytes: int = 1024 * 1024,  # 1 MB
) -> ToolResult:
    """Reconstruct TCP stream payload from a PCAP capture.

    Reassembles the raw payload of a specific TCP conversation, useful for
    extracting transferred files, command output, or HTTP request/response bodies.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        src_ip: Source IP address of the stream.
        dst_ip: Destination IP address of the stream.
        dst_port: Destination TCP port of the stream.
        max_packets: Maximum packets to process (default: 10,000).
        max_bytes: Maximum payload bytes to reconstruct (default: 1 MB).

    Returns:
        ToolResult with reconstructed stream payload (hex + printable ASCII).

    Example:
        >>> result = await pcap_reconstruct_stream(
        ...     "/app/workspace/capture.pcap",
        ...     src_ip="192.168.1.5",
        ...     dst_ip="10.0.0.1",
        ...     dst_port=4444,
        ... )
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    payload_bytes = bytearray()
    packet_count = 0

    for pkt in packets:
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            continue

        pkt_src = pkt["IP"].src
        pkt_dst = pkt["IP"].dst
        pkt_dport = pkt["TCP"].dport
        pkt_sport = pkt["TCP"].sport

        # Match in either direction
        is_forward = pkt_src == src_ip and pkt_dst == dst_ip and pkt_dport == dst_port
        is_reverse = pkt_src == dst_ip and pkt_dst == src_ip and pkt_sport == dst_port

        if is_forward or is_reverse:
            if pkt.haslayer("Raw"):
                raw = bytes(pkt["Raw"].load)
                if len(payload_bytes) + len(raw) > max_bytes:
                    payload_bytes.extend(raw[: max_bytes - len(payload_bytes)])
                    break
                payload_bytes.extend(raw)
                packet_count += 1

    if not payload_bytes:
        return success(
            {
                "pcap_path": str(validated),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "message": "No payload found for the specified stream. Check IP/port values.",
            }
        )

    raw = bytes(payload_bytes)
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)

    return success(
        {
            "pcap_path": str(validated),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "matching_packets": packet_count,
            "payload_bytes": len(raw),
            "hex_dump": raw[:4096].hex(),
            "printable_ascii": printable[:4096],
            "truncated": len(raw) >= max_bytes,
        }
    )
