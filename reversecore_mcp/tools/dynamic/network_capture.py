"""Live network packet capture and PCAP logging for dynamic analysis.

Provides real-time packet capturing during sandbox execution and process memory dumping:
- Captures live network packets to PCAP using Scapy AsyncSniffer
- Gracefully handles unprivileged/container environments without CAP_NET_RAW
- Analyzes captured protocols, unique endpoints, DNS queries, and suspicious ports
- Produces standard PCAP files consumable by forensics and incident response tools
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import os
import time
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path

logger = get_logger(__name__)


def _get_scapy() -> Any:
    """Lazily import Scapy."""
    try:
        import scapy.all as scapy  # type: ignore[import]

        return scapy
    except ImportError as exc:
        raise ImportError("Scapy is required for network packet capture") from exc


def _summarize_packets(packets: list[Any]) -> dict[str, Any]:
    """Extract structured statistics and forensic indicators from Scapy packets."""
    total = len(packets)
    proto_counts: dict[str, int] = collections.defaultdict(int)
    unique_ips: set[str] = set()
    unique_ports: set[int] = set()
    dns_queries: list[str] = []
    suspicious_flows: list[dict[str, Any]] = []

    # Common suspicious / C2 ports
    suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9001, 31337, 1337, 12345}

    for pkt in packets:
        # Check layer types
        if pkt.haslayer("IP"):
            ip_layer = pkt.getlayer("IP")
            src = getattr(ip_layer, "src", None)
            dst = getattr(ip_layer, "dst", None)
            if src:
                unique_ips.add(str(src))
            if dst:
                unique_ips.add(str(dst))

        if pkt.haslayer("TCP"):
            proto_counts["TCP"] += 1
            tcp_layer = pkt.getlayer("TCP")
            sport = getattr(tcp_layer, "sport", 0)
            dport = getattr(tcp_layer, "dport", 0)
            unique_ports.add(sport)
            unique_ports.add(dport)
            if dport in suspicious_ports:
                suspicious_flows.append(
                    {
                        "protocol": "TCP",
                        "dst_port": dport,
                        "src": str(getattr(pkt.getlayer("IP"), "src", "unknown")),
                        "dst": str(getattr(pkt.getlayer("IP"), "dst", "unknown")),
                    }
                )
        elif pkt.haslayer("UDP"):
            proto_counts["UDP"] += 1
            udp_layer = pkt.getlayer("UDP")
            sport = getattr(udp_layer, "sport", 0)
            dport = getattr(udp_layer, "dport", 0)
            unique_ports.add(sport)
            unique_ports.add(dport)
        elif pkt.haslayer("ICMP"):
            proto_counts["ICMP"] += 1
        elif pkt.haslayer("ARP"):
            proto_counts["ARP"] += 1
        else:
            proto_counts["OTHER"] += 1

        # DNS queries
        if pkt.haslayer("DNSQR"):
            try:
                dnsqr = pkt.getlayer("DNSQR")
                qname = getattr(dnsqr, "qname", b"")
                if isinstance(qname, bytes):
                    qname_str = qname.decode("utf-8", errors="replace").rstrip(".")
                else:
                    qname_str = str(qname).rstrip(".")
                if qname_str and qname_str not in dns_queries:
                    dns_queries.append(qname_str)
            except Exception:
                pass

    return {
        "total_packets": total,
        "protocol_breakdown": dict(proto_counts),
        "unique_ip_count": len(unique_ips),
        "unique_ips": sorted(unique_ips)[:25],
        "unique_ports": sorted(unique_ports)[:25],
        "dns_queries": dns_queries[:20],
        "suspicious_flows": suspicious_flows[:10],
    }


class LivePcapRecorder:
    """Background network packet recorder during dynamic binary execution."""

    def __init__(
        self,
        output_pcap: Path,
        interface: str | None = None,
        bpf_filter: str | None = None,
        packet_limit: int = 1000,
    ) -> None:
        self.output_pcap = output_pcap
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_limit = packet_limit
        self.sniffer: Any = None
        self.scapy: Any = None
        self.permission_warning: str | None = None
        self.is_active = False
        self._summary: dict[str, Any] | None = None

    def start(self) -> None:
        """Begin capturing packets asynchronously in the background."""
        self._summary = None
        try:
            self.scapy = _get_scapy()
            self.output_pcap.parent.mkdir(parents=True, exist_ok=True)
            self.sniffer = self.scapy.AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                count=self.packet_limit,
                store=True,
            )
            self.sniffer.start()
            self.is_active = True
        except Exception as exc:
            # Handle unprivileged environments (e.g. non-root without CAP_NET_RAW or macOS /dev/bpf)
            self.permission_warning = f"Live raw packet capture unavailable ({exc}). Ensure root or CAP_NET_RAW privileges."
            self.is_active = False
            # Create a valid empty PCAP container file
            try:
                scapy = self.scapy or _get_scapy()
                scapy.wrpcap(str(self.output_pcap), [])
            except Exception as write_exc:
                logger.debug(f"Failed to write empty PCAP fallback: {write_exc}")

    def stop(self) -> dict[str, Any]:
        """Stop capturing packets, flush to PCAP file, and return summary statistics.

        Idempotent: repeated calls return the first summary instead of rewriting the
        PCAP file with an empty packet list.
        """
        if self._summary is not None:
            return dict(self._summary)
        packets: list[Any] = []
        if self.is_active and self.sniffer:
            try:
                self.sniffer.stop()
                packets = list(self.sniffer.results or [])
            except Exception as exc:
                logger.debug(f"Error stopping sniffer: {exc}")
                self.permission_warning = f"Error during capture finalization: {exc}"
            finally:
                self.is_active = False

        # Always ensure the output PCAP file is written to disk
        try:
            scapy = self.scapy or _get_scapy()
            scapy.wrpcap(str(self.output_pcap), packets)
        except Exception as exc:
            logger.debug(f"Failed to write PCAP file {self.output_pcap}: {exc}")
            if not self.output_pcap.exists():
                self.output_pcap.touch()

        # Calculate file size and sha256 if file exists
        pcap_size = 0
        sha256 = ""
        if self.output_pcap.exists():
            data = self.output_pcap.read_bytes()
            pcap_size = len(data)
            sha256 = hashlib.sha256(data).hexdigest()

        summary = _summarize_packets(packets)
        summary.update(
            {
                "pcap_file": self.output_pcap.name,
                "pcap_path": str(self.output_pcap),
                "pcap_size_bytes": pcap_size,
                "sha256": sha256,
                "interface": self.interface or "default",
                "bpf_filter": self.bpf_filter,
                "permission_warning": self.permission_warning,
            }
        )
        self._summary = summary
        return dict(summary)


@log_execution(tool_name="capture_network_traffic")
@track_metrics("capture_network_traffic")
@handle_tool_errors
async def capture_network_traffic(
    output_pcap: str | None = None,
    duration_seconds: int = 5,
    interface: str | None = None,
    bpf_filter: str | None = None,
    packet_limit: int = 500,
) -> ToolResult:
    """Capture live network packets to a PCAP file and summarize communication flows.

    Captures ingress and egress network packets, records them to an industry-standard
    PCAP file in the workspace, and extracts protocol breakdowns, unique endpoints,
    and DNS lookups. Integrates seamlessly with downstream PCAP forensics tools.

    Args:
        output_pcap: Optional path or filename for the resulting PCAP file.
        duration_seconds: Duration to record network packets in seconds (default: 5, max: 60).
        interface: Specific network interface to monitor (e.g. 'eth0', 'lo', None for default).
        bpf_filter: Optional BPF filter expression (e.g. 'tcp', 'port 53', 'ip proto 17').
        packet_limit: Maximum number of packets to capture (default: 500).

    Returns:
        ToolResult with PCAP file details, protocol breakdown, IP addresses, and DNS queries.

    Example:
        >>> result = await capture_network_traffic(duration_seconds=3, bpf_filter="tcp")
        >>> print(result.status)
        'success'
    """
    workspace = get_workspace_config().workspace.resolve()
    captures_dir = workspace / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)

    target_duration = max(1, min(duration_seconds, 60))
    limit = max(1, min(packet_limit, 10_000))

    if output_pcap:
        clean_name = os.path.basename(output_pcap)
        if not clean_name.endswith(".pcap"):
            clean_name += ".pcap"
        target_pcap = captures_dir / clean_name
    else:
        timestamp = int(time.time() * 1000)
        target_pcap = captures_dir / f"live_capture_{timestamp}.pcap"

    recorder = LivePcapRecorder(
        output_pcap=target_pcap,
        interface=interface,
        bpf_filter=bpf_filter,
        packet_limit=limit,
    )
    recorder.start()

    # Wait for the capture duration
    await asyncio.sleep(float(target_duration))

    summary = recorder.stop()
    validated_pcap = validate_file_path(str(target_pcap))
    summary["pcap_path"] = str(validated_pcap)

    msg = (
        f"Captured {summary['total_packets']} packet(s) over {target_duration}s to '{validated_pcap.name}'. "
        f"Protocols: {summary['protocol_breakdown']}."
    )
    if summary.get("permission_warning"):
        msg += f" Note: {summary['permission_warning']}"

    return success(data=summary, message=msg)
