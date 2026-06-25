"""
Digital forensics tools for Reversecore_MCP.

This module provides comprehensive forensics capabilities including:
- Memory forensics via Volatility3 (process listing, injection detection, module dumping)
- Disk/filesystem forensics via Sleuth Kit CLI (deleted file recovery, MFT analysis)
- Network forensics via Scapy (PCAP analysis, C2 detection, DNS extraction)
- Artifact correlation pipeline (IoC enrichment, YARA rule auto-generation, timeline)
"""

from reversecore_mcp.tools.forensics import artifact, disk, memory, network

__all__ = [
    "memory",
    "disk",
    "network",
    "artifact",
]
