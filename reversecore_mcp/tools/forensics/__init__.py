"""
Digital forensics tools for Reversecore_MCP.

This module provides comprehensive forensics capabilities including:
- Memory forensics via Volatility3 (process listing, injection detection, module dumping)
- Disk/filesystem forensics via Sleuth Kit CLI (deleted file recovery, MFT analysis)
- Network forensics via Scapy (PCAP analysis, C2 detection, DNS extraction)
- Artifact correlation pipeline (IoC enrichment, YARA rule auto-generation, timeline)
"""

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.tools.forensics import artifact, disk, memory, network

logger = get_logger(__name__)


class ForensicsToolsPlugin(Plugin):
    """Unified plugin for all digital forensics tools."""

    @property
    def name(self) -> str:
        return "forensics_tools"

    @property
    def description(self) -> str:
        return "Unified digital forensics tools including memory, disk, network, and artifact forensics."

    def register(self, mcp_server: Any) -> None:
        """Register all forensics tools."""
        from reversecore_mcp.tools.forensics.artifact import (
            artifact_collect,
            artifact_correlate_ioc,
            artifact_generate_yara,
            artifact_report,
            artifact_timeline,
        )
        from reversecore_mcp.tools.forensics.disk import (
            disk_analyze_mft,
            disk_extract_file,
            disk_hash_verify,
            disk_list_files,
            disk_list_partition,
            disk_recover_deleted,
        )
        from reversecore_mcp.tools.forensics.memory import (
            memory_analyze,
            memory_detect_injections,
            memory_dump_module,
            memory_extract_strings,
            memory_list_processes,
            memory_list_symbols,
        )
        from reversecore_mcp.tools.forensics.network import (
            pcap_analyze,
            pcap_extract_c2,
            pcap_extract_dns,
            pcap_list_connections,
            pcap_reconstruct_stream,
        )

        # Register memory forensics tools
        mcp_server.tool(memory_list_symbols)
        mcp_server.tool(memory_analyze)
        mcp_server.tool(memory_list_processes)
        mcp_server.tool(memory_detect_injections)
        mcp_server.tool(memory_extract_strings)
        mcp_server.tool(memory_dump_module)

        # Register disk forensics tools
        mcp_server.tool(disk_list_partition)
        mcp_server.tool(disk_list_files)
        mcp_server.tool(disk_recover_deleted)
        mcp_server.tool(disk_analyze_mft)
        mcp_server.tool(disk_extract_file)
        mcp_server.tool(disk_hash_verify)

        # Register network forensics tools
        mcp_server.tool(pcap_analyze)
        mcp_server.tool(pcap_list_connections)
        mcp_server.tool(pcap_extract_dns)
        mcp_server.tool(pcap_extract_c2)
        mcp_server.tool(pcap_reconstruct_stream)

        # Register artifact correlation tools
        mcp_server.tool(artifact_collect)
        mcp_server.tool(artifact_correlate_ioc)
        mcp_server.tool(artifact_generate_yara)
        mcp_server.tool(artifact_timeline)
        mcp_server.tool(artifact_report)

        logger.info(f"Registered {self.name} plugin with 22 forensics tools (unified)")


__all__ = [
    "memory",
    "disk",
    "network",
    "artifact",
    "ForensicsToolsPlugin",
]
