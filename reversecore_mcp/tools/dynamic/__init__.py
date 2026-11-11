"""Dynamic analysis tools package.

Provides safe, container- and OS-level execution tracing, process memory
dumping, live network packet capturing, and Seccomp sandboxing tools:
- trace_execution: Traces subprocess execution, file activity, syscalls, crashes, and Seccomp policy
- dump_process_memory: Dumps virtual memory segments for dynamic unpacking inspection and Fission restoration
- capture_network_traffic: Captures live ingress/egress network packets to PCAP with protocol telemetry
- generate_seccomp_profile: Generates Docker/OCI and systemd Seccomp syscall filtering profiles
"""

from __future__ import annotations

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class DynamicToolsPlugin(Plugin):
    """Plugin for runtime dynamic analysis, memory dumping, network capture, and sandboxing tools."""

    @property
    def name(self) -> str:
        return "dynamic_tools"

    @property
    def description(self) -> str:
        return (
            "Runtime dynamic analysis tools including sandbox execution tracing, "
            "memory dumping, PCAP traffic capture, and Seccomp sandbox policies."
        )

    def register(self, mcp_server: Any) -> None:
        """Register dynamic analysis tools."""
        from reversecore_mcp.tools.dynamic.memory_dumper import dump_process_memory
        from reversecore_mcp.tools.dynamic.network_capture import capture_network_traffic
        from reversecore_mcp.tools.dynamic.sandbox_tracer import trace_execution
        from reversecore_mcp.tools.dynamic.seccomp_profiles import generate_seccomp_profile

        mcp_server.tool(trace_execution)
        mcp_server.tool(dump_process_memory)
        mcp_server.tool(capture_network_traffic)
        mcp_server.tool(generate_seccomp_profile)

        logger.info(f"Registered {self.name} plugin with 4 dynamic analysis tools")


__all__ = ["DynamicToolsPlugin"]
