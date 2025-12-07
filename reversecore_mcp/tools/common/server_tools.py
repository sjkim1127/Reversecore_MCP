
"""
Server tools for health checks, metrics, and monitoring.
"""

import os
import resource
import time
from typing import Any

from fastmcp import FastMCP

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import metrics_collector
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.core.result import ToolResult, success

logger = get_logger(__name__)

# Record module load time as approximate server start time
SERVER_START_TIME = time.time()


class ServerToolsPlugin(Plugin):
    """Plugin for server management and monitoring tools."""

    @property
    def name(self) -> str:
        return "server_tools"

    @property
    def description(self) -> str:
        return "Tools for server health checks, metrics, and monitoring."

    def register(self, mcp: FastMCP) -> None:
        """Register server tools."""

        @mcp.tool()
        async def get_server_health() -> ToolResult:
            """
            Get the current health status and resource usage of the MCP server.
            
            Use this to monitor the server's uptime, memory consumption,
            and tool execution statistics.
            
            Returns:
                ToolResult containing:
                - uptime_seconds: Server uptime
                - memory_usage_mb: Current memory usage in MB
                - status: 'healthy' or 'degraded'
                - tool_stats: Summary of tool execution success/failure
            """
            uptime = time.time() - SERVER_START_TIME
            
            # Memory usage (RSS)
            # getrusage returns kilobytes on Linux, bytes on macOS
            usage = resource.getrusage(resource.RUSAGE_SELF)
            memory_mb = usage.ru_maxrss / 1024
            if os.uname().sysname == "Darwin":
                # macOS returns bytes
                memory_mb = usage.ru_maxrss / (1024 * 1024)

            # Metrics summary
            metrics = metrics_collector.get_metrics()
            tool_metrics = metrics.get("tools", {})
            
            total_calls = sum(m.get("calls", 0) for m in tool_metrics.values())
            total_errors = sum(m.get("errors", 0) for m in tool_metrics.values())
            
            # Determine status
            status = "healthy"
            if total_calls > 0 and (total_errors / total_calls) > 0.2:
                # If error rate > 20%, mark as degraded
                status = "degraded"
                
            return success({
                "status": status,
                "uptime_seconds": round(uptime, 2),
                "uptime_formatted": _format_uptime(uptime),
                "memory_usage_mb": round(memory_mb, 2),
                "total_calls": total_calls,
                "total_errors": total_errors,
                "error_rate": f"{(total_errors/total_calls)*100:.1f}%" if total_calls > 0 else "0.0%",
                "active_tools": len(tool_metrics)
            })

        @mcp.tool()
        async def get_tool_metrics(tool_name: str = None) -> ToolResult:
            """
            Get detailed execution metrics for specific or all tools.
            
            Args:
                tool_name: Optional tool name to filter results
            
            Returns:
                Detailed metrics including execution times, call counts, and error rates.
            """
            metrics = metrics_collector.get_metrics()
            tools = metrics.get("tools", {})
            
            if tool_name:
                if tool_name not in tools:
                    return success({}, message=f"No metrics found for tool '{tool_name}'")
                return success({tool_name: tools[tool_name]})
                
            # Return all
            return success(tools)

def _format_uptime(seconds: float) -> str:
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d > 0:
        return f"{int(d)}d {int(h)}h {int(m)}m"
    return f"{int(h)}h {int(m)}m {int(s)}s"
