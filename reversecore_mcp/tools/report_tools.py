"""
Report Tools module - Backward compatibility alias.

This module was moved to report/report_tools.
"""

# Re-export everything from report.report_tools
from reversecore_mcp.tools.report.report_tools import *  # noqa: F403
from reversecore_mcp.tools.report.report_tools import ReportTools

__all__ = ["ReportTools"]
