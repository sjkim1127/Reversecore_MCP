import reversecore_mcp.tools.report.report_tools as common_module
import reversecore_mcp.tools.report_tools as alias_module


def test_report_tools_alias_exports():
    # Verify ReportTools class is correctly exported and identical
    assert alias_module.ReportTools == common_module.ReportTools
    assert "ReportTools" in alias_module.__all__
