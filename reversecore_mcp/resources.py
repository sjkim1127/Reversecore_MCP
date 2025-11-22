from fastmcp import FastMCP
from pathlib import Path

# Resources 폴더 경로 (AI용 데이터)
RESOURCES_PATH = Path("/app/resources")

def register_resources(mcp: FastMCP):
    """Register MCP resources for AI agents."""

    @mcp.resource("reversecore://guide")
    def get_guide() -> str:
        """Reversecore MCP Tool Usage Guide"""
        guide_path = RESOURCES_PATH / "FILE_COPY_TOOL_GUIDE.md"
        if guide_path.exists():
            return guide_path.read_text(encoding="utf-8")
        return "Guide not found."

    @mcp.resource("reversecore://guide/structures")
    def get_structure_guide() -> str:
        """Structure Recovery and Cross-Reference Analysis Technical Guide"""
        doc_path = RESOURCES_PATH / "XREFS_AND_STRUCTURES_IMPLEMENTATION.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Documentation not found."

    @mcp.resource("reversecore://logs")
    def get_logs() -> str:
        """Application logs (last 100 lines)"""
        log_file = Path("/var/log/reversecore/app.log")
        if log_file.exists():
            try:
                lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
                return "\n".join(lines[-100:])
            except Exception as e:
                return f"Error reading logs: {e}"
        return "No logs found."
