"""CLI tool wrappers that return structured ToolResult payloads."""

from fastmcp import FastMCP

from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_streaming
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters


def register_cli_tools(mcp: FastMCP) -> None:
    """
    Register all CLI tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_file)
    mcp.tool(run_strings)
    mcp.tool(run_radare2)
    mcp.tool(run_binwalk)


@log_execution(tool_name="run_file")
@track_metrics("run_file")
@handle_tool_errors
def run_file(file_path: str, timeout: int = 30) -> ToolResult:
    """Identify file metadata using the ``file`` CLI utility."""

    validated_path = validate_file_path(file_path)
    cmd = ["file", str(validated_path)]
    output, bytes_read = execute_subprocess_streaming(
        cmd,
        max_output_size=1_000_000,
        timeout=timeout,
    )
    return success(output.strip(), bytes_read=bytes_read)


@log_execution(tool_name="run_strings")
@track_metrics("run_strings")
@handle_tool_errors
def run_strings(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Extract printable strings using the ``strings`` CLI."""

    validate_tool_parameters(
        "run_strings",
        {"min_length": min_length, "max_output_size": max_output_size},
    )
    validated_path = validate_file_path(file_path)
    cmd = ["strings", "-n", str(min_length), str(validated_path)]
    output, bytes_read = execute_subprocess_streaming(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_radare2")
@track_metrics("run_radare2")
@handle_tool_errors
def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Execute vetted radare2 commands for binary triage."""

    validate_tool_parameters("run_radare2", {"r2_command": r2_command})
    validated_path = validate_file_path(file_path)
    validated_command = validate_r2_command(r2_command)
    cmd = ["r2", "-q", "-c", validated_command, str(validated_path)]
    output, bytes_read = execute_subprocess_streaming(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_binwalk")
@track_metrics("run_binwalk")
@handle_tool_errors
def run_binwalk(
    file_path: str,
    depth: int = 8,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Analyze binaries for embedded content using binwalk."""

    validated_path = validate_file_path(file_path)
    cmd = ["binwalk", "-A", "-d", str(depth), str(validated_path)]
    output, bytes_read = execute_subprocess_streaming(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)

