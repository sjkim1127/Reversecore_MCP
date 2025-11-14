"""
CLI tool wrappers for Reversecore_MCP.

This module provides MCP tools that wrap common reverse engineering CLI tools
such as strings, radare2, etc.
"""


from fastmcp import FastMCP

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.execution import execute_subprocess_streaming
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.command_spec import validate_r2_command
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
def run_file(file_path: str, timeout: int = 30) -> str:
    """
    Identify the type of a file using the file command.

    This tool runs the 'file' command on the specified file and returns
    information about the file type, encoding, and other metadata.
    Useful for initial file identification and triage.

    Args:
        file_path: Path to the file to identify
        timeout: Maximum execution time in seconds (default: 30)

    Returns:
        File type information as a string. May be truncated if output exceeds
        max_output_size.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    # Validate file path
    validated_path = validate_file_path(file_path)

    # Build command: file <file_path>
    cmd = ["file", validated_path]

    # Execute with streaming (small output expected, so default max_output_size is fine)
    output, bytes_read = execute_subprocess_streaming(
        cmd, max_output_size=1_000_000, timeout=timeout
    )

    return output.strip()


@log_execution(tool_name="run_strings")
@track_metrics("run_strings")
def run_strings(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> str:
    """
    Extract printable strings from a binary file using the strings command.

    This tool runs the 'strings' command on the specified file and returns
    all printable strings found. Useful for initial triage and finding
    interesting text in binaries.

    Args:
        file_path: Path to the binary file to analyze
        min_length: Minimum string length to extract (default: 4)
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Maximum execution time in seconds (default: 300)

    Returns:
        Extracted strings, one per line. May be truncated if output exceeds
        max_output_size.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    # Validate parameters
    validate_tool_parameters("run_strings", {
        "min_length": min_length,
        "max_output_size": max_output_size
    })
    
    # Validate file path
    validated_path = validate_file_path(file_path)

    # Build command: strings -n <min_length> <file_path>
    cmd = ["strings", "-n", str(min_length), validated_path]

    # Execute with streaming
    output, bytes_read = execute_subprocess_streaming(
        cmd, max_output_size=max_output_size, timeout=timeout
    )

    return output


@log_execution(tool_name="run_radare2")
@track_metrics("run_radare2")
def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> str:
    """
    Execute a radare2 command on a binary file.

    This tool opens a file in radare2 and executes the specified command.
    Useful for disassembly, analysis, and various radare2 operations.

    Args:
        file_path: Path to the binary file to analyze
        r2_command: Radare2 command to execute (e.g., "pdf @ main", "afl", "iS")
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Maximum execution time in seconds (default: 300)

    Returns:
        Output from the radare2 command. May be truncated if output exceeds
        max_output_size.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    # Validate parameters
    validate_tool_parameters("run_radare2", {"r2_command": r2_command})
    
    # Validate file path
    validated_path = validate_file_path(file_path)

    # Validate r2_command with strict regex-based validation
    # This prevents command injection attacks like "pdf @ main; w hello"
    validate_r2_command(r2_command)

    # Build command: r2 -q -c "<command>" <file_path>
    # Note: We pass r2_command as a single argument to -c flag
    # r2 expects: r2 -q -c "pdf @ main" file.exe
    cmd = ["r2", "-q", "-c", r2_command, validated_path]

    # Execute with streaming
    output, bytes_read = execute_subprocess_streaming(
        cmd, max_output_size=max_output_size, timeout=timeout
    )

    return output


@log_execution(tool_name="run_binwalk")
@track_metrics("run_binwalk")
def run_binwalk(
    file_path: str,
    depth: int = 8,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> str:
    """
    Analyze a file for embedded files and signatures using binwalk.

    This tool runs binwalk analysis on the specified file to identify
    embedded files, compression signatures, and other file system structures.
    Useful for firmware analysis and file carving.

    Note: File extraction is disabled in v1.0 for security reasons (disk-fill
    attack prevention). Only analysis mode is supported.

    Args:
        file_path: Path to the file to analyze
        depth: Maximum recursion depth for signature scanning (default: 8)
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Maximum execution time in seconds (default: 300)

    Returns:
        Binwalk analysis results showing detected signatures and embedded files.
        May be truncated if output exceeds max_output_size.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    # Validate file path
    validated_path = validate_file_path(file_path)

    # Build command: binwalk -A -d <depth> <file_path>
    # Note: -e (extract) is NOT used in v1.0 for security reasons
    # -A: Displays ASCII strings in addition to signatures
    # -d <depth>: Maximum recursion depth
    cmd = ["binwalk", "-A", "-d", str(depth), validated_path]

    # Execute with streaming
    output, bytes_read = execute_subprocess_streaming(
        cmd, max_output_size=max_output_size, timeout=timeout
    )

    return output

