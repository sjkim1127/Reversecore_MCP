"""
CLI tool wrappers for Reversecore_MCP.

This module provides MCP tools that wrap common reverse engineering CLI tools
such as strings, radare2, etc.
"""

import subprocess
import time
from pathlib import Path

from fastmcp import FastMCP

from reversecore_mcp.core.error_formatting import format_error, get_validation_hint
from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ReversecoreError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.execution import execute_subprocess_streaming
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.security import sanitize_command_string, validate_file_path

logger = get_logger(__name__)


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
    start_time = time.time()
    file_name = Path(file_path).name
    
    logger.info(
        "Starting run_file",
        extra={"tool_name": "run_file", "file_name": file_name},
    )
    
    try:
        # Validate file path
        validated_path = validate_file_path(file_path)

        # Build command: file <file_path>
        cmd = ["file", validated_path]

        # Execute with streaming (small output expected, so default max_output_size is fine)
        output, bytes_read = execute_subprocess_streaming(
            cmd, max_output_size=1_000_000, timeout=timeout
        )

        execution_time = int((time.time() - start_time) * 1000)
        logger.info(
            "run_file completed successfully",
            extra={
                "tool_name": "run_file",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
        )

        return output.strip()

    except (ToolNotFoundError, ExecutionTimeoutError, ValidationError) as e:
        execution_time = int((time.time() - start_time) * 1000)
        hint = get_validation_hint(e) if isinstance(e, ValidationError) else None
        logger.warning(
            "run_file failed",
            extra={
                "tool_name": "run_file",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "error_code": e.error_code if hasattr(e, "error_code") else None,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_file", hint=hint)
    except ValueError as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.warning(
            "run_file validation failed",
            extra={
                "tool_name": "run_file",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_file", hint=get_validation_hint(e))
    except subprocess.CalledProcessError as e:
        execution_time = int((time.time() - start_time) * 1000)
        stderr = e.stderr if e.stderr else "Unknown error"
        logger.error(
            "run_file command failed",
            extra={
                "tool_name": "run_file",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "exit_code": e.returncode,
            },
            exc_info=True,
        )
        error_msg = f"Command failed with exit code {e.returncode}. stderr: {stderr}"
        return format_error(Exception(error_msg), tool_name="run_file")
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.error(
            "run_file unexpected error",
            extra={
                "tool_name": "run_file",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_file")


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
    start_time = time.time()
    file_name = Path(file_path).name
    
    logger.info(
        "Starting run_strings",
        extra={"tool_name": "run_strings", "file_name": file_name},
    )
    
    try:
        # Validate file path
        validated_path = validate_file_path(file_path)

        # Build command: strings -n <min_length> <file_path>
        cmd = ["strings", "-n", str(min_length), validated_path]

        # Execute with streaming
        output, bytes_read = execute_subprocess_streaming(
            cmd, max_output_size=max_output_size, timeout=timeout
        )

        execution_time = int((time.time() - start_time) * 1000)
        logger.info(
            "run_strings completed successfully",
            extra={
                "tool_name": "run_strings",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
        )

        return output

    except (ToolNotFoundError, ExecutionTimeoutError, ValidationError) as e:
        execution_time = int((time.time() - start_time) * 1000)
        hint = get_validation_hint(e) if isinstance(e, ValidationError) else None
        logger.warning(
            "run_strings failed",
            extra={
                "tool_name": "run_strings",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "error_code": e.error_code if hasattr(e, "error_code") else None,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_strings", hint=hint)
    except ValueError as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.warning(
            "run_strings validation failed",
            extra={
                "tool_name": "run_strings",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_strings", hint=get_validation_hint(e))
    except subprocess.CalledProcessError as e:
        execution_time = int((time.time() - start_time) * 1000)
        stderr = e.stderr if e.stderr else "Unknown error"
        logger.error(
            "run_strings command failed",
            extra={
                "tool_name": "run_strings",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "exit_code": e.returncode,
            },
            exc_info=True,
        )
        error_msg = f"Command failed with exit code {e.returncode}. stderr: {stderr}"
        return format_error(Exception(error_msg), tool_name="run_strings")
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.error(
            "run_strings unexpected error",
            extra={
                "tool_name": "run_strings",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_strings")


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
    start_time = time.time()
    file_name = Path(file_path).name
    
    logger.info(
        "Starting run_radare2",
        extra={"tool_name": "run_radare2", "file_name": file_name},
    )
    
    try:
        # Validate file path
        validated_path = validate_file_path(file_path)

        # Basic validation of r2_command (non-empty)
        sanitized_cmd = sanitize_command_string(r2_command)

        # Build command: r2 -q -c "<command>" <file_path>
        # Note: We pass r2_command as a single argument to -c flag
        # r2 expects: r2 -q -c "pdf @ main" file.exe
        cmd = ["r2", "-q", "-c", sanitized_cmd, validated_path]

        # Execute with streaming
        output, bytes_read = execute_subprocess_streaming(
            cmd, max_output_size=max_output_size, timeout=timeout
        )

        execution_time = int((time.time() - start_time) * 1000)
        logger.info(
            "run_radare2 completed successfully",
            extra={
                "tool_name": "run_radare2",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
        )

        return output

    except (ToolNotFoundError, ExecutionTimeoutError, ValidationError) as e:
        execution_time = int((time.time() - start_time) * 1000)
        hint = get_validation_hint(e) if isinstance(e, ValidationError) else None
        logger.warning(
            "run_radare2 failed",
            extra={
                "tool_name": "run_radare2",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "error_code": e.error_code if hasattr(e, "error_code") else None,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_radare2", hint=hint)
    except ValueError as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.warning(
            "run_radare2 validation failed",
            extra={
                "tool_name": "run_radare2",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_radare2", hint=get_validation_hint(e))
    except subprocess.CalledProcessError as e:
        execution_time = int((time.time() - start_time) * 1000)
        stderr = e.stderr if e.stderr else "Unknown error"
        logger.error(
            "run_radare2 command failed",
            extra={
                "tool_name": "run_radare2",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "exit_code": e.returncode,
            },
            exc_info=True,
        )
        error_msg = f"Command failed with exit code {e.returncode}. stderr: {stderr}"
        return format_error(Exception(error_msg), tool_name="run_radare2")
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.error(
            "run_radare2 unexpected error",
            extra={
                "tool_name": "run_radare2",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_radare2")


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
    start_time = time.time()
    file_name = Path(file_path).name
    
    logger.info(
        "Starting run_binwalk",
        extra={"tool_name": "run_binwalk", "file_name": file_name},
    )
    
    try:
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

        execution_time = int((time.time() - start_time) * 1000)
        logger.info(
            "run_binwalk completed successfully",
            extra={
                "tool_name": "run_binwalk",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
        )

        return output

    except (ToolNotFoundError, ExecutionTimeoutError, ValidationError) as e:
        execution_time = int((time.time() - start_time) * 1000)
        hint = get_validation_hint(e) if isinstance(e, ValidationError) else None
        logger.warning(
            "run_binwalk failed",
            extra={
                "tool_name": "run_binwalk",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "error_code": e.error_code if hasattr(e, "error_code") else None,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_binwalk", hint=hint)
    except ValueError as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.warning(
            "run_binwalk validation failed",
            extra={
                "tool_name": "run_binwalk",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_binwalk", hint=get_validation_hint(e))
    except subprocess.CalledProcessError as e:
        execution_time = int((time.time() - start_time) * 1000)
        stderr = e.stderr if e.stderr else "Unknown error"
        logger.error(
            "run_binwalk command failed",
            extra={
                "tool_name": "run_binwalk",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "exit_code": e.returncode,
            },
            exc_info=True,
        )
        error_msg = f"Command failed with exit code {e.returncode}. stderr: {stderr}"
        return format_error(Exception(error_msg), tool_name="run_binwalk")
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.error(
            "run_binwalk unexpected error",
            extra={
                "tool_name": "run_binwalk",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_binwalk")

