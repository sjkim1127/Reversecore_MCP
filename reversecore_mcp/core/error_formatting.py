"""
Error formatting utilities for structured error responses.
"""

import os
from typing import Any, Dict

from reversecore_mcp.core.exceptions import ReversecoreError


def format_error(
    error: Exception, tool_name: str = None, hint: str = None
) -> str | Dict[str, Any]:
    """
    Format an error as string or structured JSON based on environment variable.

    Args:
        error: The exception to format
        tool_name: Name of the tool that raised the error
        hint: Optional hint message for resolving the error

    Returns:
        Error message as string (default) or structured dict (if STRUCTURED_ERRORS=true)
    """
    # Check if structured errors are enabled
    structured = os.environ.get("STRUCTURED_ERRORS", "false").lower() == "true"

    if isinstance(error, ReversecoreError):
        error_code = error.error_code
        error_type = error.error_type
        message = error.message
        details = {}

        # Add exception-specific details
        if hasattr(error, "tool_name"):
            details["tool_name"] = error.tool_name
        if hasattr(error, "timeout_seconds"):
            details["timeout_seconds"] = error.timeout_seconds
        if hasattr(error, "max_size"):
            details["max_size"] = error.max_size
        if hasattr(error, "actual_size"):
            details["actual_size"] = error.actual_size
        if hasattr(error, "details"):
            details.update(error.details)
    else:
        # Generic error
        error_code = "RCMCP-E000"
        error_type = "SYSTEM_ERROR"
        message = str(error)
        details = {"exception_type": type(error).__name__}

    if tool_name:
        details["tool_name"] = tool_name

    if structured:
        # Return structured JSON format
        result: Dict[str, Any] = {
            "error_code": error_code,
            "error_type": error_type,
            "message": message,
            "details": details,
        }
        if hint:
            result["hint"] = hint
        return result
    else:
        # Return simple string format (backward compatible)
        error_str = f"Error: {message}"
        if hint:
            error_str += f" Hint: {hint}"
        return error_str


def get_validation_hint(error: ValueError) -> str:
    """
    Generate a helpful hint message for validation errors.

    Args:
        error: The ValueError exception

    Returns:
        Hint message string
    """
    error_msg = str(error).lower()

    if "outside" in error_msg or "workspace" in error_msg:
        return "Ensure the file is in the allowed workspace directory. Set REVERSECORE_WORKSPACE environment variable to change the workspace path."
    elif "does not point to a file" in error_msg:
        return "The specified path points to a directory, not a file. Please provide a file path."
    elif "invalid file path" in error_msg:
        return "The file path is invalid or the file does not exist. Please check the path and try again."
    else:
        return "Please check the input and try again."

