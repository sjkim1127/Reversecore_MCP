"""
Custom exception classes for Reversecore_MCP.

All exceptions inherit from ReversecoreError to allow for centralized
exception handling at the MCP server level.
"""

from typing import Optional


class ReversecoreError(Exception):
    """Base exception for all Reversecore_MCP errors."""

    error_code: str = "RCMCP-E000"
    error_type: str = "UNKNOWN_ERROR"

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        error_type: Optional[str] = None,
    ):
        self.message = message
        if error_code:
            self.error_code = error_code
        if error_type:
            self.error_type = error_type
        super().__init__(message)


class ToolNotFoundError(ReversecoreError):
    """Raised when a required CLI tool is not found in the system."""

    error_code = "RCMCP-E003"
    error_type = "TOOL_ERROR"

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        message = f"Tool '{tool_name}' not found. Please install it."
        super().__init__(message, self.error_code, self.error_type)


class ExecutionTimeoutError(ReversecoreError):
    """Raised when a subprocess execution exceeds the timeout limit."""

    error_code = "RCMCP-E002"
    error_type = "TIMEOUT_ERROR"

    def __init__(self, timeout_seconds: int):
        self.timeout_seconds = timeout_seconds
        message = f"Operation timed out after {timeout_seconds} seconds."
        super().__init__(message, self.error_code, self.error_type)


class OutputLimitExceededError(ReversecoreError):
    """Raised when subprocess output exceeds the maximum allowed size."""

    error_code = "RCMCP-E004"
    error_type = "OUTPUT_ERROR"

    def __init__(self, max_size: int, actual_size: int):
        self.max_size = max_size
        self.actual_size = actual_size
        message = (
            f"Output limit exceeded: {actual_size} bytes (max: {max_size} bytes). "
            "Output has been truncated."
        )
        super().__init__(message, self.error_code, self.error_type)


class ValidationError(ReversecoreError):
    """Raised when input validation fails."""

    error_code = "RCMCP-E001"
    error_type = "VALIDATION_ERROR"

    def __init__(self, message: str, details: Optional[dict] = None):
        self.details = details or {}
        super().__init__(message, self.error_code, self.error_type)


class ToolExecutionError(ReversecoreError):
    """Raised when a tool execution fails."""

    error_code = "RCMCP-E005"
    error_type = "EXECUTION_ERROR"

    def __init__(self, message: str):
        super().__init__(message, self.error_code, self.error_type)
