"""
Custom exception classes for Reversecore_MCP.

All exceptions inherit from ReversecoreError to allow for centralized
exception handling at the MCP server level.
"""


class ReversecoreError(Exception):
    """Base exception for all Reversecore_MCP errors."""

    error_code: str = "RCMCP-E000"
    error_type: str = "UNKNOWN_ERROR"

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        error_type: str | None = None,
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

    def __init__(self, message: str, details: dict | None = None):
        self.details = details or {}
        super().__init__(message, self.error_code, self.error_type)


class ToolExecutionError(ReversecoreError):
    """Raised when a tool execution fails."""

    error_code = "RCMCP-E005"
    error_type = "EXECUTION_ERROR"

    def __init__(self, message: str):
        super().__init__(message, self.error_code, self.error_type)


# ============================================================================
# Binary Analysis Exceptions
# ============================================================================


class BinaryAnalysisError(ReversecoreError):
    """Base exception for binary analysis operations."""

    error_code = "RCMCP-E100"
    error_type = "BINARY_ANALYSIS_ERROR"

    def __init__(
        self,
        message: str,
        binary_path: str | None = None,
        tool_name: str | None = None,
    ):
        self.binary_path = binary_path
        self.tool_name = tool_name
        super().__init__(message, self.error_code, self.error_type)


class DecompilationError(BinaryAnalysisError):
    """Raised when decompilation of a function fails."""

    error_code = "RCMCP-E101"
    error_type = "DECOMPILATION_ERROR"

    def __init__(
        self,
        message: str,
        function_address: str | None = None,
        binary_path: str | None = None,
        tool_name: str = "ghidra",
    ):
        self.function_address = function_address
        detailed_message = message
        if function_address:
            detailed_message = f"Failed to decompile function at {function_address}: {message}"
        super().__init__(detailed_message, binary_path, tool_name)


class DisassemblyError(BinaryAnalysisError):
    """Raised when disassembly of code fails."""

    error_code = "RCMCP-E102"
    error_type = "DISASSEMBLY_ERROR"

    def __init__(
        self,
        message: str,
        address: str | None = None,
        binary_path: str | None = None,
    ):
        self.address = address
        detailed_message = message
        if address:
            detailed_message = f"Failed to disassemble at {address}: {message}"
        super().__init__(detailed_message, binary_path, tool_name="radare2")


class StructureRecoveryError(BinaryAnalysisError):
    """Raised when structure recovery fails."""

    error_code = "RCMCP-E103"
    error_type = "STRUCTURE_RECOVERY_ERROR"

    def __init__(
        self,
        message: str,
        function_address: str | None = None,
        binary_path: str | None = None,
    ):
        self.function_address = function_address
        super().__init__(message, binary_path, tool_name="ghidra")


class SignatureGenerationError(BinaryAnalysisError):
    """Raised when YARA signature generation fails."""

    error_code = "RCMCP-E104"
    error_type = "SIGNATURE_GENERATION_ERROR"

    def __init__(
        self,
        message: str,
        address: str | None = None,
        binary_path: str | None = None,
    ):
        self.address = address
        super().__init__(message, binary_path, tool_name="radare2")


class EmulationError(BinaryAnalysisError):
    """Raised when code emulation fails."""

    error_code = "RCMCP-E105"
    error_type = "EMULATION_ERROR"

    def __init__(
        self,
        message: str,
        start_address: str | None = None,
        binary_path: str | None = None,
    ):
        self.start_address = start_address
        super().__init__(message, binary_path, tool_name="radare2")


# ============================================================================
# Tool-Specific Exceptions
# ============================================================================


class ToolTimeoutError(ReversecoreError):
    """Raised when a specific tool exceeds its timeout."""

    error_code = "RCMCP-E200"
    error_type = "TOOL_TIMEOUT_ERROR"

    def __init__(
        self,
        tool_name: str,
        timeout_seconds: int,
        operation: str | None = None,
    ):
        self.tool_name = tool_name
        self.timeout_seconds = timeout_seconds
        self.operation = operation
        if operation:
            message = f"{tool_name} timed out after {timeout_seconds}s during {operation}"
        else:
            message = f"{tool_name} timed out after {timeout_seconds} seconds"
        super().__init__(message, self.error_code, self.error_type)


class GhidraConnectionError(ReversecoreError):
    """Raised when connection to Ghidra server fails."""

    error_code = "RCMCP-E201"
    error_type = "GHIDRA_CONNECTION_ERROR"

    def __init__(self, message: str, host: str | None = None, port: int | None = None):
        self.host = host
        self.port = port
        detailed_message = message
        if host and port:
            detailed_message = f"Failed to connect to Ghidra at {host}:{port}: {message}"
        super().__init__(detailed_message, self.error_code, self.error_type)


class Radare2Error(ReversecoreError):
    """Raised when radare2 operation fails."""

    error_code = "RCMCP-E202"
    error_type = "RADARE2_ERROR"

    def __init__(
        self,
        message: str,
        command: str | None = None,
        binary_path: str | None = None,
    ):
        self.command = command
        self.binary_path = binary_path
        detailed_message = message
        if command:
            detailed_message = f"radare2 command '{command}' failed: {message}"
        super().__init__(detailed_message, self.error_code, self.error_type)


# ============================================================================
# Workspace & Security Exceptions
# ============================================================================


class WorkspaceError(ReversecoreError):
    """Raised when workspace operation fails."""

    error_code = "RCMCP-E300"
    error_type = "WORKSPACE_ERROR"

    def __init__(self, message: str, path: str | None = None):
        self.path = path
        super().__init__(message, self.error_code, self.error_type)


class SecurityViolationError(ReversecoreError):
    """Raised when a security policy is violated."""

    error_code = "RCMCP-E301"
    error_type = "SECURITY_VIOLATION"

    def __init__(self, message: str, attempted_path: str | None = None):
        self.attempted_path = attempted_path
        super().__init__(message, self.error_code, self.error_type)


class PathTraversalError(SecurityViolationError):
    """Raised when path traversal attack is detected."""

    error_code = "RCMCP-E302"
    error_type = "PATH_TRAVERSAL"

    def __init__(self, attempted_path: str):
        message = f"Path traversal detected: {attempted_path}"
        super().__init__(message, attempted_path)


# ============================================================================
# Transaction Exceptions
# ============================================================================


class TransactionError(ReversecoreError):
    """Base exception for transaction management errors."""

    error_code = "RCMCP-E700"
    error_type = "TRANSACTION_ERROR"


class NoActiveTransactionError(TransactionError):
    """Raised when an operation requires an active transaction but none exists."""

    error_code = "RCMCP-E701"
    error_type = "NO_ACTIVE_TRANSACTION"


class NonReversibleOperationError(TransactionError):
    """Raised when an unsupported or non-reversible operation is attempted inside a strict transaction."""

    error_code = "RCMCP-E702"
    error_type = "NON_REVERSIBLE_OPERATION_REJECTED"
