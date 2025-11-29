"""Pydantic models for structured tool results."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel

try:
    from typing import TypedDict, NotRequired
except ImportError:
    from typing_extensions import TypedDict, NotRequired


# TypedDict definitions for common tool result structures
class FunctionInfo(TypedDict):
    """Information about a function in a binary."""
    name: str
    address: str
    size: NotRequired[int]
    signature: NotRequired[str]
    callees: NotRequired[List[str]]
    callers: NotRequired[List[str]]


class DisassemblyResult(TypedDict):
    """Result of disassembly operation."""
    address: str
    mnemonic: str
    operands: str
    bytes: NotRequired[str]
    comment: NotRequired[str]


class DecompilationResult(TypedDict):
    """Result of decompilation operation."""
    function_name: str
    source_code: str
    decompiler: NotRequired[str]
    address: NotRequired[str]


class BinaryMetadata(TypedDict):
    """Metadata about a binary file."""
    file_path: str
    file_size: int
    file_type: str
    architecture: NotRequired[str]
    endianness: NotRequired[str]
    entry_point: NotRequired[str]
    sections: NotRequired[List[Dict[str, Any]]]


class YaraRuleResult(TypedDict):
    """Result of YARA rule generation."""
    rule_name: str
    rule_content: str
    patterns_count: NotRequired[int]
    meta: NotRequired[Dict[str, str]]


class ScanResult(TypedDict):
    """Result of a security scan."""
    findings: List[Dict[str, Any]]
    severity: NotRequired[str]
    recommendations: NotRequired[List[str]]


class EmulationResult(TypedDict):
    """Result of code emulation."""
    final_registers: Dict[str, Any]
    steps_executed: int
    status: str
    memory_writes: NotRequired[List[Dict[str, Any]]]
    syscalls: NotRequired[List[str]]


class ErrorDetails(TypedDict, total=False):
    """Details for error responses."""
    max_size: int
    actual_size: int
    exception_type: str
    timeout_seconds: int


class ToolSuccess(BaseModel):
    """Represents a successful tool invocation."""

    status: Literal["success"] = "success"
    data: Union[str, Dict[str, Any]]
    metadata: Optional[Dict[str, Any]] = None


class ToolError(BaseModel):
    """Represents a failed tool invocation."""

    status: Literal["error"] = "error"
    error_code: str
    message: str
    hint: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


ToolResult = Union[ToolSuccess, ToolError]


def success(data: Union[str, Dict[str, Any]], **metadata: Any) -> ToolSuccess:
    """Create a ToolSuccess instance with optional metadata."""
    return ToolSuccess(data=data, metadata=metadata or None)


def failure(
    error_code: str,
    message: str,
    hint: Optional[str] = None,
    **details: Any,
) -> ToolError:
    """Create a ToolError instance with optional hint/details."""
    return ToolError(
        error_code=error_code,
        message=message,
        hint=hint,
        details=details or None,
    )
