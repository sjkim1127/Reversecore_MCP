"""Pydantic models for structured tool results."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel
from typing_extensions import NotRequired


# TypedDict definitions for common tool result structures
class FunctionInfo(TypedDict):
    """Information about a function in a binary."""

    name: str
    address: str
    size: NotRequired[int]
    signature: NotRequired[str]
    callees: NotRequired[list[str]]
    callers: NotRequired[list[str]]


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
    sections: NotRequired[list[dict[str, Any]]]


class YaraRuleResult(TypedDict):
    """Result of YARA rule generation."""

    rule_name: str
    rule_content: str
    patterns_count: NotRequired[int]
    meta: NotRequired[dict[str, str]]


class ScanResult(TypedDict):
    """Result of a security scan."""

    findings: list[dict[str, Any]]
    severity: NotRequired[str]
    recommendations: NotRequired[list[str]]


class EmulationResult(TypedDict):
    """Result of code emulation."""

    final_registers: dict[str, Any]
    steps_executed: int
    status: str
    memory_writes: NotRequired[list[dict[str, Any]]]
    syscalls: NotRequired[list[str]]


class ErrorDetails(TypedDict, total=False):
    """Details for error responses."""

    max_size: int
    actual_size: int
    exception_type: str
    timeout_seconds: int


class ToolSuccess(BaseModel):
    """Represents a successful tool invocation."""

    status: Literal["success"] = "success"
    data: str | dict[str, Any]
    metadata: dict[str, Any] | None = None


class ToolError(BaseModel):
    """Represents a failed tool invocation."""

    status: Literal["error"] = "error"
    error_code: str
    message: str
    hint: str | None = None
    details: dict[str, Any] | None = None


ToolResult = ToolSuccess | ToolError


def success(data: str | dict[str, Any], **metadata: Any) -> ToolSuccess:
    """Create a ToolSuccess instance with optional metadata."""
    return ToolSuccess(data=data, metadata=metadata or None)


def failure(
    error_code: str,
    message: str,
    hint: str | None = None,
    **details: Any,
) -> ToolError:
    """Create a ToolError instance with optional hint/details."""
    return ToolError(
        error_code=error_code,
        message=message,
        hint=hint,
        details=details or None,
    )
