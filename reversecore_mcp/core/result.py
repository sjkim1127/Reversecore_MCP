"""Pydantic models for structured tool results."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel
from typing_extensions import NotRequired

# NextToolHint is defined here to avoid circular imports with core.next_tool_hints
NextToolHint = dict[str, Any]
"""Schema: {tool: str, reason: str, confidence: str, suggested_args: dict, priority: int}"""


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


class PaginationMeta(BaseModel):
    """Metadata describing pagination and bounding status."""

    has_more: bool = False
    next_cursor: str | None = None
    total_items: int | None = None
    page: int = 1
    page_size: int = 100
    truncated: bool = False


class ToolSuccess(BaseModel):
    """Represents a successful tool invocation."""

    status: Literal["success"] = "success"
    data: Any
    metadata: dict[str, Any] | None = None
    pagination: PaginationMeta | None = None
    recommended_next_tools: list[NextToolHint] | None = None
    """Optional list of next-step tool hints for AI clients.

    Each hint has: tool, reason, confidence (high/medium/low),
    suggested_args, priority (1=highest).
    """


class ToolError(BaseModel):
    """Represents a failed tool invocation."""

    status: Literal["error"] = "error"
    error_code: str
    message: str
    hint: str | None = None
    details: dict[str, Any] | None = None


ToolResult = ToolSuccess | ToolError


def success(
    data: Any,
    *,
    pagination: PaginationMeta | None = None,
    hints: list[NextToolHint] | None = None,
    **metadata: Any,
) -> ToolSuccess:
    """Create a ToolSuccess instance with optional metadata, pagination, and next-tool hints.

    Args:
        data: The primary result payload (string, dict, list, etc.).
        pagination: Optional PaginationMeta information for paginated/windowed responses.
        hints: Optional list of NextToolHint dicts to guide AI follow-up.
        **metadata: Additional key-value metadata attached to the result.
    """
    return ToolSuccess(
        data=data,
        metadata=metadata or None,
        pagination=pagination,
        recommended_next_tools=hints or None,
    )


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
