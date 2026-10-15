"""Pydantic models for structured tool results."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel, model_validator
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


class ContinuationInfo(BaseModel):
    """Continuation parameters for retrieving remainder of truncated outputs."""

    offset: int
    length: int | None = None
    cursor: str | None = None


class TruncationMeta(BaseModel):
    """Structured truncation contract for bounded MCP tool outputs (Issue #326)."""

    truncated: bool = True
    returned_bytes: int
    total_captured_bytes: int
    saved_artifact: str | None = None
    continuation: ContinuationInfo | None = None


class ErrorInfo(BaseModel):
    """Machine-readable structured error contract for agent reasoning and recovery."""

    code: str
    message: str
    retryable: bool = False
    recovery_hint: str | None = None


class ToolSuccess(BaseModel):
    """Represents a successful tool invocation."""

    ok: Literal[True] = True
    status: Literal["success"] = "success"
    data: Any
    warnings: list[str] = []
    error: None = None
    meta: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None
    pagination: PaginationMeta | None = None
    truncation: TruncationMeta | None = None
    recommended_next_tools: list[NextToolHint] | None = None
    """Optional list of next-step tool hints for AI clients.

    Each hint has: tool, reason, confidence (high/medium/low),
    suggested_args, priority (1=highest).
    """


class ToolError(BaseModel):
    """Represents a failed tool invocation."""

    ok: Literal[False] = False
    status: Literal["error"] = "error"
    error_code: str
    message: str
    hint: str | None = None
    error: ErrorInfo | None = None
    warnings: list[str] = []
    details: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _ensure_error_info(self) -> ToolError:
        if self.error is None:
            self.error = ErrorInfo(
                code=self.error_code,
                message=self.message,
                retryable=False,
                recovery_hint=self.hint,
            )
        return self


ToolResult = ToolSuccess | ToolError


def success(
    data: Any,
    *,
    pagination: PaginationMeta | None = None,
    truncation: TruncationMeta | dict[str, Any] | None = None,
    hints: list[NextToolHint] | None = None,
    warnings: list[str] | None = None,
    meta: dict[str, Any] | None = None,
    **metadata: Any,
) -> ToolSuccess:
    """Create a ToolSuccess instance with optional metadata, pagination, and next-tool hints.

    Args:
        data: The primary result payload (string, dict, list, etc.).
        pagination: Optional PaginationMeta information for paginated/windowed responses.
        truncation: Optional TruncationMeta information for truncated outputs.
        hints: Optional list of NextToolHint dicts to guide AI follow-up.
        warnings: Optional list of non-fatal operational warnings.
        meta: Optional metadata dictionary.
        **metadata: Additional key-value metadata attached to the result.
    """
    eff_meta: dict[str, Any] = dict(meta or {})
    if metadata:
        eff_meta.update(metadata)

    eff_truncation: TruncationMeta | None = None
    if truncation is not None:
        if isinstance(truncation, dict):
            eff_truncation = TruncationMeta(**truncation)
        else:
            eff_truncation = truncation
    elif "truncation" in eff_meta and isinstance(eff_meta["truncation"], (dict, TruncationMeta)):
        raw_t = eff_meta.pop("truncation")
        eff_truncation = TruncationMeta(**raw_t) if isinstance(raw_t, dict) else raw_t

    return ToolSuccess(
        ok=True,
        status="success",
        data=data,
        warnings=warnings or [],
        error=None,
        meta=eff_meta or None,
        metadata=eff_meta or None,
        pagination=pagination,
        truncation=eff_truncation,
        recommended_next_tools=hints or None,
    )


def failure(
    error_code: str,
    message: str,
    hint: str | None = None,
    *,
    retryable: bool = False,
    recovery_hint: str | None = None,
    warnings: list[str] | None = None,
    **details: Any,
) -> ToolError:
    """Create a ToolError instance with structured error contract and recovery guidance."""
    eff_recovery_hint = recovery_hint or hint
    eff_hint = hint or recovery_hint
    error_obj = ErrorInfo(
        code=error_code,
        message=message,
        retryable=retryable,
        recovery_hint=eff_recovery_hint,
    )
    return ToolError(
        ok=False,
        status="error",
        error_code=error_code,
        message=message,
        hint=eff_hint,
        error=error_obj,
        warnings=warnings or [],
        details=details or None,
    )
