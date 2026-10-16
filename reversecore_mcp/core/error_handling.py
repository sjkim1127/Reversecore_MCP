"""Shared error handling utilities for tool wrappers."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast, overload

from reversecore_mcp.core.exceptions import (
    CaseNotFoundError,
    EmulationError,
    ExecutionTimeoutError,
    InvalidPhaseTransitionError,
    OutputLimitExceededError,
    SampleHashMismatchError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _handle_exception(exc: Exception, tool_name: str) -> ToolResult:
    """Convert common exceptions into ToolResult failures.

    This is the centralized exception handler that eliminates code duplication
    between sync and async wrappers.

    Args:
        exc: The exception to handle
        tool_name: Name of the tool that raised the exception

    Returns:
        ToolResult with appropriate error code and message
    """
    if isinstance(exc, ToolNotFoundError):
        hint = f"Install with: apt-get install {exc.tool_name}"
        return failure(
            "TOOL_NOT_FOUND",
            str(exc),
            hint=hint,
            retryable=False,
            recovery_hint=f"Required tool '{exc.tool_name}' is missing. Install it on host PATH or execute inside the official Docker container.",
        )

    if isinstance(exc, ExecutionTimeoutError):
        return failure(
            "TIMEOUT",
            f"Command timed out after {exc.timeout_seconds} seconds",
            hint="Retry with a smaller binary scope, specific function address, or increase timeout.",
            retryable=True,
            recovery_hint="Operation timed out. Retry the analysis targeting a specific function address, increase tool_timeout, or analyze a smaller scope.",
            timeout_seconds=exc.timeout_seconds,
        )

    if isinstance(exc, OutputLimitExceededError):
        return failure(
            "OUTPUT_LIMIT",
            str(exc),
            hint="Reduce output size or increase the limit",
            retryable=False,
            recovery_hint="Output size exceeded buffer limits. Use pagination parameters (e.g. page, page_size, limit) or narrower filter criteria.",
            details={
                "max_size": exc.max_size,
                "actual_size": exc.actual_size,
            },
        )

    if isinstance(exc, ValidationError):
        return failure(
            "VALIDATION_ERROR",
            str(exc),
            hint="Ensure the file is in the workspace directory",
            retryable=False,
            recovery_hint="Input parameter validation failed. Ensure the target path exists and resolves strictly within the authorized workspace.",
            details=exc.details,
        )

    if isinstance(exc, EmulationError):
        return failure(
            "EMULATION_ERROR",
            str(exc),
            hint="Ensure Qiling is installed and the target binary is supported.",
            retryable=False,
            recovery_hint="Emulation failed. Verify CPU architecture, rootfs availability, and executable format compatibility.",
        )

    if isinstance(exc, SampleHashMismatchError):
        return failure(
            "SAMPLE_HASH_MISMATCH",
            str(exc),
            hint="Target file SHA-256 does not match case state. Ensure you are targeting the correct sample.",
            retryable=False,
            recovery_hint="The target binary hash differs from the case's bound sample. Resume with the original binary or create a new case for this file.",
            details={
                "case_id": exc.case_id,
                "expected_hash": exc.expected_hash,
                "actual_hash": exc.actual_hash,
                "sample_path": exc.sample_path,
            },
        )

    if isinstance(exc, CaseNotFoundError):
        return failure(
            "CASE_NOT_FOUND",
            str(exc),
            hint="Use list_case_states to see available cases or create_case_state to start a new case.",
            retryable=False,
            recovery_hint="The specified case ID does not exist. Call list_case_states to discover active cases or initialize a new case with create_case_state.",
            details={"case_id": exc.case_id},
        )

    if isinstance(exc, InvalidPhaseTransitionError):
        return failure(
            "INVALID_PHASE_TRANSITION",
            str(exc),
            hint="Use force_phase=True if you intentionally wish to step backward or bypass intermediate phases.",
            retryable=False,
            recovery_hint="Phase transition violates sequential workflow. Pass force_phase=True to override, or advance through normal progression.",
            details={"current_phase": exc.current_phase, "target_phase": exc.target_phase},
        )

    # Generic exception handler
    logger.exception("Unexpected error in tool '%s'", tool_name)
    return failure(
        "INTERNAL_ERROR",
        f"{tool_name} failed: {exc}",
        hint="Check tool logs or run with mock/triage tools.",
        retryable=False,
        recovery_hint="An unexpected analysis failure occurred. Inspect the server log or run an alternative static scan.",
        exception_type=exc.__class__.__name__,
    )


@overload
def handle_tool_errors(
    func: None = None, *, max_retries: int = 0, backoff: float = 0.5
) -> Callable[[F], F]: ...


@overload
def handle_tool_errors(func: F, *, max_retries: int = 0, backoff: float = 0.5) -> F: ...


def handle_tool_errors(func: F | None = None, *, max_retries: int = 0, backoff: float = 0.5) -> Any:
    """
    Wrap a tool function to handle errors and optionally retry on failure.

    Supports usage as both:
    @handle_tool_errors
    def my_tool(): ...

    and:
    @handle_tool_errors(max_retries=3)
    def my_tool(): ...
    """
    import asyncio
    import inspect
    import time

    def decorator(f: F) -> F:
        is_async = inspect.iscoroutinefunction(f)
        tool_name = f.__name__

        if is_async:

            @wraps(f)
            async def async_wrapper(*args: Any, **kwargs: Any) -> ToolResult:
                last_exception = None
                for attempt in range(max_retries + 1):
                    try:
                        return cast(ToolResult, await f(*args, **kwargs))
                    except Exception as exc:
                        last_exception = exc
                        if attempt < max_retries:
                            wait_time = backoff * (2**attempt)
                            logger.warning(
                                f"Tool '{tool_name}' failed (attempt {attempt + 1}/{max_retries + 1}). "
                                f"Retrying in {wait_time:.1f}s. Error: {exc}"
                            )
                            await asyncio.sleep(wait_time)
                        else:
                            # Final attempt failed
                            (
                                f"Failed after {max_retries + 1} attempts"
                                if max_retries > 0
                                else None
                            )
                            return _handle_exception(exc, tool_name)
                # Should not reach here
                if last_exception is None:
                    last_exception = Exception("Unknown tool execution failure")
                return _handle_exception(last_exception, tool_name)

            return cast(F, async_wrapper)

        else:

            @wraps(f)
            def sync_wrapper(*args: Any, **kwargs: Any) -> ToolResult:
                last_exception = None
                for attempt in range(max_retries + 1):
                    try:
                        return cast(ToolResult, f(*args, **kwargs))
                    except Exception as exc:
                        last_exception = exc
                        if attempt < max_retries:
                            wait_time = backoff * (2**attempt)
                            logger.warning(
                                f"Tool '{tool_name}' failed (attempt {attempt + 1}/{max_retries + 1}). "
                                f"Retrying in {wait_time:.1f}s. Error: {exc}"
                            )
                            time.sleep(wait_time)
                        else:
                            return _handle_exception(exc, tool_name)
                if last_exception is None:
                    last_exception = Exception("Unknown tool execution failure")
                return _handle_exception(last_exception, tool_name)

            return cast(F, sync_wrapper)

    if func is None:
        return decorator
    return decorator(func)
