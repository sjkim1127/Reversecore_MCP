"""Shared error handling utilities for tool wrappers."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import TypeVar

from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., ToolResult])


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
        return failure("TOOL_NOT_FOUND", str(exc), hint=hint)

    if isinstance(exc, ExecutionTimeoutError):
        return failure(
            "TIMEOUT",
            f"Command timed out after {exc.timeout_seconds} seconds",
            timeout_seconds=exc.timeout_seconds,
        )

    if isinstance(exc, OutputLimitExceededError):
        return failure(
            "OUTPUT_LIMIT",
            str(exc),
            hint="Reduce output size or increase the limit",
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
            details=exc.details,
        )

    # Generic exception handler
    logger.exception("Unexpected error in tool '%s'", tool_name)
    return failure(
        "INTERNAL_ERROR",
        f"{tool_name} failed: {exc}",
        exception_type=exc.__class__.__name__,
    )


def handle_tool_errors(func: F) -> F:
    """Wrap a tool function to convert common exceptions into ToolResult failures.

    Works with both sync and async functions, using _handle_exception for
    centralized error handling logic.
    """
    import inspect

    is_async = inspect.iscoroutinefunction(func)

    if is_async:

        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> ToolResult:
            try:
                return await func(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - we intentionally coerce to ToolResult
                return _handle_exception(exc, func.__name__)

        return async_wrapper  # type: ignore[return-value]

    @wraps(func)
    def wrapper(*args, **kwargs) -> ToolResult:
        try:
            return func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - we intentionally coerce to ToolResult
            return _handle_exception(exc, func.__name__)

    return wrapper  # type: ignore[return-value]
