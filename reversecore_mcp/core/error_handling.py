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


def handle_tool_errors(func=None, *, max_retries: int = 0, backoff: float = 0.5) -> F:
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
            async def async_wrapper(*args, **kwargs) -> ToolResult:
                last_exception = None
                for attempt in range(max_retries + 1):
                    try:
                        return await f(*args, **kwargs)
                    except Exception as exc:
                        last_exception = exc
                        if attempt < max_retries:
                            wait_time = backoff * (2 ** attempt)
                            logger.warning(
                                f"Tool '{tool_name}' failed (attempt {attempt+1}/{max_retries+1}). "
                                f"Retrying in {wait_time:.1f}s. Error: {exc}"
                            )
                            await asyncio.sleep(wait_time)
                        else:
                            # Final attempt failed
                            msg = f"Failed after {max_retries+1} attempts" if max_retries > 0 else None
                            return _handle_exception(exc, tool_name)
                # Should not reach here
                return _handle_exception(last_exception, tool_name)
            return async_wrapper  # type: ignore

        else:
            @wraps(f)
            def sync_wrapper(*args, **kwargs) -> ToolResult:
                last_exception = None
                for attempt in range(max_retries + 1):
                    try:
                        return f(*args, **kwargs)
                    except Exception as exc:
                        last_exception = exc
                        if attempt < max_retries:
                            wait_time = backoff * (2 ** attempt)
                            logger.warning(
                                f"Tool '{tool_name}' failed (attempt {attempt+1}/{max_retries+1}). "
                                f"Retrying in {wait_time:.1f}s. Error: {exc}"
                            )
                            time.sleep(wait_time)
                        else:
                            return _handle_exception(exc, tool_name)
                return _handle_exception(last_exception, tool_name)
            return sync_wrapper  # type: ignore

    if func is None:
        return decorator
    return decorator(func)
