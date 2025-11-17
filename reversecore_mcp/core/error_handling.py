"""Shared error handling utilities for tool wrappers."""

from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar

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


def handle_tool_errors(func: F) -> F:
    """Wrap a tool function to convert common exceptions into ToolResult failures."""

    # Check if function is async
    import inspect
    is_async = inspect.iscoroutinefunction(func)

    if is_async:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> ToolResult:
            tool_name = func.__name__
            try:
                return await func(*args, **kwargs)
            except ToolNotFoundError as exc:
                hint = f"Install with: apt-get install {exc.tool_name}"
                return failure("TOOL_NOT_FOUND", str(exc), hint=hint)
            except ExecutionTimeoutError as exc:
                return failure(
                    "TIMEOUT",
                    f"Command timed out after {exc.timeout_seconds} seconds",
                    timeout_seconds=exc.timeout_seconds,
                )
            except OutputLimitExceededError as exc:
                return failure(
                    "OUTPUT_LIMIT",
                    str(exc),
                    hint="Reduce output size or increase the limit",
                    details={
                        "max_size": exc.max_size,
                        "actual_size": exc.actual_size,
                    },
                )
            except ValidationError as exc:
                return failure(
                    "VALIDATION_ERROR",
                    str(exc),
                    hint="Ensure the file is in the workspace directory",
                    details=exc.details,
                )
            except Exception as exc:  # noqa: BLE001 - we intentionally coerce to ToolResult
                logger.exception("Unexpected error in tool '%s'", tool_name)
                return failure(
                    "INTERNAL_ERROR",
                    f"{tool_name} failed: {exc}",
                    exception_type=exc.__class__.__name__,
                )

        return async_wrapper  # type: ignore[return-value]

    @wraps(func)
    def wrapper(*args, **kwargs) -> ToolResult:
        tool_name = func.__name__
        try:
            return func(*args, **kwargs)
        except ToolNotFoundError as exc:
            hint = f"Install with: apt-get install {exc.tool_name}"
            return failure("TOOL_NOT_FOUND", str(exc), hint=hint)
        except ExecutionTimeoutError as exc:
            return failure(
                "TIMEOUT",
                f"Command timed out after {exc.timeout_seconds} seconds",
                timeout_seconds=exc.timeout_seconds,
            )
        except OutputLimitExceededError as exc:
            return failure(
                "OUTPUT_LIMIT",
                str(exc),
                hint="Reduce output size or increase the limit",
                details={
                    "max_size": exc.max_size,
                    "actual_size": exc.actual_size,
                },
            )
        except ValidationError as exc:
            return failure(
                "VALIDATION_ERROR",
                str(exc),
                hint="Ensure the file is in the workspace directory",
                details=exc.details,
            )
        except Exception as exc:  # noqa: BLE001 - we intentionally coerce to ToolResult
            logger.exception("Unexpected error in tool '%s'", tool_name)
            return failure(
                "INTERNAL_ERROR",
                f"{tool_name} failed: {exc}",
                exception_type=exc.__class__.__name__,
            )

    return wrapper  # type: ignore[return-value]
