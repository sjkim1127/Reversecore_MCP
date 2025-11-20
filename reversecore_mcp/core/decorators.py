"""
Decorators for common tool execution patterns.

This module provides decorators to reduce code duplication in tool functions
by centralizing logging, error handling, and execution time measurement.
"""

import functools
import time
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def log_execution(tool_name: Optional[str] = None) -> Callable[[F], F]:
    """
    Decorator to add logging and error handling to tool functions.

    This decorator:
    - Logs function start and completion
    - Measures execution time
    - Handles common exceptions and formats errors
    - Extracts file_name from function arguments if present

    Args:
        tool_name: Name of the tool (defaults to function name)

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        # Use provided tool_name or function name
        actual_tool_name = tool_name or func.__name__

        # Check if function is async
        import inspect
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> ToolResult:
                start_time = time.time()
                file_name = None

                # Try to extract file_name from arguments
                for arg_name in ["file_path", "path", "file"]:
                    if arg_name in kwargs:
                        file_name = Path(kwargs[arg_name]).name
                        break
                if not file_name and args:
                    first_arg = args[0]
                    if isinstance(first_arg, str):
                        file_name = Path(first_arg).name

                # Log start
                log_extra = {"tool_name": actual_tool_name}
                if file_name:
                    log_extra["file_name"] = file_name
                logger.info(f"Starting {actual_tool_name}", extra=log_extra)

                try:
                    result = await func(*args, **kwargs)
                    execution_time = int((time.time() - start_time) * 1000)

                    # Add execution time to metadata
                    if hasattr(result, "metadata"):
                        if result.metadata is None:
                            result.metadata = {}
                        result.metadata["execution_time_ms"] = execution_time

                    log_extra["execution_time_ms"] = execution_time
                    logger.info(
                        f"{actual_tool_name} completed successfully", extra=log_extra
                    )
                    return result
                except Exception as exc:
                    execution_time = int((time.time() - start_time) * 1000)
                    log_extra["execution_time_ms"] = execution_time
                    logger.error(
                        f"{actual_tool_name} failed",
                        extra=log_extra,
                        exc_info=True,
                    )
                    return failure(
                        "INTERNAL_ERROR",
                        f"{actual_tool_name} failed: {exc}",
                        exception_type=type(exc).__name__,
                    )

            return async_wrapper  # type: ignore

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> ToolResult:
            start_time = time.time()
            file_name = None

            # Try to extract file_name from arguments
            # Common patterns: file_path, path, file
            for arg_name in ["file_path", "path", "file"]:
                if arg_name in kwargs:
                    file_name = Path(kwargs[arg_name]).name
                    break
            if not file_name and args:
                # Check first positional argument
                first_arg = args[0]
                if isinstance(first_arg, str):
                    file_name = Path(first_arg).name

            # Log start
            log_extra = {"tool_name": actual_tool_name}
            if file_name:
                log_extra["file_name"] = file_name
            logger.info(f"Starting {actual_tool_name}", extra=log_extra)

            try:
                result = func(*args, **kwargs)
                execution_time = int((time.time() - start_time) * 1000)

                # Add execution time to metadata
                if hasattr(result, "metadata"):
                    if result.metadata is None:
                        result.metadata = {}
                    result.metadata["execution_time_ms"] = execution_time

                log_extra["execution_time_ms"] = execution_time
                logger.info(
                    f"{actual_tool_name} completed successfully", extra=log_extra
                )
                return result
            except Exception as exc:
                execution_time = int((time.time() - start_time) * 1000)
                log_extra["execution_time_ms"] = execution_time
                logger.error(
                    f"{actual_tool_name} failed",
                    extra=log_extra,
                    exc_info=True,
                )
                return failure(
                    "INTERNAL_ERROR",
                    f"{actual_tool_name} failed: {exc}",
                    exception_type=type(exc).__name__,
                )

        return wrapper  # type: ignore

    return decorator

