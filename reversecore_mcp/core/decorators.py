"""
Decorators for common tool execution patterns.

This module provides decorators to reduce code duplication in tool functions
by centralizing logging, error handling, and execution time measurement.
"""

import functools
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

from reversecore_mcp.core.error_formatting import format_error, get_validation_hint
from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.logging_config import get_logger

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

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
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
                # Execute the function
                result = func(*args, **kwargs)

                # Log success
                execution_time = int((time.time() - start_time) * 1000)
                log_extra["execution_time_ms"] = execution_time
                logger.info(
                    f"{actual_tool_name} completed successfully", extra=log_extra
                )

                return result

            except (ToolNotFoundError, ExecutionTimeoutError, ValidationError) as e:
                # Known exceptions - format with hints
                execution_time = int((time.time() - start_time) * 1000)
                hint = (
                    get_validation_hint(e)
                    if isinstance(e, ValidationError)
                    else None
                )
                log_extra["execution_time_ms"] = execution_time
                log_extra["error_code"] = (
                    e.error_code if hasattr(e, "error_code") else None
                )
                logger.warning(f"{actual_tool_name} failed", extra=log_extra, exc_info=True)

                # Return formatted error (tool functions should return strings, not raise)
                return format_error(e, tool_name=actual_tool_name, hint=hint)

            except ValueError as e:
                # Validation errors
                execution_time = int((time.time() - start_time) * 1000)
                log_extra["execution_time_ms"] = execution_time
                logger.warning(
                    f"{actual_tool_name} validation failed",
                    extra=log_extra,
                    exc_info=True,
                )
                return format_error(
                    e, tool_name=actual_tool_name, hint=get_validation_hint(e)
                )

            except subprocess.CalledProcessError as e:
                # Command execution errors
                execution_time = int((time.time() - start_time) * 1000)
                stderr = e.stderr if e.stderr else "Unknown error"
                log_extra["execution_time_ms"] = execution_time
                log_extra["exit_code"] = e.returncode
                logger.error(
                    f"{actual_tool_name} command failed",
                    extra=log_extra,
                    exc_info=True,
                )
                error_msg = f"Command failed with exit code {e.returncode}. stderr: {stderr}"
                return format_error(Exception(error_msg), tool_name=actual_tool_name)

            except Exception as e:
                # Unexpected errors
                execution_time = int((time.time() - start_time) * 1000)
                log_extra["execution_time_ms"] = execution_time
                logger.error(
                    f"{actual_tool_name} unexpected error",
                    extra=log_extra,
                    exc_info=True,
                )
                return format_error(e, tool_name=actual_tool_name)

        return wrapper  # type: ignore

    return decorator

