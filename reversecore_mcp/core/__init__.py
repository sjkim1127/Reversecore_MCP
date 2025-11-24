"""
Core utilities for Reversecore_MCP.

This package contains security, execution, and exception handling utilities
used across all tool modules.
"""

# Import decorators and helpers for public API
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_formatting import format_error, get_validation_hint
from reversecore_mcp.core.exceptions import (
    ExecutionTimeoutError,
    OutputLimitExceededError,
    ReversecoreError,
    ToolNotFoundError,
    ValidationError,
)
from reversecore_mcp.core.execution import (
    execute_subprocess_streaming,
    execute_subprocess_async,
)
from reversecore_mcp.core.logging_config import get_logger, setup_logging
from reversecore_mcp.core.security import validate_file_path

# Import performance optimization modules
from reversecore_mcp.core.r2_pool import R2ConnectionPool, r2_pool
from reversecore_mcp.core.resource_manager import ResourceManager, resource_manager

__all__ = [
    "ReversecoreError",
    "ToolNotFoundError",
    "ExecutionTimeoutError",
    "OutputLimitExceededError",
    "ValidationError",
    "execute_subprocess_streaming",
    "execute_subprocess_async",
    "validate_file_path",
    "format_error",
    "get_validation_hint",
    "get_logger",
    "setup_logging",
    "log_execution",
    "R2ConnectionPool",
    "r2_pool",
    "ResourceManager",
    "resource_manager",
]
