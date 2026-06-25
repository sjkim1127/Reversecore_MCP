"""
Logging configuration for Reversecore_MCP.

This module provides structured logging with JSON output option and log rotation.
Uses high-performance JSON serialization when available.

Environment Variables:
    LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    LOG_FORMAT: Log format - "human" or "json"
    LOG_FILE: Path to log file
"""

import logging
import platform
import sys
import time
from logging.handlers import RotatingFileHandler
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging with rich context."""

    def __init__(
        self,
        datefmt: str | None = None,
        include_extra: bool = True,
        include_hostname: bool = True,
    ):
        super().__init__(datefmt=datefmt)
        self.include_extra = include_extra
        self.include_hostname = include_hostname
        self._hostname = platform.node() if include_hostname else None

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with structured fields."""
        log_data: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add hostname for distributed systems
        if self._hostname:
            log_data["hostname"] = self._hostname

        # Add process/thread info for debugging concurrency issues
        log_data["process"] = {"id": record.process, "name": record.processName}
        log_data["thread"] = {"id": record.thread, "name": record.threadName}

        # Add extra fields if present (tool execution context)
        if self.include_extra:
            extra_fields = {}
            for key in (
                "tool_name",
                "file_name",
                "execution_time_ms",
                "error_code",
                "binary_path",
            ):
                if hasattr(record, key):
                    extra_fields[key] = getattr(record, key)

            # Include any custom extra fields
            for key, value in record.__dict__.items():
                if key.startswith("ctx_"):  # Convention: ctx_ prefix for context fields
                    extra_fields[key[4:]] = value  # Strip ctx_ prefix

            if extra_fields:
                log_data["context"] = extra_fields

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info),
            }

        # Safe serialization with default=str to prevent crashes on non-serializable objects
        return json.dumps(log_data, default=str)


class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that adds contextual information to log records."""

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        """Add extra context to log message."""
        extra = kwargs.get("extra", {})
        if self.extra:
            extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs


def setup_logging() -> None:
    """
    Configure logging for Reversecore_MCP.

    Logging configuration:
    - Log level from settings (default: INFO)
    - Log format from settings (default: human-readable)
    - Log file from settings (default: /tmp/reversecore/app.log)
    - Log rotation: 100MB max size, keep 10 backup files

    When LOG_FORMAT=json:
    - Console output is JSON formatted
    - File output is JSON formatted
    - Structured fields include timestamp, level, logger, message, context

    When LOG_FORMAT=human (default):
    - Console output is human-readable
    - File output is human-readable
    """
    settings = get_config()
    log_level = settings.log_level.upper()
    log_format = settings.log_format.lower()
    log_file = settings.log_file

    # Create log directory if it doesn't exist
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        pass

    # Configure root logger
    logger = logging.getLogger("reversecore_mcp")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    # Determine formatter based on LOG_FORMAT
    if log_format == "json":
        console_formatter: logging.Formatter = JSONFormatter()
        file_formatter: logging.Formatter = JSONFormatter()
    else:
        human_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
        console_formatter = logging.Formatter(human_format, datefmt=datefmt)
        file_formatter = logging.Formatter(human_format, datefmt=datefmt)

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    # Unlock console level to allow DEBUG logs if configured
    console_handler.setLevel(getattr(logging, log_level, logging.INFO))
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler with rotation (only if we can write to the log file)
    try:
        file_handler = RotatingFileHandler(
            str(log_file),
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        logger.warning(
            f"Could not create log file handler for {log_file}: {e}. Logging to console only."
        )

    # Prevent propagation to root logger
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(f"reversecore_mcp.{name}")


def get_context_logger(name: str, **context: Any) -> ContextAdapter:
    """
    Get a logger with persistent context fields.

    This is useful for adding context that should appear in all log messages,
    such as tool name, file being analyzed, etc.

    Args:
        name: Logger name (typically __name__)
        **context: Key-value pairs to include in all log messages

    Returns:
        ContextAdapter with the given context

    Example:
        logger = get_context_logger(__name__, tool_name="neural_decompile")
        logger.info("Starting analysis")  # Includes tool_name in output
    """
    base_logger = get_logger(name)
    # Prefix context keys with ctx_ to avoid conflicts
    prefixed_context = {f"ctx_{k}": v for k, v in context.items()}
    return ContextAdapter(base_logger, prefixed_context)
