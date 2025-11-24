"""
Logging configuration for Reversecore_MCP.

This module provides structured logging with JSON output option and log rotation.
Uses high-performance JSON serialization when available.
"""

# Use high-performance JSON implementation for log serialization
from reversecore_mcp.core import json_utils as json
import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

from reversecore_mcp.core.config import get_config


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "tool_name"):
            log_data["tool_name"] = record.tool_name
        if hasattr(record, "file_name"):
            log_data["file_name"] = record.file_name
        if hasattr(record, "execution_time_ms"):
            log_data["execution_time_ms"] = record.execution_time_ms
        if hasattr(record, "error_code"):
            log_data["error_code"] = record.error_code

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


def setup_logging() -> None:
    """
    Configure logging for Reversecore_MCP.

    Logging configuration:
    - Log level from settings (default: INFO)
    - Log format from settings (default: human-readable)
    - Log file from settings (default: /tmp/reversecore/app.log)
    - Log rotation: 100MB max size, daily rotation, keep 10 backup files
    """
    # Get configuration from settings
    settings = get_config()
    log_level = settings.log_level.upper()
    log_format = settings.log_format.lower()
    log_file = settings.log_file

    # Create log directory if it doesn't exist
    # Handle permission errors gracefully (e.g., in test environments)
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        # If we can't create the directory, log to console only
        # This is acceptable in test environments
        pass

    # Configure root logger
    logger = logging.getLogger("reversecore_mcp")
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler (always human-readable)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
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

        # Choose formatter based on LOG_FORMAT
        if log_format == "json":
            file_formatter = JSONFormatter()
        else:
            file_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except (PermissionError, OSError, IOError) as e:
        # If we can't create or write to the log file, log to console only
        # This is acceptable in restricted environments (e.g., AWS Lambda, read-only filesystems)
        logger.warning(
            f"Could not create log file handler for {log_file}: {e}. "
            "Logging to console only."
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
