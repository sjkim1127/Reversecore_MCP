"""
Audit Logging Module

Provides a tamper-evident record of security-critical actions (uploads, patches, etc.).
Logs are written to a separate file (audit.json) to distinguish from operational logs.
"""

import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any

from reversecore_mcp.core.config import get_config


class AuditAction(str, Enum):
    """Types of actions that require auditing."""

    FILE_UPLOAD = "FILE_UPLOAD"
    BINARY_PATCH = "BINARY_PATCH"
    FILE_DELETE = "FILE_DELETE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    AUTH_FAILURE = "AUTH_FAILURE"


class AuditLogger:
    """Specialized logger for security audit trails."""

    _instance = None
    _initialized: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        settings = get_config()
        self.log_file = (
            settings.workspace.parent / "audit.json"
        )  # Store outside workspace if possible, or root
        # If workspace is root, maybe put in /var/log/reversecore if possible?
        # For Docker, settings.workspace is /app/workspace. Parent is /app.
        # Let's verify permission. If not, fallback to workspace.

        # Prepare file handler
        self._logger = logging.getLogger("reversecore_audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        try:
            handler = logging.FileHandler(str(self.log_file), encoding="utf-8")
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
        except Exception:
            # Fallback to standard log if separate file fails
            self._logger = logging.getLogger("reversecore_mcp")
            self._logger.warning("Failed to initialize separate audit log. Merging with app log.")

        self._initialized = True

    def log_event(
        self,
        action: AuditAction | str,
        resource: str,
        status: str,
        user: str = "system",
        ip: str = "local",
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Record a security event.

        Args:
            action: Type of action (e.g., FILE_UPLOAD)
            resource: Target resource (filename, path)
            status: SUCCESS or FAILURE
            user: Username or ID
            ip: Source IP
            details: Additional context
        """
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": str(action),
            "resource": resource,
            "status": status,
            "user": user,
            "ip": ip,
            "details": details or {},
        }

        self._logger.info(json.dumps(event))


# Global instance
audit_logger = AuditLogger()
