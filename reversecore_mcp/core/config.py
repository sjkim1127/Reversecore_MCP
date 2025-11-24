"""Lightweight configuration loader for Reversecore_MCP.

This module avoids heavy dependencies and context-based managers by loading
all configuration once from environment variables. Code can call
``get_config()`` to access the cached singleton, and tests can use
``reset_config()`` or build ad-hoc configs for dependency injection.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from dotenv import load_dotenv

load_dotenv()


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _split_paths(raw: str | None) -> Tuple[Path, ...]:
    if not raw:
        return tuple()
    parts = [segment.strip() for segment in raw.split(",") if segment.strip()]
    return tuple(Path(segment).expanduser().resolve() for segment in parts)


@dataclass(frozen=True)
class Config:
    """Immutable snapshot of runtime configuration."""

    workspace: Path
    read_only_dirs: Tuple[Path, ...]
    log_level: str
    log_file: Path
    log_format: str
    structured_errors: bool
    rate_limit: int
    lief_max_file_size: int
    mcp_transport: str
    default_tool_timeout: int

    @classmethod
    def from_env(cls) -> "Config":
        """Build a configuration object from environment variables."""
        workspace = Path(os.getenv("REVERSECORE_WORKSPACE", "/app/workspace")).expanduser().resolve()
        read_dirs = _split_paths(os.getenv("REVERSECORE_READ_DIRS", "/app/rules"))
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        log_file = Path(os.getenv("LOG_FILE", "/tmp/reversecore/app.log")).expanduser()
        log_format = os.getenv("LOG_FORMAT", "human").lower()
        structured_errors = _parse_bool(os.getenv("STRUCTURED_ERRORS"), default=False)
        rate_limit = _parse_int(os.getenv("RATE_LIMIT"), default=60)
        lief_max_file_size = _parse_int(
            os.getenv("LIEF_MAX_FILE_SIZE"),
            default=1_000_000_000,
        )
        mcp_transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
        default_tool_timeout = _parse_int(
            os.getenv("DEFAULT_TOOL_TIMEOUT"),
            default=120,
        )

        return cls(
            workspace=workspace,
            read_only_dirs=read_dirs,
            log_level=log_level,
            log_file=log_file,
            log_format=log_format,
            structured_errors=structured_errors,
            rate_limit=rate_limit,
            lief_max_file_size=lief_max_file_size,
            mcp_transport=mcp_transport,
            default_tool_timeout=default_tool_timeout,
        )

        config.validate_paths()
        return config

    def validate_paths(self) -> None:
        """Validate that configured directories exist and are directories."""
        if not self.workspace.exists():
            raise ValueError(f"Workspace directory does not exist: {self.workspace}")
        if not self.workspace.is_dir():
            raise ValueError(f"Workspace path is not a directory: {self.workspace}")

        for read_dir in self.read_only_dirs:
            if not read_dir.exists():
                raise ValueError(f"Read directory does not exist: {read_dir}")
            if not read_dir.is_dir():
                raise ValueError(f"Read directory path is not a directory: {read_dir}")


_CONFIG: Config | None = None


def get_config() -> Config:
    """Return the cached Config instance, loading it on first access."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = Config.from_env()
    return _CONFIG


def reset_config() -> Config:
    """Reload configuration from the current environment (primarily for tests)."""
    global _CONFIG
    _CONFIG = Config.from_env()
    try:  # Avoid hard dependency to prevent circular imports at module load
        from reversecore_mcp.core import security

        security.refresh_workspace_config()
    except Exception:
        # Security module may not be initialized yet (e.g., during partial imports)
        pass
    return _CONFIG


def reload_settings() -> Config:
    """Backward-compatible alias for legacy test helpers."""
    return reset_config()
