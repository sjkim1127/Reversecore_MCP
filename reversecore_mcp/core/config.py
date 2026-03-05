"""Configuration management using pydantic-settings.

This module provides type-safe configuration loading from environment variables
with automatic validation. Code can call ``get_config()`` to access the cached
singleton, and tests can use ``reset_config()`` for dependency injection.

Environment Variables:
    REVERSECORE_WORKSPACE: Path to workspace directory (default: current directory)
    REVERSECORE_READ_DIRS: Comma-separated list of read-only directories
    LOG_LEVEL: Logging level (default: INFO)
    LOG_FILE: Path to log file (default: <tempdir>/reversecore/app.log)
    LOG_FORMAT: Log format - "human" or "json" (default: human)
    STRUCTURED_ERRORS: Enable structured error responses (default: false)
    RATE_LIMIT: Rate limit per minute (default: 60)
    LIEF_MAX_FILE_SIZE: Max file size for LIEF parsing (default: 1GB)
    MCP_TRANSPORT: Transport mode - "stdio" or "http" (default: stdio)
    DEFAULT_TOOL_TIMEOUT: Default timeout in seconds (default: 120)
    R2_POOL_SIZE: Radare2 connection pool size (default: 3)
    R2_POOL_TIMEOUT: Radare2 pool connection timeout (default: 30)
    GHIDRA_MAX_PROJECTS: Max Ghidra projects to cache for multi-malware analysis (default: 3)
    REVERSECORE_STRICT_PATHS: Strict path validation mode (default: false)
"""

from __future__ import annotations

import logging
import tempfile
from enum import Enum
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogFormat(str, Enum):
    """Supported log formats."""

    HUMAN = "human"
    JSON = "json"


class TransportMode(str, Enum):
    """Supported MCP transport modes."""

    STDIO = "stdio"
    HTTP = "http"


class Settings(BaseSettings):
    """Application settings with environment variable support.

    All settings are loaded from environment variables with automatic
    type conversion and validation.
    """

    model_config = SettingsConfigDict(
        env_prefix="REVERSECORE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Workspace configuration
    workspace: Path = Field(
        default_factory=Path.cwd,
        description="Path to workspace directory for file operations",
    )
    read_dirs: str = Field(
        default="",
        alias="REVERSECORE_READ_DIRS",
        description="Comma-separated list of read-only directories",
    )
    strict_paths: bool = Field(
        default=False,
        description="Enable strict path validation (raise errors for missing paths)",
    )

    # Logging configuration
    log_level: str = Field(
        default="INFO",
        alias="LOG_LEVEL",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
    )
    log_file: Path = Field(
        default_factory=lambda: Path(tempfile.gettempdir()) / "reversecore" / "app.log",
        alias="LOG_FILE",
        description="Path to log file",
    )
    log_format: LogFormat = Field(
        default=LogFormat.HUMAN,
        alias="LOG_FORMAT",
        description="Log format: 'human' for readable, 'json' for structured",
    )

    # Error handling
    structured_errors: bool = Field(
        default=False,
        description="Enable structured error responses with error codes",
    )

    # Rate limiting
    rate_limit: int = Field(
        default=60,
        ge=1,
        le=1000,
        description="Rate limit (requests per minute)",
    )

    # File size limits
    max_output_size: int = Field(
        default=10_000_000,
        ge=1000,
        description="Maximum output size for tools (bytes)",
    )
    lief_max_file_size: int = Field(
        default=1_000_000_000,
        ge=1_000_000,
        description="Maximum file size for LIEF parsing (bytes)",
    )
    
    file_retention_minutes: int = Field(
        default=1440,  # 24 hours
        ge=60,
        description="Retention period for temporary files (minutes)",
    )

    # Transport configuration
    mcp_transport: TransportMode = Field(
        default=TransportMode.STDIO,
        alias="MCP_TRANSPORT",
        description="MCP transport mode: 'stdio' or 'http'",
    )

    # Timeout configuration
    default_tool_timeout: int = Field(
        default=120,
        ge=10,
        le=3600,
        alias="DEFAULT_TOOL_TIMEOUT",
        description="Default timeout for tool execution (seconds)",
    )

    # R2 Pool configuration
    r2_pool_size: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Number of radare2 connections in pool",
    )
    r2_pool_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Timeout for acquiring radare2 connection from pool",
    )

    # Ghidra configuration
    ghidra_max_projects: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of Ghidra projects to cache (higher = more RAM)",
    )

    # Emulation configuration
    max_emulation_instructions: int = Field(
        default=1000,
        ge=1,
        le=1_000_000,
        description="Maximum instructions for emulation safety limit",
    )

    # AI Memory configuration
    memory_db_path: Path = Field(
        default=Path.home() / ".reversecore_mcp" / "memory.db",
        alias="MEMORY_DB_PATH",
        description="Path to AI memory SQLite database",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Normalize and validate log level."""
        v = v.upper()
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v

    @field_validator("workspace", mode="before")
    @classmethod
    def expand_workspace_path(cls, v: str | Path | None) -> Path:
        """Expand and resolve workspace path."""
        if v is None or v == "":
            return Path.cwd()
        path = Path(v).expanduser().resolve()
        return path

    @field_validator("log_file", mode="before")
    @classmethod
    def expand_log_file_path(cls, v: str | Path) -> Path:
        """Expand and resolve log file path."""
        return Path(v).expanduser().resolve()

    @model_validator(mode="after")
    def validate_workspace_exists(self) -> "Settings":
        """Validate workspace directory exists."""
        if self.strict_paths:
            if not self.workspace.exists():
                raise ValueError(f"Workspace directory does not exist: {self.workspace}")
            if not self.workspace.is_dir():
                raise ValueError(f"Workspace path is not a directory: {self.workspace}")
        return self

    @property
    def read_only_dirs(self) -> tuple[Path, ...]:
        """Parse and return read-only directories."""
        if not self.read_dirs:
            return tuple()
        parts = [s.strip() for s in self.read_dirs.split(",") if s.strip()]
        dirs = []
        for part in parts:
            path = Path(part).expanduser().resolve()
            if path.exists() and path.is_dir():
                dirs.append(path)
        return tuple(dirs)


# =============================================================================
# Legacy Config Compatibility Layer
# =============================================================================
# The following provides backward compatibility with the existing codebase
# that uses the Config dataclass interface.


class Config:
    """Wrapper class for backward compatibility with existing code.

    This class wraps the pydantic Settings model to maintain the same
    interface as the previous dataclass-based Config.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        workspace: Path | str | None = None,
        read_only_dirs: tuple[Path, ...] | None = None,
        log_level: str | None = None,
        log_file: Path | str | None = None,
        log_format: str | None = None,
        structured_errors: bool | None = None,
        rate_limit: int | None = None,
        lief_max_file_size: int | None = None,
        mcp_transport: str | None = None,
        default_tool_timeout: int | None = None,
    ):
        """Initialize Config with optional Settings instance or individual values.

        For backward compatibility, individual values can be passed directly.
        """
        if settings is not None:
            self._settings = settings
        else:
            # Build settings from individual values if provided
            env_overrides = {}
            if workspace is not None:
                env_overrides["workspace"] = Path(workspace)
            if log_level is not None:
                env_overrides["log_level"] = log_level
            if log_file is not None:
                env_overrides["log_file"] = Path(log_file)
            if log_format is not None:
                env_overrides["log_format"] = LogFormat(log_format.lower())
            if structured_errors is not None:
                env_overrides["structured_errors"] = structured_errors
            if rate_limit is not None:
                env_overrides["rate_limit"] = rate_limit
            if lief_max_file_size is not None:
                env_overrides["lief_max_file_size"] = lief_max_file_size
            if mcp_transport is not None:
                env_overrides["mcp_transport"] = TransportMode(mcp_transport.lower())
            if default_tool_timeout is not None:
                env_overrides["default_tool_timeout"] = default_tool_timeout

            if env_overrides:
                self._settings = Settings(**env_overrides)
            else:
                self._settings = Settings()

        # Store read_only_dirs if explicitly provided (for test overrides)
        self._read_only_dirs_override = read_only_dirs

    @property
    def workspace(self) -> Path:
        return self._settings.workspace

    @property
    def read_only_dirs(self) -> tuple[Path, ...]:
        if self._read_only_dirs_override is not None:
            return self._read_only_dirs_override
        return self._settings.read_only_dirs

    @property
    def log_level(self) -> str:
        return self._settings.log_level

    @property
    def log_file(self) -> Path:
        return self._settings.log_file

    @property
    def log_format(self) -> str:
        return self._settings.log_format.value

    @property
    def structured_errors(self) -> bool:
        return self._settings.structured_errors

    @property
    def rate_limit(self) -> int:
        return self._settings.rate_limit

    @property
    def lief_max_file_size(self) -> int:
        return self._settings.lief_max_file_size

    @property
    def max_output_size(self) -> int:
        return self._settings.max_output_size

    @property
    def mcp_transport(self) -> str:
        return self._settings.mcp_transport.value

    @property
    def default_tool_timeout(self) -> int:
        return self._settings.default_tool_timeout

    @property
    def r2_pool_size(self) -> int:
        return self._settings.r2_pool_size

    @property
    def r2_pool_timeout(self) -> int:
        return self._settings.r2_pool_timeout

    @property
    def ghidra_max_projects(self) -> int:
        return self._settings.ghidra_max_projects

    @property
    def max_emulation_instructions(self) -> int:
        return self._settings.max_emulation_instructions

    @classmethod
    def from_env(cls) -> "Config":
        """Build a Config instance from environment variables."""
        return cls(Settings())

    def validate_paths(self, strict: bool = True) -> None:
        """Validate that configured directories exist and are directories."""
        logger = logging.getLogger(__name__)

        if not self.workspace.exists():
            msg = f"Workspace directory does not exist: {self.workspace}"
            if strict:
                raise ValueError(msg)
            logger.warning(msg)
        elif not self.workspace.is_dir():
            msg = f"Workspace path is not a directory: {self.workspace}"
            if strict:
                raise ValueError(msg)
            logger.warning(msg)

        for read_dir in self.read_only_dirs:
            if not read_dir.exists():
                msg = f"Read directory does not exist: {read_dir}"
                if strict:
                    raise ValueError(msg)
                logger.warning(msg)
            elif not read_dir.is_dir():
                msg = f"Read directory path is not a directory: {read_dir}"
                if strict:
                    raise ValueError(msg)
                logger.warning(msg)


# =============================================================================
# Module-level config management
# =============================================================================

_CONFIG: Config | None = None


def get_config() -> Config:
    """Return the cached Config instance, loading it on first access."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = Config.from_env()
    return _CONFIG


def get_settings() -> Settings:
    """Return the underlying pydantic Settings instance."""
    return get_config()._settings


def reset_config() -> Config:
    """Reload configuration from the current environment (primarily for tests)."""
    global _CONFIG
    _CONFIG = Config.from_env()
    try:
        from reversecore_mcp.core import security

        security.refresh_workspace_config()
    except Exception as e:
        logging.getLogger(__name__).debug("refresh_workspace_config skipped: %s", e)
    return _CONFIG


def reload_settings() -> Config:
    """Backward-compatible alias for legacy test helpers."""
    return reset_config()
