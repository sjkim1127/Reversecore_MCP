"""
Centralized configuration management for Reversecore_MCP.

This module uses pydantic BaseSettings to manage all environment variables
in a single location with type validation and default values.
"""

import os
from pathlib import Path
from typing import List, Optional

try:
    # Try pydantic v2 first (pydantic-settings)
    from pydantic_settings import BaseSettings, SettingsConfigDict
    from pydantic import Field
    PYDANTIC_V2 = True
except ImportError:
    try:
        # Fallback to pydantic v1
        from pydantic import BaseSettings, Field
        PYDANTIC_V2 = False
    except ImportError:
        # If pydantic is not available, use a simple class
        BaseSettings = None
        Field = None
        PYDANTIC_V2 = False


if BaseSettings:
    if PYDANTIC_V2:
        class Settings(BaseSettings):
            """
            Centralized settings for Reversecore_MCP.

            All environment variables are loaded here with type validation and defaults.
            Supports .env file loading for development/production environment separation.
            """

            # Workspace and file access settings
            reversecore_workspace: Path = Field(
                default=Path("/app/workspace"),
                description="Allowed workspace directory for file operations",
                alias="REVERSECORE_WORKSPACE",
            )
            reversecore_read_dirs: str = Field(
                default="/app/rules",
                description="Comma-separated list of allowed read-only directories",
                alias="REVERSECORE_READ_DIRS",
            )

            # Logging settings
            log_level: str = Field(
                default="INFO",
                description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
                alias="LOG_LEVEL",
            )
            log_file: Path = Field(
                default=Path("/tmp/reversecore/app.log"),
                description="Path to log file",
                alias="LOG_FILE",
            )
            log_format: str = Field(
                default="human",
                description="Log format: 'human' or 'json'",
                alias="LOG_FORMAT",
            )

            # Error handling settings
            structured_errors: bool = Field(
                default=False,
                description="Enable structured JSON error responses",
                alias="STRUCTURED_ERRORS",
            )

            # Rate limiting settings
            rate_limit: int = Field(
                default=60,
                description="Rate limit for HTTP mode (requests per minute)",
                alias="RATE_LIMIT",
            )

            # LIEF settings
            lief_max_file_size: int = Field(
                default=1_000_000_000,  # 1GB
                description="Maximum file size for LIEF parsing (bytes)",
                alias="LIEF_MAX_FILE_SIZE",
            )

            # MCP transport settings
            mcp_transport: str = Field(
                default="stdio",
                description="MCP transport mode: 'stdio' or 'http'",
                alias="MCP_TRANSPORT",
            )

            model_config = SettingsConfigDict(
                env_file=".env",
                env_file_encoding="utf-8",
                case_sensitive=False,
                populate_by_name=True,  # Allow both field name and alias
            )

            @property
            def allowed_workspace(self) -> Path:
                """Get the allowed workspace directory as a resolved Path."""
                return self.reversecore_workspace.resolve()

            @property
            def allowed_read_dirs(self) -> List[Path]:
                """Get the allowed read-only directories as a list of resolved Paths."""
                return [
                    Path(d.strip()).resolve()
                    for d in self.reversecore_read_dirs.split(",")
                    if d.strip()
                ]

            def validate_paths(self) -> None:
                """
                Validate that workspace and read directories exist and are accessible.
                
                Raises:
                    ValueError: If required directories are missing or inaccessible
                """
                workspace = self.allowed_workspace
                if not workspace.exists():
                    raise ValueError(f"Workspace directory does not exist: {workspace}")
                if not workspace.is_dir():
                    raise ValueError(f"Workspace path is not a directory: {workspace}")
                
                for read_dir in self.allowed_read_dirs:
                    if not read_dir.exists():
                        raise ValueError(f"Read directory does not exist: {read_dir}")
                    if not read_dir.is_dir():
                        raise ValueError(f"Read directory path is not a directory: {read_dir}")
    else:
        # Pydantic v1
        class Settings(BaseSettings):
            """
            Centralized settings for Reversecore_MCP.

            All environment variables are loaded here with type validation and defaults.
            Supports .env file loading for development/production environment separation.
            """

            # Workspace and file access settings
            reversecore_workspace: Path = Field(
                default=Path("/app/workspace"),
                description="Allowed workspace directory for file operations",
            )
            reversecore_read_dirs: str = Field(
                default="/app/rules",
                description="Comma-separated list of allowed read-only directories",
            )

            # Logging settings
            log_level: str = Field(
                default="INFO",
                description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
            )
            log_file: Path = Field(
                default=Path("/tmp/reversecore/app.log"),
                description="Path to log file",
            )
            log_format: str = Field(
                default="human",
                description="Log format: 'human' or 'json'",
            )

            # Error handling settings
            structured_errors: bool = Field(
                default=False,
                description="Enable structured JSON error responses",
            )

            # Rate limiting settings
            rate_limit: int = Field(
                default=60,
                description="Rate limit for HTTP mode (requests per minute)",
            )

            # LIEF settings
            lief_max_file_size: int = Field(
                default=1_000_000_000,  # 1GB
                description="Maximum file size for LIEF parsing (bytes)",
            )

            # MCP transport settings
            mcp_transport: str = Field(
                default="stdio",
                description="MCP transport mode: 'stdio' or 'http'",
            )

            class Config:
                """Pydantic v1 configuration."""

                env_prefix = ""  # No prefix, use exact env var names
                case_sensitive = False
                env_file = ".env"
                env_file_encoding = "utf-8"

                @classmethod
                def parse_env_var(cls, field_name: str, raw_val: str) -> any:
                    """Custom parser for environment variables."""
                    if field_name == "reversecore_workspace":
                        return Path(raw_val)
                    elif field_name == "log_file":
                        return Path(raw_val)
                    elif field_name == "structured_errors":
                        return raw_val.lower() in ("true", "1", "yes", "on")
                    elif field_name in ("rate_limit", "lief_max_file_size"):
                        return int(raw_val)
                    return raw_val

            @property
            def allowed_workspace(self) -> Path:
                """Get the allowed workspace directory as a resolved Path."""
                return self.reversecore_workspace.resolve()

            @property
            def allowed_read_dirs(self) -> List[Path]:
                """Get the allowed read-only directories as a list of resolved Paths."""
                return [
                    Path(d.strip()).resolve()
                    for d in self.reversecore_read_dirs.split(",")
                    if d.strip()
                ]

            def validate_paths(self) -> None:
                """
                Validate that workspace and read directories exist and are accessible.
                
                Raises:
                    ValueError: If required directories are missing or inaccessible
                """
                workspace = self.allowed_workspace
                if not workspace.exists():
                    raise ValueError(f"Workspace directory does not exist: {workspace}")
                if not workspace.is_dir():
                    raise ValueError(f"Workspace path is not a directory: {workspace}")
                
                for read_dir in self.allowed_read_dirs:
                    if not read_dir.exists():
                        raise ValueError(f"Read directory does not exist: {read_dir}")
                    if not read_dir.is_dir():
                        raise ValueError(f"Read directory path is not a directory: {read_dir}")
else:
    # Fallback: simple class without pydantic
    class Settings:
        """
        Centralized settings for Reversecore_MCP (fallback without pydantic).

        All environment variables are loaded here with basic validation and defaults.
        """

        def __init__(self, **kwargs):
            """Initialize settings with environment variable support."""
            self.reversecore_workspace = Path(
                os.environ.get("REVERSECORE_WORKSPACE", "/app/workspace")
            )
            self.reversecore_read_dirs = os.environ.get(
                "REVERSECORE_READ_DIRS", "/app/rules"
            )
            self.log_level = os.environ.get("LOG_LEVEL", "INFO")
            self.log_file = Path(
                os.environ.get("LOG_FILE", "/tmp/reversecore/app.log")
            )
            self.log_format = os.environ.get("LOG_FORMAT", "human")
            self.structured_errors = (
                os.environ.get("STRUCTURED_ERRORS", "false").lower() == "true"
            )
            self.rate_limit = int(os.environ.get("RATE_LIMIT", "60"))
            self.lief_max_file_size = int(
                os.environ.get("LIEF_MAX_FILE_SIZE", "1000000000")
            )
            self.mcp_transport = os.environ.get("MCP_TRANSPORT", "stdio")

        @property
        def allowed_workspace(self) -> Path:
            """Get the allowed workspace directory as a resolved Path."""
            return self.reversecore_workspace.resolve()

        @property
        def allowed_read_dirs(self) -> List[Path]:
            """Get the allowed read-only directories as a list of resolved Paths."""
            return [
                Path(d.strip()).resolve()
                for d in self.reversecore_read_dirs.split(",")
                if d.strip()
            ]

        def validate_paths(self) -> None:
            """
            Validate that workspace and read directories exist and are accessible.
            
            Raises:
                ValueError: If required directories are missing or inaccessible
            """
            workspace = self.allowed_workspace
            if not workspace.exists():
                raise ValueError(f"Workspace directory does not exist: {workspace}")
            if not workspace.is_dir():
                raise ValueError(f"Workspace path is not a directory: {workspace}")
            
            for read_dir in self.allowed_read_dirs:
                if not read_dir.exists():
                    raise ValueError(f"Read directory does not exist: {read_dir}")
                if not read_dir.is_dir():
                    raise ValueError(f"Read directory path is not a directory: {read_dir}")


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get the global settings instance (singleton pattern).

    Returns:
        Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """
    Reload settings from environment (useful for testing).

    Returns:
        New Settings instance
    """
    global _settings
    _settings = Settings()
    return _settings

