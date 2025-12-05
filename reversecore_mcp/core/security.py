"""
Security utilities for input validation and sanitization.

This module provides functions to validate and sanitize user inputs before
they are used in subprocess calls, preventing command injection and
unauthorized file access.

Note: For radare2 command validation, use the improved regex-based validation
in command_spec.py which provides stronger security guarantees.
"""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.exceptions import ValidationError

# Configuration constants
PATH_VALIDATION_CACHE_SIZE = 256  # Number of path resolutions to cache


@dataclass(frozen=True)
class WorkspaceConfig:
    """Immutable configuration for workspace-aware file validation."""

    workspace: Path
    read_only_dirs: tuple[Path, ...]

    @classmethod
    def from_env(cls) -> "WorkspaceConfig":
        """Create a workspace configuration from the cached Config instance."""
        config = get_config()
        return cls(workspace=config.workspace, read_only_dirs=config.read_only_dirs)


# Lazy-initialized workspace configuration
# This avoids initialization errors when the module is imported before
# environment variables are set (common in test fixtures)
_WORKSPACE_CONFIG: WorkspaceConfig | None = None


def get_workspace_config() -> WorkspaceConfig:
    """
    Get the workspace configuration, initializing it lazily on first access.

    This lazy initialization pattern allows tests to set up environment
    variables or mock configurations before the first access.

    Returns:
        WorkspaceConfig instance
    """
    global _WORKSPACE_CONFIG
    if _WORKSPACE_CONFIG is None:
        _WORKSPACE_CONFIG = WorkspaceConfig.from_env()
    return _WORKSPACE_CONFIG


def refresh_workspace_config() -> WorkspaceConfig:
    """Recompute the default workspace configuration (mainly for tests)."""
    global _WORKSPACE_CONFIG
    _WORKSPACE_CONFIG = WorkspaceConfig.from_env()
    # Clear the path resolution cache when config changes
    _resolve_path_cached.cache_clear()
    return _WORKSPACE_CONFIG


def reset_workspace_config() -> None:
    """
    Reset the workspace configuration to uninitialized state.

    This is useful for tests that need to change environment variables
    and have the configuration re-read on next access.
    """
    global _WORKSPACE_CONFIG
    _WORKSPACE_CONFIG = None
    _resolve_path_cached.cache_clear()


@lru_cache(maxsize=PATH_VALIDATION_CACHE_SIZE)
def _resolve_path_cached(path_str: str) -> tuple[Path, bool, str]:
    """
    Cached path resolution to avoid repeated filesystem calls.

    Returns:
        Tuple of (resolved_path, is_file, error_message)
        If resolution fails, returns (original_path, False, error_message)
    """
    try:
        file_path = Path(path_str)
        abs_path = file_path.resolve(strict=True)
        is_file = abs_path.is_file()
        return (abs_path, is_file, "")
    except (OSError, RuntimeError) as e:
        return (Path(path_str), False, str(e))


def validate_file_path(
    path: str,
    read_only: bool = False,
    config: WorkspaceConfig | None = None,
) -> Path:
    """
    Validate and normalize a file path.

    This function ensures that:
    1. The path exists and points to a file (not a directory)
    2. The path is within the allowed workspace directory (REVERSECORE_WORKSPACE)
       or within allowed read-only directories (if read_only=True)
    3. The path is resolved to an absolute path

    The workspace directory is determined by an immutable WorkspaceConfig that
    is loaded once from environment variables (REVERSECORE_WORKSPACE and
    REVERSECORE_READ_DIRS).

    Performance: Uses LRU cache for path resolution to avoid repeated
    filesystem calls for frequently accessed files.

    Args:
        path: The file path to validate
        read_only: If True, also allow files from configured read-only directories
        config: Optional WorkspaceConfig override (useful for tests)

    Returns:
        The normalized absolute file path as a Path instance

    Raises:
        ValueError: If the path is invalid, doesn't exist, or is outside
                   the allowed directories
    """
    active_config = config or get_workspace_config()

    # Handle relative paths: resolve them relative to workspace directory
    # This allows users to specify just the filename (e.g., "sample.exe")
    # instead of the full path ("/app/workspace/sample.exe")
    file_path = Path(path)

    # Defense against AI mistakes: if a host-side absolute path is passed
    # (e.g., "/Users/john/Reversecore_Workspace/sample.exe"), extract just
    # the filename and try to find it in the workspace directory.
    # This handles cases where AI ignores the prompt instructions.
    if file_path.is_absolute() and not str(file_path).startswith(str(active_config.workspace)):
        # Path is absolute but not in workspace - likely a host path
        # Extract filename and try workspace
        filename_only = file_path.name
        workspace_path = active_config.workspace / filename_only
        if workspace_path.exists():
            path = str(workspace_path)
        # If not found, continue with original path (will error with helpful message)

    if not file_path.is_absolute():
        # Try workspace-relative path first
        workspace_path = active_config.workspace / path
        if workspace_path.exists():
            path = str(workspace_path)

    # Use cached path resolution to avoid repeated filesystem calls
    abs_path, is_file, error = _resolve_path_cached(path)

    if error:
        raise ValidationError(
            f"Invalid file path: {path}. Error: {error}",
            details={
                "path": path,
                "error": error,
                "hint": "Ensure the file is in the workspace directory",
            },
        )

    # Check that it's a file, not a directory
    if not is_file:
        raise ValidationError(
            f"Path does not point to a file: {abs_path}",
            details={"path": str(abs_path)},
        )

    def _is_relative_to(base: Path) -> bool:
        try:
            abs_path.relative_to(base)
            return True
        except ValueError:
            return False

    is_in_workspace = _is_relative_to(active_config.workspace)
    if is_in_workspace and not read_only:
        return abs_path

    is_in_read_dir = False
    if read_only and not is_in_workspace:
        for read_dir in active_config.read_only_dirs:
            if _is_relative_to(read_dir):
                is_in_read_dir = True
                break

    if not (is_in_workspace or is_in_read_dir):
        allowed_dirs = [str(active_config.workspace)]
        if read_only:
            allowed_dirs.extend(str(d) for d in active_config.read_only_dirs)
        raise ValidationError(
            f"File path is outside allowed directories: {abs_path}. "
            f"Allowed directories: {allowed_dirs}. "
            f"Set REVERSECORE_WORKSPACE or REVERSECORE_READ_DIRS environment variables to change allowed paths.",
            details={"path": str(abs_path), "allowed_directories": allowed_dirs},
        )

    return abs_path
