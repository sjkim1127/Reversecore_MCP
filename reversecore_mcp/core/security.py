"""
Security utilities for input validation and sanitization.

This module provides functions to validate and sanitize user inputs before
they are used in subprocess calls, preventing command injection and
unauthorized file access.
"""

import os
from pathlib import Path
from typing import List, Optional

# Workspace directory for file access restrictions
# Can be overridden via REVERSECORE_WORKSPACE environment variable
ALLOWED_WORKSPACE = Path(
    os.environ.get("REVERSECORE_WORKSPACE", "/app/workspace")
).resolve()

# Read-only directories for static files (e.g., YARA rules)
# Can be overridden via REVERSECORE_READ_DIRS environment variable (comma-separated)
_read_dirs_str = os.environ.get("REVERSECORE_READ_DIRS", "/app/rules")
ALLOWED_READ_DIRS = [
    Path(d.strip()).resolve() for d in _read_dirs_str.split(",") if d.strip()
]


def validate_file_path(path: str, read_only: bool = False) -> str:
    """
    Validate and normalize a file path.

    This function ensures that:
    1. The path exists and points to a file (not a directory)
    2. The path is within the allowed workspace directory (REVERSECORE_WORKSPACE)
       or within allowed read-only directories (if read_only=True)
    3. The path is resolved to an absolute path

    The workspace directory is determined by the REVERSECORE_WORKSPACE environment
    variable, defaulting to /app/workspace if not set.
    Read-only directories are determined by the REVERSECORE_READ_DIRS environment
    variable (comma-separated), defaulting to /app/rules if not set.

    Args:
        path: The file path to validate
        read_only: If True, also allow files from ALLOWED_READ_DIRS (e.g., for YARA rules)

    Returns:
        The normalized absolute file path

    Raises:
        ValueError: If the path is invalid, doesn't exist, or is outside
                   the allowed directories
    """
    # Convert to Path object for easier manipulation
    file_path = Path(path)

    # Resolve to absolute path (removes symlinks and relative components)
    try:
        abs_path = file_path.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid file path: {path}. Error: {e}")

    # Check that it's a file, not a directory
    if not abs_path.is_file():
        raise ValueError(f"Path does not point to a file: {abs_path}")

    # Check if path is within allowed directories
    workspace_path = ALLOWED_WORKSPACE
    is_in_workspace = str(abs_path).startswith(str(workspace_path))

    # If read_only is True, also check read-only directories
    is_in_read_dirs = False
    if read_only:
        for read_dir in ALLOWED_READ_DIRS:
            if str(abs_path).startswith(str(read_dir)):
                is_in_read_dirs = True
                break

    if not (is_in_workspace or is_in_read_dirs):
        allowed_dirs = [str(workspace_path)]
        if read_only:
            allowed_dirs.extend([str(d) for d in ALLOWED_READ_DIRS])
        raise ValueError(
            f"File path is outside allowed directories: {abs_path}. "
            f"Allowed directories: {allowed_dirs}. "
            f"Set REVERSECORE_WORKSPACE or REVERSECORE_READ_DIRS environment variables to change allowed paths."
        )

    return str(abs_path)


def sanitize_command_string(cmd: str, allowlist: Optional[List[str]] = None) -> str:
    """
    Validate a command string against an allowlist.

    This function is used to validate command strings that will be passed
    as arguments to subprocess calls. It does NOT quote or escape the string
    (since we use list-based subprocess calls), but validates that the
    command matches expected patterns.

    Args:
        cmd: The command string to validate
        allowlist: Optional list of allowed command patterns.
                  If None, only basic validation is performed (non-empty).

    Returns:
        The validated command string

    Raises:
        ValueError: If the command string is invalid or not in allowlist
    """
    if not cmd or not cmd.strip():
        raise ValueError("Command string cannot be empty")

    # If allowlist is provided, check if command matches any pattern
    if allowlist:
        cmd_lower = cmd.lower().strip()
        matches = any(
            pattern.lower() in cmd_lower or cmd_lower.startswith(pattern.lower())
            for pattern in allowlist
        )
        if not matches:
            raise ValueError(
                f"Command string does not match allowed patterns: {cmd}. "
                f"Allowed patterns: {allowlist}"
            )

    return cmd.strip()

