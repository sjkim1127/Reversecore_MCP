"""
Security utilities for input validation and sanitization.

This module provides functions to validate and sanitize user inputs before
they are used in subprocess calls, preventing command injection and
unauthorized file access.
"""

import os
from pathlib import Path
from typing import List, Optional

from reversecore_mcp.core.config import get_settings
from reversecore_mcp.core.exceptions import ValidationError


def _get_allowed_workspace() -> Path:
    """Get the allowed workspace directory from settings."""
    return get_settings().allowed_workspace


def _get_allowed_read_dirs() -> List[Path]:
    """Get the allowed read-only directories from settings."""
    return get_settings().allowed_read_dirs


# For backward compatibility, provide module-level constants
# These are computed at access time to allow test overrides
# Note: Direct access to these should use the functions above
ALLOWED_WORKSPACE = _get_allowed_workspace()  # Initial value, but functions are used internally
ALLOWED_READ_DIRS = _get_allowed_read_dirs()  # Initial value, but functions are used internally


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
        raise ValidationError(
            f"Invalid file path: {path}. Error: {e}",
            details={"path": path, "error": str(e)},
        )

    # Check that it's a file, not a directory
    if not abs_path.is_file():
        raise ValidationError(
            f"Path does not point to a file: {abs_path}",
            details={"path": str(abs_path)},
        )

    # Check if path is within allowed directories using os.path.commonpath()
    # This is more robust than startswith() and handles edge cases correctly
    # Read workspace path dynamically to allow test overrides
    workspace_path = _get_allowed_workspace()

    # Convert to string once for reuse
    abs_path_str = str(abs_path)
    workspace_path_str = str(workspace_path)

    def is_path_in_directory(file_path_str: str, dir_path_str: str) -> bool:
        """Check if file_path is within dir_path using commonpath."""
        try:
            common = os.path.commonpath([file_path_str, dir_path_str])
            return common == dir_path_str
        except ValueError:
            # Different drives on Windows or no common path
            return False

    is_in_workspace = is_path_in_directory(abs_path_str, workspace_path_str)

    # Early return if in workspace and no read_only check needed
    if is_in_workspace and not read_only:
        return abs_path_str

    # If read_only is True, also check read-only directories
    # Read read-only dirs dynamically to allow test overrides
    is_in_read_dirs = False
    if read_only and not is_in_workspace:
        read_dirs = _get_allowed_read_dirs()
        for read_dir in read_dirs:
            if is_path_in_directory(abs_path_str, str(read_dir)):
                is_in_read_dirs = True
                break

    if not (is_in_workspace or is_in_read_dirs):
        allowed_dirs = [workspace_path_str]
        if read_only:
            read_dirs = _get_allowed_read_dirs()
            allowed_dirs.extend([str(d) for d in read_dirs])
        raise ValidationError(
            f"File path is outside allowed directories: {abs_path_str}. "
            f"Allowed directories: {allowed_dirs}. "
            f"Set REVERSECORE_WORKSPACE or REVERSECORE_READ_DIRS environment variables to change allowed paths.",
            details={"path": abs_path_str, "allowed_directories": allowed_dirs},
        )

    return abs_path_str


# Radare2 command allowlist
# Read-only commands that are safe to execute
R2_READONLY_COMMANDS = [
    "pdf",  # Print disassembly function
    "afl",  # Analyze functions list
    "iS",   # Sections info
    "iz",   # Strings in data sections
    "px",   # Print hexdump
    "pd",   # Print disassembly
    "V",    # Visual mode (read-only)
    "s",    # Seek (read-only navigation)
    "?",    # Help
    "i",    # Info commands (read-only)
    "fs",   # Flag spaces (read-only)
    "f",    # Flags (read-only)
    "a",    # Analysis commands (read-only)
    "aa",   # Analyze all
    "af",   # Analyze function
    "pdj",  # Print disassembly JSON
    "pdfj", # Print disassembly function JSON
    "aflj", # Analyze functions list JSON
]

# Dangerous radare2 commands that should be blocked
R2_DANGEROUS_PATTERNS = [
    "w",    # Write
    "wo",   # Write opcode
    "wx",   # Write hex
    "o+",   # Open file for writing
    "o-",   # Close file
    "!",    # System command execution
    "#!",   # Script execution
    "waf",  # Write assembly function
    "wa",   # Write assembly
]


def sanitize_command_string(cmd: str, allowlist: Optional[List[str]] = None) -> str:
    """
    Validate a command string against an allowlist.

    This function is used to validate command strings that will be passed
    as arguments to subprocess calls. It does NOT quote or escape the string
    (since we use list-based subprocess calls), but validates that the
    command matches expected patterns.

    For radare2 commands, this function checks:
    1. Command is not empty
    2. Command does not contain dangerous patterns (write, system execution, etc.)
    3. If allowlist is provided, command matches allowed patterns

    Args:
        cmd: The command string to validate
        allowlist: Optional list of allowed command patterns.
                  If None, only basic validation and dangerous pattern checking
                  is performed. For radare2, use R2_READONLY_COMMANDS.

    Returns:
        The validated command string

    Raises:
        ValueError: If the command string is invalid, contains dangerous patterns,
                   or does not match allowlist
    """
    if not cmd or not cmd.strip():
        raise ValueError("Command string cannot be empty")

    cmd_stripped = cmd.strip()
    cmd_lower = cmd_stripped.lower()

    # Check for dangerous patterns first
    for dangerous in R2_DANGEROUS_PATTERNS:
        # Check if dangerous pattern appears as a standalone command or with whitespace
        # This prevents "w", "w ", " w", "wx", "wo", etc.
        dangerous_lower = dangerous.lower()
        if cmd_lower == dangerous_lower or cmd_lower.startswith(dangerous_lower + " "):
            raise ValueError(
                f"Dangerous command pattern detected: {dangerous}. "
                f"Write and system execution commands are not allowed."
            )

    # If allowlist is provided, check if command matches any pattern
    if allowlist:
        # Check if command starts with any allowed pattern
        # This allows commands like "pdf @ main", "afl", "iS", etc.
        matches = any(
            cmd_lower == pattern.lower()
            or cmd_lower.startswith(pattern.lower() + " ")
            or cmd_lower.startswith(pattern.lower() + "@")
            for pattern in allowlist
        )
        if not matches:
            raise ValueError(
                f"Command string does not match allowed patterns: {cmd}. "
                f"Allowed patterns: {allowlist}"
            )

    return cmd_stripped

