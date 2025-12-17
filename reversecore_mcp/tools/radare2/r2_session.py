"""
Radare2 Session Management and Security Validators.

This module provides session management and security validation utilities
for radare2 analysis tools.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from functools import lru_cache
from typing import Any, TYPE_CHECKING

# Lazy import for r2pipe to allow tests to run without it
try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    r2pipe = None  # type: ignore
    R2PIPE_AVAILABLE = False

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# Default configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout
DEFAULT_PAGE_SIZE = 1000
MAX_PAGE_SIZE = 10000

# =============================================================================
# Security Validators
# =============================================================================

# Pattern for safe identifiers (function names, class names, etc.)
_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]*$")

# Pattern for safe math expressions (for calculate tool)
# Allows: hex (0x..), decimal, operators, symbols (sym.xxx), parentheses
_SAFE_EXPRESSION_PATTERN = re.compile(r"^[a-zA-Z0-9_.\s+\-*/%()[\]]+$")

# Dangerous r2 commands that should be blocked
_BLOCKED_R2_COMMANDS = frozenset(
    {
        "!",  # Shell escape
        "#!",  # Alternative shell
        "=!",  # Remote shell
        "o+",  # Open for write
        "w",  # Write
        "wa",  # Write assembly
        "wb",  # Write bytes
        "wc",  # Write comment (file modification)
        "wf",  # Write file
        "Ps",  # Project save (can overwrite)
        "rm",  # Remove (radare2 built-in)
        "r2pm",  # Package manager
    }
)


def _validate_identifier(value: str, param_name: str) -> None:
    """
    Validate that a value is a safe identifier (no injection).

    Args:
        value: The identifier to validate
        param_name: Name of parameter for error messages

    Raises:
        ValidationError: If identifier is invalid
    """
    if not value:
        raise ValidationError(f"{param_name} cannot be empty")

    if not _SAFE_IDENTIFIER_PATTERN.match(value):
        raise ValidationError(
            f"{param_name} must contain only alphanumeric characters, "
            "underscores, and dots (starting with letter or underscore)"
        )


def _validate_expression(expression: str) -> None:
    """
    Validate math expression for calculate tool.

    Args:
        expression: Math expression to validate

    Raises:
        ValidationError: If expression contains dangerous characters
    """
    if not expression:
        raise ValidationError("expression cannot be empty")

    if not _SAFE_EXPRESSION_PATTERN.match(expression):
        raise ValidationError(
            "expression contains invalid characters. "
            "Only alphanumeric, operators (+,-,*,/,%), parentheses, and symbols allowed."
        )

    # Additional check for shell escape attempts
    if any(c in expression for c in ["`", "$", ";", "|", "&", ">", "<", "~"]):
        raise ValidationError("expression contains forbidden shell characters")


def _validate_r2_command(command: str) -> None:
    """
    Validate radare2 command for safety.

    Args:
        command: r2 command to validate

    Raises:
        ValidationError: If command is blocked or dangerous
    """
    if not command:
        raise ValidationError("command cannot be empty")

    # Check for shell escape
    cmd_start = command.strip().split()[0] if command.strip() else ""

    # Block dangerous commands
    for blocked in _BLOCKED_R2_COMMANDS:
        if cmd_start.startswith(blocked):
            raise ValidationError(
                f"Command '{blocked}' is blocked for security reasons. "
                "Only analysis commands are allowed."
            )

    # Block shell metacharacters in command
    if any(c in command for c in ["`", "$", "|", "&", ">", "<", "\n", "\r"]):
        raise ValidationError("Command contains forbidden shell metacharacters")


def _sanitize_for_r2_cmd(value: str) -> str:
    """
    Sanitize a value for safe use in r2 commands.

    Removes/escapes dangerous characters while preserving functionality.

    Args:
        value: Value to sanitize

    Returns:
        Sanitized value safe for r2 commands
    """
    if not value:
        return ""

    # Remove shell metacharacters
    dangerous_chars = "`$;|&><\n\r\t\\"
    sanitized = value
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")

    # Remove quotes that could break command parsing
    sanitized = sanitized.replace('"', "").replace("'", "")

    return sanitized


class R2Session:
    """
    Manages a radare2 session with enhanced state tracking and diagnostics.
    """

    def __init__(self, file_path: str | None = None):
        self.session_id = str(uuid.uuid4())
        self.file_path = file_path
        self._r2: Any = None  # r2pipe.open_sync when available
        self._analyzed = False
        self.created_at = datetime.now()
        self.status = "initialized"  # initialized, active, error, closed
        self.last_error = None
        self.retry_count = 0

    def open(self, file_path: str) -> bool:
        """Open a binary file with radare2."""
        if not R2PIPE_AVAILABLE:
            self.status = "error"
            self.last_error = "r2pipe module not installed"
            logger.error("r2pipe module not available - install with: pip install r2pipe")
            return False
        
        try:
            self.close()
            # Verify file exists strictly before passing to r2
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            self._r2 = r2pipe.open(file_path)
            if not self._r2:
                raise RuntimeError("r2pipe.open returned None")

            self.file_path = file_path
            self.status = "active"
            return True
        except Exception as e:
            self.status = "error"
            self.last_error = str(e)
            logger.error(f"Failed to open file {file_path}: {e}")
            return False

    def close(self) -> None:
        """Close the current radare2 session."""
        if self._r2:
            try:
                self._r2.quit()
            except Exception:
                pass
            self._r2 = None
            self.status = "closed"
            self._analyzed = False

    def cmd(self, command: str) -> str:
        """Execute a radare2 command and return the output."""
        if not self._r2:
            return ""
        try:
            result = self._r2.cmd(command)
            return result if result else ""
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"R2 command failed: {e}")
            return f"Error: {e}"

    def cmdj(self, command: str) -> Any:
        """Execute a radare2 command and return JSON output."""
        if not self._r2:
            return None
        try:
            return self._r2.cmdj(command)
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"R2 JSON command failed: {e}")
            return None

    def analyze(self, level: int = 2) -> str:
        """Run analysis with specified depth level."""
        if self._analyzed and level <= 2:
            return "Already analyzed"

        analysis_cmds = {
            0: "aa",  # Basic analysis
            1: "aaa",  # Auto-analysis
            2: "aaaa",  # Experimental analysis
            3: "aaaaa",  # Deep analysis
            4: "aaaaaa",  # Very deep analysis
        }
        cmd = analysis_cmds.get(level, "aaa")
        result = self.cmd(cmd)
        self._analyzed = True
        return result

    @property
    def is_open(self) -> bool:
        return self._r2 is not None and self.status == "active"


# =============================================================================
# Utility Functions
# =============================================================================


@lru_cache(maxsize=64)
def _compile_regex_cached(pattern: str) -> re.Pattern | None:
    """Compile and cache regex pattern."""
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _filter_lines_by_regex(text: str, pattern: str) -> str:
    """Filter lines matching a regex pattern."""
    if not pattern or not text:
        return text

    # Limit pattern length to prevent ReDoS
    if len(pattern) > 500:
        return "Error: Regex pattern too long (max 500 chars)"

    regex = _compile_regex_cached(pattern)
    if regex is None:
        return f"Invalid regex pattern: {pattern}"

    lines = text.split("\n")
    filtered = [line for line in lines if regex.search(line)]
    return "\n".join(filtered)


def _filter_named_functions(text: str) -> str:
    """Filter out functions with numeric suffixes (e.g., sym.func.1000016c8)."""
    if not text:
        return text
    lines = text.split("\n")
    filtered = []
    for line in lines:
        # Check if last part after dot is a number (hex)
        parts = line.split(".")
        if parts:
            last_part = parts[-1].split()[0] if parts[-1] else ""
            # Skip if last part looks like a hex address
            if last_part and last_part[0].isdigit():
                continue
        filtered.append(line)
    return "\n".join(filtered)


def _paginate_text(text: str, cursor: str | None, page_size: int) -> tuple[str, bool, str | None]:
    """
    Paginate text by lines.

    Returns: (paginated_text, has_more, next_cursor)
    """
    if not text:
        return "", False, None

    lines = text.split("\n")
    start_index = int(cursor) if cursor and cursor.isdigit() else 0

    if start_index < 0:
        start_index = 0

    end_index = start_index + page_size
    paginated_lines = lines[start_index:end_index]

    has_more = end_index < len(lines)
    next_cursor = str(end_index) if has_more else None

    return "\n".join(paginated_lines), has_more, next_cursor
