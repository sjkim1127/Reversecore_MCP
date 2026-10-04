"""
Radare2 Session Management and Security Validators.

This module provides session management and security validation utilities
for radare2 analysis tools.
"""

from __future__ import annotations

import asyncio
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import lru_cache
from typing import Any

import regex as timeout_regex

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
_REGEX_MATCH_MIN_TIMEOUT_SECONDS = 0.1
_REGEX_MATCH_MAX_TIMEOUT_SECONDS = 2.0
_REGEX_MATCH_CHARS_PER_SECOND = 2_000_000
_REGEX_FILTER_MAX_WORKERS = 4
_REGEX_FILTER_MAX_IN_FLIGHT = _REGEX_FILTER_MAX_WORKERS * 2
_REGEX_FILTER_EXECUTOR = ThreadPoolExecutor(
    max_workers=_REGEX_FILTER_MAX_WORKERS,
    thread_name_prefix="r2-regex-filter",
)
_REGEX_FILTER_CAPACITY = threading.BoundedSemaphore(_REGEX_FILTER_MAX_IN_FLIGHT)
_REGEX_MATCH_TIMEOUT_ERROR_PREFIX = "Error: Regex matching timed out"
_REGEX_FILTER_CAPACITY_ERROR_PREFIX = "Error: Regex filter capacity exceeded"

# =============================================================================
# Security Validators
# =============================================================================

# Pattern for safe identifiers (function names, class names, etc.)
_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]*$")

# Pattern for safe math expressions (for calculate tool)
# Allows: hex (0x..), decimal, operators, symbols (sym.xxx), parentheses
_SAFE_EXPRESSION_PATTERN = re.compile(r"^[a-zA-Z0-9_.\s+\-*/%()[\]]+$")

_MAX_RAW_R2_COMMAND_LENGTH = 512
_MAX_RAW_R2_READ_BYTES = 4096
_MAX_RAW_R2_INSTRUCTIONS = 512
_SAFE_R2_ADDRESS = (
    r"(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20}|[A-Za-z_][A-Za-z0-9_.]*)"
    r"(?:[+-](?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20}))*"
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


def _validate_r2_command(command: str) -> str:
    """
    Validate radare2 command for safety.

    Args:
        command: r2 command to validate

    Raises:
        ValidationError: If command is blocked or dangerous
    """
    if not command:
        raise ValidationError("command cannot be empty")
    if len(command) > _MAX_RAW_R2_COMMAND_LENGTH:
        raise ValidationError(f"command must not exceed {_MAX_RAW_R2_COMMAND_LENGTH} characters")

    normalized = " ".join(command.split())
    if not normalized:
        raise ValidationError("command cannot be empty")

    # Keep the raw-command API to read-only commands with operands that cannot
    # name files, scripts, shell commands, or command chains. In particular,
    # `o` is intentionally absent: even read-only `o /path` switches the file
    # backing the session and bypasses validation of the initial sample path.
    location = rf"(?:\s*@\s*{_SAFE_R2_ADDRESS})?"
    patterns = (
        (rf"pdf{location}", "pd 256{location}"),
        (rf"pd(?:\s+(\d{{1,4}}))?{location}", None),
        (rf"px(?:\s+(\d{{1,5}}))?{location}", None),
        (rf"ps(?:\s+(\d{{1,5}}))?{location}", None),
    )

    for pattern, rewrite in patterns:
        match = re.fullmatch(pattern, normalized)
        if not match:
            continue

        if rewrite is not None:
            normalized = re.sub(r"^pdf", "pd 256", normalized)
            break

        command_name = normalized.split(maxsplit=1)[0]
        size = int(match.group(1)) if match.group(1) else None
        if command_name == "pd":
            if size is not None and not 1 <= size <= _MAX_RAW_R2_INSTRUCTIONS:
                raise ValidationError(
                    f"pd instruction count must be between 1 and {_MAX_RAW_R2_INSTRUCTIONS}"
                )
            if size is None:
                normalized = re.sub(r"^pd(?=\s|$)", "pd 256", normalized)
        elif command_name == "px":
            if size is not None and not 1 <= size <= _MAX_RAW_R2_READ_BYTES:
                raise ValidationError(
                    f"px byte count must be between 1 and {_MAX_RAW_R2_READ_BYTES}"
                )
            if size is None:
                normalized = re.sub(r"^px(?=\s|$)", "px 256", normalized)
        elif command_name == "ps":
            if size is not None and not 1 <= size <= _MAX_RAW_R2_READ_BYTES:
                raise ValidationError(
                    f"ps byte count must be between 1 and {_MAX_RAW_R2_READ_BYTES}"
                )
            if size is None:
                normalized = re.sub(r"^ps(?=\s|$)", "ps 512", normalized)
        break
    else:
        # Bounded metadata queries used by normal analysis workflows.
        if re.fullmatch(r"(?:afl|aflj|iI|ij|ie|iS|is|iz|ii)", normalized):
            return normalized
        if re.fullmatch(r"ii\s+~[A-Za-z0-9_.-]{1,128}", normalized):
            return normalized
        if re.fullmatch(rf"axt\s+(?:{_SAFE_R2_ADDRESS}|@\s*{_SAFE_R2_ADDRESS})", normalized):
            return normalized
        if re.fullmatch(rf"s\s+{_SAFE_R2_ADDRESS}", normalized):
            return normalized
        raise ValidationError(
            "Command is not in the read-only Radare2 allowlist or has an unsafe operand"
        )

    # Keep the output cap effective even when a metadata command returns an
    # unusually large result. Command-specific byte/instruction limits above
    # also bound commands that read directly from the sample.
    return normalized


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

    Includes asyncio.Lock for thread-safe command execution in async contexts.
    """

    def __init__(self, file_path: str | None = None):
        self.session_id = str(uuid.uuid4())
        self.file_path = file_path
        self._r2: Any = None  # r2pipe.open_sync when available
        self._analyzed = False
        self.created_at = datetime.now()
        self.status = "initialized"  # initialized, active, error, closed
        self.last_error: str | None = None
        self.retry_count = 0
        # Async lock for safe concurrent command execution
        self._command_lock_obj: asyncio.Lock | None = None
        self._command_lock_loop: asyncio.AbstractEventLoop | None = None

    def open(self, file_path: str, arch: str | None = None, bits: int | None = None) -> bool:
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

            if arch is not None:
                from reversecore_mcp.core.arch_registry import get_arch_init_cmds

                init_cmds = get_arch_init_cmds(arch, bits)
                for init_cmd in init_cmds:
                    self._r2.cmd(init_cmd)

            # Wire R2 extension lifecycle hooks and startup commands (Issue #270)
            try:
                from reversecore_mcp.core.extension_registry import get_extension_registry

                registry = get_extension_registry()
                registry.run_r2_session_open_hooks_sync(file_path, self._r2)
                commands = registry.get_r2_startup_commands(file_path)
                for cmd in commands:
                    try:
                        from reversecore_mcp.core.command_spec import validate_r2_command

                        validated_cmd = validate_r2_command(cmd)
                        self._r2.cmd(validated_cmd)
                    except Exception as exc:
                        logger.error(
                            "Failed to execute R2 startup command '%s' in session for %s: %s",
                            cmd,
                            file_path,
                            exc,
                        )
            except Exception as exc:
                logger.debug("Error running extension session open hooks: %s", exc)

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
                from reversecore_mcp.core.extension_registry import get_extension_registry

                if self.file_path:
                    get_extension_registry().run_r2_session_close_hooks_sync(self.file_path)
            except Exception as exc:
                logger.debug("Error running extension session close hooks: %s", exc)

            try:
                self._r2.quit()
            except Exception as e:
                logger.debug("r2 quit on close: %s", e)
            self._r2 = None
            self.status = "closed"
            self._analyzed = False

    def terminate(self) -> None:
        """Kill a blocked radare2 child process and invalidate this session."""
        if self._r2:
            try:
                from reversecore_mcp.core.extension_registry import get_extension_registry

                if self.file_path:
                    get_extension_registry().run_r2_session_close_hooks_sync(self.file_path)
            except Exception as exc:
                logger.debug("Error running extension session close hooks on terminate: %s", exc)

        r2 = self._r2
        process = getattr(r2, "process", None) if r2 is not None else None
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
            except Exception as e:
                logger.debug("Could not fully reap timed-out radare2 process: %s", e)
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

    @property
    def command_lock(self) -> asyncio.Lock:
        """Get or create the async command lock, ensuring loop safety."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if getattr(self, "_command_lock_obj", None) is None:
            self._command_lock_obj = asyncio.Lock()
            self._command_lock_loop = loop
        elif getattr(self, "_command_lock_loop", None) != loop:
            self._command_lock_obj = asyncio.Lock()
            self._command_lock_loop = loop
        assert self._command_lock_obj is not None
        return self._command_lock_obj

    async def safe_cmd(self, command: str) -> str:
        """
        Execute a radare2 command with session-level locking.

        This method is safe for concurrent async access and prevents
        command interleaving when multiple coroutines use the same session.
        """
        import asyncio

        async with self.command_lock:
            return await asyncio.to_thread(self.cmd, command)

    async def safe_cmdj(self, command: str) -> Any:
        """
        Execute a radare2 JSON command with session-level locking.

        This method is safe for concurrent async access.
        """
        import asyncio

        async with self.command_lock:
            return await asyncio.to_thread(self.cmdj, command)

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
def _compile_regex_cached(pattern: str) -> timeout_regex.Pattern | None:
    """Compile and cache regex pattern."""
    try:
        return timeout_regex.compile(pattern)
    except timeout_regex.error:
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

    timeout_seconds = min(
        _REGEX_MATCH_MAX_TIMEOUT_SECONDS,
        max(_REGEX_MATCH_MIN_TIMEOUT_SECONDS, len(text) / _REGEX_MATCH_CHARS_PER_SECOND),
    )
    deadline = time.monotonic() + timeout_seconds
    filtered = []
    try:
        # Walk the original output without materializing a second list of every
        # line. Keep split("\n") semantics, including empty and trailing lines.
        line_start = 0
        while True:
            newline = text.find("\n", line_start)
            line_end = len(text) if newline == -1 else newline
            line = text[line_start:line_end]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if regex.search(line, timeout=remaining):
                filtered.append(line)
            if newline == -1:
                break
            line_start = newline + 1
    except TimeoutError:
        return f"{_REGEX_MATCH_TIMEOUT_ERROR_PREFIX} (max {timeout_seconds:.1f} seconds)"

    return "\n".join(filtered)


def _is_regex_filter_error(result: str) -> bool:
    """Return whether a filter result reports a timeout or capacity limit."""
    return result.startswith(
        (_REGEX_MATCH_TIMEOUT_ERROR_PREFIX, _REGEX_FILTER_CAPACITY_ERROR_PREFIX)
    )


async def _filter_lines_by_regex_async(text: str, pattern: str) -> str:
    """Filter caller regexes in an isolated worker pool with bounded admission.

    The dedicated executor keeps adversarial filters from occupying the shared
    default executor used by Radare2 I/O and unrelated asynchronous operations.
    Admission is capped so queued jobs cannot retain unbounded Radare2 output.
    """
    if not _REGEX_FILTER_CAPACITY.acquire(blocking=False):
        return f"{_REGEX_FILTER_CAPACITY_ERROR_PREFIX} (retry after current filters finish)"

    try:
        future = _REGEX_FILTER_EXECUTOR.submit(_filter_lines_by_regex, text, pattern)
    except Exception:
        _REGEX_FILTER_CAPACITY.release()
        raise

    future.add_done_callback(lambda _: _REGEX_FILTER_CAPACITY.release())
    # Keep the admission slot until the executor work item actually finishes.
    # If the request task is cancelled, cancelling the wrapped future could mark
    # a queued job done while its arguments remain in ThreadPoolExecutor's queue.
    return await asyncio.shield(asyncio.wrap_future(future))


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
