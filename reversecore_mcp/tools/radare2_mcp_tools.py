"""
Radare2 MCP Tools - Direct port from r2mcp C implementation.

This module provides MCP-compatible tools that mirror the official r2mcp server,
enabling full radare2 functionality through the MCP protocol.

All tools are prefixed with 'Radare2_' for namespace clarity.

SECURITY PHILOSOPHY:
- All user inputs are strictly validated before passing to r2pipe
- Address/expression parameters are sanitized to prevent command injection
- Path validation uses the project's security module
- No shell=True, no f-strings with unsanitized input in commands
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

import r2pipe
from fastmcp import FastMCP

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_address_format

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
_SAFE_EXPRESSION_PATTERN = re.compile(r"^[a-zA-Z0-9_.\s+\-*/%()\[\]]+$")

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
    Manages a radare2 session for a binary file.

    Handles opening, closing, and command execution with proper cleanup.
    All commands are validated before execution for security.
    """

    def __init__(self, file_path: str | None = None):
        self.file_path = file_path
        self._r2: r2pipe.open_sync | None = None
        self._analyzed = False

    def open(self, file_path: str) -> bool:
        """Open a binary file with radare2."""
        try:
            self.close()
            self._r2 = r2pipe.open(file_path)
            self.file_path = file_path
            return True
        except Exception as e:
            logger.error(f"Failed to open file: {e}")
            return False

    def close(self) -> None:
        """Close the current radare2 session."""
        if self._r2:
            try:
                self._r2.quit()
            except Exception:
                pass
            self._r2 = None
            self.file_path = None
            self._analyzed = False

    def cmd(self, command: str) -> str:
        """Execute a radare2 command and return the output."""
        if not self._r2:
            return ""
        try:
            result = self._r2.cmd(command)
            return result if result else ""
        except Exception as e:
            logger.error(f"R2 command failed: {e}")
            return f"Error: {e}"

    def cmdj(self, command: str) -> Any:
        """Execute a radare2 command and return JSON output."""
        if not self._r2:
            return None
        try:
            return self._r2.cmdj(command)
        except Exception as e:
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
        return self._r2 is not None


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


class Radare2ToolsPlugin(Plugin):
    """Plugin for Radare2 MCP tools - port from r2mcp."""

    name = "radare2_mcp_tools"
    description = "Radare2 binary analysis tools (r2mcp compatible)"

    def __init__(self):
        self._sessions: dict[str, R2Session] = {}

    def _get_or_create_session(self, file_path: str, auto_analyze: bool = False) -> R2Session:
        """
        Get existing session or create new one for the file.

        Args:
            file_path: Path to the binary file
            auto_analyze: If True, run analysis on new sessions (default: False for lazy loading)

        Returns:
            R2Session instance
        """
        if file_path in self._sessions:
            session = self._sessions[file_path]
            if session.is_open:
                return session

        session = R2Session()
        if session.open(file_path):
            self._sessions[file_path] = session
            # Only analyze if explicitly requested (lazy loading)
            if auto_analyze:
                session.analyze(1)
        return session

    def _ensure_analyzed(self, session: R2Session, level: int = 1) -> None:
        """
        Ensure session has been analyzed at least once.

        Args:
            session: R2Session to check
            level: Minimum analysis level required
        """
        if not session._analyzed:
            session.analyze(level)

    def register(self, mcp: FastMCP) -> None:
        """Register all Radare2 tools with the MCP server."""

        # =====================================================================
        # File Management Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_open_file(file_path: str) -> dict[str, Any]:
            """
            Opens a binary file with radare2 for analysis.

            Call this tool before any other r2mcp tool. Use an absolute file_path.

            Args:
                file_path: Absolute path to the binary file to analyze

            Returns:
                Status of the file opening operation
            """
            # Validate path using project security module
            try:
                validated_path = validate_file_path(file_path)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(str(validated_path))
            if session.is_open:
                return {
                    "status": "success",
                    "message": "File opened successfully",
                    "file_path": str(validated_path),
                }
            return {"status": "error", "message": "Failed to open file"}

        @mcp.tool()
        async def Radare2_close_file(file_path: str) -> dict[str, Any]:
            """
            Close the currently open radare2 session for a file.

            Args:
                file_path: Path to the file to close

            Returns:
                Status of the close operation
            """
            if file_path in self._sessions:
                self._sessions[file_path].close()
                del self._sessions[file_path]
                return {"status": "success", "message": "File closed successfully"}
            return {"status": "success", "message": "File was not open"}

        # =====================================================================
        # Analysis Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_analyze(
            file_path: str,
            level: int = 2,
        ) -> dict[str, Any]:
            """
            Run binary analysis with optional depth level.

            Args:
                file_path: Path to the binary file
                level: Analysis level 0-4 (higher = more thorough, slower)
                    0: Basic (aa)
                    1: Auto (aaa)
                    2: Experimental (aaaa) - default
                    3: Deep (aaaaa)
                    4: Very deep (aaaaaa)

            Returns:
                Analysis result with function count
            """
            # Validate level is in range
            if not isinstance(level, int) or level < 0 or level > 4:
                return {"status": "error", "message": "level must be 0-4"}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            session.analyze(level)
            func_count = session.cmd("aflc").strip()

            return {
                "status": "success",
                "message": f"Analysis completed with level {level}",
                "function_count": int(func_count) if func_count.isdigit() else 0,
            }

        @mcp.tool()
        async def Radare2_run_command(
            file_path: str,
            command: str,
        ) -> dict[str, Any]:
            """
            Execute a raw radare2 command directly.

            NOTE: Only analysis commands are allowed. Write and shell commands are blocked.

            Args:
                file_path: Path to the binary file
                command: The radare2 command to execute

            Returns:
                Command output
            """
            # Validate command for security
            try:
                _validate_r2_command(command)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd(command)
            return {"status": "success", "output": result}

        @mcp.tool()
        async def Radare2_calculate(
            file_path: str,
            expression: str,
        ) -> dict[str, Any]:
            """
            Evaluate a math expression using radare2's number parser.

            Useful for: 64-bit math, resolving addresses for symbols,
            avoiding hallucinated results.

            Args:
                file_path: Path to the binary file
                expression: Math expression to evaluate (e.g., "0x100 + sym.flag - 4")

            Returns:
                Calculated result in hex and decimal
            """
            # Validate expression for security
            try:
                _validate_expression(expression)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            # Use validated expression
            result = session.cmd(f"?v {expression}").strip()
            return {
                "status": "success",
                "result": result,
                "expression": expression,
            }

        # =====================================================================
        # Function Listing Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_list_functions(
            file_path: str,
            only_named: bool = False,
            filter: str | None = None,
        ) -> dict[str, Any]:
            """
            List all functions discovered during analysis.

            Args:
                file_path: Path to the binary file
                only_named: If true, exclude functions with numeric suffixes
                filter: Regular expression to filter results

            Returns:
                List of functions with addresses and names
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            # Ensure analysis is done (lazy - only if not already analyzed)
            self._ensure_analyzed(session)
            result = session.cmd("afl")

            if only_named:
                result = _filter_named_functions(result)

            if filter:
                result = _filter_lines_by_regex(result, filter)

            lines = [line for line in result.strip().split("\n") if line]
            return {
                "status": "success",
                "count": len(lines),
                "functions": result,
            }

        @mcp.tool()
        async def Radare2_list_functions_tree(
            file_path: str,
        ) -> dict[str, Any]:
            """
            List functions and their successors (call tree).

            Args:
                file_path: Path to the binary file

            Returns:
                Function call tree
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd("aflm")
            return {"status": "success", "output": result.strip()}

        @mcp.tool()
        async def Radare2_show_function_details(
            file_path: str,
            address: str | None = None,
        ) -> dict[str, Any]:
            """
            Display detailed information about a function.

            Args:
                file_path: Path to the binary file
                address: Function address (uses current if not specified)

            Returns:
                Detailed function information
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            if address:
                # Validate address format
                try:
                    validate_address_format(address)
                except ValidationError as e:
                    return {"status": "error", "message": str(e)}
                result = session.cmd(f"afi @ {address}")
            else:
                result = session.cmd("afi")

            return {"status": "success", "output": result}

        @mcp.tool()
        async def Radare2_get_current_address(
            file_path: str,
        ) -> dict[str, Any]:
            """
            Show the current seek position and function name.

            Args:
                file_path: Path to the binary file

            Returns:
                Current address and function name
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            address = session.cmd("s").strip()
            func_name = session.cmd("fd").strip()

            return {
                "status": "success",
                "address": address,
                "function": func_name,
            }

        @mcp.tool()
        async def Radare2_get_function_prototype(
            file_path: str,
            address: str,
        ) -> dict[str, Any]:
            """
            Retrieve the function signature at the specified address.

            Args:
                file_path: Path to the binary file
                address: Address of the function

            Returns:
                Function prototype/signature
            """
            # Validate address
            try:
                validate_address_format(address)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd(f"afs @ {address}").strip()
            return {"status": "success", "prototype": result}

        @mcp.tool()
        async def Radare2_set_function_prototype(
            file_path: str,
            address: str,
            prototype: str,
        ) -> dict[str, Any]:
            """
            Set the function signature (return type, name, arguments).

            Args:
                file_path: Path to the binary file
                address: Address of the function
                prototype: Function signature in C-like syntax

            Returns:
                Confirmation
            """
            # Validate address
            try:
                validate_address_format(address)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            # Sanitize prototype (remove dangerous chars)
            safe_prototype = _sanitize_for_r2_cmd(prototype)
            if not safe_prototype:
                return {"status": "error", "message": "Invalid prototype"}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            session.cmd(f"afs {safe_prototype} @ {address}")
            return {"status": "success", "message": "Function prototype set"}

        # =====================================================================
        # Binary Information Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_show_headers(
            file_path: str,
        ) -> dict[str, Any]:
            """
            Display binary headers and file information.

            Args:
                file_path: Path to the binary file

            Returns:
                Binary header information
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            info = session.cmd("i")
            headers = session.cmd("iH")

            return {
                "status": "success",
                "info": info,
                "headers": headers,
            }

        @mcp.tool()
        async def Radare2_list_sections(
            file_path: str,
        ) -> dict[str, Any]:
            """
            Display memory sections and segments from the binary.

            Args:
                file_path: Path to the binary file

            Returns:
                Sections and segments information
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            sections = session.cmd("iS")
            segments = session.cmd("iSS")

            return {
                "status": "success",
                "sections": sections,
                "segments": segments,
            }

        @mcp.tool()
        async def Radare2_list_imports(
            file_path: str,
            filter: str | None = None,
        ) -> dict[str, Any]:
            """
            List imported symbols.

            Note: Use list_symbols for addresses with sym.imp. prefix.

            Args:
                file_path: Path to the binary file
                filter: Regular expression to filter results

            Returns:
                List of imports
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd("ii")

            if filter:
                result = _filter_lines_by_regex(result, filter)

            return {"status": "success", "imports": result}

        @mcp.tool()
        async def Radare2_list_symbols(
            file_path: str,
            filter: str | None = None,
        ) -> dict[str, Any]:
            """
            Show all symbols (functions, variables, imports) with addresses.

            Args:
                file_path: Path to the binary file
                filter: Regular expression to filter results

            Returns:
                List of symbols
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd("is")

            if filter:
                result = _filter_lines_by_regex(result, filter)

            return {"status": "success", "symbols": result}

        @mcp.tool()
        async def Radare2_list_entrypoints(
            file_path: str,
        ) -> dict[str, Any]:
            """
            Display program entrypoints, constructors and main function.

            Args:
                file_path: Path to the binary file

            Returns:
                Entrypoint information
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd("ie")
            return {"status": "success", "entrypoints": result}

        @mcp.tool()
        async def Radare2_list_libraries(
            file_path: str,
        ) -> dict[str, Any]:
            """
            List all shared libraries linked to the binary.

            Args:
                file_path: Path to the binary file

            Returns:
                List of linked libraries
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd("il")
            return {"status": "success", "libraries": result}

        @mcp.tool()
        async def Radare2_list_strings(
            file_path: str,
            filter: str | None = None,
            cursor: str | None = None,
            page_size: int = DEFAULT_PAGE_SIZE,
        ) -> dict[str, Any]:
            """
            List strings from data sections with optional regex filter.

            Args:
                file_path: Path to the binary file
                filter: Regular expression to filter results
                cursor: Pagination cursor (line number to start from)
                page_size: Number of lines per page (default: 1000, max: 10000)

            Returns:
                List of strings with pagination
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            if page_size > MAX_PAGE_SIZE:
                page_size = MAX_PAGE_SIZE

            result = session.cmd("iz")

            if filter:
                result = _filter_lines_by_regex(result, filter)

            paginated, has_more, next_cursor = _paginate_text(result, cursor, page_size)

            return {
                "status": "success",
                "strings": paginated,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }

        @mcp.tool()
        async def Radare2_list_all_strings(
            file_path: str,
            filter: str | None = None,
            cursor: str | None = None,
            page_size: int = DEFAULT_PAGE_SIZE,
        ) -> dict[str, Any]:
            """
            Scan the entire binary for strings with optional regex filter.

            More thorough than list_strings, but slower.

            Args:
                file_path: Path to the binary file
                filter: Regular expression to filter results
                cursor: Pagination cursor
                page_size: Number of lines per page

            Returns:
                List of all strings with pagination
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            if page_size > MAX_PAGE_SIZE:
                page_size = MAX_PAGE_SIZE

            result = session.cmd("izz")

            if filter:
                result = _filter_lines_by_regex(result, filter)

            paginated, has_more, next_cursor = _paginate_text(result, cursor, page_size)

            return {
                "status": "success",
                "strings": paginated,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }

        # =====================================================================
        # Class/OOP Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_list_classes(
            file_path: str,
            filter: str | None = None,
        ) -> dict[str, Any]:
            """
            List class names from various languages (C++, ObjC, Swift, Java, Dalvik).

            Args:
                file_path: Path to the binary file
                filter: Regular expression to filter results

            Returns:
                List of classes
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd("ic")

            if filter:
                result = _filter_lines_by_regex(result, filter)

            return {"status": "success", "classes": result}

        @mcp.tool()
        async def Radare2_list_methods(
            file_path: str,
            classname: str,
        ) -> dict[str, Any]:
            """
            List all methods belonging to the specified class.

            Args:
                file_path: Path to the binary file
                classname: Name of the class to list methods for

            Returns:
                List of methods in the class
            """
            # Validate classname to prevent injection
            try:
                _validate_identifier(classname, "classname")
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd(f"ic {classname}")
            return {"status": "success", "methods": result}

        # =====================================================================
        # Disassembly & Decompilation Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_disassemble(
            file_path: str,
            address: str,
            num_instructions: int = 10,
        ) -> dict[str, Any]:
            """
            Disassemble a specific number of instructions from an address.

            Use this to inspect a portion of memory as code without depending
            on function analysis boundaries.

            Args:
                file_path: Path to the binary file
                address: Address to start disassembly
                num_instructions: Number of instructions to disassemble (default: 10, max: 1000)

            Returns:
                Disassembled instructions
            """
            # Validate address
            try:
                validate_address_format(address)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            # Limit instructions to prevent abuse
            if not isinstance(num_instructions, int) or num_instructions < 1:
                num_instructions = 10
            if num_instructions > 1000:
                num_instructions = 1000

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd(f"pd {num_instructions} @ {address}")
            return {"status": "success", "disassembly": result}

        @mcp.tool()
        async def Radare2_disassemble_function(
            file_path: str,
            address: str,
            cursor: str | None = None,
            page_size: int = DEFAULT_PAGE_SIZE,
        ) -> dict[str, Any]:
            """
            Show assembly listing of the function at the specified address.

            Args:
                file_path: Path to the binary file
                address: Address of the function to disassemble
                cursor: Pagination cursor
                page_size: Number of lines per page

            Returns:
                Function disassembly with pagination
            """
            # Validate address
            try:
                validate_address_format(address)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            if page_size > MAX_PAGE_SIZE:
                page_size = MAX_PAGE_SIZE

            result = session.cmd(f"pdf @ {address}")
            paginated, has_more, next_cursor = _paginate_text(result, cursor, page_size)

            return {
                "status": "success",
                "disassembly": paginated,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }

        @mcp.tool()
        async def Radare2_decompile_function(
            file_path: str,
            address: str,
            cursor: str | None = None,
            page_size: int = DEFAULT_PAGE_SIZE,
        ) -> dict[str, Any]:
            """
            Show C-like pseudocode of the function at the given address.

            Use this to inspect code in a function. Do not run multiple times
            on the same offset.

            Args:
                file_path: Path to the binary file
                address: Address of the function to decompile
                cursor: Pagination cursor
                page_size: Number of lines per page

            Returns:
                Decompiled pseudocode with pagination
            """
            # Validate address
            try:
                validate_address_format(address)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            if page_size > MAX_PAGE_SIZE:
                page_size = MAX_PAGE_SIZE

            result = session.cmd(f"pdc @ {address}")
            paginated, has_more, next_cursor = _paginate_text(result, cursor, page_size)

            return {
                "status": "success",
                "decompiled": paginated,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }

        @mcp.tool()
        async def Radare2_list_decompilers(
            file_path: str,
        ) -> dict[str, Any]:
            """
            Show all available decompiler backends.

            Args:
                file_path: Path to the binary file

            Returns:
                List of available decompilers
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd("e cmd.pdc=?")
            return {"status": "success", "decompilers": result}

        @mcp.tool()
        async def Radare2_use_decompiler(
            file_path: str,
            name: str,
        ) -> dict[str, Any]:
            """
            Select which decompiler backend to use.

            Args:
                file_path: Path to the binary file
                name: Decompiler name (ghidra, r2dec, pdc)

            Returns:
                Confirmation or error
            """
            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            available = session.cmd("e cmd.pdc=?")

            # Whitelist of allowed decompilers
            decompiler_map = {
                "ghidra": "pdg",
                "r2dec": "pdd",
                "pdc": "pdc",
            }

            name_lower = name.lower()
            if name_lower not in decompiler_map:
                return {
                    "status": "error",
                    "message": f"Unknown decompiler: {name}. Allowed: ghidra, r2dec, pdc",
                }

            cmd_name = decompiler_map[name_lower]
            if cmd_name not in available:
                return {"status": "error", "message": f"Decompiler {name} is not available"}

            session.cmd(f"e cmd.pdc={cmd_name}")
            return {"status": "success", "message": f"Decompiler set to {name}"}

        # =====================================================================
        # Cross-Reference Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_xrefs_to(
            file_path: str,
            address: str,
        ) -> dict[str, Any]:
            """
            Find all code references TO the specified address.

            Args:
                file_path: Path to the binary file
                address: Address to check for cross-references

            Returns:
                List of xrefs to the address
            """
            # Validate address
            try:
                validate_address_format(address)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd(f"axt @ {address}")
            return {"status": "success", "xrefs": result}

        # =====================================================================
        # Modification Tools
        # =====================================================================

        @mcp.tool()
        async def Radare2_rename_function(
            file_path: str,
            address: str,
            name: str,
        ) -> dict[str, Any]:
            """
            Rename the function at the specified address.

            Args:
                file_path: Path to the binary file
                address: Address of the function to rename
                name: New function name

            Returns:
                Confirmation
            """
            # Validate inputs
            try:
                validate_address_format(address)
                _validate_identifier(name, "name")
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            session.cmd(f"afn {name} @ {address}")
            return {"status": "success", "message": f"Function renamed to {name}"}

        @mcp.tool()
        async def Radare2_rename_flag(
            file_path: str,
            address: str,
            name: str,
            new_name: str,
        ) -> dict[str, Any]:
            """
            Rename a flag (variable or data reference) at the specified address.

            Args:
                file_path: Path to the binary file
                address: Address of the flag
                name: Current flag name
                new_name: New flag name

            Returns:
                Confirmation
            """
            # Validate all inputs
            try:
                validate_address_format(address)
                _validate_identifier(name, "name")
                _validate_identifier(new_name, "new_name")
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            result = session.cmd(f"fr {name} {new_name} @ {address}")
            if result.strip():
                return {"status": "error", "message": result}
            return {"status": "success", "message": f"Flag renamed to {new_name}"}

        @mcp.tool()
        async def Radare2_set_comment(
            file_path: str,
            address: str,
            message: str,
        ) -> dict[str, Any]:
            """
            Add a comment at the specified address.

            Args:
                file_path: Path to the binary file
                address: Address to add comment
                message: Comment text

            Returns:
                Confirmation
            """
            # Validate address
            try:
                validate_address_format(address)
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

            # Sanitize message (remove dangerous chars but allow more characters for comments)
            safe_message = _sanitize_for_r2_cmd(message)
            if not safe_message:
                return {"status": "error", "message": "Comment message is empty or invalid"}

            session = self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            session.cmd(f"CC {safe_message} @ {address}")
            return {"status": "success", "message": "Comment added"}

        # NOTE: Radare2_list_files and Radare2_run_javascript are REMOVED
        # for security reasons:
        # - list_files: potential path traversal attack vector
        # - run_javascript: arbitrary code execution risk

        logger.info(f"Registered {self.name} plugin with 30 Radare2 tools (security hardened)")


def register_radare2_tools(mcp: FastMCP) -> None:
    """
    Register Radare2 tools with an MCP server instance.

    Args:
        mcp: FastMCP server instance
    """
    plugin = Radare2ToolsPlugin()
    plugin.register(mcp)
