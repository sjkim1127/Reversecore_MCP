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

import asyncio
import os
import shutil
from typing import Any

from fastmcp import FastMCP

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_address_format

# Import session management and utilities from r2_session module
from reversecore_mcp.tools.radare2.r2_session import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    R2Session,
    _filter_lines_by_regex,
    _filter_named_functions,
    _paginate_text,
    _sanitize_for_r2_cmd,
    _validate_expression,
    _validate_identifier,
    _validate_r2_command,
)

logger = get_logger(__name__)

# Default configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout


class Radare2ToolsPlugin(Plugin):
    """Plugin for Radare2 MCP tools - port from r2mcp."""

    name = "radare2_mcp_tools"
    description = "Radare2 binary analysis tools (r2mcp compatible)"

    def __init__(self):
        self._sessions: dict[str, R2Session] = {}  # session_id -> Session
        self._file_to_session: dict[str, str] = {}  # file_path -> session_id
        self._lock = asyncio.Lock()  # Protects session creation race conditions

    def _diagnose_error(self, file_path: str, error: Exception) -> dict[str, Any]:
        """Diagnose why r2 failed to open a file."""
        diagnosis = {
            "error": str(error),
            "file_exists": os.path.exists(file_path),
            "is_file": os.path.isfile(file_path) if os.path.exists(file_path) else False,
            "permissions": oct(os.stat(file_path).st_mode)[-3:]
            if os.path.exists(file_path)
            else "N/A",
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "r2_available": shutil.which("radare2") is not None,
            "hints": [],
        }

        if not diagnosis["file_exists"]:
            diagnosis["hints"].append(
                "Check if the file path is correct (relative to /app/workspace?)"
            )
        elif not diagnosis["is_file"]:
            diagnosis["hints"].append("Path exists but is not a file (directory?)")
        elif diagnosis["file_size"] == 0:
            diagnosis["hints"].append("File is empty (0 bytes)")

        return diagnosis

    async def _get_or_create_session(self, file_path: str, auto_analyze: bool = False) -> R2Session:
        """
        Get existing session or create new one with strict validation.
        Protected by lock to prevent race conditions.
        """
        # 1. Normalize Path
        try:
            validated_path = validate_file_path(file_path)
            file_path = str(validated_path)
        except ValidationError:
            return R2Session(file_path)

        async with self._lock:
            # 2. Check existing session (double-checked locking pattern)
            if file_path in self._file_to_session:
                sid = self._file_to_session[file_path]
                if sid in self._sessions:
                    session = self._sessions[sid]
                    if session.is_open:
                        return session
                    else:
                        # Stale session, remove it
                        del self._sessions[sid]
                        del self._file_to_session[file_path]

            # 3. Create new session (blocking I/O wrapped in thread)
            try:
                # Validate file availability again inside lock
                if not os.path.exists(file_path):
                    raise ValueError(f"File not found: {file_path}")

                # Use to_thread for blocking R2 spawning
                session = await asyncio.to_thread(R2Session, file_path)

                # 4. Store session
                self._sessions[session.session_id] = session
                self._file_to_session[file_path] = session.session_id

                # 5. Auto analyze if requested
                if auto_analyze:
                    # Async analysis call (assuming session.analyze is async or needs wrapping)
                    # For now, R2Session methods are sync, so we wrap them
                    await asyncio.to_thread(session.cmd, "aaa")

                return session

            except Exception as e:
                logger.error(f"Failed to create R2 session for {file_path}: {e}")
                # Raise exception instead of returning dummy session that may also fail
                from reversecore_mcp.core.exceptions import ToolExecutionError

                raise ToolExecutionError(f"Cannot open file with radare2: {file_path}") from e

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
                Status of the file opening operation, including session_id
            """
            # Validate path using project security module
            try:
                validated_path = validate_file_path(file_path)
                abs_path = str(validated_path)
            except ValidationError as e:
                return {"status": "error", "message": str(e), "error_code": "INVALID_PATH"}

            session = await self._get_or_create_session(abs_path)

            if session.is_open:
                return {
                    "status": "success",
                    "message": "File opened successfully",
                    "file_path": abs_path,
                    "session_id": session.session_id,
                    "file_size": os.path.getsize(abs_path) if os.path.exists(abs_path) else 0,
                    "status_code": "OPENED",
                }

            # Diagnose failure
            diagnosis = self._diagnose_error(
                abs_path, Exception(session.last_error or "Unknown error")
            )
            return {
                "status": "error",
                "message": f"Failed to open file: {session.last_error}",
                "error_code": "R2_OPEN_FAILED",
                "diagnosis": diagnosis,
                "hints": diagnosis["hints"],
                "attempts": 1,
            }

        @mcp.tool()
        async def Radare2_close_file(file_path: str) -> dict[str, Any]:
            """
            Close the currently open radare2 session for a file.

            Args:
                file_path: Path to the file to close

            Returns:
                Status of the close operation
            """
            try:
                validated_path = validate_file_path(file_path)
                abs_path = str(validated_path)

                # Check mapping
                if abs_path in self._file_to_session:
                    sid = self._file_to_session[abs_path]
                    if sid in self._sessions:
                        self._sessions[sid].close()
                        del self._sessions[sid]
                    del self._file_to_session[abs_path]
                    return {
                        "status": "success",
                        "message": "File closed successfully",
                        "session_id": sid,
                    }

                return {"status": "success", "message": "File was not open (no active session)"}
            except ValidationError as e:
                return {"status": "error", "message": str(e)}

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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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
            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
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

            session = await self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            session.cmd(f"CC {safe_message} @ {address}")
            return {"status": "success", "message": "Comment added"}

        # NOTE: Radare2_list_files and Radare2_run_javascript are REMOVED
        # for security reasons:
        # - list_files: potential path traversal attack vector
        # - run_javascript: arbitrary code execution risk

        # =====================================================================
        # Advanced Analysis Tools (from r2_analysis module)
        # =====================================================================
        # Import and register advanced analysis tools for unified plugin management
        from reversecore_mcp.tools.radare2.r2_analysis import (
            analyze_xrefs,
            generate_function_graph,
            run_radare2,
            trace_execution_path,
        )

        mcp.tool(run_radare2)
        mcp.tool(trace_execution_path)
        mcp.tool(generate_function_graph)
        mcp.tool(analyze_xrefs)

        logger.info(f"Registered {self.name} plugin with 34 Radare2 tools (security hardened)")


def register_radare2_tools(mcp: FastMCP) -> None:
    """
    Register Radare2 tools with an MCP server instance.

    Args:
        mcp: FastMCP server instance
    """
    plugin = Radare2ToolsPlugin()
    plugin.register(mcp)
