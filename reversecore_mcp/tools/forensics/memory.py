"""Memory forensics tools backed by Volatility3.

All heavy Volatility3 operations are enqueued via the ARQ task queue
with Redis caching to avoid redundant re-analysis of the same dump.
"""

import asyncio
import re
import shutil
import subprocess  # nosec B404
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_lines_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path

logger = get_logger(__name__)
_MAX_MEMORY_DUMP_BYTES = 512 * 1024 * 1024
_MAX_STRING_LINE_BYTES = 65_536
_MAX_RETURNED_STRINGS = 10_000


class _StringSummary:
    """Accumulate bounded memory-string results and notable indicators."""

    def __init__(self, limit: int, max_result_bytes: int) -> None:
        self.limit = min(max(limit, 0), _MAX_RETURNED_STRINGS)
        self.max_result_bytes = max_result_bytes
        self.strings: list[str] = []
        self.string_count = 0
        self.returned_bytes = 0
        self.truncated = False
        self._ips_seen: set[str] = set()
        self.ips: list[str] = []
        self.urls: list[str] = []
        self._ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self._url_pattern = re.compile(r"https?://[^\s]{8,}")
        self._url_bytes = 0

    def add(self, value: str, line_truncated: bool = False) -> None:
        """Count one extracted string, retaining only bounded result data."""
        if not value and not line_truncated:
            return
        self.string_count += 1
        if line_truncated:
            self.truncated = True

        encoded_size = len(value.encode("utf-8", errors="replace"))
        if (
            not line_truncated
            and len(self.strings) < self.limit
            and self.returned_bytes + encoded_size <= self.max_result_bytes
        ):
            self.strings.append(value)
            self.returned_bytes += encoded_size
        else:
            self.truncated = True

        for ip in self._ip_pattern.findall(value):
            if ip not in self._ips_seen and len(self.ips) < 50:
                self._ips_seen.add(ip)
                self.ips.append(ip)
        if len(self.urls) < 50 and self._url_pattern.search(value):
            if self._url_bytes + encoded_size <= self.max_result_bytes:
                self.urls.append(value)
                self._url_bytes += encoded_size


def _iter_ascii_strings(
    path: Path,
    min_length: int,
    *,
    chunk_size: int = 65_536,
) -> Iterator[tuple[str, bool]]:
    """Yield bounded ASCII strings from a file without reading it all at once."""
    pattern = re.compile(rb"[\x20-\x7E]+")
    carry = b""
    carry_length = 0
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            data = carry + chunk
            trailing_match = False
            for match in pattern.finditer(data):
                starts_with_carry = bool(carry) and match.start() == 0
                string_length = match.end() - match.start()
                if starts_with_carry:
                    string_length = carry_length + match.end() - len(carry)
                string_bytes = data[match.start() : match.end()]
                if match.end() == len(data):
                    carry = string_bytes[:_MAX_STRING_LINE_BYTES]
                    carry_length = string_length
                    trailing_match = True
                    continue
                if string_length >= min_length:
                    yield (
                        string_bytes[:_MAX_STRING_LINE_BYTES].decode("ascii", errors="replace"),
                        string_length > _MAX_STRING_LINE_BYTES,
                    )
            if not trailing_match:
                carry = b""
                carry_length = 0

    if carry_length >= min_length:
        yield (
            carry.decode("ascii", errors="replace"),
            carry_length > _MAX_STRING_LINE_BYTES,
        )


# Supported Volatility3 plugins
_SUPPORTED_PLUGINS: dict[str, str] = {
    "windows.pslist": "List all running Windows processes",
    "windows.pstree": "Display the Windows process tree",
    "windows.psscan": "Scan for EPROCESS structures (finds hidden processes)",
    "windows.netscan": "Scan for Windows network connections",
    "windows.malfind": "Detect injected code / suspicious Windows memory regions",
    "windows.dlllist": "List DLLs loaded by Windows processes",
    "windows.handles": "List open handles per Windows process",
    "windows.cmdline": "Extract command-line arguments for Windows processes",
    "windows.filescan": "Scan for Windows FILE_OBJECT structures",
    "windows.hivelist": "List Windows registry hives",
    "windows.hashdump": "Dump Windows password hashes from registry",
    "windows.lsadump": "Dump Windows LSA secrets",
    "linux.pslist": "Linux process list",
    "linux.bash": "Recover bash history from memory",
    "mac.pslist": "macOS process list",
}
_PLUGIN_NAMESPACES = ("windows.", "linux.", "mac.", "banners.")


def _plugin_namespace_error(plugin: str) -> str | None:
    """Describe why an unqualified or unsupported Volatility plugin is invalid."""
    if plugin.startswith(_PLUGIN_NAMESPACES):
        return None

    matching_plugins = [
        supported for supported in _SUPPORTED_PLUGINS if supported.endswith(f".{plugin}")
    ]
    if matching_plugins:
        return (
            f"Plugin '{plugin}' is not OS-qualified. Choose one of: {', '.join(matching_plugins)}."
        )
    return f"Plugin '{plugin}' must use an OS-qualified name such as 'windows.pslist'."


def _is_unsupported_volatility_option(error: RuntimeError, option: str) -> bool:
    """Return whether Volatility rejected an option as unsupported by its CLI."""
    message = str(error).lower()
    return option.lower() in message and any(
        marker in message
        for marker in ("unrecognized arguments", "unknown option", "no such option")
    )


def _remove_empty_output_dir(path: Path | None) -> None:
    """Remove an unused per-run output directory without touching its parent."""
    if path is None:
        return
    try:
        path.rmdir()
    except OSError:
        pass


def _run_vol3(
    dump_path: str,
    plugin: str,
    extra_args: list[str] | None = None,
    *,
    global_args: list[str] | None = None,
) -> dict[str, Any]:
    """Run a Volatility3 plugin against a memory dump.

    Args:
        dump_path: Path to the memory dump file.
        plugin: OS-qualified Volatility3 plugin name (e.g., 'windows.pslist').
        extra_args: Additional arguments to pass to the plugin.
        global_args: Volatility3 CLI arguments placed before the plugin name.

    Returns:
        Dictionary with plugin output or error information.

    Raises:
        FileNotFoundError: If volatility3 (vol.py / vol3) is not installed.
        subprocess.TimeoutExpired: If the plugin exceeds the execution timeout.
    """
    namespace_error = _plugin_namespace_error(plugin)
    if namespace_error:
        raise ValueError(namespace_error)

    cmd = ["vol", "-f", dump_path, "-r", "json"]
    if global_args:
        cmd.extend(global_args)
    cmd.append(plugin)
    if extra_args:
        cmd.extend(extra_args)

    resolved_exe = shutil.which(cmd[0])
    if not resolved_exe:
        raise FileNotFoundError("vol is not installed or not in PATH")

    result = subprocess.run(  # nosec B603
        [resolved_exe] + cmd[1:],
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        # vol returns non-zero on symbol table issues — still try to parse output
        stderr = result.stderr.strip()
        if result.stdout.strip():
            # Partial output available
            logger.warning("Volatility3 non-zero exit (%d): %s", result.returncode, stderr)
        else:
            raise RuntimeError(f"Volatility3 error (exit {result.returncode}): {stderr}")

    output = result.stdout.strip()
    if not output:
        return {"rows": [], "plugin": plugin}

    try:
        parsed = json.loads(output)
        return {
            "rows": parsed if isinstance(parsed, list) else [parsed],
            "plugin": plugin,
        }
    except json.JSONDecodeError:
        # Return raw output if JSON parsing fails
        return {"raw_output": output, "plugin": plugin}


async def _run_vol3_async(
    dump_path: str,
    plugin: str,
    extra_args: list[str] | None = None,
    *,
    global_args: list[str] | None = None,
) -> dict[str, Any]:
    """Async wrapper for _run_vol3 to avoid blocking the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _run_vol3(dump_path, plugin, extra_args, global_args=global_args),
    )


@log_execution(tool_name="memory_list_symbols")
@track_metrics("memory_list_symbols")
@handle_tool_errors
async def memory_list_symbols(dump_path: str) -> ToolResult:
    """List available Volatility3 symbol tables for a memory dump.

    Volatility3 requires OS-specific symbol tables (ISF files) to run most plugins.
    Use this tool to inspect which symbol tables are currently available, then load
    the appropriate one using ``memory_load_symbols`` before running analysis plugins.

    Args:
        dump_path: Path to the memory dump file (e.g., .raw, .vmem, .mem).

    Returns:
        ToolResult with a list of available symbol table paths and instructions.

    Example:
        >>> result = await memory_list_symbols("/app/workspace/win10.raw")
        >>> print(result.data["symbol_tables"])
    """
    validated = validate_file_path(dump_path)

    try:
        resolved_exe = shutil.which("vol")
        if not resolved_exe:
            raise FileNotFoundError()

        def run_info():
            return subprocess.run(  # nosec B603
                [resolved_exe, "--info"],
                capture_output=True,
                text=True,
                timeout=30,
            )

        result = await asyncio.to_thread(run_info)
        output = result.stdout + result.stderr
    except FileNotFoundError:
        return failure(
            "DEPENDENCY_MISSING",
            "Volatility3 (vol) is not installed or not in PATH",
            hint="Install with: pip install volatility3",
        )

    # Parse ISF/symbol table lines
    symbol_lines = [
        line.strip()
        for line in output.splitlines()
        if "symbols" in line.lower() or "isf" in line.lower()
    ]

    return success(
        {
            "dump_path": str(validated),
            "symbol_tables": symbol_lines[:50],
            "vol_info": output[:2000],
            "hint": (
                "Use memory_analyze with 'symbol_path' parameter to specify an ISF file. "
                "Default symbol packs are at ~/.local/lib/python*/dist-packages/volatility3/symbols/"
            ),
        }
    )


@log_execution(tool_name="memory_analyze")
@track_metrics("memory_analyze")
@handle_tool_errors
async def memory_analyze(
    dump_path: str,
    plugin: str = "windows.pslist",
    symbol_path: str | None = None,
    extra_args: str | None = None,
    _bypass_queue: bool = False,
) -> ToolResult:
    """Run a Volatility3 plugin against a memory dump file.

    Supports Windows, Linux, and macOS memory dumps. Heavy plugin operations
    (malfind, psscan, netscan) are queued via ARQ for non-blocking execution.

    Args:
        dump_path: Path to the memory dump file (.raw, .vmem, .mem, .dmp).
        plugin: OS-qualified Volatility3 plugin name. Run ``memory_analyze`` with
            plugin='help' to see supported plugins. Bare names such as ``pslist``
            are rejected because they can match plugins from multiple operating systems.
        symbol_path: Optional path to an ISF symbol table file. Required for some
            plugins on unknown OS versions.
        extra_args: Additional plugin arguments as a space-separated string
            (e.g., "--pid 1234").
        _bypass_queue: Internal — set True to skip ARQ queueing.

    Returns:
        ToolResult with plugin output rows or queued job ID.

    Raises:
        ValidationError: If dump_path is not accessible.

    Example:
        >>> result = await memory_analyze(
        ...     "/app/workspace/memdump.raw", plugin="windows.pslist"
        ... )
        >>> print(result.data["rows"])
    """
    if plugin == "help":
        return success({"supported_plugins": _SUPPORTED_PLUGINS, "total": len(_SUPPORTED_PLUGINS)})

    namespace_error = _plugin_namespace_error(plugin)
    if namespace_error:
        is_ambiguous = "not OS-qualified" in namespace_error
        return failure(
            "AMBIGUOUS_PLUGIN" if is_ambiguous else "UNSUPPORTED_PLUGIN",
            namespace_error,
            hint=f"Choose an OS-qualified plugin. Supported plugins: {', '.join(_SUPPORTED_PLUGINS)}. "
            "Pass plugin='help' to list all supported plugins.",
        )

    if not _bypass_queue:
        try:
            from reversecore_mcp.core.task_queue import run_task_or_fallback

            return await run_task_or_fallback(
                "task_memory_analyze",
                memory_analyze,
                dump_path,
                plugin,
                symbol_path,
                extra_args,
                _bypass_queue=True,
            )
        except Exception as exc:
            logger.warning("Task queue unavailable, running directly: %s", exc)

    validated = validate_file_path(dump_path)

    args: list[str] = []
    if symbol_path:
        validated_sym = validate_file_path(symbol_path, read_only=True)
        args.extend(["--symbol-dirs", str(validated_sym.parent)])
    if extra_args:
        args.extend(extra_args.split())

    try:
        data = await _run_vol3_async(str(validated), plugin, args or None)
        return success(
            {
                "dump_path": str(validated),
                "plugin": plugin,
                **data,
            }
        )
    except FileNotFoundError:
        return failure(
            "DEPENDENCY_MISSING",
            "Volatility3 (vol) is not installed or not in PATH",
            hint="Install with: pip install volatility3",
        )
    except subprocess.TimeoutExpired:
        return failure(
            "TIMEOUT",
            f"Volatility3 plugin '{plugin}' timed out after 300 seconds",
            hint="Try a lighter plugin or split analysis into smaller regions.",
        )
    except RuntimeError as exc:
        return failure("VOLATILITY_ERROR", str(exc))


@log_execution(tool_name="memory_list_processes")
@track_metrics("memory_list_processes")
@handle_tool_errors
async def memory_list_processes(
    dump_path: str,
    include_hidden: bool = True,
) -> ToolResult:
    """List Windows processes from a memory dump.

    Args:
        dump_path: Path to the memory dump file.
        include_hidden: If True, also run psscan to detect hidden/unlinked processes.
            Hidden processes may indicate rootkits or process injection.

    Returns:
        ToolResult with process list and optional hidden process scan results.

    Example:
        >>> result = await memory_list_processes("/app/workspace/windows_memdump.raw")
        >>> for proc in result.data["processes"]:
        ...     print(proc["ImageFileName"], proc["PID"])
    """
    validated = validate_file_path(dump_path)

    try:
        pslist_data = await _run_vol3_async(str(validated), "windows.pslist")
    except FileNotFoundError:
        return failure(
            "DEPENDENCY_MISSING",
            "Volatility3 (vol) is not installed",
            hint="Install with: pip install volatility3",
        )
    except RuntimeError as exc:
        return failure("VOLATILITY_ERROR", str(exc))

    result_data: dict[str, Any] = {
        "dump_path": str(validated),
        "processes": pslist_data.get("rows", []),
        "process_count": len(pslist_data.get("rows", [])),
    }

    if include_hidden:
        try:
            psscan_data = await _run_vol3_async(str(validated), "windows.psscan")
            scan_rows = psscan_data.get("rows", [])
            list_pids = {r.get("PID") for r in pslist_data.get("rows", []) if "PID" in r}
            hidden = [r for r in scan_rows if r.get("PID") not in list_pids]
            result_data["hidden_processes"] = hidden
            result_data["hidden_count"] = len(hidden)
        except Exception as exc:
            logger.warning("psscan failed: %s", exc)
            result_data["hidden_processes"] = []
            result_data["hidden_count"] = 0
            result_data["psscan_error"] = str(exc)

    return success(result_data)


@log_execution(tool_name="memory_detect_injections")
@track_metrics("memory_detect_injections")
@handle_tool_errors
async def memory_detect_injections(
    dump_path: str,
    _bypass_queue: bool = False,
) -> ToolResult:
    """Detect Windows process injection using the Volatility3 windows.malfind plugin.

    Uses the ``malfind`` plugin to identify memory regions with executable permissions
    that contain suspicious patterns (MZ headers, shellcode signatures).

    Args:
        dump_path: Path to the memory dump file.
        _bypass_queue: Internal — set True to skip ARQ queueing.

    Returns:
        ToolResult with list of suspicious memory regions and severity assessment.

    Example:
        >>> result = await memory_detect_injections("/app/workspace/memdump.raw")
        >>> print(result.data["injection_count"])
    """
    if not _bypass_queue:
        try:
            from reversecore_mcp.core.task_queue import run_task_or_fallback

            return await run_task_or_fallback(
                "task_memory_detect_injections",
                memory_detect_injections,
                dump_path,
                _bypass_queue=True,
            )
        except Exception as exc:
            logger.warning("Task queue unavailable: %s", exc)

    validated = validate_file_path(dump_path)

    try:
        data = await _run_vol3_async(str(validated), "windows.malfind")
    except FileNotFoundError:
        return failure(
            "DEPENDENCY_MISSING",
            "Volatility3 (vol) is not installed",
            hint="Install with: pip install volatility3",
        )
    except RuntimeError as exc:
        return failure("VOLATILITY_ERROR", str(exc))

    rows = data.get("rows", [])
    # Flag rows with MZ header as highest risk
    for row in rows:
        disasm = row.get("Disassembly", "") or ""
        row["risk"] = "HIGH" if "MZ" in str(row.get("Hexdump", "")) else "MEDIUM"
        row["has_pe_header"] = "MZ" in str(row.get("Hexdump", ""))
        row["has_shellcode"] = any(
            keyword in disasm.upper() for keyword in ["CALL", "JMP", "PUSH", "POP"]
        )

    high_risk = [r for r in rows if r.get("risk") == "HIGH"]

    return success(
        {
            "dump_path": str(validated),
            "injections": rows,
            "injection_count": len(rows),
            "high_risk_count": len(high_risk),
            "severity": "CRITICAL" if high_risk else ("HIGH" if rows else "CLEAN"),
        }
    )


@log_execution(tool_name="memory_extract_strings")
@track_metrics("memory_extract_strings")
@handle_tool_errors
async def memory_extract_strings(
    dump_path: str,
    min_length: int = 6,
    limit: int = 500,
) -> ToolResult:
    """Extract ASCII and Unicode strings from a memory dump.

    Args:
        dump_path: Path to the memory dump file.
        min_length: Minimum string length to include (default: 6).
        limit: Maximum number of strings to return (default: 500).

    Returns:
        ToolResult with extracted strings, counts, and notable patterns (IPs, URLs).

    Example:
        >>> result = await memory_extract_strings("/app/workspace/memdump.raw", limit=100)
        >>> print(result.data["string_count"])
    """
    validated = validate_file_path(dump_path)
    file_size = validated.stat().st_size

    if file_size > _MAX_MEMORY_DUMP_BYTES:
        return failure(
            "FILE_TOO_LARGE",
            f"Memory dump is {file_size // (1024 * 1024)} MB — too large for in-process string extraction",
            hint="Use the 'strings' CLI tool directly or reduce dump size.",
        )

    summary = _StringSummary(limit, get_config().max_output_size)
    resolved_exe = shutil.which("strings")
    output_limit_reached = False
    command_incomplete = False
    if resolved_exe:

        def add_line(line: str, line_truncated: bool) -> None:
            summary.add(line.rstrip("\r"), line_truncated)

        returncode, _, _, output_limit_reached, _ = await execute_subprocess_lines_async(
            [resolved_exe, f"-n{min_length}", str(validated)],
            add_line,
            # Each printable run adds a newline, so allow a conservative
            # two bytes per input byte while keeping process memory bounded.
            max_output_size=max(file_size * 2 + 1, 1),
            max_line_size=_MAX_STRING_LINE_BYTES,
            timeout=120,
        )
        command_incomplete = returncode != 0
    else:

        def extract_strings() -> None:
            for value, line_truncated in _iter_ascii_strings(validated, min_length):
                summary.add(value, line_truncated)

        await asyncio.to_thread(extract_strings)

    notable = {"ips": summary.ips, "urls": summary.urls}

    return success(
        {
            "dump_path": str(validated),
            "string_count": summary.string_count,
            "strings": summary.strings,
            "notable": notable,
            "truncated": summary.truncated or output_limit_reached or command_incomplete,
            "count_complete": not output_limit_reached and not command_incomplete,
        }
    )


@log_execution(tool_name="memory_dump_module")
@track_metrics("memory_dump_module")
@handle_tool_errors
async def memory_dump_module(
    dump_path: str,
    process_name: str,
    module_name: str | None = None,
    output_dir: str | None = None,
) -> ToolResult:
    """Dump a Windows module or DLL from a memory dump via Volatility3.

    Args:
        dump_path: Path to the memory dump file.
        process_name: Name of the target process (e.g., 'explorer.exe').
        module_name: Exact module/DLL name to dump. If None, dumps all modules
            for the specified process.
        output_dir: Workspace directory under which a unique run directory is
            created for the dumped modules. Defaults to the workspace directory.

    Returns:
        ToolResult with dumped file paths and module information.

    Example:
        >>> result = await memory_dump_module(
        ...     "/app/workspace/memdump.raw",
        ...     "malware.exe",
        ...     module_name="injected.dll"
        ... )
    """
    validated = validate_file_path(dump_path)

    workspace = get_workspace_config().workspace.resolve()
    if output_dir:
        out_path = Path(output_dir).expanduser().resolve()
    else:
        out_path = (workspace / "forensics_dumps").resolve()
    if not out_path.is_relative_to(workspace):
        return failure(
            "PATH_TRAVERSAL_DETECTED",
            f"output_dir '{output_dir}' must reside within the workspace directory",
        )

    run_output_dir: Path | None = None
    try:
        # First find the PID
        pslist_data = await _run_vol3_async(str(validated), "windows.pslist")
        processes = pslist_data.get("rows", [])
        target_procs = [
            p for p in processes if process_name.lower() in str(p.get("ImageFileName", "")).lower()
        ]

        if not target_procs:
            return failure(
                "PROCESS_NOT_FOUND",
                f"No process matching '{process_name}' found in memory dump",
                hint="Use memory_list_processes to see all available processes.",
            )

        # Dump modules for the first matching process. Keep each run isolated so
        # old files cannot be reported as results and Volatility cannot follow a
        # pre-existing output-file symlink outside the validated workspace.
        pid = target_procs[0].get("PID")
        if pid is None:
            return failure(
                "VOLATILITY_ERROR",
                f"Process matching '{process_name}' has no PID in Volatility3 output",
            )

        out_path.mkdir(parents=True, exist_ok=True)
        run_output_dir = Path(tempfile.mkdtemp(prefix="volatility-", dir=str(out_path))).resolve()
        if not run_output_dir.is_relative_to(workspace):
            run_output_dir.rmdir()
            return failure(
                "PATH_TRAVERSAL_DETECTED",
                "Volatility3 output directory resolved outside the workspace",
            )

        extra_args = ["--pid", str(pid), "--dump"]
        if module_name:
            # Volatility treats --name as a regular expression. Escape user
            # input and anchor it so only the requested DLL basename matches.
            extra_args.extend(["--name", f"^{re.escape(module_name)}$", "--ignore-case"])

        data = await _run_vol3_async(
            str(validated),
            "windows.dlllist",
            extra_args,
            global_args=["-o", str(run_output_dir)],
        )
        raw_output = data.get("raw_output", "")
        if raw_output and _is_unsupported_volatility_option(RuntimeError(raw_output), "--dump"):
            _remove_empty_output_dir(run_output_dir)
            return failure(
                "DUMP_UNSUPPORTED",
                "The installed Volatility3 windows.dlllist plugin does not support --dump",
                hint="Upgrade Volatility3 to a version whose windows.dlllist supports DLL extraction.",
            )
        modules = data.get("rows", [])
        if module_name and not modules:
            _remove_empty_output_dir(run_output_dir)
            return failure(
                "MODULE_NOT_FOUND",
                f"No DLL matching '{module_name}' was found in process '{process_name}'",
                hint="Use memory_list_processes and memory_analyze to inspect loaded DLL names.",
            )

        dumped_files = []
        for path in sorted(run_output_dir.glob("*.dmp")):
            resolved_path = path.resolve()
            if not resolved_path.is_relative_to(workspace):
                return failure(
                    "PATH_TRAVERSAL_DETECTED",
                    "Volatility3 created an output file outside the workspace",
                )
            if path.is_file() and path.stat().st_size > 0:
                dumped_files.append(resolved_path)

        if not dumped_files:
            _remove_empty_output_dir(run_output_dir)
            output_status = [
                str(row.get("File output")) for row in modules if row.get("File output")
            ]
            detail = (
                f" Volatility3 reported: {', '.join(output_status[:5])}." if output_status else ""
            )
            return failure(
                "DUMP_FAILED",
                f"Volatility3 did not create any DLL dump files for process '{process_name}'.{detail}",
                hint=(
                    "Confirm the process has readable DLLs and that the installed "
                    "windows.dlllist plugin supports --dump."
                ),
            )

        return success(
            {
                "dump_path": str(validated),
                "process_name": process_name,
                "matching_processes": target_procs[:5],
                "modules": modules[:50],
                "dumped_files": [str(f) for f in dumped_files[:20]],
                "output_dir": str(out_path),
                "run_output_dir": str(run_output_dir),
            }
        )

    except FileNotFoundError:
        _remove_empty_output_dir(run_output_dir)
        return failure(
            "DEPENDENCY_MISSING",
            "Volatility3 (vol) is not installed",
            hint="Install with: pip install volatility3",
        )
    except RuntimeError as exc:
        _remove_empty_output_dir(run_output_dir)
        if _is_unsupported_volatility_option(exc, "--dump"):
            return failure(
                "DUMP_UNSUPPORTED",
                "The installed Volatility3 windows.dlllist plugin does not support --dump",
                hint="Upgrade Volatility3 to a version whose windows.dlllist supports DLL extraction.",
            )
        return failure("VOLATILITY_ERROR", str(exc))
