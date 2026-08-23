"""Memory forensics tools backed by Volatility3.

All heavy Volatility3 operations are enqueued via the ARQ task queue
with Redis caching to avoid redundant re-analysis of the same dump.
"""

import asyncio
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# Supported Volatility3 plugins
_SUPPORTED_PLUGINS: dict[str, str] = {
    "pslist": "List all running processes",
    "pstree": "Display process tree",
    "psscan": "Scan for EPROCESS structures (finds hidden processes)",
    "netscan": "Scan for network connections",
    "malfind": "Detect injected code / suspicious memory regions",
    "dlllist": "List DLLs loaded by each process",
    "handles": "List open handles per process",
    "cmdline": "Extract command-line arguments for each process",
    "filescan": "Scan for FILE_OBJECT structures",
    "hivelist": "List registry hives",
    "hashdump": "Dump password hashes from registry",
    "lsadump": "Dump LSA secrets",
    "linux.pslist": "Linux process list",
    "linux.bash": "Recover bash history from memory",
    "mac.pslist": "macOS process list",
}


def _run_vol3(dump_path: str, plugin: str, extra_args: list[str] | None = None) -> dict[str, Any]:
    """Run a Volatility3 plugin against a memory dump.

    Args:
        dump_path: Path to the memory dump file.
        plugin: Volatility3 plugin name (e.g., 'pslist', 'malfind').
        extra_args: Additional arguments to pass to the plugin.

    Returns:
        Dictionary with plugin output or error information.

    Raises:
        FileNotFoundError: If volatility3 (vol.py / vol3) is not installed.
        subprocess.TimeoutExpired: If the plugin exceeds the execution timeout.
    """
    cmd = ["vol", "-f", dump_path, "-r", "json", plugin]
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
    dump_path: str, plugin: str, extra_args: list[str] | None = None
) -> dict[str, Any]:
    """Async wrapper for _run_vol3 to avoid blocking the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _run_vol3, dump_path, plugin, extra_args)


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
    plugin: str = "pslist",
    symbol_path: str | None = None,
    extra_args: str | None = None,
    _bypass_queue: bool = False,
) -> ToolResult:
    """Run a Volatility3 plugin against a memory dump file.

    Supports Windows, Linux, and macOS memory dumps. Heavy plugin operations
    (malfind, psscan, netscan) are queued via ARQ for non-blocking execution.

    Args:
        dump_path: Path to the memory dump file (.raw, .vmem, .mem, .dmp).
        plugin: Volatility3 plugin name. Run ``memory_analyze`` with plugin='help'
            to see all supported plugins.
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
        >>> result = await memory_analyze("/app/workspace/memdump.raw", plugin="pslist")
        >>> print(result.data["rows"])
    """
    if plugin == "help":
        return success({"supported_plugins": _SUPPORTED_PLUGINS, "total": len(_SUPPORTED_PLUGINS)})

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

    if plugin not in _SUPPORTED_PLUGINS and not plugin.startswith(
        ("windows.", "linux.", "mac.", "banners.")
    ):
        return failure(
            "UNSUPPORTED_PLUGIN",
            f"Plugin '{plugin}' is not in the supported list",
            hint=f"Supported plugins: {', '.join(_SUPPORTED_PLUGINS.keys())}. "
            "Pass plugin='help' to list all.",
        )

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
    """List all running processes from a memory dump.

    Args:
        dump_path: Path to the memory dump file.
        include_hidden: If True, also run psscan to detect hidden/unlinked processes.
            Hidden processes may indicate rootkits or process injection.

    Returns:
        ToolResult with process list and optional hidden process scan results.

    Example:
        >>> result = await memory_list_processes("/app/workspace/memdump.raw")
        >>> for proc in result.data["processes"]:
        ...     print(proc["ImageFileName"], proc["PID"])
    """
    validated = validate_file_path(dump_path)

    try:
        pslist_data = await _run_vol3_async(str(validated), "pslist")
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
            psscan_data = await _run_vol3_async(str(validated), "psscan")
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
    """Detect process injection and suspicious memory regions using Volatility3 malfind.

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
        data = await _run_vol3_async(str(validated), "malfind")
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
    import re

    validated = validate_file_path(dump_path)
    file_size = validated.stat().st_size

    # Cap at 512 MB to avoid OOM
    if file_size > 512 * 1024 * 1024:
        return failure(
            "FILE_TOO_LARGE",
            f"Memory dump is {file_size // (1024 * 1024)} MB — too large for in-process string extraction",
            hint="Use the 'strings' CLI tool directly or reduce dump size.",
        )

    try:
        resolved_exe = shutil.which("strings")
        if not resolved_exe:
            raise FileNotFoundError()

        def run_strings():
            return subprocess.run(  # nosec B603
                [resolved_exe, f"-n{min_length}", str(validated)],
                capture_output=True,
                text=True,
                timeout=120,
            )

        result = await asyncio.to_thread(run_strings)
        all_strings = result.stdout.splitlines()
    except FileNotFoundError:
        # Fallback: pure Python extraction
        data = validated.read_bytes()
        pattern = rb"[\x20-\x7E]{%d,}" % min_length
        all_strings = [
            m.group(0).decode("ascii", errors="replace") for m in re.finditer(pattern, data)
        ]

    # Detect notable patterns
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"https?://[^\s]{8,}")
    notable = {
        "ips": list({m for s in all_strings for m in ip_pattern.findall(s)})[:50],
        "urls": [s for s in all_strings if url_pattern.search(s)][:50],
    }

    return success(
        {
            "dump_path": str(validated),
            "string_count": len(all_strings),
            "strings": all_strings[:limit],
            "notable": notable,
            "truncated": len(all_strings) > limit,
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
    """Dump a loaded module or DLL from a memory dump via Volatility3.

    Args:
        dump_path: Path to the memory dump file.
        process_name: Name of the target process (e.g., 'explorer.exe').
        module_name: Name of the module/DLL to dump. If None, dumps all modules
            for the specified process.
        output_dir: Directory to save the dumped module. Defaults to the
            workspace directory.

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

    if output_dir:
        out_path = Path(output_dir)
    else:
        from reversecore_mcp.core.config import get_settings

        out_path = get_settings().workspace / "forensics_dumps"
    out_path.mkdir(parents=True, exist_ok=True)

    extra_args = [f"--dump-dir={out_path}"]
    if module_name:
        extra_args.append(f"--module={module_name}")

    try:
        # First find the PID
        pslist_data = await _run_vol3_async(str(validated), "pslist")
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

        # Dump modules for first matching process
        pid = target_procs[0].get("PID")
        if pid:
            extra_args.append(f"--pid={pid}")

        data = await _run_vol3_async(str(validated), "dlllist", extra_args)
        dumped_files = list(out_path.glob("*.dmp")) + list(out_path.glob("*.exe"))

        return success(
            {
                "dump_path": str(validated),
                "process_name": process_name,
                "matching_processes": target_procs[:5],
                "modules": data.get("rows", [])[:50],
                "dumped_files": [str(f) for f in dumped_files[:20]],
                "output_dir": str(out_path),
            }
        )

    except FileNotFoundError:
        return failure(
            "DEPENDENCY_MISSING",
            "Volatility3 (vol) is not installed",
            hint="Install with: pip install volatility3",
        )
    except RuntimeError as exc:
        return failure("VOLATILITY_ERROR", str(exc))
