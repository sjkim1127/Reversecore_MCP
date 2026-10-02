"""
Symbolic Execution Module.

This module provides an interface to run angr-based symbolic execution
as a separate process to prevent OOM issues and event loop blocking in the main server.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


async def verify_path_and_get_args(
    binary_path: str | Path,
    target_addr: int | str,
    start_addr: int | str | None = None,
    avoid_addrs: list[int | str] | None = None,
    source_addr: int | str | None = None,
    source_api: str | None = None,
    sink_api: str | None = None,
    check_taint: bool = False,
    timeout: int = 120,
) -> dict[str, Any]:
    """Run symbolic execution to verify path reachability and data-flow taint.

    Args:
        binary_path: Path to the binary file.
        target_addr: The address to reach (e.g. vulnerable API call).
        start_addr: The starting address for execution (e.g. caller function). If None, starts from entry point.
        avoid_addrs: List of addresses (hex or int) to avoid during execution.
        source_addr: Optional source address where tainted input enters.
        source_api: Optional name of the taint source function (e.g. read, argv, recv).
        sink_api: Optional name of the sink function (e.g. system, strcpy, popen).
        check_taint: When True, verify actual data-flow dependency from source to sink.
        timeout: Maximum execution time in seconds.

    Returns:
        A dictionary containing:
        - satisfiable: bool indicating if the target path was reached
        - taint_verified: bool indicating if data from source controls sink argument
        - data_flow_confirmed: bool alias for taint_verified
        - reachability_only: bool indicating reachability without confirmed data dependency
        - concrete_input: Optional string showing input required to trigger the path
        - error: Optional error message
    """
    # Locate the angr_worker script
    worker_script = Path(__file__).parent.parent.parent.parent / "scripts" / "angr_worker.py"

    if not worker_script.exists():
        logger.error(f"angr_worker script not found at {worker_script}")
        return {
            "satisfiable": False,
            "taint_verified": False,
            "data_flow_confirmed": False,
            "error": "Worker script not found",
        }

    cmd = [
        sys.executable or "python3",
        str(worker_script),
        "--binary",
        str(binary_path),
        "--target-addr",
        str(target_addr),
    ]

    if start_addr is not None:
        cmd.extend(["--start-addr", str(start_addr)])

    if avoid_addrs:
        avoid_str = ",".join(str(x) for x in avoid_addrs)
        cmd.extend(["--avoid-addrs", avoid_str])

    if source_addr is not None:
        cmd.extend(["--source-addr", str(source_addr)])

    if source_api:
        cmd.extend(["--source-api", str(source_api)])

    if sink_api:
        cmd.extend(["--sink-api", str(sink_api)])

    if check_taint:
        cmd.append("--check-taint")

    try:
        stdout, _ = await execute_subprocess_async(cmd, timeout=timeout)

        if stdout:
            try:
                # Find the JSON output which should be on the last line
                lines = stdout.strip().split("\n")
                parsed = json.loads(lines[-1])
                if isinstance(parsed, dict):
                    return parsed
                return {
                    "satisfiable": False,
                    "taint_verified": False,
                    "data_flow_confirmed": False,
                    "error": "Invalid output format from worker",
                }
            except json.JSONDecodeError:
                logger.error(f"Failed to parse angr worker output: {stdout}")
                return {
                    "satisfiable": False,
                    "taint_verified": False,
                    "data_flow_confirmed": False,
                    "error": "Invalid output format from worker",
                }

        return {
            "satisfiable": False,
            "taint_verified": False,
            "data_flow_confirmed": False,
            "error": "No output from worker",
        }

    except Exception as e:
        logger.error(f"Symbolic execution failed: {e}")
        return {
            "satisfiable": False,
            "taint_verified": False,
            "data_flow_confirmed": False,
            "error": str(e),
        }


@log_execution(tool_name="verify_path_and_get_args")
@track_metrics("verify_path_and_get_args")
@handle_tool_errors
async def verify_path_and_get_args_tool(
    file_path: str,
    target_addr: str,
    start_addr: str | None = None,
    avoid_addrs: list[str] | None = None,
    source_addr: str | None = None,
    source_api: str | None = None,
    sink_api: str | None = None,
    check_taint: bool = False,
    timeout: int = 120,
) -> ToolResult:
    """Run symbolic execution using angr to verify path reachability and extract inputs.

    Allows proving path reachability and verifying data-flow taint to a target instruction.

    Args:
        file_path: Workspace-relative or absolute path to the binary to analyze.
        target_addr: The target instruction address to reach (hex or integer).
        start_addr: Optional starting instruction address. If omitted, starts from entry point.
        avoid_addrs: Optional list of instruction addresses to avoid.
        source_addr: Optional source instruction address introducing user data.
        source_api: Optional name of the taint source function (e.g. read, argv, recv).
        sink_api: Optional name of the dangerous sink function (e.g. system, strcpy).
        check_taint: When True, verify actual data dependence on the sink arguments.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with symbolic path reachability status and concrete input if reachable.
    """
    validated_path = validate_file_path(file_path)

    def parse_addr(val: str) -> int | str:
        val_strip = val.strip()
        if val_strip.startswith("0x") or val_strip.startswith("0X"):
            return int(val_strip, 16)
        try:
            return int(val_strip)
        except ValueError:
            return val_strip

    parsed_target = parse_addr(target_addr)
    parsed_start = parse_addr(start_addr) if start_addr is not None else None
    parsed_source = parse_addr(source_addr) if source_addr is not None else None
    parsed_avoid = [parse_addr(x) for x in avoid_addrs] if avoid_addrs else None

    # Call core execution logic
    res = await verify_path_and_get_args(
        binary_path=validated_path,
        target_addr=parsed_target,
        start_addr=parsed_start,
        avoid_addrs=parsed_avoid,
        source_addr=parsed_source,
        source_api=source_api,
        sink_api=sink_api,
        check_taint=check_taint,
        timeout=timeout,
    )
    if "error" in res and res.get("error"):
        return failure("SYMBOLIC_EXECUTION_ERROR", res["error"])
    return success(res)
