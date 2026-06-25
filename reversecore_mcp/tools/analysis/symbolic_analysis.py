"""
Symbolic Execution Module.

This module provides an interface to run angr-based symbolic execution
as a separate process to prevent OOM issues and event loop blocking in the main server.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


async def verify_path_and_get_args(
    binary_path: str | Path,
    target_addr: int | str,
    start_addr: int | str | None = None,
    avoid_addrs: list[int | str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Run symbolic execution to verify path reachability.

    Args:
        binary_path: Path to the binary file.
        target_addr: The address to reach (e.g. vulnerable API call).
        start_addr: The starting address for execution (e.g. caller function). If None, starts from entry point.
        avoid_addrs: List of addresses (hex or int) to avoid during execution.
        timeout: Maximum execution time in seconds.

    Returns:
        A dictionary containing:
        - satisfiable: bool indicating if the path is reachable
        - concrete_input: Optional string showing input required to reach the path
        - error: Optional error message
    """
    # Locate the angr_worker script
    worker_script = Path(__file__).parent.parent.parent.parent / "scripts" / "angr_worker.py"

    if not worker_script.exists():
        logger.error(f"angr_worker script not found at {worker_script}")
        return {"satisfiable": False, "error": "Worker script not found"}

    cmd = [
        "python",
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

    try:
        stdout, stderr = await execute_subprocess_async(cmd, timeout=timeout)

        if stdout:
            try:
                # Find the JSON output which should be on the last line
                lines = stdout.strip().split("\n")
                return json.loads(lines[-1])
            except json.JSONDecodeError:
                logger.error(f"Failed to parse angr worker output: {stdout}")
                return {
                    "satisfiable": False,
                    "error": "Invalid output format from worker",
                }

        if stderr:
            logger.error(f"angr worker stderr: {stderr}")

        return {"satisfiable": False, "error": "No output from worker"}

    except Exception as e:
        logger.error(f"Symbolic execution failed: {e}")
        return {"satisfiable": False, "error": str(e)}
