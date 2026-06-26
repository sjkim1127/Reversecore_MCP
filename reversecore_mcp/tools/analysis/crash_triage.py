"""
Crash Triage Pipeline Tool.

This tool automatically analyzes crash files (e.g., from AFL++) against a target binary
to determine exploitability and extract crash context using GDB.
"""

from __future__ import annotations

import os
import re
import shlex
import tempfile
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

DEFAULT_TIMEOUT = get_config().default_tool_timeout


@log_execution(tool_name="triage_crash")
@track_metrics("triage_crash")
@handle_tool_errors
async def triage_crash(
    binary_path: str,
    crash_file: str,
    use_stdin: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Analyze a crash file against a binary using GDB to determine exploitability.

    Args:
        binary_path: Path to the executable binary.
        crash_file: Path to the crash input file (e.g., from AFL++ crashes/ dir).
        use_stdin: If True, pipe the crash file to stdin. If False, pass it as an argument.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult containing parsed GDB output, including signal, registers, backtrace,
        and an exploitability assessment.
    """
    valid_bin = validate_file_path(binary_path)
    valid_crash = validate_file_path(crash_file)

    if not os.access(valid_bin, os.X_OK):
        # We might need to ensure it's executable for GDB to run it
        try:
            os.chmod(valid_bin, 0o755)  # nosec B103
        except Exception:
            pass

    # Create a GDB script to run and extract info
    # We use a temporary script file to avoid complex escaping in command line arguments
    # and to ensure GDB does exactly what we want without interactivity.
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gdb") as f:
        gdb_script_path = f.name

        f.write("set width 0\n")
        f.write("set height 0\n")
        f.write("set pagination off\n")
        f.write("set confirm off\n")

        if use_stdin:
            f.write(f"run < {shlex.quote(str(valid_crash))}\n")
        else:
            f.write(f"run {shlex.quote(str(valid_crash))}\n")

        f.write("echo \\n---CRASH_INFO_START---\\n\n")
        f.write("echo \\n[SIGNAL]\\n\n")
        f.write("info program\n")
        f.write("echo \\n[REGISTERS]\\n\n")
        f.write("info registers\n")
        f.write("echo \\n[BACKTRACE]\\n\n")
        f.write("bt full\n")
        f.write("echo \\n[INSTRUCTION]\\n\n")
        f.write("x/i $pc\n")
        f.write("echo \\n---CRASH_INFO_END---\\n\n")
        f.write("quit\n")

    try:
        cmd = ["gdb", "--batch", "--quiet", "-x", gdb_script_path, str(valid_bin)]

        stdout, stderr = await execute_subprocess_async(cmd, timeout=timeout)

        # Parse GDB output
        if "---CRASH_INFO_START---" not in stdout:
            # Maybe it didn't crash? Or GDB failed to run
            if "exited normally" in stdout.lower() or "exited with code" in stdout.lower():
                return success(
                    {
                        "crashed": False,
                        "message": "The program did not crash with the provided input.",
                        "raw_output": stdout[:1000],
                    }
                )
            else:
                return failure(
                    "GDB_ERROR",
                    "Failed to get crash info from GDB.",
                    details={"stdout": stdout[-1000:], "stderr": stderr},
                )

        crash_info = _parse_gdb_output(stdout)

        # Add assessment
        crash_info["exploitability"] = _assess_exploitability(crash_info)
        crash_info["crashed"] = True

        return success(crash_info)

    finally:
        if os.path.exists(gdb_script_path):
            os.remove(gdb_script_path)


def _parse_gdb_output(output: str) -> dict[str, Any]:
    """Parse the custom GDB script output into a structured dictionary."""
    result: dict[str, Any] = {
        "signal": None,
        "signal_name": None,
        "faulting_address": None,
        "registers": {},
        "backtrace": [],
        "instruction": None,
    }

    # Extract sections
    signal_match = re.search(r"\[SIGNAL\]\s*(.*?)(?=\[REGISTERS\])", output, re.DOTALL)
    if signal_match:
        sig_text = signal_match.group(1).strip()
        # "Program stopped with signal SIGSEGV, Segmentation fault."
        # "It stopped with signal SIGABRT, Aborted."
        if "signal" in sig_text:
            m = re.search(r"signal\s+(SIG[A-Z]+)[,\.]\s+(.*?)\.", sig_text)
            if m:
                result["signal"] = m.group(1)
                result["signal_name"] = m.group(2)

    reg_match = re.search(r"\[REGISTERS\]\s*(.*?)(?=\[BACKTRACE\])", output, re.DOTALL)
    if reg_match:
        reg_text = reg_match.group(1).strip()
        for line in reg_text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                reg_name = parts[0]
                # Usually hex value is second part
                reg_val = parts[1]
                result["registers"][reg_name] = reg_val

                # Try to capture instruction pointer explicitly for convenience
                if reg_name in ("rip", "eip", "pc"):
                    result["faulting_address"] = reg_val

    bt_match = re.search(r"\[BACKTRACE\]\s*(.*?)(?=\[INSTRUCTION\])", output, re.DOTALL)
    if bt_match:
        bt_text = bt_match.group(1).strip()
        if "No stack" not in bt_text:
            # Parse basic backtrace frames
            for line in bt_text.splitlines():
                if line.startswith("#"):
                    result["backtrace"].append(line.strip())

    inst_match = re.search(r"\[INSTRUCTION\]\s*(.*?)(?=\n---CRASH_INFO_END---)", output, re.DOTALL)
    if inst_match:
        inst_text = inst_match.group(1).strip()
        result["instruction"] = inst_text

        # If we didn't get faulting address from registers, try to get it from instruction
        if not result["faulting_address"]:
            m = re.search(r"=>\s*(0x[0-9a-fA-F]+)", inst_text)
            if m:
                result["faulting_address"] = m.group(1)

    return result


def _assess_exploitability(crash_info: dict[str, Any]) -> dict[str, Any]:
    """Perform a basic heuristic assessment of exploitability based on GDB output."""
    assessment = {
        "status": "UNKNOWN",
        "description": "Could not determine exploitability.",
        "tags": [],
    }

    signal = crash_info.get("signal")
    if not signal:
        return assessment

    if signal == "SIGABRT":
        assessment["status"] = "LOW"
        assessment["description"] = (
            "Program aborted (likely an assert or explicit abort), usually difficult to exploit directly unless it leads to a bypass."
        )
        assessment["tags"].append("aborted")
        return assessment

    if signal == "SIGSEGV":
        instruction = crash_info.get("instruction", "").lower()
        regs = crash_info.get("registers", {})

        # Check PC control
        pc_val = regs.get("rip", regs.get("eip", regs.get("pc", "")))
        if pc_val:
            # E.g. PC = 0x41414141 or similar repeating pattern
            if "414141" in pc_val.lower():
                assessment["status"] = "CRITICAL"
                assessment["description"] = (
                    "Instruction pointer is completely controlled by attacker data (e.g., 0x41414141)."
                )
                assessment["tags"].append("pc_control")
                return assessment

        if "call" in instruction or "jmp" in instruction:
            assessment["status"] = "HIGH"
            assessment["description"] = (
                "Segmentation fault occurred on a branch instruction. High likelihood of control flow hijack."
            )
            assessment["tags"].append("control_flow_hijack")
        elif "mov" in instruction or "ldr" in instruction or "str" in instruction:
            if "rip" in instruction or "eip" in instruction or "pc" in instruction:
                assessment["status"] = "HIGH"
                assessment["description"] = (
                    "Segmentation fault involving instruction pointer. High likelihood of exploitability."
                )
                assessment["tags"].append("pc_involved")
            else:
                assessment["status"] = "MEDIUM"
                assessment["description"] = (
                    "Segmentation fault on a memory access instruction. Could be an out-of-bounds read/write."
                )
                assessment["tags"].append("memory_corruption")
        else:
            assessment["status"] = "MEDIUM"
            assessment["description"] = "Segmentation fault. Requires further analysis."
            assessment["tags"].append("memory_corruption")

    elif signal in ("SIGILL", "SIGFPE", "SIGBUS"):
        assessment["status"] = "MEDIUM"
        assessment["description"] = (
            f"Crash due to {signal}. Could indicate memory corruption or logic errors."
        )
        assessment["tags"].append(signal.lower())

    return assessment
