"""Testcase Minimizer and Standalone PoC Generator."""

from __future__ import annotations

import os
import re
import signal
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.core.execution import execute_subprocess_async, prepare_sandbox_access
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)
MAX_C_POC_PAYLOAD_SIZE = 65536  # 64 KiB: maximum payload embedded in C source array

# Fatal POSIX signals indicative of unhandled memory corruption or fatal conditions
FATAL_SIGNALS: dict[int, str] = {
    11: "SIGSEGV",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    4: "SIGILL",
    5: "SIGTRAP",
    31: "SIGSYS",
}
for _sig_name in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGTRAP", "SIGSYS"):
    if hasattr(signal, _sig_name):
        FATAL_SIGNALS[getattr(signal, _sig_name)] = _sig_name

# Standard shell/wrapper exit codes: 128 + signal
FATAL_SIGNAL_EXIT_CODES: dict[int, str] = {
    128 + sig_val: name for sig_val, name in FATAL_SIGNALS.items()
}

# Windows fatal NTSTATUS crash codes (both unsigned and signed 32-bit int representations)
WINDOWS_CRASH_CODES: dict[int, str] = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    -1073741819: "STATUS_ACCESS_VIOLATION",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    -1073741571: "STATUS_STACK_OVERFLOW",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    -1073740791: "STATUS_STACK_BUFFER_OVERRUN",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    -1073741795: "STATUS_ILLEGAL_INSTRUCTION",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    -1073741676: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    -1073740940: "STATUS_HEAP_CORRUPTION",
}

_SANITIZER_PATTERN = re.compile(
    r"(?:(?:ERROR|SUMMARY):\s*)?(?:AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|ThreadSanitizer|MemorySanitizer):\s*([a-zA-Z0-9\-_]+)",
    re.IGNORECASE,
)

_STACK_FRAME_PATTERN = re.compile(
    r"#0\s+([0-9a-fA-Fx]+)\s+in\s+([A-Za-z0-9_:\<\>\~]+)",
)


@dataclass(frozen=True)
class CrashClassification:
    """Represents a classified program crash signature."""

    kind: str  # "signal", "sanitizer", "fatal_code"
    detail: str  # e.g., "SIGSEGV", "heap-buffer-overflow", "STATUS_ACCESS_VIOLATION"
    returncode: int | None = None
    crash_site: str | None = None

    def matches(self, other: CrashClassification | None) -> bool:
        """Check if candidate crash matches this baseline crash condition."""
        if other is None:
            return False
        if self.kind != other.kind:
            return False
        if self.detail and other.detail:
            if self.detail.lower() != other.detail.lower():
                return False
        if self.crash_site and other.crash_site:
            if self.crash_site != other.crash_site:
                return False
        return True


class _WorkspaceScratchError(RuntimeError):
    """Raised when minimizer scratch cannot be kept inside the configured workspace."""


def _ensure_minimizer_scratch_dir() -> Path:
    """Create and validate the workspace-local scratch directory for test inputs."""
    config = get_config()
    workspace = config.workspace.resolve()
    cache_dir = config.workspace / ".cache"

    if cache_dir.is_symlink():
        raise _WorkspaceScratchError("Workspace cache directory must not be a symbolic link.")

    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        if cache_dir.is_symlink() or not cache_dir.is_dir():
            raise _WorkspaceScratchError("Workspace cache path must be a real directory.")
        resolved_cache_dir = cache_dir.resolve(strict=True)
        resolved_cache_dir.relative_to(workspace)
    except _WorkspaceScratchError:
        raise
    except (OSError, ValueError) as exc:
        raise _WorkspaceScratchError(
            "Workspace cache directory must resolve inside the configured workspace."
        ) from exc

    return resolved_cache_dir


def generate_python_poc_script(
    target_binary_path: str,
    payload_bytes: bytes,
    cwe_id: str = "CWE-122",
    bug_name: str = "Heap Buffer Overflow",
) -> str:
    """Generate a clean, standalone Python reproduction script for CVE submission.

    Args:
        target_binary_path: Path or command name of target binary.
        payload_bytes: Minimal crash-inducing payload bytes.
        cwe_id: CWE vulnerability identifier.
        bug_name: Human-readable vulnerability name.

    Returns:
        Complete Python script string.
    """
    hex_payload = payload_bytes.hex()

    script = f'''#!/usr/bin/env python3
"""
CVE Proof-of-Concept Reproduction Script
Vulnerability: {bug_name} ({cwe_id})
Target: {target_binary_path}
Generated by: Reversecore_MCP AI CVE Hunter Engine
"""

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PAYLOAD_HEX = "{hex_payload}"
PAYLOAD = bytes.fromhex(PAYLOAD_HEX)

def reproduce():
    print(f"[*] Triggering PoC against target: {target_binary_path}")
    print(f"[*] Payload size: {{len(PAYLOAD)}} bytes")

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(PAYLOAD)
        tmp_poc = f.name

    try:
        cmd = ["{target_binary_path}", tmp_poc]
        print(f"[*] Executing command: {{' '.join(cmd)}}")
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        print(f"[*] Process exited with return code: {{proc.returncode}}")
        if proc.stderr:
            print("[*] Stderr output:")
            print(proc.stderr.decode("utf-8", errors="ignore"))
    except subprocess.TimeoutExpired:
        print("[!] Execution timed out (possible hang or loop)")
    except Exception as e:
        print(f"[!] Execution failed: {{e}}")
    finally:
        try:
            Path(tmp_poc).unlink(missing_ok=True)
        except Exception:
            pass

if __name__ == "__main__":
    reproduce()
'''
    return script


def generate_c_poc_harness(
    target_function: str,
    payload_bytes: bytes,
    cwe_id: str = "CWE-122",
    max_payload_size: int | None = None,
) -> str:
    """Generate a standalone C reproducer file for vendor bug reporting.

    Args:
        target_function: Target parser function name.
        payload_bytes: Raw payload byte content.
        cwe_id: CWE identifier.
        max_payload_size: Optional maximum byte limit for embedding into the C array.
            Defaults to MAX_C_POC_PAYLOAD_SIZE (64 KiB).

    Returns:
        C source code reproducing the crash.
    """
    limit = max_payload_size if max_payload_size is not None else MAX_C_POC_PAYLOAD_SIZE
    is_truncated = len(payload_bytes) > limit
    emitted_payload = payload_bytes[:limit] if is_truncated else payload_bytes
    byte_array_str = ", ".join(f"0x{b:02x}" for b in emitted_payload)

    if is_truncated:
        header_comment = f"""/*
 * Incomplete C Reproduction Harness for {cwe_id}
 * WARNING: Crash payload was truncated from {len(payload_bytes)} bytes to {len(emitted_payload)} bytes.
 * This harness may not reproduce crashes requiring data beyond offset {len(emitted_payload) - 1}.
 * Generated by Reversecore_MCP
 */"""
        run_print = f'    printf("[!] WARNING: Incomplete testcase (Truncated to %zu of {len(payload_bytes)} bytes) against {target_function}\\n", g_poc_size);'
    else:
        header_comment = f"""/*
 * Standalone C Reproduction Harness for {cwe_id}
 * Generated by Reversecore_MCP
 */"""
        run_print = f'    printf("[*] Running PoC testcase against {target_function} (Size: %zu bytes)\\n", g_poc_size);'

    c_code = f"""{header_comment}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Forward declaration of target entry point
extern int {target_function}(const uint8_t *data, size_t size);

static const uint8_t g_poc_payload[] = {{
    {byte_array_str}
}};
static const size_t g_poc_size = {len(emitted_payload)};

int main(int argc, char **argv) {{
{run_print}
    {target_function}(g_poc_payload, g_poc_size);
    printf("[*] Finished execution.\\n");
    return 0;
}}
"""
    return c_code


def _classify_execution_outcome(
    returncode: int,
    stdout_str: str,
    stderr_str: str,
) -> CrashClassification | None:
    """Classify process execution outcome into a CrashClassification or None if not crashed."""
    combined = f"{stdout_str}\n{stderr_str}"

    # 1. Check for Sanitizer diagnostics first (can occur with returncode 0, 1, or fatal code)
    san_match = _SANITIZER_PATTERN.search(combined)
    if san_match:
        bug_type = san_match.group(1).lower()
        frame_match = _STACK_FRAME_PATTERN.search(combined)
        crash_site = frame_match.group(2) if frame_match else None
        return CrashClassification(
            kind="sanitizer",
            detail=bug_type,
            returncode=returncode,
            crash_site=crash_site,
        )
    if "AddressSanitizer" in combined or "UndefinedBehaviorSanitizer" in combined:
        return CrashClassification(
            kind="sanitizer",
            detail="sanitizer-generic",
            returncode=returncode,
        )

    # 2. Fatal signals (negative returncode on POSIX)
    if returncode < 0:
        sig_num = -returncode
        detail = FATAL_SIGNALS.get(sig_num, f"SIG_{sig_num}")
        return CrashClassification(
            kind="signal",
            detail=detail,
            returncode=returncode,
        )

    # 3. Shell / wrapper fatal exit codes (128 + signum)
    if returncode in FATAL_SIGNAL_EXIT_CODES:
        return CrashClassification(
            kind="signal",
            detail=FATAL_SIGNAL_EXIT_CODES[returncode],
            returncode=returncode,
        )

    # 4. Windows fatal NTSTATUS crash codes
    if returncode in WINDOWS_CRASH_CODES:
        return CrashClassification(
            kind="fatal_code",
            detail=WINDOWS_CRASH_CODES[returncode],
            returncode=returncode,
        )

    # 5. Core dump / fatal crash strings in output or stderr
    lower = combined.lower()
    if "segmentation fault" in lower or "segfault" in lower:
        return CrashClassification(kind="signal", detail="SIGSEGV", returncode=returncode)
    if "stack smashing detected" in lower or "aborted (core dumped)" in lower:
        return CrashClassification(kind="signal", detail="SIGABRT", returncode=returncode)
    if "bus error" in lower:
        return CrashClassification(kind="signal", detail="SIGBUS", returncode=returncode)

    # Clean exit (0) or ordinary error exit (1, 2, 255) is NOT a crash
    return None


async def _classify_input_crash(
    binary_path: Path, data: bytes, timeout: int = 5
) -> CrashClassification | None:
    """Execute binary with input testcase and classify crash signature if any."""
    cache_dir = _ensure_minimizer_scratch_dir()
    tmp_name: str | None = None
    try:
        try:
            with tempfile.NamedTemporaryFile(suffix=".bin", dir=cache_dir, delete=False) as tmp:
                tmp_name = tmp.name
                tmp.write(data)
        except OSError as exc:
            raise _WorkspaceScratchError(
                "Could not create minimizer testcase under workspace/.cache."
            ) from exc

        candidate_path = Path(tmp_name)
        try:
            prepare_sandbox_access(candidate_path)
        except (OSError, RuntimeError) as exc:
            raise _WorkspaceScratchError(
                "Minimizer testcase is not accessible to the configured sandbox user."
            ) from exc

        try:
            output, _ = await execute_subprocess_async(
                [str(binary_path), str(candidate_path)],
                max_output_size=1_000_000,
                timeout=timeout,
            )
            return _classify_execution_outcome(0, output, "")
        except subprocess.CalledProcessError as err:
            stderr_str = err.stderr or ""
            output_str = err.output or ""
            return _classify_execution_outcome(err.returncode, output_str, stderr_str)
        except (ExecutionTimeoutError, ToolNotFoundError, OSError):
            return None
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


async def _test_input_causes_crash(
    binary_path: Path,
    data: bytes,
    timeout: int = 5,
    expected_crash: CrashClassification | None = None,
) -> bool:
    """Check if feeding data to target binary triggers a crash (signal, ASan, or fatal exception).

    If expected_crash is specified, the observed crash must match the baseline crash classification.
    Ordinary non-zero exit codes (such as exit(1) for parser rejection) are not considered crashes.
    """
    crash = await _classify_input_crash(binary_path, data, timeout=timeout)
    if crash is None:
        return False
    if expected_crash is None:
        return True
    return expected_crash.matches(crash)


async def delta_debug_minimize(
    binary_path: Path,
    original_bytes: bytes,
    max_iterations: int = 50,
    expected_crash: CrashClassification | None = None,
    timeout: int = 5,
) -> bytes:
    """Delta-debugging algorithm to shrink crash input to the minimal byte payload.

    Args:
        binary_path: Path to target executable.
        original_bytes: Crash-inducing payload.
        max_iterations: Maximum bisection iterations.
        expected_crash: Optional baseline crash classification to preserve.
        timeout: Subprocess execution timeout in seconds.

    Returns:
        Minimized byte payload.
    """
    if len(original_bytes) <= 4:
        return original_bytes

    if expected_crash is None:
        try:
            expected_crash = await _classify_input_crash(
                binary_path, original_bytes, timeout=timeout
            )
        except Exception as e:
            logger.debug(f"Baseline crash classification probe error: {e}")
            expected_crash = None

    current = bytearray(original_bytes)
    chunk_size = len(current) // 2

    iteration = 0
    while chunk_size > 0 and iteration < max_iterations:
        iteration += 1
        reduced = False
        i = 0
        while i < len(current):
            # Try removing chunk [i : i + chunk_size]
            candidate = current[:i] + current[i + chunk_size :]
            if len(candidate) > 0:
                try:
                    crashed = await _test_input_causes_crash(
                        binary_path,
                        bytes(candidate),
                        timeout=timeout,
                        expected_crash=expected_crash,
                    )
                except TypeError:
                    # Backward compatibility if mock only takes (binary_path, data, timeout)
                    crashed = await _test_input_causes_crash(
                        binary_path, bytes(candidate), timeout=timeout
                    )
                if crashed:
                    current = candidate
                    reduced = True
                    break
            i += chunk_size

        if not reduced:
            chunk_size //= 2

    return bytes(current)


async def minimize_poc_impl(
    binary_path: str,
    crash_input_path: str,
    target_function: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Minimize crash testcase input and generate standalone PoCs.

    Args:
        binary_path: Path to target binary in workspace.
        crash_input_path: Path to crash-inducing input file.
        target_function: Optional target parser function name.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with minimized payload, size reduction percentage, and PoC scripts.
    """
    try:
        bin_path = validate_file_path(binary_path)
        input_path = validate_file_path(crash_input_path)
    except Exception as e:
        return failure("INVALID_PATH", f"Validation error: {e}")

    if not bin_path.exists() or not input_path.exists():
        return failure("FILE_NOT_FOUND", "Target binary or crash input file does not exist.")

    try:
        _ensure_minimizer_scratch_dir()
    except _WorkspaceScratchError as e:
        return failure("INVALID_SCRATCH_DIR", str(e))

    calc_timeout = calculate_dynamic_timeout(bin_path, base_timeout=timeout or 30)

    original_payload = input_path.read_bytes()
    original_size = len(original_payload)

    # Determine baseline crash condition
    baseline_crash: CrashClassification | None = None
    try:
        baseline_crash = await _classify_input_crash(
            bin_path, original_payload, timeout=calc_timeout
        )
    except Exception as e:
        logger.debug(f"Baseline crash classification probe error: {e}")

    # Perform minimization
    try:
        minimized_payload = await delta_debug_minimize(
            bin_path,
            original_payload,
            max_iterations=min(calc_timeout, 30),
            expected_crash=baseline_crash,
            timeout=calc_timeout,
        )
    except _WorkspaceScratchError as e:
        return failure("INVALID_SCRATCH_DIR", str(e))
    except Exception as e:
        logger.warning(f"Delta-debug minimization fallback: {e}")
        minimized_payload = original_payload

    minimized_size = len(minimized_payload)
    reduction_pct = (
        round(((original_size - minimized_size) / original_size) * 100, 1)
        if original_size > 0
        else 0.0
    )

    # Generate Python and C PoCs
    func_name = target_function or "parse_input"
    py_poc = generate_python_poc_script(
        target_binary_path=str(bin_path),
        payload_bytes=minimized_payload,
    )
    c_poc = generate_c_poc_harness(
        target_function=func_name,
        payload_bytes=minimized_payload,
    )
    gdb_cmd = (
        f"gdb -q {bin_path} -ex 'r {crash_input_path}' -ex 'bt' -ex 'info registers' -ex 'quit'"
    )

    c_poc_truncated = len(minimized_payload) > MAX_C_POC_PAYLOAD_SIZE
    emitted_c_size = min(len(minimized_payload), MAX_C_POC_PAYLOAD_SIZE)
    c_poc_status = "incomplete" if c_poc_truncated else "standalone"

    if c_poc_truncated:
        c_summary_note = (
            f"Standalone Python reproducer generated; C reproducer harness is incomplete "
            f"({emitted_c_size}B of {minimized_size}B emitted)."
        )
    else:
        c_summary_note = "Standalone Python and C reproducers generated."

    summary = (
        f"Minimized PoC from {original_size}B to {minimized_size}B "
        f"({reduction_pct}% reduction). {c_summary_note}"
    )

    result_data = {
        "binary_path": str(bin_path),
        "original_input_size_bytes": original_size,
        "minimized_input_size_bytes": minimized_size,
        "reduction_percentage": f"{reduction_pct}%",
        "minimized_payload_hex": minimized_payload[:256].hex(),
        "standalone_python_poc": py_poc,
        "standalone_c_poc": c_poc,
        "c_poc_payload_size_bytes": emitted_c_size,
        "c_poc_status": c_poc_status,
        "c_poc_truncated": c_poc_truncated,
        "crash_type": baseline_crash.kind if baseline_crash else None,
        "crash_detail": baseline_crash.detail if baseline_crash else None,
        "gdb_reproduction_command": gdb_cmd,
        "summary": summary,
    }

    metadata_kwargs: dict[str, Any] = {
        "original_payload_size": original_size,
        "minimized_payload_size": minimized_size,
        "emitted_c_poc_payload_size": emitted_c_size,
        "emitted_python_poc_payload_size": minimized_size,
        "c_poc_truncated": c_poc_truncated,
        "c_poc_status": c_poc_status,
        "crash_type": baseline_crash.kind if baseline_crash else None,
        "crash_detail": baseline_crash.detail if baseline_crash else None,
    }

    return success(result_data, meta=metadata_kwargs)
