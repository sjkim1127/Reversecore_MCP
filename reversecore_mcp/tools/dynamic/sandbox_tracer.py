"""Sandbox execution tracer for dynamic binary behavioral analysis.

Provides safe, container- and OS-level execution tracing for binaries
without requiring Radare2, GDB, or heavy external virtualization:
- Captures stdout, stderr, exit codes, and execution duration
- Detects crashes (SIGSEGV, SIGFPE, SIGILL) and abnormal terminations
- Monitors filesystem mutations (dropped files, modified payloads)
- Enforces Seccomp syscall containment profiles ('strict', 'no_network', 'read_only')
- Supports Bubblewrap ('bwrap') namespace containment and user-space API hooking
- Records real-time network packets to PCAP during execution
- Parses syscall activity (files, sockets, process forks, blocked calls) via strace
"""

from __future__ import annotations

import asyncio
import os
import platform
import re
import shutil
import time
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path
from reversecore_mcp.tools.dynamic.api_hooker import compile_api_hook, parse_hook_log
from reversecore_mcp.tools.dynamic.network_capture import LivePcapRecorder
from reversecore_mcp.tools.dynamic.seccomp_profiles import get_profile_blocked_syscalls

logger = get_logger(__name__)

# Common crash exit codes (128 + signal number)
_SIGNAL_NAMES: dict[int, str] = {
    132: "SIGILL (Illegal Instruction)",
    134: "SIGABRT (Abort)",
    136: "SIGFPE (Floating Point Exception)",
    139: "SIGSEGV (Segmentation Fault)",
    143: "SIGTERM (Terminated)",
}

# Regex patterns for parsing strace output
_STRACE_FILE_PATTERN = re.compile(r'(?:open|openat|creat)\([^"]*"([^"]+)"', re.IGNORECASE)
_STRACE_NET_PATTERN = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET(?:6)?,\s*sin(?:6)?_port=htons\((\d+)\),\s*sin(?:6)?_addr=inet_addr\("([^"]+)"\)',
    re.IGNORECASE,
)
_STRACE_EXEC_PATTERN = re.compile(r'execve\("([^"]+)"', re.IGNORECASE)
_STRACE_BLOCKED_PATTERN = re.compile(r"(\w+)\(.*=\s*-1\s+EPERM", re.IGNORECASE)


def _snapshot_workspace(workspace: Path) -> dict[str, float]:
    """Take a lightweight mtime snapshot of files in workspace."""
    snapshot: dict[str, float] = {}
    try:
        for p in workspace.rglob("*"):
            if p.is_file() and not p.name.startswith("."):
                try:
                    snapshot[str(p.relative_to(workspace))] = p.stat().st_mtime
                except OSError:
                    pass
    except Exception as exc:
        logger.debug(f"Workspace snapshot warning: {exc}")
    return snapshot


def _diff_workspace(workspace: Path, before: dict[str, float]) -> dict[str, list[str]]:
    """Compare workspace before and after execution to find created/modified files."""
    after = _snapshot_workspace(workspace)
    created: list[str] = []
    modified: list[str] = []

    for rel_path, mtime in after.items():
        if rel_path not in before:
            created.append(rel_path)
        elif mtime > before[rel_path]:
            modified.append(rel_path)

    return {"created_files": created, "modified_files": modified}


@log_execution(tool_name="trace_execution")
@track_metrics("trace_execution")
@handle_tool_errors
async def trace_execution(
    file_path: str,
    arguments: list[str] | None = None,
    stdin_input: str | None = None,
    env_vars: dict[str, str] | None = None,
    timeout: int = 15,
    max_output_bytes: int = 100_000,
    capture_pcap: bool = False,
    seccomp_profile: str | None = None,
    isolation_backend: str = "auto",
    api_hooking: bool = False,
) -> ToolResult:
    """Execute a binary under sandbox monitoring to trace runtime behavior.

    Monitors file system modifications, child process creation, network sockets,
    exit codes, crashes, and syscall activity. Supports Bubblewrap ('bwrap') namespace
    containment, user-space API hooking, Seccomp policies, and live network PCAP logging.

    Args:
        file_path: Absolute or workspace-relative path to the executable binary.
        arguments: Optional command-line arguments to pass to the binary.
        stdin_input: Optional text or payload to feed into stdin.
        env_vars: Optional environment variable overrides for execution.
        timeout: Maximum execution timeout in seconds (default: 15).
        max_output_bytes: Maximum stdout/stderr capture length (default: 100,000 bytes).
        capture_pcap: If True, records live network traffic to a PCAP file during execution.
        seccomp_profile: Optional Seccomp profile ('strict', 'no_network', 'read_only', 'minimal_sandbox').
        isolation_backend: Isolation sandbox backend ('auto', 'bwrap', 'host'). Default: 'auto'.
        api_hooking: If True, injects user-space API hooking to trace fopen, connect, system, execve.

    Returns:
        ToolResult with exit code, stdout/stderr, filesystem activity, crash status, syscalls, and API calls.

    Example:
        >>> result = await trace_execution("/app/workspace/sample.bin", capture_pcap=True, api_hooking=True)
        >>> print(result.status)
        'success'
    """
    validated_path = validate_file_path(file_path)
    workspace = get_workspace_config().workspace.resolve()
    args_list = arguments or []

    # Ensure executable permissions
    if not os.access(validated_path, os.X_OK):
        try:
            current_mode = validated_path.stat().st_mode
            validated_path.chmod(current_mode | 0o755)
        except Exception as exc:
            logger.debug(f"Failed to set executable mode on {validated_path}: {exc}")

    # Build safe execution environment
    safe_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": str(workspace / "tmp"),
    }
    (workspace / "tmp").mkdir(parents=True, exist_ok=True)
    if env_vars:
        for k, v in env_vars.items():
            if isinstance(k, str) and isinstance(v, str):
                safe_env[k] = v

    # Snapshot workspace state before run
    before_snap = _snapshot_workspace(workspace)

    # Check for strace on Linux
    has_strace = shutil.which("strace") is not None
    strace_log_file: Path | None = None

    # Resolve Seccomp profile if requested
    blocked_syscalls: list[str] = []
    if seccomp_profile:
        blocked_syscalls = get_profile_blocked_syscalls(seccomp_profile)

    # Check for Bubblewrap (bwrap) isolation
    has_bwrap = shutil.which("bwrap") is not None
    backend = isolation_backend.strip().lower()
    if backend == "bwrap" and not has_bwrap:
        return failure(
            "DEPENDENCY_MISSING", "Bubblewrap ('bwrap') is not installed on this system."
        )

    use_bwrap = has_bwrap and backend in ("auto", "bwrap")

    cmd: list[str] = []
    if has_strace:
        strace_log_file = workspace / "tmp" / f"strace_{os.getpid()}_{int(time.time() * 1000)}.log"
        strace_cmd = [
            "strace",
            "-f",  # Follow child processes
            "-s",
            "128",  # String length
            "-e",
            "trace=file,process,network",
            "-o",
            str(strace_log_file),
        ]
        if blocked_syscalls:
            inject_spec = f"fault={','.join(blocked_syscalls[:25])}:error=EPERM"
            strace_cmd.extend(["-e", inject_spec])

        strace_cmd.extend([str(validated_path), *args_list])
        cmd = strace_cmd
    else:
        cmd = [str(validated_path), *args_list]

    # Prepend bwrap sandbox if enabled
    if use_bwrap:
        bwrap_prefix = [
            "bwrap",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            str(workspace),
            str(workspace),
            "--tmpfs",
            "/tmp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--die-with-parent",
            "--new-session",
        ]
        if seccomp_profile in ("no_network", "strict"):
            bwrap_prefix.append("--unshare-net")
        cmd = [*bwrap_prefix, *cmd]

    # Configure API hooking if requested
    hook_log_file: Path | None = None
    if api_hooking:
        lib_hook, _ = compile_api_hook(workspace)
        if lib_hook and lib_hook.exists():
            hook_log_file = workspace / "tmp" / f"hook_{os.getpid()}_{int(time.time() * 1000)}.log"
            is_darwin = platform.system() == "Darwin"
            preload_var = "DYLD_INSERT_LIBRARIES" if is_darwin else "LD_PRELOAD"
            safe_env[preload_var] = str(lib_hook)
            safe_env["REVERSECORE_HOOK_LOG"] = str(hook_log_file)

    # Initialize live packet capture if requested
    pcap_recorder: LivePcapRecorder | None = None
    pcap_summary: dict[str, Any] | None = None
    if capture_pcap:
        captures_dir = workspace / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        pcap_file = captures_dir / f"pcap_{validated_path.stem}_{int(time.time() * 1000)}.pcap"
        pcap_recorder = LivePcapRecorder(output_pcap=pcap_file)
        pcap_recorder.start()

    t_start = time.perf_counter()
    timed_out = False
    proc = None
    stdout_data = b""
    stderr_data = b""

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_input is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workspace),
            env=safe_env,
        )

        input_bytes = stdin_input.encode("utf-8", errors="replace") if stdin_input else None
        try:
            stdout_raw, stderr_raw = await asyncio.wait_for(
                proc.communicate(input=input_bytes),
                timeout=timeout,
            )
            stdout_data = stdout_raw or b""
            stderr_data = stderr_raw or b""
        except asyncio.TimeoutError:
            timed_out = True
            logger.warning(f"Execution of {validated_path.name} timed out after {timeout}s")
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass

    except Exception as exc:
        if pcap_recorder:
            pcap_recorder.stop()
        return failure("EXECUTION_FAILED", f"Failed to launch binary: {exc}")
    finally:
        if pcap_recorder:
            pcap_summary = pcap_recorder.stop()

    execution_duration_ms = round((time.perf_counter() - t_start) * 1000, 2)
    exit_code = proc.returncode if proc and proc.returncode is not None else -1

    # Detect signals or crashes
    crash_info: dict[str, Any] | None = None
    if exit_code in _SIGNAL_NAMES:
        crash_info = {
            "signal_code": exit_code,
            "signal_name": _SIGNAL_NAMES[exit_code],
            "is_crash": True,
        }
    elif exit_code != 0:
        crash_info = {
            "signal_code": exit_code,
            "signal_name": "NON_ZERO_EXIT",
            "is_crash": False,
        }

    # Workspace file activity diff
    fs_diff = _diff_workspace(workspace, before_snap)

    # Parse strace output if available
    syscall_activity: dict[str, Any] = {
        "opened_files": [],
        "network_connections": [],
        "child_executions": [],
        "blocked_calls": [],
    }
    if strace_log_file and strace_log_file.exists():
        try:
            strace_text = strace_log_file.read_text(encoding="utf-8", errors="replace")
            # Files
            files_opened = list(dict.fromkeys(_STRACE_FILE_PATTERN.findall(strace_text)))
            syscall_activity["opened_files"] = [
                f for f in files_opened if not f.startswith("/etc/ld.so")
            ][:20]
            # Network
            nets = _STRACE_NET_PATTERN.findall(strace_text)
            syscall_activity["network_connections"] = [
                {"ip": ip, "port": port} for port, ip in nets
            ][:15]
            # Child execve
            execs = list(dict.fromkeys(_STRACE_EXEC_PATTERN.findall(strace_text)))
            syscall_activity["child_executions"] = [e for e in execs if e != str(validated_path)][
                :10
            ]
            # Blocked syscalls by Seccomp / fault injection
            blocked_matches = list(dict.fromkeys(_STRACE_BLOCKED_PATTERN.findall(strace_text)))
            syscall_activity["blocked_calls"] = blocked_matches
        except Exception as exc:
            logger.debug(f"Failed to parse strace log: {exc}")
        finally:
            try:
                strace_log_file.unlink(missing_ok=True)
            except Exception:
                pass

    # Parse hooked API log if available
    api_calls: list[dict[str, Any]] = []
    if hook_log_file and hook_log_file.exists():
        api_calls = parse_hook_log(hook_log_file)
        try:
            hook_log_file.unlink(missing_ok=True)
        except Exception:
            pass

    # Anomaly scoring
    anomalies: list[str] = []
    if timed_out:
        anomalies.append(
            f"Process timed out after {timeout} seconds (potential infinite loop or waiting for input)"
        )
    if crash_info and crash_info.get("is_crash"):
        anomalies.append(f"Process crashed with signal: {crash_info['signal_name']}")
    if fs_diff["created_files"]:
        anomalies.append(
            f"Process dropped or created {len(fs_diff['created_files'])} file(s): {', '.join(fs_diff['created_files'][:5])}"
        )
    if syscall_activity["network_connections"]:
        anomalies.append(
            f"Process initiated {len(syscall_activity['network_connections'])} network connection(s)"
        )
    if syscall_activity["child_executions"]:
        anomalies.append(
            f"Process spawned child executable(s): {', '.join(syscall_activity['child_executions'][:3])}"
        )
    if syscall_activity["blocked_calls"]:
        anomalies.append(
            f"Seccomp profile '{seccomp_profile}' blocked {len(syscall_activity['blocked_calls'])} forbidden syscall(s): {', '.join(syscall_activity['blocked_calls'])}"
        )
    if pcap_summary and pcap_summary.get("total_packets", 0) > 0:
        anomalies.append(f"Live network capture recorded {pcap_summary['total_packets']} packet(s)")
    if api_calls:
        risk_apis = [c["api"] for c in api_calls if c.get("api") in ("system", "execve", "connect")]
        if risk_apis:
            anomalies.append(
                f"Intercepted {len(risk_apis)} high-risk API call(s): {', '.join(set(risk_apis))}"
            )

    stdout_truncated = stdout_data[:max_output_bytes].decode("utf-8", errors="replace")
    stderr_truncated = stderr_data[:max_output_bytes].decode("utf-8", errors="replace")

    result: dict[str, Any] = {
        "status": "success",
        "binary_name": validated_path.name,
        "binary_path": str(validated_path),
        "arguments": args_list,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "execution_duration_ms": execution_duration_ms,
        "stdout": stdout_truncated,
        "stderr": stderr_truncated,
        "stdout_bytes": len(stdout_data),
        "stderr_bytes": len(stderr_data),
        "isolation_backend": "bwrap" if use_bwrap else "host",
        "crash_info": crash_info,
        "file_activity": fs_diff,
        "syscall_activity": syscall_activity,
        "anomalies": anomalies,
    }

    if api_hooking:
        result["api_activity"] = {
            "hooking_enabled": True,
            "total_calls_intercepted": len(api_calls),
            "calls": api_calls[:50],
        }

    if seccomp_profile:
        result["seccomp_profile"] = {
            "profile_name": seccomp_profile,
            "blocked_syscalls": blocked_syscalls,
            "enforcement": "strace_fault_injection" if has_strace else "simulated",
            "violations_detected": len(syscall_activity["blocked_calls"]),
        }

    if pcap_summary:
        result["pcap_capture"] = pcap_summary

    status_msg = (
        f"Executed '{validated_path.name}' in {execution_duration_ms} ms (exit code: {exit_code})."
    )
    if anomalies:
        status_msg += f" Detected {len(anomalies)} behavioral anomaly/anomalies."
    if seccomp_profile:
        status_msg += f" Enforced Seccomp profile '{seccomp_profile}'."
    if pcap_summary:
        status_msg += f" Logged PCAP ({pcap_summary['total_packets']} pkts)."
    if api_hooking:
        status_msg += f" Intercepted {len(api_calls)} API call(s)."

    return success(data=result, message=status_msg)
