"""Analysis helpers for the sandbox execution tracer.

Pure, side-effect-light building blocks used by ``trace_execution``:

- Exit status / signal classification (handles both negative asyncio return codes
  and shell-style ``128 + signal`` codes)
- Bounded output capture so a noisy sample cannot exhaust server memory
- Opt-in POSIX resource limits (CPU, memory, file size, open files)
- Dropped file inspection (sha256, size, executable format)
- A simple, explainable risk assessment built from the collected telemetry
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Exit status / signal classification
# ---------------------------------------------------------------------------

_SIGNAL_DESCRIPTIONS: dict[int, str] = {
    signal.SIGILL: "SIGILL (Illegal Instruction)",
    signal.SIGABRT: "SIGABRT (Abort)",
    signal.SIGFPE: "SIGFPE (Floating Point Exception)",
    signal.SIGSEGV: "SIGSEGV (Segmentation Fault)",
    signal.SIGBUS: "SIGBUS (Bus Error)",
    signal.SIGTRAP: "SIGTRAP (Trace/Breakpoint Trap)",
    signal.SIGSYS: "SIGSYS (Bad System Call)",
    signal.SIGTERM: "SIGTERM (Terminated)",
    signal.SIGKILL: "SIGKILL (Killed)",
}
if hasattr(signal, "SIGXCPU"):
    _SIGNAL_DESCRIPTIONS[signal.SIGXCPU] = "SIGXCPU (CPU Time Limit Exceeded)"
if hasattr(signal, "SIGXFSZ"):
    _SIGNAL_DESCRIPTIONS[signal.SIGXFSZ] = "SIGXFSZ (File Size Limit Exceeded)"

# Signals that indicate the sample itself faulted (or was terminated) rather than
# being stopped by a resource limit or by the tracer.
_CRASH_SIGNALS: frozenset[int] = frozenset(
    {
        signal.SIGILL,
        signal.SIGABRT,
        signal.SIGFPE,
        signal.SIGSEGV,
        signal.SIGBUS,
        signal.SIGTRAP,
        signal.SIGSYS,
        signal.SIGTERM,
    }
)

_RESOURCE_SIGNAL_NAMES: frozenset[str] = frozenset({"SIGXCPU", "SIGXFSZ"})


def classify_exit(exit_code: int) -> dict[str, Any] | None:
    """Classify a process exit status.

    ``asyncio`` reports a process killed by signal ``N`` as ``-N``, while a shell
    wrapper reports ``128 + N``. Both forms are recognised.

    Args:
        exit_code: Process return code.

    Returns:
        ``None`` for a clean exit, otherwise a dict with ``signal_code``,
        ``signal_name``, ``is_crash`` and, for signals, ``signal_number`` and
        ``resource_limit_hit``.
    """
    if exit_code == 0:
        return None

    sig_num: int | None = None
    if exit_code < 0:
        sig_num = -exit_code
    elif 129 <= exit_code <= 159:
        sig_num = exit_code - 128

    if sig_num is not None:
        try:
            sig = signal.Signals(sig_num)
        except ValueError:
            sig = None
        if sig is not None:
            return {
                "signal_code": exit_code,
                "signal_number": sig_num,
                "signal_name": _SIGNAL_DESCRIPTIONS.get(sig_num, sig.name),
                "is_crash": sig_num in _CRASH_SIGNALS,
                "resource_limit_hit": sig.name in _RESOURCE_SIGNAL_NAMES,
            }

    return {
        "signal_code": exit_code,
        "signal_name": "NON_ZERO_EXIT",
        "is_crash": False,
    }


# ---------------------------------------------------------------------------
# Bounded output capture
# ---------------------------------------------------------------------------

_READ_CHUNK = 64 * 1024


class CappedBuffer:
    """Accumulates up to ``limit`` bytes while counting everything that was produced."""

    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self.data = bytearray()
        self.total = 0

    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        remaining = self.limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])

    @property
    def truncated(self) -> bool:
        return self.total > len(self.data)


async def _drain(stream: asyncio.StreamReader | None, buf: CappedBuffer) -> None:
    if stream is None:
        return
    while True:
        chunk = await stream.read(_READ_CHUNK)
        if not chunk:
            return
        buf.feed(chunk)


async def _feed_stdin(proc: asyncio.subprocess.Process, payload: bytes | None) -> None:
    writer = proc.stdin
    if writer is None:
        return
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def collect_output(
    proc: asyncio.subprocess.Process,
    stdin_payload: bytes | None,
    stdout_buf: CappedBuffer,
    stderr_buf: CappedBuffer,
) -> None:
    """Feed stdin and drain stdout/stderr into capped buffers until the process exits.

    The buffers are filled incrementally, so partial output survives cancellation
    (e.g. when the caller wraps this in ``asyncio.wait_for`` and the timeout fires).
    """
    await asyncio.gather(
        _feed_stdin(proc, stdin_payload),
        _drain(proc.stdout, stdout_buf),
        _drain(proc.stderr, stderr_buf),
    )
    await proc.wait()


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

# name -> (min, max)
_LIMIT_BOUNDS: dict[str, tuple[int, int]] = {
    "cpu_seconds": (1, 3600),
    "memory_mb": (16, 65_536),
    "max_file_size_mb": (1, 10_240),
    "max_open_files": (8, 65_536),
}


def validate_resource_limits(limits: dict[str, int] | None) -> dict[str, int]:
    """Validate user supplied resource limits.

    Args:
        limits: Mapping with any of ``cpu_seconds``, ``memory_mb``,
            ``max_file_size_mb`` and ``max_open_files``.

    Returns:
        A clean dict of validated integer limits (empty when none requested).

    Raises:
        ValidationError: On unknown keys, non-integer values or out-of-range values.
    """
    if not limits:
        return {}
    clean: dict[str, int] = {}
    for key, value in limits.items():
        if key not in _LIMIT_BOUNDS:
            raise ValidationError(
                f"Unknown resource limit '{key}'. Allowed: {sorted(_LIMIT_BOUNDS)}"
            )
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"Resource limit '{key}' must be an integer, got {value!r}")
        low, high = _LIMIT_BOUNDS[key]
        if not low <= value <= high:
            raise ValidationError(f"Resource limit '{key}' must be between {low} and {high}")
        clean[key] = value
    return clean


def build_preexec(limits: dict[str, int]) -> Callable[[], None] | None:
    """Build a ``preexec_fn`` applying the limits (and disabling core dumps) in the child.

    Limits are inherited by everything the sample spawns. Applied best-effort per
    limit: some platforms (e.g. macOS for ``RLIMIT_AS``) refuse or ignore a limit.
    Returns ``None`` when no limits were requested or the platform lacks ``resource``.
    """
    if not limits or os.name != "posix":
        return None
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        return None

    plan: list[tuple[int, int]] = [(resource.RLIMIT_CORE, 0)]
    if "cpu_seconds" in limits:
        plan.append((resource.RLIMIT_CPU, limits["cpu_seconds"]))
    if "memory_mb" in limits:
        plan.append((resource.RLIMIT_AS, limits["memory_mb"] * 1024 * 1024))
    if "max_file_size_mb" in limits:
        plan.append((resource.RLIMIT_FSIZE, limits["max_file_size_mb"] * 1024 * 1024))
    if "max_open_files" in limits:
        plan.append((resource.RLIMIT_NOFILE, limits["max_open_files"]))

    def _apply() -> None:
        for res, value in plan:
            try:
                _, hard = resource.getrlimit(res)
                if hard != resource.RLIM_INFINITY:
                    value = min(value, hard)
                resource.setrlimit(res, (value, value))
            except (ValueError, OSError):
                pass

    return _apply


# ---------------------------------------------------------------------------
# Dropped file inspection
# ---------------------------------------------------------------------------

_MAX_DROPPED_FILES = 20
_MAX_HASH_BYTES = 16 * 1024 * 1024

_MACHO_MAGICS: frozenset[bytes] = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",  # universal binary (also Java class files)
    }
)


def detect_file_type(head: bytes) -> tuple[str, bool]:
    """Identify an executable format from the first bytes of a file.

    Returns:
        ``(file_type, is_executable_content)``.
    """
    if head.startswith(b"\x7fELF"):
        return "ELF", True
    if head.startswith(b"MZ"):
        return "PE/MZ", True
    if head[:4] in _MACHO_MAGICS:
        return "Mach-O", True
    if head.startswith(b"#!"):
        return "script", True
    if head.startswith(b"PK\x03\x04"):
        return "zip", False
    if head.startswith(b"%PDF"):
        return "pdf", False
    if not head:
        return "empty", False
    try:
        head.decode("utf-8")
        return "text", False
    except UnicodeDecodeError:
        return "data", False


def describe_dropped_files(
    workspace: Path, rel_paths: list[str], limit: int = _MAX_DROPPED_FILES
) -> list[dict[str, Any]]:
    """Hash and classify files created or modified by the sample.

    Symlinks and paths resolving outside the workspace are skipped so a sample
    cannot use this inspection to read files it should not reach.
    """
    root = workspace.resolve()
    details: list[dict[str, Any]] = []
    for rel in rel_paths[:limit]:
        path = workspace / rel
        try:
            if path.is_symlink() or not path.is_file():
                continue
            resolved = path.resolve()
            if root not in resolved.parents:
                continue
            size = resolved.stat().st_size
            digest = hashlib.sha256()
            hashed = 0
            head = b""
            with resolved.open("rb") as fh:
                while hashed < _MAX_HASH_BYTES:
                    chunk = fh.read(min(_READ_CHUNK, _MAX_HASH_BYTES - hashed))
                    if not chunk:
                        break
                    if not head:
                        head = chunk[:4096]
                    digest.update(chunk)
                    hashed += len(chunk)
            file_type, executable = detect_file_type(head)
            details.append(
                {
                    "path": rel,
                    "size": size,
                    "sha256": digest.hexdigest(),
                    "sha256_partial": size > hashed,
                    "file_type": file_type,
                    "executable_content": executable,
                    "has_exec_bit": bool(resolved.stat().st_mode & 0o111),
                }
            )
        except OSError as exc:
            logger.debug(f"Could not inspect dropped file {rel}: {exc}")
    return details


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_MARKERS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/.ssh/",
    "/etc/cron",
    "/var/spool/cron",
    "crontab",
    "LaunchAgents",
    "LaunchDaemons",
    "/etc/rc.local",
    "/etc/systemd/",
    "/.bashrc",
    "/.bash_profile",
    "/.profile",
    "/.zshrc",
    "/etc/ld.so.preload",
)

_HIGH_RISK_APIS: frozenset[str] = frozenset({"system", "execve", "connect"})


def assess_risk(
    *,
    crash_info: dict[str, Any] | None,
    timed_out: bool,
    dropped_files: list[dict[str, Any]],
    created_files: list[str],
    syscall_activity: dict[str, Any],
    api_calls: list[dict[str, Any]],
    pcap_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    """Derive an explainable 0-100 risk score from collected telemetry.

    Every contribution is listed under ``indicators`` so the score can be audited.
    """
    indicators: list[dict[str, Any]] = []

    def add(tag: str, weight: int, evidence: str) -> None:
        indicators.append({"tag": tag, "weight": weight, "evidence": evidence})

    if crash_info and crash_info.get("is_crash"):
        add("crash", 10, str(crash_info.get("signal_name")))
    if timed_out:
        add("timeout", 5, "process did not finish before the timeout")

    executable_drops = [d["path"] for d in dropped_files if d.get("executable_content")]
    if executable_drops:
        add("dropped_executable", 30, ", ".join(executable_drops[:3]))
    elif created_files:
        add("dropped_files", 10, f"{len(created_files)} file(s) created")

    net_conns = syscall_activity.get("network_connections") or []
    pcap_packets = (pcap_summary or {}).get("total_packets", 0)
    api_connects = [c for c in api_calls if c.get("api") == "connect"]
    if net_conns or pcap_packets or api_connects:
        add(
            "network_activity",
            20,
            f"{len(net_conns)} connection(s), {pcap_packets} packet(s), "
            f"{len(api_connects)} connect() call(s)",
        )

    children = syscall_activity.get("child_executions") or []
    api_exec = [c for c in api_calls if c.get("api") in ("system", "execve")]
    if children or api_exec:
        add("process_spawn", 20, ", ".join(children[:3]) or f"{len(api_exec)} exec API call(s)")

    risky_apis = sorted({c.get("api", "") for c in api_calls} & _HIGH_RISK_APIS)
    if risky_apis:
        add("high_risk_api", 10, ", ".join(risky_apis))

    sensitive = sorted(
        {
            f
            for f in (syscall_activity.get("opened_files") or [])
            if any(marker in f for marker in _SENSITIVE_PATH_MARKERS)
        }
    )
    if sensitive:
        add("persistence_or_credential_access", 25, ", ".join(sensitive[:3]))

    if syscall_activity.get("blocked_calls"):
        add(
            "containment_violation",
            15,
            ", ".join(syscall_activity["blocked_calls"][:5]),
        )

    score = min(100, sum(i["weight"] for i in indicators))
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "tags": [i["tag"] for i in indicators],
        "indicators": indicators,
    }
