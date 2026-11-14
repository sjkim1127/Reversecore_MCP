"""Tests for the dynamic tracer extensions: crash classification, bounded output,
resource limits, dropped-file inspection and risk assessment."""

from __future__ import annotations

import asyncio
import os
import signal

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.dynamic import sandbox_tracer as st
from reversecore_mcp.tools.dynamic.sandbox_tracer import trace_execution
from reversecore_mcp.tools.dynamic.trace_analysis import (
    CappedBuffer,
    assess_risk,
    classify_exit,
    describe_dropped_files,
    detect_file_type,
    validate_resource_limits,
)


@pytest.fixture
def host_only(monkeypatch):
    """Force the plain host backend so tests behave the same on every platform."""
    monkeypatch.setattr(st, "_is_bwrap_supported", lambda: False)
    monkeypatch.setattr(st, "_is_strace_supported", lambda: False)


def _script(workspace, name: str, body: str):
    path = workspace / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------- classify_exit


class TestClassifyExit:
    def test_clean_exit(self):
        assert classify_exit(0) is None

    def test_negative_asyncio_segv_is_crash(self):
        info = classify_exit(-signal.SIGSEGV)
        assert info is not None
        assert info["is_crash"] is True
        assert info["signal_name"].startswith("SIGSEGV")
        assert info["signal_number"] == signal.SIGSEGV

    def test_shell_style_segv_is_crash(self):
        info = classify_exit(139)
        assert info is not None and info["is_crash"] is True

    def test_plain_nonzero_exit_is_not_crash(self):
        info = classify_exit(2)
        assert info == {"signal_code": 2, "signal_name": "NON_ZERO_EXIT", "is_crash": False}

    def test_sigkill_is_not_crash(self):
        info = classify_exit(-signal.SIGKILL)
        assert info is not None and info["is_crash"] is False

    def test_resource_limit_signal_flagged(self):
        info = classify_exit(-signal.SIGXCPU)
        assert info is not None
        assert info["is_crash"] is False
        assert info["resource_limit_hit"] is True


@pytest.mark.asyncio
async def test_trace_execution_detects_real_segfault(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(workspace_dir, "segv.sh", "kill -SEGV $$\n")
    res = await trace_execution(str(sample), isolation_backend="host", timeout=5)
    crash = res.data["crash_info"]
    assert crash["is_crash"] is True
    assert crash["signal_name"].startswith("SIGSEGV")
    assert "crash" in res.data["risk_assessment"]["tags"]


# ------------------------------------------------------------ bounded output


def test_capped_buffer_counts_everything_but_keeps_limit():
    buf = CappedBuffer(10)
    buf.feed(b"a" * 6)
    buf.feed(b"b" * 6)
    assert bytes(buf.data) == b"a" * 6 + b"b" * 4
    assert buf.total == 12
    assert buf.truncated is True


@pytest.mark.asyncio
async def test_trace_execution_caps_flooding_output(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(
        workspace_dir,
        "flood.sh",
        "i=0\nwhile [ $i -lt 300 ]; do printf '%01000d' 0; i=$((i+1)); done\n",
    )
    res = await trace_execution(
        str(sample), isolation_backend="host", timeout=10, max_output_bytes=2000
    )
    assert len(res.data["stdout"]) == 2000
    assert res.data["stdout_bytes"] == 300_000
    assert res.data["stdout_truncated"] is True
    assert res.data["stderr_truncated"] is False


@pytest.mark.asyncio
async def test_trace_execution_keeps_partial_output_on_timeout(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(workspace_dir, "partial.sh", "echo started\nsleep 30\n")
    res = await trace_execution(str(sample), isolation_backend="host", timeout=1)
    assert res.data["timed_out"] is True
    assert "started" in res.data["stdout"]


@pytest.mark.asyncio
async def test_trace_execution_still_feeds_stdin(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(workspace_dir, "echo_stdin.sh", "read line\necho got:$line\n")
    res = await trace_execution(
        str(sample), isolation_backend="host", timeout=5, stdin_input="hello\n"
    )
    assert "got:hello" in res.data["stdout"]


# ----------------------------------------------------------- resource limits


class TestResourceLimitValidation:
    def test_empty(self):
        assert validate_resource_limits(None) == {}
        assert validate_resource_limits({}) == {}

    def test_valid(self):
        assert validate_resource_limits({"cpu_seconds": 5, "memory_mb": 256}) == {
            "cpu_seconds": 5,
            "memory_mb": 256,
        }

    @pytest.mark.parametrize(
        "bad",
        [
            {"nope": 1},
            {"cpu_seconds": 0},
            {"cpu_seconds": 10**9},
            {"memory_mb": "100"},
            {"memory_mb": True},
        ],
    )
    def test_invalid(self, bad):
        with pytest.raises(ValidationError):
            validate_resource_limits(bad)  # type: ignore[arg-type]


@pytest.mark.skipif(os.name != "posix", reason="POSIX rlimits only")
@pytest.mark.asyncio
async def test_trace_execution_enforces_file_size_limit(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(
        workspace_dir,
        "bigwrite.sh",
        "dd if=/dev/zero of=big.bin bs=1024 count=4096 2>/dev/null\nexit 0\n",
    )
    res = await trace_execution(
        str(sample),
        isolation_backend="host",
        timeout=10,
        resource_limits={"max_file_size_mb": 1},
    )
    assert res.data["resource_limits"] == {"max_file_size_mb": 1}
    big = workspace_dir / "big.bin"
    assert big.exists()
    assert big.stat().st_size <= 1024 * 1024


@pytest.mark.asyncio
async def test_trace_execution_rejects_bad_resource_limits(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(workspace_dir, "noop.sh", "exit 0\n")
    res = await trace_execution(str(sample), isolation_backend="host", resource_limits={"x": 1})
    assert res.status == "error"


# ----------------------------------------------------------- dropped files


def test_detect_file_type():
    assert detect_file_type(b"\x7fELF....") == ("ELF", True)
    assert detect_file_type(b"MZ\x90\x00") == ("PE/MZ", True)
    assert detect_file_type(b"\xcf\xfa\xed\xfe") == ("Mach-O", True)
    assert detect_file_type(b"#!/bin/sh\n") == ("script", True)
    assert detect_file_type(b"hello") == ("text", False)
    assert detect_file_type(b"\xff\xfe\x00\x80") == ("data", False)
    assert detect_file_type(b"") == ("empty", False)


def test_describe_dropped_files_skips_symlinks_and_outside(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (ws / "ok.bin").write_bytes(b"\x7fELF" + b"\x00" * 10)
    (ws / "link").symlink_to(outside)

    details = describe_dropped_files(ws, ["ok.bin", "link", "missing"])

    assert [d["path"] for d in details] == ["ok.bin"]
    assert details[0]["file_type"] == "ELF"
    assert details[0]["executable_content"] is True
    assert len(details[0]["sha256"]) == 64


@pytest.mark.asyncio
async def test_trace_execution_reports_dropped_executable(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(
        workspace_dir,
        "dropper.sh",
        "printf '\\177ELF payload' > payload.bin\nexit 0\n",
    )
    res = await trace_execution(str(sample), isolation_backend="host", timeout=5)

    drops = {d["path"]: d for d in res.data["dropped_files"]}
    assert "payload.bin" in drops
    assert drops["payload.bin"]["file_type"] == "ELF"
    tags = res.data["risk_assessment"]["tags"]
    assert "dropped_executable" in tags
    assert res.data["risk_assessment"]["level"] in ("medium", "high", "critical")


@pytest.mark.asyncio
async def test_tracer_own_pcap_not_reported_as_dropped(
    workspace_dir, patched_workspace_config, host_only
):
    sample = _script(workspace_dir, "quiet.sh", "exit 0\n")
    res = await trace_execution(str(sample), isolation_backend="host", timeout=5, capture_pcap=True)
    activity = res.data["file_activity"]
    assert not any(
        p.endswith(".pcap") for p in activity["created_files"] + activity["modified_files"]
    )
    assert res.data["risk_assessment"]["tags"] == []
    assert res.data["anomalies"] == []


# ----------------------------------------------------------- risk assessment


def _risk(**overrides):
    base: dict = {
        "crash_info": None,
        "timed_out": False,
        "dropped_files": [],
        "created_files": [],
        "syscall_activity": {
            "opened_files": [],
            "network_connections": [],
            "child_executions": [],
            "blocked_calls": [],
        },
        "api_calls": [],
        "pcap_summary": None,
    }
    base.update(overrides)
    return assess_risk(**base)


def test_risk_clean_run_is_low():
    r = _risk()
    assert (r["score"], r["level"], r["tags"]) == (0, "low", [])


def test_risk_combines_and_caps_indicators():
    r = _risk(
        crash_info={"is_crash": True, "signal_name": "SIGSEGV"},
        dropped_files=[{"path": "a", "executable_content": True}],
        created_files=["a"],
        syscall_activity={
            "opened_files": ["/home/u/.ssh/id_rsa", "/etc/shadow"],
            "network_connections": [{"ip": "1.2.3.4", "port": "80"}],
            "child_executions": ["/bin/sh"],
            "blocked_calls": ["socket"],
        },
        api_calls=[{"api": "system"}],
    )
    assert r["level"] == "critical"
    assert r["score"] == 100
    assert {
        "crash",
        "dropped_executable",
        "network_activity",
        "process_spawn",
        "persistence_or_credential_access",
        "containment_violation",
    } <= set(r["tags"])


def test_risk_network_via_pcap_only():
    r = _risk(pcap_summary={"total_packets": 3})
    assert r["tags"] == ["network_activity"]


@pytest.mark.asyncio
async def test_collect_output_handles_stdin_closed_early():
    """Feeding stdin to a process that exits immediately must not raise."""
    proc = await asyncio.create_subprocess_exec(
        "true",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    from reversecore_mcp.tools.dynamic.trace_analysis import collect_output

    out, err = CappedBuffer(100), CappedBuffer(100)
    await collect_output(proc, b"x" * 1_000_000, out, err)
    assert proc.returncode == 0
