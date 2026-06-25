"""Unit tests for memory forensics tools (memory.py).

Tests cover happy path with mocked Volatility3 subprocess calls
and edge cases: missing binary, invalid dump, timeout, empty output.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.forensics.memory import (
    memory_analyze,
    memory_detect_injections,
    memory_dump_module,
    memory_extract_strings,
    memory_list_processes,
    memory_list_symbols,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_dump(workspace_dir, patched_workspace_config):
    """Create a minimal fake memory dump file inside the allowed workspace."""
    dump = workspace_dir / "test.raw"
    dump.write_bytes(b"\x00" * 1024)
    return str(dump)


@pytest.fixture()
def vol_pslist_json():
    """Sample Volatility3 pslist JSON output."""
    return '[{"PID": 4, "ImageFileName": "System", "PPID": 0}, {"PID": 1234, "ImageFileName": "malware.exe", "PPID": 4}]'


# ── memory_list_symbols ───────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_list_symbols_success(tmp_dump):
    """Happy path: vol --info returns symbol table information."""
    mock_result = MagicMock()
    mock_result.stdout = "Available symbols:\n  windows.ntkrnlmp\n  linux.vmlinux\n"
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_list_symbols(tmp_dump)

    assert result.status == "success"
    assert "symbol_tables" in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_list_symbols_no_vol(tmp_dump):
    """Edge case: Volatility3 not installed."""
    with patch("shutil.which", return_value=None):
        result = await memory_list_symbols(tmp_dump)

    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_list_symbols_invalid_path():
    """Edge case: dump file does not exist."""
    result = await memory_list_symbols("/nonexistent/path/dump.raw")
    assert result.status == "error"


# ── memory_analyze ────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_analyze_help():
    """Happy path: plugin='help' returns supported plugins list."""
    result = await memory_analyze("any_path", plugin="help", _bypass_queue=True)
    assert result.status == "success"
    assert "supported_plugins" in result.data
    assert "pslist" in result.data["supported_plugins"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_analyze_pslist_success(tmp_dump, vol_pslist_json):
    """Happy path: pslist plugin runs and returns rows."""
    mock_result = MagicMock()
    mock_result.stdout = vol_pslist_json
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_analyze(tmp_dump, plugin="pslist", _bypass_queue=True)

    assert result.status == "success"
    assert "rows" in result.data
    assert len(result.data["rows"]) == 2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_analyze_invalid_plugin(tmp_dump):
    """Edge case: unsupported plugin name is rejected."""
    result = await memory_analyze(tmp_dump, plugin="invalid_plugin_xyz", _bypass_queue=True)
    assert result.status == "error"
    assert result.error_code == "UNSUPPORTED_PLUGIN"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_analyze_vol_not_found(tmp_dump):
    """Edge case: Volatility3 binary not available."""
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=FileNotFoundError,
    ):
        result = await memory_analyze(tmp_dump, plugin="pslist", _bypass_queue=True)

    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_analyze_timeout(tmp_dump):
    """Edge case: Volatility3 plugin times out."""
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=subprocess.TimeoutExpired(cmd="vol", timeout=300),
    ):
        result = await memory_analyze(tmp_dump, plugin="pslist", _bypass_queue=True)

    assert result.status == "error"
    assert result.error_code == "TIMEOUT"


# ── memory_list_processes ─────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_list_processes_success(tmp_dump, vol_pslist_json):
    """Happy path: list processes with hidden process detection."""
    mock_result = MagicMock()
    mock_result.stdout = vol_pslist_json
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_list_processes(tmp_dump, include_hidden=True)

    assert result.status == "success"
    assert "processes" in result.data
    assert result.data["process_count"] == 2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_list_processes_no_hidden(tmp_dump, vol_pslist_json):
    """Happy path: list processes without hidden scan."""
    mock_result = MagicMock()
    mock_result.stdout = vol_pslist_json
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_list_processes(tmp_dump, include_hidden=False)

    assert result.status == "success"
    assert "hidden_processes" not in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_list_processes_vol_missing(tmp_dump):
    """Edge case: Volatility3 not installed."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = await memory_list_processes(tmp_dump)

    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


# ── memory_detect_injections ──────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_detect_injections_clean(tmp_dump):
    """Happy path: malfind returns no results (clean dump)."""
    mock_result = MagicMock()
    mock_result.stdout = "[]"
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_detect_injections(tmp_dump, _bypass_queue=True)

    assert result.status == "success"
    assert result.data["injection_count"] == 0
    assert result.data["severity"] == "CLEAN"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_detect_injections_found(tmp_dump):
    """Happy path: malfind finds injected regions."""
    injection_json = '[{"PID": 1234, "Hexdump": "4D5A90...(MZ)", "Disassembly": "CALL 0x1000"}]'
    mock_result = MagicMock()
    mock_result.stdout = injection_json
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_detect_injections(tmp_dump, _bypass_queue=True)

    assert result.status == "success"
    assert result.data["injection_count"] >= 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_detect_injections_vol_error(tmp_dump):
    """Edge case: Volatility3 returns runtime error."""
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=RuntimeError("Symbol table not found"),
    ):
        result = await memory_detect_injections(tmp_dump, _bypass_queue=True)

    assert result.status == "error"
    assert result.error_code == "VOLATILITY_ERROR"


# ── memory_extract_strings ────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_extract_strings_success(tmp_dump):
    """Happy path: strings extracted from dump file."""
    mock_result = MagicMock()
    mock_result.stdout = "cmd.exe\n192.168.1.1\nhttps://evil.com/c2\npowershell\n"
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_extract_strings(tmp_dump)

    assert result.status == "success"
    assert result.data["string_count"] >= 1
    assert "notable" in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_extract_strings_large_file(workspace_dir, patched_workspace_config):
    """Edge case: dump file exceeds 512 MB limit."""
    dump = workspace_dir / "large.raw"
    # Create sparse file by seeking to large offset
    with dump.open("wb") as f:
        f.seek(512 * 1024 * 1024 + 1)
        f.write(b"\x00")

    result = await memory_extract_strings(str(dump))
    assert result.status == "error"
    assert result.error_code == "FILE_TOO_LARGE"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_extract_strings_no_strings(tmp_dump):
    """Edge case: strings binary returns empty output, falls back to Python."""
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_extract_strings(tmp_dump)

    assert result.status == "success"
    # Should gracefully return 0 strings
    assert result.data["string_count"] == 0


# ── memory_dump_module ────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_dump_module_process_not_found(tmp_dump, vol_pslist_json):
    """Edge case: target process not found in memory dump."""
    mock_result = MagicMock()
    mock_result.stdout = vol_pslist_json
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await memory_dump_module(tmp_dump, process_name="nonexistent.exe")

    assert result.status == "error"
    assert result.error_code == "PROCESS_NOT_FOUND"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_dump_module_success(tmp_dump, vol_pslist_json, workspace_dir):
    """Happy path: module dump for existing process."""
    dlllist_json = '[{"BaseDllName": "malware.exe", "DllBase": "0x400000"}]'
    call_count = 0

    def mock_run(*args, **kwargs):
        nonlocal call_count
        mock = MagicMock()
        mock.returncode = 0
        mock.stderr = ""
        mock.stdout = vol_pslist_json if call_count == 0 else dlllist_json
        call_count += 1
        return mock

    with patch("subprocess.run", side_effect=mock_run):
        result = await memory_dump_module(
            tmp_dump,
            process_name="malware.exe",
            output_dir=str(workspace_dir / "dumps"),
        )

    assert result.status == "success"
    assert "modules" in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_vol3_errors(tmp_dump):
    """Test _run_vol3 internal error handling paths."""
    from reversecore_mcp.tools.forensics.memory import _run_vol3

    # Missing vol executable (FileNotFoundError)
    with patch("shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError) as exc:
            _run_vol3(tmp_dump, "pslist")
        assert "vol is not installed" in str(exc.value)

    # Non-zero exit code with stdout (partial output warning)
    mock_res = MagicMock()
    mock_res.returncode = 1
    mock_res.stdout = "[]"
    mock_res.stderr = "symbol pack warning"
    with patch("subprocess.run", return_value=mock_res):
        res = _run_vol3(tmp_dump, "pslist")
        assert res == {"rows": [], "plugin": "pslist"}

    # Non-zero exit code without stdout (RuntimeError)
    mock_res = MagicMock()
    mock_res.returncode = 2
    mock_res.stdout = ""
    mock_res.stderr = "critical crash"
    with patch("subprocess.run", return_value=mock_res):
        with pytest.raises(RuntimeError) as exc:
            _run_vol3(tmp_dump, "pslist")
        assert "Volatility3 error" in str(exc.value)

    # Empty stdout
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "   "
    mock_res.stderr = ""
    with patch("subprocess.run", return_value=mock_res):
        res = _run_vol3(tmp_dump, "pslist")
        assert res == {"rows": [], "plugin": "pslist"}

    # JSONDecodeError (fallback to raw output)
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "Raw non-JSON output here"
    mock_res.stderr = ""
    with patch("subprocess.run", return_value=mock_res):
        res = _run_vol3(tmp_dump, "pslist")
        assert res == {"raw_output": "Raw non-JSON output here", "plugin": "pslist"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_analyze_task_queue_fallback(tmp_dump):
    """Happy path: memory_analyze runs directly when task queue fails/is bypassed."""
    mock_result = MagicMock()
    mock_result.stdout = "[]"
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch(
        "reversecore_mcp.core.task_queue.run_task_or_fallback",
        side_effect=Exception("Queue unavailable"),
    ):
        with patch("subprocess.run", return_value=mock_result):
            # Do not pass _bypass_queue, triggers queue try block which fails and falls back
            result = await memory_analyze(tmp_dump, plugin="pslist")
    assert result.status == "success"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_analyze_args_and_runtime_error(
    tmp_dump, workspace_dir, patched_workspace_config
):
    """Happy path/Edge case: symbol_path, extra_args, and RuntimeError."""
    mock_result = MagicMock()
    mock_result.stdout = "[]"
    mock_result.stderr = ""
    mock_result.returncode = 0

    sym = workspace_dir / "symbols" / "pack.txt"
    sym.parent.mkdir(parents=True, exist_ok=True)
    sym.write_text("some symbol data")

    # Success path with symbol_path & extra_args
    with patch("subprocess.run", return_value=mock_result) as mock_sub:
        result = await memory_analyze(
            tmp_dump,
            plugin="pslist",
            symbol_path=str(sym),
            extra_args="--pid 123",
            _bypass_queue=True,
        )
        assert result.status == "success"
        called_args = mock_sub.call_args[0][0]
        assert "--symbol-dirs" in called_args
        assert "--pid" in called_args
        assert "123" in called_args

    # Volatility error path (RuntimeError)
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=RuntimeError("vol crash"),
    ):
        result = await memory_analyze(
            tmp_dump,
            plugin="pslist",
            _bypass_queue=True,
        )
    assert result.status == "error"
    assert result.error_code == "VOLATILITY_ERROR"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_list_processes_errors(tmp_dump):
    """Edge cases: list processes Volatility runtime error and psscan sub-step failure."""
    # Volatility error
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=RuntimeError("vol crash"),
    ):
        result = await memory_list_processes(tmp_dump)
    assert result.status == "error"
    assert result.error_code == "VOLATILITY_ERROR"

    # psscan fails but pslist succeeds
    def mock_run_vol(dump_path, plugin, extra_args=None):
        if plugin == "pslist":
            return {"rows": [{"PID": 4, "ImageFileName": "System"}]}
        raise RuntimeError("psscan failed")

    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=mock_run_vol,
    ):
        result = await memory_list_processes(tmp_dump, include_hidden=True)
    assert result.status == "success"
    assert result.data["psscan_error"] == "psscan failed"
    assert result.data["hidden_processes"] == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_detect_injections_task_queue_fallback_and_dependency_missing(
    tmp_dump,
):
    """Happy path/Edge case: detect injections task queue and FileNotFoundError."""
    # Task queue fallback path
    mock_result = MagicMock()
    mock_result.stdout = "[]"
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch(
        "reversecore_mcp.core.task_queue.run_task_or_fallback",
        side_effect=Exception("Queue unavailable"),
    ):
        with patch("subprocess.run", return_value=mock_result):
            # Triggers queue check because _bypass_queue is not passed
            result = await memory_detect_injections(tmp_dump)
    assert result.status == "success"

    # FileNotFoundError (dependency missing)
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=FileNotFoundError(),
    ):
        result = await memory_detect_injections(tmp_dump, _bypass_queue=True)
    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"

    # RuntimeError
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=RuntimeError("error"),
    ):
        result = await memory_detect_injections(tmp_dump, _bypass_queue=True)
    assert result.status == "error"
    assert result.error_code == "VOLATILITY_ERROR"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_extract_strings_no_binary(tmp_dump):
    """Edge case: strings binary missing triggers pure-Python extraction fallback."""
    with patch("shutil.which", return_value=None):
        result = await memory_extract_strings(tmp_dump)

    assert result.status == "success"
    # Fallback should still find some strings (our fake dump has zeros, but we can verify it ran)
    assert "string_count" in result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_dump_module_module_name_and_exceptions(
    tmp_dump, vol_pslist_json, workspace_dir
):
    """Happy path/Edge cases: dump module with module filter and error conditions."""
    dlllist_json = '[{"BaseDllName": "malware.exe", "DllBase": "0x400000"}]'

    # Filtered module dump
    call_count = 0

    def mock_run_filter(*args, **kwargs):
        nonlocal call_count
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = vol_pslist_json if call_count == 0 else dlllist_json
        call_count += 1
        return mock

    output_dir = str(workspace_dir / "dumps_filter")
    with patch("subprocess.run", side_effect=mock_run_filter) as mock_sub:
        result = await memory_dump_module(
            tmp_dump,
            process_name="malware.exe",
            module_name="injected.dll",
            output_dir=output_dir,
        )
        assert result.status == "success"
        # Verify module filter argument
        called_args = mock_sub.call_args[0][0]
        assert "--module=injected.dll" in called_args

    # Volatility dependency missing (FileNotFoundError)
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=FileNotFoundError(),
    ):
        result = await memory_dump_module(tmp_dump, process_name="malware.exe")
    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"

    # Volatility runtime error (RuntimeError)
    with patch(
        "reversecore_mcp.tools.forensics.memory._run_vol3_async",
        side_effect=RuntimeError("error"),
    ):
        result = await memory_dump_module(tmp_dump, process_name="malware.exe")
    assert result.status == "error"
    assert result.error_code == "VOLATILITY_ERROR"
