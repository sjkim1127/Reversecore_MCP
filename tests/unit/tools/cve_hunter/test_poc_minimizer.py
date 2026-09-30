"""Unit tests for Testcase Minimizer and PoC Generator."""

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from reversecore_mcp.core.exceptions import ExecutionTimeoutError
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import cve_minimize_poc
from reversecore_mcp.tools.cve_hunter.poc_minimizer import (
    _test_input_causes_crash,
    delta_debug_minimize,
    generate_c_poc_harness,
    generate_python_poc_script,
    minimize_poc_impl,
)


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.write_bytes(content)
        return f

    return _create


@pytest.mark.unit
class TestPocMinimizer:
    """Tests for payload minimization and standalone PoC script generation."""

    def test_generate_python_poc_script(self):
        script = generate_python_poc_script(
            target_binary_path="/app/target_fuzzer",
            payload_bytes=b"CRASH_PAYLOAD_1234",
            cwe_id="CWE-122",
            bug_name="Heap Buffer Overflow",
        )
        assert "CVE Proof-of-Concept" in script
        assert "PAYLOAD_HEX" in script
        assert "/app/target_fuzzer" in script
        assert "subprocess.run" in script

    def test_generate_c_poc_harness(self):
        c_code = generate_c_poc_harness(
            target_function="parse_header",
            payload_bytes=b"\x41\x42\x43\x44",
            cwe_id="CWE-416",
        )
        assert "parse_header" in c_code
        assert "g_poc_payload" in c_code
        assert "0x41, 0x42, 0x43, 0x44" in c_code

    @pytest.mark.parametrize("payload_size", [512, 513, 1024])
    def test_generate_c_poc_harness_declares_emitted_payload_size(self, payload_size):
        c_code = generate_c_poc_harness(
            target_function="parse_header",
            payload_bytes=b"A" * payload_size,
        )

        array_body = c_code.split("g_poc_payload[] = {", 1)[1].split("};", 1)[0]
        emitted_elements = [element.strip() for element in array_body.split(",") if element.strip()]
        size_declaration = next(line for line in c_code.splitlines() if "g_poc_size =" in line)
        declared_size = int(size_declaration.split("=", 1)[1].strip().rstrip(";"))

        assert len(emitted_elements) == min(payload_size, 512)
        assert declared_size == len(emitted_elements)

    @pytest.mark.asyncio
    async def test_test_input_causes_crash_subprocess(self, workspace_file):
        test_bin = workspace_file("test_bin_crash.bin")

        # Case 1: CalledProcessError with ASan in stderr triggers crash detection
        asan_err = subprocess.CalledProcessError(
            1, [str(test_bin)], stderr="AddressSanitizer: heap-buffer-overflow"
        )
        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.execute_subprocess_async",
            side_effect=asan_err,
        ) as mock_exec:
            assert await _test_input_causes_crash(test_bin, b"TEST_PAYLOAD") is True
            mock_exec.assert_awaited_once()

        # Case 2: Normal exit without ASan does not trigger crash detection
        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.execute_subprocess_async",
            return_value=("normal execution completed", 30),
        ):
            assert await _test_input_causes_crash(test_bin, b"NORMAL_PAYLOAD") is False

        # Case 3: Output with ASan message without non-zero exit triggers crash detection
        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.execute_subprocess_async",
            return_value=("AddressSanitizer: global-buffer-overflow", 35),
        ):
            assert await _test_input_causes_crash(test_bin, b"ASAN_PAYLOAD") is True

    @pytest.mark.asyncio
    async def test_testcase_uses_new_workspace_cache_and_cleans_up(self, tmp_path, monkeypatch):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        cache_dir = workspace / ".cache"
        config = SimpleNamespace(
            workspace=workspace,
            sandbox_enabled=True,
            sandbox_mode="host",
            sandbox_user="nobody",
        )
        monkeypatch.setattr(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.get_config", lambda: config
        )
        monkeypatch.setattr("reversecore_mcp.core.config.get_config", lambda: config)
        candidate_paths: list[Path] = []

        async def inspect_candidate(command, **kwargs):
            candidate = Path(command[1])
            assert candidate.parent == cache_dir
            assert candidate.read_bytes() == b"HOST_SANDBOX_PAYLOAD"
            candidate_paths.append(candidate)
            return "normal execution", 16

        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.execute_subprocess_async",
            side_effect=inspect_candidate,
        ):
            result = await _test_input_causes_crash(tmp_path / "target", b"HOST_SANDBOX_PAYLOAD")

        assert result is False
        assert cache_dir.is_dir()
        assert len(candidate_paths) == 1
        assert not candidate_paths[0].exists()

    @pytest.mark.parametrize(
        ("outcome", "expected_crash"),
        [("normal", False), ("timeout", False), ("subprocess_failure", True)],
    )
    @pytest.mark.asyncio
    async def test_candidate_is_cleaned_after_execution_outcomes(
        self, outcome, expected_crash, tmp_path, monkeypatch
    ):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        config = SimpleNamespace(
            workspace=workspace,
            sandbox_enabled=False,
            sandbox_mode="disabled",
            sandbox_user="nobody",
        )
        monkeypatch.setattr(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.get_config", lambda: config
        )
        monkeypatch.setattr("reversecore_mcp.core.config.get_config", lambda: config)
        candidate_paths: list[Path] = []

        async def simulate_execution(command, **kwargs):
            candidate = Path(command[1])
            assert candidate.is_file()
            assert candidate.read_bytes() == b"CLEANUP_PAYLOAD"
            candidate_paths.append(candidate)
            if outcome == "timeout":
                raise ExecutionTimeoutError(5)
            if outcome == "subprocess_failure":
                raise subprocess.CalledProcessError(1, command, output="", stderr="")
            return "normal execution", len("normal execution")

        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.execute_subprocess_async",
            side_effect=simulate_execution,
        ):
            result = await _test_input_causes_crash(tmp_path / "target", b"CLEANUP_PAYLOAD")

        assert result is expected_crash
        assert len(candidate_paths) == 1
        assert not candidate_paths[0].exists()

    @pytest.mark.asyncio
    async def test_container_sandbox_prepares_candidate_for_dropped_user(
        self, tmp_path, monkeypatch
    ):
        if not hasattr(os, "geteuid") or not hasattr(os, "getuid"):
            pytest.skip("Container ownership preparation requires POSIX user IDs")

        import pwd

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        sandbox_user = pwd.getpwuid(os.getuid()).pw_name
        config = SimpleNamespace(
            workspace=workspace,
            sandbox_enabled=True,
            sandbox_mode="container",
            sandbox_user=sandbox_user,
        )
        monkeypatch.setattr(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.get_config", lambda: config
        )
        monkeypatch.setattr("reversecore_mcp.core.config.get_config", lambda: config)
        monkeypatch.setattr("reversecore_mcp.core.execution.os.geteuid", lambda: 0)
        prepared_paths: list[Path] = []
        real_prepare = __import__(
            "reversecore_mcp.core.execution", fromlist=["prepare_sandbox_access"]
        ).prepare_sandbox_access

        def record_preparation(path):
            prepared_paths.append(path)
            real_prepare(path)

        monkeypatch.setattr(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.prepare_sandbox_access",
            record_preparation,
        )
        candidate_paths: list[Path] = []

        async def inspect_candidate(command, **kwargs):
            candidate = Path(command[1])
            assert candidate.read_bytes() == b"CONTAINER_PAYLOAD"
            assert candidate.stat().st_uid == os.getuid()
            assert candidate.stat().st_mode & 0o777 == 0o600
            candidate_paths.append(candidate)
            return "normal execution", len("normal execution")

        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.execute_subprocess_async",
            side_effect=inspect_candidate,
        ):
            result = await _test_input_causes_crash(tmp_path / "target", b"CONTAINER_PAYLOAD")

        assert result is False
        assert candidate_paths[0] in prepared_paths
        assert not candidate_paths[0].exists()

    @pytest.mark.asyncio
    async def test_minimize_poc_rejects_symlinked_workspace_cache(self, tmp_path, monkeypatch):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside_cache = tmp_path / "outside-cache"
        outside_cache.mkdir()
        try:
            (workspace / ".cache").symlink_to(outside_cache, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"directory symlinks are unavailable: {exc}")

        target = tmp_path / "target.bin"
        target.write_bytes(b"target")
        crash_input = tmp_path / "crash.bin"
        crash_input.write_bytes(b"CRASH_INPUT")
        config = SimpleNamespace(
            workspace=workspace,
            sandbox_enabled=False,
            sandbox_mode="disabled",
            sandbox_user="nobody",
        )
        monkeypatch.setattr(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.get_config", lambda: config
        )
        monkeypatch.setattr("reversecore_mcp.core.config.get_config", lambda: config)
        monkeypatch.setattr(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer.validate_file_path",
            lambda path: Path(path),
        )

        res = await minimize_poc_impl(str(target), str(crash_input))

        assert res.status == "error"
        assert res.error_code == "INVALID_SCRATCH_DIR"

    @pytest.mark.asyncio
    async def test_delta_debug_minimize(self, workspace_file):
        dummy_bin = workspace_file("test_dummy.bin")
        original_data = b"PREFIX_1234567890_CRASH_SUFFIX_9876543210"

        async def mock_causes_crash(binary_path, data, timeout=5):
            # Crashes only if 'CRASH' substring is present
            return b"CRASH" in data

        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer._test_input_causes_crash",
            side_effect=mock_causes_crash,
        ):
            minimized = await delta_debug_minimize(dummy_bin, original_data, max_iterations=20)

        assert len(minimized) < len(original_data)
        assert b"CRASH" in minimized

    @pytest.mark.asyncio
    async def test_minimize_poc_impl_invalid_path(self):
        res = await minimize_poc_impl("/non/existent/bin", "/non/existent/poc.bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_minimize_poc_via_tool_wrapper(self):
        res = await cve_minimize_poc("/non/existent/bin", "/non/existent/poc.bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_minimize_poc_impl_success(self, workspace_file):
        test_bin = workspace_file("fuzzer_bin.bin", content=b"\x7fELF" + b"\x00" * 50)
        crash_input = workspace_file("crash_seed.bin", content=b"A" * 100 + b"CRASH" + b"B" * 100)

        async def mock_causes_crash(binary_path, data, timeout=5):
            return b"CRASH" in data

        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer._test_input_causes_crash",
            side_effect=mock_causes_crash,
        ):
            res = await minimize_poc_impl(
                binary_path=str(test_bin),
                crash_input_path=str(crash_input),
                target_function="parse_chunk",
            )

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["minimized_input_size_bytes"] < data["original_input_size_bytes"]
        assert "standalone_python_poc" in data
        assert "standalone_c_poc" in data
