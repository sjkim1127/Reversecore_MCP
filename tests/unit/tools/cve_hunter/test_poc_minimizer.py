"""Unit tests for Testcase Minimizer and PoC Generator."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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

    def test_test_input_causes_crash_subprocess(self, workspace_file):
        test_bin = workspace_file("test_bin_crash.bin")
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = b"AddressSanitizer: heap-buffer-overflow"

        with patch("subprocess.run", return_value=mock_proc):
            assert _test_input_causes_crash(test_bin, b"TEST_PAYLOAD") is True

    def test_delta_debug_minimize(self, workspace_file):
        dummy_bin = workspace_file("test_dummy.bin")
        original_data = b"PREFIX_1234567890_CRASH_SUFFIX_9876543210"

        def mock_causes_crash(binary_path, data, timeout=5):
            # Crashes only if 'CRASH' substring is present
            return b"CRASH" in data

        with patch(
            "reversecore_mcp.tools.cve_hunter.poc_minimizer._test_input_causes_crash",
            side_effect=mock_causes_crash,
        ):
            minimized = delta_debug_minimize(dummy_bin, original_data, max_iterations=20)

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

        def mock_causes_crash(binary_path, data, timeout=5):
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
