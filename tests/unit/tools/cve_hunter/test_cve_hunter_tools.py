"""Unit tests for CVE Hunter FastMCP tool wrappers and Plugin."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core.result import success
from reversecore_mcp.tools.cve_hunter import CVEHunterToolsPlugin
from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import (
    cve_fuzz_target,
    cve_minimize_poc,
    cve_synthesize_harness,
    cve_triage_crash,
    hunt_cve_vulnerabilities,
)


@pytest.mark.unit
class TestCveHunterToolsWrappers:
    """Test FastMCP tool wrapper endpoints."""

    @pytest.mark.asyncio
    async def test_cve_synthesize_harness_wrapper(self):
        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.synthesize_fuzz_harness_impl",
            new_callable=AsyncMock,
            return_value=success({"harness_source_code": "int LLVM..."}),
        ) as mock_impl:
            res = await cve_synthesize_harness(
                "/app/workspace/target.h", sample_file_path="/app/sample.bin"
            )
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                header_or_binary_path="/app/workspace/target.h",
                sample_file_path="/app/sample.bin",
                target_function=None,
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_cve_fuzz_target_wrapper(self):
        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.run_hybrid_fuzz_impl",
            new_callable=AsyncMock,
            return_value=success({"total_executions": 1000}),
        ) as mock_impl:
            res = await cve_fuzz_target("/app/workspace/fuzzer", max_total_time_seconds=10)
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                target_binary_path="/app/workspace/fuzzer",
                corpus_dir=None,
                dictionary_path=None,
                max_total_time_seconds=10,
                enable_angr_concolic=True,
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_cve_triage_crash_wrapper(self):
        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.triage_crash_impl",
            new_callable=AsyncMock,
            return_value=success({"bug_type": "heap-buffer-overflow"}),
        ) as mock_impl:
            res = await cve_triage_crash("==123==ERROR: AddressSanitizer: ...")
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                crash_log_or_text="==123==ERROR: AddressSanitizer: ...",
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_cve_minimize_poc_wrapper(self):
        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.minimize_poc_impl",
            new_callable=AsyncMock,
            return_value=success({"minimized_input_size_bytes": 12}),
        ) as mock_impl:
            res = await cve_minimize_poc("/app/target", "/app/crash.bin", target_function="parse")
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                binary_path="/app/target",
                crash_input_path="/app/crash.bin",
                target_function="parse",
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_hunt_cve_vulnerabilities_wrapper(self):
        with patch(
            "reversecore_mcp.tools.cve_hunter.cve_hunter_tools.hunt_cve_pipeline_impl",
            new_callable=AsyncMock,
            return_value=success({"cwe_id": "CWE-122"}),
        ) as mock_impl:
            res = await hunt_cve_vulnerabilities("/app/target.h", options={"fuzz_duration": 10})
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                target_path_str="/app/target.h",
                sample_file_path=None,
                options={"fuzz_duration": 10},
                timeout=None,
            )


@pytest.mark.unit
class TestCveHunterToolsPlugin:
    """Test CVEHunterToolsPlugin plugin properties and registration."""

    def test_plugin_properties_and_register(self):
        plugin = CVEHunterToolsPlugin()
        assert plugin.name == "cve_hunter_tools"
        assert "CVE" in plugin.description

        mock_server = MagicMock()
        plugin.register(mock_server)
        assert mock_server.tool.call_count == 5
