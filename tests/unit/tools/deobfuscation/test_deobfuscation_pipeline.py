"""Unit tests for unified deobfuscation pipeline."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.result import success
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline import (
    run_deobfuscation_pipeline_impl,
)
from reversecore_mcp.tools.deobfuscation.deobfuscation_tools import (
    run_deobfuscation_pipeline,
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
class TestDeobfuscationPipeline:
    """Test run_deobfuscation_pipeline_impl."""

    @pytest.mark.asyncio
    async def test_invalid_path_raises_validation_error(self):
        with pytest.raises(ValidationError):
            await run_deobfuscation_pipeline_impl("/non/existent/file.bin")

    @pytest.mark.asyncio
    async def test_invalid_path_via_tool_wrapper(self):
        res = await run_deobfuscation_pipeline("/non/existent/file.bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_pipeline_execution_high_severity(self, workspace_file):
        test_bin = workspace_file("malware_sample.exe")

        mock_strings_res = success(
            {
                "recovered_strings": [
                    {"string": "http://malicious.c2/bot", "type": "stack_string"},
                    {"string": "cmd.exe /c calc", "type": "emulated_loop"},
                ]
            }
        )

        mock_apis_res = success(
            {
                "peb_walking_detected": True,
                "resolved_apis": [
                    {"api_name": "VirtualAllocEx", "dll": "kernel32.dll"},
                    {"api_name": "WriteProcessMemory", "dll": "kernel32.dll"},
                    {"api_name": "CreateRemoteThread", "dll": "kernel32.dll"},
                    {"api_name": "RegSetValueExA", "dll": "advapi32.dll"},
                    {"api_name": "IsDebuggerPresent", "dll": "kernel32.dll"},
                ],
            }
        )

        mock_dead_code_res = success(
            {
                "opaque_predicates": [{"type": "zero_xor_test"}],
                "cfg_simplifications": [{"function": "main", "reduction_percent": "35%"}],
            }
        )

        with (
            patch(
                "reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline.deobfuscate_strings_impl",
                new_callable=AsyncMock,
                return_value=mock_strings_res,
            ),
            patch(
                "reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline.resolve_api_hashes_impl",
                new_callable=AsyncMock,
                return_value=mock_apis_res,
            ),
            patch(
                "reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline.eliminate_dead_code_impl",
                new_callable=AsyncMock,
                return_value=mock_dead_code_res,
            ),
        ):
            res = await run_deobfuscation_pipeline_impl(
                str(test_bin),
                options={"algorithm": "ror13", "function_address": "main"},
            )

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["obfuscation_level"] == "HIGH"
        assert data["obfuscation_severity_score"] >= 50
        assert "Process Injection (VirtualAllocEx)" in data["detected_capabilities"]
        assert "System Persistence (RegSetValueExA)" in data["detected_capabilities"]
        assert "Anti-Analysis Evasion (IsDebuggerPresent)" in data["detected_capabilities"]
        assert "Dynamic PEB/TEB Walking" in data["threat_tags"]

    @pytest.mark.asyncio
    async def test_pipeline_execution_low_severity(self, workspace_file):
        test_bin = workspace_file("clean_sample.exe")

        mock_strings_res = success({"recovered_strings": []})
        mock_apis_res = success({"peb_walking_detected": False, "resolved_apis": []})
        mock_dead_code_res = success({"opaque_predicates": [], "cfg_simplifications": []})

        with (
            patch(
                "reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline.deobfuscate_strings_impl",
                new_callable=AsyncMock,
                return_value=mock_strings_res,
            ),
            patch(
                "reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline.resolve_api_hashes_impl",
                new_callable=AsyncMock,
                return_value=mock_apis_res,
            ),
            patch(
                "reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline.eliminate_dead_code_impl",
                new_callable=AsyncMock,
                return_value=mock_dead_code_res,
            ),
        ):
            res = await run_deobfuscation_pipeline_impl(str(test_bin))

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["obfuscation_level"] == "LOW"
        assert data["obfuscation_severity_score"] == 0
