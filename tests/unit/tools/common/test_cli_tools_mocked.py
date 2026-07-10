import json
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.tools.analysis import diff_tools, signature_tools, static_analysis
from reversecore_mcp.tools.radare2 import r2_analysis


@pytest.mark.asyncio
class TestCliToolsMocked:
    async def test_generate_signature_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        # Mock output should be continuous hex string (p8 output)
        mock_output = "4883ec20"

        # Mock r2_helpers where execute_subprocess_async is actually used
        with patch(
            "reversecore_mcp.core.r2_helpers.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = (mock_output, len(mock_output))

            result = await signature_tools.generate_signature(str(test_file), "0x401000", length=4)

            assert result.status == "success"
            assert "rule suspicious_test_x401000" in result.data
            assert "48 83 ec 20" in result.data

    async def test_generate_signature_invalid_length(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        result = await signature_tools.generate_signature(str(test_file), "0x401000", length=0)
        assert result.status == "error"
        assert "Length must be between" in result.message

    async def test_generate_signature_invalid_address(
        self, workspace_dir, patched_workspace_config
    ):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        result = await signature_tools.generate_signature(str(test_file), "invalid;cmd")
        assert result.status == "error"
        # Updated to match the new error message from validate_address_format
        assert "safe characters" in result.message

    async def test_generate_signature_extraction_failed(
        self, workspace_dir, patched_workspace_config
    ):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        # Mock r2_helpers where execute_subprocess_async is actually used
        with patch(
            "reversecore_mcp.core.r2_helpers.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = ("", 0)

            result = await signature_tools.generate_signature(str(test_file), "0x401000")

            assert result.status == "error"
            assert "Failed to extract valid hex bytes" in result.message

    async def test_extract_rtti_info_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        # Mock output for strings command
        mock_output = """
_ZTSMyClass
class MyClass
_ZTIMyClass
"""

        with patch(
            "reversecore_mcp.tools.static_analysis.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = (mock_output, len(mock_output))

            result = await static_analysis.extract_rtti_info(str(test_file))

            assert result.status == "success"
            data = result.data
            assert "MyClass" in data["class_names"]
            assert data["total_classes"] >= 1
            assert data["total_rtti_entries"] >= 1

    async def test_extract_rtti_info_no_results(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        with patch(
            "reversecore_mcp.tools.static_analysis.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = ("NO RTTI HERE", 10)

            result = await static_analysis.extract_rtti_info(str(test_file))

            # Should succeed but return empty results
            assert result.status == "success"
            assert result.data["total_classes"] == 0
            assert result.data["total_rtti_entries"] == 0

    async def test_analyze_xrefs_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        xrefs_to_json = json.dumps([{"from": "0x400", "type": "call", "function": "main"}])
        xrefs_from_json = json.dumps([{"addr": "0x500", "type": "call", "function": "printf"}])

        output = f"{xrefs_to_json}\n{xrefs_from_json}"

        # Mock r2_helpers where execute_subprocess_async is actually used
        with patch(
            "reversecore_mcp.core.r2_helpers.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = (output, len(output))

            result = await r2_analysis.analyze_xrefs(str(test_file), "0x401000", xref_type="all")

            assert result.status == "success"
            data = result.data
            assert data["total_refs_to"] == 1
            assert data["total_refs_from"] == 1
            assert data["xrefs_to"][0]["from"] == "0x400"

    async def test_analyze_xrefs_invalid_type(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        result = await r2_analysis.analyze_xrefs(str(test_file), "0x401000", xref_type="invalid")
        assert result.status == "error"
        assert "Invalid xref_type" in result.message

    async def test_diff_binaries_success(self, workspace_dir, patched_workspace_config):
        file_a = workspace_dir / "v1.exe"
        file_a.write_bytes(b"V1")
        file_b = workspace_dir / "v2.exe"
        file_b.write_bytes(b"V2")

        diff_output = "0x401000 code_change instruction modified"
        sim_output = "similarity: 0.95"

        # Mock diff_tools where execute_subprocess_async is actually used
        with patch(
            "reversecore_mcp.tools.diff_tools.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.side_effect = [
                (diff_output, len(diff_output)),
                (sim_output, len(sim_output)),
            ]

            result = await diff_tools.diff_binaries(str(file_a), str(file_b))

            assert result.status == "success"
            data = json.loads(result.data)
            assert data["similarity"] == 0.95
            assert len(data["changes"]) == 1
            assert data["changes"][0]["type"] == "code_change"

    async def test_match_libraries_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        funcs_json = json.dumps(
            [
                {"name": "sym.imp.printf", "offset": 0x1000},
                {"name": "main", "offset": 0x2000},
            ]
        )

        # Mock r2_helpers where execute_subprocess_async is actually used
        with patch(
            "reversecore_mcp.core.r2_helpers.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = (funcs_json, len(funcs_json))

            result = await diff_tools.match_libraries(str(test_file))

            assert result.status == "success"
            data = json.loads(result.data)
            assert data["total_functions"] == 2
            assert data["library_functions"] == 1
            assert data["user_functions"] == 1
            assert data["library_matches"][0]["name"] == "sym.imp.printf"

    async def test_match_libraries_parse_error(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")

        # Mock r2_helpers where execute_subprocess_async is actually used
        with patch(
            "reversecore_mcp.core.r2_helpers.execute_subprocess_async",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = ("INVALID", 10)

            result = await diff_tools.match_libraries(str(test_file))

            assert result.status == "error"
            assert "Failed to parse function list" in result.message
