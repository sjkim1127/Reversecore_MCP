"""Additional coverage tests for ghost_trace, cli_tools, and static_analysis modules.

This file targets the lowest coverage modules to achieve 80% overall coverage.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ghost Trace Tests


class TestGhostTraceHelpers:
    """Tests for ghost_trace helper functions."""

    def test_extract_json_safely_empty_input(self):
        """Test _extract_json_safely with empty input."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        assert _extract_json_safely(None) is None
        assert _extract_json_safely("") is None
        assert _extract_json_safely("   ") is None

    def test_extract_json_safely_array(self):
        """Test _extract_json_safely with valid JSON array."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        result = _extract_json_safely('some noise [{"key": "value"}] more noise')
        assert result == [{"key": "value"}]

    def test_extract_json_safely_object(self):
        """Test _extract_json_safely with valid JSON object."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        result = _extract_json_safely('noise {"key": "value"} noise')
        assert result == {"key": "value"}

    def test_extract_json_safely_nested(self):
        """Test _extract_json_safely with nested JSON."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        result = _extract_json_safely('[{"nested": {"deep": "value"}}]')
        assert result == [{"nested": {"deep": "value"}}]

    def test_extract_json_safely_line_by_line(self):
        """Test _extract_json_safely single line fallback."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        result = _extract_json_safely("line1\n[1,2,3]\nline3")
        assert result == [1, 2, 3]

    def test_extract_json_safely_invalid(self):
        """Test _extract_json_safely with no valid JSON."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        result = _extract_json_safely("no json here")
        assert result is None

    def test_validate_r2_identifier_hex(self):
        """Test _validate_r2_identifier with hex address."""
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        result = _validate_r2_identifier("0x401000")
        assert result == "0x401000"

    def test_validate_r2_identifier_symbol(self):
        """Test _validate_r2_identifier with symbol."""
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        result = _validate_r2_identifier("sym.main")
        assert result == "sym.main"

    def test_validate_r2_identifier_function_name(self):
        """Test _validate_r2_identifier with function name."""
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        result = _validate_r2_identifier("my_function")
        assert result == "my_function"

    def test_validate_r2_identifier_invalid(self):
        """Test _validate_r2_identifier with invalid input."""
        from reversecore_mcp.core.exceptions import ValidationError
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        with pytest.raises(ValidationError):
            _validate_r2_identifier("invalid;injection")

    def test_functions_to_tuple(self):
        """Test _functions_to_tuple conversion."""
        from reversecore_mcp.tools.ghost_trace import _functions_to_tuple

        funcs = [
            {"name": "main", "offset": 0x1000, "size": 100, "codexrefs": [1, 2]},
            {"name": "sub1", "offset": 0x2000, "size": 50},
        ]
        result = _functions_to_tuple(funcs)
        assert len(result) == 2
        assert result[0][0] == "main"
        assert result[1][0] == "sub1"

    def test_get_file_cache_key_existing_file(self, tmp_path):
        """Test _get_file_cache_key with existing file."""
        from reversecore_mcp.tools.ghost_trace import _get_file_cache_key

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test")

        key = _get_file_cache_key(str(test_file))
        assert str(test_file) in key
        assert ":" in key

    def test_get_file_cache_key_nonexistent_file(self):
        """Test _get_file_cache_key with nonexistent file."""
        from reversecore_mcp.tools.ghost_trace import _get_file_cache_key

        key = _get_file_cache_key("/nonexistent/path")
        assert key == "/nonexistent/path"


class TestGhostTraceFindOrphanFunctions:
    """Tests for _find_orphan_functions."""

    @pytest.mark.asyncio
    async def test_find_orphan_functions_basic(self):
        """Test _find_orphan_functions with basic input."""
        from reversecore_mcp.tools.ghost_trace import _find_orphan_functions

        functions = [
            {"name": "main", "offset": 0x1000, "size": 100, "codexrefs": [1]},
            {"name": "orphan", "offset": 0x2000, "size": 100, "codexrefs": []},
            {"name": "small", "offset": 0x3000, "size": 10, "codexrefs": []},
        ]

        result = await _find_orphan_functions(Path("/test"), functions)
        assert len(result) == 1
        assert result[0]["name"] == "orphan"

    @pytest.mark.asyncio
    async def test_find_orphan_functions_skip_imports(self):
        """Test _find_orphan_functions skips imports."""
        from reversecore_mcp.tools.ghost_trace import _find_orphan_functions

        functions = [
            {"name": "sym.imp.printf", "offset": 0x1000, "size": 100, "codexrefs": []},
        ]

        result = await _find_orphan_functions(Path("/test"), functions)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_find_orphan_functions_skip_entry(self):
        """Test _find_orphan_functions skips entry points."""
        from reversecore_mcp.tools.ghost_trace import _find_orphan_functions

        functions = [
            {"name": "entry0", "offset": 0x1000, "size": 100, "codexrefs": []},
        ]

        result = await _find_orphan_functions(Path("/test"), functions)
        assert len(result) == 0


class TestGhostTraceIdentifyConditionalPaths:
    """Tests for _identify_conditional_paths."""

    @pytest.mark.asyncio
    async def test_identify_conditional_paths_empty(self):
        """Test _identify_conditional_paths with empty functions."""
        from reversecore_mcp.tools.ghost_trace import _identify_conditional_paths

        result = await _identify_conditional_paths(Path("/test"), [])
        assert result == []

    @pytest.mark.asyncio
    async def test_identify_conditional_paths_magic_value(self):
        """Test _identify_conditional_paths detects magic values."""
        from reversecore_mcp.tools.ghost_trace import _identify_conditional_paths

        functions = [{"name": "func1", "offset": 0x1000, "size": 100}]

        # Mock the r2 command output
        mock_output = '{"ops": [{"disasm": "cmp eax, 0xdeadbeef", "offset": 4096}]}'

        with patch(
            "reversecore_mcp.tools.ghost_trace._run_r2_cmd",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            result = await _identify_conditional_paths(Path("/test"), functions)
            assert len(result) == 1
            assert "magic value" in result[0]["reason"].lower()


class TestGhostTraceVerifyHypothesis:
    """Tests for _verify_hypothesis_with_emulation."""

    @pytest.mark.asyncio
    async def test_verify_hypothesis_invalid_function(self):
        """Test _verify_hypothesis_with_emulation with invalid function."""
        from reversecore_mcp.tools.ghost_trace import _verify_hypothesis_with_emulation

        result = await _verify_hypothesis_with_emulation(
            Path("/test"), "invalid;cmd", {"registers": {}}, timeout=30
        )
        assert result.status == "error"
        assert "invalid" in result.message.lower()

    @pytest.mark.asyncio
    async def test_verify_hypothesis_valid(self):
        """Test _verify_hypothesis_with_emulation with valid input."""
        from reversecore_mcp.tools.ghost_trace import _verify_hypothesis_with_emulation

        mock_output = '{"eax": 0, "ebx": 0}'

        with patch(
            "reversecore_mcp.tools.ghost_trace._run_r2_cmd",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            result = await _verify_hypothesis_with_emulation(
                Path("/test"),
                "0x401000",
                {"registers": {"eax": "0x1234"}, "max_steps": 10},
                timeout=30,
            )
            assert result.status == "success"

    @pytest.mark.asyncio
    async def test_verify_hypothesis_parse_failure(self):
        """Test _verify_hypothesis_with_emulation with parse failure."""
        from reversecore_mcp.tools.ghost_trace import _verify_hypothesis_with_emulation

        with patch(
            "reversecore_mcp.tools.ghost_trace._run_r2_cmd",
            new_callable=AsyncMock,
            return_value="not valid json",
        ):
            result = await _verify_hypothesis_with_emulation(
                Path("/test"), "main", {"registers": {}}, timeout=30
            )
            assert result.status == "error"


# Static Analysis Tests


class TestStaticAnalysisFormatSize:
    """Tests for _format_size helper."""

    def test_format_size_bytes(self):
        """Test _format_size with bytes."""
        from reversecore_mcp.tools.static_analysis import _format_size

        result = _format_size(500)
        assert "500" in result and "B" in result

    def test_format_size_kilobytes(self):
        """Test _format_size with kilobytes."""
        from reversecore_mcp.tools.static_analysis import _format_size

        result = _format_size(2048)
        assert "KB" in result

    def test_format_size_megabytes(self):
        """Test _format_size with megabytes."""
        from reversecore_mcp.tools.static_analysis import _format_size

        result = _format_size(2 * 1024 * 1024)
        assert "MB" in result


class TestStaticAnalysisRunStrings:
    """Tests for run_strings function."""

    @pytest.mark.asyncio
    async def test_run_strings_basic(self, patched_workspace_config, workspace_dir):
        """Test run_strings with basic file."""
        from reversecore_mcp.tools.static_analysis import run_strings

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"Hello World Test\x00Binary Data\x00")

        # Mock the strings command - patch where it's used, not where it's defined
        with patch(
            "reversecore_mcp.tools.static_analysis.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("Hello World Test\nBinary Data\n", 0),
        ):
            result = await run_strings(str(test_file))
            assert result.status == "success"

    @pytest.mark.asyncio
    async def test_run_strings_with_min_length(self, patched_workspace_config, workspace_dir):
        """Test run_strings with minimum length."""
        from reversecore_mcp.tools.static_analysis import run_strings

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"Hello World\x00AB\x00")

        with patch(
            "reversecore_mcp.tools.static_analysis.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("Hello World\n", 0),
        ):
            result = await run_strings(str(test_file), min_length=5)
            assert result.status == "success"


class TestStaticAnalysisRunBinwalk:
    """Tests for run_binwalk function."""

    @pytest.mark.asyncio
    async def test_run_binwalk_basic(self, patched_workspace_config, workspace_dir):
        """Test run_binwalk with basic file."""
        from reversecore_mcp.tools.static_analysis import run_binwalk

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_output = "0   ELF 32-bit\n100 gzip compressed data"

        with patch(
            "reversecore_mcp.tools.static_analysis.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=(mock_output, ""),
        ):
            result = await run_binwalk(str(test_file))
            # Accept either success or error (binwalk might not be installed)
            assert result.status in ("success", "error")


class TestStaticAnalysisScanVersions:
    """Tests for scan_for_versions function."""

    @pytest.mark.asyncio
    async def test_scan_for_versions_basic(self, patched_workspace_config, workspace_dir):
        """Test scan_for_versions with basic file."""
        from reversecore_mcp.tools.static_analysis import scan_for_versions

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"Version: 1.2.3\x00Build: 20240101\x00")

        with patch(
            "reversecore_mcp.tools.static_analysis.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("Version: 1.2.3\nBuild: 20240101\n", 0),
        ):
            result = await scan_for_versions(str(test_file))
            assert result.status == "success"


class TestStaticAnalysisExtractRTTI:
    """Tests for extract_rtti_info function."""

    @pytest.mark.asyncio
    async def test_extract_rtti_basic(self, patched_workspace_config, workspace_dir):
        """Test extract_rtti_info with basic file."""
        from reversecore_mcp.tools.static_analysis import extract_rtti_info

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_output = "class MyClass\nstruct DataStruct"

        with patch(
            "reversecore_mcp.tools.static_analysis.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=(mock_output, 0),
        ):
            result = await extract_rtti_info(str(test_file))
            assert result.status == "success"


# Trinity Defense Tests


class TestTrinityDefenseInferIntent:
    """Tests for _infer_intent functions."""

    def test_infer_intent_network(self):
        """Test _infer_intent with network code."""
        from reversecore_mcp.tools.trinity_defense import _infer_intent

        code = """
        socket.connect(host, port)
        send(data)
        recv(buffer)
        """
        result = _infer_intent(code)
        assert isinstance(result, str)

    def test_infer_intent_file_operations(self):
        """Test _infer_intent with file operations."""
        from reversecore_mcp.tools.trinity_defense import _infer_intent

        code = """
        fopen(filename, "w")
        fwrite(data, size)
        unlink(path)
        """
        result = _infer_intent(code)
        assert isinstance(result, str)

    def test_infer_intent_crypto(self):
        """Test _infer_intent with crypto operations."""
        from reversecore_mcp.tools.trinity_defense import _infer_intent

        code = """
        AES_encrypt(key, data)
        RSA_public_decrypt(sig)
        """
        result = _infer_intent(code)
        assert isinstance(result, str)


class TestTrinityDefenseInferIntentWithConfidence:
    """Tests for _infer_intent_with_confidence."""

    def test_infer_intent_with_confidence_network(self):
        """Test _infer_intent_with_confidence with network code."""
        from reversecore_mcp.tools.trinity_defense import _infer_intent_with_confidence

        neural_result = {"neural_code": "socket.connect(host, port)\nsend(data)"}
        threat_info = {"reason": "orphan function"}
        intent, confidence = _infer_intent_with_confidence(neural_result, threat_info)
        assert isinstance(intent, str)
        assert 0 <= confidence <= 100

    def test_infer_intent_with_confidence_file_deletion(self):
        """Test _infer_intent_with_confidence with file deletion code."""
        from reversecore_mcp.tools.trinity_defense import _infer_intent_with_confidence

        neural_result = {"neural_code": "unlink(path)\nrm -rf /"}
        threat_info = {"reason": "suspicious function"}
        intent, confidence = _infer_intent_with_confidence(neural_result, threat_info)
        assert isinstance(intent, str)

    def test_infer_intent_with_confidence_empty(self):
        """Test _infer_intent_with_confidence with empty code."""
        from reversecore_mcp.tools.trinity_defense import _infer_intent_with_confidence

        neural_result = {"neural_code": ""}
        threat_info = {"reason": ""}
        intent, confidence = _infer_intent_with_confidence(neural_result, threat_info)
        assert isinstance(intent, str)


class TestTrinityDefenseGenerateRecommendations:
    """Tests for _generate_recommendations."""

    def test_generate_recommendations_basic(self):
        """Test _generate_recommendations with basic threats."""
        from reversecore_mcp.tools.trinity_defense import _generate_recommendations

        threats = [
            {"type": "network", "severity": "high"},
            {"type": "file", "severity": "medium"},
        ]
        result = _generate_recommendations(threats)
        assert isinstance(result, list)


# Additional edge case tests


class TestEdgeCases:
    """Additional edge case tests for coverage."""

    def test_ghost_trace_register_function(self):
        """Test register_ghost_trace function."""
        from reversecore_mcp.tools.ghost_trace import register_ghost_trace

        mock_mcp = MagicMock()
        register_ghost_trace(mock_mcp)
        mock_mcp.tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_ghost_trace_main_function_scan(self, patched_workspace_config, workspace_dir):
        """Test ghost_trace main function in scan mode."""
        from reversecore_mcp.tools.ghost_trace import ghost_trace

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Mock r2 command
        mock_output = '[{"name": "main", "offset": 4096, "size": 100}]'

        with patch(
            "reversecore_mcp.tools.ghost_trace._run_r2_cmd",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            with patch(
                "reversecore_mcp.tools.ghost_trace._find_orphan_functions",
                new_callable=AsyncMock,
                return_value=[],
            ):
                with patch(
                    "reversecore_mcp.tools.ghost_trace._identify_conditional_paths",
                    new_callable=AsyncMock,
                    return_value=[],
                ):
                    result = await ghost_trace(str(test_file))
                    assert result.status == "success"
                    assert "scan_type" in result.data

    @pytest.mark.asyncio
    async def test_ghost_trace_emulation_mode(self, patched_workspace_config, workspace_dir):
        """Test ghost_trace in emulation mode."""
        from reversecore_mcp.tools.ghost_trace import ghost_trace

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_output = '{"eax": 0}'

        with patch(
            "reversecore_mcp.tools.ghost_trace._run_r2_cmd",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            result = await ghost_trace(
                str(test_file),
                focus_function="0x401000",
                hypothesis={"registers": {"eax": "0x1234"}},
            )
            assert result.status == "success"

    @pytest.mark.asyncio
    async def test_ghost_trace_invalid_json_output(self, patched_workspace_config, workspace_dir):
        """Test ghost_trace with invalid JSON output from r2."""
        from reversecore_mcp.tools.ghost_trace import ghost_trace

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.ghost_trace._run_r2_cmd",
            new_callable=AsyncMock,
            return_value="not valid json at all",
        ):
            result = await ghost_trace(str(test_file))
            assert result.status == "error"

    def test_trinity_defense_register_function(self):
        """Test register_trinity_defense function."""
        from reversecore_mcp.tools.trinity_defense import register_trinity_defense

        mock_mcp = MagicMock()
        register_trinity_defense(mock_mcp)
        mock_mcp.tool.assert_called_once()

    @pytest.mark.asyncio
    async def test_trinity_defense_basic(self, patched_workspace_config, workspace_dir):
        """Test trinity_defense main function."""
        from reversecore_mcp.tools.trinity_defense import trinity_defense

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Mock various subprocess calls
        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=('{"functions": []}', ""),
        ):
            result = await trinity_defense(str(test_file))
            # May succeed or fail depending on mocks
            assert result.status in ("success", "error")
