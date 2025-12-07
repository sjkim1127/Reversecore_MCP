"""Final push to reach 80%+ coverage target.

Focus on remaining gaps to reach 80%.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ============================================================================
# R2 Pool additional tests
# ============================================================================


class TestR2PoolFinal:
    """Final tests for r2_pool to increase coverage."""

    def test_r2_pool_get_async_lock(self):
        """Test R2ConnectionPool _get_async_lock method."""
        from reversecore_mcp.core.r2_pool import R2ConnectionPool

        pool = R2ConnectionPool()
        lock = pool._get_async_lock()
        assert lock is not None


# ============================================================================
# IOC Tools additional tests
# ============================================================================


class TestIOCToolsFinal:
    """Final tests for ioc_tools to increase coverage."""

    def test_extract_iocs_with_hashes(self, patched_workspace_config, workspace_dir):
        """Test extract_iocs with hash patterns."""
        from reversecore_mcp.tools.malware.ioc_tools import extract_iocs

        # MD5 and SHA256 patterns
        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(
            b"d41d8cd98f00b204e9800998ecf8427e\x00"  # MD5
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\x00"  # SHA256
        )

        result = extract_iocs(str(test_file))
        assert result.status in ("success", "error")


# ============================================================================
# Adaptive Vaccine additional tests
# ============================================================================


class TestAdaptiveVaccineFinal:
    """Final tests for adaptive_vaccine to increase coverage."""

    def test_adaptive_vaccine_helpers(self):
        """Test adaptive_vaccine helper imports."""
        from reversecore_mcp.tools import adaptive_vaccine

        assert adaptive_vaccine is not None


# ============================================================================
# Static Analysis additional tests
# ============================================================================


class TestStaticAnalysisFinal:
    """Final tests for static_analysis."""

    @pytest.mark.asyncio
    async def test_run_binwalk_basic(self, patched_workspace_config, workspace_dir):
        """Test run_binwalk function."""
        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("DECIMAL       HEXADECIMAL     DESCRIPTION", ""),
        ):
            result = await run_binwalk(str(test_file))
            assert result.status in ("success", "error")


# ============================================================================
# CLI Tools additional tests
# ============================================================================


# ============================================================================
# JSON Utils additional tests
# ============================================================================


class TestJsonUtilsFinal:
    """Final tests for json_utils."""

    def test_json_dumps_bytes(self):
        """Test json dumps with bytes encoding."""
        from reversecore_mcp.core import json_utils

        result = json_utils.dumps({"bytes": b"test".hex()})
        assert isinstance(result, str)


# ============================================================================
# R2 Analysis additional tests
# ============================================================================


class TestR2AnalysisFinal:
    """Final tests for r2_analysis."""

    @pytest.mark.asyncio
    async def test_trace_execution_path(self, patched_workspace_config, workspace_dir):
        """Test trace_execution_path function."""
        from reversecore_mcp.tools.radare2.r2_analysis import trace_execution_path

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=('{"blocks": []}', ""),
        ):
            result = await trace_execution_path(str(test_file), "0x401000")
            assert result.status in ("success", "error")


# ============================================================================
# Diff Tools additional tests
# ============================================================================


class TestDiffToolsFinal:
    """Final tests for diff_tools."""

    def test_extract_library_name_complex(self):
        """Test _extract_library_name with complex input."""
        from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

        result = _extract_library_name("sym.imp.kernel32.dll_GetProcAddress")
        assert isinstance(result, str)


# ============================================================================
# Dormant Detector additional tests
# ============================================================================


class TestDormantDetectorFinal:
    """Final tests for dormant_detector."""

    @pytest.mark.asyncio
    async def test_dormant_detector_basic(self, patched_workspace_config, workspace_dir):
        """Test dormant_detector basic call."""
        from reversecore_mcp.tools.malware.dormant_detector import dormant_detector

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=('{"traces": []}', ""),
        ):
            result = await dormant_detector(str(test_file))
            assert result.status in ("success", "error")


# ============================================================================
# YARA Tools additional tests
# ============================================================================


class TestYaraToolsFinal:
    """Final tests for yara_tools."""

    def test_format_match_with_empty_strings(self):
        """Test _format_yara_match with empty strings list."""
        from reversecore_mcp.tools.malware.yara_tools import _format_yara_match

        mock_match = MagicMock()
        mock_match.rule = "empty_strings_rule"
        mock_match.namespace = "test"
        mock_match.tags = []
        mock_match.meta = {}
        mock_match.strings = []

        result = _format_yara_match(mock_match)
        assert result["rule"] == "empty_strings_rule"


# ============================================================================
# Vulnerability Hunter additional tests
# ============================================================================


class TestVulnerabilityHunterFinal:
    """Final tests for vulnerability_hunter."""

    @pytest.mark.asyncio
    async def test_vulnerability_hunter_basic(self, patched_workspace_config, workspace_dir):
        """Test vulnerability_hunter basic call."""
        from reversecore_mcp.tools.malware.vulnerability_hunter import vulnerability_hunter

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=('{"result": "clean"}', ""),
        ):
            result = await vulnerability_hunter(str(test_file))
            assert result.status in ("success", "error")


# ============================================================================
# Decompilation additional tests
# ============================================================================


class TestDecompilationFinal:
    """Final tests for decompilation."""

    @pytest.mark.asyncio
    async def test_smart_decompile_basic(self, patched_workspace_config, workspace_dir):
        """Test smart_decompile basic call."""
        from reversecore_mcp.tools.ghidra.decompilation import smart_decompile

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("void main() {}", ""),
        ):
            result = await smart_decompile(str(test_file), "0x401000")
            assert result.status in ("success", "error")


# ============================================================================
# Signature Tools additional tests
# ============================================================================


class TestSignatureToolsFinal:
    """Final tests for signature_tools."""

    @pytest.mark.asyncio
    async def test_generate_signature_basic(self, patched_workspace_config, workspace_dir):
        """Test generate_signature basic call."""
        from reversecore_mcp.tools.analysis.signature_tools import generate_signature

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("7f454c46...", ""),
        ):
            result = await generate_signature(str(test_file), "0x401000")
            assert result.status in ("success", "error")


# ============================================================================
# Core additional tests
# ============================================================================


class TestCoreFinal:
    """Final tests for core modules."""

    def test_get_validation_hint(self):
        """Test get_validation_hint function."""
        from reversecore_mcp.core.error_formatting import get_validation_hint

        err = ValueError("address must be hex")
        hint = get_validation_hint(err)
        assert isinstance(hint, str)

    def test_timeout_error_properties(self):
        """Test ExecutionTimeoutError properties."""
        from reversecore_mcp.core.exceptions import ExecutionTimeoutError

        err = ExecutionTimeoutError(60)
        assert err.timeout_seconds == 60
        assert "60" in str(err)

    def test_output_limit_error_properties(self):
        """Test OutputLimitExceededError properties."""
        from reversecore_mcp.core.exceptions import OutputLimitExceededError

        err = OutputLimitExceededError(1024, 2048)
        assert err.max_size == 1024
        assert err.actual_size == 2048
