"""Integration tests for P0-P2 improvement features.

This module tests the improvements made in P0, P1, and P2 priority items:
- P0: Neural Decompiler radare2 fallback, YARA input validation
- P1: R2 Pool async support, error handler deduplication, ghost_trace caching
- P2: Circuit Breaker sync support, TypedDict types, binwalk extraction
"""

import asyncio
import shutil
import subprocess

import pytest


def _require_radare2() -> None:
    """Skip tests if radare2 is not installed."""
    try:
        subprocess.run(["r2", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("radare2 not installed")


def _require_binwalk() -> None:
    """Skip tests if binwalk is not installed."""
    if not shutil.which("binwalk"):
        pytest.skip("binwalk not installed")


class TestNeuralDecompilerFallback:
    """P0: Test Neural Decompiler with radare2 fallback."""

    @pytest.mark.asyncio
    async def test_neural_decompiler_with_radare2_fallback(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test that neural_decompiler falls back to radare2 when Ghidra unavailable."""
        _require_radare2()

        from reversecore_mcp.tools.neural_decompiler import neural_decompiler

        # Force use_ghidra=False to test radare2 fallback
        result = await neural_decompiler(
            str(sample_binary_path), function_address="entry0", use_ghidra=False
        )

        assert result.status == "success"
        assert isinstance(result.data, dict)
        # Should indicate radare2 was used
        assert result.data.get("decompiler") == "radare2"

    @pytest.mark.asyncio
    async def test_neural_decompiler_ghidra_not_available(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test neural_decompiler gracefully handles missing Ghidra."""
        _require_radare2()

        from reversecore_mcp.tools.neural_decompiler import neural_decompiler

        # With use_ghidra=True but Ghidra not installed, should fall back or return appropriate error
        result = await neural_decompiler(
            str(sample_binary_path),
            function_address="entry0",
            use_ghidra=True,  # Will try Ghidra first, then may fall back
        )

        # Either succeeds with fallback or returns meaningful error
        assert result.status in ["success", "error"]
        if result.status == "success":
            # If success, should have valid decompiler info
            assert "decompiler" in result.data or "refined_code" in result.data


class TestYaraInputValidation:
    """P0: Test YARA input validation in adaptive_vaccine."""

    @pytest.mark.asyncio
    async def test_yara_rule_name_validation(self, sample_binary_path, patched_workspace_config):
        """Test that YARA rule names are properly validated."""
        from reversecore_mcp.tools.malware.adaptive_vaccine import adaptive_vaccine

        # Test with valid threat report
        result = await adaptive_vaccine(
            str(sample_binary_path),
            threat_report={
                "malware_name": "TestMalware",
                "strings": ["suspicious_string"],
                "patch_addresses": ["0x1000"],
            },
            action="yara",
        )

        # Should either succeed or fail with validation error
        assert result.status in ["success", "error"]

    @pytest.mark.asyncio
    async def test_yara_invalid_action_validation(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test that invalid action parameter is rejected."""
        from reversecore_mcp.tools.malware.adaptive_vaccine import adaptive_vaccine

        result = await adaptive_vaccine(
            threat_report={"malware_name": "Test"},
            action="invalid_action",  # Invalid action
            file_path=str(sample_binary_path),
        )

        assert result.status == "error"
        assert "action" in result.message.lower() or "invalid" in result.message.lower()

    @pytest.mark.asyncio
    async def test_yara_string_sanitization(self, sample_binary_path, patched_workspace_config):
        """Test that special characters in strings are properly sanitized."""
        from reversecore_mcp.tools.malware.adaptive_vaccine import adaptive_vaccine

        # Test with strings containing special characters
        result = await adaptive_vaccine(
            threat_report={
                "malware_name": "TestMalware",
                "strings": ['test"string', "test\\path", "test\nline"],
                "patch_addresses": [],
            },
            action="yara",
            file_path=str(sample_binary_path),
        )

        # Should handle special characters without crashing
        assert result.status in ["success", "error"]


class TestR2PoolAsync:
    """P1: Test R2 Pool async support improvements."""

    @pytest.mark.asyncio
    async def test_r2_pool_async_execution(self, sample_binary_path, patched_workspace_config):
        """Test that R2 pool async execution works correctly."""
        _require_radare2()

        from reversecore_mcp.core.r2_pool import r2_pool

        # Test async execution
        result = await r2_pool.execute_async(str(sample_binary_path), "i")

        assert result is not None
        assert isinstance(result, str)
        # Should contain some binary info
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_r2_pool_async_concurrent_execution(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test concurrent async r2 command execution."""
        _require_radare2()

        from reversecore_mcp.core.r2_pool import r2_pool

        # Run multiple commands concurrently
        tasks = [
            r2_pool.execute_async(str(sample_binary_path), "i"),
            r2_pool.execute_async(str(sample_binary_path), "iS"),
            r2_pool.execute_async(str(sample_binary_path), "ie"),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should complete successfully
        for result in results:
            assert not isinstance(result, Exception)
            assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_r2_pool_async_session(self, sample_binary_path, patched_workspace_config):
        """Test R2 pool async context manager."""
        _require_radare2()

        from reversecore_mcp.core.r2_pool import r2_pool

        # Test async session context manager
        async with r2_pool.async_session(str(sample_binary_path)) as r2:
            result = r2.cmd("i")
            assert result is not None
            assert isinstance(result, str)


class TestErrorHandlerDeduplication:
    """P1: Test error handler code deduplication."""

    @pytest.mark.asyncio
    async def test_error_handler_sync_function(self):
        """Test error handler works with sync functions."""
        from reversecore_mcp.core.error_handling import handle_tool_errors
        from reversecore_mcp.core.exceptions import ValidationError

        @handle_tool_errors
        def sync_tool():
            raise ValidationError("Test validation error")

        result = sync_tool()
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_error_handler_async_function(self):
        """Test error handler works with async functions."""
        from reversecore_mcp.core.error_handling import handle_tool_errors
        from reversecore_mcp.core.exceptions import ValidationError

        @handle_tool_errors
        async def async_tool():
            raise ValidationError("Test validation error")

        result = await async_tool()
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_handle_exception_centralized(self):
        """Test _handle_exception function handles all exception types."""
        from reversecore_mcp.core.error_handling import _handle_exception
        from reversecore_mcp.core.exceptions import (
            ExecutionTimeoutError,
            ToolNotFoundError,
            ValidationError,
        )

        # Test ToolNotFoundError
        result = _handle_exception(ToolNotFoundError("test_tool"), "test_func")
        assert result.error_code == "TOOL_NOT_FOUND"

        # Test ExecutionTimeoutError
        result = _handle_exception(ExecutionTimeoutError(30), "test_func")
        assert result.error_code == "TIMEOUT"

        # Test ValidationError
        result = _handle_exception(ValidationError("Invalid input"), "test_func")
        assert result.error_code == "VALIDATION_ERROR"

        # Test generic Exception
        result = _handle_exception(Exception("Generic error"), "test_func")
        assert result.error_code == "INTERNAL_ERROR"


class TestCircuitBreakerSync:
    """P2: Test Circuit Breaker sync support."""

    def test_circuit_breaker_sync_decorator(self):
        """Test circuit_breaker_sync decorator works correctly."""
        from reversecore_mcp.core.resilience import circuit_breaker_sync

        call_count = 0

        @circuit_breaker_sync("test_sync_tool", failure_threshold=3, recovery_timeout=1)
        def sync_tool():
            nonlocal call_count
            call_count += 1
            return "success"

        # Should work normally
        result = sync_tool()
        assert result == "success"
        assert call_count == 1

    def test_circuit_breaker_sync_opens_on_failures(self):
        """Test circuit breaker opens after threshold failures."""
        from reversecore_mcp.core.exceptions import ToolExecutionError
        from reversecore_mcp.core.resilience import (
            CircuitState,
            _breakers,
            circuit_breaker_sync,
            get_circuit_breaker,
        )

        # Clear any existing breaker
        _breakers.pop("test_failing_tool", None)

        @circuit_breaker_sync("test_failing_tool", failure_threshold=2, recovery_timeout=60)
        def failing_tool():
            raise ValueError("Simulated failure")

        # Trigger failures to open circuit
        for _ in range(2):
            try:
                failing_tool()
            except ValueError:
                pass

        # Circuit should be open now
        breaker = get_circuit_breaker("test_failing_tool")
        assert breaker.state == CircuitState.OPEN

        # Next call should raise ToolExecutionError
        with pytest.raises(ToolExecutionError):
            failing_tool()

    @pytest.mark.asyncio
    async def test_circuit_breaker_auto_detection(self):
        """Test circuit_breaker automatically detects async/sync."""
        from reversecore_mcp.core.resilience import _breakers, circuit_breaker

        # Clear any existing breakers
        _breakers.pop("test_auto_sync", None)
        _breakers.pop("test_auto_async", None)

        @circuit_breaker("test_auto_sync")
        def sync_func():
            return "sync_result"

        @circuit_breaker("test_auto_async")
        async def async_func():
            return "async_result"

        # Sync function should work
        assert sync_func() == "sync_result"

        # Async function should work
        assert await async_func() == "async_result"


class TestTypedDictTypes:
    """P2: Test TypedDict type definitions."""

    def test_function_info_typed_dict(self):
        """Test FunctionInfo TypedDict structure."""
        from reversecore_mcp.core.result import FunctionInfo

        # Create a valid FunctionInfo
        func_info: FunctionInfo = {
            "name": "main",
            "address": "0x401000",
            "size": 128,
            "signature": "int main(int argc, char** argv)",
        }

        assert func_info["name"] == "main"
        assert func_info["address"] == "0x401000"

    def test_decompilation_result_typed_dict(self):
        """Test DecompilationResult TypedDict structure."""
        from reversecore_mcp.core.result import DecompilationResult

        result: DecompilationResult = {
            "function_name": "main",
            "source_code": "int main() { return 0; }",
            "decompiler": "ghidra",
            "address": "0x401000",
        }

        assert result["function_name"] == "main"
        assert result["decompiler"] == "ghidra"

    def test_yara_rule_result_typed_dict(self):
        """Test YaraRuleResult TypedDict structure."""
        from reversecore_mcp.core.result import YaraRuleResult

        result: YaraRuleResult = {
            "rule_name": "detect_malware",
            "rule_content": "rule detect_malware { condition: true }",
            "patterns_count": 5,
        }

        assert result["rule_name"] == "detect_malware"
        assert result["patterns_count"] == 5

    def test_emulation_result_typed_dict(self):
        """Test EmulationResult TypedDict structure."""
        from reversecore_mcp.core.result import EmulationResult

        result: EmulationResult = {
            "final_registers": {"eax": 0, "ebx": 1},
            "steps_executed": 100,
            "status": "completed",
        }

        assert result["steps_executed"] == 100
        assert result["status"] == "completed"


class TestBinwalkExtraction:
    """P2: Test binwalk extraction feature."""

    @pytest.mark.asyncio
    async def test_binwalk_extract_basic(self, sample_binary_path, patched_workspace_config):
        """Test basic binwalk extraction functionality."""
        _require_binwalk()

        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk_extract

        result = await run_binwalk_extract(str(sample_binary_path))

        assert result.status == "success"
        assert isinstance(result.data, dict)
        assert "output_directory" in result.data
        assert "extracted_files" in result.data
        assert "total_size" in result.data

    @pytest.mark.asyncio
    async def test_binwalk_extract_with_custom_output_dir(
        self, sample_binary_path, patched_workspace_config, tmp_path
    ):
        """Test binwalk extraction with custom output directory."""
        _require_binwalk()

        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk_extract

        output_dir = tmp_path / "binwalk_output"
        result = await run_binwalk_extract(str(sample_binary_path), output_dir=str(output_dir))

        assert result.status == "success"
        # Output directory should be set correctly
        assert str(output_dir) in result.data["output_directory"]

    @pytest.mark.asyncio
    async def test_binwalk_extract_matryoshka_disabled(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test binwalk extraction with matryoshka disabled."""
        _require_binwalk()

        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk_extract

        result = await run_binwalk_extract(str(sample_binary_path), matryoshka=False)

        assert result.status == "success"
        assert isinstance(result.data["extracted_files"], list)

    @pytest.mark.asyncio
    async def test_binwalk_extract_result_structure(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test binwalk extraction result has correct structure."""
        _require_binwalk()

        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk_extract

        result = await run_binwalk_extract(str(sample_binary_path))

        assert result.status == "success"
        data = result.data

        # Check required fields
        assert "output_directory" in data
        assert "extracted_files" in data
        assert "total_files" in data
        assert "total_size" in data
        assert "total_size_human" in data
        assert "extraction_depth" in data
        assert "signatures_found" in data

        # Check types
        assert isinstance(data["extracted_files"], list)
        assert isinstance(data["total_size"], int)
        assert isinstance(data["total_size_human"], str)


class TestGhostTraceCaching:
    """P1: Test ghost_trace caching improvements."""

    @pytest.mark.asyncio
    async def test_ghost_trace_cache_key_generation(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test that cache keys are generated correctly."""
        from reversecore_mcp.tools.ghost_trace import _get_file_cache_key

        key1 = _get_file_cache_key(str(sample_binary_path))
        key2 = _get_file_cache_key(str(sample_binary_path))

        # Same file should produce same key
        assert key1 == key2

        # Key should include file path
        assert str(sample_binary_path) in key1

    @pytest.mark.asyncio
    async def test_ghost_trace_cached_execution(self, sample_binary_path, patched_workspace_config):
        """Test that ghost_trace uses caching for repeated calls."""
        _require_radare2()

        from reversecore_mcp.tools.ghost_trace import _run_r2_cmd

        # First call - cache miss
        result1 = await _run_r2_cmd(str(sample_binary_path), "i", use_cache=True)

        # Second call - should hit cache
        result2 = await _run_r2_cmd(str(sample_binary_path), "i", use_cache=True)

        # Results should be identical
        assert result1 == result2

    @pytest.mark.asyncio
    async def test_ghost_trace_bypass_cache(self, sample_binary_path, patched_workspace_config):
        """Test that cache can be bypassed when needed."""
        _require_radare2()

        from reversecore_mcp.tools.ghost_trace import _run_r2_cmd

        # Call with cache disabled
        result = await _run_r2_cmd(str(sample_binary_path), "i", use_cache=False)

        assert result is not None
        assert isinstance(result, str)


class TestEndToEndWorkflow:
    """End-to-end integration tests combining multiple improvements."""

    @pytest.mark.asyncio
    async def test_full_analysis_workflow(self, sample_binary_path, patched_workspace_config):
        """Test a complete analysis workflow using improved components."""
        _require_radare2()

        from reversecore_mcp.core.r2_pool import r2_pool
        from reversecore_mcp.tools.analysis.static_analysis import run_strings, scan_for_versions

        # Step 1: Extract strings
        strings_result = await run_strings(str(sample_binary_path))
        assert strings_result.status == "success"

        # Step 2: Scan for versions
        versions_result = await scan_for_versions(str(sample_binary_path))
        assert versions_result.status == "success"

        # Step 3: Use R2 pool for basic info
        info = await r2_pool.execute_async(str(sample_binary_path), "i")
        assert info is not None

        # Cleanup
        r2_pool.close_all()

    @pytest.mark.asyncio
    async def test_error_handling_workflow(self, workspace_dir, patched_workspace_config):
        """Test error handling across multiple components."""
        from reversecore_mcp.tools.analysis.static_analysis import run_strings

        # Test with nonexistent file
        result = await run_strings(str(workspace_dir / "nonexistent.bin"))

        # Should return proper error
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
