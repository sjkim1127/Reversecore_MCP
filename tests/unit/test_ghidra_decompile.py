"""Unit tests for Ghidra decompilation integration."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from reversecore_mcp.tools import cli_tools


@pytest.mark.asyncio
class TestGhidraDecompile:
    """Test Ghidra-based decompilation."""
    
    async def test_smart_decompile_with_ghidra_success(
        self, workspace_dir, patched_workspace_config
    ):
        """Test successful Ghidra decompilation."""
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        # Mock Ghidra helper
        mock_decompile = MagicMock(return_value=(
            """void main(int argc, char **argv) {
    if (argc > 1) {
        process_args();
    }
    return 0;
}""",
            {
                "function_name": "main",
                "entry_point": "0x401000",
                "parameter_count": 2,
                "local_symbol_count": 1,
                "signature": "int main(int argc, char **argv)",
                "body_size": 100
            }
        ))
        
        with patch("reversecore_mcp.core.ghidra_helper.ensure_ghidra_available", return_value=True), \
             patch("reversecore_mcp.core.ghidra_helper.decompile_function_with_ghidra", mock_decompile):
            
            result = await cli_tools.smart_decompile(str(test_file), "main", use_ghidra=True)
            
            assert result.status == "success"
            assert "void main" in result.data
            assert result.metadata.get("decompiler") == "ghidra"
            assert result.metadata.get("function_name") == "main"
            assert result.metadata.get("parameter_count") == 2
    
    async def test_smart_decompile_ghidra_disabled(
        self, workspace_dir, patched_workspace_config
    ):
        """Test decompilation with Ghidra explicitly disabled."""
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        # Mock radare2 execution
        mock_output = "void main() { return 0; }"
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock, return_value=(mock_output, len(mock_output))):
            
            result = await cli_tools.smart_decompile(str(test_file), "main", use_ghidra=False)
            
            assert result.status == "success"
            assert result.metadata.get("decompiler") == "radare2"
    
    async def test_smart_decompile_fallback_to_radare2(
        self, workspace_dir, patched_workspace_config
    ):
        """Test fallback to radare2 when Ghidra fails."""
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        # Mock Ghidra as unavailable
        mock_r2_output = "radare2 pseudo-c output"
        
        with patch("reversecore_mcp.core.ghidra_helper.ensure_ghidra_available", return_value=False), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_r2_output, len(mock_r2_output))):
            
            result = await cli_tools.smart_decompile(str(test_file), "main", use_ghidra=True)
            
            assert result.status == "success"
            assert result.metadata.get("decompiler") == "radare2"
    
    async def test_smart_decompile_ghidra_error_fallback(
        self, workspace_dir, patched_workspace_config
    ):
        """Test fallback to radare2 when Ghidra decompilation fails."""
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        # Mock Ghidra available but decompilation fails
        mock_decompile = MagicMock(side_effect=Exception("Ghidra decompilation error"))
        mock_r2_output = "radare2 fallback output"
        
        with patch("reversecore_mcp.core.ghidra_helper.ensure_ghidra_available", return_value=True), \
             patch("reversecore_mcp.core.ghidra_helper.decompile_function_with_ghidra", mock_decompile), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_r2_output, len(mock_r2_output))):
            
            result = await cli_tools.smart_decompile(str(test_file), "main", use_ghidra=True)
            
            assert result.status == "success"
            assert result.metadata.get("decompiler") == "radare2"
    
    async def test_smart_decompile_pyghidra_not_installed(
        self, workspace_dir, patched_workspace_config
    ):
        """Test fallback when PyGhidra is not installed."""
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_r2_output = "radare2 output"
        
        # Simulate ImportError when trying to import ghidra_helper
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_r2_output, len(mock_r2_output))):
            
            # The import should work (we're not testing actual import failure),
            # but ensure_ghidra_available returns False
            with patch("reversecore_mcp.core.ghidra_helper.ensure_ghidra_available", return_value=False):
                result = await cli_tools.smart_decompile(str(test_file), "main", use_ghidra=True)
                
                assert result.status == "success"
                assert result.metadata.get("decompiler") == "radare2"
    
    async def test_smart_decompile_ghidra_hex_address(
        self, workspace_dir, patched_workspace_config
    ):
        """Test Ghidra decompilation with hex address."""
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_decompile = MagicMock(return_value=(
            "void fcn_401000() { return; }",
            {
                "function_name": "fcn_401000",
                "entry_point": "0x401000",
                "parameter_count": 0,
                "local_symbol_count": 0,
                "signature": "void fcn_401000(void)",
                "body_size": 10
            }
        ))
        
        with patch("reversecore_mcp.core.ghidra_helper.ensure_ghidra_available", return_value=True), \
             patch("reversecore_mcp.core.ghidra_helper.decompile_function_with_ghidra", mock_decompile):
            
            result = await cli_tools.smart_decompile(str(test_file), "0x401000", use_ghidra=True)
            
            assert result.status == "success"
            assert "fcn_401000" in result.data
            assert result.metadata.get("decompiler") == "ghidra"


class TestGhidraHelperModule:
    """Test Ghidra helper module functions."""
    
    def test_ensure_ghidra_available_installed(self):
        """Test ensure_ghidra_available when PyGhidra is installed."""
        with patch.dict('sys.modules', {'pyghidra': MagicMock()}):
            from reversecore_mcp.core.ghidra_helper import ensure_ghidra_available
            assert ensure_ghidra_available() is True
    
    def test_ensure_ghidra_available_not_installed(self):
        """Test ensure_ghidra_available when PyGhidra is not installed."""
        # Create a fresh import to test ImportError handling
        import sys
        
        # Temporarily remove pyghidra from sys.modules if it exists
        pyghidra_backup = sys.modules.pop('pyghidra', None)
        
        try:
            # Simulate pyghidra not being installed
            with patch.dict('sys.modules', {'pyghidra': None}):
                # Force reimport to test the ImportError path
                import importlib
                from reversecore_mcp.core import ghidra_helper
                importlib.reload(ghidra_helper)
                
                # Test that it returns False when pyghidra import fails
                result = ghidra_helper.ensure_ghidra_available()
                assert result is False
        finally:
            # Restore pyghidra if it was previously imported
            if pyghidra_backup is not None:
                sys.modules['pyghidra'] = pyghidra_backup
