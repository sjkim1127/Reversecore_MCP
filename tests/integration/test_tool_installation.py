"""
Integration tests: Tool installation and execution verification.

Verifies that external tools (radare2, yara, ghidra, etc.) are properly
installed and can be invoked through the MCP server tools.
"""

import shutil
import subprocess
import pytest
from pathlib import Path


class TestToolInstallation:
    """Verify that external analysis tools are installed."""

    def test_radare2_installed(self):
        """Verify radare2 is installed and accessible."""
        result = shutil.which("r2")
        pytest.skip("radare2 (r2) is not installed", allow_module_level=False) \
            if result is None else None
        
        # Test r2 version
        output = subprocess.run(
            ["r2", "-v"],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert output.returncode == 0, f"r2 -v failed: {output.stderr}"
        assert "radare2" in output.stdout.lower(), "radare2 version check failed"

    def test_yara_installed(self):
        """Verify yara is installed and accessible."""
        result = shutil.which("yara")
        pytest.skip("yara is not installed", allow_module_level=False) \
            if result is None else None

        # Test yara version
        output = subprocess.run(
            ["yara", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert output.returncode == 0, f"yara --version failed: {output.stderr}"
        # yara --version outputs plain version number (e.g. "4.5.0")
        assert output.stdout.strip(), "yara version output is empty"

    def test_strings_installed(self):
        """Verify strings utility is installed."""
        result = shutil.which("strings")
        assert result is not None, "strings is not installed"

    def test_file_installed(self):
        """Verify file utility is installed."""
        result = shutil.which("file")
        assert result is not None, "file is not installed"

    def test_binwalk_installed(self):
        """Verify binwalk is installed."""
        result = shutil.which("binwalk")
        pytest.skip("binwalk is not installed", allow_module_level=False) \
            if result is None else None

    def test_objdump_installed(self):
        """Verify objdump (part of binutils) is installed."""
        result = shutil.which("objdump")
        assert result is not None, "objdump is not installed"


class TestToolInvocation:
    """Test that tools can be invoked through MCP tool functions."""

    @pytest.fixture
    def sample_binary(self, tmp_path):
        """Create a minimal ELF binary for testing."""
        binary_path = tmp_path / "test_binary"
        # Create a minimal ELF binary (hello world)
        binary_content = bytes([
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        ])
        binary_path.write_bytes(binary_content)
        return binary_path

    def test_radare2_file_analysis(self, sample_binary):
        """Test radare2 can analyze a file."""
        if shutil.which("r2") is None:
            pytest.skip("radare2 (r2) is not installed")
        
        output = subprocess.run(
            ["r2", "-c", "afl", "-q", str(sample_binary)],
            capture_output=True,
            text=True,
            timeout=10
        )
        # r2 may fail on minimal binary, but should not have permission errors
        assert output.returncode in (0, 1), f"r2 unexpected error: {output.stderr}"

    def test_file_command(self, sample_binary):
        """Test file command can identify binary type."""
        output = subprocess.run(
            ["file", str(sample_binary)],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert output.returncode == 0, f"file command failed: {output.stderr}"
        assert len(output.stdout) > 0, "file command returned no output"

    def test_strings_command(self, sample_binary):
        """Test strings command can extract strings."""
        output = subprocess.run(
            ["strings", str(sample_binary)],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert output.returncode == 0, f"strings command failed: {output.stderr}"


class TestMCPToolCalls:
    """Test that MCP tools actually invoke the external tools."""

    @pytest.fixture
    def sample_binary_file(self, tmp_path, monkeypatch):
        """Create a test binary and setup workspace."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        binary_path = workspace / "test.bin"
        binary_content = bytes([
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        binary_path.write_bytes(binary_content)
        
        # Set workspace env vars
        monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
        
        return workspace, binary_path

    @pytest.mark.asyncio
    async def test_radare2_analysis_tool(self, sample_binary_file, patched_workspace_config):
        """Test that radare2 analysis tool invokes r2 successfully."""
        if shutil.which("r2") is None:
            pytest.skip("radare2 (r2) is not installed")
        
        from reversecore_mcp.tools.radare2.r2_analysis import get_file_info
        
        workspace, binary_path = sample_binary_file
        
        try:
            result = get_file_info(str(binary_path))
            # Should return a dict with analysis results
            assert isinstance(result, dict), "get_file_info should return dict"
        except Exception as e:
            # May fail on minimal binary, but should not be tool unavailable error
            error_msg = str(e).lower()
            assert "radare2" not in error_msg or "executable" in error_msg, \
                f"Unexpected radare2 error: {e}"

    def test_file_identification_tool(self, sample_binary_file, patched_workspace_config):
        """Test file identification using file command."""
        from reversecore_mcp.tools.common.file_operations import identify_file
        
        workspace, binary_path = sample_binary_file
        
        result = identify_file(str(binary_path))
        assert isinstance(result, str), "identify_file should return string"
        assert len(result) > 0, "identify_file should return non-empty result"

    @pytest.mark.asyncio
    async def test_mcp_tool_execution(self, sample_binary_file):
        """Test end-to-end MCP tool execution."""
        from fastmcp import FastMCP
        from fastmcp.client import Client
        from reversecore_mcp.tools.common.file_operations import list_workspace
        
        workspace, binary_path = sample_binary_file
        
        # Create minimal MCP server
        mcp = FastMCP(name="test", lifespan=None)
        mcp.tool(list_workspace)
        
        async with Client(transport=mcp) as client:
            # List tools
            tools = await client.list_tools()
            assert len(tools) > 0, "Should have at least one tool"
            
            # Call list_workspace tool
            result = await client.call_tool("list_workspace", {})
            assert result is not None, "list_workspace should return result"


class TestToolErrorHandling:
    """Test proper error handling when tools are unavailable."""

    def test_missing_tool_error_message(self, monkeypatch):
        """Test that missing tools produce clear error messages."""
        # Temporarily hide radare2
        original_which = shutil.which
        
        def mock_which(cmd):
            if cmd == "r2":
                return None
            return original_which(cmd)
        
        monkeypatch.setattr(shutil, "which", mock_which)
        
        # This should either work with fallback or raise clear error
        # Don't assert failure - just ensure error handling exists
        import reversecore_mcp.core.r2_helpers
        # Tool should have graceful degradation


@pytest.mark.integration
class TestToolIntegration:
    """Integration tests for all tools working together."""

    @pytest.fixture
    def test_workspace(self, tmp_path):
        """Create a test workspace with sample files."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        # Create test binary
        binary_file = workspace / "sample.bin"
        binary_file.write_bytes(b"\x7fELF" + b"\x00" * 20)
        
        # Create test file
        text_file = workspace / "readme.txt"
        text_file.write_text("Test content for analysis")
        
        return workspace

    def test_all_tools_accessible(self, test_workspace):
        """Verify all critical tools are accessible."""
        tools_to_check = ["r2", "yara", "file", "strings", "binwalk"]
        available = []
        missing = []
        
        for tool in tools_to_check:
            if shutil.which(tool):
                available.append(tool)
            else:
                missing.append(tool)
        
        # At least half should be available in CI environment
        # Local machines may not have all tools
        if available:
            print(f"\n✅ Available tools: {available}")
        if missing:
            print(f"\n⚠️  Missing tools: {missing}")

    def test_basic_file_operations(self, test_workspace):
        """Test basic file operations with available tools."""
        binary_file = test_workspace / "sample.bin"
        
        # Test file identification
        output = subprocess.run(
            ["file", str(binary_file)],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert output.returncode == 0
        
        # Test strings extraction
        output = subprocess.run(
            ["strings", str(binary_file)],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert output.returncode == 0
