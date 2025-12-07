"""Integration tests for new analysis tools (pseudo code, signature, RTTI)."""

import subprocess

import pytest

from reversecore_mcp.tools.ghidra import decompilation, signature_tools, static_analysis


def _require_radare2() -> None:
    """Skip tests if radare2 is not installed."""
    try:
        subprocess.run(["r2", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("radare2 not installed")


class TestGetPseudoCode:
    """Integration tests for get_pseudo_code tool."""

    @pytest.mark.asyncio
    async def test_get_pseudo_code_success(self, sample_binary_path, patched_workspace_config):
        """Test successful pseudo C code generation."""
        _require_radare2()

        result = await decompilation.get_pseudo_code(str(sample_binary_path), "entry0")
        assert result.status == "success"
        assert isinstance(result.data, str)
        assert result.metadata and "bytes_read" in result.metadata
        assert result.metadata.get("format") == "pseudo_c"

    @pytest.mark.asyncio
    async def test_get_pseudo_code_default_address(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test pseudo code with default 'main' address."""
        _require_radare2()

        # Default address is 'main', which may not exist in test binary
        # The tool should return an error or empty result gracefully
        result = await decompilation.get_pseudo_code(str(sample_binary_path))
        # Either success (if main exists) or error (if not found)
        assert result.status in ["success", "error"]

    @pytest.mark.asyncio
    async def test_get_pseudo_code_invalid_address(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test pseudo code with invalid address format."""
        _require_radare2()

        # Test with shell injection attempt
        result = await decompilation.get_pseudo_code(str(sample_binary_path), "main; ls")
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_get_pseudo_code_nonexistent_file(self, workspace_dir, patched_workspace_config):
        """Test pseudo code on nonexistent file."""
        _require_radare2()

        result = await decompilation.get_pseudo_code(str(workspace_dir / "nonexistent.bin"))
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"


class TestGenerateSignature:
    """Integration tests for generate_signature tool."""

    @pytest.mark.asyncio
    async def test_generate_signature_success(self, sample_binary_path, patched_workspace_config):
        """Test successful YARA signature generation."""
        _require_radare2()

        result = await signature_tools.generate_signature(str(sample_binary_path), "0x0", 16)
        assert result.status == "success"
        assert isinstance(result.data, str)
        assert "rule suspicious_" in result.data
        assert "strings:" in result.data
        assert "condition:" in result.data
        assert result.metadata and "format" in result.metadata
        assert result.metadata.get("format") == "yara"
        assert "hex_bytes" in result.metadata

    @pytest.mark.asyncio
    async def test_generate_signature_default_length(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test signature generation with default length."""
        _require_radare2()

        result = await signature_tools.generate_signature(str(sample_binary_path), "0x0")
        assert result.status == "success"
        assert result.metadata.get("length") == 32  # default

    @pytest.mark.asyncio
    async def test_generate_signature_invalid_length(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test signature generation with invalid length."""
        _require_radare2()

        # Test with length > 1024
        result = await signature_tools.generate_signature(str(sample_binary_path), "0x0", 2000)
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

        # Test with negative length
        result = await signature_tools.generate_signature(str(sample_binary_path), "0x0", -10)
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_generate_signature_invalid_address(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test signature generation with invalid address."""
        _require_radare2()

        # Test with shell injection attempt
        result = await signature_tools.generate_signature(
            str(sample_binary_path), "0x0; rm -rf /", 16
        )
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_generate_signature_hex_format(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test that signature hex bytes are properly formatted."""
        _require_radare2()

        result = await signature_tools.generate_signature(str(sample_binary_path), "0x0", 8)
        assert result.status == "success"

        # Check hex_bytes in metadata
        hex_bytes = result.metadata.get("hex_bytes", "")
        # Should be space-separated pairs like "48 83 ec 20"
        parts = hex_bytes.split()
        assert len(parts) == 8  # 8 bytes requested
        for part in parts:
            assert len(part) == 2  # Each byte is 2 hex chars
            assert all(c in "0123456789abcdefABCDEF" for c in part)


class TestExtractRTTIInfo:
    """Integration tests for extract_rtti_info tool."""

    @pytest.mark.asyncio
    async def test_extract_rtti_success(self, sample_binary_path, patched_workspace_config):
        """Test successful RTTI extraction."""
        _require_radare2()

        result = await static_analysis.extract_rtti_info(str(sample_binary_path))
        assert result.status == "success"
        assert isinstance(result.data, dict)
        assert "classes" in result.data
        assert "class_count" in result.data
        assert "methods" in result.data
        assert "method_count" in result.data
        assert "vtables" in result.data
        assert "vtable_count" in result.data
        assert "has_rtti" in result.data
        assert "binary_type" in result.data
        assert result.metadata and "format" in result.metadata
        assert result.metadata.get("format") == "rtti_info"

    @pytest.mark.asyncio
    async def test_extract_rtti_no_cpp_binary(self, sample_binary_path, patched_workspace_config):
        """Test RTTI extraction on non-C++ binary."""
        _require_radare2()

        # Simple test binary likely has no RTTI
        result = await static_analysis.extract_rtti_info(str(sample_binary_path))
        assert result.status == "success"
        assert result.data["has_rtti"] in [True, False]
        # Should return empty lists for non-C++ binary
        if not result.data["has_rtti"]:
            assert result.data["class_count"] == 0

    @pytest.mark.asyncio
    async def test_extract_rtti_nonexistent_file(self, workspace_dir, patched_workspace_config):
        """Test RTTI extraction on nonexistent file."""
        _require_radare2()

        result = await static_analysis.extract_rtti_info(str(workspace_dir / "nonexistent.bin"))
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_extract_rtti_structure(self, sample_binary_path, patched_workspace_config):
        """Test that RTTI output has correct structure."""
        _require_radare2()

        result = await static_analysis.extract_rtti_info(str(sample_binary_path))
        assert result.status == "success"

        # Check classes structure
        assert isinstance(result.data["classes"], list)

        # Check methods structure
        assert isinstance(result.data["methods"], list)

        # Check vtables structure
        assert isinstance(result.data["vtables"], list)

        # Check counts are integers
        assert isinstance(result.data["class_count"], int)
        assert isinstance(result.data["method_count"], int)
        assert isinstance(result.data["vtable_count"], int)
