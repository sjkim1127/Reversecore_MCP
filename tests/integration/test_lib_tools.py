"""Integration tests for library tools."""

import pytest

from reversecore_mcp.tools.common import lib_tools


class TestRunYara:
    """Integration tests for run_yara tool."""

    def test_run_yara_success(self, workspace_dir, read_only_dir, patched_workspace_config):
        """Test successful YARA scan."""

        # Create test file
        test_file = workspace_dir / "test.txt"
        test_file.write_text("This is a test file with some content")

        # Create YARA rule inside allowed read-only directory
        rule_file = read_only_dir / "test.yar"
        rule_file.write_text('rule test { strings: $a = "test" condition: $a }')

        try:
            import yara
        except ImportError:
            pytest.skip("yara-python not installed")

        result = lib_tools.run_yara(str(test_file), str(rule_file))
        if result.status == "error":
            pytest.fail(f"YARA scan failed: {result.message}")
        assert result.status == "success"
        assert isinstance(result.data, dict)
        assert "match_count" in result.data

    def test_run_yara_nonexistent_file(self, workspace_dir, read_only_dir, patched_workspace_config):
        """Test YARA scan on nonexistent file."""

        rule_file = read_only_dir / "test.yar"
        rule_file.write_text('rule test { condition: true }')

        try:
            import yara
        except ImportError:
            pytest.skip("yara-python not installed")

        result = lib_tools.run_yara(
            str(workspace_dir / "nonexistent.txt"), str(rule_file)
        )
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"


@pytest.mark.skip(reason="disassemble_with_capstone was removed")
class TestDisassembleWithCapstone:
    """Integration tests for disassemble_with_capstone tool."""

    def test_disassemble_x86_64(self, sample_binary_path, patched_workspace_config):
        """Test disassembly with x86-64 architecture."""

        try:
            from capstone import Cs
        except ImportError:
            pytest.skip("capstone not installed")

        result = lib_tools.disassemble_with_capstone(
            sample_binary_path, offset=0, size=16, arch="x86", mode="64"
        )
        assert result.status == "success"
        assert isinstance(result.data, str)
        assert result.metadata and result.metadata.get("instruction_count") is not None

    def test_disassemble_invalid_arch(self, sample_binary_path, patched_workspace_config):
        """Test disassembly with invalid architecture."""

        try:
            from capstone import Cs
        except ImportError:
            pytest.skip("capstone not installed")

        result = lib_tools.disassemble_with_capstone(
            sample_binary_path, arch="invalid_arch", mode="64"
        )
        assert result.status == "error"
        assert result.error_code == "INVALID_PARAMETER"
        assert "unsupported architecture" in result.message.lower()

    def test_disassemble_invalid_mode(self, sample_binary_path, patched_workspace_config):
        """Test disassembly with invalid mode."""

        try:
            from capstone import Cs
        except ImportError:
            pytest.skip("capstone not installed")

        result = lib_tools.disassemble_with_capstone(
            sample_binary_path, arch="x86", mode="invalid_mode"
        )
        assert result.status == "error"
        assert result.error_code == "INVALID_PARAMETER"
        assert "unsupported mode" in result.message.lower()

