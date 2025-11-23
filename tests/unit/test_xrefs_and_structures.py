"""Unit tests for analyze_xrefs and recover_structures tools."""

import json
import pytest

from reversecore_mcp.tools import cli_tools
from reversecore_mcp.tools import r2_analysis


def _create_workspace_file(workspace_dir, name: str, data: str | bytes = "stub"):
    """Helper to create test files in workspace."""
    path = workspace_dir / name
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data)
    return path


class TestAnalyzeXrefs:
    """Tests for analyze_xrefs tool."""

    @pytest.mark.asyncio
    async def test_analyze_xrefs_all_success(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test analyzing all cross-references (to and from)."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        # Mock radare2 output with xrefs
        xrefs_output = """[{"from":4198480,"type":"CALL","opcode":"call sym.imp.malloc","fcn_addr":4198464,"fcn_name":"main"}]
[{"addr":4198500,"type":"CALL","opcode":"call sym.imp.printf"}]"""
        
        async def mock_exec(cmd, **kw):
            return (xrefs_output, 100)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.analyze_xrefs(
            str(mocked_path),
            "main",
            "all"
        )
        
        assert result.status == "success"
        assert isinstance(result.data, dict)
        assert "xrefs_to" in result.data
        assert "xrefs_from" in result.data
        assert "summary" in result.data
        assert result.data["address"] == "main"
        assert result.data["xref_type"] == "all"

    @pytest.mark.asyncio
    async def test_analyze_xrefs_to_only(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test analyzing references TO an address (callers)."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        xrefs_output = '[{"from":4198480,"type":"CALL","opcode":"call main","fcn_addr":4198464}]'
        
        async def mock_exec(cmd, **kw):
            return (xrefs_output, 50)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.analyze_xrefs(
            str(mocked_path),
            "0x401000",
            "to"
        )
        
        assert result.status == "success"
        assert result.data["xref_type"] == "to"
        assert result.data["total_refs_to"] > 0

    @pytest.mark.asyncio
    async def test_analyze_xrefs_from_only(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test analyzing references FROM an address (callees)."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        xrefs_output = '[{"addr":4198500,"type":"CALL","opcode":"call sym.imp.printf"}]'
        
        async def mock_exec(cmd, **kw):
            return (xrefs_output, 50)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.analyze_xrefs(
            str(mocked_path),
            "main",
            "from"
        )
        
        assert result.status == "success"
        assert result.data["xref_type"] == "from"
        assert result.data["total_refs_from"] > 0

    @pytest.mark.asyncio
    async def test_analyze_xrefs_no_refs_found(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test when no cross-references are found."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        async def mock_exec(cmd, **kw):
            return ("[]", 10)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.analyze_xrefs(
            str(mocked_path),
            "0x401000",
            "all"
        )
        
        assert result.status == "success"
        assert result.data["total_refs_to"] == 0
        assert result.data["total_refs_from"] == 0
        assert "No cross-references found" in result.data["summary"]

    @pytest.mark.asyncio
    async def test_analyze_xrefs_invalid_type(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test with invalid xref_type parameter."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        result = await cli_tools.analyze_xrefs(
            str(mocked_path),
            "main",
            "invalid_type"
        )
        
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_analyze_xrefs_invalid_address(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test with invalid address format."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        result = await cli_tools.analyze_xrefs(
            str(mocked_path),
            "main; rm -rf /",  # Shell injection attempt
            "all"
        )
        
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_analyze_xrefs_malformed_json(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test handling of malformed JSON output."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        async def mock_exec(cmd, **kw):
            return ("{not valid json}", 10)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.analyze_xrefs(
            str(mocked_path),
            "main",
            "all"
        )
        
        # Should return success but with empty refs since it gracefully handles parse errors
        assert result.status == "success"


class TestRecoverStructures:
    """Tests for recover_structures tool."""

    @pytest.mark.asyncio
    async def test_recover_structures_radare2_success(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test structure recovery using radare2."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        # Mock radare2 variables output
        variables_output = json.dumps([
            {"type": "int", "name": "var_10h", "delta": -16, "ref": {"base": "rbp"}},
            {"type": "char *", "name": "var_8h", "delta": -8, "ref": {"base": "rbp"}},
            {"type": "int", "name": "var_4h", "delta": -4, "ref": {"base": "rbp"}}
        ])
        
        async def mock_exec(cmd, **kw):
            return (variables_output, 100)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.recover_structures(
            str(mocked_path),
            "main",
            use_ghidra=False
        )
        
        assert result.status == "success"
        assert isinstance(result.data, dict)
        assert "structures" in result.data
        assert "c_definitions" in result.data
        assert result.data["count"] > 0

    @pytest.mark.asyncio
    async def test_recover_structures_radare2_empty(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test when no structures are found."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        async def mock_exec(cmd, **kw):
            return ("[]", 10)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.recover_structures(
            str(mocked_path),
            "main",
            use_ghidra=False
        )
        
        assert result.status == "success"
        assert result.data["count"] == 0

    @pytest.mark.asyncio
    async def test_recover_structures_invalid_address(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test with invalid function address."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        result = await cli_tools.recover_structures(
            str(mocked_path),
            "main; echo hack",  # Shell injection attempt
            use_ghidra=False
        )
        
        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_recover_structures_ghidra_not_available(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test when Ghidra is requested but not available (should fallback)."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        # Mock ensure_ghidra_available to return False
        def mock_ghidra_check():
            return False
        
        monkeypatch.setattr(
            "reversecore_mcp.core.ghidra_helper.ensure_ghidra_available",
            mock_ghidra_check,
        )

        # Mock radare2 output for fallback
        variables_output = json.dumps([
            {"type": "int", "name": "var_10h", "delta": -16, "ref": {"base": "rbp"}}
        ])
        
        async def mock_exec(cmd, **kw):
            return (variables_output, 100)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.recover_structures(
            str(mocked_path),
            "main",
            use_ghidra=True
        )
        
        assert result.status == "success"
        assert result.metadata["method"] == "radare2"
        assert "Ghidra not available" in result.metadata["description"]

    @pytest.mark.asyncio
    async def test_recover_structures_radare2_malformed_json(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test handling of malformed JSON from radare2."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        async def mock_exec(cmd, **kw):
            return ("{not valid json", 10)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.recover_structures(
            str(mocked_path),
            "main",
            use_ghidra=False
        )
        
        assert result.status == "error"
        assert result.error_code == "STRUCTURE_RECOVERY_ERROR"

    @pytest.mark.asyncio
    async def test_recover_structures_cpp_method_address(
        self, monkeypatch, workspace_dir, patched_workspace_config
    ):
        """Test with C++ method name format (Player::update)."""
        mocked_path = _create_workspace_file(workspace_dir, "test_binary")
        
        variables_output = json.dumps([
            {"type": "Player *", "name": "this", "delta": 0, "ref": {"base": "rdi"}}
        ])
        
        async def mock_exec(cmd, **kw):
            return (variables_output, 50)
        
        monkeypatch.setattr(
            r2_analysis,
            "execute_subprocess_async",
            mock_exec,
        )
        
        result = await cli_tools.recover_structures(
            str(mocked_path),
            "Player::update",
            use_ghidra=False
        )
        
        assert result.status == "success"
        assert result.metadata["function_address"] == "Player::update"


# Integration-style tests (will be skipped if radare2 not available)
@pytest.mark.skipif(
    not __import__('shutil').which('r2'),
    reason="radare2 not installed"
)
class TestXrefsAndStructuresIntegration:
    """Integration tests requiring actual radare2 installation."""
    
    @pytest.mark.asyncio
    async def test_xrefs_with_real_binary(
        self, workspace_dir, patched_workspace_config
    ):
        """Test xrefs with a real binary (if radare2 available)."""
        # Create a minimal ELF binary for testing
        # This would require an actual binary file
        # Skipping for now - would need test fixtures
        pass

    @pytest.mark.asyncio
    async def test_structures_with_real_binary(
        self, workspace_dir, patched_workspace_config
    ):
        """Test structure recovery with a real binary (if radare2 available)."""
        # Similar to above - needs real binary
        pass
