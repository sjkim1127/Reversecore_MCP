
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import json
from reversecore_mcp.tools import cli_tools
from reversecore_mcp.core.result import ToolResult

@pytest.mark.asyncio
class TestCliToolsMocked:

    async def test_generate_signature_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        # Mock output should be continuous hex string (p8 output)
        mock_output = "4883ec20"
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (mock_output, len(mock_output))
            
            result = await cli_tools.generate_signature(str(test_file), "0x401000", length=4)
            
            assert result.status == "success"
            assert "rule suspicious_test_x401000" in result.data
            assert "48 83 ec 20" in result.data

    async def test_generate_signature_invalid_length(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        result = await cli_tools.generate_signature(str(test_file), "0x401000", length=0)
        assert result.status == "error"
        assert "Length must be between" in result.message

    async def test_generate_signature_invalid_address(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        result = await cli_tools.generate_signature(str(test_file), "invalid;cmd")
        assert result.status == "error"
        # Updated to match the new error message from validate_address_format
        assert "must contain only alphanumeric characters" in result.message

    async def test_generate_signature_extraction_failed(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = ("", 0)
            
            result = await cli_tools.generate_signature(str(test_file), "0x401000")
            
            assert result.status == "error"
            assert "Failed to extract valid hex bytes" in result.message

    async def test_extract_rtti_info_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        classes_json = json.dumps([
            {"classname": "MyClass", "addr": "0x1000", "methods": [], "vtable": "0x2000"}
        ])
        symbols_json = json.dumps([
            {"name": "_Z7MyClass", "vaddr": "0x1000", "type": "FUNC", "size": 100},
            {"name": "vtable_MyClass", "vaddr": "0x2000"}
        ])
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = [
                (classes_json, len(classes_json)),
                (symbols_json, len(symbols_json))
            ]
            
            result = await cli_tools.extract_rtti_info(str(test_file))
            
            assert result.status == "success"
            data = result.data
            assert data["class_count"] == 1
            assert data["classes"][0]["name"] == "MyClass"
            assert data["method_count"] == 1
            assert data["vtable_count"] == 1
            assert data["binary_type"] == "C++"

    async def test_extract_rtti_info_parse_error(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = ("INVALID JSON", 10)
            
            result = await cli_tools.extract_rtti_info(str(test_file))
            
            assert result.status == "error"
            assert "Failed to parse RTTI output" in result.message

    async def test_analyze_xrefs_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        xrefs_to_json = json.dumps([{"from": "0x400", "type": "call", "function": "main"}])
        xrefs_from_json = json.dumps([{"addr": "0x500", "type": "call", "function": "printf"}])
        
        output = f"{xrefs_to_json}\n{xrefs_from_json}"
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (output, len(output))
            
            result = await cli_tools.analyze_xrefs(str(test_file), "0x401000", xref_type="all")
            
            assert result.status == "success"
            data = result.data
            assert data["total_refs_to"] == 1
            assert data["total_refs_from"] == 1
            assert data["xrefs_to"][0]["from"] == "0x400"

    async def test_analyze_xrefs_invalid_type(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        result = await cli_tools.analyze_xrefs(str(test_file), "0x401000", xref_type="invalid")
        assert result.status == "error"
        assert "Invalid xref_type" in result.message

    async def test_recover_structures_radare2(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        vars_json = json.dumps([
            {"type": "int", "name": "field1", "delta": 0, "ref": {"base": "rbp"}},
            {"type": "char *", "name": "field2", "delta": 8, "ref": {"base": "rbp"}}
        ])
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (vars_json, len(vars_json))
            
            result = await cli_tools.recover_structures(str(test_file), "main", use_ghidra=False)
            
            assert result.status == "success"
            data = result.data
            assert data["count"] == 1
            assert data["structures"][0]["name"] == "struct_rbp"
            assert len(data["structures"][0]["fields"]) == 2

    async def test_recover_structures_ghidra_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        mock_structures = [{"name": "Player", "fields": []}]
        mock_metadata = {"structure_count": 1}
        
        with patch("reversecore_mcp.core.ghidra_helper.ensure_ghidra_available", return_value=True), \
             patch("reversecore_mcp.core.ghidra_helper.recover_structures_with_ghidra", 
                   return_value=(mock_structures, mock_metadata)):
            
            result = await cli_tools.recover_structures(str(test_file), "main", use_ghidra=True)
            
            assert result.status == "success"
            assert result.data["structures"] == mock_structures
            assert result.metadata["method"] == "ghidra"

    async def test_recover_structures_ghidra_missing(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        # Mock radare2 output for fallback
        vars_json = json.dumps([
            {"type": "int", "name": "field1", "delta": 0, "ref": {"base": "rbp"}}
        ])

        with patch("reversecore_mcp.core.ghidra_helper.ensure_ghidra_available", return_value=False), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", new_callable=AsyncMock) as mock_exec:
            
            mock_exec.return_value = (vars_json, len(vars_json))
            
            result = await cli_tools.recover_structures(str(test_file), "main", use_ghidra=True)
            
            # Should succeed via fallback
            assert result.status == "success"
            assert result.metadata["method"] == "radare2"
            assert "Ghidra not available" in result.metadata["description"]

    async def test_diff_binaries_success(self, workspace_dir, patched_workspace_config):
        file_a = workspace_dir / "v1.exe"
        file_a.write_bytes(b"V1")
        file_b = workspace_dir / "v2.exe"
        file_b.write_bytes(b"V2")
        
        diff_output = "0x401000 code_change instruction modified"
        sim_output = "similarity: 0.95"
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = [
                (diff_output, len(diff_output)),
                (sim_output, len(sim_output))
            ]
            
            result = await cli_tools.diff_binaries(str(file_a), str(file_b))
            
            assert result.status == "success"
            data = json.loads(result.data)
            assert data["similarity"] == 0.95
            assert len(data["changes"]) == 1
            assert data["changes"][0]["type"] == "code_change"

    async def test_match_libraries_success(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        funcs_json = json.dumps([
            {"name": "sym.imp.printf", "offset": 0x1000},
            {"name": "main", "offset": 0x2000}
        ])
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (funcs_json, len(funcs_json))
            
            result = await cli_tools.match_libraries(str(test_file))
            
            assert result.status == "success"
            data = json.loads(result.data)
            assert data["total_functions"] == 2
            assert data["library_functions"] == 1
            assert data["user_functions"] == 1
            assert data["library_matches"][0]["name"] == "sym.imp.printf"

    async def test_match_libraries_parse_error(self, workspace_dir, patched_workspace_config):
        test_file = workspace_dir / "test.exe"
        test_file.write_bytes(b"FAKE")
        
        with patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = ("INVALID", 10)
            
            result = await cli_tools.match_libraries(str(test_file))
            
            assert result.status == "error"
            assert "Failed to parse function list" in result.message

