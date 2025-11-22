"""Unit tests for smart_decompile and generate_yara_rule tools."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools import cli_tools


@pytest.mark.asyncio
class TestSmartDecompile:
    """Test suite for smart_decompile function."""
    
    async def test_smart_decompile_success(self, tmp_path):
        """Test successful decompilation."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_output = """void main(int argc, char **argv) {
    int result = 0;
    if (argc > 1) {
        result = process_args();
    }
    return result;
}"""
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async", 
                   new_callable=AsyncMock, return_value=(mock_output, len(mock_output))):
            
            result = await cli_tools.smart_decompile(str(test_file), "main")
            
            assert result.status == "success"
            assert "void main" in result.data
            assert "process_args" in result.data
    
    async def test_smart_decompile_invalid_address(self, tmp_path):
        """Test decompilation with invalid function address."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file):
            result = await cli_tools.smart_decompile(str(test_file), "main; rm -rf /")
            
            assert result.status == "error"
            # Updated to match the new error message from validate_address_format
            assert "must contain only alphanumeric characters" in result.message
    
    async def test_smart_decompile_no_function(self, tmp_path):
        """Test decompilation when function doesn't exist."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_output = "Cannot find function at nonexistent_func"
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_output, len(mock_output))):
            
            result = await cli_tools.smart_decompile(str(test_file), "nonexistent_func")
            
            assert result.status == "success"
            assert "Cannot find function" in result.data
    
    async def test_smart_decompile_hex_address(self, tmp_path):
        """Test decompilation with hex address."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_output = "void fcn_401000() { return; }"
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_output, len(mock_output))):
            
            result = await cli_tools.smart_decompile(str(test_file), "0x401000")
            
            assert result.status == "success"
            assert "fcn_401000" in result.data


@pytest.mark.asyncio
class TestGenerateYaraRule:
    """Test suite for generate_yara_rule function."""
    
    async def test_generate_yara_rule_success(self, tmp_path):
        """Test successful YARA rule generation."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_output = "554889e54883ec10897dfc488b45fc"
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_output, len(mock_output))):
            
            result = await cli_tools.generate_yara_rule(str(test_file), "main", rule_name="test_rule")
            
            assert result.status == "success"
            assert "rule test_rule" in result.data
            assert "strings:" in result.data
            assert "condition:" in result.data
            assert "$code" in result.data
    
    async def test_generate_yara_rule_invalid_name(self, tmp_path):
        """Test YARA rule generation with invalid rule name."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file):
            result = await cli_tools.generate_yara_rule(str(test_file), "main", rule_name="123-invalid")
            
            assert result.status == "error"
            assert "rule_name must start with a letter" in result.message
    
    async def test_generate_yara_rule_invalid_byte_length(self, tmp_path):
        """Test YARA rule generation with invalid byte_length."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file):
            result = await cli_tools.generate_yara_rule(str(test_file), "main", byte_length=2000)
            
            assert result.status == "error"
            assert "cannot exceed 1024" in result.message
    
    async def test_generate_yara_rule_invalid_address(self, tmp_path):
        """Test YARA rule generation with invalid function address."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file):
            result = await cli_tools.generate_yara_rule(str(test_file), "main; echo hacked")
            
            assert result.status == "error"
            # Updated to match the new error message from validate_address_format
            assert "must contain only alphanumeric characters" in result.message
    
    async def test_generate_yara_rule_custom_byte_length(self, tmp_path):
        """Test YARA rule generation with custom byte length."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_output = "554889e5"
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_output, len(mock_output))):
            
            result = await cli_tools.generate_yara_rule(
                str(test_file), 
                "main", 
                byte_length=32,
                rule_name="custom_rule"
            )
            
            assert result.status == "success"
            assert "rule custom_rule" in result.data
    
    async def test_generate_yara_rule_hex_address(self, tmp_path):
        """Test YARA rule generation with hex address."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"FAKE_BINARY")
        
        mock_output = "554889e54883ec10"
        
        with patch("reversecore_mcp.tools.cli_tools.validate_file_path", return_value=test_file), \
             patch("reversecore_mcp.tools.cli_tools.execute_subprocess_async",
                   new_callable=AsyncMock, return_value=(mock_output, len(mock_output))):
            
            result = await cli_tools.generate_yara_rule(str(test_file), "0x401000")
            
            assert result.status == "success"
            assert "rule auto_generated_rule" in result.data


def test_validate_decompile_params():
    """Test decompile parameter validation."""
    from reversecore_mcp.core.validators import _validate_decompile_params
    
    # Valid params
    _validate_decompile_params({"function_address": "main"})
    _validate_decompile_params({"function_address": "0x401000"})
    _validate_decompile_params({})  # No address is also valid (uses default)
    
    # Invalid params
    with pytest.raises(ValidationError, match="function_address must be a string"):
        _validate_decompile_params({"function_address": 12345})


def test_validate_yara_generation_params():
    """Test YARA generation parameter validation."""
    from reversecore_mcp.core.validators import _validate_yara_generation_params
    
    # Valid params
    _validate_yara_generation_params({
        "function_address": "main",
        "byte_length": 64,
        "rule_name": "test_rule"
    })
    
    # Invalid byte_length
    with pytest.raises(ValidationError, match="byte_length must be a positive integer"):
        _validate_yara_generation_params({"byte_length": 0})
    
    with pytest.raises(ValidationError, match="byte_length must be a positive integer"):
        _validate_yara_generation_params({"byte_length": "large"})
    
    with pytest.raises(ValidationError, match="cannot exceed 1024"):
        _validate_yara_generation_params({"byte_length": 2000})
    
    # Invalid rule_name
    with pytest.raises(ValidationError, match="rule_name must be a string"):
        _validate_yara_generation_params({"rule_name": 123})
    
    # Invalid function_address
    with pytest.raises(ValidationError, match="function_address must be a string"):
        _validate_yara_generation_params({"function_address": 456})
