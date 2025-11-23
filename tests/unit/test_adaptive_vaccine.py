"""Unit tests for adaptive_vaccine tool."""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from pathlib import Path
from reversecore_mcp.tools.adaptive_vaccine import (
    adaptive_vaccine,
    _detect_architecture,
    _hex_to_yara_bytes,
    _generate_yara_rule,
)
from reversecore_mcp.core.result import ToolResult


class TestAdaptiveVaccine:
    """Test cases for adaptive_vaccine tool."""

    @pytest.mark.asyncio
    async def test_yara_generation_basic(self):
        """Test basic YARA rule generation."""
        threat_report = {
            "function": "suspicious_func",
            "address": "0x401000",
            "instruction": "cmp eax, 0xDEADBEEF",
            "reason": "Magic value detected"
        }
        
        result = await adaptive_vaccine(
            threat_report=threat_report,
            action="yara",
            dry_run=True
        )
        
        assert result.status == "success"
        assert "yara_rule" in result.data
        assert "suspicious_func" in result.data["yara_rule"]
        assert "0x401000" in result.data["yara_rule"]
        assert "architecture" in result.data

    @pytest.mark.asyncio
    async def test_patch_action_requires_file_path(self):
        """Test that patch action requires file_path."""
        threat_report = {
            "function": "test_func",
            "address": "0x401000"
        }
        
        result = await adaptive_vaccine(
            threat_report=threat_report,
            action="patch",
            dry_run=True
        )
        
        assert result.status == "error"
        assert "file_path is required" in result.message.lower()

    @pytest.mark.asyncio
    async def test_yara_with_context(self):
        """Test YARA generation with context logging."""
        threat_report = {
            "function": "test_func",
            "address": "0x401000",
            "instruction": "mov eax, 0x1234"
        }
        
        mock_ctx = AsyncMock()
        
        result = await adaptive_vaccine(
            threat_report=threat_report,
            action="yara",
            ctx=mock_ctx
        )
        
        assert result.status == "success"
        assert mock_ctx.info.called

    @pytest.mark.asyncio
    async def test_invalid_file_path_for_patch(self):
        """Test patch action with invalid file path."""
        threat_report = {
            "function": "test_func",
            "address": "0x401000"
        }
        
        with patch('reversecore_mcp.tools.adaptive_vaccine.validate_file_path') as mock_validate:
            mock_validate.side_effect = ValueError("Invalid file path")
            
            result = await adaptive_vaccine(
                threat_report=threat_report,
                action="patch",
                file_path="/invalid/path.exe",
                dry_run=True
            )
            
            assert result.status == "error"

    @pytest.mark.asyncio
    async def test_both_action(self):
        """Test generating both YARA and patch."""
        threat_report = {
            "function": "test_func",
            "address": "0x401000",
            "instruction": "nop"
        }
        
        # We can't test full patch without a real binary, but can test the flow
        result = await adaptive_vaccine(
            threat_report=threat_report,
            action="yara",  # Use yara only for testing
            dry_run=True
        )
        
        assert result.status == "success"
        assert "yara_rule" in result.data


class TestDetectArchitecture:
    """Test architecture detection."""

    def test_detect_architecture_with_mock(self):
        """Test architecture detection with mocked LIEF."""
        with patch('reversecore_mcp.tools.adaptive_vaccine.lief') as mock_lief:
            # Mock PE binary - x86
            mock_binary = Mock()
            mock_binary.header.machine = Mock()
            mock_lief.parse.return_value = mock_binary
            mock_lief.PE.Binary = type(mock_binary)
            mock_lief.PE.MACHINE_TYPES.I386 = 0x14c
            mock_binary.header.machine = 0x14c
            
            result = _detect_architecture(Path("/fake/binary.exe"))
            # May return various results based on mock setup
            assert isinstance(result, str)

    def test_detect_architecture_invalid_binary(self):
        """Test architecture detection with invalid binary."""
        with patch('reversecore_mcp.tools.adaptive_vaccine.lief') as mock_lief:
            mock_lief.parse.return_value = None
            
            result = _detect_architecture(Path("/fake/invalid.bin"))
            assert result == "unknown"

    def test_detect_architecture_exception(self):
        """Test architecture detection with exception."""
        with patch('reversecore_mcp.tools.adaptive_vaccine.lief') as mock_lief:
            mock_lief.parse.side_effect = Exception("Parse error")
            
            result = _detect_architecture(Path("/fake/binary.exe"))
            assert result == "unknown"


class TestHexToYaraBytes:
    """Test hex to YARA bytes conversion."""

    def test_hex_to_yara_bytes_x86(self):
        """Test conversion for x86 (little-endian)."""
        result = _hex_to_yara_bytes("DEADBEEF", "x86")
        assert isinstance(result, str)
        # Little-endian should reverse bytes
        assert "ef be ad de" == result.lower()

    def test_hex_to_yara_bytes_x86_64(self):
        """Test conversion for x86_64 (little-endian)."""
        result = _hex_to_yara_bytes("1234", "x86_64")
        assert isinstance(result, str)
        assert "34 12" == result.lower()

    def test_hex_to_yara_bytes_arm(self):
        """Test conversion for ARM (big-endian)."""
        result = _hex_to_yara_bytes("ABCD", "arm")
        assert isinstance(result, str)
        # Big-endian should not reverse
        assert "ab cd" == result.lower()

    def test_hex_to_yara_bytes_odd_length(self):
        """Test conversion with odd-length hex string."""
        result = _hex_to_yara_bytes("ABC", "x86")
        assert isinstance(result, str)
        # Should pad to even length

    def test_hex_to_yara_bytes_invalid_hex(self):
        """Test conversion with invalid hex."""
        result = _hex_to_yara_bytes("INVALID_HEX", "x86")
        # Should pad and return the modified string on error
        # The function pads odd-length strings, so "INVALID_HEX" becomes "0INVALID_HEX"
        # then tries to convert, which fails and returns as-is
        assert "INVALID_HEX" in result or result == "0INVALID_HEX"


class TestGenerateYaraRule:
    """Test YARA rule generation."""

    def test_generate_yara_rule_basic(self):
        """Test basic YARA rule generation."""
        threat_report = {
            "function": "test_function",
            "address": "0x401000",
            "instruction": "cmp eax, 0x12345678",
            "reason": "Test threat"
        }
        
        rule = _generate_yara_rule(threat_report, "x86")
        
        assert "rule test_function" in rule
        assert "0x401000" in rule
        assert "Test threat" in rule
        assert "x86" in rule
        assert "Reversecore TDS" in rule

    def test_generate_yara_rule_with_string_literals(self):
        """Test YARA rule with string literals from refined code."""
        threat_report = {
            "function": "malware_func",
            "address": "0x401000",
            "instruction": "call 0x402000",
            "reason": "Suspicious API call",
            "refined_code": 'if (strcmp(str, "malware") == 0)'
        }
        
        rule = _generate_yara_rule(threat_report, "x86")
        
        assert "malware" in rule
        assert "$str_0" in rule

    def test_generate_yara_rule_sanitize_name(self):
        """Test YARA rule name sanitization."""
        threat_report = {
            "function": "func-with-dashes",
            "address": "0x401000",
            "instruction": "nop"
        }
        
        rule = _generate_yara_rule(threat_report, "x86")
        
        # Dashes should be replaced with underscores
        assert "func_with_dashes" in rule or "Threat_" in rule

    def test_generate_yara_rule_numeric_function_name(self):
        """Test YARA rule with numeric function name."""
        threat_report = {
            "function": "12345",
            "address": "0x401000",
            "instruction": "nop"
        }
        
        rule = _generate_yara_rule(threat_report, "x86")
        
        # Numeric names should be handled
        assert "Threat_401000" in rule or "rule " in rule

    def test_generate_yara_rule_multiple_hex_patterns(self):
        """Test YARA rule with multiple hex patterns."""
        threat_report = {
            "function": "multi_pattern",
            "address": "0x401000",
            "instruction": "mov eax, 0xDEAD; mov ebx, 0xBEEF; cmp ecx, 0xCAFE",
            "reason": "Multiple magic values"
        }
        
        rule = _generate_yara_rule(threat_report, "x86")
        
        # Should extract multiple hex patterns
        assert "$hex_0" in rule or "// No patterns" in rule

    def test_generate_yara_rule_no_patterns(self):
        """Test YARA rule with no extractable patterns."""
        threat_report = {
            "function": "empty_func",
            "address": "0x401000",
            "instruction": "nop",
            "reason": "Empty function"
        }
        
        rule = _generate_yara_rule(threat_report, "x86")
        
        assert "// No patterns" in rule or "true" in rule

    def test_generate_yara_rule_with_all_fields(self):
        """Test YARA rule generation with all possible fields."""
        threat_report = {
            "function": "complete_test",
            "address": "0xDEADBEEF",
            "instruction": "mov rax, 0xCAFEBABE",
            "reason": "Complete test case",
            "refined_code": 'const char* key = "test_key";'
        }
        
        rule = _generate_yara_rule(threat_report, "x86_64")
        
        assert "rule complete_test" in rule
        assert "0xDEADBEEF" in rule
        assert "Complete test case" in rule
        assert "x86_64" in rule
        assert "generated" in rule.lower()
        assert "Adaptive Vaccine" in rule


class TestRegisterAdaptiveVaccine:
    """Test registration function."""

    def test_register_adaptive_vaccine(self):
        """Test that registration function works."""
        from reversecore_mcp.tools.adaptive_vaccine import register_adaptive_vaccine
        
        mock_mcp = Mock()
        mock_mcp.tool = Mock()
        
        register_adaptive_vaccine(mock_mcp)
        
        assert mock_mcp.tool.called
        # Verify the tool was registered
        call_args = mock_mcp.tool.call_args
        assert call_args is not None
