"""
Unit tests for core.validators module.
"""

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.validators import (
    _validate_capstone_params,
    _validate_cfg_params,
    _validate_diff_binaries_params,
    _validate_emulation_params,
    _validate_match_libraries_params,
    _validate_pseudo_code_params,
    _validate_radare2_params,
    _validate_rtti_params,
    _validate_signature_params,
    _validate_strings_params,
    _validate_yara_params,
    validate_tool_parameters,
)


class TestValidateToolParameters:
    """Test suite for validate_tool_parameters function."""

    def test_validate_tool_parameters_unknown_tool(self):
        """Test that unknown tools don't raise errors."""
        # Should not raise for unknown tool
        validate_tool_parameters("unknown_tool", {})

    def test_validate_tool_parameters_dispatches_correctly(self):
        """Test that correct validator is called for each tool."""
        # Should call _validate_strings_params
        with pytest.raises(ValidationError, match="min_length"):
            validate_tool_parameters("run_strings", {"min_length": -1})

        # Should call _validate_radare2_params
        with pytest.raises(ValidationError, match="r2_command"):
            validate_tool_parameters("run_radare2", {})

        # Should call _validate_yara_params
        with pytest.raises(ValidationError, match="rule_file"):
            validate_tool_parameters("run_yara", {})


class TestValidateStringsParams:
    """Test suite for _validate_strings_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_strings_params({"min_length": 4, "max_output_size": 10000000})
        _validate_strings_params({"min_length": 1})
        _validate_strings_params({"max_output_size": 1000})
        _validate_strings_params({})  # defaults

    def test_invalid_min_length_type(self):
        """Test invalid min_length type."""
        with pytest.raises(ValidationError, match="min_length must be a positive integer"):
            _validate_strings_params({"min_length": "four"})

    def test_invalid_min_length_value(self):
        """Test invalid min_length value."""
        with pytest.raises(ValidationError, match="min_length must be a positive integer"):
            _validate_strings_params({"min_length": 0})

        with pytest.raises(ValidationError, match="min_length must be a positive integer"):
            _validate_strings_params({"min_length": -5})

    def test_invalid_max_output_size_type(self):
        """Test invalid max_output_size type."""
        with pytest.raises(ValidationError, match="max_output_size must be a positive integer"):
            _validate_strings_params({"max_output_size": "large"})

    def test_invalid_max_output_size_value(self):
        """Test invalid max_output_size value."""
        with pytest.raises(ValidationError, match="max_output_size must be a positive integer"):
            _validate_strings_params({"max_output_size": 0})

        with pytest.raises(ValidationError, match="max_output_size must be a positive integer"):
            _validate_strings_params({"max_output_size": -100})


class TestValidateRadare2Params:
    """Test suite for _validate_radare2_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_radare2_params({"r2_command": "pdf"})
        _validate_radare2_params({"r2_command": "afl"})

    def test_missing_r2_command(self):
        """Test missing r2_command."""
        with pytest.raises(ValidationError, match="r2_command is required"):
            _validate_radare2_params({})

    def test_invalid_r2_command_type(self):
        """Test invalid r2_command type."""
        with pytest.raises(ValidationError, match="r2_command must be a string"):
            _validate_radare2_params({"r2_command": 123})

        with pytest.raises(ValidationError, match="r2_command must be a string"):
            _validate_radare2_params({"r2_command": ["pdf"]})


class TestValidateCapstoneParams:
    """Test suite for _validate_capstone_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_capstone_params({"offset": 0, "size": 1024})
        _validate_capstone_params({"offset": 100, "size": 500})
        _validate_capstone_params({})  # defaults

    def test_invalid_offset_type(self):
        """Test invalid offset type."""
        with pytest.raises(ValidationError, match="offset must be a non-negative integer"):
            _validate_capstone_params({"offset": "zero"})

    def test_invalid_offset_value(self):
        """Test invalid offset value."""
        with pytest.raises(ValidationError, match="offset must be a non-negative integer"):
            _validate_capstone_params({"offset": -1})

    def test_invalid_size_type(self):
        """Test invalid size type."""
        with pytest.raises(ValidationError, match="size must be a positive integer"):
            _validate_capstone_params({"size": "large"})

    def test_invalid_size_value(self):
        """Test invalid size value."""
        with pytest.raises(ValidationError, match="size must be a positive integer"):
            _validate_capstone_params({"size": 0})

        with pytest.raises(ValidationError, match="size must be a positive integer"):
            _validate_capstone_params({"size": -100})


class TestValidateYaraParams:
    """Test suite for _validate_yara_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_yara_params({"rule_file": "rules.yar", "timeout": 300})
        _validate_yara_params({"rule_file": "test.yara", "timeout": 60})

    def test_missing_rule_file(self):
        """Test missing rule_file."""
        with pytest.raises(ValidationError, match="rule_file is required"):
            _validate_yara_params({})

        with pytest.raises(ValidationError, match="rule_file is required"):
            _validate_yara_params({"timeout": 60})

    def test_invalid_timeout_type(self):
        """Test invalid timeout type."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_yara_params({"rule_file": "test.yar", "timeout": "long"})

    def test_invalid_timeout_value(self):
        """Test invalid timeout value."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_yara_params({"rule_file": "test.yar", "timeout": 0})

        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_yara_params({"rule_file": "test.yar", "timeout": -30})


class TestValidateCfgParams:
    """Test suite for _validate_cfg_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_cfg_params({"function_address": "main", "format": "mermaid"})
        _validate_cfg_params({"function_address": "0x401000", "format": "json"})
        _validate_cfg_params({"format": "dot"})
        _validate_cfg_params({})  # defaults

    def test_invalid_function_address_type(self):
        """Test invalid function_address type."""
        with pytest.raises(ValidationError, match="function_address must be a string"):
            _validate_cfg_params({"function_address": 12345})

    def test_invalid_format(self):
        """Test invalid format."""
        with pytest.raises(ValidationError, match="Invalid format"):
            _validate_cfg_params({"format": "xml"})

        with pytest.raises(ValidationError, match="Invalid format"):
            _validate_cfg_params({"format": "yaml"})


class TestValidateEmulationParams:
    """Test suite for _validate_emulation_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_emulation_params({"start_address": "0x401000", "instructions": 50})
        _validate_emulation_params({"start_address": "main", "instructions": 1})
        _validate_emulation_params({"start_address": "entry", "instructions": 1000})
        _validate_emulation_params({})  # defaults

    def test_invalid_start_address_type(self):
        """Test invalid start_address type."""
        with pytest.raises(ValidationError, match="start_address must be a string"):
            _validate_emulation_params({"start_address": 0x401000})

    def test_invalid_instructions_type(self):
        """Test invalid instructions type."""
        with pytest.raises(ValidationError, match="instructions must be an integer"):
            _validate_emulation_params({"instructions": "fifty"})

    def test_invalid_instructions_too_low(self):
        """Test instructions value too low."""
        with pytest.raises(ValidationError, match="instructions must be at least 1"):
            _validate_emulation_params({"instructions": 0})

        with pytest.raises(ValidationError, match="instructions must be at least 1"):
            _validate_emulation_params({"instructions": -10})

    def test_invalid_instructions_too_high(self):
        """Test instructions value too high."""
        with pytest.raises(ValidationError, match="instructions cannot exceed 1000"):
            _validate_emulation_params({"instructions": 1001})

        with pytest.raises(ValidationError, match="instructions cannot exceed 1000"):
            _validate_emulation_params({"instructions": 10000})


class TestValidatePseudoCodeParams:
    """Test suite for _validate_pseudo_code_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_pseudo_code_params({"address": "main", "timeout": 300})
        _validate_pseudo_code_params({"address": "0x401000", "timeout": 60})
        _validate_pseudo_code_params({})  # defaults

    def test_invalid_address_type(self):
        """Test invalid address type."""
        with pytest.raises(ValidationError, match="address must be a string"):
            _validate_pseudo_code_params({"address": 12345})

    def test_invalid_timeout_type(self):
        """Test invalid timeout type."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_pseudo_code_params({"timeout": "long"})

    def test_invalid_timeout_value(self):
        """Test invalid timeout value."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_pseudo_code_params({"timeout": 0})

        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_pseudo_code_params({"timeout": -60})


class TestValidateSignatureParams:
    """Test suite for _validate_signature_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_signature_params({"address": "main", "length": 32, "timeout": 300})
        _validate_signature_params({"address": "0x401000", "length": 1, "timeout": 60})
        _validate_signature_params({"address": "entry", "length": 1024})

    def test_missing_address(self):
        """Test missing address."""
        with pytest.raises(ValidationError, match="address is required"):
            _validate_signature_params({})

        with pytest.raises(ValidationError, match="address is required"):
            _validate_signature_params({"length": 32})

    def test_invalid_address_type(self):
        """Test invalid address type."""
        with pytest.raises(ValidationError, match="address must be a string"):
            _validate_signature_params({"address": 12345})

    def test_invalid_length_type(self):
        """Test invalid length type."""
        with pytest.raises(ValidationError, match="length must be between 1 and 1024 bytes"):
            _validate_signature_params({"address": "main", "length": "large"})

    def test_invalid_length_value_too_low(self):
        """Test length value too low."""
        with pytest.raises(ValidationError, match="length must be between 1 and 1024 bytes"):
            _validate_signature_params({"address": "main", "length": 0})

        with pytest.raises(ValidationError, match="length must be between 1 and 1024 bytes"):
            _validate_signature_params({"address": "main", "length": -5})

    def test_invalid_length_value_too_high(self):
        """Test length value too high."""
        with pytest.raises(ValidationError, match="length must be between 1 and 1024 bytes"):
            _validate_signature_params({"address": "main", "length": 1025})

        with pytest.raises(ValidationError, match="length must be between 1 and 1024 bytes"):
            _validate_signature_params({"address": "main", "length": 10000})

    def test_invalid_timeout_type(self):
        """Test invalid timeout type."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_signature_params({"address": "main", "timeout": "long"})

    def test_invalid_timeout_value(self):
        """Test invalid timeout value."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_signature_params({"address": "main", "timeout": 0})


class TestValidateRttiParams:
    """Test suite for _validate_rtti_params function."""

    def test_valid_params(self):
        """Test valid parameters."""
        _validate_rtti_params({"timeout": 300})
        _validate_rtti_params({"timeout": 60})
        _validate_rtti_params({})  # defaults

    def test_invalid_timeout_type(self):
        """Test invalid timeout type."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_rtti_params({"timeout": "long"})

    def test_invalid_timeout_value(self):
        """Test invalid timeout value."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_rtti_params({"timeout": 0})

        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_rtti_params({"timeout": -30})


class TestValidateDiffBinariesParams:
    """Test suite for _validate_diff_binaries_params."""

    def test_valid_params(self):
        """Valid parameters do not raise."""
        _validate_diff_binaries_params({})
        _validate_diff_binaries_params({"function_name": "main"})
        _validate_diff_binaries_params({"max_output_size": 10_000_000, "timeout": 300})

    def test_invalid_function_name_type(self):
        """function_name must be a string."""
        with pytest.raises(ValidationError, match="function_name must be a string"):
            _validate_diff_binaries_params({"function_name": 123})

    def test_invalid_max_output_size(self):
        """max_output_size must be a positive integer."""
        with pytest.raises(ValidationError, match="max_output_size must be a positive integer"):
            _validate_diff_binaries_params({"max_output_size": 0})
        with pytest.raises(ValidationError, match="max_output_size must be a positive integer"):
            _validate_diff_binaries_params({"max_output_size": -1})

    def test_invalid_timeout(self):
        """timeout must be a positive integer."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_diff_binaries_params({"timeout": 0})


class TestValidateMatchLibrariesParams:
    """Test suite for _validate_match_libraries_params."""

    def test_valid_params(self):
        """Valid parameters do not raise."""
        _validate_match_libraries_params({})
        _validate_match_libraries_params({"max_output_size": 5_000_000, "timeout": 60})

    def test_invalid_max_output_size(self):
        """max_output_size must be a positive integer."""
        with pytest.raises(ValidationError, match="max_output_size must be a positive integer"):
            _validate_match_libraries_params({"max_output_size": 0})

    def test_invalid_timeout(self):
        """timeout must be a positive integer."""
        with pytest.raises(ValidationError, match="timeout must be a positive integer"):
            _validate_match_libraries_params({"timeout": -1})


class TestValidateAddressFormat:
    """Test suite for _validate_address_format (internal)."""

    def test_valid_hex_address(self):
        """Should accept valid hex address."""
        from reversecore_mcp.core.validators import validate_address_format

        validate_address_format("0x401000", "address")

    def test_valid_symbol_name(self):
        """Should accept valid symbol name."""
        from reversecore_mcp.core.validators import validate_address_format

        validate_address_format("main", "address")
        validate_address_format("std::string::c_str", "address")

    def test_invalid_characters(self):
        """Should reject addresses with invalid characters."""
        from reversecore_mcp.core.validators import validate_address_format

        with pytest.raises(ValidationError, match="must contain only safe characters"):
            validate_address_format("main; rm -rf /", "address")


class TestValidateDecompileParams:
    """Test suite for _validate_decompile_params."""

    def test_valid_params(self):
        """Valid parameters do not raise."""
        from reversecore_mcp.core.validators import _validate_decompile_params

        _validate_decompile_params({})
        _validate_decompile_params({"function_address": "0x401000"})

    def test_invalid_function_address_type(self):
        """function_address must be a string."""
        from reversecore_mcp.core.validators import _validate_decompile_params

        with pytest.raises(ValidationError, match="function_address must be a string"):
            _validate_decompile_params({"function_address": 12345})


class TestValidateYaraGenerationParams:
    """Test suite for _validate_yara_generation_params."""

    def test_valid_params(self):
        """Valid parameters do not raise."""
        from reversecore_mcp.core.validators import _validate_yara_generation_params

        _validate_yara_generation_params({})
        _validate_yara_generation_params(
            {"function_address": "0x401000", "byte_length": 64, "rule_name": "test_rule"}
        )

    def test_invalid_function_address_type(self):
        """function_address must be a string."""
        from reversecore_mcp.core.validators import _validate_yara_generation_params

        with pytest.raises(ValidationError, match="function_address must be a string"):
            _validate_yara_generation_params({"function_address": 12345})

    def test_invalid_byte_length_type(self):
        """byte_length must be an integer."""
        from reversecore_mcp.core.validators import _validate_yara_generation_params

        with pytest.raises(ValidationError, match="byte_length must be a positive integer"):
            _validate_yara_generation_params({"byte_length": "large"})

    def test_invalid_byte_length_zero(self):
        """byte_length must be positive."""
        from reversecore_mcp.core.validators import _validate_yara_generation_params

        with pytest.raises(ValidationError, match="byte_length must be a positive integer"):
            _validate_yara_generation_params({"byte_length": 0})

    def test_invalid_byte_length_too_large(self):
        """byte_length cannot exceed 1024."""
        from reversecore_mcp.core.validators import _validate_yara_generation_params

        with pytest.raises(ValidationError, match="byte_length cannot exceed 1024"):
            _validate_yara_generation_params({"byte_length": 2048})

    def test_invalid_rule_name_type(self):
        """rule_name must be a string."""
        from reversecore_mcp.core.validators import _validate_yara_generation_params

        with pytest.raises(ValidationError, match="rule_name must be a string"):
            _validate_yara_generation_params({"rule_name": 123})
