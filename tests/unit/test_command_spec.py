"""
Unit tests for command specification and regex-based validation.
"""

import pytest
import re
from reversecore_mcp.core.command_spec import (
    CommandSpec,
    R2_COMMAND_SPECS,
    DANGEROUS_PATTERNS,
    validate_r2_command,
    is_safe_r2_command,
)
from reversecore_mcp.core.exceptions import ValidationError


class TestCommandSpec:
    """Tests for CommandSpec class."""
    
    def test_command_spec_creation(self):
        """Test creating a CommandSpec."""
        spec = CommandSpec(
            name="test",
            type="read",
            regex=re.compile(r'^test$'),
            description="Test command"
        )
        assert spec.name == "test"
        assert spec.type == "read"
        assert spec.description == "Test command"
    
    def test_command_spec_validate_match(self):
        """Test validation with matching command."""
        spec = CommandSpec(
            name="test",
            type="read",
            regex=re.compile(r'^test(\s+\w+)?$')
        )
        assert spec.validate("test") is True
        assert spec.validate("test arg") is True
        assert spec.validate(" test ") is True  # Strips whitespace
    
    def test_command_spec_validate_no_match(self):
        """Test validation with non-matching command."""
        spec = CommandSpec(
            name="test",
            type="read",
            regex=re.compile(r'^test$')
        )
        assert spec.validate("test arg") is False
        assert spec.validate("other") is False


class TestR2CommandSpecs:
    """Tests for radare2 command specifications."""
    
    def test_pdf_command_patterns(self):
        """Test pdf command pattern matching."""
        # Find pdf spec
        pdf_spec = next(s for s in R2_COMMAND_SPECS if s.name == "pdf")
        
        # Valid patterns
        assert pdf_spec.validate("pdf") is True
        assert pdf_spec.validate("pdf @ main") is True
        assert pdf_spec.validate("pdf @ sym.main") is True
        assert pdf_spec.validate("pdf @ func_0x1234") is True
        
        # Invalid patterns
        assert pdf_spec.validate("pdf @ main; w hello") is False
        assert pdf_spec.validate("pdf && ls") is False
        assert pdf_spec.validate("pdf | grep") is False
    
    def test_afl_command_patterns(self):
        """Test afl command pattern matching."""
        afl_spec = next(s for s in R2_COMMAND_SPECS if s.name == "afl")
        
        assert afl_spec.validate("afl") is True
        assert afl_spec.validate("aflj") is True
        assert afl_spec.validate("afl -h") is False  # No args allowed
        
        # Test ~ filter support
        assert afl_spec.validate("afl~entry") is True
        assert afl_spec.validate("afl ~entry") is True
        assert afl_spec.validate("aflj~main") is True
    
    def test_px_command_patterns(self):
        """Test px hexdump command patterns."""
        px_spec = next(s for s in R2_COMMAND_SPECS if s.name == "px")
        
        # Valid patterns
        assert px_spec.validate("px") is True
        assert px_spec.validate("px 16") is True
        assert px_spec.validate("px @ 0x1000") is True
        assert px_spec.validate("px 32 @ main") is True
        assert px_spec.validate("pxw") is True
        assert px_spec.validate("pxq 64") is True
        
        # Invalid patterns
        assert px_spec.validate("px -99") is False  # Negative numbers
        assert px_spec.validate("px $(cmd)") is False


class TestDangerousPatterns:
    """Tests for dangerous pattern detection."""
    
    def test_semicolon_chaining(self):
        """Test detection of semicolon command chaining."""
        pattern = next(p for p in DANGEROUS_PATTERNS if ';' in p.pattern)
        
        assert pattern.search("pdf; w hello") is not None
        assert pattern.search("pdf @ main ; w") is not None
        assert pattern.search("pdf;w") is not None
    
    def test_pipe_detection(self):
        """Test detection of pipe to other commands."""
        pattern = next(p for p in DANGEROUS_PATTERNS if '\\|' in p.pattern and '&&' not in p.pattern)
        
        assert pattern.search("pdf | grep") is not None
        assert pattern.search("afl|wc") is not None
    
    def test_command_substitution(self):
        """Test detection of command substitution."""
        backtick_pattern = next(p for p in DANGEROUS_PATTERNS if '`' in p.pattern)
        dollar_pattern = next(p for p in DANGEROUS_PATTERNS if r'\$\(' in p.pattern)
        
        assert backtick_pattern.search("`whoami`") is not None
        assert dollar_pattern.search("$(ls)") is not None
    
    def test_logical_operators(self):
        """Test detection of logical operators for chaining."""
        and_pattern = next(p for p in DANGEROUS_PATTERNS if '&&' in p.pattern)
        or_pattern = next(p for p in DANGEROUS_PATTERNS if r'\|\|' in p.pattern)
        
        assert and_pattern.search("pdf && echo") is not None
        assert or_pattern.search("pdf || echo") is not None
    
    def test_write_commands(self):
        """Test detection of write commands."""
        write_pattern = next(p for p in DANGEROUS_PATTERNS if '^w' in p.pattern)
        
        assert write_pattern.search("w hello") is not None
        assert write_pattern.search("wx 90") is not None
        assert write_pattern.search("wo +") is not None
    
    def test_system_commands(self):
        """Test detection of system command execution."""
        system_pattern = next(p for p in DANGEROUS_PATTERNS if '^!' in p.pattern)
        
        assert system_pattern.search("!ls") is not None
        assert system_pattern.search("!whoami") is not None


class TestValidateR2Command:
    """Tests for validate_r2_command function."""
    
    def test_valid_read_commands(self):
        """Test validation of valid read commands."""
        # Should not raise
        validate_r2_command("pdf @ main")
        validate_r2_command("afl")
        validate_r2_command("aflj")
        validate_r2_command("iS")
        validate_r2_command("iz")
        validate_r2_command("px 16")
        validate_r2_command("ii")
    
    def test_agfj_graph_command_validation(self):
        """Test agfj (graph JSON) command validation."""
        # Valid agfj commands - should not raise
        validate_r2_command("agfj")
        validate_r2_command("agfj @ main")
        validate_r2_command("agfj @ sym.main")
        validate_r2_command("agfj @ 0x401000")
        validate_r2_command("agfj @ entry0")
    
    def test_agfj_invalid_patterns(self):
        """Test that agfj blocks dangerous patterns."""
        # Should block command injection attempts
        with pytest.raises(ValidationError):
            validate_r2_command("agfj; w hello")
        
        with pytest.raises(ValidationError):
            validate_r2_command("agfj | grep test")
        
        with pytest.raises(ValidationError):
            validate_r2_command("agfj && ls")
        
        with pytest.raises(ValidationError):
            validate_r2_command("agfj @ main; rm -rf /")
    
    def test_empty_command_rejected(self):
        """Test that empty commands are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("")
        assert "cannot be empty" in str(exc_info.value)
        
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("   ")
        assert "cannot be empty" in str(exc_info.value)
    
    def test_command_injection_blocked(self):
        """Test that command injection attempts are blocked."""
        # Semicolon chaining
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("pdf @ main; w hello")
        assert "Dangerous command pattern" in str(exc_info.value)
        
        # Pipe to other command
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("pdf | grep")
        assert "Dangerous command pattern" in str(exc_info.value)
        
        # Logical AND
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("pdf && echo")
        assert "Dangerous command pattern" in str(exc_info.value)
        
        # Command substitution
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("pdf `whoami`")
        assert "Dangerous command pattern" in str(exc_info.value)
        
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("pdf $(ls)")
        assert "Dangerous command pattern" in str(exc_info.value)
    
    def test_write_commands_blocked_by_default(self):
        """Test that write commands are blocked by default."""
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("w hello")
        assert "Dangerous command pattern" in str(exc_info.value)
    
    def test_system_commands_blocked(self):
        """Test that system commands are blocked."""
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("!ls")
        assert "Dangerous command pattern" in str(exc_info.value)
        
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("#!python")
        assert "Dangerous command pattern" in str(exc_info.value)
    
    def test_unknown_command_rejected(self):
        """Test that unknown commands are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("unknown_command")
        assert "not in allowlist" in str(exc_info.value)
    
    def test_command_with_invalid_arguments(self):
        """Test that commands with invalid arguments are rejected."""
        # pdf doesn't accept numeric arguments
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("pdf 123")
        assert "not in allowlist" in str(exc_info.value)
    
    def test_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        # Should work with leading/trailing whitespace
        validated = validate_r2_command("  pdf @ main  ")
        assert validated == "pdf @ main"
    
    def test_case_sensitivity(self):
        """Test case sensitivity of validation."""
        # Commands are case-sensitive in radare2
        validate_r2_command("pdf")  # Should work
        
        # Uppercase should not match (commands are lowercase)
        with pytest.raises(ValidationError):
            validate_r2_command("PDF")
    
    def test_returns_validated_command_string(self):
        """Test that validation returns the sanitized command string."""
        validated_pdf = validate_r2_command("pdf @ main")
        assert validated_pdf == "pdf @ main"

        validated_analyze = validate_r2_command("aaa")
        assert validated_analyze == "aaa"


class TestIsSafeR2Command:
    """Tests for is_safe_r2_command helper function."""
    
    def test_safe_commands_return_true(self):
        """Test that safe commands return True."""
        assert is_safe_r2_command("pdf @ main") is True
        assert is_safe_r2_command("afl") is True
        assert is_safe_r2_command("iS") is True
    
    def test_dangerous_commands_return_false(self):
        """Test that dangerous commands return False."""
        assert is_safe_r2_command("pdf; w hello") is False
        assert is_safe_r2_command("!ls") is False
        assert is_safe_r2_command("unknown") is False
        assert is_safe_r2_command("") is False


class TestSecurityRegressions:
    """Tests for specific security vulnerabilities mentioned in the problem statement."""
    
    def test_pdf_semicolon_bypass_blocked(self):
        """
        Test that the vulnerability "pdf @ main; w hello" is blocked.
        
        This was the specific example in the problem statement where
        the old implementation would pass because it only checked if
        the command started with "pdf @".
        """
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("pdf @ main; w hello")
        assert "Dangerous command pattern" in str(exc_info.value)
        assert ";" in str(exc_info.value) or "chaining" in str(exc_info.value).lower()
    
    def test_pdf_at_symbol_variations(self):
        """Test various @ symbol usages in pdf command."""
        # Valid uses
        validate_r2_command("pdf @ main")
        validate_r2_command("pdf @ sym.main")
        validate_r2_command("pdf @ 0x1000")
        
        # Invalid - multiple @ symbols or invalid syntax
        with pytest.raises(ValidationError):
            validate_r2_command("pdf @ @ main")
        
        with pytest.raises(ValidationError):
            validate_r2_command("pdf @main ; w")
    
    def test_allowlist_bypass_attempts(self):
        """Test various attempts to bypass the allowlist."""
        bypass_attempts = [
            "pdf@ main;w hello",  # No space before @
            "pdf @main;w hello",  # No space after @
            "pdf@main;w hello",   # No spaces around @
            "pdf @ main ;w",      # Space before semicolon
            "pdf @ main; w",      # Space after semicolon
            "pdf @ main;w",       # No spaces around semicolon
        ]
        
        for attempt in bypass_attempts:
            with pytest.raises(ValidationError) as exc_info:
                validate_r2_command(attempt)
            # Should be caught by either dangerous pattern or regex mismatch
            assert "Dangerous" in str(exc_info.value) or "not in allowlist" in str(exc_info.value)


class TestRadare2InternalFilter:
    """Tests for radare2 internal filter (~) support."""
    
    def test_afl_with_tilde_filter(self):
        """Test that afl~entry pattern works (from problem statement)."""
        # This was the specific command mentioned in the problem statement
        validated = validate_r2_command("afl~entry")
        assert validated == "afl~entry"
        
        # Also test with space
        validated = validate_r2_command("afl ~entry")
        assert validated == "afl ~entry"
    
    def test_various_commands_with_tilde_filter(self):
        """Test ~ filter on various commands."""
        # These should all pass
        test_cases = [
            "afl~main",
            "afl ~main",
            "aflj~sym",
            "iz~http",
            "iz ~http",
            "ii~kernel",
            "iS~.text",
            "pdf @ main~mov",
            "pd 10 @ 0x1000~call",
        ]
        
        for cmd in test_cases:
            validated = validate_r2_command(cmd)
            assert validated == cmd.strip()
    
    def test_tilde_filter_does_not_bypass_dangerous_patterns(self):
        """Test that ~ filter doesn't allow dangerous patterns."""
        # Pipe should still be blocked even with ~
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("afl | grep main")
        assert "Dangerous" in str(exc_info.value)
        
        # Semicolon should still be blocked
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("afl~entry; w hello")
        assert "Dangerous" in str(exc_info.value)
        
        # Command substitution should still be blocked
        with pytest.raises(ValidationError) as exc_info:
            validate_r2_command("afl~$(whoami)")
        assert "Dangerous" in str(exc_info.value)
    
    def test_tilde_filter_with_complex_patterns(self):
        """Test ~ filter with more complex filter patterns."""
        # Radare2 supports various filter patterns
        test_cases = [
            "afl~[0]",           # Column filter
            "afl~:0",            # Row filter
            "afl~main[0]",       # Combined filter
            "iz~http:10",        # Filter + row limit
            "ii~kernel32.dll",   # Filter with dots
        ]
        
        for cmd in test_cases:
            validated = validate_r2_command(cmd)
            assert validated == cmd.strip()

