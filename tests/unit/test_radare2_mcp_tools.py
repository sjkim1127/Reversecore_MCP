"""Unit tests for Radare2 MCP tools module (security-hardened)."""

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.radare2.radare2_mcp_tools import (
    Radare2ToolsPlugin,
    R2Session,
    _filter_lines_by_regex,
    _filter_named_functions,
    _paginate_text,
    _validate_identifier,
    _validate_expression,
    _validate_r2_command,
    _sanitize_for_r2_cmd,
)


class TestSecurityValidators:
    """Tests for security validation functions."""

    def test_validate_identifier_valid(self):
        """Valid identifiers should pass."""
        _validate_identifier("main", "test")
        _validate_identifier("MyClass", "test")
        _validate_identifier("_private_func", "test")
        _validate_identifier("sym.main", "test")
        _validate_identifier("func_123", "test")

    def test_validate_identifier_injection_attempt(self):
        """Injection attempts should be blocked."""
        with pytest.raises(ValidationError):
            _validate_identifier("main; rm -rf /", "test")

        with pytest.raises(ValidationError):
            _validate_identifier("foo`whoami`", "test")

        with pytest.raises(ValidationError):
            _validate_identifier("$(cat /etc/passwd)", "test")

    def test_validate_identifier_empty(self):
        """Empty identifiers should fail."""
        with pytest.raises(ValidationError):
            _validate_identifier("", "test")

    def test_validate_expression_valid(self):
        """Valid expressions should pass."""
        _validate_expression("0x401000")
        _validate_expression("sym.main + 0x10")
        _validate_expression("0x100 - 4 * 2")
        _validate_expression("(sym.func + 0x20) / 8")

    def test_validate_expression_injection_attempt(self):
        """Shell injection in expressions should be blocked."""
        with pytest.raises(ValidationError):
            _validate_expression("0x100; !rm -rf /")

        with pytest.raises(ValidationError):
            _validate_expression("`cat /etc/passwd`")

        with pytest.raises(ValidationError):
            _validate_expression("$HOME")

        with pytest.raises(ValidationError):
            _validate_expression("0x100 | grep")

    def test_validate_r2_command_safe_commands(self):
        """Safe r2 commands should pass."""
        _validate_r2_command("afl")
        _validate_r2_command("pdf @ main")
        _validate_r2_command("iz")
        _validate_r2_command("ii")
        _validate_r2_command("axt @ 0x401000")

    def test_validate_r2_command_blocked_shell(self):
        """Shell escape commands should be blocked."""
        with pytest.raises(ValidationError):
            _validate_r2_command("!ls -la")

        with pytest.raises(ValidationError):
            _validate_r2_command("#!pipe cat /etc/passwd")

    def test_validate_r2_command_blocked_write(self):
        """Write commands should be blocked."""
        with pytest.raises(ValidationError):
            _validate_r2_command("w hello")

        with pytest.raises(ValidationError):
            _validate_r2_command("wa mov eax, 0")

    def test_validate_r2_command_blocked_metacharacters(self):
        """Commands with shell metacharacters should be blocked."""
        with pytest.raises(ValidationError):
            _validate_r2_command("afl | grep main")

        with pytest.raises(ValidationError):
            _validate_r2_command("pdf & whoami")

        with pytest.raises(ValidationError):
            _validate_r2_command("ii > /tmp/out")

    def test_sanitize_removes_dangerous_chars(self):
        """Sanitize should remove dangerous shell characters."""
        assert _sanitize_for_r2_cmd("hello`world") == "helloworld"
        assert _sanitize_for_r2_cmd("foo;bar") == "foobar"
        assert _sanitize_for_r2_cmd("test$var") == "testvar"
        assert _sanitize_for_r2_cmd("a|b&c") == "abc"
        assert _sanitize_for_r2_cmd('say "hi"') == "say hi"


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_filter_lines_by_regex_basic(self):
        """Should filter lines matching pattern."""
        text = "func_main\nfunc_helper\nother_stuff"
        result = _filter_lines_by_regex(text, "func_")
        assert "func_main" in result
        assert "func_helper" in result
        assert "other_stuff" not in result

    def test_filter_lines_by_regex_empty_pattern(self):
        """Empty pattern should return original text."""
        text = "some text"
        result = _filter_lines_by_regex(text, "")
        assert result == text

    def test_filter_lines_by_regex_invalid(self):
        """Invalid regex should return error message."""
        result = _filter_lines_by_regex("text", "[invalid")
        assert "Invalid regex" in result

    def test_filter_lines_by_regex_too_long(self):
        """Very long regex should be rejected (ReDoS protection)."""
        long_pattern = "a" * 600
        result = _filter_lines_by_regex("text", long_pattern)
        assert "too long" in result

    def test_filter_named_functions(self):
        """Should filter out functions with numeric suffixes."""
        text = "sym.main\nsym.func.1000016c8\nsym.helper"
        result = _filter_named_functions(text)
        assert "sym.main" in result
        assert "sym.helper" in result
        assert "1000016c8" not in result

    def test_paginate_text_first_page(self):
        """Should return first page of lines."""
        text = "\n".join([f"line{i}" for i in range(10)])
        paginated, has_more, next_cursor = _paginate_text(text, None, 5)

        assert "line0" in paginated
        assert "line4" in paginated
        assert "line5" not in paginated
        assert has_more is True
        assert next_cursor == "5"

    def test_paginate_text_with_cursor(self):
        """Should return page starting at cursor."""
        text = "\n".join([f"line{i}" for i in range(10)])
        paginated, has_more, next_cursor = _paginate_text(text, "5", 5)

        assert "line0" not in paginated
        assert "line5" in paginated
        assert "line9" in paginated
        assert has_more is False
        assert next_cursor is None

    def test_paginate_text_empty(self):
        """Empty text should return empty result."""
        paginated, has_more, next_cursor = _paginate_text("", None, 10)
        assert paginated == ""
        assert has_more is False
        assert next_cursor is None


class TestR2Session:
    """Tests for R2Session class."""

    def test_session_initial_state(self):
        """Session should start closed."""
        session = R2Session()
        assert not session.is_open
        assert session.file_path is None

    def test_session_cmd_when_closed(self):
        """Commands should return empty when session closed."""
        session = R2Session()
        result = session.cmd("i")
        assert result == ""


class TestRadare2ToolsPlugin:
    """Tests for Radare2ToolsPlugin class."""

    def test_plugin_metadata(self):
        """Plugin should have correct metadata."""
        plugin = Radare2ToolsPlugin()
        assert plugin.name == "radare2_mcp_tools"
        assert "Radare2" in plugin.description

    def test_plugin_session_management(self):
        """Plugin should manage sessions dictionary."""
        plugin = Radare2ToolsPlugin()
        assert plugin._sessions == {}
