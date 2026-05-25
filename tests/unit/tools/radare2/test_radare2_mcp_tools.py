"""Unit tests for Radare2 MCP tools module (security-hardened)."""

import os
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.radare2.radare2_mcp_tools import (
    R2Session,
    Radare2ToolsPlugin,
    _filter_lines_by_regex,
    _filter_named_functions,
    _paginate_text,
    _sanitize_for_r2_cmd,
    _validate_expression,
    _validate_identifier,
    _validate_r2_command,
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


class TestDiagnoseError:
    """Tests for _diagnose_error method."""

    def test_diagnose_missing_file(self):
        """Should diagnose missing file correctly."""
        plugin = Radare2ToolsPlugin()
        with patch("os.path.exists", return_value=False):
            with patch("shutil.which", return_value="/usr/bin/radare2"):
                result = plugin._diagnose_error("/fake/path", Exception("failed"))
        assert result["file_exists"] is False
        assert "Check if the file path is correct" in result["hints"][0]
        assert result["r2_available"] is True

    def test_diagnose_directory_instead_of_file(self):
        """Should diagnose directory path."""
        plugin = Radare2ToolsPlugin()
        with patch("os.path.exists", return_value=True):
            with patch("os.path.isfile", return_value=False):
                with patch("os.stat"):
                    result = plugin._diagnose_error("/fake/dir", Exception("failed"))
        assert result["is_file"] is False
        assert "directory" in result["hints"][0].lower()

    def test_diagnose_empty_file(self):
        """Should diagnose empty file."""
        plugin = Radare2ToolsPlugin()
        with patch("os.path.exists", return_value=True):
            with patch("os.path.isfile", return_value=True):
                with patch("os.path.getsize", return_value=0):
                    with patch("os.stat"):
                        result = plugin._diagnose_error("/fake/file", Exception("failed"))
        assert result["file_size"] == 0
        assert "empty" in result["hints"][0].lower()

    def test_diagnose_r2_not_available(self):
        """Should detect when radare2 is not installed."""
        plugin = Radare2ToolsPlugin()
        with patch("shutil.which", return_value=None):
            result = plugin._diagnose_error("/fake/file", Exception("failed"))
        assert result["r2_available"] is False


class TestGetOrCreateSession:
    """Tests for _get_or_create_session with mocked R2Session."""

    @pytest.mark.asyncio
    async def test_creates_new_session(self):
        """Should create a new session when none exists."""
        plugin = Radare2ToolsPlugin()

        def mock_init(self, file_path):
            self.session_id = "test-id-123"
            self.last_error = None

        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", return_value="/app/test.bin"):
            with patch("os.path.exists", return_value=True):
                with patch.object(R2Session, "__init__", side_effect=mock_init, autospec=True):
                    with patch.object(R2Session, "open", return_value=True):
                        with patch.object(R2Session, "cmd", return_value=""):
                            with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
                                result = await plugin._get_or_create_session("/app/test.bin")

        assert result is not None

    @pytest.mark.asyncio
    async def test_returns_existing_open_session(self):
        """Should return existing session if already open."""
        plugin = Radare2ToolsPlugin()
        mock_session = MagicMock()
        mock_session.is_open = True
        plugin._sessions["sid-1"] = mock_session
        plugin._file_to_session["/app/test.bin"] = "sid-1"

        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", return_value="/app/test.bin"):
            result = await plugin._get_or_create_session("/app/test.bin")
        assert result == mock_session

    @pytest.mark.asyncio
    async def test_removes_stale_session(self):
        """Should remove stale session and create new one."""
        plugin = Radare2ToolsPlugin()
        stale = MagicMock()
        stale.is_open = False
        plugin._sessions["sid-1"] = stale
        plugin._file_to_session["/app/test.bin"] = "sid-1"

        def mock_init(self, file_path):
            self.session_id = "test-id-456"
            self.last_error = None

        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", return_value="/app/test.bin"):
            with patch("os.path.exists", return_value=True):
                with patch.object(R2Session, "__init__", side_effect=mock_init, autospec=True):
                    with patch.object(R2Session, "open", return_value=True):
                        with patch("asyncio.to_thread", side_effect=lambda f, *a, **k: f(*a, **k)):
                            result = await plugin._get_or_create_session("/app/test.bin")
        assert "sid-1" not in plugin._sessions

    @pytest.mark.asyncio
    async def test_validation_error_returns_dummy_session(self):
        """Should return dummy session on validation error."""
        plugin = Radare2ToolsPlugin()
        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", side_effect=ValidationError("invalid")):
            result = await plugin._get_or_create_session("../../../etc/passwd")
        assert isinstance(result, R2Session)


class TestMcpToolsMocked:
    """Tests for MCP tool wrappers with fully mocked sessions."""

    @pytest.fixture
    def plugin(self):
        return Radare2ToolsPlugin()

    @pytest.fixture
    def mock_mcp(self):
        """Create a mock MCP that captures registered tools."""
        mcp = MagicMock()
        mcp.tools = {}

        def capture_tool(*args, **kwargs):
            # Handles both @mcp.tool() and @mcp.tool(name="foo")
            if len(args) == 1 and callable(args[0]) and not kwargs:
                func = args[0]
                mcp.tools[func.__name__] = func
                return func
            # Decorator factory mode: return a wrapper that captures
            def decorator(func):
                mcp.tools[func.__name__] = func
                return func
            return decorator

        mcp.tool = capture_tool
        return mcp

    @pytest.fixture
    def registered_plugin(self, plugin, mock_mcp):
        """Register tools and return the plugin with accessible tools."""
        plugin.register(mock_mcp)
        plugin._tools = mock_mcp.tools
        return plugin

    @pytest.fixture
    def mock_session(self):
        """Create a mock R2Session that behaves like an open session."""
        session = MagicMock()
        session.is_open = True
        session.session_id = "mock-sid"
        session._analyzed = False
        return session

    @pytest.mark.asyncio
    async def test_Radare2_open_file_success(self, registered_plugin, mock_session):
        """Radare2_open_file should return success on valid file."""
        plugin = registered_plugin
        plugin._sessions["mock-sid"] = mock_session
        plugin._file_to_session["/app/test.bin"] = "mock-sid"

        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", return_value="/app/test.bin"):
            with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
                tool = plugin._tools["Radare2_open_file"]
                result = await tool("/app/test.bin")

        assert result["status"] == "success"
        assert result["status_code"] == "OPENED"
        assert "session_id" in result

    @pytest.mark.asyncio
    async def test_Radare2_open_file_failure(self, registered_plugin):
        """Radare2_open_file should return error with diagnosis when session fails."""
        plugin = registered_plugin
        failed_session = MagicMock()
        failed_session.is_open = False
        failed_session.last_error = "cannot open file"

        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", return_value="/app/bad.bin"):
            with patch.object(plugin, "_get_or_create_session", return_value=failed_session):
                with patch.object(plugin, "_diagnose_error", return_value={"hints": []}):
                    tool = plugin._tools["Radare2_open_file"]
                    result = await tool("/app/bad.bin")

        assert result["status"] == "error"
        assert result["error_code"] == "R2_OPEN_FAILED"

    @pytest.mark.asyncio
    async def test_Radare2_open_file_invalid_path(self, registered_plugin):
        """Radare2_open_file should reject invalid paths."""
        plugin = registered_plugin
        tool = plugin._tools["Radare2_open_file"]
        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", side_effect=ValidationError("invalid path")):
            result = await tool("../../../etc/passwd")
        assert result["status"] == "error"
        assert result["error_code"] == "INVALID_PATH"

    @pytest.mark.asyncio
    async def test_Radare2_close_file_existing(self, registered_plugin):
        """Radare2_close_file should close existing session."""
        plugin = registered_plugin
        mock_session = MagicMock()
        plugin._sessions["sid-1"] = mock_session
        plugin._file_to_session["/app/test.bin"] = "sid-1"

        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", return_value="/app/test.bin"):
            tool = plugin._tools["Radare2_close_file"]
            result = await tool("/app/test.bin")

        assert result["status"] == "success"
        mock_session.close.assert_called_once()
        assert "sid-1" not in plugin._sessions

    @pytest.mark.asyncio
    async def test_Radare2_close_file_not_open(self, registered_plugin):
        """Radare2_close_file should handle file that was not open."""
        plugin = registered_plugin
        with patch("reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path", return_value="/app/test.bin"):
            tool = plugin._tools["Radare2_close_file"]
            result = await tool("/app/test.bin")
        assert result["status"] == "success"
        assert "not open" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_Radare2_analyze_success(self, registered_plugin, mock_session):
        """Radare2_analyze should run analysis and return function count."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "42"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_analyze"]
            result = await tool("/app/test.bin", level=2)

        assert result["status"] == "success"
        assert result["function_count"] == 42
        mock_session.cmd.assert_called_with("aflc")

    @pytest.mark.asyncio
    async def test_Radare2_analyze_invalid_level(self, registered_plugin):
        """Radare2_analyze should reject invalid level values."""
        plugin = registered_plugin
        tool = plugin._tools["Radare2_analyze"]
        result = await tool("/app/test.bin", level=10)
        assert result["status"] == "error"
        assert "level must be 0-4" in result["message"]

    @pytest.mark.asyncio
    async def test_Radare2_analyze_session_closed(self, registered_plugin):
        """Radare2_analyze should fail if session not open."""
        plugin = registered_plugin
        closed = MagicMock()
        closed.is_open = False

        with patch.object(plugin, "_get_or_create_session", return_value=closed):
            tool = plugin._tools["Radare2_analyze"]
            result = await tool("/app/test.bin")
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_Radare2_run_command_success(self, registered_plugin, mock_session):
        """Radare2_run_command should execute and return output."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "analysis output"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_run_command"]
            result = await tool("/app/test.bin", command="afl")

        assert result["status"] == "success"
        assert result["output"] == "analysis output"

    @pytest.mark.asyncio
    async def test_Radare2_run_command_blocked(self, registered_plugin):
        """Radare2_run_command should block dangerous commands."""
        plugin = registered_plugin
        tool = plugin._tools["Radare2_run_command"]
        result = await tool("/app/test.bin", command="!rm -rf /")
        assert result["status"] == "error"
        assert "blocked" in result["message"].lower() or "invalid" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_Radare2_calculate_success(self, registered_plugin, mock_session):
        """Radare2_calculate should evaluate expression."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "0x104"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_calculate"]
            result = await tool("/app/test.bin", expression="0x100 + 4")

        assert result["status"] == "success"
        assert result["result"] == "0x104"

    @pytest.mark.asyncio
    async def test_Radare2_calculate_invalid_expression(self, registered_plugin):
        """Radare2_calculate should reject invalid expressions."""
        plugin = registered_plugin
        tool = plugin._tools["Radare2_calculate"]
        result = await tool("/app/test.bin", expression="`whoami`")
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_Radare2_list_functions_success(self, registered_plugin, mock_session):
        """Radare2_list_functions should return function list."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "0x401000  main\n0x401020  helper"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_list_functions"]
            result = await tool("/app/test.bin")

        assert result["status"] == "success"
        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_Radare2_list_functions_with_filter(self, registered_plugin, mock_session):
        """Radare2_list_functions should apply regex filter."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "0x401000  main\n0x401020  helper"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_list_functions"]
            result = await tool("/app/test.bin", filter="main")

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_Radare2_show_headers_success(self, registered_plugin, mock_session):
        """Radare2_show_headers should return binary info and headers."""
        plugin = registered_plugin
        mock_session.cmd.side_effect = ["info output", "headers output"]

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_show_headers"]
            result = await tool("/app/test.bin")

        assert result["status"] == "success"
        assert "info" in result
        assert "headers" in result

    @pytest.mark.asyncio
    async def test_Radare2_list_sections_success(self, registered_plugin, mock_session):
        """Radare2_list_sections should return sections and segments."""
        plugin = registered_plugin
        mock_session.cmd.side_effect = [".text\n.data", " segments"]

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_list_sections"]
            result = await tool("/app/test.bin")

        assert result["status"] == "success"
        assert "sections" in result
        assert "segments" in result

    @pytest.mark.asyncio
    async def test_Radare2_list_imports_success(self, registered_plugin, mock_session):
        """Radare2_list_imports should return import list."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "sym.imp.printf\nsym.imp.malloc"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_list_imports"]
            result = await tool("/app/test.bin")

        assert result["status"] == "success"
        assert "imports" in result

    @pytest.mark.asyncio
    async def test_Radare2_get_current_address_success(self, registered_plugin, mock_session):
        """Radare2_get_current_address should return address and function."""
        plugin = registered_plugin
        mock_session.cmd.side_effect = ["0x401000", "sym.main"]

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_get_current_address"]
            result = await tool("/app/test.bin")

        assert result["status"] == "success"
        assert result["address"] == "0x401000"
        assert result["function"] == "sym.main"

    @pytest.mark.asyncio
    async def test_Radare2_show_function_details_with_address(self, registered_plugin, mock_session):
        """Radare2_show_function_details should use provided address."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "function details"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_show_function_details"]
            result = await tool("/app/test.bin", address="0x401000")

        assert result["status"] == "success"
        assert result["output"] == "function details"

    @pytest.mark.asyncio
    async def test_Radare2_show_function_details_invalid_address(self, registered_plugin):
        """Radare2_show_function_details should reject invalid address."""
        plugin = registered_plugin
        tool = plugin._tools["Radare2_show_function_details"]
        result = await tool("/app/test.bin", address="invalid")
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_Radare2_get_function_prototype_success(self, registered_plugin, mock_session):
        """Radare2_get_function_prototype should return function signature."""
        plugin = registered_plugin
        mock_session.cmd.return_value = "int main(int argc, char **argv)"

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_get_function_prototype"]
            result = await tool("/app/test.bin", address="0x401000")

        assert result["status"] == "success"
        assert "prototype" in result

    @pytest.mark.asyncio
    async def test_Radare2_set_function_prototype_success(self, registered_plugin, mock_session):
        """Radare2_set_function_prototype should set and confirm."""
        plugin = registered_plugin

        with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
            tool = plugin._tools["Radare2_set_function_prototype"]
            result = await tool("/app/test.bin", address="0x401000", prototype="void foo()")

        assert result["status"] == "success"
        mock_session.cmd.assert_called()

    @pytest.mark.asyncio
    async def test_Radare2_set_function_prototype_empty(self, registered_plugin):
        """Radare2_set_function_prototype should reject empty prototype after sanitization."""
        plugin = registered_plugin
        tool = plugin._tools["Radare2_set_function_prototype"]
        result = await tool("/app/test.bin", address="0x401000", prototype="``")
        assert result["status"] == "error"
