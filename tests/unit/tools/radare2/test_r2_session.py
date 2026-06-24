"""Unit tests for R2Session and r2_session utilities."""

from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.radare2.r2_session import (
    R2Session,
    _compile_regex_cached,
    _filter_lines_by_regex,
    _filter_named_functions,
    _paginate_text,
    _sanitize_for_r2_cmd,
    _validate_expression,
    _validate_identifier,
    _validate_r2_command,
)


class TestValidateIdentifier:
    """Tests for _validate_identifier."""

    def test_valid_hex_address(self):
        """Should accept hex-like identifiers without 0x prefix."""
        _validate_identifier("sym_401000", "address")

    def test_valid_symbol(self):
        """Should accept symbol names."""
        _validate_identifier("sym.main", "symbol")

    def test_valid_function_name(self):
        """Should accept C function names."""
        _validate_identifier("main", "func")

    def test_invalid_semicolon(self):
        """Should reject semicolon injection."""
        with pytest.raises(Exception):
            _validate_identifier("main; rm -rf /", "address")

    def test_invalid_backtick(self):
        """Should reject backtick injection."""
        with pytest.raises(Exception):
            _validate_identifier("`whoami`", "address")

    def test_invalid_dollar(self):
        """Should reject dollar sign."""
        with pytest.raises(Exception):
            _validate_identifier("$HOME", "address")

    def test_empty_identifier(self):
        """Should reject empty identifier."""
        with pytest.raises(Exception):
            _validate_identifier("", "name")


class TestValidateExpression:
    """Tests for _validate_expression."""

    def test_valid_math(self):
        """Should accept simple math."""
        _validate_expression("1 + 2")

    def test_valid_hex(self):
        """Should accept hex values."""
        _validate_expression("0x1000 + 0x200")

    def test_invalid_forbidden_chars(self):
        """Should reject shell characters."""
        with pytest.raises(Exception):
            _validate_expression("1 + ; rm -rf /")

    def test_invalid_backtick(self):
        """Should reject backticks."""
        with pytest.raises(Exception):
            _validate_expression("`echo bad`")

    def test_empty_expression(self):
        """Should reject empty expression."""
        with pytest.raises(Exception):
            _validate_expression("")

    def test_shell_escape(self):
        """Should reject shell escape characters."""
        with pytest.raises(Exception):
            _validate_expression("1 + `whoami`")


class TestValidateR2Command:
    """Tests for _validate_r2_command."""

    def test_valid_pdf(self):
        """Should accept pdf command."""
        _validate_r2_command("pdf @ main")

    def test_valid_afl(self):
        """Should accept aflj."""
        _validate_r2_command("aflj")

    def test_invalid_backtick(self):
        """Should reject backticks."""
        with pytest.raises(Exception):
            _validate_r2_command("?V `whoami`")

    def test_invalid_semicolon(self):
        """Should reject semicolons."""
        with pytest.raises(Exception):
            _validate_r2_command("pdf; !rm -rf /")

    def test_invalid_pipe(self):
        """Should reject pipe."""
        with pytest.raises(Exception):
            _validate_r2_command("px | cat /etc/passwd")

    def test_empty_command(self):
        """Should reject empty command."""
        with pytest.raises(Exception):
            _validate_r2_command("")

    def test_blocked_command(self):
        """Should reject blocked commands."""
        with pytest.raises(Exception):
            _validate_r2_command("!ls")


class TestSanitizeForR2Cmd:
    """Tests for _sanitize_for_r2_cmd."""

    def test_allows_safe_chars(self):
        """Should pass safe characters."""
        assert _sanitize_for_r2_cmd("sym.main") == "sym.main"

    def test_strips_dangerous_chars(self):
        """Should strip dangerous characters."""
        assert _sanitize_for_r2_cmd("main; rm -rf /") == "main rm -rf /"

    def test_strips_backticks(self):
        """Should strip backticks."""
        assert _sanitize_for_r2_cmd("`whoami`") == "whoami"

    def test_strips_dollar(self):
        """Should strip dollar signs."""
        assert _sanitize_for_r2_cmd("$HOME") == "HOME"

    def test_empty_string(self):
        """Should handle empty string."""
        assert _sanitize_for_r2_cmd("") == ""


class TestR2Session:
    """Tests for R2Session class."""

    def test_init(self):
        """Should initialize properly."""
        session = R2Session()
        assert session.file_path is None
        assert session._r2 is None
        assert session._analyzed is False
        assert session.status == "initialized"
        assert session.last_error is None

    def test_init_with_file_path(self):
        """Should accept file_path."""
        session = R2Session("/app/test.bin")
        assert session.file_path == "/app/test.bin"

    def test_is_open_false_initially(self):
        """Should not be open initially."""
        session = R2Session()
        assert session.is_open is False

    def test_close_no_r2(self):
        """Should handle close with no r2."""
        session = R2Session()
        session.close()
        assert session._r2 is None

    def test_close_with_r2(self):
        """Should close r2 connection."""
        session = R2Session()
        mock_r2 = MagicMock()
        session._r2 = mock_r2
        session.status = "active"
        session.close()
        assert session._r2 is None
        assert session.status == "closed"
        mock_r2.quit.assert_called_once()

    def test_close_quit_error(self):
        """Should handle quit error gracefully."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.quit = MagicMock(side_effect=RuntimeError("fail"))
        session._r2 = mock_r2
        session.close()
        assert session._r2 is None

    def test_cmd_no_r2(self):
        """Should return empty string with no r2."""
        session = R2Session()
        assert session.cmd("pdf") == ""

    def test_cmd_success(self):
        """Should execute command on r2."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="push ebp")
        session._r2 = mock_r2
        result = session.cmd("pdf")
        assert result == "push ebp"

    def test_cmd_error(self):
        """Should return error string on failure."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(side_effect=RuntimeError("broken"))
        session._r2 = mock_r2
        result = session.cmd("pdf")
        assert "Error:" in result
        assert "broken" in result

    def test_cmdj_no_r2(self):
        """Should return None with no r2."""
        session = R2Session()
        assert session.cmdj("aflj") is None

    def test_cmdj_success(self):
        """Should return JSON result."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmdj = MagicMock(return_value=[{"name": "main"}])
        session._r2 = mock_r2
        result = session.cmdj("aflj")
        assert result == [{"name": "main"}]

    def test_cmdj_error(self):
        """Should return None on JSON failure."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmdj = MagicMock(side_effect=RuntimeError("broken"))
        session._r2 = mock_r2
        assert session.cmdj("aflj") is None

    @pytest.mark.asyncio
    async def test_safe_cmd(self):
        """Should execute async with lock."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="result")
        session._r2 = mock_r2
        result = await session.safe_cmd("pdf")
        assert result == "result"

    @pytest.mark.asyncio
    async def test_safe_cmdj(self):
        """Should execute JSON async with lock."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmdj = MagicMock(return_value={"foo": "bar"})
        session._r2 = mock_r2
        result = await session.safe_cmdj("ij")
        assert result == {"foo": "bar"}

    def test_analyze_level_0(self):
        """Should run aa for level 0."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="analysis done")
        session._r2 = mock_r2
        result = session.analyze(0)
        assert result == "analysis done"
        assert session._analyzed is True

    def test_analyze_already_done(self):
        """Should skip if already analyzed at low level."""
        session = R2Session()
        session._analyzed = True
        assert session.analyze(2) == "Already analyzed"

    def test_analyze_deep_override(self):
        """Should allow deeper analysis override."""
        session = R2Session()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="deep analysis")
        session._r2 = mock_r2
        session._analyzed = True
        result = session.analyze(3)
        assert result == "deep analysis"

    def test_open_no_r2pipe(self):
        """Should fail when r2pipe unavailable."""
        session = R2Session()
        with patch("reversecore_mcp.tools.radare2.r2_session.R2PIPE_AVAILABLE", False):
            result = session.open("/app/test.bin")
            assert result is False
            assert session.status == "error"

    def test_open_file_not_found(self):
        """Should fail when file doesn't exist."""
        session = R2Session()
        with patch("os.path.exists", return_value=False):
            with patch("reversecore_mcp.tools.radare2.r2_session.R2PIPE_AVAILABLE", True):
                result = session.open("/nonexistent.bin")
                assert result is False
                assert session.status == "error"

    def test_open_success(self):
        """Should open successfully."""
        session = R2Session()
        mock_r2 = MagicMock()
        with patch("os.path.exists", return_value=True):
            with patch("reversecore_mcp.tools.radare2.r2_session.r2pipe") as mock_r2pipe:
                mock_r2pipe.open = MagicMock(return_value=mock_r2)
                with patch("reversecore_mcp.tools.radare2.r2_session.R2PIPE_AVAILABLE", True):
                    result = session.open("/app/test.bin")
                    assert result is True
                    assert session.status == "active"
                    assert session.file_path == "/app/test.bin"

    def test_open_none_return(self):
        """Should handle None return from r2pipe.open."""
        session = R2Session()
        with patch("os.path.exists", return_value=True):
            with patch("reversecore_mcp.tools.radare2.r2_session.r2pipe") as mock_r2pipe:
                mock_r2pipe.open = MagicMock(return_value=None)
                result = session.open("/app/test.bin")
                assert result is False
                assert session.status == "error"


class TestCompileRegexCached:
    """Tests for regex compilation caching."""

    def test_valid_pattern(self):
        """Should compile valid pattern."""
        pattern = _compile_regex_cached("main")
        assert pattern is not None
        assert pattern.pattern == "main"

    def test_invalid_pattern(self):
        """Should return None for invalid pattern."""
        pattern = _compile_regex_cached("[invalid")
        assert pattern is None

    def test_caching(self):
        """Should cache compiled patterns."""
        p1 = _compile_regex_cached("test_pattern")
        p2 = _compile_regex_cached("test_pattern")
        assert p1 is p2


class TestFilterLinesByRegex:
    """Tests for line filtering."""

    def test_matching_lines(self):
        """Should return matching lines."""
        text = "main\nfoo\nbar\nmain2"
        result = _filter_lines_by_regex(text, "main")
        assert "main" in result
        assert "foo" not in result

    def test_empty_pattern(self):
        """Should return original text for empty pattern."""
        text = "line1\nline2"
        assert _filter_lines_by_regex(text, "") == text

    def test_empty_text(self):
        """Should return empty for empty text."""
        assert _filter_lines_by_regex("", "pattern") == ""

    def test_no_matches(self):
        """Should return empty when no matches."""
        assert _filter_lines_by_regex("abc\ndef", "zzz") == ""

    def test_invalid_pattern(self):
        """Should return error message for invalid pattern."""
        text = "line1\nline2"
        assert "Invalid regex pattern" in _filter_lines_by_regex(text, "[bad")

    def test_pattern_too_long(self):
        """Should reject overly long regex patterns."""
        text = "line1\nline2"
        result = _filter_lines_by_regex(text, "a" * 501)
        assert "too long" in result


class TestFilterNamedFunctions:
    """Tests for filtering numeric-suffixed functions."""

    def test_filters_numeric_suffix(self):
        """Should filter functions with numeric suffixes."""
        text = "sym.main\nsym.func.1000016c8\nsym.helper"
        result = _filter_named_functions(text)
        assert "sym.main" in result
        assert "sym.helper" in result
        assert "sym.func.1000016c8" not in result

    def test_empty_text(self):
        """Should handle empty text."""
        assert _filter_named_functions("") == ""

    def test_all_numeric(self):
        """Should filter all numeric suffixed lines."""
        text = "sym.func.1\nsym.func.2"
        result = _filter_named_functions(text)
        assert result == ""


class TestPaginateText:
    """Tests for text pagination."""

    def test_first_page(self):
        """Should return first page."""
        text = "\n".join(str(i) for i in range(100))
        page, has_more, cursor = _paginate_text(text, None, 20)
        assert page.count("\n") == 19
        assert has_more is True
        assert cursor is not None

    def test_last_page(self):
        """Should indicate no more pages."""
        text = "line1\nline2\nline3"
        page, has_more, cursor = _paginate_text(text, None, 10)
        assert has_more is False
        assert cursor is None

    def test_empty_text(self):
        """Should handle empty text."""
        page, has_more, cursor = _paginate_text("", None, 20)
        assert page == ""
        assert has_more is False
        assert cursor is None

    def test_invalid_cursor(self):
        """Should handle invalid cursor."""
        text = "line1\nline2\nline3"
        page, has_more, cursor = _paginate_text(text, "999", 20)
        assert page == ""
        assert has_more is False

    def test_negative_cursor(self):
        """Should handle negative cursor."""
        text = "line1\nline2\nline3"
        page, has_more, cursor = _paginate_text(text, "-5", 20)
        assert "line1" in page
        assert has_more is False
