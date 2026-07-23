#!/usr/bin/env python3
"""Update the Radare2 invalid-path unit test to the fail-closed contract."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "tests/unit/tools/radare2/test_radare2_mcp_tools.py"
text = path.read_text()

old_import = "from reversecore_mcp.core.exceptions import ValidationError\n"
new_import = "from reversecore_mcp.core.exceptions import ToolExecutionError, ValidationError\n"
if text.count(old_import) != 1:
    raise RuntimeError("expected ValidationError import once")
text = text.replace(old_import, new_import, 1)

old_test = '''    @pytest.mark.asyncio
    async def test_validation_error_returns_dummy_session(self):
        """Should return dummy session on validation error."""
        plugin = Radare2ToolsPlugin()
        with patch(
            "reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path",
            side_effect=ValidationError("invalid"),
        ):
            result = await plugin._get_or_create_session("../../../etc/passwd")
        assert isinstance(result, R2Session)
'''
new_test = '''    @pytest.mark.asyncio
    async def test_validation_error_fails_closed(self):
        """Invalid paths must fail before a Radare2 process is created."""
        plugin = Radare2ToolsPlugin()
        with patch(
            "reversecore_mcp.tools.radare2.radare2_mcp_tools.validate_file_path",
            side_effect=ValidationError("invalid"),
        ):
            with pytest.raises(ToolExecutionError, match="Invalid Radare2 file path"):
                await plugin._get_or_create_session("../../../etc/passwd")
        assert plugin._sessions == {}
        assert plugin._file_to_session == {}
'''
if text.count(old_test) != 1:
    raise RuntimeError("legacy dummy-session test not found exactly once")
path.write_text(text.replace(old_test, new_test, 1))

(root / "scripts/update_r2_invalid_path_contract_test.py").unlink()
(root / ".github/workflows/update-r2-invalid-path-test.yml").unlink()
