"""
More unit tests for tools.cli_tools covering additional branches.
"""

import pytest

from reversecore_mcp.core import command_spec
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.radare2 import r2_analysis, static_analysis


@pytest.mark.asyncio
async def test_run_radare2_invalid_command_sanitization(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    path = workspace_dir / "a.out"
    path.write_text("bin")

    def _validate(cmd):
        raise ValidationError("invalid command")

    monkeypatch.setattr(command_spec, "validate_r2_command", _validate)
    out = await r2_analysis.run_radare2(str(path), "bad")
    assert out.status == "error" and out.error_code == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_run_strings_validation_error(
    tmp_path,
    workspace_dir,
    patched_workspace_config,
):
    outside_file = tmp_path / "outside.bin"
    outside_file.write_text("nope")

    out = await static_analysis.run_strings(str(outside_file))
    assert out.status == "error" and out.error_code == "VALIDATION_ERROR"
