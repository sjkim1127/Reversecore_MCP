import pytest

from reversecore_mcp.core.extension import (
    GhidraAnalysisContext,
    GhidraExtensionPoint,
    R2CommandResult,
    R2ExtensionPoint,
)


class MockR2Ext(R2ExtensionPoint):
    name = "mock_r2"
    priority = 10
    r2_command_allowlist = ["mycmd"]

    async def on_before_r2_command(self, file_path: str, command: str) -> tuple[str, str]:
        return file_path + "_mod", command + " -q"

    async def on_after_r2_command(self, result: R2CommandResult) -> R2CommandResult:
        result.metadata["test"] = True
        return result

    def get_mcp_tools(self):
        async def dummy_tool():
            pass

        return [dummy_tool]

    def get_r2_startup_commands(self):
        return ["e asm.syntax=intel"]


class MockGhidraExt(GhidraExtensionPoint):
    name = "mock_ghidra"
    priority = 20

    async def on_after_decompile(self, ctx: GhidraAnalysisContext, code: str) -> str:
        return code.replace("var_1", "my_var")

    async def on_after_function_analysis(self, ctx: GhidraAnalysisContext, functions: list) -> list:
        functions.append({"name": "injected"})
        return functions

    def get_headless_scripts(self):
        return ["/tmp/script.py"]


def test_r2_extension_point_defaults():
    class EmptyExt(R2ExtensionPoint):
        name = "empty"

    ext = EmptyExt()
    assert ext.priority == 100
    assert ext.r2_command_allowlist == []
    assert ext.get_mcp_tools() == []
    assert ext.get_r2_startup_commands() == []


def test_ghidra_extension_point_defaults():
    class EmptyExt(GhidraExtensionPoint):
        name = "empty"

    ext = EmptyExt()
    assert ext.priority == 100
    assert ext.get_headless_scripts() == []
    assert ext.get_mcp_tools() == []


def test_extension_point_missing_name():
    with pytest.raises(TypeError, match="must define a non-empty class attribute 'name'"):

        class InvalidExt(R2ExtensionPoint):
            pass


@pytest.mark.asyncio
async def test_r2_extension_hooks():
    ext = MockR2Ext()

    # Pre-hook
    fp, cmd = await ext.on_before_r2_command("file", "cmd")
    assert fp == "file_mod"
    assert cmd == "cmd -q"

    # Post-hook
    res = R2CommandResult("file", "cmd", "out")
    res = await ext.on_after_r2_command(res)
    assert res.metadata["test"] is True


@pytest.mark.asyncio
async def test_ghidra_extension_hooks():
    ext = MockGhidraExt()
    ctx = GhidraAnalysisContext("file", "main")

    # Decompile hook
    code = await ext.on_after_decompile(ctx, "int var_1 = 0;")
    assert code == "int my_var = 0;"

    # Function hook
    funcs = await ext.on_after_function_analysis(ctx, [])
    assert len(funcs) == 1
    assert funcs[0]["name"] == "injected"
