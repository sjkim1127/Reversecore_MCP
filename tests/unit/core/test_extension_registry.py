import os
from unittest.mock import patch

import pytest

from reversecore_mcp.core.extension import (
    GhidraAnalysisContext,
    GhidraExtensionPoint,
    R2ExtensionPoint,
)
from reversecore_mcp.core.extension_registry import (
    ExtensionRegistry,
    get_extension_registry,
    reset_extension_registry,
)


class MockR2Ext1(R2ExtensionPoint):
    name = "r2_ext1"
    priority = 20

    async def on_before_r2_command(self, file_path, command):
        return file_path, command + "1"

    def get_mcp_tools(self):
        async def tool1():
            pass

        return [tool1]


class MockR2Ext2(R2ExtensionPoint):
    name = "r2_ext2"
    priority = 10  # Should run first

    async def on_before_r2_command(self, file_path, command):
        return file_path, command + "2"


class MockGhidraExt(GhidraExtensionPoint):
    name = "ghidra_ext1"

    async def on_after_decompile(self, ctx, code):
        return code + " mod"

    def get_headless_scripts(self):
        return ["script1.py"]


@pytest.fixture(autouse=True)
def clean_registry():
    reset_extension_registry()
    yield
    reset_extension_registry()


def test_registry_singleton():
    reg1 = get_extension_registry()
    reg2 = get_extension_registry()
    assert reg1 is reg2


def test_register_and_sort():
    reg = ExtensionRegistry()

    ext1 = MockR2Ext1()
    ext2 = MockR2Ext2()

    reg.register_r2(ext1)
    reg.register_r2(ext2)

    # Priority 10 should be before Priority 20
    assert reg.r2_extensions[0] is ext2
    assert reg.r2_extensions[1] is ext1


def test_duplicate_registration():
    reg = ExtensionRegistry()
    ext1 = MockR2Ext1()

    reg.register_r2(ext1)
    reg.register_r2(ext1)  # Should be ignored

    assert len(reg.r2_extensions) == 1


@pytest.mark.asyncio
async def test_r2_hook_chain():
    reg = ExtensionRegistry()
    reg.register_r2(MockR2Ext1())
    reg.register_r2(MockR2Ext2())

    # Pre-hooks: ext2 runs first (priority 10), then ext1 (priority 20)
    fp, cmd = await reg.run_r2_pre_hooks("file", "cmd")

    # "cmd" -> "cmd2" (ext2) -> "cmd21" (ext1)
    assert cmd == "cmd21"


@pytest.mark.asyncio
async def test_ghidra_hook_chain():
    reg = ExtensionRegistry()
    reg.register_ghidra(MockGhidraExt())

    ctx = GhidraAnalysisContext("file", "main")
    code = await reg.run_ghidra_decompile_hooks(ctx, "code")
    assert code == "code mod"


def test_get_all_extension_tools():
    reg = ExtensionRegistry()
    reg.register_r2(MockR2Ext1())
    reg.register_ghidra(MockGhidraExt())

    tools = reg.get_all_extension_tools()
    assert len(tools) == 1
    assert tools[0].__name__ == "tool1"


def test_get_ghidra_startup_scripts():
    reg = ExtensionRegistry()
    reg.register_ghidra(MockGhidraExt())

    scripts = reg.get_ghidra_startup_scripts()
    assert len(scripts) == 1
    assert scripts[0] == "script1.py"


@patch.dict(
    os.environ, {"REVERSECORE_R2_EXTENSIONS": "tests.unit.core.test_extension_registry:MockR2Ext1"}
)
def test_discover_from_env_vars():
    reg = ExtensionRegistry()
    reg._discover_from_env_vars()

    assert len(reg.r2_extensions) == 1
    assert reg.r2_extensions[0].name == "r2_ext1"
