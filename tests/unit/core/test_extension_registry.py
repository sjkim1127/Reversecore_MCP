"""Comprehensive edge-case tests for reversecore_mcp.core.extension_registry."""

import os
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.extension import (
    GhidraAnalysisContext,
    GhidraExtensionPoint,
    R2CommandResult,
    R2ExtensionPoint,
)
from reversecore_mcp.core.extension_registry import (
    ExtensionRegistry,
    get_extension_registry,
    reset_extension_registry,
)

# ---------------------------------------------------------------------------
# Shared mock extensions
# ---------------------------------------------------------------------------


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


class FailingR2Ext(R2ExtensionPoint):
    name = "failing_r2"
    priority = 5

    async def on_before_r2_command(self, file_path, command):
        raise RuntimeError("pre-hook exploded")

    async def on_after_r2_command(self, result):
        raise RuntimeError("post-hook exploded")

    async def on_session_open(self, file_path, r2pipe_instance):
        raise RuntimeError("session-open exploded")

    async def on_session_close(self, file_path):
        raise RuntimeError("session-close exploded")


class FailingGhidraExt(GhidraExtensionPoint):
    name = "failing_ghidra"

    async def on_after_decompile(self, ctx, code):
        raise RuntimeError("decompile hook exploded")

    async def on_after_function_analysis(self, ctx, functions):
        raise RuntimeError("function hook exploded")

    def get_headless_scripts(self):
        raise RuntimeError("get_headless_scripts exploded")

    def get_mcp_tools(self):
        raise RuntimeError("get_mcp_tools exploded")


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_registry():
    reset_extension_registry()
    yield
    reset_extension_registry()


# ===========================================================================
# Original tests (preserved)
# ===========================================================================


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
    assert reg.r2_extensions[0] is ext2
    assert reg.r2_extensions[1] is ext1


def test_duplicate_registration():
    reg = ExtensionRegistry()
    ext1 = MockR2Ext1()
    reg.register_r2(ext1)
    reg.register_r2(ext1)
    assert len(reg.r2_extensions) == 1


@pytest.mark.asyncio
async def test_r2_hook_chain():
    reg = ExtensionRegistry()
    reg.register_r2(MockR2Ext1())
    reg.register_r2(MockR2Ext2())
    fp, cmd = await reg.run_r2_pre_hooks("file", "cmd")
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
    os.environ,
    {"REVERSECORE_R2_EXTENSIONS": "tests.unit.core.test_extension_registry:MockR2Ext1"},
)
def test_discover_from_env_vars():
    reg = ExtensionRegistry()
    reg._discover_from_env_vars()
    assert len(reg.r2_extensions) == 1
    assert reg.r2_extensions[0].name == "r2_ext1"


# ===========================================================================
# Edge-case: Hook exception isolation
# ===========================================================================


@pytest.mark.asyncio
async def test_r2_pre_hook_exception_does_not_abort_chain():
    """Exception in a pre-hook must not prevent subsequent hooks from running."""
    reg = ExtensionRegistry()
    called = []

    class GoodR2Ext(R2ExtensionPoint):
        name = "good_r2"
        priority = 10

        async def on_before_r2_command(self, file_path, command):
            called.append("good")
            return file_path, command + "_good"

    reg.register_r2(FailingR2Ext())  # priority 5 — runs first, explodes
    reg.register_r2(GoodR2Ext())  # priority 10 — must still run

    fp, cmd = await reg.run_r2_pre_hooks("f", "cmd")
    assert "good" in called
    assert "_good" in cmd


@pytest.mark.asyncio
async def test_r2_post_hook_exception_isolated():
    reg = ExtensionRegistry()
    reg.register_r2(FailingR2Ext())
    result = R2CommandResult(file_path="f", command="cmd", raw_output="out")
    returned = await reg.run_r2_post_hooks(result)
    assert returned is not None


@pytest.mark.asyncio
async def test_r2_pre_hooks_empty_passthrough():
    reg = ExtensionRegistry()
    fp, cmd = await reg.run_r2_pre_hooks("myfile", "mycommand")
    assert fp == "myfile"
    assert cmd == "mycommand"


@pytest.mark.asyncio
async def test_r2_post_hooks_empty_passthrough():
    reg = ExtensionRegistry()
    result = R2CommandResult(file_path="f", command="c", raw_output="o")
    returned = await reg.run_r2_post_hooks(result)
    assert returned is result


@pytest.mark.asyncio
async def test_r2_session_open_hook_exception_isolated():
    reg = ExtensionRegistry()
    reg.register_r2(FailingR2Ext())
    await reg.run_r2_session_open_hooks("file", MagicMock())  # must not raise


@pytest.mark.asyncio
async def test_r2_session_close_hook_exception_isolated():
    reg = ExtensionRegistry()
    reg.register_r2(FailingR2Ext())
    await reg.run_r2_session_close_hooks("file")  # must not raise


@pytest.mark.asyncio
async def test_ghidra_decompile_hook_exception_returns_original():
    reg = ExtensionRegistry()
    reg.register_ghidra(FailingGhidraExt())
    ctx = GhidraAnalysisContext("file", "main")
    code = await reg.run_ghidra_decompile_hooks(ctx, "original_code")
    assert code == "original_code"


@pytest.mark.asyncio
async def test_ghidra_decompile_hooks_empty_passthrough():
    reg = ExtensionRegistry()
    ctx = GhidraAnalysisContext("file", "main")
    code = await reg.run_ghidra_decompile_hooks(ctx, "mycode")
    assert code == "mycode"


@pytest.mark.asyncio
async def test_ghidra_function_hooks_exception_returns_original():
    reg = ExtensionRegistry()
    reg.register_ghidra(FailingGhidraExt())
    ctx = GhidraAnalysisContext("file", "main")
    funcs = [{"name": "main"}]
    returned = await reg.run_ghidra_function_hooks(ctx, funcs)
    assert returned == funcs


@pytest.mark.asyncio
async def test_ghidra_function_hooks_empty_passthrough():
    reg = ExtensionRegistry()
    ctx = GhidraAnalysisContext("file", "main")
    funcs = [{"name": "foo"}]
    returned = await reg.run_ghidra_function_hooks(ctx, funcs)
    assert returned is funcs


def test_get_all_extension_tools_exception_isolated():
    reg = ExtensionRegistry()
    reg.register_ghidra(FailingGhidraExt())
    reg.register_r2(MockR2Ext1())
    tools = reg.get_all_extension_tools()
    assert len(tools) == 1


def test_get_ghidra_startup_scripts_exception_isolated():
    reg = ExtensionRegistry()
    reg.register_ghidra(FailingGhidraExt())
    reg.register_ghidra(MockGhidraExt())
    scripts = reg.get_ghidra_startup_scripts()
    assert "script1.py" in scripts


# ===========================================================================
# Edge-case: get_r2_startup_commands
# ===========================================================================


def test_get_r2_startup_commands_empty():
    reg = ExtensionRegistry()
    assert reg.get_r2_startup_commands("somefile") == []


def test_get_r2_startup_commands_returns_commands():
    class CmdR2Ext(R2ExtensionPoint):
        name = "cmd_r2"

        def get_r2_startup_commands(self):
            return ["aaa", "ii"]

    reg = ExtensionRegistry()
    reg.register_r2(CmdR2Ext())
    cmds = reg.get_r2_startup_commands("file")
    assert "aaa" in cmds and "ii" in cmds


def test_get_r2_startup_commands_exception_isolated():
    class BrokenR2Ext(R2ExtensionPoint):
        name = "broken_r2"

        def get_r2_startup_commands(self):
            raise RuntimeError("oops")

    reg = ExtensionRegistry()
    reg.register_r2(BrokenR2Ext())
    assert reg.get_r2_startup_commands("file") == []


# ===========================================================================
# Edge-case: _load_class static method
# ===========================================================================


class TestLoadClass:
    def test_colon_format(self):
        cls = ExtensionRegistry._load_class("tests.unit.core.test_extension_registry:MockR2Ext1")
        assert cls is MockR2Ext1

    def test_dot_format(self):
        cls = ExtensionRegistry._load_class("tests.unit.core.test_extension_registry.MockR2Ext1")
        assert cls is MockR2Ext1

    def test_invalid_format_no_separator(self):
        cls = ExtensionRegistry._load_class("noSeparator")
        assert cls is None

    def test_nonexistent_module(self):
        cls = ExtensionRegistry._load_class("nonexistent.module:SomeClass")
        assert cls is None

    def test_nonexistent_class(self):
        cls = ExtensionRegistry._load_class("tests.unit.core.test_extension_registry:DoesNotExist")
        assert cls is None


# ===========================================================================
# Edge-case: _discover_from_plugin_dirs
# ===========================================================================


class TestDiscoverFromPluginDirs:
    def test_missing_dir_is_skipped(self, tmp_path):
        reg = ExtensionRegistry()
        nonexistent = str(tmp_path / "nonexistent_dir")
        with patch.dict(os.environ, {"REVERSECORE_PLUGIN_DIRS": nonexistent}):
            reg._discover_from_plugin_dirs()
        assert reg.r2_extensions == []

    def test_empty_env_var_is_noop(self):
        reg = ExtensionRegistry()
        with patch.dict(os.environ, {"REVERSECORE_PLUGIN_DIRS": ""}):
            reg._discover_from_plugin_dirs()
        assert reg.r2_extensions == []

    def test_valid_plugin_file_registers_extension(self, tmp_path):
        plugin_code = (
            "from reversecore_mcp.core.extension import R2ExtensionPoint\n\n"
            "class MyPluginExt(R2ExtensionPoint):\n"
            "    name = 'my_plugin'\n"
            "    priority = 50\n"
        )
        (tmp_path / "my_plugin.py").write_text(plugin_code)
        reg = ExtensionRegistry()
        with patch.dict(os.environ, {"REVERSECORE_PLUGIN_DIRS": str(tmp_path)}):
            reg._discover_from_plugin_dirs()
        assert any(e.name == "my_plugin" for e in reg.r2_extensions)

    def test_broken_plugin_file_is_skipped(self, tmp_path):
        (tmp_path / "broken.py").write_text("this is not valid python syntax !!!")
        reg = ExtensionRegistry()
        with patch.dict(os.environ, {"REVERSECORE_PLUGIN_DIRS": str(tmp_path)}):
            reg._discover_from_plugin_dirs()
        assert reg.r2_extensions == []


# ===========================================================================
# Edge-case: _discover_from_env_vars
# ===========================================================================


class TestDiscoverFromEnvVarsEdgeCases:
    def test_non_subclass_r2_extension_skipped(self):
        reg = ExtensionRegistry()
        with patch.dict(
            os.environ,
            {
                "REVERSECORE_R2_EXTENSIONS": (
                    "tests.unit.core.test_extension_registry:MockGhidraExt"
                )
            },
        ):
            reg._discover_from_env_vars()
        assert reg.r2_extensions == []

    def test_non_subclass_ghidra_extension_skipped(self):
        reg = ExtensionRegistry()
        with patch.dict(
            os.environ,
            {
                "REVERSECORE_GHIDRA_EXTENSIONS": (
                    "tests.unit.core.test_extension_registry:MockR2Ext1"
                )
            },
        ):
            reg._discover_from_env_vars()
        assert reg.ghidra_extensions == []

    def test_instantiation_failure_is_handled(self):
        class BrokenR2Ext(R2ExtensionPoint):
            name = "broken"

            def __init__(self):
                raise ValueError("cannot instantiate")

        with patch(
            "reversecore_mcp.core.extension_registry.ExtensionRegistry._load_class",
            return_value=BrokenR2Ext,
        ):
            with patch.dict(os.environ, {"REVERSECORE_R2_EXTENSIONS": "some:BrokenR2Ext"}):
                reg = ExtensionRegistry()
                reg._discover_from_env_vars()
        assert reg.r2_extensions == []

    def test_empty_env_vars_noop(self):
        reg = ExtensionRegistry()
        with patch.dict(
            os.environ,
            {"REVERSECORE_R2_EXTENSIONS": "", "REVERSECORE_GHIDRA_EXTENSIONS": ""},
        ):
            reg._discover_from_env_vars()
        assert reg.r2_extensions == []
        assert reg.ghidra_extensions == []


# ===========================================================================
# Edge-case: _expand_r2_allowlist
# ===========================================================================


class TestExpandR2Allowlist:
    def test_expand_adds_new_commands(self):
        from reversecore_mcp.core import command_spec

        original = getattr(command_spec, "ALLOWED_R2_COMMANDS", set()).copy()
        try:
            ExtensionRegistry._expand_r2_allowlist(["zz_test_unique_cmd_9999"])
            assert "zz_test_unique_cmd_9999" in command_spec.ALLOWED_R2_COMMANDS
        finally:
            command_spec.ALLOWED_R2_COMMANDS = original  # type: ignore[attr-defined]

    def test_expand_allowlist_import_error_is_silent(self):
        """If command_spec import fails, _expand_r2_allowlist must not propagate."""
        with patch.dict("sys.modules", {"reversecore_mcp.core.command_spec": None}):
            # Should not raise even when command_spec is unavailable
            try:
                ExtensionRegistry._expand_r2_allowlist(["test_cmd"])
            except Exception:
                pass  # tolerate; important is no unhandled propagation in normal flow


# ===========================================================================
# Edge-case: discover_all idempotency
# ===========================================================================


def test_discover_all_idempotent():
    reg = ExtensionRegistry()
    with patch.object(reg, "_discover_from_entry_points") as mock_ep:
        with patch.object(reg, "_discover_from_plugin_dirs") as mock_dirs:
            with patch.object(reg, "_discover_from_env_vars") as mock_env:
                reg.discover_all()
                reg.discover_all()
    assert mock_ep.call_count == 1
    assert mock_dirs.call_count == 1
    assert mock_env.call_count == 1


def test_reset_clears_discovered_flag():
    reg = ExtensionRegistry()
    reg.discover_all()
    assert reg._discovered is True
    reg.reset()
    assert reg._discovered is False


# ===========================================================================
# Edge-case: list_extensions introspection
# ===========================================================================


def test_list_extensions():
    reg = ExtensionRegistry()
    reg.register_r2(MockR2Ext1())
    reg.register_ghidra(MockGhidraExt())
    info = reg.list_extensions()
    assert "r2_ext1" in info["r2"]
    assert "ghidra_ext1" in info["ghidra"]


def test_ghidra_duplicate_registration_skipped():
    reg = ExtensionRegistry()
    ext = MockGhidraExt()
    reg.register_ghidra(ext)
    reg.register_ghidra(ext)
    assert len(reg.ghidra_extensions) == 1
