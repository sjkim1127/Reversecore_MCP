"""More unit tests for tools.lib_tools covering error branches."""

import sys
import types

import pytest

from reversecore_mcp.tools.common import lib_tools


def _create_workspace_binary(workspace_dir, name: str, data: bytes = b"x"):
    path = workspace_dir / name
    path.write_bytes(data)
    return path


def _create_rule_file(read_only_dir, name: str = "rule.yar"):
    path = read_only_dir / name
    path.write_text("rule test { condition: true }")
    return path


def test_run_yara_import_error(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    binary = _create_workspace_binary(workspace_dir, "x.bin")
    rule_file = _create_rule_file(read_only_dir)

    real_import = __import__

    def _fake_import(name, *args, **kwargs):
        if name == "yara":
            raise ImportError()
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _fake_import)

    out = lib_tools.run_yara(str(binary), str(rule_file))
    assert out.status == "error"
    assert out.error_code == "DEPENDENCY_MISSING"
    assert "yara-python" in out.message.lower()


def test_run_yara_compile_error(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    binary = _create_workspace_binary(workspace_dir, "x.bin")
    rule_file = _create_rule_file(read_only_dir)

    fake_yara = types.ModuleType("yara")

    class _Err(Exception):
        pass

    def _compile(_filepath=None, **_kwargs):
        raise _Err("bad rule")

    fake_yara.Error = _Err
    fake_yara.TimeoutError = RuntimeError
    fake_yara.compile = _compile
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(binary), str(rule_file))
    assert out.status == "error"
    assert out.error_code == "YARA_ERROR"
    assert "bad rule" in out.message.lower()


def test_run_yara_timeout(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    binary = _create_workspace_binary(workspace_dir, "x.bin")
    rule_file = _create_rule_file(read_only_dir)

    fake_yara = types.ModuleType("yara")

    class _Err(Exception):
        pass

    class _TO(Exception):
        pass

    class _Rules:
        def match(self, *_args, **_kwargs):
            raise _TO()

    def _compile(_filepath=None, **_kwargs):
        return _Rules()

    fake_yara.Error = _Err
    fake_yara.TimeoutError = _TO
    fake_yara.compile = _compile
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(binary), str(rule_file))
    assert out.status == "error"
    assert out.error_code == "TIMEOUT"
    assert "timed out" in out.message.lower()


@pytest.mark.skip(reason="disassemble_with_capstone was removed")
def test_disassemble_capstone_import_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    binary = _create_workspace_binary(workspace_dir, "x.bin", b"\x90\x90")

    real_import = __import__

    def _fake_import(name, *args, **kwargs):
        if name == "capstone" or name.startswith("capstone"):
            raise ImportError()
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _fake_import)
    out = lib_tools.disassemble_with_capstone(str(binary))
    assert out.status == "error"
    assert out.error_code == "DEPENDENCY_MISSING"
    assert "capstone" in out.message.lower()


@pytest.mark.skip(reason="disassemble_with_capstone was removed")
def test_disassemble_capstone_runtime_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    binary = _create_workspace_binary(workspace_dir, "x.bin", b"\x90\x90")

    fake_capstone = types.ModuleType("capstone")
    fake_capstone.CS_ARCH_ARM = 1
    fake_capstone.CS_ARCH_ARM64 = 2
    fake_capstone.CS_ARCH_X86 = 3
    fake_capstone.CS_MODE_32 = 4
    fake_capstone.CS_MODE_64 = 5
    fake_capstone.CS_MODE_ARM = 6
    fake_capstone.CS_MODE_THUMB = 7

    class _CsError(Exception):
        pass

    class _Cs:
        def __init__(self, *_args, **_kwargs):
            raise _CsError("capstone boom")

    fake_capstone.CsError = _CsError
    fake_capstone.Cs = _Cs
    monkeypatch.setitem(sys.modules, "capstone", fake_capstone)

    out = lib_tools.disassemble_with_capstone(str(binary))
    assert out.status == "error"
    assert out.error_code == "CAPSTONE_ERROR"
    assert "capstone boom" in out.message.lower()
