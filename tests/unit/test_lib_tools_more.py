"""
More unit tests for tools.lib_tools covering error branches.
"""

import sys
import types

import pytest

from reversecore_mcp.tools import lib_tools


def test_run_yara_import_error(monkeypatch, tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    monkeypatch.setattr(
        lib_tools,
        "validate_file_path",
        lambda p, read_only=False, config=None: f,
    )
    # Remove yara from sys.modules and make import raise ImportError
    real_import = __import__
    def _fake_import(name, *args, **kwargs):
        if name == "yara":
            raise ImportError()
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr("builtins.__import__", _fake_import)

    out = lib_tools.run_yara(str(f), str(f))
    assert out.status == "error"
    assert out.error_code == "DEPENDENCY_MISSING"
    assert "yara-python" in out.message.lower()


def test_run_yara_compile_error(monkeypatch, tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    monkeypatch.setattr(
        lib_tools,
        "validate_file_path",
        lambda p, read_only=False, config=None: f,
    )

    fake_yara = types.ModuleType("yara")
    class _Err(Exception):
        pass
    def _compile(filepath):
        raise _Err("bad rule")
    fake_yara.Error = _Err
    fake_yara.TimeoutError = RuntimeError
    fake_yara.compile = _compile
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(f), str(f))
    assert out.status == "error"
    assert out.error_code == "INTERNAL_ERROR"
    assert "bad rule" in out.message.lower()


def test_run_yara_timeout(monkeypatch, tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    monkeypatch.setattr(
        lib_tools,
        "validate_file_path",
        lambda p, read_only=False, config=None: f,
    )

    fake_yara = types.ModuleType("yara")
    class _Err(Exception):
        pass
    class _TO(Exception):
        pass
    class _Rules:
        def match(self, *a, **kw):
            raise _TO()
    def _compile(filepath):
        return _Rules()
    fake_yara.Error = _Err
    fake_yara.TimeoutError = _TO
    fake_yara.compile = _compile
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(f), str(f))
    assert out.status == "error"
    assert out.error_code == "TIMEOUT"
    assert "timed out" in out.message.lower()


def test_disassemble_capstone_import_error(monkeypatch, tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x90\x90")
    monkeypatch.setattr(
        lib_tools,
        "validate_file_path",
        lambda p, read_only=False, config=None: f,
    )
    real_import = __import__
    def _fake_import(name, *args, **kwargs):
        if name == "capstone" or name.startswith("capstone"):
            raise ImportError()
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr("builtins.__import__", _fake_import)
    out = lib_tools.disassemble_with_capstone(str(f))
    assert out.status == "error"
    assert out.error_code == "DEPENDENCY_MISSING"
    assert "capstone" in out.message.lower()
