"""Additional unit tests for tools.lib_tools with mocks."""

import sys
import types

import pytest

from reversecore_mcp.tools import lib_tools


class _Inst:
    def __init__(self, offset, data: bytes):
        self.offset = offset
        self.matched_data = data


class _SM:
    def __init__(self, identifier, instances):
        self.identifier = identifier
        self.instances = instances


class _Match:
    def __init__(self, rule, namespace, tags, meta, strings):
        self.rule = rule
        self.namespace = namespace
        self.tags = tags
        self.meta = meta
        self.strings = strings


def test_run_yara_formatter(monkeypatch, tmp_path):
    test_file = tmp_path / "t.bin"
    test_file.write_bytes(b"abc")

    # Bypass validation for both file and rule
    monkeypatch.setattr(
        lib_tools,
        "validate_file_path",
        lambda p, read_only=False, config=None: test_file,
    )

    # Fake yara module injected into sys.modules
    fake_yara = types.ModuleType("yara")

    class _Rules:
        def match(self, f, timeout=300):
            inst1 = _Inst(10, b"abc")
            sm = _SM("$a", [inst1])
            return [_Match("r1", "default", ["tag"], {"k": "v"}, [sm])]

    class _Error(Exception):
        pass

    class _TimeoutError(Exception):
        pass

    def _compile(filepath):
        return _Rules()

    fake_yara.compile = _compile
    fake_yara.Error = _Error
    fake_yara.TimeoutError = _TimeoutError

    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(test_file), str(test_file))
    assert out.status == "success"
    data = out.data
    assert isinstance(data, dict)
    assert "matches" in data
    assert isinstance(data["matches"], list)
    assert data["matches"][0]["rule"] == "r1"
    assert data["matches"][0]["strings"][0]["identifier"] == "$a"
    assert data["matches"][0]["strings"][0]["offset"] == 10
    assert data["match_count"] == 1


def test_disassemble_invalid_arch_mode(monkeypatch, tmp_path):
    test_file = tmp_path / "t.bin"
    test_file.write_bytes(b"\x90\x90\x90\x90")
    monkeypatch.setattr(
        lib_tools,
        "validate_file_path",
        lambda p, read_only=False, config=None: test_file,
    )

    # Invalid arch
    out1 = lib_tools.disassemble_with_capstone(str(test_file), arch="badarch", mode="64")
    assert out1.status == "error"
    assert out1.error_code == "INVALID_PARAMETER"
    assert "unsupported architecture" in out1.message.lower()

    # Valid arch but invalid mode
    out2 = lib_tools.disassemble_with_capstone(str(test_file), arch="x86", mode="badmode")
    assert out2.status == "error"
    assert out2.error_code == "INVALID_PARAMETER"
    assert "unsupported mode" in out2.message.lower()
