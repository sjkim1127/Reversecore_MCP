"""
Additional unit tests for tools.lib_tools with mocks.
"""

import json
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

    # Bypass validation
    monkeypatch.setattr(lib_tools, "validate_file_path", lambda p, read_only=False: str(test_file))

    # Mock yara module and behavior
    class _Rules:
        def match(self, f, timeout=300):
            inst1 = _Inst(10, b"abc")
            sm = _SM("$a", [inst1])
            return [_Match("r1", "default", ["tag"], {"k": "v"}, [sm])]

    class _Yara:
        class Error(Exception):
            pass
        class TimeoutError(Exception):
            pass
        def compile(self, filepath):
            return _Rules()

    def _compile(filepath):
        return _Rules()

    # Inject yara
    monkeypatch.setitem(__import__("builtins").__dict__, "yara", _Yara())
    monkeypatch.setattr(_Yara, "compile", staticmethod(_compile))

    out = lib_tools.run_yara(str(test_file), str(test_file))
    # Should be JSON
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["rule"] == "r1"
    assert data[0]["strings"][0]["identifier"] == "$a"
    assert data[0]["strings"][0]["offset"] == 10


def test_disassemble_invalid_arch_mode(monkeypatch, tmp_path):
    test_file = tmp_path / "t.bin"
    test_file.write_bytes(b"\x90\x90\x90\x90")
    monkeypatch.setattr(lib_tools, "validate_file_path", lambda p, read_only=False: str(test_file))

    # Invalid arch
    out1 = lib_tools.disassemble_with_capstone(str(test_file), arch="badarch", mode="64")
    assert "Unsupported architecture" in out1

    # Valid arch but invalid mode
    out2 = lib_tools.disassemble_with_capstone(str(test_file), arch="x86", mode="badmode")
    assert "Unsupported mode" in out2
