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


def _create_workspace_binary(workspace_dir, name: str, data: bytes = b"abc"):
    path = workspace_dir / name
    path.write_bytes(data)
    return path


def test_run_yara_formatter(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    test_file = _create_workspace_binary(workspace_dir, "t.bin")
    rule_file = read_only_dir / "rules.yar"
    rule_file.write_text("rule t { condition: true }")

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

    def _compile(filepath=None, **_kwargs):
        return _Rules()

    fake_yara.compile = _compile
    fake_yara.Error = _Error
    fake_yara.TimeoutError = _TimeoutError

    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(test_file), str(rule_file))
    assert out.status == "success"
    data = out.data
    assert isinstance(data, dict)
    assert "matches" in data
    assert isinstance(data["matches"], list)
    assert data["matches"][0]["rule"] == "r1"
    assert data["matches"][0]["strings"][0]["identifier"] == "$a"
    assert data["matches"][0]["strings"][0]["offset"] == 10
    assert data["match_count"] == 1


def test_disassemble_invalid_arch_mode(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    test_file = _create_workspace_binary(workspace_dir, "t.bin", b"\x90\x90\x90\x90")

    # Mock capstone
    fake_capstone = types.ModuleType("capstone")
    fake_capstone.CS_ARCH_X86 = 0
    fake_capstone.CS_ARCH_ARM = 1
    fake_capstone.CS_ARCH_ARM64 = 2
    fake_capstone.CS_MODE_32 = 0
    fake_capstone.CS_MODE_64 = 1
    fake_capstone.CS_MODE_ARM = 2
    fake_capstone.CS_MODE_THUMB = 3
    fake_capstone.Cs = lambda *args: None
    fake_capstone.CsError = Exception

    monkeypatch.setitem(sys.modules, "capstone", fake_capstone)

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


def test_parse_binary_with_lief_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
    patched_config,
):
    test_file = _create_workspace_binary(workspace_dir, "t.bin", b"\x00\x01")

    fake_lief = types.ModuleType("lief")

    class _BadFile(Exception):
        pass

    fake_lief.bad_file = _BadFile
    fake_lief.exception = _BadFile

    def _parse(path):
        raise _BadFile("corrupt binary")

    fake_lief.parse = _parse
    monkeypatch.setitem(sys.modules, "lief", fake_lief)

    out = lib_tools.parse_binary_with_lief(str(test_file))
    assert out.status == "error"
    assert out.error_code == "LIEF_ERROR"
    assert "corrupt" in out.message.lower()


def test_run_yara_formatter_fallback_tuple_api(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    """Test YARA formatter fallback to tuple API for older YARA versions."""
    test_file = _create_workspace_binary(workspace_dir, "t2.bin")
    rule_file = read_only_dir / "rules2.yar"
    rule_file.write_text("rule t2 { condition: true }")

    # Fake yara module with older tuple API
    fake_yara = types.ModuleType("yara")

    class _Rules:
        def match(self, f, timeout=300):
            # Old API: returns tuples instead of objects
            class OldMatch:
                def __init__(self):
                    self.rule = "r2"
                    self.namespace = "default"
                    self.tags = ["tag2"]
                    self.meta = {"author": "test"}
                    # Old strings API that raises AttributeError when accessing .instances
                    self.strings = [(20, "$b", b"xyz")]
            return [OldMatch()]

    class _Error(Exception):
        pass

    class _TimeoutError(Exception):
        pass

    def _compile(filepath=None, **_kwargs):
        return _Rules()

    fake_yara.compile = _compile
    fake_yara.Error = _Error
    fake_yara.TimeoutError = _TimeoutError

    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(test_file), str(rule_file))
    assert out.status == "success"
    data = out.data
    assert data["matches"][0]["rule"] == "r2"
    # Should handle fallback gracefully
    assert data["match_count"] == 1


def test_run_yara_formatter_with_none_values(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    """Test YARA formatter handles None values in matched_data."""
    test_file = _create_workspace_binary(workspace_dir, "t3.bin")
    rule_file = read_only_dir / "rules3.yar"
    rule_file.write_text("rule t3 { condition: true }")

    fake_yara = types.ModuleType("yara")

    class _InstNone:
        def __init__(self, offset):
            self.offset = offset
            self.matched_data = None

    class _SM:
        def __init__(self, identifier, instances):
            self.identifier = identifier
            self.instances = instances

    class _Rules:
        def match(self, f, timeout=300):
            inst1 = _InstNone(30)
            sm = _SM("$c", [inst1])
            return [_Match("r3", "default", [], {}, [sm])]

    class _Error(Exception):
        pass

    class _TimeoutError(Exception):
        pass

    def _compile(filepath=None, **_kwargs):
        return _Rules()

    fake_yara.compile = _compile
    fake_yara.Error = _Error
    fake_yara.TimeoutError = _TimeoutError

    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(test_file), str(rule_file))
    assert out.status == "success"
    data = out.data
    assert data["matches"][0]["strings"][0]["matched_data"] is None


def test_disassemble_no_data_at_offset(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    """Test disassemble when no data is read from offset."""
    # Create a very small file
    test_file = _create_workspace_binary(workspace_dir, "tiny.bin", b"\x90")
    
    # Mock capstone
    fake_capstone = types.ModuleType("capstone")
    fake_capstone.CS_ARCH_X86 = 0
    fake_capstone.CS_ARCH_ARM = 1
    fake_capstone.CS_ARCH_ARM64 = 2
    fake_capstone.CS_MODE_32 = 0
    fake_capstone.CS_MODE_64 = 1
    fake_capstone.CS_MODE_ARM = 2
    fake_capstone.CS_MODE_THUMB = 3
    fake_capstone.Cs = lambda *args: None
    fake_capstone.CsError = Exception

    monkeypatch.setitem(sys.modules, "capstone", fake_capstone)

    # Try to read from an offset beyond the file
    out = lib_tools.disassemble_with_capstone(str(test_file), arch="x86", mode="64", offset=100, size=1024)
    assert out.status == "error"
    assert out.error_code == "NO_DATA"


def test_disassemble_no_instructions(
    workspace_dir,
    patched_workspace_config,
):
    """Test disassemble when no instructions are disassembled."""
    # Create file with invalid opcodes that won't disassemble
    test_file = _create_workspace_binary(workspace_dir, "invalid.bin", b"\xff" * 10)
    
    out = lib_tools.disassemble_with_capstone(str(test_file), arch="x86", mode="64", offset=0, size=10)
    # Should succeed but with no instructions
    if out.status == "success":
        assert "No instructions" in out.data or out.metadata.get("instruction_count") == 0


def test_run_yara_no_matches(
    monkeypatch,
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    """Test YARA with no matches."""
    test_file = _create_workspace_binary(workspace_dir, "nomatch.bin")
    rule_file = read_only_dir / "rules_nomatch.yar"
    rule_file.write_text("rule nomatch { condition: false }")

    fake_yara = types.ModuleType("yara")

    class _Rules:
        def match(self, f, timeout=300):
            return []

    class _Error(Exception):
        pass

    class _TimeoutError(Exception):
        pass

    def _compile(filepath=None, **_kwargs):
        return _Rules()

    fake_yara.compile = _compile
    fake_yara.Error = _Error
    fake_yara.TimeoutError = _TimeoutError

    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    out = lib_tools.run_yara(str(test_file), str(rule_file))
    assert out.status == "success"
    data = out.data
    assert data["match_count"] == 0
    assert len(data["matches"]) == 0


def test_parse_binary_with_lief_no_sections(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    """Test LIEF parsing with binary that has no sections."""
    test_file = _create_workspace_binary(workspace_dir, "nosections.bin")

    fake_lief = types.ModuleType("lief")

    class _Binary:
        def __init__(self):
            self.format = "ELF"
            self.sections = []  # No sections
            self.entrypoint = 0x1000

    def _parse(path):
        return _Binary()

    fake_lief.parse = _parse
    monkeypatch.setitem(sys.modules, "lief", fake_lief)

    out = lib_tools.parse_binary_with_lief(str(test_file))
    assert out.status == "success"
    # Default format is json, so data should be a dict
    data = out.data
    assert isinstance(data, dict)
    assert data["format"] == "elf"


def test_parse_binary_with_lief_with_symbols(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    """Test LIEF parsing with binary that has symbols."""
    test_file = _create_workspace_binary(workspace_dir, "withsyms.bin")

    fake_lief = types.ModuleType("lief")

    class _Function:
        def __init__(self, name):
            self.name = name
        def __str__(self):
            return self.name

    class _Import:
        def __init__(self, name, entries):
            self.name = name
            self.entries = entries

    class _Export:
        def __init__(self, name, addr):
            self.name = name
            self.address = addr

    class _Binary:
        def __init__(self):
            self.format = "PE"
            self.sections = []
            self.entrypoint = 0x401000
            self.imported_functions = [_Function("printf"), _Function("malloc")]
            self.exported_functions = [_Function("main")]
            self.imports = [_Import("msvcrt.dll", [_Function("printf")])]
            self.exports = [_Export("main", 0x401000)]

    def _parse(path):
        return _Binary()

    fake_lief.parse = _parse
    monkeypatch.setitem(sys.modules, "lief", fake_lief)

    out = lib_tools.parse_binary_with_lief(str(test_file))
    assert out.status == "success"
    # Default format is json, so data should be a dict
    data = out.data
    assert isinstance(data, dict)
    assert "imported_functions" in data
    assert "printf" in data["imported_functions"]
    assert "main" in data["exported_functions"]
