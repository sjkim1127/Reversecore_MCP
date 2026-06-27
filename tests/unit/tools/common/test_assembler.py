"""Tests for reversecore_mcp.tools.common.assembler."""

from unittest.mock import patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.common.assembler import (
    assemble_instructions,
    get_capstone_params,
    get_keystone_params,
)

# Define mock constants to use in testing parameter mapping
MOCK_KS_ARCH_X86 = 4
MOCK_KS_MODE_64 = 8
MOCK_KS_ARCH_ARM = 1
MOCK_KS_MODE_THUMB = 16
MOCK_KS_ARCH_ARM64 = 2
MOCK_KS_MODE_LITTLE_ENDIAN = 0


def test_get_keystone_params_valid():
    """Test mapping of valid architecture and mode to Keystone constants."""
    with (
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_X86", MOCK_KS_ARCH_X86),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_64", MOCK_KS_MODE_64),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_ARM", MOCK_KS_ARCH_ARM),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_THUMB", MOCK_KS_MODE_THUMB),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_ARM64", MOCK_KS_ARCH_ARM64),
        patch(
            "reversecore_mcp.tools.common.assembler.KS_MODE_LITTLE_ENDIAN",
            MOCK_KS_MODE_LITTLE_ENDIAN,
        ),
    ):
        arch, mode = get_keystone_params("x86", "64")
        assert arch == MOCK_KS_ARCH_X86
        assert mode == MOCK_KS_MODE_64

        arch, mode = get_keystone_params("arm", "thumb")
        assert arch == MOCK_KS_ARCH_ARM
        assert mode == MOCK_KS_MODE_THUMB

        arch, mode = get_keystone_params("arm64", "64")
        assert arch == MOCK_KS_ARCH_ARM64
        assert mode == MOCK_KS_MODE_LITTLE_ENDIAN


def test_get_keystone_params_invalid():
    """Test get_keystone_params raises ValidationError for invalid inputs."""
    with pytest.raises(ValidationError):
        get_keystone_params("x86", "99")

    with pytest.raises(ValidationError):
        get_keystone_params("unknown_arch", "64")

    with pytest.raises(ValidationError):
        get_keystone_params("arm", "invalid_mode")


def test_get_capstone_params_valid():
    """Test mapping of valid architecture and mode to Capstone constants."""
    from capstone import CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_64, CS_MODE_ARM

    arch, mode = get_capstone_params("x86", "64")
    assert arch == CS_ARCH_X86
    assert mode == CS_MODE_64

    arch, mode = get_capstone_params("arm", "arm")
    assert arch == CS_ARCH_ARM
    assert mode == CS_MODE_ARM


def test_get_capstone_params_unsupported():
    """Test get_capstone_params returns None for unsupported mapping."""
    arch, mode = get_capstone_params("unknown", "64")
    assert arch is None
    assert mode == 0


class MockKsInstance:
    """Mock Keystone class instance for simulating assemblies."""

    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode

    def asm(self, code, addr=0):
        if "invalid" in code:
            from reversecore_mcp.tools.common.assembler import KsError

            if KsError is Exception:
                raise KsError("Keystone compile error")
            else:
                raise KsError(1)

        # Return mock encoding
        if "push" in code:
            return [0x50, 0x5B], 2
        return [0x90], 1


@pytest.mark.asyncio
async def test_assemble_instructions_success_x86_64():
    """Test successful x86-64 assembly using mocked Keystone."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert result.data["hex"] == "90"
        assert result.data["bytes"] == [0x90]
        assert result.data["instruction_count"] == 1
        assert "0x0: nop" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_success_x86_32():
    """Test successful x86-32 assembly with semicolons using mocked Keystone."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions(
            "push eax; pop ebx", arch="x86", mode="32", base_address="0x1000"
        )
        assert result.status == "success"
        assert result.data["hex"] == "505b"
        assert result.data["bytes"] == [0x50, 0x5B]
        assert result.data["instruction_count"] == 2
        # Since Capstone is installed, it will disassemble [0x50, 0x5b] as push eax; pop ebx
        assert "0x1000: push eax" in result.data["verification"]
        assert "0x1001: pop ebx" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_invalid_assembly():
    """Test assembly compilation fails for syntax error."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        # "invalid" in code triggers simulated KsError
        result = await assemble_instructions("invalid_instruction", arch="x86", mode="64")
        assert result.status == "error"
        assert result.error_code == "INTERNAL_ERROR"
        assert result.details["exception_type"] == "ToolExecutionError"


@pytest.mark.asyncio
async def test_assemble_instructions_invalid_params():
    """Test ValidationError is returned as error result for bad base address or architecture."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions(
            "nop", arch="x86", mode="64", base_address="invalid_hex"
        )
        assert result.status == "error"
        assert "VALIDATION_ERROR" in result.error_code

        result = await assemble_instructions("nop", arch="invalid_arch", mode="64")
        assert result.status == "error"
        assert "VALIDATION_ERROR" in result.error_code


@pytest.mark.asyncio
async def test_assemble_instructions_keystone_unavailable():
    """Test failure response when Keystone is not available."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", None):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert "KEYSTONE_NOT_AVAILABLE" in result.error_code


# --- Category A: Import Failures & Module Reloading Tests ---


def test_module_imports_keystone_unavailable():
    """Test fallback when keystone is completely unavailable."""
    import builtins
    import importlib
    import sys

    orig_import = builtins.__import__
    in_import = False

    def import_side_effect(name, *args, **kwargs):
        nonlocal in_import
        if name == "keystone":
            raise ImportError("Mocked keystone import error")
        if in_import:
            return orig_import(name, *args, **kwargs)
        in_import = True
        try:
            return orig_import(name, *args, **kwargs)
        finally:
            in_import = False

    try:
        with patch("builtins.__import__", side_effect=import_side_effect):
            if "reversecore_mcp.tools.common.assembler" in sys.modules:
                del sys.modules["reversecore_mcp.tools.common.assembler"]
            importlib.invalidate_caches()
            import reversecore_mcp.tools.common.assembler as assembler_mod

            assert assembler_mod.Ks is None
            assert assembler_mod.KsError is Exception
            assert assembler_mod.KS_ARCH_X86 == 4
    finally:
        sys.modules.pop("reversecore_mcp.tools.common.assembler", None)
        importlib.invalidate_caches()


def test_module_imports_capstone_unavailable():
    """Test fallback when capstone is completely unavailable."""
    import builtins
    import importlib
    import sys

    orig_import = builtins.__import__
    in_import = False

    def import_side_effect(name, *args, **kwargs):
        nonlocal in_import
        if name == "capstone":
            raise ImportError("Mocked capstone import error")
        if in_import:
            return orig_import(name, *args, **kwargs)
        in_import = True
        try:
            return orig_import(name, *args, **kwargs)
        finally:
            in_import = False

    try:
        with patch("builtins.__import__", side_effect=import_side_effect):
            if "reversecore_mcp.tools.common.assembler" in sys.modules:
                del sys.modules["reversecore_mcp.tools.common.assembler"]
            importlib.invalidate_caches()
            import reversecore_mcp.tools.common.assembler as assembler_mod

            assert assembler_mod.Cs is None
            assert assembler_mod.CsError is Exception
            assert assembler_mod.CS_ARCH_X86 == 4
    finally:
        sys.modules.pop("reversecore_mcp.tools.common.assembler", None)
        importlib.invalidate_caches()


def test_capstone_v6_attribute_fallbacks():
    """Test Capstone v6 fallback imports when standard attributes fail."""
    import builtins
    import importlib
    import sys

    try:
        import capstone
    except ImportError:
        # If capstone is not available at all, skip this test
        return

    class MockCapstoneModule:
        pass

    mock_capstone = MockCapstoneModule()
    for attr in dir(capstone):
        if attr not in ("CS_ARCH_ARM64", "CS_ARCH_SYSZ"):
            try:
                setattr(mock_capstone, attr, getattr(capstone, attr))
            except AttributeError:
                pass

    mock_capstone.CS_ARCH_AARCH64 = 9999
    mock_capstone.CS_ARCH_SYSTEMZ = 8888

    orig_import = builtins.__import__
    in_import = False

    def import_side_effect(name, *args, **kwargs):
        nonlocal in_import
        if name == "capstone":
            return mock_capstone
        if in_import:
            return orig_import(name, *args, **kwargs)
        in_import = True
        try:
            return orig_import(name, *args, **kwargs)
        finally:
            in_import = False

    try:
        with patch("builtins.__import__", side_effect=import_side_effect):
            if "reversecore_mcp.tools.common.assembler" in sys.modules:
                del sys.modules["reversecore_mcp.tools.common.assembler"]
            importlib.invalidate_caches()
            import reversecore_mcp.tools.common.assembler as assembler_mod

            assert assembler_mod.CS_ARCH_ARM64 == 9999
            assert assembler_mod.CS_ARCH_SYSZ == 8888
    finally:
        sys.modules.pop("reversecore_mcp.tools.common.assembler", None)
        importlib.invalidate_caches()


# --- Category B & C: Parameter Mappings for All Architectures & Modes ---


@pytest.mark.parametrize(
    "arch, mode, ks_arch_attr, ks_mode_expr",
    [
        ("x86", "16", "KS_ARCH_X86", "KS_MODE_16"),
        ("x86", "32", "KS_ARCH_X86", "KS_MODE_32"),
        ("x86", "64", "KS_ARCH_X86", "KS_MODE_64"),
        ("arm", "arm", "KS_ARCH_ARM", "KS_MODE_ARM"),
        ("arm", "thumb", "KS_ARCH_ARM", "KS_MODE_THUMB"),
        ("arm", "v8", "KS_ARCH_ARM", "KS_MODE_ARM + KS_MODE_V8"),
        ("arm64", "64", "KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
        ("arm64", "big", "KS_ARCH_ARM64", "KS_MODE_BIG_ENDIAN"),
        ("mips", "32", "KS_ARCH_MIPS", "KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN"),
        ("mips", "64", "KS_ARCH_MIPS", "KS_MODE_MIPS64 + KS_MODE_LITTLE_ENDIAN"),
        ("mips", "32 big", "KS_ARCH_MIPS", "KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN"),
        ("mips", "64 be", "KS_ARCH_MIPS", "KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN"),
        ("sparc", "32", "KS_ARCH_SPARC", "KS_MODE_32"),
        ("sparc", "64", "KS_ARCH_SPARC", "KS_MODE_64"),
        ("sparc", "32 big", "KS_ARCH_SPARC", "KS_MODE_32 + KS_MODE_BIG_ENDIAN"),
        ("sparc", "64 be", "KS_ARCH_SPARC", "KS_MODE_64 + KS_MODE_BIG_ENDIAN"),
        ("ppc", "64", "KS_ARCH_PPC", "KS_MODE_64"),
        ("ppc", "32", "KS_ARCH_PPC", "KS_MODE_32"),
        ("ppc", "64 big", "KS_ARCH_PPC", "KS_MODE_64 + KS_MODE_BIG_ENDIAN"),
        ("ppc", "32 be", "KS_ARCH_PPC", "KS_MODE_32 + KS_MODE_BIG_ENDIAN"),
        ("systemz", "32", "KS_ARCH_SYSTEMZ", "KS_MODE_32"),
    ],
)
def test_get_keystone_params_all_architectures(arch, mode, ks_arch_attr, ks_mode_expr):
    import reversecore_mcp.tools.common.assembler as assembler_mod

    actual_arch, actual_mode = assembler_mod.get_keystone_params(arch, mode)

    expected_arch = getattr(assembler_mod, ks_arch_attr)
    parts = [p.strip() for p in ks_mode_expr.split("+")]
    expected_mode = sum(getattr(assembler_mod, p) for p in parts)

    assert actual_arch == expected_arch
    assert actual_mode == expected_mode


@pytest.mark.parametrize(
    "arch, mode, cs_arch_attr, cs_mode_expr",
    [
        ("x86", "16", "CS_ARCH_X86", "CS_MODE_16"),
        ("x86", "32", "CS_ARCH_X86", "CS_MODE_32"),
        ("x86", "64", "CS_ARCH_X86", "CS_MODE_64"),
        ("arm", "thumb", "CS_ARCH_ARM", "CS_MODE_THUMB"),
        ("arm", "arm", "CS_ARCH_ARM", "CS_MODE_ARM"),
        ("arm64", "64", "CS_ARCH_ARM64", "CS_MODE_ARM"),
        ("arm64", "big", "CS_ARCH_ARM64", "CS_MODE_BIG_ENDIAN"),
        ("mips", "32", "CS_ARCH_MIPS", "CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN"),
        ("mips", "64", "CS_ARCH_MIPS", "CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN"),
        ("mips", "32 big", "CS_ARCH_MIPS", "CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN"),
        ("sparc", "32", "CS_ARCH_SPARC", "CS_MODE_32"),
        ("sparc", "64", "CS_ARCH_SPARC", "CS_MODE_64"),
        ("sparc", "32 big", "CS_ARCH_SPARC", "CS_MODE_32 + CS_MODE_BIG_ENDIAN"),
        ("ppc", "64", "CS_ARCH_PPC", "CS_MODE_64"),
        ("ppc", "32", "CS_ARCH_PPC", "CS_MODE_32"),
        ("ppc", "64 big", "CS_ARCH_PPC", "CS_MODE_64 + CS_MODE_BIG_ENDIAN"),
        ("systemz", "32", "CS_ARCH_SYSZ", "CS_MODE_32"),
    ],
)
def test_get_capstone_params_all_architectures(arch, mode, cs_arch_attr, cs_mode_expr):
    import reversecore_mcp.tools.common.assembler as assembler_mod

    actual_arch, actual_mode = assembler_mod.get_capstone_params(arch, mode)

    expected_arch = getattr(assembler_mod, cs_arch_attr)
    parts = [p.strip() for p in cs_mode_expr.split("+")]
    expected_mode = sum(getattr(assembler_mod, p) for p in parts)

    assert actual_arch == expected_arch
    assert actual_mode == expected_mode


# --- Category D: Keystone Assembly Exceptions ---


@pytest.mark.asyncio
async def test_assemble_instructions_keystone_init_kserror():
    """Test KsError during Keystone engine instantiation."""
    import reversecore_mcp.tools.common.assembler as assembler_mod
    from reversecore_mcp.tools.common.assembler import KsError

    def mock_ks_init_error(arch, mode):
        if KsError is Exception:
            raise KsError("Failed to initialize Keystone engine")
        else:
            raise KsError(1)

    with patch("reversecore_mcp.tools.common.assembler.Ks", mock_ks_init_error):
        result = await assembler_mod.assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "Failed to initialize Keystone engine" in result.message


@pytest.mark.asyncio
async def test_assemble_instructions_empty_encoding_new():
    """Test error when assembly returns empty encoding."""
    import reversecore_mcp.tools.common.assembler as assembler_mod

    class MockKsEmptyAsm:
        def __init__(self, arch, mode):
            pass

        def asm(self, code, addr=0):
            return None, 0

    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsEmptyAsm):
        result = await assembler_mod.assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert "returned empty encoding" in result.message or "empty encoding" in result.message


@pytest.mark.asyncio
async def test_assemble_instructions_generic_exception_new():
    """Test error when ks.asm raises an unexpected general exception."""
    import reversecore_mcp.tools.common.assembler as assembler_mod

    class MockKsGenericError:
        def __init__(self, arch, mode):
            pass

        def asm(self, code, addr=0):
            raise ValueError("Some internal value error")

    class MockKsError(Exception):
        pass

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsGenericError),
        patch("reversecore_mcp.tools.common.assembler.KsError", MockKsError),
    ):
        result = await assembler_mod.assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert "Some internal value error" in result.message


# --- Category E: Capstone Warnings & Fallbacks ---


@pytest.mark.asyncio
async def test_assemble_instructions_decimal_base_address():
    """Test parsing of integer base address in decimal format."""
    import reversecore_mcp.tools.common.assembler as assembler_mod

    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assembler_mod.assemble_instructions(
            "nop", arch="x86", mode="64", base_address="4096"
        )
        assert result.status == "success"
        assert result.metadata["base_address"] == "0x1000"


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_missing():
    """Test warning output when Capstone is unavailable."""
    import reversecore_mcp.tools.common.assembler as assembler_mod

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", None),
    ):
        result = await assembler_mod.assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "Capstone not available" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_unsupported_mode():
    """Test warning when Capstone does not support the mode/architecture configuration (e.g. ARM v8)."""
    import reversecore_mcp.tools.common.assembler as assembler_mod

    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assembler_mod.assemble_instructions("nop", arch="arm", mode="v8")
        assert result.status == "success"
        assert "Verification not supported for arm/v8" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_no_instructions_new():
    """Test warning when Capstone fails to disassemble any instructions (0 instruction count)."""
    import reversecore_mcp.tools.common.assembler as assembler_mod

    class MockCsEmpty:
        def __init__(self, arch, mode):
            pass

        def disasm(self, code, addr):
            return []

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", MockCsEmpty),
    ):
        result = await assembler_mod.assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "No instructions disassembled" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_cserror_new():
    """Test warning when Capstone disassembly throws CsError."""
    import reversecore_mcp.tools.common.assembler as assembler_mod

    class MockCsError:
        def __init__(self, arch, mode):
            pass

        def disasm(self, code, addr):
            from reversecore_mcp.tools.common.assembler import CsError

            if CsError is Exception:
                raise CsError("Mock disassembly failure")
            else:
                raise CsError(1)

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", MockCsError),
    ):
        result = await assembler_mod.assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "Disassembly verification failed" in result.data["verification"]
