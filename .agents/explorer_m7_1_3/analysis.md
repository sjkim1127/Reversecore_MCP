# Test Coverage Gap Analysis: `reversecore_mcp/tools/common/assembler.py`

This report provides a detailed analysis of the current test coverage for `reversecore_mcp/tools/common/assembler.py` (located in the codebase of `Reversecore_MCP`). Based on this analysis, we identify all uncovered lines/branches and outline a precise testing strategy to achieve 100% test coverage.

---

## 1. Executive Summary
- **Target File**: `reversecore_mcp/tools/common/assembler.py`
- **Current Coverage**: **57%** (112 out of 197 statements covered, 85 missed statements)
- **Primary Goal**: Achieve **100%** test coverage by addressing:
  - Import errors / fallback constants for Keystone and Capstone modules.
  - Undocumented/untested architecture and mode mapping combinations.
  - Exception paths during Keystone engine instantiation and compilation.
  - Warning and fallback branches in Capstone disassembly verification.

---

## 2. Line-by-Line Gap Identification

Below is a categorization of all uncovered lines/branches in `assembler.py`:

### Category A: Module Import Failures & Version Fallbacks
These lines handle scenarios where Keystone/Capstone are missing, or when dealing with Capstone v6 imports.
- **Lines 69-70**: Fallback for `CS_ARCH_ARM64` when importing it fails (uses `CS_ARCH_AARCH64` instead).
  ```python
  except ImportError:
      from capstone import CS_ARCH_AARCH64 as CS_ARCH_ARM64
  ```
- **Lines 75-76**: Fallback for `CS_ARCH_SYSZ` when importing it fails (uses `CS_ARCH_SYSTEMZ` instead).
  ```python
  except ImportError:
      from capstone import CS_ARCH_SYSTEMZ as CS_ARCH_SYSZ
  ```
- **Lines 77-95**: Fallback declarations when Capstone is completely unavailable.
  ```python
  except ImportError:
      Cs = None
      CsError = Exception
      ... (constants assignment)
  ```

### Category B: Uncovered Architecture/Mode Mappings in `get_keystone_params`
- **Line 122**: x86 16-bit mode returns `KS_ARCH_X86, KS_MODE_16`.
- **Line 135**: ARM in ARM-mode returns `KS_ARCH_ARM, KS_MODE_ARM`.
- **Line 139**: ARM v8 mode returns `KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_V8`.
- **Line 149**: ARM64 Big Endian returns `KS_ARCH_ARM64, KS_MODE_BIG_ENDIAN`.
- **Lines 153-163**: MIPS architecture mapping (MIPS32/MIPS64, Big Endian vs Little Endian).
- **Lines 166-171**: SPARC architecture mapping (32-bit/64-bit, Big Endian).
- **Lines 174-179**: PowerPC (PPC) architecture mapping (32-bit/64-bit, Big Endian).
- **Line 182**: SystemZ architecture mapping (`KS_ARCH_SYSTEMZ, KS_MODE_32`).

### Category C: Uncovered Architecture/Mode Mappings in `get_capstone_params`
- **Line 206**: x86 16-bit mode returns `CS_ARCH_X86, CS_MODE_16`.
- **Line 214**: ARM Thumb mode returns `CS_ARCH_ARM, CS_MODE_THUMB`.
- **Lines 219-222**: ARM64 mappings (default ARM mode vs Big Endian).
- **Lines 225-232**: MIPS architecture mapping (MIPS32/MIPS64, Big/Little Endian).
- **Lines 235-240**: SPARC architecture mapping (32/64-bit, Big Endian).
- **Lines 243-248**: PowerPC (PPC) architecture mapping (32/64-bit, Big Endian).
- **Line 251**: SystemZ architecture mapping (`CS_ARCH_SYSZ, CS_MODE_32`).

### Category D: Keystone/Assembly Exception & Compilation Error Paths
- **Lines 322-323**: Keystone instantiation raises `KsError`.
  ```python
  except KsError as e:
      raise ToolExecutionError(f"Failed to initialize Keystone engine: {e}")
  ```
- **Line 331**: Keystone assembly returns empty encoding `None`.
  ```python
  if encoding is None:
      raise ToolExecutionError("Keystone compilation returned empty encoding.")
  ```
- **Line 333**: Explicit re-raise block for `ToolExecutionError`.
- **Lines 336-338**: Generic/other exception catch-all from `ks.asm()` (e.g. `RuntimeError`, `ValueError`).
  ```python
  except Exception as e:
      raise ToolExecutionError(f"Assembly compilation failed: {type(e).__name__}: {e}")
  ```

### Category E: Capstone Verification Warnings and Error Paths
- **Line 356**: Capstone disassembles 0 instructions (returns empty disassembly).
  ```python
  else:
      verification_text = "Capstone warning: No instructions disassembled (invalid byte sequence or alignment)."
  ```
- **Lines 357-358**: Capstone disassembly execution raises `CsError`.
  ```python
  except CsError as e:
      verification_text = f"Capstone warning: Disassembly verification failed: {e}"
  ```
- **Lines 359-360**: Capstone architecture mapping returned `None` (unsupported by Capstone but supported by Keystone, e.g. ARM v8).
  ```python
  else:
      verification_text = f"Capstone warning: Verification not supported for {arch}/{mode}."
  ```
- **Lines 361-362**: Capstone module itself is unavailable (`Cs` is `None`).
  ```python
  else:
      verification_text = "Capstone warning: Capstone not available for disassembly verification."
  ```

---

## 3. Recommended Testing Strategy

To cover all of the identified lines without affecting system stability, we recommend the following testing techniques:

1. **Clean Process/Module Reloading Mocking**:
   Use `importlib.reload` alongside patching of `builtins.__import__` to simulate environments where `keystone` or `capstone` is missing, or where certain properties of `capstone` are missing (such as Capstone 6 fallbacks).
2. **Parameterized Mappings Testing**:
   Implement dynamic parameterized tests (`pytest.mark.parametrize`) verifying that all combinations of architecture and mode map to the correct constants defined in `assembler.py` (both for Keystone and Capstone).
3. **Robust Keystone & Capstone Mocking**:
   Define flexible mock classes for `Ks` and `Cs` that can simulate successful compilation, empty encoding, generic exceptions, init exceptions, empty disassembly, and `CsError` disassembly failures.
4. **Valid Base Address Scenarios**:
   Add a test case for base address inputs formatted as decimal string (e.g., `"4096"`).

---

## 4. Proposed Test Cases

The following test suite expansion is recommended for `tests/unit/tools/common/test_assembler.py` to achieve **100% test coverage**:

```python
import sys
import importlib
from unittest.mock import patch, MagicMock
import pytest

from reversecore_mcp.core.exceptions import ValidationError, ToolExecutionError
from reversecore_mcp.tools.common.assembler import (
    assemble_instructions,
    get_capstone_params,
    get_keystone_params,
)

# Existing mock class for normal operations
class MockKsInstance:
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
        if "push" in code:
            return [0x50, 0x5B], 2
        return [0x90], 1


# --- Category A: Import Failures & Module Reloading Tests ---

def test_module_imports_keystone_unavailable():
    """Test fallback when keystone is completely unavailable."""
    with patch("builtins.__import__") as mock_import:
        orig_import = __import__
        def import_side_effect(name, *args, **kwargs):
            if name == "keystone":
                raise ImportError("Mocked keystone import error")
            return orig_import(name, *args, **kwargs)
        mock_import.side_effect = import_side_effect

        if "reversecore_mcp.tools.common.assembler" in sys.modules:
            del sys.modules["reversecore_mcp.tools.common.assembler"]

        import reversecore_mcp.tools.common.assembler as assembler_mod
        assert assembler_mod.Ks is None
        assert assembler_mod.KsError is Exception
        assert assembler_mod.KS_ARCH_X86 == 4

    # Restore module state
    if "reversecore_mcp.tools.common.assembler" in sys.modules:
        del sys.modules["reversecore_mcp.tools.common.assembler"]
    importlib.invalidate_caches()
    import reversecore_mcp.tools.common.assembler


def test_module_imports_capstone_unavailable():
    """Test fallback when capstone is completely unavailable."""
    with patch("builtins.__import__") as mock_import:
        orig_import = __import__
        def import_side_effect(name, *args, **kwargs):
            if name == "capstone":
                raise ImportError("Mocked capstone import error")
            return orig_import(name, *args, **kwargs)
        mock_import.side_effect = import_side_effect

        if "reversecore_mcp.tools.common.assembler" in sys.modules:
            del sys.modules["reversecore_mcp.tools.common.assembler"]

        import reversecore_mcp.tools.common.assembler as assembler_mod
        assert assembler_mod.Cs is None
        assert assembler_mod.CsError is Exception
        assert assembler_mod.CS_ARCH_X86 == 4

    # Restore module state
    if "reversecore_mcp.tools.common.assembler" in sys.modules:
        del sys.modules["reversecore_mcp.tools.common.assembler"]
    importlib.invalidate_caches()
    import reversecore_mcp.tools.common.assembler


def test_capstone_v6_attribute_fallbacks():
    """Test Capstone v6 fallback imports when standard attributes fail."""
    import capstone
    mock_capstone = MagicMock(spec=capstone)

    # Copy existing properties EXCEPT CS_ARCH_ARM64 and CS_ARCH_SYSZ
    for attr in dir(capstone):
        if attr not in ("CS_ARCH_ARM64", "CS_ARCH_SYSZ"):
            setattr(mock_capstone, attr, getattr(capstone, attr))

    # Set fallback targets
    mock_capstone.CS_ARCH_AARCH64 = 9999
    mock_capstone.CS_ARCH_SYSTEMZ = 8888

    with patch("builtins.__import__") as mock_import:
        orig_import = __import__
        def import_side_effect(name, *args, **kwargs):
            if name == "capstone":
                return mock_capstone
            return orig_import(name, *args, **kwargs)
        mock_import.side_effect = import_side_effect

        if "reversecore_mcp.tools.common.assembler" in sys.modules:
            del sys.modules["reversecore_mcp.tools.common.assembler"]

        import reversecore_mcp.tools.common.assembler as assembler_mod
        assert assembler_mod.CS_ARCH_ARM64 == 9999
        assert assembler_mod.CS_ARCH_SYSZ == 8888

    # Restore module state
    if "reversecore_mcp.tools.common.assembler" in sys.modules:
        del sys.modules["reversecore_mcp.tools.common.assembler"]
    importlib.invalidate_caches()
    import reversecore_mcp.tools.common.assembler


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
    ]
)
def test_get_keystone_params_all_architectures(arch, mode, ks_arch_attr, ks_mode_expr):
    import reversecore_mcp.tools.common.assembler as assembler_mod
    actual_arch, actual_mode = get_keystone_params(arch, mode)

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
    ]
)
def test_get_capstone_params_all_architectures(arch, mode, cs_arch_attr, cs_mode_expr):
    import reversecore_mcp.tools.common.assembler as assembler_mod
    actual_arch, actual_mode = get_capstone_params(arch, mode)

    expected_arch = getattr(assembler_mod, cs_arch_attr)
    parts = [p.strip() for p in cs_mode_expr.split("+")]
    expected_mode = sum(getattr(assembler_mod, p) for p in parts)

    assert actual_arch == expected_arch
    assert actual_mode == expected_mode


# --- Category D: Keystone Assembly Exceptions ---

@pytest.mark.asyncio
async def test_assemble_instructions_keystone_init_kserror():
    """Test KsError during Keystone engine instantiation."""
    from reversecore_mcp.tools.common.assembler import KsError
    def mock_ks_init_error(arch, mode):
        if KsError is Exception:
            raise KsError("Failed to initialize Keystone engine")
        else:
            raise KsError(1)

    with patch("reversecore_mcp.tools.common.assembler.Ks", mock_ks_init_error):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "Failed to initialize Keystone engine" in result.error_message


@pytest.mark.asyncio
async def test_assemble_instructions_empty_encoding():
    """Test error when assembly returns empty encoding."""
    class MockKsEmptyAsm:
        def __init__(self, arch, mode): pass
        def asm(self, code, addr=0):
            return None, 0

    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsEmptyAsm):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert "empty encoding" in result.error_message


@pytest.mark.asyncio
async def test_assemble_instructions_generic_exception():
    """Test error when ks.asm raises an unexpected general exception."""
    class MockKsGenericError:
        def __init__(self, arch, mode): pass
        def asm(self, code, addr=0):
            raise ValueError("Some internal value error")

    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsGenericError):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert "ValueError" in result.error_message


# --- Category E: Capstone Warnings & Fallbacks ---

@pytest.mark.asyncio
async def test_assemble_instructions_decimal_base_address():
    """Test parsing of integer base address in decimal format."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions("nop", arch="x86", mode="64", base_address="4096")
        assert result.status == "success"
        assert result.data["base_address"] == "0x1000"


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_missing():
    """Test warning output when Capstone is unavailable."""
    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", None)
    ):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "Capstone not available" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_unsupported_mode():
    """Test warning when Capstone does not support the mode/architecture configuration (e.g. ARM v8)."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions("nop", arch="arm", mode="v8")
        assert result.status == "success"
        assert "Verification not supported for arm/v8" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_no_instructions():
    """Test warning when Capstone fails to disassemble any instructions (0 instruction count)."""
    class MockCsEmpty:
        def __init__(self, arch, mode): pass
        def disasm(self, code, addr):
            return []

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", MockCsEmpty)
    ):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "No instructions disassembled" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_cserror():
    """Test warning when Capstone disassembly throws CsError."""
    class MockCsError:
        def __init__(self, arch, mode): pass
        def disasm(self, code, addr):
            from reversecore_mcp.tools.common.assembler import CsError
            if CsError is Exception:
                raise CsError("Mock disassembly failure")
            else:
                raise CsError(1)

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", MockCsError)
    ):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "Disassembly verification failed" in result.data["verification"]
```
