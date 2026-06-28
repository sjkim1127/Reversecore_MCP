# Test Coverage Gap Analysis: `assembler.py`

This report provides a detailed analysis of the test coverage gaps in `reversecore_mcp/tools/common/assembler.py` compared against `tests/unit/tools/common/test_assembler.py`. It presents exact uncovered lines, branches, and exception paths, followed by a precise testing strategy and mock setups required to achieve 100% statement and branch coverage.

---

## 1. Executive Summary

- **File under analysis**: `reversecore_mcp/tools/common/assembler.py` (376 lines)
- **Current Test File**: `tests/unit/tools/common/test_assembler.py`
- **Current Statement Coverage**: **59%** (81 out of 197 executable lines are uncovered)
- **Primary Gaps Identified**:
  1. **Module-level import fallbacks**: Missing tests for when `keystone` or `capstone` modules cannot be imported or have version-specific naming differences (e.g. `CS_ARCH_ARM64` / `CS_ARCH_AARCH64`).
  2. **Untested Architectures & Modes**: Missing mappings for MIPS, SPARC, PPC, SystemZ, and specific modes of x86 (16-bit), ARM (32-bit ARM, v8), and ARM64 (big-endian).
  3. **Exceptional/Error execution paths**: Uncovered code paths handling Keystone engine initialization failures, empty assemblies, and unexpected compilation exceptions.
  4. **Capstone verification warnings**: Uncovered warnings when Capstone is not available, when disassembly returns empty sequences, or when `CsError` is raised.

---

## 2. Detailed Gap Mapping

### A. Module-Level Import Fallbacks (Lines 25-45 and 77-95)
The file attempts to import `keystone` and `capstone`. If they fail, it sets fallbacks:
- **Keystone import error (Lines 25-45)**: Defines fallback constants and sets `Ks = None`.
- **Capstone import error (Lines 77-95)**: Defines fallback constants and sets `Cs = None`.
- **Capstone architecture rename blocks (Lines 67-70 & 73-76)**:
  ```python
  67:     try:
  68:         from capstone import CS_ARCH_ARM64
  69:     except ImportError:
  70:         from capstone import CS_ARCH_AARCH64 as CS_ARCH_ARM64
  ```
  and
  ```python
  73:     try:
  74:         from capstone import CS_ARCH_SYSZ
  75:     except ImportError:
  76:         from capstone import CS_ARCH_SYSTEMZ as CS_ARCH_SYSZ
  ```
- **Uncovered lines**: 70, 76, 77-95 (since capstone succeeds to import in the test environment, these fallback paths are never hit). If tested in an environment where Keystone is installed, 25-45 will also be uncovered.

### B. `get_keystone_params` Gaps (Lines 120-189)
Maps architectures and modes to Keystone constants.
- **x86 Mode (Line 122)**: `mode_clean in ("16", "v16")` is not tested.
- **ARM Mode (Lines 135, 139)**: `mode_clean == "arm"` and `mode_clean == "v8"` are not tested.
- **ARM64 Mode (Line 149)**: Big-endian arm64 mode (`ks_mode = KS_MODE_BIG_ENDIAN`) is not tested.
- **MIPS Architecture (Lines 153-163)**: Uncovered. Tests both MIPS32 vs MIPS64 and Big vs Little Endian branches.
- **SPARC Architecture (Lines 166-171)**: Uncovered. Tests SPARC32 vs SPARC64 and Endianness.
- **PPC Architecture (Lines 174-179)**: Uncovered. Tests PPC64 vs PPC32 and Endianness.
- **SystemZ Architecture (Line 182)**: Uncovered.

### C. `get_capstone_params` Gaps (Lines 204-253)
Maps architectures and modes to Capstone constants.
- **x86 Mode (Line 206)**: `mode_clean in ("16", "v16")` is not tested.
- **ARM Mode (Line 214)**: `mode_clean == "thumb"` is not tested.
- **ARM64 Mode (Lines 219-222)**: Uncovered.
- **MIPS Architecture (Lines 225-232)**: Uncovered.
- **SPARC Architecture (Lines 235-240)**: Uncovered.
- **PPC Architecture (Lines 243-248)**: Uncovered.
- **SystemZ Architecture (Line 251)**: Uncovered.

### D. `assemble_instructions` Logic & Exception Gaps (Lines 308-338)
- **Decimal Base Address Parsing (Line 312)**: The branch parsing decimal strings (e.g. `"4096"` or `"0"`) is not tested.
- **Keystone Init Failure (Lines 322-323)**:
  ```python
  322:     except KsError as e:
  323:         raise ToolExecutionError(f"Failed to initialize Keystone engine: {e}")
  ```
  This is never raised in tests because the mock `Ks` constructor succeeds.
- **Empty Keystone Encoding (Lines 330-331)**:
  ```python
  330:         if encoding is None:
  331:             raise ToolExecutionError("Keystone compilation returned empty encoding.")
  ```
- **ToolExecutionError Propagation (Line 333)**:
  ```python
  332:     except ToolExecutionError:
  333:         raise
  ```
- **Generic Exception handling inside `ks.asm` (Lines 336-338)**:
  ```python
  336:     except Exception as e:
  337:         # Catch any other exception from ks.asm()
  338:         raise ToolExecutionError(f"Assembly compilation failed: {type(e).__name__}: {e}")
  ```

### E. Capstone Verification Warnings (Lines 356-362)
- **Capstone returns empty disassembly list (Line 356)**:
  ```python
  356:                     verification_text = "Capstone warning: No instructions disassembled (invalid byte sequence or alignment)."
  ```
- **Capstone raises CsError (Lines 357-358)**:
  ```python
  357:             except CsError as e:
  358:                 verification_text = f"Capstone warning: Disassembly verification failed: {e}"
  ```
- **Capstone unsupported architecture (Lines 359-360)**:
  ```python
  359:         else:
  360:             verification_text = f"Capstone warning: Verification not supported for {arch}/{mode}."
  ```
- **Capstone not available/installed (Lines 361-362)**:
  ```python
  361:     else:
  362:         verification_text = "Capstone warning: Capstone not available for disassembly verification."
  ```

---

## 3. Precise Testing Strategy & Recommended Test Cases

To cover all lines and branches without modifying production code, we recommend adding the following structured tests inside `tests/unit/tools/common/test_assembler.py`.

### A. Testing Module-Level Imports via Reloading
Since module-level imports run only once upon initial import, we can test their fallback paths by mocking the sys modules and reloading the module via `importlib.reload`.

```python
import sys
import importlib
from unittest.mock import patch, MagicMock
import pytest

def test_module_import_fallbacks():
    # 1. Test Keystone ImportError fallback
    with patch.dict(sys.modules, {"keystone": None}):
        import reversecore_mcp.tools.common.assembler as asm
        importlib.reload(asm)
        assert asm.Ks is None
        assert asm.KS_ARCH_X86 == 4
        assert asm.KS_MODE_16 == 2

    # 2. Test Capstone ImportError fallback
    with patch.dict(sys.modules, {"capstone": None}):
        import reversecore_mcp.tools.common.assembler as asm
        importlib.reload(asm)
        assert asm.Cs is None
        assert asm.CS_ARCH_X86 == 4

    # 3. Test Capstone version fallback for CS_ARCH_ARM64 (rename case)
    mock_capstone = MagicMock()
    del mock_capstone.CS_ARCH_ARM64
    mock_capstone.CS_ARCH_AARCH64 = 999
    with patch.dict(sys.modules, {"capstone": mock_capstone}):
        import reversecore_mcp.tools.common.assembler as asm
        importlib.reload(asm)
        assert asm.CS_ARCH_ARM64 == 999

    # 4. Test Capstone version fallback for CS_ARCH_SYSZ (rename case)
    mock_capstone = MagicMock()
    del mock_capstone.CS_ARCH_SYSZ
    mock_capstone.CS_ARCH_SYSTEMZ = 888
    with patch.dict(sys.modules, {"capstone": mock_capstone}):
        import reversecore_mcp.tools.common.assembler as asm
        importlib.reload(asm)
        assert asm.CS_ARCH_SYSZ == 888

    # CRITICAL: Reload again to restore standard imports for other tests
    importlib.reload(asm)
```

### B. Parameter Mapping Test Cases
Test the clean mappings for various architectures and modes.

```python
@pytest.mark.parametrize(
    "arch,mode,expected_arch,expected_mode",
    [
        # x86 modes
        ("x86", "16", 4, 2), # KS_ARCH_X86, KS_MODE_16
        ("x86", "v16", 4, 2),
        # ARM modes
        ("arm", "arm", 1, 1), # KS_ARCH_ARM, KS_MODE_ARM
        ("arm", "v8", 1, 1 + 64), # KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_V8
        # ARM64 modes
        ("arm64", "big", 2, 1073741824), # KS_ARCH_ARM64, KS_MODE_BIG_ENDIAN
        ("arm64", "be", 2, 1073741824),
        # MIPS modes
        ("mips", "32", 3, 4 + 0), # KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN
        ("mips", "64", 3, 8 + 0), # KS_MODE_MIPS64 + KS_MODE_LITTLE_ENDIAN
        ("mips", "32 big", 3, 4 + 1073741824), # KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN
        ("mips", "64 be", 3, 8 + 1073741824),
        # SPARC modes
        ("sparc", "32", 6, 4), # KS_ARCH_SPARC, KS_MODE_32 (mapped to 4)
        ("sparc", "64", 6, 8),
        ("sparc", "64 big", 6, 8 + 1073741824),
        # PPC modes
        ("ppc", "64", 5, 8), # KS_ARCH_PPC, KS_MODE_64
        ("ppc", "32", 5, 4),
        ("ppc", "32 big", 5, 4 + 1073741824),
        # SystemZ
        ("systemz", "32", 7, 4), # KS_ARCH_SYSTEMZ, KS_MODE_32
    ]
)
def test_get_keystone_params_additional(arch, mode, expected_arch, expected_mode):
    with (
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_X86", 4),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_16", 2),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_ARM", 1),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_ARM", 1),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_V8", 64),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_ARM64", 2),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_BIG_ENDIAN", 1073741824),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_LITTLE_ENDIAN", 0),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_MIPS", 3),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_MIPS32", 4),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_MIPS64", 8),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_SPARC", 6),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_32", 4),
        patch("reversecore_mcp.tools.common.assembler.KS_MODE_64", 8),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_PPC", 5),
        patch("reversecore_mcp.tools.common.assembler.KS_ARCH_SYSTEMZ", 7),
    ):
        ks_arch, ks_mode = get_keystone_params(arch, mode)
        assert ks_arch == expected_arch
        assert ks_mode == expected_mode


@pytest.mark.parametrize(
    "arch,mode,expected_arch,expected_mode",
    [
        ("x86", "16", 4, 2), # CS_ARCH_X86, CS_MODE_16
        ("x86", "v16", 4, 2),
        ("arm", "thumb", 1, 16), # CS_ARCH_ARM, CS_MODE_THUMB
        ("arm64", "64", 2, 0), # CS_ARCH_ARM64, CS_MODE_ARM
        ("arm64", "64 big", 2, 2147483648), # CS_MODE_BIG_ENDIAN
        ("mips", "32", 3, 4 + 0), # CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN
        ("mips", "64 big", 3, 8 + 2147483648),
        ("sparc", "32", 6, 4), # CS_ARCH_SPARC, CS_MODE_32
        ("sparc", "64 big", 6, 8 + 2147483648),
        ("ppc", "64", 5, 8), # CS_ARCH_PPC, CS_MODE_64
        ("ppc", "32 big", 5, 4 + 2147483648),
        ("systemz", "32", 7, 4), # CS_ARCH_SYSZ, CS_MODE_32
    ]
)
def test_get_capstone_params_additional(arch, mode, expected_arch, expected_mode):
    with (
        patch("reversecore_mcp.tools.common.assembler.CS_ARCH_X86", 4),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_16", 2),
        patch("reversecore_mcp.tools.common.assembler.CS_ARCH_ARM", 1),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_THUMB", 16),
        patch("reversecore_mcp.tools.common.assembler.CS_ARCH_ARM64", 2),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_ARM", 0),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_BIG_ENDIAN", 2147483648),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_LITTLE_ENDIAN", 0),
        patch("reversecore_mcp.tools.common.assembler.CS_ARCH_MIPS", 3),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_MIPS32", 4),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_MIPS64", 8),
        patch("reversecore_mcp.tools.common.assembler.CS_ARCH_SPARC", 6),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_32", 4),
        patch("reversecore_mcp.tools.common.assembler.CS_MODE_64", 8),
        patch("reversecore_mcp.tools.common.assembler.CS_ARCH_PPC", 5),
        patch("reversecore_mcp.tools.common.assembler.CS_ARCH_SYSZ", 7),
    ):
        cs_arch, cs_mode = get_capstone_params(arch, mode)
        assert cs_arch == expected_arch
        assert cs_mode == expected_mode
```

### C. `assemble_instructions` Execution and Warning Gaps
We can test error states and warning branches by mocking `Ks` constructor, `ks.asm` method, and Capstone objects.

```python
@pytest.mark.asyncio
async def test_assemble_instructions_decimal_base_address():
    """Test base address parsing using a decimal string (covers line 312)."""
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions("nop", base_address="4096")
        assert result.status == "success"
        assert result.data["hex"] == "90"
        # base_address in result.metadata should format as hex
        assert result.metadata["base_address"] == "0x1000"


@pytest.mark.asyncio
async def test_assemble_instructions_ks_init_error():
    """Test tool error raised when Ks constructor fails (covers lines 322-323)."""
    from reversecore_mcp.tools.common.assembler import KsError
    def failing_ks_init(*args, **kwargs):
        raise KsError("Mock Initialization Error")

    with patch("reversecore_mcp.tools.common.assembler.Ks", failing_ks_init):
        result = await assemble_instructions("nop")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "Failed to initialize Keystone" in result.error_message


@pytest.mark.asyncio
async def test_assemble_instructions_empty_encoding():
    """Test tool error raised when ks.asm returns None (covers lines 330-331)."""
    class EmptyKsInstance:
        def __init__(self, arch, mode): pass
        def asm(self, code, addr=0):
            return None, 0

    with patch("reversecore_mcp.tools.common.assembler.Ks", EmptyKsInstance):
        result = await assemble_instructions("nop")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "returned empty encoding" in result.error_message


@pytest.mark.asyncio
async def test_assemble_instructions_generic_exception():
    """Test ToolExecutionError wrapping generic exceptions in ks.asm (covers lines 336-338)."""
    class CrashyKsInstance:
        def __init__(self, arch, mode): pass
        def asm(self, code, addr=0):
            raise RuntimeError("Out of memory")

    with patch("reversecore_mcp.tools.common.assembler.Ks", CrashyKsInstance):
        result = await assemble_instructions("nop")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "RuntimeError: Out of memory" in result.error_message


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_not_installed():
    """Test capstone unavailable warning message (covers lines 361-362)."""
    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", None)
    ):
        result = await assemble_instructions("nop")
        assert result.status == "success"
        assert "Capstone not available" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_unsupported_arch():
    """Test capstone unsupported arch warning (covers lines 359-360)."""
    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.get_capstone_params", return_value=(None, 0))
    ):
        result = await assemble_instructions("nop")
        assert result.status == "success"
        assert "Verification not supported" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_no_instructions():
    """Test warning when capstone disassembler returns empty list (covers line 356)."""
    class EmptyCs:
        def __init__(self, arch, mode): pass
        def disasm(self, bytes_data, addr):
            return [] # Empty list of instructions

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", EmptyCs)
    ):
        result = await assemble_instructions("nop")
        assert result.status == "success"
        assert "No instructions disassembled" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_cs_error():
    """Test warning when capstone disassembler raises CsError (covers lines 357-358)."""
    from capstone import CsError
    class ErrorCs:
        def __init__(self, arch, mode): pass
        def disasm(self, bytes_data, addr):
            raise CsError(4) # cs_errno = 4

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", ErrorCs)
    ):
        result = await assemble_instructions("nop")
        assert result.status == "success"
        assert "Disassembly verification failed" in result.data["verification"]
```

---

## 4. Verification Method

To verify that these changes achieve 100% test coverage for `assembler.py` once implemented:
1. Incorporate the test cases above into `tests/unit/tools/common/test_assembler.py`.
2. Run the test coverage command specifying only the assembler module:
   ```bash
   .venv/bin/pytest --cov=reversecore_mcp.tools.common.assembler tests/unit/tools/common/test_assembler.py --cov-report=term-missing
   ```
3. Ensure the test coverage output reaches **100%** coverage for `assembler.py`.
