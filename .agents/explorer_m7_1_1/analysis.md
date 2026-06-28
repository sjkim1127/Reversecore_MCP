# Analysis of Test Coverage Gaps for `reversecore_mcp/tools/common/assembler.py`

This report analyzes the test coverage gaps for the assembler tool, identifies every uncovered line and branch, and recommends a comprehensive testing strategy to achieve 100% test coverage.

---

## 1. Summary of Findings
The `reversecore_mcp/tools/common/assembler.py` module currently achieves **57% line coverage** with 9 passing tests. The gaps reside in import fallbacks for missing/modern libraries, untested processor architectures/modes, Keystone engine initialization/compilation exceptions, and Capstone disassembly verification warnings.

---

## 2. Detailed Line and Branch Gaps

The table below catalogs all uncovered lines in `reversecore_mcp/tools/common/assembler.py` based on the pytest-cov output, along with the precise reason they are not currently executed.

| Line Number(s) | Category | Code Snippet / Context | Reason for Coverage Gap |
|---|---|---|---|
| **69-70** | Import Fallbacks | `except ImportError: from capstone import CS_ARCH_AARCH64 as CS_ARCH_ARM64` | `CS_ARCH_ARM64` exists in the local environment's Capstone, so the fallback is never triggered. |
| **75-76** | Import Fallbacks | `except ImportError: from capstone import CS_ARCH_SYSTEMZ as CS_ARCH_SYSZ` | `CS_ARCH_SYSZ` exists in the local environment's Capstone, so the fallback is never triggered. |
| **77-96** | Import Fallbacks | `except ImportError: Cs = None ... CS_MODE_THUMB = 16` | Capstone is installed in the test environment, so the outer `except ImportError` block is never reached. |
| **122** | Parameters | `if mode_clean in ("16", "v16"): return KS_ARCH_X86, KS_MODE_16` | `x86` with `16` or `v16` mode is never requested in Keystone parameter tests. |
| **135** | Parameters | `if mode_clean == "arm": return KS_ARCH_ARM, KS_MODE_ARM` | `arm` with `arm` mode is never requested in Keystone parameter tests. |
| **139** | Parameters | `elif mode_clean == "v8": return KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_V8` | `arm` with `v8` mode is never requested in Keystone parameter tests. |
| **149** | Parameters | `ks_mode = KS_MODE_BIG_ENDIAN` | `arm64` big-endian mode is never requested in Keystone parameter tests. |
| **153-163** | Parameters | `elif arch_clean == "mips": ...` | The `mips` architecture modes (32 vs 64, big vs little endian) are never requested in Keystone parameter tests. |
| **166-171** | Parameters | `elif arch_clean == "sparc": ...` | The `sparc` architecture modes (32 vs 64, big-endian) are never requested in Keystone parameter tests. |
| **174-179** | Parameters | `elif arch_clean == "ppc": ...` | The `ppc` architecture modes (32 vs 64, big-endian) are never requested in Keystone parameter tests. |
| **182** | Parameters | `elif arch_clean == "systemz": return KS_ARCH_SYSTEMZ, KS_MODE_32` | The `systemz` architecture is never requested in Keystone parameter tests. |
| **206** | Parameters | `if mode_clean in ("16", "v16"): return CS_ARCH_X86, CS_MODE_16` | `x86` with `16` or `v16` mode is never requested in Capstone parameter tests. |
| **214** | Parameters | `if mode_clean == "thumb": return CS_ARCH_ARM, CS_MODE_THUMB` | `arm` with `thumb` mode is never requested in Capstone parameter tests. |
| **219-222** | Parameters | `elif arch_clean == "arm64": ...` | The `arm64` architecture (big vs little endian) is never requested in Capstone parameter tests. |
| **225-232** | Parameters | `elif arch_clean == "mips": ...` | The `mips` architecture modes (32 vs 64, big vs little endian) are never requested in Capstone parameter tests. |
| **235-240** | Parameters | `elif arch_clean == "sparc": ...` | The `sparc` architecture modes (32 vs 64, big-endian) are never requested in Capstone parameter tests. |
| **243-248** | Parameters | `elif arch_clean == "ppc": ...` | The `ppc` architecture modes (32 vs 64, big-endian) are never requested in Capstone parameter tests. |
| **251** | Parameters | `elif arch_clean == "systemz": return CS_ARCH_SYSZ, CS_MODE_32` | The `systemz` architecture is never requested in Capstone parameter tests. |
| **322-323** | Exceptions | `except KsError as e: raise ToolExecutionError(...)` | Mocked Keystone initialization never raises `KsError`. |
| **331** | Exceptions | `if encoding is None: raise ToolExecutionError(...)` | Mocked Keystone compilation never returns `None` as the encoding. |
| **333** | Exceptions | `except ToolExecutionError: raise` | The `ToolExecutionError` raised within the block is never triggered. |
| **336-338** | Exceptions | `except KsError: raise ... except Exception as e: raise ...` | Mocked Keystone compilation never triggers generic `Exception` or uncovered `KsError` blocks. |
| **356** | Warning Paths | `verification_text = "Capstone warning: No instructions disassembled..."` | Capstone verification always successfully disassembles mocked byte inputs. |
| **357-358** | Warning Paths | `except CsError as e: verification_text = ...` | Capstone disassembly does not raise `CsError` in the existing tests. |
| **360** | Warning Paths | `verification_text = f"Capstone warning: Verification not supported for {arch}/{mode}."` | No test requests an architecture that is supported by Keystone but unsupported by Capstone (e.g. `arm`/`v8`). |
| **362** | Warning Paths | `verification_text = "Capstone warning: Capstone not available..."` | Capstone is always available in the test runtime context. |

---

## 3. Recommended Testing Strategy

To cover 100% of these lines and branches without modifying the source code of `assembler.py`, the following four-part testing strategy should be implemented:

1. **Dynamic Import Reloading (for lines 69-70, 75-76, 77-96)**:
   By patching `sys.modules` to hide or alter the `capstone` module and then reloading `reversecore_mcp.tools.common.assembler` via `importlib.reload`, we can simulate environments where Capstone is not installed or has modern renames. The module must be reloaded again at the end of the test to restore its original state.

2. **Parametrized Mode and Arch Mapping (for lines 122, 135, 139, 149, 153-163, 166-171, 174-179, 182, 206, 214, 219-222, 225-232, 235-240, 243-248, 251)**:
   Implement structured `pytest.mark.parametrize` matrices that exhaustively test every architecture and mode combination for both mapping functions (`get_keystone_params` and `get_capstone_params`).

3. **Engine Exception Mocking (for lines 322-323, 331, 333, 336-338)**:
   Mock the `Ks` class constructor and `Ks.asm` method to raise `KsError` and generic `Exception` types, as well as return `(None, 0)` to verify the empty encoding block.

4. **Capstone Disassembly Verification Mocking (for lines 356, 357-358, 360, 362)**:
   - Request `arm` with `v8` mode to naturally trigger Capstone's unsupported verification branch (`cs_arch` is `None` but `ks_arch` is valid).
   - Patch `assembler.Cs` to `None` to verify the Capstone unavailable message.
   - Patch `assembler.Cs` with mock disassembler classes that return empty lists or raise `CsError`.

---

## 4. Proposed Test Cases (Implementation Details)

The following test functions should be appended to `tests/unit/tools/common/test_assembler.py` to achieve full coverage:

```python
import importlib
import sys
from unittest.mock import MagicMock, patch
import pytest

from reversecore_mcp.core.exceptions import ToolExecutionError
import reversecore_mcp.tools.common.assembler as assembler

# ==============================================================================
# 1. IMPORT FALLBACK TESTS
# ==============================================================================

def test_imports_no_capstone():
    """Test importing when Capstone is not installed at all."""
    with patch.dict("sys.modules", {"capstone": None}):
        importlib.reload(assembler)
        assert assembler.Cs is None
        assert assembler.CsError is Exception
        assert assembler.CS_ARCH_ARM == 1
    # Restore original module state
    importlib.reload(assembler)


def test_imports_capstone_modern_renames():
    """Test Capstone v6+ modern renames migration fallback (ImportError on old names)."""
    class FakeCapstone:
        Cs = MagicMock()
        CsError = Exception
        CS_ARCH_ARM = 1
        CS_ARCH_MIPS = 3
        CS_ARCH_PPC = 5
        CS_ARCH_SPARC = 6
        CS_ARCH_X86 = 4
        CS_MODE_16 = 2
        CS_MODE_32 = 4
        CS_MODE_64 = 8
        CS_MODE_ARM = 0
        CS_MODE_BIG_ENDIAN = 2147483648
        CS_MODE_LITTLE_ENDIAN = 0
        CS_MODE_MIPS32 = 4
        CS_MODE_MIPS64 = 8
        CS_MODE_THUMB = 16
        CS_ARCH_AARCH64 = 999
        CS_ARCH_SYSTEMZ = 888

    with patch.dict("sys.modules", {"capstone": FakeCapstone()}):
        importlib.reload(assembler)
        assert assembler.CS_ARCH_ARM64 == 999
        assert assembler.CS_ARCH_SYSZ == 888
    # Restore original module state
    importlib.reload(assembler)


# ==============================================================================
# 2. PARAMETRIZED PARAMETER MAPPING TESTS
# ==============================================================================

@pytest.mark.parametrize(
    "arch,mode,expected_arch,expected_mode",
    [
        # x86 modes
        ("x86", "16", "KS_ARCH_X86", "KS_MODE_16"),
        ("x86", "v16", "KS_ARCH_X86", "KS_MODE_16"),
        ("x86", "32", "KS_ARCH_X86", "KS_MODE_32"),
        ("x86", "v32", "KS_ARCH_X86", "KS_MODE_32"),
        ("x86", "64", "KS_ARCH_X86", "KS_MODE_64"),
        ("x86", "v64", "KS_ARCH_X86", "KS_MODE_64"),
        # arm modes
        ("arm", "arm", "KS_ARCH_ARM", "KS_MODE_ARM"),
        ("arm", "thumb", "KS_ARCH_ARM", "KS_MODE_THUMB"),
        ("arm", "v8", "KS_ARCH_ARM", "KS_MODE_ARM + KS_MODE_V8"),
        # arm64 modes
        ("arm64", "64", "KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
        ("arm64", "big", "KS_ARCH_ARM64", "KS_MODE_BIG_ENDIAN"),
        ("arm64", "be", "KS_ARCH_ARM64", "KS_MODE_BIG_ENDIAN"),
        # mips modes
        ("mips", "32", "KS_ARCH_MIPS", "KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN"),
        ("mips", "64", "KS_ARCH_MIPS", "KS_MODE_MIPS64 + KS_MODE_LITTLE_ENDIAN"),
        ("mips", "32 big", "KS_ARCH_MIPS", "KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN"),
        ("mips", "64 be", "KS_ARCH_MIPS", "KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN"),
        # sparc modes
        ("sparc", "32", "KS_ARCH_SPARC", "KS_MODE_32"),
        ("sparc", "64", "KS_ARCH_SPARC", "KS_MODE_64"),
        ("sparc", "32 big", "KS_ARCH_SPARC", "KS_MODE_32 + KS_MODE_BIG_ENDIAN"),
        ("sparc", "64 be", "KS_ARCH_SPARC", "KS_MODE_64 + KS_MODE_BIG_ENDIAN"),
        # ppc modes
        ("ppc", "32", "KS_ARCH_PPC", "KS_MODE_32"),
        ("ppc", "64", "KS_ARCH_PPC", "KS_MODE_64"),
        ("ppc", "32 big", "KS_ARCH_PPC", "KS_MODE_32 + KS_MODE_BIG_ENDIAN"),
        ("ppc", "64 be", "KS_ARCH_PPC", "KS_MODE_64 + KS_MODE_BIG_ENDIAN"),
        # systemz
        ("systemz", "any", "KS_ARCH_SYSTEMZ", "KS_MODE_32"),
    ]
)
def test_get_keystone_params_all_combinations(arch, mode, expected_arch, expected_mode):
    exp_arch_val = getattr(assembler, expected_arch)
    if "+" in expected_mode:
        parts = [p.strip() for p in expected_mode.split("+")]
        exp_mode_val = sum(getattr(assembler, p) for p in parts)
    else:
        exp_mode_val = getattr(assembler, expected_mode)

    act_arch, act_mode = get_keystone_params(arch, mode)
    assert act_arch == exp_arch_val
    assert act_mode == exp_mode_val


@pytest.mark.parametrize(
    "arch,mode,expected_arch,expected_mode",
    [
        # x86 modes
        ("x86", "16", "CS_ARCH_X86", "CS_MODE_16"),
        ("x86", "v16", "CS_ARCH_X86", "CS_MODE_16"),
        ("x86", "32", "CS_ARCH_X86", "CS_MODE_32"),
        ("x86", "v32", "CS_ARCH_X86", "CS_MODE_32"),
        ("x86", "64", "CS_ARCH_X86", "CS_MODE_64"),
        ("x86", "v64", "CS_ARCH_X86", "CS_MODE_64"),
        ("x86", "invalid_mode", None, 0),
        # arm modes
        ("arm", "thumb", "CS_ARCH_ARM", "CS_MODE_THUMB"),
        ("arm", "arm", "CS_ARCH_ARM", "CS_MODE_ARM"),
        ("arm", "invalid_mode", None, 0),
        # arm64 modes
        ("arm64", "64", "CS_ARCH_ARM64", "CS_MODE_ARM"),
        ("arm64", "big", "CS_ARCH_ARM64", "CS_MODE_BIG_ENDIAN"),
        ("arm64", "be", "CS_ARCH_ARM64", "CS_MODE_BIG_ENDIAN"),
        # mips modes
        ("mips", "32", "CS_ARCH_MIPS", "CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN"),
        ("mips", "64", "CS_ARCH_MIPS", "CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN"),
        ("mips", "32 big", "CS_ARCH_MIPS", "CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN"),
        ("mips", "64 be", "CS_ARCH_MIPS", "CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN"),
        # sparc modes
        ("sparc", "32", "CS_ARCH_SPARC", "CS_MODE_32"),
        ("sparc", "64", "CS_ARCH_SPARC", "CS_MODE_64"),
        ("sparc", "32 big", "CS_ARCH_SPARC", "CS_MODE_32 + CS_MODE_BIG_ENDIAN"),
        ("sparc", "64 be", "CS_ARCH_SPARC", "CS_MODE_64 + CS_MODE_BIG_ENDIAN"),
        # ppc modes
        ("ppc", "32", "CS_ARCH_PPC", "CS_MODE_32"),
        ("ppc", "64", "CS_ARCH_PPC", "CS_MODE_64"),
        ("ppc", "32 big", "CS_ARCH_PPC", "CS_MODE_32 + CS_MODE_BIG_ENDIAN"),
        ("ppc", "64 be", "CS_ARCH_PPC", "CS_MODE_64 + CS_MODE_BIG_ENDIAN"),
        # systemz
        ("systemz", "any", "CS_ARCH_SYSZ", "CS_MODE_32"),
    ]
)
def test_get_capstone_params_all_combinations(arch, mode, expected_arch, expected_mode):
    if expected_arch is None:
        exp_arch_val = None
    else:
        exp_arch_val = getattr(assembler, expected_arch)

    if expected_mode == 0:
        exp_mode_val = 0
    elif "+" in expected_mode:
        parts = [p.strip() for p in expected_mode.split("+")]
        exp_mode_val = sum(getattr(assembler, p) for p in parts)
    else:
        exp_mode_val = getattr(assembler, expected_mode)

    act_arch, act_mode = get_capstone_params(arch, mode)
    assert act_arch == exp_arch_val
    assert act_mode == exp_mode_val


# ==============================================================================
# 3. ENGINE EXCEPTION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_assemble_instructions_decimal_base_address():
    """Test using decimal base address format."""
    from tests.unit.tools.common.test_assembler import MockKsInstance
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions("nop", arch="x86", mode="64", base_address="4096")
        assert result.status == "success"
        assert result.metadata["base_address"] == "0x1000"


@pytest.mark.asyncio
async def test_assemble_instructions_keystone_init_fail():
    """Test when Keystone engine initialization raises KsError."""
    from reversecore_mcp.tools.common.assembler import KsError
    def mock_ks_init(arch, mode):
        raise KsError("Mock Ks initialization error")

    with patch("reversecore_mcp.tools.common.assembler.Ks", mock_ks_init):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "Failed to initialize Keystone engine" in result.message


@pytest.mark.asyncio
async def test_assemble_instructions_keystone_empty_encoding():
    """Test when Keystone returns None as encoding, raising ToolExecutionError."""
    class MockKsEmptyEncoding:
        def __init__(self, arch, mode): pass
        def asm(self, code, addr=0):
            return None, 0

    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsEmptyEncoding):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "Keystone compilation returned empty encoding." in result.message


@pytest.mark.asyncio
async def test_assemble_instructions_generic_exception():
    """Test when Keystone assembly compilation raises a generic non-KsError Exception."""
    class MockKsGenericException:
        def __init__(self, arch, mode): pass
        def asm(self, code, addr=0):
            raise RuntimeError("Generic compilation failure")

    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsGenericException):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "error"
        assert result.details["exception_type"] == "ToolExecutionError"
        assert "Assembly compilation failed: RuntimeError" in result.message


# ==============================================================================
# 4. CAPSTONE WARNING & VERIFICATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_assemble_instructions_capstone_unsupported_verification():
    """Test warning output when Keystone supports target but Capstone does not (e.g. arm v8)."""
    from tests.unit.tools.common.test_assembler import MockKsInstance
    with patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance):
        result = await assemble_instructions("nop", arch="arm", mode="v8")
        assert result.status == "success"
        assert "Verification not supported for arm/v8" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_unavailable():
    """Test warning output when Capstone library is mock-uninstalled."""
    from tests.unit.tools.common.test_assembler import MockKsInstance
    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", None),
    ):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "Capstone not available" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_no_instructions():
    """Test warning output when disassembly fails to return instructions (invalid sequence or alignment)."""
    from tests.unit.tools.common.test_assembler import MockKsInstance
    class MockCsNoInstructions:
        def __init__(self, arch, mode): pass
        def disasm(self, encoding, base_addr):
            return []

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", MockCsNoInstructions),
    ):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "No instructions disassembled" in result.data["verification"]


@pytest.mark.asyncio
async def test_assemble_instructions_capstone_disasm_error():
    """Test warning output when Capstone disasm execution raises a CsError."""
    from tests.unit.tools.common.test_assembler import MockKsInstance
    from reversecore_mcp.tools.common.assembler import CsError

    class MockCsDisasmError:
        def __init__(self, arch, mode): pass
        def disasm(self, encoding, base_addr):
            raise CsError("Mock disassembly error")

    with (
        patch("reversecore_mcp.tools.common.assembler.Ks", MockKsInstance),
        patch("reversecore_mcp.tools.common.assembler.Cs", MockCsDisasmError),
    ):
        result = await assemble_instructions("nop", arch="x86", mode="64")
        assert result.status == "success"
        assert "Disassembly verification failed: Mock disassembly error" in result.data["verification"]
```
