# Enhanced CI/CD - Real Binary Verification

## 📋 Overview

This guide explains the verification pipeline for auditing system binaries, compiled test fixtures, and static tool integrations during CI/CD checks.

---

## 🎯 Verification Pipeline Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline v2.0                      │
│ 1. Environment Initialization                                │
│    ├─ Python matrix installation (3.10, 3.11, 3.12)         │
│    ├─ Tool binaries extraction (r2, YARA, binwalk)          │
│    └─ Dependencies setup                                    │
│                                                             │
│ 2. Compile Test Fixture Binaries                            │
│    ├─ Hello World (GCC compiled)                            │
│    ├─ Fibonacci (compiled with debug symbols)               │
│    ├─ Stripped binary (compiled without symbols)            │
│    └─ PIE binary (Position Independent Executable)          │
│                                                             │
│ 3. Tool Installation Audits                                 │
│    ├─ Check command-line availability                       │
│    ├─ Check version codes                                   │
│    └─ Log errors and skips                                  │
│                                                             │
│ 4. Executable Analysis Validation                           │
│    ├─ run 'file' command to assert format                   │
│    ├─ run 'strings' to extract printables                   │
│    ├─ run 'radare2' to disassemble blocks                   │
│    ├─ run 'objdump' to audit compiler flags                 │
│    └─ run 'nm' to list symbol tables                        │
│                                                             │
│ 5. Unit & Quality Tests Gate                                │
│    ├─ run unit test suite (1,520+ tests)                    │
│    └─ Enforce 80% coverage threshold                        │
│                                                             │
│ 6. Output Pipeline Telemetry                                │
│    ├─ Test execution summary                                │
│    ├─ Tool audit matrix                                     │
│    ├─ Coverage delta logs                                   │
│    └─ latency benchmarks                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Test Binary Targets

### 1. **hello_x64**
- **Description**: Standard Hello World executable compiled with GCC.
- **Attributes**: Debug symbols included, basic layout.
- **Purpose**: Validate baseline disassembly and symbol mapping.
- **Expected Results**:
  - `file`: `ELF 64-bit LSB executable`
  - `strings`: Contains target string `"Hello from test binary"`
  - `nm`: Discovers main entrypoint and standard library symbols.

### 2. **hello_x64_stripped**
- **Description**: A stripped version of `hello_x64`.
- **Attributes**: Debug symbols removed, sections collapsed.
- **Purpose**: Validate recovery of unnamed routines and test stripped binary parsing.
- **Expected Results**:
  - `file`: `ELF 64-bit LSB executable`
  - `nm`: Resolves no debug symbols.

### 3. **pie_x64**
- **Description**: Position Independent Executable (PIE) binary compiled with ASLR flags enabled.
- **Attributes**: Relocatable addresses.
- **Purpose**: Validate address translation helpers.
- **Expected Results**:
  - `file`: `ELF 64-bit LSB pie executable`
  - Entrypoint addresses mapped relative to virtual base offsets.

---

## 📊 Verification Matrix

| CLI Utility | Verification Metric | Expected Output | status |
|-------------|---------------------|-----------------|--------|
| **file** | Format identification | `ELF 64-bit...` | ✅ Required |
| **strings** | ASCII character extraction | `"Hello from test binary"` | ✅ Required |
| **radare2** | Function decompilation | list functions (`afl`) | ✅ Optional |
| **objdump** | Section disassembly | Assembly mnemonics | ✅ Required |
| **nm** | Symbol extraction | main address | ✅ Required |

---

## 🚀 Running Verification Locally

```bash
# 1. Compile test binaries
bash scripts/generate-test-binaries.sh

# 2. Run verification checks
./scripts/verify-tools.sh

# 3. Run unit test suite
pytest tests/unit/ -v --cov=reversecore_mcp --cov-fail-under=80

# 4. Run integration checks
pytest tests/integration/ -v
```

---

## 🔒 Reliability Controls

- **Isolation**: Every test run creates a unique, randomized temp directory to prevent state corruption.
- **Soft Skips**: If a tool is missing (e.g. Radare2 on local desktop development environments), the test prints a skip warning without triggering a pipeline build failure.
- **Conditional Marks**:
  ```python
  @pytest.mark.skipif(not shutil.which("r2"), reason="radare2 is required")
  def test_radare2_functionality():
      ...
  ```
