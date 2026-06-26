# CI/CD Tool Testing Guide

This document describes how external binary analysis tools are validated and tested within the Reversecore MCP CI/CD pipelines and local test environments.

---

## 📋 Pipeline Overview

### CI/CD Workflow Stages

```
GitHub Actions (Push / Pull Request)
    ↓
┌─────────────────────────────────────────┐
│ 1. Security & Quality Gate              │
│    - Gitleaks (Secret auditing)         │
│    - Hadolint (Dockerfile linting)      │
│    - Ruff check & format (Python lint)  │
│    - Mypy (Type checks - strict mode)   │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 2. Dependencies Setup                   │
│    - Python 3.10 / 3.11 / 3.12          │
│    - System dependencies:               │
│      • radare2                          │
│      • yara                             │
│      • binwalk                          │
│      • binutils (objdump, nm)           │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 3. External Tool Verification           │
│    - Verify executable paths            │
│    - Check versions                     │
│    - Basic execution check              │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 4. Unit Testing (Async Event Loop)      │
│    - run pytest tests/unit/             │
│    - Coverage threshold gate (min 80%)  │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 5. Integration & MCP Testing            │
│    - Check tools installation           │
│    - E2E MCP JSON-RPC call invocation   │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 6. CodeQL Static Analysis               │
│    - GitHub SAST engine scanning        │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 7. Docker Build & Push (main only)      │
│    - Build multi-arch (amd64, arm64)    │
│    - Push to ghcr.io                    │
│    - Trivy vulnerability container scan │
└─────────────────────────────────────────┘
```

---

## 🔧 Core Tests Description

### 1. Tool Installation Checks

**File**: `tests/integration/test_tool_installation.py::TestToolInstallation`

Asserts that key terminal utilities are available in the system PATH:

- `test_radare2_installed`: Confirms `r2` command responds.
- `test_yara_installed`: Confirms `yara` version check works.
- `test_strings_installed`: Assures `strings` is accessible.
- `test_file_installed`: Assures `file` format utility is accessible.
- `test_binwalk_installed`: Checks for `binwalk` binary.
- `test_objdump_installed`: Assures `objdump` is available.

*Note*: If a tool is optional (like YARA or binwalk) and not installed locally, the integration test will execute `pytest.skip()` gracefully.

### 2. Execution Checks

**File**: `tests/integration/test_tool_installation.py::TestToolInvocation`

Validates that tools can parse mock inputs without throwing permissions or execution violations:

- `test_radare2_file_analysis`: Invokes `r2 -c afl` against a test ELF file.
- `test_file_command`: Asserts that `file` command correctly parses ELF metadata.
- `test_strings_command`: Runs string extraction against mock inputs.

### 3. MCP Call Integration Checks

**File**: `tests/integration/test_tool_installation.py::TestMCPToolCalls`

Ensures the FastMCP framework successfully maps natural language requests to tool functions:

- `test_radare2_analysis_tool`: Checks `r2_analysis` tool calls.
- `test_file_identification_tool`: Checks `run_file` tool calls.
- `test_mcp_tool_execution`: Starts a test server/client connection and invokes `list_workspace` E2E.

---

## 🖥️ Local Test Execution

### Verification Script

Run the verification helper script to inspect your local setup:

```bash
./scripts/verify-tools.sh
```

### Local Package Installation

#### macOS (Homebrew)
```bash
brew install radare2 graphviz
```

#### Ubuntu / Debian
```bash
sudo apt-get update
sudo apt-get install -y radare2 graphviz
```

### Running Specific Test Selections

```bash
# Run tool checks only
pytest tests/integration/test_tool_installation.py::TestToolInstallation -v

# Run MCP integration tests only
pytest tests/integration/test_tool_installation.py::TestMCPToolCalls -v

# Run entire integration test suite
pytest tests/integration/test_tool_installation.py -v
```

---

## 📊 CI/CD Workflow Rules

- **Optional Tools Failures**: Failing to find an optional dependency skips its related tests but does not fail the pipeline.
- **Required Tools Failures**: Missing core files (e.g. `file` or `strings`) fails the build immediately.
- **Coverage Policy**: Minimum coverage is strict (80%). If a commit drops coverage below 80%, the build fails.
