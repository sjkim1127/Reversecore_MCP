# Decompilation Guide

This guide covers advanced decompilation techniques using Reversecore MCP's Ghidra and Radare2 integration.

## Overview

Decompilation converts machine code back to human-readable pseudo-C code. Reversecore MCP provides two decompilation backends:

| Backend | Strengths | Best For |
|---------|-----------|----------|
| **Ghidra** | Superior type recovery, structure propagation | Complex C++ binaries |
| **Radare2 (r2dec)** | Faster, lighter | Quick analysis, smaller binaries |

## Smart Decompilation

The `smart_decompile` tool automatically selects the best backend:

```python
smart_decompile(
    file_path="/app/workspace/sample.exe",
    function_address="main"
)
```

**Features:**
- Automatic backend selection
- Timeout handling
- Error recovery with fallback

## Ghidra Decompilation

For advanced analysis, use Ghidra directly:

```python
get_pseudo_code(
    file_path="/app/workspace/sample.exe",
    function_address="0x401000",
    use_ghidra=True
)
```

### Ghidra Advantages

1. **Type Recovery**: Better inference of data types
2. **Structure Propagation**: Recognizes struct field access
3. **Symbol Recovery**: Maintains function and variable names
4. **Call Analysis**: Accurate function signature detection

### Performance Tips

```python
# For large binaries, use fast_mode
get_pseudo_code(
    file_path="/app/workspace/large_game.exe",
    function_address="main",
    use_ghidra=True,
    fast_mode=True  # Skip full binary analysis
)
```

## Neural Decompiler

Enhance decompiled output with AI-powered analysis:

```python
neural_decompile(
    file_path="/app/workspace/sample.exe",
    function_address="main"
)
```

**Enhancements:**
- Semantic variable naming (`iVar1` → `socket_fd`)
- Structure inference from pointer arithmetic
- Inline comments explaining operations

## Radare2 Decompilation

For quick analysis:

```python
get_pseudo_code(
    file_path="/app/workspace/sample.exe",
    function_address="main",
    use_ghidra=False  # Use r2dec
)
```

### When to Use r2dec

- Quick triage of small functions
- When Ghidra is unavailable
- ARM/MIPS architectures (broader support)

## Decompilation Workflow

### 1. Identify Target Functions

```python
# List all functions
run_radare2(file_path="/app/workspace/sample.exe", r2_command="afl")
```

### 2. Analyze Cross-References

```python
# Find calls to interesting APIs
run_radare2(
    file_path="/app/workspace/sample.exe",
    r2_command="axt @ sym.imp.CreateFileW"
)
```

### 3. Decompile Key Functions

```python
smart_decompile(
    file_path="/app/workspace/sample.exe",
    function_address="fcn.00401234"
)
```

### 4. Recover Structures

```python
recover_structures(
    file_path="/app/workspace/sample.exe",
    function_address="fcn.00401234"
)
```

### 5. Document Findings

```python
start_analysis_session(sample_path="/app/workspace/sample.exe")
# ... analysis ...
create_analysis_report(template_type="full_analysis")
```

## Understanding Decompiled Output

### Variable Types

| Pattern | Likely Type |
|---------|-------------|
| `iVar1` | Integer |
| `uVar1` | Unsigned integer |
| `pcVar1` | Char pointer (string) |
| `pvVar1` | Void pointer |
| `local_XX` | Stack variable at offset XX |
| `param_1` | First function parameter |

### Common Patterns

**String Comparison:**
```c
if (strcmp(param_1, "password") == 0) {
    // Authentication check
}
```

**Memory Allocation:**
```c
pvVar1 = malloc(0x100);
if (pvVar1 == NULL) {
    // Error handling
}
```

**Loop Pattern:**
```c
for (local_c = 0; local_c < param_2; local_c = local_c + 1) {
    // Iteration
}
```

## Troubleshooting

### Timeout Issues

For large functions:
```python
get_pseudo_code(
    file_path="/app/workspace/sample.exe",
    function_address="main",
    timeout=600  # Increase timeout
)
```

### Missing Types

Use structure recovery first:
```python
recover_structures(file_path="/app/workspace/sample.exe", function_address="main")
# Then decompile
smart_decompile(file_path="/app/workspace/sample.exe", function_address="main")
```

## Next Steps

- [Threat Detection Guide](threat-detection.md) - Malware analysis
- [Ghost Trace API](../api/tools/ghost-trace.md) - Hidden behavior detection
