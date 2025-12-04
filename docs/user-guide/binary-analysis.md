# Binary Analysis Guide

This guide covers the fundamental binary analysis capabilities of Reversecore MCP.

## Getting Started

### File Identification

Start by identifying the binary type:

```python
# Identify file type
run_file(file_path="/app/workspace/sample.exe")
```

**Output:**
```json
{
  "status": "success",
  "data": "PE32+ executable (GUI) x86-64, for MS Windows"
}
```

### String Extraction

Extract readable strings from the binary:

```python
# Extract strings with minimum length 6
run_strings(file_path="/app/workspace/sample.exe", min_length=6)
```

### Binary Parsing with LIEF

Get detailed PE/ELF metadata:

```python
parse_binary_with_lief(file_path="/app/workspace/sample.exe")
```

**Returns:**
- Headers (DOS, PE, Optional)
- Sections (.text, .data, .rdata, etc.)
- Imports and Exports
- Resources
- Digital signatures

## Disassembly

### Using Radare2

Execute Radare2 commands for deep analysis:

```python
# List all functions
run_radare2(file_path="/app/workspace/sample.exe", r2_command="afl")

# Disassemble main function
run_radare2(file_path="/app/workspace/sample.exe", r2_command="pdf @ main")

# Print cross-references to a function
run_radare2(file_path="/app/workspace/sample.exe", r2_command="axt @ sym.encrypt")
```

### Using Capstone

For fine-grained disassembly control:

```python
disassemble_with_capstone(
    file_path="/app/workspace/sample.exe",
    start_address="0x401000",
    length=100
)
```

## Cross-Reference Analysis

Track how functions and data are used:

```python
analyze_xrefs(
    file_path="/app/workspace/sample.exe",
    function_address="main"
)
```

**Returns:**
- Functions that call this address
- Functions called from this address
- Data references

## Structure Recovery

Recover C++ class structures automatically:

```python
recover_structures(
    file_path="/app/workspace/game.exe",
    function_address="main",
    fast_mode=True
)
```

**Output:**
```c
struct Player {
    int health;      // offset 0x0
    int armor;       // offset 0x4
    Vector3 position; // offset 0x8
};
```

## Binary Comparison

Compare two versions of a binary:

```python
diff_binaries(
    file_path_a="/app/workspace/app_v1.exe",
    file_path_b="/app/workspace/app_v2.exe"
)
```

**Use Cases:**
- Patch analysis (1-day exploit research)
- Malware variant comparison
- Game update analysis

## Code Emulation

Safely emulate code without execution:

```python
emulate_machine_code(
    file_path="/app/workspace/sample.exe",
    start_address="0x401000",
    instructions=50
)
```

**Returns:**
- Register states after emulation
- Memory changes
- Instruction trace

## IOC Extraction

Extract Indicators of Compromise:

```python
extract_iocs(
    text=strings_output,
    extract_ips=True,
    extract_urls=True,
    extract_emails=True
)
```

## Best Practices

1. **Start with triage**: Use `run_file` and `run_strings` first
2. **Parse metadata**: Use `parse_binary_with_lief` for structure info
3. **Find entry points**: Locate `main` or `_start` functions
4. **Follow xrefs**: Track interesting function calls
5. **Recover structures**: For C++ binaries, recover class layouts
6. **Document findings**: Use Report Tools to create analysis reports

## Next Steps

- [Decompilation Guide](decompilation.md) - Generate pseudo-C code
- [Threat Detection Guide](threat-detection.md) - Malware analysis
