# Binary Analysis Guide

This guide covers the fundamental binary analysis capabilities of Reversecore MCP, showing how to identify, disassemble, and analyze executables.

---

## 1. Initial File Triage

Before performing deep analysis, always begin by gathering metadata about the target file format, architecture, and packer.

### File Identification

Determine the binary type, target architecture, and compiler details:

```python
# Identify file type and basic properties
run_file(file_path="malware.elf")
```

### Packer & Compiler Detection

Check if the binary is packed (e.g. with UPX or VMProtect) using Detect It Easy (DIE) and identify compiler/linker fingerprints:

```python
# Query compiler and packer signatures
detect_packer(file_path="malware.elf")
```

### Static Metadata Parsing (LIEF)

Extract comprehensive file headers, section properties, import tables, and exports:

```python
# Parse detailed headers and imports
parse_binary_with_lief(file_path="malware.elf")
```

### String Extraction

Locate printable strings in the executable to identify URLs, IPs, API calls, and debug paths:

```python
# Extract strings with a minimum length of 6
run_strings(file_path="malware.elf", min_length=6)
```

### Capability Scan (CAPA)

Detect high-level capabilities (e.g. registry creation, encryption, network access) mapped to the MITRE ATT&CK framework:

```python
# Scan for capabilities
run_capa(file_path="malware.elf")
```

---

## 2. Disassembly

### Using Radare2

Execute specific Radare2 command strings directly on the file via connection pooling:

```python
# List functions inside the binary
Radare2_list_functions(file_path="malware.elf")

# Run a custom Radare2 command
Radare2_run_command(file_path="malware.elf", command="pdf @ main")
```

### Advanced Disassembly

Extract the assembly instructions of a function with compiler analysis:

```python
# Disassemble a function at a specific virtual address
Radare2_disassemble_function(file_path="malware.elf", offset="0x401000")
```

---

## 3. Emulation

Execute sections of instructions without running the untrusted binary on your host CPU. Reversecore MCP logs register states and memory updates at each emulation step.

### Emulating Instructions

```python
# Emulate 50 instructions starting from entrypoint
emulate_machine_code(
    file_path="malware.elf",
    start_address="0x401000",
    instructions=50
)
```

---

## 4. Binary Comparison (Diffing)

Compare two binary versions to analyze security patches, compiler differences, or malware mutations.

### Semantic Diffing

```python
# Compare app version 1 and version 2
diff_binaries(
    file_path_a="app_v1.bin",
    file_path_b="app_v2.bin"
)
```

---

## Best Practices for Triage

1. **Safety First**: Run analyses inside isolated virtual environments or the provided Docker container.
2. **Start Broad**: Use `run_file` -> `detect_packer` -> `run_strings` to verify what you're dealing with.
3. **Check Capabilities**: Use `run_capa` to establish the high-level purpose of the binary.
4. **Decompile Main**: Identify the entry point or `main` function and start analyzing control flow.
