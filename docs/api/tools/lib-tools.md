# Library Tools API Reference

::: reversecore_mcp.tools.lib_tools
    options:
      show_source: true
      show_root_heading: true
      members:
        - parse_binary_with_lief
        - match_libraries
        - scan_for_versions
        - recover_structures
        - analyze_xrefs
        - generate_function_graph

## Overview

The Library Tools module provides binary analysis using Python libraries like LIEF, Capstone, and integration with analysis frameworks.

## Tools

### parse_binary_with_lief

Parse PE/ELF/Mach-O binary and extract metadata.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary file |

**Returns:**
```json
{
  "format": "PE",
  "architecture": "x86_64",
  "entrypoint": "0x00401000",
  "sections": [
    {"name": ".text", "virtual_address": "0x1000", "size": 4096},
    {"name": ".data", "virtual_address": "0x5000", "size": 1024}
  ],
  "imports": [
    {"library": "kernel32.dll", "functions": ["CreateFileW", "ReadFile"]}
  ],
  "exports": ["main", "init"]
}
```

### match_libraries

Match known library functions in binary to filter noise.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `signature_path` | str | No | Path to signature database |

**Use Case:**
Filter out standard library code to focus on user-defined functions.

**Returns:**
```json
{
  "matched_functions": [
    {"address": "0x401000", "library": "msvcrt", "name": "printf"},
    {"address": "0x401100", "library": "msvcrt", "name": "malloc"}
  ],
  "user_functions": [
    {"address": "0x402000", "name": "fcn.00402000"}
  ]
}
```

### scan_for_versions

Detect library versions and outdated components.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |

**Returns:**
```json
{
  "detected_versions": [
    {"library": "OpenSSL", "version": "1.0.2k", "vulnerable": true},
    {"library": "zlib", "version": "1.2.11", "vulnerable": false}
  ]
}
```

### recover_structures

Recover C++ class structures from binary code.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `function_address` | str | Yes | Function to analyze |
| `use_ghidra` | bool | No | Use Ghidra (default: True) |
| `fast_mode` | bool | No | Skip full analysis (default: True) |
| `timeout` | int | No | Timeout in seconds (default: 600) |

**Returns:**
```json
{
  "structures": [
    {
      "name": "Player",
      "size": 64,
      "fields": [
        {"offset": "0x0", "type": "int", "name": "health"},
        {"offset": "0x4", "type": "int", "name": "armor"},
        {"offset": "0x8", "type": "float[3]", "name": "position"}
      ]
    }
  ],
  "c_definitions": "struct Player { int health; int armor; float position[3]; };"
}
```

### analyze_xrefs

Analyze cross-references for a function or address.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `function_address` | str | Yes | Address or function name |
| `max_depth` | int | No | Analysis depth (default: 2) |

**Returns:**
```json
{
  "address": "0x401000",
  "callers": [
    {"address": "0x402000", "function": "main"}
  ],
  "callees": [
    {"address": "0x401500", "function": "encrypt"},
    {"address": "0x401600", "function": "send_data"}
  ],
  "data_refs": [
    {"address": "0x403000", "type": "string", "value": "config.dat"}
  ]
}
```

### generate_function_graph

Generate control flow graph for a function.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `function_address` | str | Yes | Function to graph |
| `output_format` | str | No | Format: "dot", "json" (default: "json") |

**Returns:**
```json
{
  "nodes": [
    {"id": "0x401000", "type": "entry"},
    {"id": "0x401010", "type": "basic_block"},
    {"id": "0x401050", "type": "exit"}
  ],
  "edges": [
    {"from": "0x401000", "to": "0x401010", "type": "flow"},
    {"from": "0x401010", "to": "0x401050", "type": "conditional"}
  ]
}
```

## Usage Examples

### Complete Binary Analysis

```python
# 1. Parse binary metadata
metadata = parse_binary_with_lief(file_path="/app/workspace/target.exe")

# 2. Filter library functions
libraries = match_libraries(file_path="/app/workspace/target.exe")

# 3. Analyze user functions
for func in libraries["user_functions"]:
    xrefs = analyze_xrefs(
        file_path="/app/workspace/target.exe",
        function_address=func["address"]
    )
    
# 4. Recover structures
structs = recover_structures(
    file_path="/app/workspace/target.exe",
    function_address="main"
)
```

### Security Audit

```python
# Check for vulnerable libraries
versions = scan_for_versions(file_path="/app/workspace/app.exe")

for lib in versions["detected_versions"]:
    if lib["vulnerable"]:
        print(f"⚠️ {lib['library']} {lib['version']} is vulnerable!")
```
