# CLI Tools API Reference

::: reversecore_mcp.tools.cli_tools
    options:
      show_source: true
      show_root_heading: true
      members:
        - run_file
        - run_strings
        - run_binwalk
        - run_binwalk_extract
        - run_radare2
        - run_yara
        - disassemble_with_capstone
        - emulate_machine_code
        - diff_binaries
        - extract_iocs
        - generate_signature
        - scan_workspace

## Overview

The CLI Tools module provides wrappers around command-line binary analysis tools.

## Tools

### run_file

Identify file type using the `file` command.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the file to analyze |
| `timeout` | int | No | Timeout in seconds (default: 120) |

**Example:**
```python
run_file(file_path="/app/workspace/sample.exe")
```

### run_strings

Extract printable strings from a binary.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the file |
| `min_length` | int | No | Minimum string length (default: 4) |
| `timeout` | int | No | Timeout in seconds (default: 120) |
| `max_output_size` | int | No | Max output bytes (default: 10MB) |

### run_binwalk

Scan binary for embedded files and signatures.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the file |
| `timeout` | int | No | Timeout in seconds (default: 120) |

### run_radare2

Execute Radare2 commands for binary analysis.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `r2_command` | str | Yes | Radare2 command to execute |
| `timeout` | int | No | Timeout in seconds (default: 120) |
| `max_output_size` | int | No | Max output bytes (default: 10MB) |

**Common Commands:**

| Command | Description |
|---------|-------------|
| `afl` | List all functions |
| `pdf @ main` | Disassemble main function |
| `axt @ addr` | Cross-references to address |
| `ii` | List imports |
| `iE` | List exports |
| `izz` | List strings |

### disassemble_with_capstone

Disassemble code using Capstone engine.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `start_address` | str | Yes | Start address (e.g., "0x401000") |
| `length` | int | No | Number of bytes (default: 100) |

### emulate_machine_code

Emulate code execution using Radare2 ESIL.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `start_address` | str | Yes | Start address |
| `instructions` | int | No | Number of instructions (default: 50, max: 1000) |
| `timeout` | int | No | Timeout in seconds (default: 120) |

### diff_binaries

Compare two binary files for code changes.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path_a` | str | Yes | Path to first binary |
| `file_path_b` | str | Yes | Path to second binary |
| `function_name` | str | No | Specific function to compare |
| `timeout` | int | No | Timeout in seconds (default: 120) |

**Returns:**
```json
{
  "similarity": 0.95,
  "changes": [
    {"address": "0x401050", "type": "code_change", "description": "..."}
  ]
}
```

### extract_iocs

Extract Indicators of Compromise from text.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `text` | str | Yes | Text to analyze |
| `extract_ips` | bool | No | Extract IP addresses (default: True) |
| `extract_urls` | bool | No | Extract URLs (default: True) |
| `extract_emails` | bool | No | Extract emails (default: True) |
| `limit` | int | No | Max IOCs per category (default: 100) |

### generate_signature

Generate YARA signature from binary code.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `address` | str | Yes | Start address for signature |
| `length` | int | No | Bytes to extract (default: 32) |
| `timeout` | int | No | Timeout in seconds (default: 120) |

### scan_workspace

Batch scan all files in workspace.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_patterns` | list | No | Glob patterns (default: ["*"]) |
| `timeout` | int | No | Global timeout (default: 600) |
