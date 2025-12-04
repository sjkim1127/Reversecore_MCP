# Neural Decompiler API Reference

::: reversecore_mcp.tools.neural_decompiler
    options:
      show_source: true
      show_root_heading: true

## Overview

Neural Decompiler enhances raw decompiled code with AI-powered analysis, transforming cryptic variable names and pointer arithmetic into human-readable code with meaningful annotations.

## Main Tool

### neural_decompile

Decompile a function with AI-enhanced output.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary |
| `function_address` | str | Yes | Function address or name |
| `enhance_names` | bool | No | Apply semantic naming (default: True) |
| `add_comments` | bool | No | Add explanatory comments (default: True) |
| `timeout` | int | No | Timeout in seconds (default: 300) |

**Returns:**
```json
{
  "status": "success",
  "original_code": "int fcn.00401000(int param_1, char *param_2) { ... }",
  "enhanced_code": "int authenticate_user(int user_id, char *password) { ... }",
  "annotations": [
    {
      "line": 5,
      "comment": "// XOR decryption loop - decodes embedded string"
    },
    {
      "line": 12,
      "comment": "// Network connection to C2 server"
    }
  ],
  "inferred_types": [
    {"variable": "local_20", "inferred": "SOCKET", "reason": "Used with WSAConnect"}
  ]
}
```

## Enhancements

### Semantic Variable Naming

Transforms generic names to meaningful identifiers:

| Original | Enhanced | Reason |
|----------|----------|--------|
| `iVar1` | `socket_fd` | Used with socket APIs |
| `pcVar1` | `decrypted_string` | Result of decryption loop |
| `param_1` | `user_id` | Integer param passed to auth |
| `local_20` | `file_handle` | Used with CreateFile |
| `uVar3` | `buffer_size` | Used in malloc call |

### Structure Inference

Converts pointer arithmetic to structure access:

**Before:**
```c
*(int *)(param_1 + 4) = 100;
*(float *)(param_1 + 8) = 1.5;
```

**After:**
```c
// Inferred: param_1 is Player*
player->health = 100;
player->speed = 1.5;
```

### Smart Annotations

Adds contextual comments explaining code behavior:

```c
// XOR decryption with key 0x55
for (i = 0; i < len; i++) {
    buffer[i] ^= 0x55;
}

// Establish C2 connection
connect(sock, (struct sockaddr*)&server, sizeof(server));

// Registry persistence
RegSetValueExW(hKey, L"Run", 0, REG_SZ, payload_path, path_len);
```

## Usage Examples

### Basic Enhancement

```python
result = neural_decompile(
    file_path="/app/workspace/malware.exe",
    function_address="main"
)

print(result["enhanced_code"])
```

### With Custom Options

```python
result = neural_decompile(
    file_path="/app/workspace/malware.exe",
    function_address="0x00401234",
    enhance_names=True,
    add_comments=True,
    timeout=600
)

# Print annotations
for ann in result["annotations"]:
    print(f"Line {ann['line']}: {ann['comment']}")
```

### Combined with Ghost Trace

```python
# First detect hidden behaviors
hidden = ghost_trace(file_path="/app/workspace/malware.exe")

# Then understand each suspicious function
for behavior in hidden["hidden_behaviors"]:
    enhanced = neural_decompile(
        file_path="/app/workspace/malware.exe",
        function_address=behavior["address"]
    )
    print(f"\n=== {behavior['type']} at {behavior['address']} ===")
    print(enhanced["enhanced_code"])
```

## Integration with Trinity Defense

Neural Decompiler is Phase 2 (UNDERSTAND) of the Trinity Defense pipeline:

```
Ghost Trace     Neural Decompiler    Adaptive Vaccine
(DISCOVER)  →   (UNDERSTAND)      →  (NEUTRALIZE)
    │                 │                    │
    │                 │                    │
Find hidden      Explain intent      Generate defense
behaviors        with AI analysis    (YARA + patches)
```

## Comparison with Standard Decompilation

| Aspect | Standard | Neural Decompiler |
|--------|----------|-------------------|
| Variable names | `iVar1`, `local_20` | `socket_fd`, `decrypted_key` |
| Structures | Pointer arithmetic | Named field access |
| Comments | None | Context-aware annotations |
| API understanding | Raw calls | Purpose explanation |

## Best Practices

1. **Use after triage**: Run Ghost Trace first to identify targets
2. **Verify inferences**: AI suggestions may need validation
3. **Document findings**: Copy enhanced code to reports
4. **Combine with structures**: Use `recover_structures` for complex types

## Related Tools

- [Ghost Trace](ghost-trace.md) - Detect hidden behaviors
- [Trinity Defense](trinity-defense.md) - Full pipeline
- [Lib Tools](lib-tools.md) - Structure recovery
