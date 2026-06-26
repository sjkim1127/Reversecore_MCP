# Decompilation Guide

Decompilation converts raw binary machine instructions back into high-level human-readable pseudo-C code.

Reversecore MCP provides native decompilation powered by the **r2ghidra** plugin, which integrates the Ghidra decompiler engine directly inside Radare2. This native approach runs **without a JVM or Java installation**, providing fast decompilation with low memory usage.

---

## 1. Basic Decompilation

To generate pseudo-C code for a specific function name or virtual address:

```python
# Decompile the main function
r2_decompile(file_path="malware.elf", function_name="main")
```

Under the hood, `r2ghidra` performs:
1. Entrypoint mapping and basic block parsing.
2. Control flow analysis and structure translation.
3. Variable name and type propagation.

---

## 2. Structure Recovery

C++ class layouts, object structures, and struct allocations can be automatically recovered from pointer offsets and offset comparisons:

```python
# Recover C structures referenced by a function
r2_recover_structures(file_path="malware.elf", function_address="0x401500")
```

Recovered structs are saved into a stateful SQLite annotation database. You can review them or create your own custom types to assist the decompiler.

---

## 3. Function & Control Flow Analysis

Obtain detailed analysis of variable definitions, parameter sizes, and stack frame layouts for a specific function:

```python
# Deep analyze function prototype and variables
r2_analyze_function(file_path="malware.elf", function_address="main")

# Generate the call graph (callers and callees)
r2_get_call_graph(file_path="malware.elf", function_address="main")
```

---

## 4. Decompiled Code Patterns

When analyzing decompiled pseudo-C code, look for these common compiler patterns:

### String Comparisons
Used for checking licensing, passwords, or command parameters:
```c
if (strcmp(param_1, "admin_pass") == 0) {
    // Authenticated path
}
```

### Memory Allocation
Look for buffer allocations which could be vulnerable to overflows:
```c
void *pvVar1 = malloc(0x200);
memcpy(pvVar1, param_1, param_2); // Potential overflow if param_2 > 0x200
```

### Socket Communications
Standard C network socket code:
```c
sVar1 = socket(2, 1, 6);
connect(sVar1, &addr, 16);
send(sVar1, "HELLO", 5, 0);
```

---

## Troubleshooting

### Tool Timeout
For large or obfuscated binaries, decompilation can take longer. Increase the default timeout parameter:

```python
# Run with a 10-minute timeout limit
r2_decompile(file_path="large_game.bin", function_name="complex_loop", timeout=600)
```
