# Ghost Trace API Reference

::: reversecore_mcp.tools.ghost_trace
    options:
      show_source: true
      show_root_heading: true

## Overview

Ghost Trace is a specialized tool for detecting hidden malware behaviors that evade traditional static and dynamic analysis. It identifies "logic bombs", dormant backdoors, and anti-analysis techniques.

## Main Tool

### ghost_trace

Scan a binary for hidden malicious behaviors.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary to analyze |
| `timeout` | int | No | Analysis timeout (default: 300s) |
| `deep_scan` | bool | No | Enable thorough analysis (default: False) |

**Returns:**
```json
{
  "status": "success",
  "hidden_behaviors": [
    {
      "type": "orphan_function",
      "address": "0x00401500",
      "risk": "high",
      "description": "Function not reachable from entry point",
      "indicators": ["No callers in call graph", "Contains network APIs"]
    },
    {
      "type": "magic_value_trigger",
      "address": "0x00401234",
      "risk": "medium",
      "value": "0xDEADBEEF",
      "description": "Hardcoded comparison value - potential activation trigger"
    },
    {
      "type": "time_bomb",
      "address": "0x00401300",
      "risk": "high",
      "trigger_date": "2025-01-01",
      "description": "Code path activated after specific date"
    }
  ],
  "summary": {
    "total_hidden": 3,
    "high_risk": 2,
    "medium_risk": 1,
    "low_risk": 0
  }
}
```

## Detection Categories

### Orphan Functions

Functions that exist in the binary but have no callers in the normal call graph.

**Indicators:**
- No cross-references from other functions
- Contains sensitive API calls (network, file, registry)
- May be triggered through function pointers or reflection

**Example:**
```c
// This function has no callers - hidden backdoor
void __hidden_backdoor() {
    connect(sock, &c2_server, sizeof(c2_server));
    // Remote access code
}
```

### Magic Value Triggers

Hardcoded values used to activate hidden functionality.

**Indicators:**
- Comparison with unusual constants
- Environment variable checks
- Registry key value comparisons

**Example:**
```c
if (input == 0xDEADBEEF) {
    activate_payload();  // Hidden functionality
}
```

### Time Bombs

Code that activates based on date/time conditions.

**Indicators:**
- GetSystemTime/GetLocalTime calls
- Date string comparisons
- Unix timestamp checks

**Example:**
```c
GetSystemTime(&st);
if (st.wYear >= 2025 && st.wMonth >= 6) {
    encrypt_files();  // Ransomware activation
}
```

### Anti-Sandbox Checks

Code designed to detect analysis environments.

**Indicators:**
- IsDebuggerPresent calls
- VM detection (CPUID, registry checks)
- Sandbox artifacts (files, processes, usernames)

**Example:**
```c
if (IsDebuggerPresent()) {
    exit(0);  // Terminate if debugged
}
```

### Environment Triggers

Activation based on specific system configuration.

**Indicators:**
- Username/computername checks
- Domain membership verification
- Specific file existence checks

**Example:**
```c
if (strcmp(getenv("USERNAME"), "target_user") == 0) {
    deploy_payload();  // Targeted attack
}
```

## Usage Examples

### Basic Scan

```python
result = ghost_trace(file_path="/app/workspace/suspicious.exe")

for behavior in result["hidden_behaviors"]:
    print(f"[{behavior['risk'].upper()}] {behavior['type']}")
    print(f"  Address: {behavior['address']}")
    print(f"  {behavior['description']}")
```

### Deep Scan with Extended Timeout

```python
result = ghost_trace(
    file_path="/app/workspace/complex_malware.exe",
    timeout=600,
    deep_scan=True
)
```

### Integration with Trinity Defense

Ghost Trace is automatically invoked as Phase 1 of Trinity Defense:

```python
# Full pipeline
trinity_defense(file_path="/app/workspace/malware.exe")

# Equivalent to:
# 1. ghost_trace() - DISCOVER
# 2. neural_decompile() - UNDERSTAND  
# 3. adaptive_vaccine() - NEUTRALIZE
```

## Best Practices

1. **Start with basic scan**: Use default settings first
2. **Enable deep_scan for APT**: Advanced threats require thorough analysis
3. **Combine with emulation**: Use `emulate_machine_code` on suspicious functions
4. **Document findings**: Add to session IOCs for reporting

## Related Tools

- [Neural Decompiler](neural-decompiler.md) - Understand detected behaviors
- [Trinity Defense](trinity-defense.md) - Automated response pipeline
- [CLI Tools](cli-tools.md) - Manual analysis commands
