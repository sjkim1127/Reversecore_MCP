# Threat Detection Guide

This guide covers malware analysis and threat detection using Reversecore MCP's specialized tools.

## Overview

Reversecore MCP provides a comprehensive threat detection pipeline:

```
┌─────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐
│  Triage │ →  │Ghost Trace│ →  │  Neural  │ →  │ Defense  │
│         │    │  Discover │    │Understand│    │Neutralize│
└─────────┘    └───────────┘    └──────────┘    └──────────┘
```

## Trinity Defense System

The Trinity Defense System automates the entire threat analysis pipeline:

```python
trinity_defense(file_path="/app/workspace/malware.exe")
```

### Three Phases

1. **DISCOVER** (Ghost Trace): Scans for hidden threats
2. **UNDERSTAND** (Neural Decompiler): Analyzes malicious intent
3. **NEUTRALIZE** (Adaptive Vaccine): Generates defenses

**Output includes:**
- Threat assessment report
- YARA signature for detection
- Binary patch recommendations

## Ghost Trace

Ghost Trace detects hidden malware behaviors that evade traditional analysis:

```python
ghost_trace(file_path="/app/workspace/suspicious.exe")
```

### Detection Capabilities

| Threat Type | Description |
|-------------|-------------|
| **Logic Bombs** | Code triggered by specific conditions (date, environment) |
| **Orphan Functions** | Hidden backdoors not in call graph |
| **Magic Value Triggers** | Hardcoded activation values |
| **Anti-Sandbox** | Environment detection and evasion |
| **Time Bombs** | Date/time triggered payloads |

### Example Output

```json
{
  "hidden_behaviors": [
    {
      "type": "orphan_function",
      "address": "0x00401500",
      "risk": "high",
      "description": "Function not reachable from main - potential backdoor"
    },
    {
      "type": "magic_value",
      "address": "0x00401234",
      "value": "0xDEADBEEF",
      "description": "Hardcoded trigger value comparison"
    }
  ]
}
```

## YARA Signature Generation

Generate detection signatures from malware samples:

```python
# Generate from function bytes
generate_signature(
    file_path="/app/workspace/malware.exe",
    address="0x401000",
    length=48
)
```

**Output:**
```yara
rule malware_sample {
    meta:
        description = "Generated from malware.exe at 0x401000"
        date = "2025-12-05"
    strings:
        $opcodes = { 55 8B EC 83 EC 20 53 56 57 ... }
    condition:
        $opcodes
}
```

### Running YARA Scans

```python
run_yara(
    rules_path="/app/workspace/rules/",
    target_path="/app/workspace/samples/"
)
```

## IOC Extraction

Extract Indicators of Compromise automatically:

```python
# First get strings
strings_output = run_strings(file_path="/app/workspace/malware.exe")

# Then extract IOCs
extract_iocs(
    text=strings_output,
    extract_ips=True,
    extract_urls=True,
    extract_emails=True
)
```

**Returns:**
```json
{
  "ips": ["192.168.1.100", "10.0.0.5"],
  "urls": ["http://malware-c2.com/gate.php"],
  "emails": ["attacker@evil.com"],
  "domains": ["malware-c2.com"]
}
```

## Malware Analysis Workflow

### 1. Initial Triage

```python
# Identify file type
run_file(file_path="/app/workspace/sample.exe")

# Extract strings
run_strings(file_path="/app/workspace/sample.exe")

# Parse PE structure
parse_binary_with_lief(file_path="/app/workspace/sample.exe")
```

### 2. Behavioral Analysis

```python
# Scan for hidden behaviors
ghost_trace(file_path="/app/workspace/sample.exe")

# Emulate suspicious functions
emulate_machine_code(
    file_path="/app/workspace/sample.exe",
    start_address="0x401000",
    instructions=100
)
```

### 3. Code Analysis

```python
# Decompile key functions
smart_decompile(
    file_path="/app/workspace/sample.exe",
    function_address="main"
)

# Analyze with AI enhancement
neural_decompile(
    file_path="/app/workspace/sample.exe",
    function_address="suspicious_func"
)
```

### 4. Defense Generation

```python
# Generate YARA rule
generate_signature(
    file_path="/app/workspace/sample.exe",
    address="main",
    length=64
)

# Or use Trinity for full pipeline
trinity_defense(file_path="/app/workspace/sample.exe")
```

### 5. Documentation

```python
# Start session
start_analysis_session(sample_path="/app/workspace/sample.exe")

# Add IOCs
add_session_ioc("ips", "192.168.1.100")
add_session_ioc("urls", "http://c2.evil.com/gate.php")

# Add MITRE mappings
add_session_mitre("T1059.001", "PowerShell", "Execution")
add_session_mitre("T1071.001", "Web Protocols", "Command and Control")

# Generate report
end_analysis_session(summary="Ransomware variant with C2 communication")
create_analysis_report(template_type="full_analysis")
```

## Common Malware Indicators

### Suspicious API Calls

| API | Potential Behavior |
|-----|-------------------|
| `VirtualAlloc` + `WriteProcessMemory` | Process injection |
| `CreateRemoteThread` | Remote code execution |
| `RegSetValue` | Persistence |
| `CryptEncrypt` | Ransomware encryption |
| `WSAConnect` | Network communication |

### Anti-Analysis Techniques

| Technique | Detection |
|-----------|-----------|
| IsDebuggerPresent | Anti-debugging |
| GetTickCount timing | Anti-sandbox |
| CPUID checks | VM detection |
| Registry queries | Environment fingerprinting |

## Best Practices

1. **Isolate samples**: Always analyze in isolated environment
2. **Hash verification**: Record MD5/SHA256 before analysis
3. **Network monitoring**: Watch for C2 communication attempts
4. **Snapshot VM**: Restore to clean state after analysis
5. **Document everything**: Use Report Tools for comprehensive documentation

## Next Steps

- [Ghost Trace API](../api/tools/ghost-trace.md) - Detailed API reference
- [Trinity Defense API](../api/tools/trinity-defense.md) - Automated defense
- [Report Tools](../api/tools/report-tools.md) - Analysis documentation
