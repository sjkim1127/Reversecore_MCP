# Trinity Defense API Reference

::: reversecore_mcp.tools.trinity_defense
    options:
      show_source: true
      show_root_heading: true

## Overview

Trinity Defense is a fully automated threat detection and neutralization pipeline that combines three specialized modules into a comprehensive defense system.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TRINITY DEFENSE                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────┐    ┌───────────────┐    ┌────────────────┐  │
│  │  PHASE 1  │    │    PHASE 2    │    │    PHASE 3     │  │
│  │  DISCOVER │ →  │  UNDERSTAND   │ →  │   NEUTRALIZE   │  │
│  │           │    │               │    │                │  │
│  │Ghost Trace│    │Neural Decomp. │    │Adaptive Vaccine│  │
│  └───────────┘    └───────────────┘    └────────────────┘  │
│       │                  │                    │             │
│       ▼                  ▼                    ▼             │
│  Hidden threats     AI analysis         YARA rules         │
│  Logic bombs        Intent mapping      Binary patches     │
│  Backdoors          Code explanation    IOC extraction     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Main Tool

### trinity_defense

Execute the complete threat analysis and defense pipeline.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the binary to analyze |
| `timeout` | int | No | Total pipeline timeout (default: 900s) |
| `generate_vaccine` | bool | No | Generate defensive measures (default: True) |

**Returns:**
```json
{
  "status": "success",
  "phases": {
    "discover": {
      "hidden_behaviors": 3,
      "high_risk": 2,
      "threats": [...]
    },
    "understand": {
      "analyzed_functions": 3,
      "malicious_intent": "Ransomware with C2 capability",
      "techniques": ["T1059.001", "T1486", "T1071.001"]
    },
    "neutralize": {
      "yara_rule": "rule malware_family {...}",
      "iocs": {
        "ips": ["192.168.1.100"],
        "urls": ["http://c2.evil.com/gate.php"],
        "hashes": {"md5": "...", "sha256": "..."}
      },
      "patches": [
        {
          "address": "0x401234",
          "original": "75 10",
          "patched": "EB 10",
          "description": "Bypass anti-debug check"
        }
      ]
    }
  },
  "summary": {
    "threat_level": "critical",
    "malware_family": "Ransomware",
    "confidence": 0.95
  }
}
```

## Phase Details

### Phase 1: DISCOVER (Ghost Trace)

Scans for hidden malicious behaviors:

- **Orphan functions**: Unreachable code (backdoors)
- **Magic values**: Trigger conditions
- **Time bombs**: Date-based activation
- **Anti-analysis**: Sandbox/debugger detection

### Phase 2: UNDERSTAND (Neural Decompiler)

Analyzes discovered threats with AI:

- **Intent mapping**: What the code does
- **Technique identification**: MITRE ATT&CK mapping
- **Behavior explanation**: Human-readable summary

### Phase 3: NEUTRALIZE (Adaptive Vaccine)

Generates defensive measures:

- **YARA rules**: Detection signatures
- **IOC extraction**: Network indicators, file artifacts
- **Binary patches**: Neutralization recommendations

## Adaptive Vaccine

### adaptive_vaccine

Generate defensive measures from threat analysis.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | str | Yes | Path to the analyzed binary |
| `threat_report` | dict | Yes | Output from discover/understand phases |

**Returns:**
```json
{
  "yara_rule": "rule detected_threat { ... }",
  "iocs": {
    "ips": ["192.168.1.100", "10.0.0.5"],
    "domains": ["malware-c2.com"],
    "urls": ["http://malware-c2.com/gate.php"],
    "file_hashes": {
      "md5": "abc123...",
      "sha256": "def456..."
    },
    "mutexes": ["Global\\MalwareMutex"],
    "registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"]
  },
  "patches": [
    {
      "address": "0x401234",
      "type": "nop_out",
      "bytes": "90 90 90 90 90",
      "description": "Disable anti-debug check"
    }
  ],
  "mitre_mappings": [
    {"technique": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
    {"technique": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
  ]
}
```

## Usage Examples

### Full Pipeline

```python
# Run complete Trinity Defense pipeline
result = trinity_defense(file_path="/app/workspace/malware.exe")

# Check threat level
print(f"Threat Level: {result['summary']['threat_level']}")
print(f"Malware Family: {result['summary']['malware_family']}")

# Extract YARA rule
yara_rule = result["phases"]["neutralize"]["yara_rule"]
with open("detection.yar", "w") as f:
    f.write(yara_rule)
```

### Phased Execution

```python
# Phase 1: Discover
hidden = ghost_trace(file_path="/app/workspace/malware.exe")

# Phase 2: Understand each threat
for threat in hidden["hidden_behaviors"]:
    analysis = neural_decompile(
        file_path="/app/workspace/malware.exe",
        function_address=threat["address"]
    )

# Phase 3: Generate defense
vaccine = adaptive_vaccine(
    file_path="/app/workspace/malware.exe",
    threat_report=hidden
)
```

### With Report Generation

```python
# Start session
start_analysis_session(sample_path="/app/workspace/malware.exe")

# Run Trinity Defense
result = trinity_defense(file_path="/app/workspace/malware.exe")

# Add IOCs to session
for ip in result["phases"]["neutralize"]["iocs"]["ips"]:
    add_session_ioc("ips", ip)

# Add MITRE mappings
for mapping in result["phases"]["neutralize"]["mitre_mappings"]:
    add_session_mitre(mapping["technique"], mapping["name"], mapping["tactic"])

# Generate report
end_analysis_session(summary=result["summary"]["malware_family"])
create_analysis_report(template_type="full_analysis")
```

## Best Practices

1. **Allocate sufficient timeout**: Complex samples need 15+ minutes
2. **Review YARA rules**: Auto-generated rules may need tuning
3. **Validate patches**: Test neutralization in isolated environment
4. **Export IOCs**: Share with threat intelligence platforms
5. **Document everything**: Use Report Tools for comprehensive reporting

## Related Tools

- [Ghost Trace](ghost-trace.md) - Phase 1 component
- [Neural Decompiler](neural-decompiler.md) - Phase 2 component
- [CLI Tools](cli-tools.md) - Manual analysis
- [Report Tools](report-tools.md) - Documentation
