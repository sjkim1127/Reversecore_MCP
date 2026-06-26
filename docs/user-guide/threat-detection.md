# Threat Detection Guide

This guide covers malware triage, threat hunting, and automated vaccine generation using Reversecore MCP.

---

## 1. Backdoor & Evasion Scanning

Traditional analysis can miss hidden code paths, logic bombs, and sandbox evasion tricks. The **Dormant Detector** analyzes control flow to identify code that runs only under specific environments or dates.

```python
# Scan for VM checks, logic bombs, and orphan functions
dormant_detector(file_path="suspicious.elf")
```

### Detection Capabilities

- **Orphan Functions**: Subroutines that exist in the binary but have no references or incoming calls in the normal control flow graph (often used as dormant backdoors).
- **Anti-Sandbox / Anti-Debugging**: Searches for API sequences that detect VM environments (CPUID, hypervisor checks) or debugging attachments (`IsDebuggerPresent`).
- **Time/Date Bombs**: Code paths containing epoch timestamp comparisons or local system date checks.
- **Environment Triggers**: Logic checks on computer names, domains, or specific usernames.

---

## 2. Vulnerability Hunting

Search for security bugs, dangerous function calls, and exploit structures:

```python
# Identify bad API patterns and locate ROP gadget chains
vulnerability_hunter(file_path="suspicious.elf")
```

### Scan Parameters

- **Dangerous APIs**: Highlights legacy C functions susceptible to stack/heap overflows (e.g. `strcpy`, `sprintf`, `gets`).
- **ROP Gadgets**: Computes Return-Oriented Programming gadget sequences (`pop rdi; ret`, etc.) for potential stack exploitation mapping.

---

## 3. Indicator of Compromise (IOC) Extraction

Search files or log buffers for standard signatures:

```python
# Extract network IPs, URLs, emails, and crypto addresses
extract_iocs(text="...log string or extracted strings...")
```

---

## 4. YARA Scanning & Vaccine Generation

### Running YARA Scans
Perform multi-file scans against standard or custom YARA rules:

```python
# Scan workspace against custom rule folder
run_yara(rules_path="rules/", target_path="samples/")
```

### Adaptive Vaccine
Automatically generate YARA signatures to detect the threat, along with proposed binary modification patches to neutralize the behavior:

```python
# Generate detection rule and neutralization patch proposal
adaptive_vaccine(file_path="malware.elf")
```

---

## 5. Malware Analysis Workflow

Use this standard workflow to analyze a suspicious file from triage to final reporting:

```
Triage File (run_file)
    ↓
Scan Backdoors & Evasions (dormant_detector)
    ↓
Extract Network/Host IOCs (extract_iocs)
    ↓
Search Exploit Gadgets (vulnerability_hunter)
    ↓
Generate YARA Rules & Patch (adaptive_vaccine)
    ↓
Create Standard Triage Report (create_analysis_report)
```

### Triage Session Code Example

```python
# 1. Start session tracking
start_analysis_session(sample_path="malware.elf", analyst_name="IR Team")

# 2. Add found IOCs
add_session_ioc(ioc_type="ips", value="185.190.140.10", context="C2 Server")
add_session_ioc(ioc_type="domains", value="c2-malicious.net", context="Dynamic DNS")

# 3. Add MITRE ATT&CK Mapping
add_session_mitre(
    technique_id="T1497",
    technique_name="Virtualization/Sandbox Evasion",
    tactic="Defense Evasion",
    evidence="Found VM artifacts in dormant_detector output"
)

# 4. Conclude session and output report
end_analysis_session(summary="Spyware variant communicating with C2.")
create_analysis_report(template_type="full_analysis", output_format="markdown")
```
