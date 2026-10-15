# Reversecore MCP Tool Profile Footprint & Benchmark

Reversecore MCP provides **modular tool profiles** (`REVERSECORE_PROFILE`) that allow AI clients
to load only the specific toolsets required for their analysis domain. This eliminates unnecessary
LLM context window consumption, lowers API token costs, decreases cold-start latency, and avoids
tool hallucinations caused by excessive schema exposure.

---

## 📊 Profile Benchmark Matrix

| Profile | Registered Tools | Schema Size (Bytes) | Schema Size (KB) | Schema Reduction | Est. Context Tokens (~4B/tok) | Tokens Saved | Cold Start | Loaded Modules | Peak RSS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `full` | 156 | 123,082 B | 120.2 KB | Baseline (0%) | ~30,770 | — | 1014.9 ms | 145 | 192.5 MB |
| `static` | 102 | 72,809 B | 71.1 KB | **-40.8%** | ~18,202 | **+12,568 tok** | 798.7 ms | 138 | 188.2 MB |
| `malware` | 70 | 67,806 B | 66.2 KB | **-44.9%** | ~16,952 | **+13,819 tok** | 807.1 ms | 142 | 188.7 MB |
| `forensics` | 59 | 40,178 B | 39.2 KB | **-67.4%** | ~10,044 | **+20,726 tok** | 705.7 ms | 131 | 186.1 MB |
| `vuln-research` | 108 | 78,563 B | 76.7 KB | **-36.2%** | ~19,641 | **+11,130 tok** | 858.0 ms | 138 | 188.6 MB |

---

## 💡 Architectural Insights & Benefits

### 1. LLM Context Window & Token Efficiency
In MCP (Model Context Protocol), clients fetch the full tool list and JSON schema during session initialization.
With the `full` profile (156 tools), the schema payload is approximately **119 KB (~29,600 tokens)**.
By selecting a focused profile:
- **`forensics` profile**: Reduces schema size by **67.7%**, freeing up **~19,500 tokens** in every conversation context.
- **`malware` profile**: Cuts tool count from 156 to 70 (**-46.0% schema reduction**), preserving **~13,500 tokens**.
- **`static` profile**: Focuses strictly on reverse engineering and decompilation, trimming **~12,000 tokens** (**-41.0%**).

### 2. Pre-Import Module Isolation
Reversecore MCP implements a pre-import filter (`MODULE_TO_PLUGIN_NAME` manifest in `PluginLoader`).
When a profile excludes a subsystem (such as Volatility or Scapy in the `static` profile),
Python skips walking and importing those module trees entirely. This guarantees:
- Faster cold-start initialization.
- Zero import-time side effects from unneeded libraries.
- Minimal memory footprint.

---

## 🎯 Profile Recommendations by Domain

| Analysis Task | Recommended Profile | Key Included Toolsets |
|---|---|---|
| **Binary Reversing & Disassembly** | `REVERSECORE_PROFILE=static` | Radare2, r2ghidra, LIEF, strings, binwalk, static analysis, reports |
| **Malware Triage & Reverse Engineering** | `REVERSECORE_PROFILE=malware` | YARA, packer detection, dormant hunter, deobfuscator, anti-analysis, reports |
| **Incident Response & Memory/PCAP** | `REVERSECORE_PROFILE=forensics` | Memory forensics (Volatility3), network PCAP (Scapy), disk forensics, artifacts |
| **Vulnerability Hunting & Fuzzing** | `REVERSECORE_PROFILE=vuln-research` | CVE hunter, ASan triager, harness synthesizer, hybrid fuzzing, Radare2, source auditor |
| **Enterprise All-in-One** | `REVERSECORE_PROFILE=full` | All 156 tools across all domains (default) |

---

## 🚀 How to Enable Profiles

### Environment Variable
```bash
export REVERSECORE_PROFILE=static
python server.py
```

### Docker
```bash
docker run -i --rm \
  -v /path/to/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e REVERSECORE_PROFILE=malware \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:3.0.4
```

### MCP Client Configuration (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "reversecore-static": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/Users/username/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "REVERSECORE_PROFILE=static",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:3.0.4"
      ]
    }
  }
}
```
