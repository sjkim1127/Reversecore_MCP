# Reversecore MCP Tool Profile Footprint & Benchmark

Reversecore MCP provides **modular tool profiles** (`REVERSECORE_PROFILE`) that allow AI clients
to load only the specific toolsets required for their analysis domain. This eliminates unnecessary
LLM context window consumption, lowers API token costs, decreases cold-start latency, and avoids
tool hallucinations caused by excessive schema exposure.

---

## 📊 Profile Benchmark Matrix

| Profile | Registered Tools | Schema Size (Bytes) | Schema Size (KB) | Schema Reduction | Est. Context Tokens (~4B/tok) | Tokens Saved | Cold Start | Loaded Modules | Peak RSS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `full` | 189 | 156,374 B | 152.7 KB | Baseline (0%) | ~39,094 | — | 1626.3 ms | 165 | 198.9 MB |
| `static` | 135 | 105,866 B | 103.4 KB | **-32.3%** | ~26,466 | **+12,627 tok** | 1030.7 ms | 159 | 191.0 MB |
| `malware` | 103 | 100,063 B | 97.7 KB | **-36.0%** | ~25,016 | **+14,078 tok** | 1252.5 ms | 163 | 190.8 MB |
| `forensics` | 84 | 64,197 B | 62.7 KB | **-58.9%** | ~16,049 | **+23,044 tok** | 835.6 ms | 147 | 188.9 MB |
| `vuln-research` | 141 | 111,620 B | 109.0 KB | **-28.6%** | ~27,905 | **+11,188 tok** | 1645.9 ms | 159 | 191.4 MB |
| `tiered` | 18 | 13,146 B | 12.8 KB | **-91.6%** | ~3,286 | **+35,807 tok** | 1189.0 ms | 165 | 191.1 MB |

---

## 💡 Architectural Insights & Benefits

### 1. LLM Context Window & Token Efficiency
In MCP (Model Context Protocol), clients fetch the full tool list and JSON schema during session initialization.
With the `full` profile (189 tools), the schema payload is approximately **153.2 KB (~39,200 tokens)**.
By selecting a focused profile:
- **`tiered` profile (Router)**: Reduces schema size by **91.8%**, exposing 15 core tools + 3 router tools (18 total) and freeing up **~36,000 tokens** in every conversation context.
- **`forensics` profile**: Reduces schema size by **59.3%**, freeing up **~23,200 tokens**.
- **`malware` profile**: Cuts tool count from 189 to 103 (**-36.2% schema reduction**), preserving **~14,200 tokens**.
- **`static` profile**: Focuses strictly on reverse engineering and decompilation, trimming **~12,800 tokens** (**-32.5%**).
- **`vuln-research` profile**: Trims **~11,400 tokens** (**-28.8%**) while keeping full CVE hunter, fuzzing, and static analysis suites.

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
| **Context-Optimized Orchestration (Router)** | `REVERSECORE_PROFILE=tiered` | 15 Core tools + 3 Router/Agent tools (`call_expert_agent`, `search_tools`, `execute_domain_tool`) with on-demand access to all 189 tools |
| **Binary Reversing & Disassembly** | `REVERSECORE_PROFILE=static` | Radare2, r2ghidra, LIEF, strings, binwalk, static analysis, reports |
| **Malware Triage & Reverse Engineering** | `REVERSECORE_PROFILE=malware` | YARA, packer detection, dormant hunter, deobfuscator, anti-analysis, reports |
| **Incident Response & Memory/PCAP** | `REVERSECORE_PROFILE=forensics` | Memory forensics (Volatility3), network PCAP (Scapy), disk forensics, artifacts |
| **Vulnerability Hunting & Fuzzing** | `REVERSECORE_PROFILE=vuln-research` | CVE hunter, ASan triager, harness synthesizer, hybrid fuzzing, Radare2, source auditor |
| **Enterprise All-in-One** | `REVERSECORE_PROFILE=full` | All 189 tools across all domains (default) |

---

## 🚀 How to Enable Profiles

### Environment Variable
```bash
export REVERSECORE_PROFILE=tiered
python server.py
```

### Docker
```bash
docker run -i --rm \
  -v /path/to/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e REVERSECORE_PROFILE=tiered \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:3.1.0
```

### MCP Client Configuration (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "reversecore-tiered": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/Users/username/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "REVERSECORE_PROFILE=tiered",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:3.1.0"
      ]
    }
  }
}
```
