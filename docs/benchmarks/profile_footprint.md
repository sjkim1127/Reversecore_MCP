# Reversecore MCP Tool Profile Footprint & Benchmark

Reversecore MCP provides **modular tool profiles** (`REVERSECORE_PROFILE`) that allow AI clients
to load only the specific toolsets required for their analysis domain. This eliminates unnecessary
LLM context window consumption, lowers API token costs, decreases cold-start latency, and avoids
tool hallucinations caused by excessive schema exposure.

---

## 📊 Profile Benchmark Matrix

| Profile | Registered Tools | Schema Size (Bytes) | Schema Size (KB) | Schema Reduction | Est. Context Tokens (~4B/tok) | Tokens Saved | Cold Start | Loaded Modules | Peak RSS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `full` | 193 | 161,521 B | 157.7 KB | Baseline (0%) | ~40,380 | — | 1082.0 ms | 171 | 193.9 MB |
| `static` | 135 | 105,866 B | 103.4 KB | **-34.5%** | ~26,466 | **+13,914 tok** | 865.0 ms | 161 | 191.0 MB |
| `malware` | 107 | 105,210 B | 102.7 KB | **-34.9%** | ~26,302 | **+14,078 tok** | 919.8 ms | 169 | 192.1 MB |
| `forensics` | 84 | 64,197 B | 62.7 KB | **-60.3%** | ~16,049 | **+24,331 tok** | 725.6 ms | 149 | 187.8 MB |
| `vuln-research` | 141 | 111,620 B | 109.0 KB | **-30.9%** | ~27,905 | **+12,475 tok** | 895.4 ms | 161 | 190.9 MB |
| `tiered` | 18 | 13,146 B | 12.8 KB | **-91.9%** | ~3,286 | **+37,094 tok** | 1055.1 ms | 171 | 191.7 MB |

---

## 💡 Architectural Insights & Benefits

### 1. LLM Context Window & Token Efficiency
In MCP (Model Context Protocol), clients fetch the full tool list and JSON schema during session initialization.
With the `full` profile (193 tools), the schema payload is approximately **156.0 KB (~39,800 tokens)**.
By selecting a focused profile:
- **`tiered` profile (Router)**: Reduces schema size by **91.8%**, exposing 15 core tools + 3 router tools (18 total) and freeing up **~36,500 tokens** in every conversation context.
- **`forensics` profile**: Reduces schema size by **59.5%**, freeing up **~23,600 tokens**.
- **`malware` profile**: Cuts tool count from 193 to 107 (**-34.8% schema reduction**), preserving **~13,800 tokens**.
- **`static` profile**: Focuses strictly on reverse engineering and decompilation, trimming **~13,200 tokens** (**-33.2%**).
- **`vuln-research` profile**: Trims **~11,800 tokens** (**-29.6%**) while keeping full CVE hunter, fuzzing, and static analysis suites.

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
| **Context-Optimized Orchestration (Router)** | `REVERSECORE_PROFILE=tiered` | 15 Core tools + 3 Router/Agent tools (`call_expert_agent`, `search_tools`, `execute_domain_tool`) with on-demand access to all 193 tools |
| **Binary Reversing & Disassembly** | `REVERSECORE_PROFILE=static` | Radare2, r2ghidra, LIEF, strings, binwalk, static analysis, reports |
| **Malware Triage & Reverse Engineering** | `REVERSECORE_PROFILE=malware` | Dynamic sandbox tracing, memory dumper, network capture, Seccomp profiles, YARA, packer detection, dormant hunter, deobfuscator, anti-analysis, reports |
| **Incident Response & Memory/PCAP** | `REVERSECORE_PROFILE=forensics` | Memory forensics (Volatility3), network PCAP (Scapy), disk forensics, artifacts |
| **Vulnerability Hunting & Fuzzing** | `REVERSECORE_PROFILE=vuln-research` | CVE hunter, ASan triager, harness synthesizer, hybrid fuzzing, Radare2, source auditor |
| **Enterprise All-in-One** | `REVERSECORE_PROFILE=full` | All 193 tools across all domains (default) |

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
