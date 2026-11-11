# Reversecore MCP Tool Profile Footprint & Benchmark

Reversecore MCP provides **modular tool profiles** (`REVERSECORE_PROFILE`) that allow AI clients
to load only the specific toolsets required for their analysis domain. This eliminates unnecessary
LLM context window consumption, lowers API token costs, decreases cold-start latency, and avoids
tool hallucinations caused by excessive schema exposure.

---

## 📊 Profile Benchmark Matrix

| Profile | Registered Tools | Schema Size (Bytes) | Schema Size (KB) | Schema Reduction | Est. Context Tokens (~4B/tok) | Tokens Saved | Cold Start | Loaded Modules | Peak RSS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `full` | 191 | 158,801 B | 155.1 KB | Baseline (0%) | ~39,700 | — | 1858.2 ms | 169 | 193.8 MB |
| `static` | 135 | 105,866 B | 103.4 KB | **-33.3%** | ~26,466 | **+13,234 tok** | 1447.2 ms | 161 | 195.8 MB |
| `malware` | 105 | 102,490 B | 100.1 KB | **-35.5%** | ~25,622 | **+14,078 tok** | 1494.2 ms | 167 | 192.3 MB |
| `forensics` | 84 | 64,197 B | 62.7 KB | **-59.6%** | ~16,049 | **+23,651 tok** | 1213.5 ms | 149 | 193.5 MB |
| `vuln-research` | 141 | 111,620 B | 109.0 KB | **-29.7%** | ~27,905 | **+11,795 tok** | 1665.8 ms | 161 | 192.3 MB |
| `tiered` | 18 | 13,146 B | 12.8 KB | **-91.7%** | ~3,286 | **+36,414 tok** | 1675.7 ms | 169 | 190.1 MB |

---

## 💡 Architectural Insights & Benefits

### 1. LLM Context Window & Token Efficiency
In MCP (Model Context Protocol), clients fetch the full tool list and JSON schema during session initialization.
With the `full` profile (191 tools), the schema payload is approximately **154.5 KB (~39,500 tokens)**.
By selecting a focused profile:
- **`tiered` profile (Router)**: Reduces schema size by **91.7%**, exposing 15 core tools + 3 router tools (18 total) and freeing up **~36,200 tokens** in every conversation context.
- **`forensics` profile**: Reduces schema size by **59.4%**, freeing up **~23,400 tokens**.
- **`malware` profile**: Cuts tool count from 191 to 105 (**-35.3% schema reduction**), preserving **~13,900 tokens**.
- **`static` profile**: Focuses strictly on reverse engineering and decompilation, trimming **~13,000 tokens** (**-33.0%**).
- **`vuln-research` profile**: Trims **~11,600 tokens** (**-29.4%**) while keeping full CVE hunter, fuzzing, and static analysis suites.

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
| **Context-Optimized Orchestration (Router)** | `REVERSECORE_PROFILE=tiered` | 15 Core tools + 3 Router/Agent tools (`call_expert_agent`, `search_tools`, `execute_domain_tool`) with on-demand access to all 191 tools |
| **Binary Reversing & Disassembly** | `REVERSECORE_PROFILE=static` | Radare2, r2ghidra, LIEF, strings, binwalk, static analysis, reports |
| **Malware Triage & Reverse Engineering** | `REVERSECORE_PROFILE=malware` | Dynamic sandbox tracing, memory dumper, YARA, packer detection, dormant hunter, deobfuscator, anti-analysis, reports |
| **Incident Response & Memory/PCAP** | `REVERSECORE_PROFILE=forensics` | Memory forensics (Volatility3), network PCAP (Scapy), disk forensics, artifacts |
| **Vulnerability Hunting & Fuzzing** | `REVERSECORE_PROFILE=vuln-research` | CVE hunter, ASan triager, harness synthesizer, hybrid fuzzing, Radare2, source auditor |
| **Enterprise All-in-One** | `REVERSECORE_PROFILE=full` | All 191 tools across all domains (default) |

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
