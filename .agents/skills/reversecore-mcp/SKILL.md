---
name: reversecore-mcp
description: Reverse engineer native binaries (PE/ELF/Mach-O), stripped Go and Rust executables, Electron ASAR desktop apps, Unity IL2CPP games, network PCAPs, and memory dumps with Reversecore_MCP. Use summary-first paging, r2ghidra decompilation, ESIL emulation, and feature code reconstruction with behavioral equivalence verification.
metadata:
  version: "1.0.0"
---

# Reversecore_MCP Agent Skill

Use **Reversecore_MCP** whenever a task requires analyzing compiled binaries, decompiling native code, unpacking Electron `.asar` applications, recovering stripped Go/Rust or Unity IL2CPP metadata, triaging crashes/vulnerabilities, analyzing malware/forensics artifacts, or reconstructing binary features into clean C/Python code.

## 1. Route the Target First

- **Go or Rust Native Executable**: `inspect_go_rust_binary(file_path, detail="summary")`
- **Electron Desktop Archive (`app.asar`)**: `inspect_electron_asar(file_path, detail="summary")`
- **Unity IL2CPP Metadata (`global-metadata.dat`)**: `inspect_unity_il2cpp(metadata_path, binary_path=..., detail="summary")`
- **Native PE/ELF/Mach-O Decompilation**: `r2_decompile(file_path, function_address, detail="summary")`
- **Feature Reconstruction & ESIL Verification**: `reconstruct_feature_code(file_path, address_or_symbol, target_language="python")`
- **Retained Evidence Paging**: `inspect_analysis_view(evidence_id, facet=..., offset=0, limit=50, filter_query=...)`
- **On-Demand Guidance Search**: `search_guidance(query)` and `read_guidance_section(locator)`

## 2. Read Focused Reference Guides

- Modern runtime targets (Go, Rust, Electron ASAR, Unity IL2CPP):
  [references/modern-runtimes.md](references/modern-runtimes.md)
