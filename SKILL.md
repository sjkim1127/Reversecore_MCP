---
name: reversecore-mcp
description: Reverse engineer native binaries (PE/ELF/Mach-O), stripped Go and Rust executables, Electron ASAR desktop apps, Unity IL2CPP games, network PCAPs, and memory dumps with Reversecore_MCP. Use summary-first paging, r2ghidra decompilation, ESIL emulation, and feature code reconstruction with behavioral equivalence verification.
metadata:
  version: "1.0.0"
---

# Reversecore_MCP Agent Skill

Use **Reversecore_MCP** whenever a task requires analyzing compiled binaries, decompiling native code, unpacking Electron `.asar` applications, recovering stripped Go/Rust or Unity IL2CPP metadata, triaging crashes/vulnerabilities, analyzing malware/forensics artifacts, or reconstructing binary features into clean C/Python code.

## 1. Quick Setup & Connection

If Reversecore_MCP tools are not yet registered in the current client environment, configure them with a single command:

```bash
# Automatic multi-client setup (Cursor, Claude Code, Windsurf, Claude Desktop, Codex, Gemini, Kimi)
python -m reversecore_mcp setup

# Or enable Tiered Mode (15 core/router tools, >94% prompt token reduction)
python -m reversecore_mcp setup --tiered
```

## 2. Route the Target First

Choose the initial tool directly from the target artifact type:

- **Unknown Binary / Executable Triage**:
  1. `run_file(file_path)` — identify file format, architecture, and ABI.
  2. `parse_binary_with_lief(file_path)` — inspect sections, imports, exports, and security mitigations (ASLR, DEP/NX, PIE, Canary).
- **Stripped Go or Rust Binary**:
  - `inspect_go_rust_binary(file_path, detail="summary")` — recovers `gopclntab` function names, Go `buildinfo` modules, Rust `.dep-v0` (`cargo-auditable`) crate graphs, and demangled `_ZN...E` symbols without needing a disassembler.
- **Electron Application (`app.asar`)**:
  - `inspect_electron_asar(file_path, detail="summary")` — parses Chromium Pickle headers in pure Python, inventories bundled JS/JSON/native `.node` files, audits `BrowserWindow` security flags (`nodeIntegration`, `contextIsolation`), extracts `ipcMain`/`ipcRenderer` channels, and optionally unpacks sources via `extract_path`.
- **Unity IL2CPP Game (`global-metadata.dat` + `libil2cpp.so` / `GameAssembly.dll`)**:
  - `inspect_unity_il2cpp(metadata_path, binary_path=..., detail="summary")` — validates `0xFAB11BAF` sanity magic, extracts C# string literals, namespaces, class names, and method identifiers, or flags encrypted metadata headers.
- **Native Function Disassembly & Decompilation (Radare2 + r2ghidra)**:
  - `Radare2_open_file(file_path)` -> `Radare2_list_functions(file_path)`
  - `r2_decompile(file_path, function_address, detail="summary")` or `Radare2_decompile_function(file_path, address, detail="summary")`.
- **Feature Reconstruction & Behavioral Equivalence Loop**:
  - `reconstruct_feature_code(file_path, address_or_symbol, target_language="python", test_inputs=[...])` — decompiles the target routine, synthesizes idiomatic modern C or Python code, checks structural branch/API parity, and verifies behavioral equivalence via Radare2 ESIL emulation.
- **Vulnerability Research & Crash Triage**:
  - `vulnerability_hunter(file_path)`, `triage_crash(file_path, crash_log=...)`, `build_rop_chain(file_path)`, or `call_expert_agent(agent_name="vulnerability_hunter", ...)`.
- **Malware & DFIR Forensics**:
  - `extract_iocs(file_path)`, `run_capa_quick(file_path)`, `dormant_detector(file_path)`, `pcap_analyze(pcap_path)`, `memory_analyze(dump_path)`.

## 3. Work Summary-First & Paginate via `evidence_id`

To prevent LLM context window overflow on large binaries:

1. **Call with `detail="summary"`**:
   Tools such as `Radare2_disassemble`, `Radare2_disassemble_function`, `Radare2_decompile_function`, `r2_decompile`, `Radare2_list_strings`, `Radare2_list_all_strings`, `memory_extract_strings`, `inspect_go_rust_binary`, `inspect_electron_asar`, and `inspect_unity_il2cpp` return high-level metrics plus a retained `evidence_id` (e.g. `ev_8f3a92b1c4d0`).
2. **Paginate & Filter with `inspect_analysis_view`**:
   ```json
   {
     "evidence_id": "ev_8f3a92b1c4d0",
     "facet": "strings",
     "offset": 0,
     "limit": 50,
     "filter_query": "https://"
   }
   ```
3. **Discover On-Demand Documentation**:
   Whenever encountering an unfamiliar format or workflow, call `search_guidance(query="...")` followed by `read_guidance_section(locator="...")` instead of guessing tool parameters.

## 4. Epistemological Discipline (Anti-Hallucination Contract)

Every reverse engineering report or reconstruction must separate three epistemic categories:

1. **Observations**: Facts directly proven by raw tool bytes, addresses, or instructions.
2. **Inferences**: Analytical hypotheses derived from observations (e.g. algorithm identification from constants).
3. **Residual Unknowns**: Unresolved indirect calls (`call rax`), stripped external imports, unexecuted branches, or truncated pages.
4. **No Proof of Absence**: Never claim a binary lacks a behavior solely because a summary or filtered view did not show it.
