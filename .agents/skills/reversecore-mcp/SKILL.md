---
name: reversecore-mcp
description: Reverse engineer native binaries (PE/ELF/Mach-O), stripped Go and Rust executables, Electron ASAR desktop apps, Unity IL2CPP games, network PCAPs, and memory dumps with Reversecore_MCP. Use Layer 1 meta-tools for 1-turn triage, dynamic sandboxing with PCAP/Seccomp, r2ghidra decompilation, and feature code reconstruction.
metadata:
  version: "2.1.0"
---

# Reversecore_MCP Agent Skill

Use **Reversecore_MCP** whenever a task requires analyzing compiled binaries, inspecting suspicious runtime behavior, decompiling native code, unpacking Electron `.asar` applications, recovering stripped Go/Rust or Unity IL2CPP metadata, triaging crashes/vulnerabilities, or reconstructing binary features into clean C/Python code.

---

## 1. Fast-Path: 1-Turn Meta-Tools (Always Start Here)

Instead of manually querying file headers, sections, symbols, strings, and decompilers in multiple turns, invoke the Layer 1 Meta-Tools for instant comprehensive triage:

* **Static Binary Triage**:
  ```python
  analyze_binary(file_path="sample.bin", goal="general") # or goal="malware" / "vuln"
  ```
  *Returns file format (ELF/PE/Mach-O), security mitigations (NX, PIE, Canary, RELRO, ASLR), high-entropy packed sections, dangerous APIs, main function decompile, and domain-specific verdict in 1 turn.*

* **Forensics & Incident Triage**:
  ```python
  triage_incident(artifact_path="traffic.pcap", type="auto") # or "memory" / "disk"
  ```
  *Automatically detects PCAP, memory dump, or disk image, correlating C2 beacon intervals, suspicious DNS queries, and injected memory regions (`malfind`).*

* **Crash & Vulnerability Scoring**:
  ```python
  investigate_vulnerability(binary_path="vuln.bin", crash_log="ASan stack trace...")
  ```
  *Parses crash logs, determines CWE classification, evaluates ROP/Heap gadget feasibility, and computes an Exploitability Score (0.0 to 10.0).*

---

## 2. Dynamic Analysis & Safe OS Sandboxing (Radare2-Independent)

When analyzing suspicious binaries, malware, or packed executables without heavy virtualization:

* **Safe Execution Tracing with PCAP & Seccomp**:
  ```python
  trace_execution(
      file_path="malware.bin",
      capture_pcap=True,                 # Records real-time network packets during execution
      seccomp_profile="no_network",      # Enforces syscall containment ('strict', 'no_network', 'read_only')
      isolation_backend="auto",          # Uses Bubblewrap ('bwrap') namespace sandbox if available
      api_hooking=True                   # Intercepts fopen, connect, system, execve via LD_PRELOAD
  )
  ```
  *Monitors file drops, child processes, exit signals, network sockets, blocked syscalls, and API calls.*

* **Runtime Memory Unpacking (Fission Pipeline Entrypoint)**:
  ```python
  dump_process_memory(
      file_path="packed_sample.bin",
      wait_ms=150,                       # Waits for decryption/unpacking loop
      filter_permissions="rwx",          # Extracts self-modifying / executable code
      capture_pcap=True                  # Simultaneously records network traffic
  )
  ```
  *Freezes process via SIGSTOP, dumps `/proc/<pid>/mem` segments, calculates Shannon entropy, and outputs clean binary dumps ready for decompiler / Fission source restoration.*

* **Live Network Traffic Sniffing**:
  ```python
  capture_network_traffic(
      duration_seconds=5,
      bpf_filter="tcp or udp port 53"
  )
  ```
  *Saves industry-standard `.pcap` files directly to the workspace with protocol breakdown, DNS queries, and suspicious flows.*

* **Security Policy & Hooking Generators**:
  * `generate_seccomp_profile(profile_type="no_network")`: Exports Docker/OCI JSON and systemd filter policies.
  * `generate_api_hook_library()`: Generates and compiles user-space C hooking libraries for LD_PRELOAD / DYLD_INSERT_LIBRARIES.

---

## 3. Specialized Runtime Metadata Recovery

For managed and modern runtimes, use dedicated parsers before attempting raw disassembly:

* **Go / Rust Stripped Binaries**:
  ```python
  inspect_go_rust_binary(file_path="app", detail="summary")
  ```
  *Recovers pclntab symbol table, type descriptors, standard library dependencies, and build ID.*

* **Electron Desktop Archives**:
  ```python
  inspect_electron_asar(file_path="resources/app.asar", detail="summary")
  ```
  *Extracts package.json, Node.js entrypoints, IPC handlers, and flags remote code execution vulnerabilities.*

* **Unity IL2CPP Games**:
  ```python
  inspect_unity_il2cpp(metadata_path="global-metadata.dat", binary_path="GameAssembly.dll")
  ```
  *Recovers C# class structures, method signatures, fields, and string literals.*

---

## 4. Deep Static Reverse Engineering & Decompilation

When analyzing specific functions, algorithms, or vulnerability proofs:

* **Decompilation**: `r2_decompile(file_path, function_address, detail="summary")` (powered by r2ghidra plugin)
* **Disassembly & CFG**: `r2_disassemble_function(file_path, function_name)`
* **Feature Reconstruction**: `reconstruct_feature_code(file_path, address_or_symbol, target_language="python")` (verifies behavioral equivalence via ESIL emulation)
* **Evidence Paging**: `inspect_analysis_view(evidence_id, facet="functions", offset=0, limit=50)`

---

## 5. Token Efficiency & Tiered Mode (`REVERSECORE_PROFILE=tiered`)

In complex or multi-agent workflows, Reversecore_MCP supports Progressive Disclosure to save up to **91.9% context tokens** (~36,500 tokens/turn):

1. **Handshake Stage**: Only 18 core tools are loaded into the LLM system prompt.
2. **On-Demand Domain Expansion**:
   * Dispatch to specialized domain sub-agents: `call_expert_agent(domain="malware"|"forensics"|"vuln", task=...)`
   * Discover any of the 190+ tools on-demand: `search_tools(query="heap")`
   * Directly invoke specialized tools: `execute_domain_tool(tool_name="pcap_extract_c2", arguments={...})`
