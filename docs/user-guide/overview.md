# Overview

Reversecore MCP is a security analysis platform built on the Model Context Protocol (MCP). It allows AI assistants to perform comprehensive, low-level binary analysis and forensics through natural language commands.

---

## What is Model Context Protocol (MCP)?

The Model Context Protocol (MCP) is an open standard developed by Anthropic that allows LLMs to query external databases, run code generators, and execute system commands in a controlled, structured way. Reversecore MCP implements this protocol, enabling models like Claude or GPT inside Cursor to use Radare2, YARA, Volatility3, and other utilities directly.

---

## Core Capabilities

### 🔍 Binary Analysis & Static Triage
- **File & Metadata Parsing**: Determine file architecture, compiler, linker, and packer signatures.
- **Header Auditing**: Extract sections, imports, exports, and directory tables from PE, ELF, and Mach-O files.
- **String Extraction**: Locate plain ASCII/Unicode strings with offset tracing.

### ⚙️ Disassembly & Decompilation
- **Native Disassembly**: Disassemble function bytes using Radare2.
- **Native Decompilation**: Decompile binary code to human-readable pseudo-C code using the JVM-free native `r2ghidra` engine.
- **Symbol & Struct Recovery**: Infer data types and recover C structures from compiler offsets.

### 🧬 Dynamic & Symbolic Analysis
- **ESIL Code Emulation**: Perform lightweight code emulation with register and memory logging without executing the untrusted binary on the host OS.
- **angr Symbolic Execution**: Compute concrete inputs to prove path reachability and solve block constraints.
- **Fuzzing Harness**: Generate AFL++ harnesses wrapped in Qiling emulator environments.

### 🦠 Threat Hunting & Malware Analysis
- **Dormant Detector**: Scan for VM evasions, anti-debugging indicators, logic bombs, and orphan functions.
- **YARA Scanner**: Match signatures against files or search directories.
- **Adaptive Vaccine**: Generate YARA signatures and proposed binary patches to disable threat loops.

### 🕵️ Digital Forensics
- **Memory Forensics**: Parse raw RAM dumps using Volatility3 plugins (e.g. `pslist`, `malfind`).
- **Network Capture**: Inspect PCAP files using Scapy for protocol details and domain lookups.
- **Disk & Host Artifacts**: Parse registry files, browser history, and Sleuth Kit file entries.

---

## Tool Categories in Reversecore MCP

| Category | Primary Backend | Examples of Registered Tools |
|----------|-----------------|------------------------------|
| **Static Analysis** | `file`, `strings`, LIEF, DIE, CAPA | `run_file`, `run_strings`, `parse_binary_with_lief`, `run_capa`, `detect_packer` |
| **Radare2 & Decompilation** | Radare2 + `r2ghidra` plugin | `Radare2_disassemble`, `r2_decompile`, `r2_recover_structures`, `r2_analyze_function` |
| **Malware & Threat Hunting** | YARA, custom heuristics | `dormant_detector`, `extract_iocs`, `yara_scan`, `adaptive_vaccine` |
| **Dynamic & Symbolic** | angr, Qiling, Radare2 ESIL | `emulate_binary`, `verify_path_and_get_args`, `generate_fuzzing_harness`, `diff_binaries` |
| **Digital Forensics** | Volatility3, Scapy, TSK | `analyze_memory_dump`, `analyze_network_capture`, `analyze_disk_image` |
| **Reporting & Sessions** | Python SMTP, SQLite | `start_analysis_session`, `add_session_ioc`, `create_analysis_report`, `send_report_email` |
