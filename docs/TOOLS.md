# Reversecore MCP Tool Catalog (151 Tools)

> **Single Source of Truth**: This document is automatically generated from the FastMCP runtime
> tool registry by `scripts/generate_tool_catalog.py`. Do not edit manually.

Reversecore MCP exposes **151 production-grade security analysis tools** and **11 dynamic resource templates** via the Model Context Protocol (MCP).

---

## 🧭 Tool Profiles Overview

To optimize LLM context usage and minimize token consumption, tools are organized into modular profiles via `REVERSECORE_PROFILE`:

| Profile | Tools | Primary Focus | Included Plugins |
|---|:---:|---|---|
| `full` | **151** | Complete All-in-One Suite (Default) | All plugins |
| `static` | **97** | Reverse Engineering & Decompilation | `analysis`, `common`, `radare2`, `report`, `server` |
| `vuln-research` | **103** | Vulnerability Hunting & Exploitation | `analysis`, `source_auditor`, `cve_hunter`, `radare2`, `common`, `report`, `server` |
| `malware` | **65** | Threat Triage & Malware Analysis | `analysis`, `common`, `malware`, `deobfuscation`, `report`, `server` |
| `forensics` | **57** | Digital & Memory Forensics | `forensics`, `memory`, `common`, `report`, `server` |

📊 *For empirical context token savings, cold-start latency, and memory benchmarks across profiles, see [Profile Footprint Benchmark](benchmarks/profile_footprint.md).*

---

## 📦 Plugin Summary

| Domain | Plugin Name | Tools | Description |
|---|---|:---:|---|
| 🔍 Static Analysis & Inspection | `analysis_tools` | **26** | Binary Headers, Formats, Capabilities & Strings |
| 📜 Source Code Auditing | `source_auditor` | **1** | AST & Regex Pattern Analysis for Python/C/C++ |
| ⚙️ Radare2 & Decompilation | `radare2_mcp_tools` | **47** | Disassembly, CFG, Ghidra Decompiler & ESIL Emulation |
| 🦠 Malware Analysis & Threat Hunting | `malware_tools` | **11** | YARA Detection, Anti-Analysis, Packer & Vaccine Engines |
| 🧩 Automated Deobfuscation | `deobfuscation_tools` | **4** | String Decryption, API Hashing & Dead Code Removal |
| 🎯 Vulnerability Research & CVE Hunting | `cve_hunter_tools` | **5** | ASan Crash Triage, Fuzz Harness Synthesis & PoC Minimization |
| 🔬 Digital Forensics | `forensics_tools` | **22** | Memory (Volatility), Network (PCAP), Disk & Artifacts |
| 🧠 Process & Memory Utilities | `memory_tools` | **11** | Live Memory Inspection, Patterns & Hex Dumps |
| 🛠️ Common Binary Utilities | `common_tools` | **7** | File Operations, Hashing, Patch Explanations & Assembly |
| 🖥️ Server Lifecycle & State | `server_tools` | **2** | Server Status, Health & Memory Cache Management |
| 📋 Reporting & MITRE ATT&CK | `report_tools` | **14** | Session Reports, MITRE Mapping, SIGMA & VEX Generation |
| ⏳ Task Queue & Async Jobs | `core_task_queue` | **1** | Background Job Status & Result Retrieval |
| **Total** | — | **151** | **Complete Reversecore MCP Suite** |

---

## 🛠️ Complete Tool Reference

### 🔍 Static Analysis & Inspection (`analysis_tools` — 26 tools)

*Binary Headers, Formats, Capabilities & Strings*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 1 | `analyze_patch_diff_auto` | Automatically infer vulnerabilities from binary patch differences. | `file_path_old` (string, req), `file_path_new` (string, req), `top_functions` (integer), `auto_infer_vuln` (boolean), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 2 | `analyze_variant_changes` | Analyze structural changes between two binary variants (Lineage Mapper). | `file_path_a` (string, req), `file_path_b` (string, req), `top_n` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 3 | `detect_packer` | Detect packer, compiler, and protector using Shannon entropy, section heuristics, and signature matching. | `file_path` (string, req) | `static`, `malware`, `vuln-research` |
| 4 | `detect_packer_deep` | Deep scan combining block-level entropy, overlay analysis, section anomaly heuristics, and full signature scanning. | `file_path` (string, req) | `static`, `malware`, `vuln-research` |
| 5 | `diff_binaries` | Compare two binary files to identify code changes and modifications. | `file_path_a` (string, req), `file_path_b` (string, req), `function_name` (any), `page` (integer), `page_size` (integer), `top_n` (integer), `max_output_size` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 6 | `emulate_binary` | Emulate the execution of a binary using the Qiling framework. | `file_path` (string, req), `start_address` (any), `end_address` (any), `registers` (any), `stack_inputs` (any), `mock_files` (any), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 7 | `extract_rtti_info` | Extract RTTI (Run-Time Type Information) from C++ binaries. | `file_path` (string, req), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 8 | `generate_advanced_yara_rule` | Generate an advanced YARA rule based on radare2 disassembly opcodes. | `file_path` (string, req), `address` (string, req), `rule_name` (string), `num_instructions` (integer), `mask_operands` (boolean), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 9 | `generate_enhanced_yara_rule` | Generate an enhanced YARA rule with structural conditions to reduce false positives. | `file_path` (string, req), `rule_name` (string, req), `strings` (array, req), `imports` (any), `file_type` (string), `min_filesize` (any), `max_filesize` (any), `section_names` (any), `entry_point_pattern` (any), `description` (string), `author` (string), `min_string_matches` (any), `tags` (any) | `static`, `malware`, `vuln-research` |
| 10 | `generate_fuzzing_harness` | Generate a dynamic fuzzing harness (Qiling + AFL++) for a vulnerable function. | `file_path` (string, req), `target_function_or_addr` (string, req), `fuzzer_type` (string), `save_to_workspace` (boolean) | `static`, `malware`, `vuln-research` |
| 11 | `generate_signature` | Generate a YARA signature from opcode bytes at a specific address. | `file_path` (string, req), `address` (string, req), `length` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 12 | `generate_yara_rule` | Generate a YARA rule from function bytes. | `file_path` (string, req), `function_address` (string, req), `rule_name` (string), `byte_length` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 13 | `match_libraries` | Match and filter known library functions to focus on user code. | `file_path` (string, req), `signature_db` (any), `max_output_size` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 14 | `parse_binary_with_lief` | Parse binary metadata using LIEF and return structured results. | `file_path` (string, req), `format` (string) | `static`, `malware`, `vuln-research` |
| 15 | `patch_diff_1day` | Analyze patch differences for 1-day vulnerability analysis. | `file_path_a` (string, req), `file_path_b` (string, req), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 16 | `run_binwalk` | Analyze binaries for embedded content using binwalk. | `file_path` (string, req), `depth` (integer), `max_output_size` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 17 | `run_binwalk_extract` | Extract embedded files and file systems from a binary using binwalk. | `file_path` (string, req), `output_dir` (any), `matryoshka` (boolean), `depth` (integer), `max_output_size` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 18 | `run_capa` | Analyze binary capabilities using CAPA (Mandiant FLARE). | `file_path` (string, req), `output_format` (string) | `static`, `malware`, `vuln-research` |
| 19 | `run_capa_quick` | Quick CAPA scan returning only high-risk capabilities. | `file_path` (string, req) | `static`, `malware`, `vuln-research` |
| 20 | `run_fuzzing_campaign` | Run a real AFL++ fuzzing campaign and automatically triage all crashes. | `file_path` (string, req), `timeout_seconds` (integer), `seed_corpus` (any), `use_stdin` (boolean), `max_crashes_to_triage` (integer), `afl_extra_args` (string), `target_function_or_addr` (any), `fuzzer_type` (string) | `static`, `malware`, `vuln-research` |
| 21 | `run_strings` | Extract printable strings using the ``strings`` CLI. | `file_path` (string, req), `min_length` (integer), `max_output_size` (integer), `timeout` (integer), `run_async` (boolean), `_bypass_queue` (boolean) | `static`, `malware`, `vuln-research` |
| 22 | `scan_for_versions` | Extract library version strings and CVE clues from a binary. | `file_path` (string, req), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 23 | `taint_trace` | Automatically trace taint paths from user input sources to dangerous sinks. | `file_path` (string, req), `sources` (any), `sinks` (any), `verify_with_angr` (boolean), `max_paths` (integer), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 24 | `triage_crash` | Analyze a crash file against a binary using GDB to determine exploitability. | `binary_path` (string, req), `crash_file` (string, req), `use_stdin` (boolean), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 25 | `verify_path_and_get_args` | Run symbolic execution using angr to verify path reachability and extract inputs. | `file_path` (string, req), `target_addr` (string, req), `start_addr` (any), `avoid_addrs` (any), `timeout` (integer) | `static`, `malware`, `vuln-research` |
| 26 | `vt_lookup` | Look up IOC reputation using the VirusTotal API v3. | `iocs` (array, req), `api_key` (any) | `static`, `malware`, `vuln-research` |

---

### 📜 Source Code Auditing (`source_auditor` — 1 tools)

*AST & Regex Pattern Analysis for Python/C/C++*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 27 | `audit_source_code` | Perform a security audit on a source code file (SAST). | `file_path` (string, req), `language` (any) | `vuln-research` |

---

### ⚙️ Radare2 & Decompilation (`radare2_mcp_tools` — 47 tools)

*Disassembly, CFG, Ghidra Decompiler & ESIL Emulation*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 28 | `Radare2_analyze` | Run binary analysis with optional depth level. | `file_path` (string, req), `level` (integer), `arch` (any), `bits` (any) | `static`, `vuln-research` |
| 29 | `Radare2_calculate` | Evaluate a math expression using radare2's number parser. | `file_path` (string, req), `expression` (string, req) | `static`, `vuln-research` |
| 30 | `Radare2_close_file` | Close the currently open radare2 session for a file. | `file_path` (string, req) | `static`, `vuln-research` |
| 31 | `Radare2_decompile_function` | Show C-like pseudocode of the function at the given address. | `file_path` (string, req), `address` (string, req), `line_offset` (integer), `max_lines` (integer), `cursor` (any), `page_size` (integer) | `static`, `vuln-research` |
| 32 | `Radare2_disassemble` | Disassemble a specific number of instructions from an address. | `file_path` (string, req), `address` (string, req), `num_instructions` (integer) | `static`, `vuln-research` |
| 33 | `Radare2_disassemble_function` | Show assembly listing of the function at the specified address. | `file_path` (string, req), `address` (string, req), `format` (string), `cursor` (any), `page_size` (integer) | `static`, `vuln-research` |
| 34 | `Radare2_get_current_address` | Show the current seek position and function name. | `file_path` (string, req) | `static`, `vuln-research` |
| 35 | `Radare2_get_function_prototype` | Retrieve the function signature at the specified address. | `file_path` (string, req), `address` (string, req) | `static`, `vuln-research` |
| 36 | `Radare2_list_all_strings` | Scan the entire binary for strings with optional regex filter. | `file_path` (string, req), `filter` (any), `cursor` (any), `page_size` (integer) | `static`, `vuln-research` |
| 37 | `Radare2_list_classes` | List class names from various languages (C++, ObjC, Swift, Java, Dalvik). | `file_path` (string, req), `filter` (any) | `static`, `vuln-research` |
| 38 | `Radare2_list_decompilers` | Show all available decompiler backends. | `file_path` (string, req) | `static`, `vuln-research` |
| 39 | `Radare2_list_entrypoints` | Display program entrypoints, constructors and main function. | `file_path` (string, req) | `static`, `vuln-research` |
| 40 | `Radare2_list_functions` | List all functions discovered during analysis. | `file_path` (string, req), `only_named` (boolean), `filter` (any) | `static`, `vuln-research` |
| 41 | `Radare2_list_functions_tree` | List functions and their successors (call tree). | `file_path` (string, req) | `static`, `vuln-research` |
| 42 | `Radare2_list_imports` | List imported symbols. | `file_path` (string, req), `filter` (any) | `static`, `vuln-research` |
| 43 | `Radare2_list_libraries` | List all shared libraries linked to the binary. | `file_path` (string, req) | `static`, `vuln-research` |
| 44 | `Radare2_list_methods` | List all methods belonging to the specified class. | `file_path` (string, req), `classname` (string, req) | `static`, `vuln-research` |
| 45 | `Radare2_list_sections` | Display memory sections and segments from the binary. | `file_path` (string, req) | `static`, `vuln-research` |
| 46 | `Radare2_list_strings` | List strings from data sections with optional regex filter. | `file_path` (string, req), `filter` (any), `cursor` (any), `page_size` (integer) | `static`, `vuln-research` |
| 47 | `Radare2_list_symbols` | Show all symbols (functions, variables, imports) with addresses. | `file_path` (string, req), `filter` (any) | `static`, `vuln-research` |
| 48 | `Radare2_open_file` | Opens a binary file with radare2 for analysis. | `file_path` (string, req), `arch` (any), `bits` (any) | `static`, `vuln-research` |
| 49 | `Radare2_rename_flag` | Rename a flag (variable or data reference) at the specified address. | `file_path` (string, req), `address` (string, req), `name` (string, req), `new_name` (string, req) | `static`, `vuln-research` |
| 50 | `Radare2_rename_function` | Rename the function at the specified address. | `file_path` (string, req), `address` (string, req), `name` (string, req) | `static`, `vuln-research` |
| 51 | `Radare2_run_command` | Execute a raw radare2 command directly. | `file_path` (string, req), `command` (string, req) | `static`, `vuln-research` |
| 52 | `Radare2_set_comment` | Add a comment at the specified address. | `file_path` (string, req), `address` (string, req), `message` (string, req) | `static`, `vuln-research` |
| 53 | `Radare2_set_function_prototype` | Set the function signature (return type, name, arguments). | `file_path` (string, req), `address` (string, req), `prototype` (string, req) | `static`, `vuln-research` |
| 54 | `Radare2_show_function_details` | Display detailed information about a function. | `file_path` (string, req), `address` (any) | `static`, `vuln-research` |
| 55 | `Radare2_show_headers` | Display binary headers and file information. | `file_path` (string, req) | `static`, `vuln-research` |
| 56 | `Radare2_use_decompiler` | Select which decompiler backend to use. | `file_path` (string, req), `name` (string, req) | `static`, `vuln-research` |
| 57 | `Radare2_xrefs_to` | Find all code references TO the specified address. | `file_path` (string, req), `address` (string, req), `limit` (integer) | `static`, `vuln-research` |
| 58 | `analyze_xrefs` | Analyze cross-references (xrefs) for a specific address using radare2. | `file_path` (string, req), `address` (string, req), `xref_type` (string), `limit` (integer), `timeout` (integer) | `static`, `vuln-research` |
| 59 | `emulate_machine_code` | Emulate machine code execution using radare2 ESIL (Evaluable Strings Intermediate Language). | `file_path` (string, req), `start_address` (string, req), `instructions` (integer), `timeout` (integer) | `static`, `vuln-research` |
| 60 | `generate_function_graph` | Generate a Control Flow Graph (CFG) for a specific function. | `file_path` (string, req), `function_address` (string, req), `format` (string), `timeout` (integer) | `static`, `vuln-research` |
| 61 | `r2_add_bookmark` | Add (or update) an annotated bookmark at a binary address. | `file_path` (string, req), `address` (string, req), `comment` (string, req), `category` (string) | `static`, `vuln-research` |
| 62 | `r2_analyze_function` | Return full metadata for a binary function via radare2. | `file_path` (string, req), `function_address` (string, req), `timeout` (integer) | `static`, `vuln-research` |
| 63 | `r2_create_structure` | Save (or replace) a C struct definition in the annotation DB. | `file_path` (string, req), `name` (string, req), `fields` (any, req) | `static`, `vuln-research` |
| 64 | `r2_decompile` | Decompile a binary function to pseudo-C using the r2ghidra plugin. | `file_path` (string, req), `function_address` (string, req), `line_offset` (integer), `max_lines` (integer), `timeout` (integer) | `static`, `vuln-research` |
| 65 | `r2_get_call_graph` | Generate a caller/callee call graph for a function. | `file_path` (string, req), `function_address` (string, req), `depth` (integer), `timeout` (integer) | `static`, `vuln-research` |
| 66 | `r2_get_structure` | Retrieve a single saved struct definition by name. | `file_path` (string, req), `name` (string, req) | `static`, `vuln-research` |
| 67 | `r2_list_bookmarks` | List all saved bookmarks / address annotations for a binary. | `file_path` (string, req), `category` (any), `offset` (integer), `limit` (integer) | `static`, `vuln-research` |
| 68 | `r2_list_structures` | List all saved C struct definitions for a binary. | `file_path` (string, req), `offset` (integer), `limit` (integer) | `static`, `vuln-research` |
| 69 | `r2_list_types` | List all custom type definitions saved for a binary. | `file_path` (string, req), `offset` (integer), `limit` (integer) | `static`, `vuln-research` |
| 70 | `r2_read_memory` | Read raw bytes from a binary at a given virtual address. | `file_path` (string, req), `address` (string, req), `size` (integer) | `static`, `vuln-research` |
| 71 | `r2_recover_structures` | Recover C struct layouts from a function's memory access patterns. | `file_path` (string, req), `function_address` (string, req), `timeout` (integer) | `static`, `vuln-research` |
| 72 | `r2_simulate_patch` | Simulate a byte-level patch at an address and re-decompile. | `file_path` (string, req), `address` (string, req), `patch_bytes` (string, req), `timeout` (integer) | `static`, `vuln-research` |
| 73 | `run_radare2` | Execute vetted radare2 commands for binary triage. | `file_path` (string, req), `r2_command` (string, req), `max_output_size` (integer), `timeout` (integer) | `static`, `vuln-research` |
| 74 | `trace_execution_path` | Trace function calls backwards from a target function (Sink) to find potential execution paths. | `file_path` (string, req), `target_function` (string, req), `max_depth` (integer), `max_paths` (integer), `timeout` (any), `prioritize_sinks` (boolean) | `static`, `vuln-research` |

---

### 🦠 Malware Analysis & Threat Hunting (`malware_tools` — 11 tools)

*YARA Detection, Anti-Analysis, Packer & Vaccine Engines*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 75 | `adaptive_vaccine` | Generate automated defenses against detected threats. | `threat_report` (object, req), `action` (string), `file_path` (any), `dry_run` (boolean) | `malware` |
| 76 | `analyze_heap_exploit` | Analyze heap corruption crashes and generate exploitation strategies. | `file_path` (string, req), `crash_file` (any), `overflow_size` (integer), `target_object` (string), `glibc_version` (string), `use_stdin_for_crash` (boolean), `simulate_esil` (boolean) | `malware` |
| 77 | `autonomous_vuln_hunt` | Fully autonomous end-to-end vulnerability discovery and exploit generation. | `file_path` (string, req), `max_functions` (integer), `timeout_per_function` (integer), `objective` (string), `auto_poc` (boolean), `auto_rop` (boolean), `severity_filter` (string), `enable_taint` (boolean), `enable_fuzzing` (boolean), `fuzzing_timeout` (integer) | `malware` |
| 78 | `build_rop_chain` | Automatically build a Return-Oriented Programming (ROP) exploit chain. | `file_path` (string, req), `objective` (string), `libc_path` (string), `offset` (integer) | `malware` |
| 79 | `detect_anti_analysis` | Detect anti-debugging, timing anomalies, hypervisor/anti-VM, and opaque conditionals. | `file_path` (string, req), `focus_functions` (any), `verify_with_esil` (boolean), `timeout` (integer) | `malware` |
| 80 | `dormant_detector` | Detect hidden malicious behaviors using static analysis + emulation. | `file_path` (string, req), `focus_function` (any), `hypothesis` (any), `timeout` (integer) | `malware` |
| 81 | `extract_iocs` | Extract Indicators of Compromise (IOCs) from text or file using regex. | `text` (string), `file_path` (string), `extract_ips` (boolean), `extract_urls` (boolean), `extract_emails` (boolean), `extract_bitcoin` (boolean), `extract_hashes` (boolean), `extract_others` (boolean), `limit` (integer) | `malware` |
| 82 | `generate_poc_exploit` | Generate and verify a pwntools proof-of-concept exploit script. | `file_path` (string, req), `vulnerability_class` (string), `concrete_input` (string), `crash_offset` (integer) | `malware` |
| 83 | `packer_fingerprint` | Deep fingerprinting of binary packers, cryptors, protectors, and compilers. | `file_path` (string, req), `timeout` (integer) | `malware` |
| 84 | `run_yara` | Scan binaries against YARA rules via ``yara-python`` with modular namespace support. | `file_path` (string, req), `rule_file` (any), `category` (any), `timeout` (integer), `run_async` (boolean), `_bypass_queue` (boolean) | `malware` |
| 85 | `vulnerability_hunter` | Automated vulnerability discovery combining multiple analysis techniques. | `file_path` (string, req), `max_depth` (integer), `severity_filter` (string), `generate_yara` (boolean), `timeout` (integer), `use_symbolic_execution` (boolean), `auto_dynamic_verify` (boolean), `run_async` (boolean), `_bypass_queue` (boolean) | `malware` |

---

### 🧩 Automated Deobfuscation (`deobfuscation_tools` — 4 tools)

*String Decryption, API Hashing & Dead Code Removal*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 86 | `deobfuscate_strings` | Recover dynamically constructed stack strings and emulated loop strings in a binary. | `file_path` (string, req), `function_address` (any), `timeout` (any) | `malware` |
| 87 | `eliminate_dead_code` | Analyze opaque predicates and identify unreachable basic blocks in a function CFG. | `file_path` (string, req), `function_address` (any), `timeout` (any) | `malware` |
| 88 | `resolve_api_hashes` | Detect dynamic PEB/TEB walking and resolve 32-bit API hashes to Windows export symbols. | `file_path` (string, req), `algorithm` (any), `custom_hashes` (any), `timeout` (any) | `malware` |
| 89 | `run_deobfuscation_pipeline` | Run all deobfuscation engines concurrently and assemble a unified intelligence report. | `file_path` (string, req), `options` (any), `timeout` (any) | `malware` |

---

### 🎯 Vulnerability Research & CVE Hunting (`cve_hunter_tools` — 5 tools)

*ASan Crash Triage, Fuzz Harness Synthesis & PoC Minimization*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 90 | `cve_fuzz_target` | Execute hybrid fuzzing campaign with Sanitizer tracking and angr concolic seed solver. | `target_binary_path` (string, req), `corpus_dir` (any), `dictionary_path` (any), `max_total_time_seconds` (integer), `enable_angr_concolic` (boolean), `timeout` (any) | `vuln-research` |
| 91 | `cve_minimize_poc` | Minimize crash testcase payload via delta-debugging and generate standalone PoC scripts. | `binary_path` (string, req), `crash_input_path` (string, req), `target_function` (any), `timeout` (any) | `vuln-research` |
| 92 | `cve_synthesize_harness` | Synthesize LibFuzzer/AFL++ C/C++ test harness and format dictionary (.dict) for target parser. | `header_or_binary_path` (string, req), `sample_file_path` (any), `target_function` (any), `timeout` (any) | `vuln-research` |
| 93 | `cve_triage_crash` | Triage AddressSanitizer/UBSan crash log and compute CWE and CVSS v3.1 rating. | `crash_log_or_text` (string, req), `timeout` (any) | `vuln-research` |
| 94 | `hunt_cve_vulnerabilities` | One-click automated CVE hunting pipeline for C/C++ libraries, parsers, and codecs. | `target_path` (string, req), `sample_file_path` (any), `options` (any), `timeout` (any) | `vuln-research` |

---

### 🔬 Digital Forensics (`forensics_tools` — 22 tools)

*Memory (Volatility), Network (PCAP), Disk & Artifacts*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 95 | `artifact_collect` | Collect and normalize forensic artifacts from analysis results. | `artifacts` (array, req), `artifact_type` (string), `source` (string) | `forensics` |
| 96 | `artifact_correlate_ioc` | Correlate collected forensic artifacts against IoC patterns. | `artifacts` (array, req), `check_ips` (boolean), `check_domains` (boolean), `check_hashes` (boolean) | `forensics` |
| 97 | `artifact_generate_yara` | Auto-generate YARA rules from collected forensic artifacts. | `artifacts` (array, req), `rule_name` (string), `output_path` (any) | `forensics` |
| 98 | `artifact_report` | Export a comprehensive forensics investigation report. | `artifacts` (array, req), `case_name` (string), `analyst` (string), `include_yara` (boolean), `output_path` (any) | `forensics` |
| 99 | `artifact_timeline` | Build a chronological event timeline from multi-source forensic artifacts. | `artifacts` (array, req), `sort_order` (string) | `forensics` |
| 100 | `disk_analyze_mft` | Analyze the NTFS Master File Table (MFT) for file timeline and metadata. | `image_path` (string, req), `offset` (any), `limit` (integer) | `forensics` |
| 101 | `disk_extract_file` | Extract a live (non-deleted) file from a disk image by inode number. | `image_path` (string, req), `inode` (string, req), `output_path` (string, req), `offset` (any) | `forensics` |
| 102 | `disk_hash_verify` | Compute and verify the integrity hash of a disk image or recovered file. | `image_path` (string, req), `expected_hash` (any), `algorithm` (string) | `forensics` |
| 103 | `disk_list_files` | List all files and directories in a disk/filesystem image. | `image_path` (string, req), `directory` (string), `include_deleted` (boolean), `offset` (any), `recursive` (boolean), `limit` (integer) | `forensics` |
| 104 | `disk_list_partition` | List partition layout of a disk image using Sleuth Kit mmls. | `image_path` (string, req) | `forensics` |
| 105 | `disk_recover_deleted` | Recover a deleted file from a disk/filesystem image by inode number. | `image_path` (string, req), `inode` (string, req), `output_path` (string, req), `offset` (any) | `forensics` |
| 106 | `memory_analyze` | Run a Volatility3 plugin against a memory dump file. | `dump_path` (string, req), `plugin` (string), `symbol_path` (any), `extra_args` (any), `_bypass_queue` (boolean) | `forensics` |
| 107 | `memory_detect_injections` | Detect process injection and suspicious memory regions using Volatility3 malfind. | `dump_path` (string, req), `_bypass_queue` (boolean) | `forensics` |
| 108 | `memory_dump_module` | Dump a loaded module or DLL from a memory dump via Volatility3. | `dump_path` (string, req), `process_name` (string, req), `module_name` (any), `output_dir` (any) | `forensics` |
| 109 | `memory_extract_strings` | Extract ASCII and Unicode strings from a memory dump. | `dump_path` (string, req), `min_length` (integer), `limit` (integer) | `forensics` |
| 110 | `memory_list_processes` | List all running processes from a memory dump. | `dump_path` (string, req), `include_hidden` (boolean) | `forensics` |
| 111 | `memory_list_symbols` | List available Volatility3 symbol tables for a memory dump. | `dump_path` (string, req) | `forensics` |
| 112 | `pcap_analyze` | Summarize sessions, protocols, and packet statistics from a PCAP file. | `pcap_path` (string, req), `max_packets` (integer) | `forensics` |
| 113 | `pcap_extract_c2` | Detect potential C2 traffic patterns in a PCAP capture. | `pcap_path` (string, req), `beacon_threshold_sec` (integer), `max_packets` (integer) | `forensics` |
| 114 | `pcap_extract_dns` | Extract DNS queries and responses from a PCAP capture. | `pcap_path` (string, req), `include_responses` (boolean), `max_packets` (integer) | `forensics` |
| 115 | `pcap_list_connections` | List all unique IP/port connections observed in a PCAP capture. | `pcap_path` (string, req), `protocol` (any), `max_packets` (integer) | `forensics` |
| 116 | `pcap_reconstruct_stream` | Reconstruct TCP stream payload from a PCAP capture. | `pcap_path` (string, req), `src_ip` (string, req), `dst_ip` (string, req), `dst_port` (integer, req), `max_packets` (integer), `max_bytes` (integer) | `forensics` |

---

### 🧠 Process & Memory Utilities (`memory_tools` — 11 tools)

*Live Memory Inspection, Patterns & Hex Dumps*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 117 | `complete_memory_session` | Mark an analysis session as completed with a summary. | `session_id` (string, req), `summary` (string, req) | `forensics` |
| 118 | `create_memory_session` | Create a new memory session to store memories. | `name` (string, req), `binary_name` (any), `binary_path` (any) | `forensics` |
| 119 | `find_similar_patterns` | Find similar patterns from previous analyses. | `pattern_signature` (string, req), `pattern_type` (any), `current_session_id` (any), `limit` (integer) | `forensics` |
| 120 | `get_memory_session_detail` | Get complete details and context for a specific session. | `session_id` (string, req) | `forensics` |
| 121 | `get_relevant_context` | Get relevant context from past analyses for current work. | `description` (string, req), `current_session_id` (any), `limit` (integer) | `forensics` |
| 122 | `list_memory_sessions` | List all analysis sessions with timestamps and status. | `status` (any), `limit` (integer) | `forensics` |
| 123 | `recall_memory_item` | Search and recall memories from past analyses. | `query` (string, req), `session_id` (any), `memory_type` (any), `limit` (integer) | `forensics` |
| 124 | `resume_memory_session` | Resume a previous analysis session with full context restoration. | `session_id` (any), `binary_name` (any) | `forensics` |
| 125 | `save_memory_item` | Save important information to long-term memory. | `session_id` (string, req), `memory_type` (string, req), `content` (string, req), `category` (any), `user_prompt` (any), `importance` (integer) | `forensics` |
| 126 | `save_pattern` | Save a code/behavior pattern for cross-session similarity search. | `session_id` (string, req), `pattern_type` (string, req), `pattern_signature` (string, req), `description` (any) | `forensics` |
| 127 | `update_memory_session_time` | Update the cumulative analysis time for a session. | `session_id` (string, req), `duration_seconds` (number, req) | `forensics` |

---

### 🛠️ Common Binary Utilities (`common_tools` — 7 tools)

*File Operations, Hashing, Patch Explanations & Assembly*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 128 | `assemble_instructions` | Assemble assembly instruction strings into raw machine byte values using Keystone. | `assembly_code` (string, req), `arch` (string), `mode` (string), `base_address` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 129 | `copy_to_workspace` | Copy any accessible file to the workspace directory. | `source_path` (string, req), `destination_name` (any) | `static`, `malware`, `forensics`, `vuln-research` |
| 130 | `create_directory` | Create a new sub-directory within the workspace. | `directory_path` (string, req) | `static`, `malware`, `forensics`, `vuln-research` |
| 131 | `explain_patch` | Analyze differences between two binaries and explain changes in natural language. | `file_path_a` (string, req), `file_path_b` (string, req), `function_name` (any) | `static`, `malware`, `forensics`, `vuln-research` |
| 132 | `list_workspace` | List all files in the workspace directory. | *(none)* | `static`, `malware`, `forensics`, `vuln-research` |
| 133 | `run_file` | Identify file metadata using the ``file`` CLI utility. | `file_path` (string, req), `timeout` (integer) | `static`, `malware`, `forensics`, `vuln-research` |
| 134 | `scan_workspace` | Batch scan all files in the workspace using multiple tools in parallel. | `file_patterns` (any), `timeout` (integer) | `static`, `malware`, `forensics`, `vuln-research` |

---

### 🖥️ Server Lifecycle & State (`server_tools` — 2 tools)

*Server Status, Health & Memory Cache Management*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 135 | `get_server_health` | Get the current health status and resource usage of the MCP server. | *(none)* | `static`, `malware`, `forensics`, `vuln-research` |
| 136 | `get_tool_metrics` | Get detailed execution metrics for specific or all tools. | `tool_name` (any) | `static`, `malware`, `forensics`, `vuln-research` |

---

### 📋 Reporting & MITRE ATT&CK (`report_tools` — 14 tools)

*Session Reports, MITRE Mapping, SIGMA & VEX Generation*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 137 | `add_analysis_note` | Add a timestamped note to the analysis session. | `note` (string, req), `category` (string), `session_id` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 138 | `add_ioc` | Add an Indicator of Compromise to the current session. | `ioc_type` (string, req), `value` (string, req), `session_id` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 139 | `add_mitre_technique` | Add a MITRE ATT&CK technique to the session. | `technique_id` (string, req), `technique_name` (string, req), `tactic` (string, req), `session_id` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 140 | `create_analysis_report` | Generate a comprehensive analysis report. | `template_type` (string), `session_id` (string), `sample_path` (string), `analyst` (string), `classification` (string), `output_format` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 141 | `end_report_session` | End the current analysis session. | `session_id` (string), `status` (string), `summary` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 142 | `generate_sigma_rule` | Generate a Sigma rule (YAML) for SIEM integration based on extracted IOCs or API calls. | `title` (string, req), `iocs` (any), `api_calls` (any), `category` (string), `product` (string), `level` (string), `description` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 143 | `generate_vex_report` | Generate a CSAF 2.0 VEX JSON report from vulnerability findings. | `product_name` (string, req), `product_version` (string, req), `vulnerabilities` (string, req), `document_title` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 144 | `get_report_session_status` | Get current session information and collected data. | `session_id` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 145 | `get_system_time` | Get accurate system timestamp from the server. | *(none)* | `static`, `malware`, `forensics`, `vuln-research` |
| 146 | `get_timezone_info` | Get current timezone configuration and available options. | *(none)* | `static`, `malware`, `forensics`, `vuln-research` |
| 147 | `list_report_sessions` | List all analysis sessions with their status and duration. | *(none)* | `static`, `malware`, `forensics`, `vuln-research` |
| 148 | `set_severity` | Update the severity level of the analysis. | `severity` (string, req), `session_id` (string) | `static`, `malware`, `forensics`, `vuln-research` |
| 149 | `set_timezone` | Set the default timezone for timestamps. | `timezone` (string, req) | `static`, `malware`, `forensics`, `vuln-research` |
| 150 | `start_report_session` | Start a new malware analysis session. | `sample_path` (string), `analyst` (string), `severity` (string), `malware_family` (string), `tags` (string) | `static`, `malware`, `forensics`, `vuln-research` |

---

### ⏳ Task Queue & Async Jobs (`core_task_queue` — 1 tools)

*Background Job Status & Result Retrieval*

| # | Tool Name | Description | Key Parameters | Profiles |
|:---:|---|---|---|---|
| 151 | `get_job_result` | Retrieve the status and result of a background job from the task queue. | `job_id` (string, req) | `static`, `malware`, `forensics`, `vuln-research` |

---

## 📁 Dynamic Context Resources (11 URIs)

Resources provide direct read-only context to AI clients without requiring tool invocations:

| URI Template | MIME Type | Description |
|---|:---:|---|
| `reversecore://guide` | `text/markdown` | Tool usage guide with file path rules and security practices |
| `reversecore://guide/structures` | `text/markdown` | Structure recovery and cross-reference analysis technical guide |
| `reversecore://tools` | `text/markdown` | Authoritative catalog and usage reference for all registered tools |
| `reversecore://logs` | `text/markdown` | Application and execution logs (tail 100 lines) |
| `reversecore://{filename}/metadata` | `text/markdown` | Binary file metadata, hashes, architecture, and headers |
| `reversecore://{filename}/func/{address}/xrefs` | `text/markdown` | Cross-references (to/from) for a specific function address |
| `reversecore://{filename}/func/{address}/context` | `text/markdown` | Contextual disassembly and call hierarchy for a function |
| `reversecore://{filename}/memory_map` | `text/markdown` | Virtual memory segment layout and permissions |
| `reversecore://{filename}/signatures` | `text/markdown` | Cryptographic and compiler signature detection results |
| `reversecore://{filename}/imports` | `text/markdown` | Imported dynamic libraries and symbol tables |
| `reversecore://{filename}/exports` | `text/markdown` | Exported function symbols and entry points |
