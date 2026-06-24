# Reversecore MCP Tools Documentation

> **AI Agent Quick Start**: Read [Tag Legend](#tag-legend), then [Analysis Recipes](#analysis-recipes), then [Phase Guide](#phase-based-tool-guide) — skip the full reference until you need a specific tool's arguments.

Comprehensive reference for all 96 tools available in the Reversecore MCP server for reverse engineering and malware analysis.

## Table of Contents

1. [Tag Legend](#tag-legend) — Tool capability tags explained
2. [Quick-Reference Table](#quick-reference-table) — All 96 tools at a glance
3. [Analysis Recipes](#analysis-recipes) — Task-based tool combinations
4. [Phase-Based Tool Guide](#phase-based-tool-guide) — What to run first, what to run next
5. [Analysis Tools](#analysis-tools) (11 tools) - Binary diffing, signature generation, static analysis
6. [Common Tools](#common-tools) (17 tools) - Memory management, file operations, server monitoring
7. [Ghidra Tools](#ghidra-tools) (17 tools) - Structure recovery, decompilation, patching
8. [Malware Tools](#malware-tools) (5 tools) - Threat detection, IOC extraction, YARA scanning
9. [Radare2 Tools](#radare2-tools) (34 tools) - Comprehensive binary analysis suite
10. [Report Tools](#report-tools) (12 tools) - Professional malware analysis reporting

---

## Tag Legend

Every tool in this document is annotated with one or more tags that help AI agents quickly understand when and how to use them.

| Tag | Meaning |
|-----|---------|
| `[FIRST]` | **Run this first.** Essential for every analysis — do not skip. |
| `[QUICK]` | Fast result (< 5 seconds). Ideal for initial triage. |
| `[SLOW]` | Execution time > 30 seconds. Run only when needed. |
| `[STATIC]` | Works on the file without execution — always safe. |
| `[DYNAMIC]` | Emulates or traces execution. Sandboxed, but slower. |
| `[GHIDRA]` | Requires Ghidra to be installed (`GHIDRA_INSTALL_DIR`). |
| `[SESSION]` | Requires an active Radare2 session (`Radare2_open_file` first). |
| `[AI_MEMORY]` | Manages AI long-term memory across sessions. |
| `[REPORT]` | Produces analyst-facing output (session, IOC, MITRE). |
| `[PE_ONLY]` | Most reliable on PE (Windows .exe/.dll) files. |
| `[ELF_OK]` | Works well on ELF (Linux) binaries. |
| `[FIRMWARE]` | Specialized for firmware / IoT images. |
| `[C++]` | Designed for C++ binaries (RTTI, vtables, classes). |
| `[COMPARISON]` | Requires two files (before/after, original/variant). |

---

## Quick-Reference Table

All 96 tools sorted by category. The "Needs" column shows what must be done before calling this tool.

### Analysis Tools

| Tool | Tags | One-line Description | Needs |
|------|------|----------------------|-------|
| `diff_binaries` | `[STATIC]` `[COMPARISON]` | Compare two binaries, get similarity score + diff list | Two files |
| `analyze_variant_changes` | `[STATIC]` `[COMPARISON]` `[SLOW]` | Structural diff + CFG for top-changed functions | Two files |
| `match_libraries` | `[STATIC]` `[SLOW]` | Filter out known library functions; focus on user code | — |
| `parse_binary_with_lief` | `[STATIC]` `[QUICK]` `[FIRST]` | PE/ELF/Mach-O metadata: headers, sections, imports | — |
| `generate_signature` | `[STATIC]` | YARA signature from opcode bytes at an address | — |
| `generate_yara_rule` | `[STATIC]` | Full YARA rule from function bytes | — |
| `generate_enhanced_yara_rule` | `[STATIC]` | YARA rule with entropy + byte patterns combined | — |
| `run_strings` | `[STATIC]` `[QUICK]` `[FIRST]` | Extract printable strings (≥ min_length chars) | — |
| `run_binwalk` | `[STATIC]` `[QUICK]` `[FIRMWARE]` | Detect embedded content signatures (no extraction) | — |
| `run_binwalk_extract` | `[STATIC]` `[SLOW]` `[FIRMWARE]` | Extract embedded files/file systems from binary | — |
| `scan_for_versions` | `[STATIC]` `[QUICK]` | Find library version strings (OpenSSL, GCC, etc.) | — |
| `extract_rtti_info` | `[STATIC]` `[QUICK]` `[C++]` | Extract C++ class names and inheritance from RTTI | — |

### Common Tools

| Tool | Tags | One-line Description | Needs |
|------|------|----------------------|-------|
| `create_memory_session` | `[AI_MEMORY]` `[QUICK]` | Start a new AI memory session for this analysis | — |
| `save_memory_item` | `[AI_MEMORY]` `[QUICK]` | Store a finding, address, or insight in memory | Active session |
| `recall_memory_item` | `[AI_MEMORY]` `[QUICK]` | Full-text + semantic search over stored memories | — |
| `list_memory_sessions` | `[AI_MEMORY]` `[QUICK]` | List all memory sessions (optionally filter by status) | — |
| `get_memory_session_detail` | `[AI_MEMORY]` `[QUICK]` | Full details + all memories for one session | Session ID |
| `resume_memory_session` | `[AI_MEMORY]` `[QUICK]` | Resume a previous session and load its context | Session ID |
| `complete_memory_session` | `[AI_MEMORY]` `[QUICK]` | Close session with a summary | Session ID |
| `save_pattern` | `[AI_MEMORY]` `[QUICK]` | Save a reusable pattern for cross-session recognition | Active session |
| `find_similar_patterns` | `[AI_MEMORY]` `[QUICK]` | Find previously saved patterns matching a signature | — |
| `get_relevant_context` | `[AI_MEMORY]` `[QUICK]` | Auto-retrieve relevant memories for current task | — |
| `update_analysis_time` | `[AI_MEMORY]` `[QUICK]` | Log elapsed analysis time into session | Session ID |
| `get_server_health` | `[QUICK]` | Server uptime, memory usage, error rate | — |
| `get_tool_metrics` | `[QUICK]` | Per-tool call count, avg time, error rate | — |
| `run_file` | `[STATIC]` `[QUICK]` `[FIRST]` | File type, architecture, magic identification | — |
| `copy_to_workspace` | `[QUICK]` | Copy any file into workspace so tools can access it | — |
| `list_workspace` | `[QUICK]` | List all files in workspace | — |
| `scan_workspace` | `[STATIC]` `[SLOW]` | Batch run file/LIEF/YARA on all workspace files | — |
| `explain_patch` | `[STATIC]` `[COMPARISON]` | Natural-language explanation of binary diff | Two files |

### Ghidra Tools

| Tool | Tags | One-line Description | Needs |
|------|------|----------------------|-------|
| `Ghidra_list_structures` | `[GHIDRA]` `[SLOW]` `[C++]` | List all defined structs in the binary | — |
| `Ghidra_get_structure` | `[GHIDRA]` `[SLOW]` `[C++]` | Get fields, offsets, size for a named struct | — |
| `Ghidra_create_structure` | `[GHIDRA]` `[SLOW]` `[C++]` | Define a new C struct in Ghidra's type database | — |
| `Ghidra_list_enums` | `[GHIDRA]` `[SLOW]` | List all enum definitions | — |
| `Ghidra_list_data_types` | `[GHIDRA]` `[SLOW]` | List all data types (struct, typedef, pointer...) | — |
| `Ghidra_list_bookmarks` | `[GHIDRA]` `[SLOW]` | List Ghidra bookmarks (Notes, Warnings, Errors) | — |
| `Ghidra_add_bookmark` | `[GHIDRA]` `[SLOW]` | Add a bookmark at a specific address | — |
| `Ghidra_read_memory` | `[GHIDRA]` `[SLOW]` | Read raw bytes at an address | — |
| `Ghidra_get_bytes` ⚠️ | `[GHIDRA]` `[SLOW]` | Get bytes as hex string (prefer `Ghidra_read_memory`) | — |
| `Ghidra_simulate_patch` | `[GHIDRA]` `[SLOW]` | Simulate patching (in cache only, file unchanged) | — |
| `Ghidra_analyze_function` | `[GHIDRA]` `[SLOW]` | Force re-analysis of a function with all analyzers | — |
| `Ghidra_get_call_graph` | `[GHIDRA]` `[SLOW]` | Callers + callees call graph for a function | — |
| `emulate_machine_code` | `[DYNAMIC]` `[SLOW]` | ESIL-based sandboxed emulation (de-obfuscation) | — |
| `get_pseudo_code` | `[STATIC]` `[SLOW]` | r2 `pdc` decompilation to C-like pseudocode | — |
| `smart_decompile` | `[GHIDRA]` `[SLOW]` | Ghidra decompilation (falls back to r2) | — |
| `recover_structures` | `[GHIDRA]` `[SLOW]` `[C++]` | Recover C++ classes from vtable/RTTI patterns | — |

### Malware Tools

| Tool | Tags | One-line Description | Needs |
|------|------|----------------------|-------|
| `dormant_detector` | `[STATIC]` `[SLOW]` | Find time bombs, logic bombs, orphan functions | — |
| `adaptive_vaccine` | `[STATIC]` `[SLOW]` | Generate neutralization patch for malware behavior | — |
| `vulnerability_hunter` | `[STATIC]` `[SLOW]` | Auto-detect buffer overflows, format strings, UAF | — |
| `extract_iocs` | `[STATIC]` `[QUICK]` | Regex-extract IPs, URLs, hashes, CVEs from text/file | — |
| `run_yara` | `[STATIC]` `[QUICK]` | Scan file against a YARA rules file | YARA rules file |
| `run_capa` | `[STATIC]` `[SLOW]` | Detect capabilities (encrypt, persist, lateral move) | capa installed |
| `run_capa_quick` | `[STATIC]` `[SLOW]` | Quick capability scan (fewer rules, faster) | capa installed |
| `detect_packer` | `[STATIC]` `[QUICK]` `[FIRST]` | Detect packer/compiler/protector (DIE-based) | — |
| `detect_packer_deep` | `[STATIC]` `[SLOW]` | Deep packer detection with entropy analysis | — |

### Radare2 Tools

| Tool | Tags | One-line Description | Needs |
|------|------|----------------------|-------|
| `Radare2_open_file` | `[QUICK]` | Open binary in r2, get session ID | — |
| `Radare2_close_file` | `[QUICK]` | Close r2 session | Session ID |
| `Radare2_analyze` | `[SLOW]` `[SESSION]` | Run r2 analysis (basic/standard/advanced) | Session ID |
| `Radare2_run_command` | `[SESSION]` | Execute arbitrary r2 command | Session ID |
| `Radare2_calculate` | `[QUICK]` `[SESSION]` | Calculate hex/address expressions | Session ID |
| `Radare2_list_functions` | `[QUICK]` `[SESSION]` | List all functions (paginated) | Session ID + Analyze |
| `Radare2_list_functions_tree` | `[QUICK]` `[SESSION]` | Call-hierarchy tree view | Session ID + Analyze |
| `Radare2_show_function_details` | `[QUICK]` `[SESSION]` | Size, blocks, complexity, locals for one function | Session ID |
| `Radare2_get_current_address` | `[QUICK]` `[SESSION]` | Current seek address | Session ID |
| `Radare2_get_function_prototype` | `[QUICK]` `[SESSION]` | Return type + parameters signature | Session ID |
| `Radare2_set_function_prototype` | `[SESSION]` | Set function signature for better decompilation | Session ID |
| `Radare2_show_headers` | `[QUICK]` `[SESSION]` | Binary format, arch, entry point | Session ID |
| `Radare2_list_sections` | `[QUICK]` `[SESSION]` | All sections with address, size, permissions | Session ID |
| `Radare2_list_imports` | `[QUICK]` `[SESSION]` | Imported functions + library names | Session ID |
| `Radare2_list_symbols` | `[QUICK]` `[SESSION]` | All symbols (address, type, name) | Session ID |
| `Radare2_list_entrypoints` | `[QUICK]` `[SESSION]` | Entry point addresses | Session ID |
| `Radare2_list_libraries` | `[QUICK]` `[SESSION]` | Linked library dependencies | Session ID |
| `Radare2_list_strings` | `[QUICK]` `[SESSION]` | Strings with optional regex filter | Session ID |
| `Radare2_list_all_strings` | `[SLOW]` `[SESSION]` | All strings without any filter | Session ID |
| `Radare2_list_classes` | `[QUICK]` `[SESSION]` `[C++]` | C++/ObjC classes with vtables | Session ID + Analyze |
| `Radare2_list_methods` | `[QUICK]` `[SESSION]` `[C++]` | Methods for a specific class | Session ID |
| `Radare2_disassemble` | `[QUICK]` `[SESSION]` | N instructions at an address | Session ID |
| `Radare2_disassemble_function` | `[SESSION]` | Full function disassembly | Session ID |
| `Radare2_decompile_function` | `[SESSION]` `[SLOW]` | r2 pseudo-C decompilation | Session ID |
| `Radare2_list_decompilers` | `[QUICK]` `[SESSION]` | Available decompilers (pdc, pdg, r2ghidra) | Session ID |
| `Radare2_use_decompiler` | `[SESSION]` | Switch active decompiler | Session ID |
| `Radare2_xrefs_to` | `[QUICK]` `[SESSION]` | Who calls this address | Session ID |
| `Radare2_rename_function` | `[SESSION]` | Rename a function | Session ID |
| `Radare2_rename_flag` | `[SESSION]` | Rename a label/flag | Session ID |
| `Radare2_set_comment` | `[SESSION]` | Annotate an address with a comment | Session ID |
| `run_radare2` | `[STATIC]` `[QUICK]` | Execute r2 commands without a session | — |
| `trace_execution_path` | `[STATIC]` `[SLOW]` | Backtrace: who calls a dangerous function (system, strcpy) | — |
| `generate_function_graph` | `[STATIC]` `[SLOW]` | CFG as Mermaid/JSON/DOT/PNG | — |
| `analyze_xrefs` | `[STATIC]` `[QUICK]` | Cross-references to/from an address | — |

### Report Tools

| Tool | Tags | One-line Description | Needs |
|------|------|----------------------|-------|
| `get_system_time` | `[QUICK]` `[REPORT]` | Current timestamp with timezone | — |
| `set_timezone` | `[QUICK]` `[REPORT]` | Set timezone for report timestamps | — |
| `get_timezone_info` | `[QUICK]` `[REPORT]` | Current timezone config | — |
| `start_report_session` | `[QUICK]` `[REPORT]` | Start a malware analysis report session | — |
| `end_report_session` | `[QUICK]` `[REPORT]` | End session with final status + summary | Session ID |
| `get_report_session_status` | `[QUICK]` `[REPORT]` | Current session stats (IOCs, notes, duration) | Session ID |
| `list_report_sessions` | `[QUICK]` `[REPORT]` | List all report sessions | — |
| `add_ioc` | `[QUICK]` `[REPORT]` | Add IOC (IP, hash, domain, mutex...) to session | Session ID |
| `add_analysis_note` | `[QUICK]` `[REPORT]` | Add timestamped observation/finding to session | Session ID |
| `add_mitre_technique` | `[QUICK]` `[REPORT]` | Map a MITRE ATT&CK technique to session | Session ID |
| `set_severity` | `[QUICK]` `[REPORT]` | Update threat severity (low/medium/high/critical) | Session ID |
| `create_analysis_report` | `[SLOW]` `[REPORT]` | Generate full professional report (MD/HTML/PDF) | Session ID |

---

## Analysis Recipes

These recipes show the exact tool sequence for common reverse engineering tasks.
Use them as your starting point — adapt as needed based on findings.

---

### 🔴 Recipe 1: Malware Initial Triage (Unknown Sample)

**Goal**: Understand what a suspicious binary is in under 5 minutes.

```
STEP 1 — Identify file type and architecture
  run_file("{file}")                        # [FIRST][QUICK] What kind of file is it?
  detect_packer("{file}")                   # [FIRST][QUICK] Is it packed? If YES → unpack first

STEP 2 — Extract observable artifacts
  run_strings("{file}", min_length=8)       # Readable strings (URLs, keys, commands)
  parse_binary_with_lief("{file}")          # PE/ELF structure, imports, exports, entropy
  extract_iocs("{file}")                    # IPs, URLs, hashes, emails, CVEs

STEP 3 — Capability detection (if not packed)
  run_capa_quick("{file}")                  # What can it DO? (encrypt, persist, C2...)
  run_yara("{file}", "{rules_path}")        # Known malware family match?

STEP 4 — Deep static analysis
  dormant_detector("{file}")               # Time bombs, logic bombs, orphan functions
```

❌ **NOT**: Do NOT run `smart_decompile` or `Ghidra_*` before checking packer status — packed binaries produce meaningless decompilation.

---

### 🟠 Recipe 2: Ransomware Analysis

**Goal**: Identify encryption algorithm, key derivation, and file extension targeting.

```
STEP 1 — Triage (same as Recipe 1, STEP 1-2)
  run_file → detect_packer → run_strings → parse_binary_with_lief

STEP 2 — Find crypto patterns
  run_capa("{file}", "detailed")           # Look for "encrypt data using AES", "derive key"
  run_yara("{file}", "{crypto_rules}")     # Crypto detection YARA rules

STEP 3 — Locate encryption function
  r2_sid = Radare2_open_file("{file}")
  Radare2_analyze(r2_sid, "standard")
  Radare2_list_imports(r2_sid)            # CryptEncrypt, BCryptEncrypt, EVP_EncryptInit?
  Radare2_list_strings(r2_sid, filter="crypt|aes|ransom|encrypt")

STEP 4 — Decompile key functions
  smart_decompile("{file}", "{crypto_func_addr}")
  emulate_machine_code("{file}", "{decrypt_stub_addr}", steps=200)  # De-obfuscate key

STEP 5 — Collect IOCs and report
  add_ioc("mutex", "{mutex_name}")
  add_mitre_technique("T1486", "Data Encrypted for Impact", "Impact")
  create_analysis_report(template_type="technical")
```

---

### 🟡 Recipe 3: Patch Diffing (1-day Exploit Research)

**Goal**: Find what security bug was fixed between two binary versions.

```
STEP 1 — Quick diff overview
  diff_binaries("{before_patch}", "{after_patch}")    # Similarity score + changed areas

STEP 2 — Structural change analysis
  analyze_variant_changes("{before}", "{after}", top_n=5)   # Top 5 most-changed functions + CFG

STEP 3 — Natural-language explanation
  explain_patch("{before}", "{after}")                # Human-readable "what changed and why"

STEP 4 — Deep dive on changed functions
  r2_sid = Radare2_open_file("{after_patch}")
  Radare2_analyze(r2_sid)
  smart_decompile("{after_patch}", "{changed_func}")
  smart_decompile("{before_patch}", "{changed_func}")  # Compare manually

STEP 5 — Vulnerability confirmation
  trace_execution_path("{after_patch}", "{dangerous_func}")  # Is it still reachable?
  vulnerability_hunter("{before_patch}")                     # Was the bug here?
```

---

### 🟢 Recipe 4: C++ Game Client / Application Reverse Engineering

**Goal**: Understand class hierarchy, game objects, and key logic.

```
STEP 1 — Triage
  run_file → parse_binary_with_lief → detect_packer

STEP 2 — C++ structure discovery
  extract_rtti_info("{file}")              # Class names, vtable layout, inheritance
  r2_sid = Radare2_open_file("{file}")
  Radare2_analyze(r2_sid, "advanced")     # Full analysis for C++ (slower but necessary)
  Radare2_list_classes(r2_sid)            # All C++ classes detected by r2

STEP 3 — Recover struct definitions
  recover_structures("{file}", "{player_class_addr}")  # Convert `this+0x4` → `Player.health`

STEP 4 — Explore key functions
  Radare2_list_functions(r2_sid)
  Radare2_show_function_details(r2_sid, "{target_func}")
  Radare2_decompile_function(r2_sid, "{target_func}")
  Ghidra_get_call_graph("{file}", "{target_func}")    # Full call tree

STEP 5 — Find variant changes (game update)
  diff_binaries("{old_exe}", "{new_exe}")
  analyze_variant_changes("{old_exe}", "{new_exe}", top_n=3)
```

---

### 🔵 Recipe 5: Firmware / IoT Analysis

**Goal**: Extract file system, identify components, find vulnerabilities.

```
STEP 1 — Identify firmware format
  run_file("{firmware}")
  run_binwalk("{firmware}")               # What's embedded? (squashfs, gzip, bootloader?)

STEP 2 — Extract embedded content
  run_binwalk_extract("{firmware}")       # Extract file system and binaries

STEP 3 — Analyze extracted binaries
  scan_workspace()                        # Batch scan all extracted files
  scan_for_versions("{firmware}")         # OpenSSL version? Busybox? Kernel?
  run_yara("{firmware}", "{iot_rules}")   # Known IoT malware families?

STEP 4 — Vulnerability hunting
  vulnerability_hunter("{target_binary}")  # Buffer overflows, format strings
  trace_execution_path("{target}", "system")  # Does user input reach system()?
```

---

### 🟣 Recipe 6: APT / Advanced Threat Hunting

**Goal**: Identify nation-state malware, C2 infrastructure, and attribution.

```
STEP 1 — Full triage
  run_file → detect_packer_deep → run_strings → parse_binary_with_lief

STEP 2 — Capability + IOC extraction
  run_capa("{file}", "detailed")          # Full capability matrix
  extract_iocs("{file}")                  # C2 IPs, domains, mutex, paths

STEP 3 — Code similarity / lineage
  match_libraries("{file}")               # Filter library code → focus on custom code
  generate_yara_rule("{file}", "{unique_func_addr}")  # Hunt for variants

STEP 4 — Behavioral analysis
  dormant_detector("{file}")             # Sleeping implants, time triggers
  emulate_machine_code("{file}", "{decode_stub}")   # De-obfuscate C2 string

STEP 5 — Attribution and reporting
  add_mitre_technique("T1027", "Obfuscated Files or Information", "Defense Evasion")
  add_mitre_technique("T1071", "Application Layer Protocol", "Command and Control")
  create_analysis_report(template_type="full", classification="TLP:AMBER")
```

---

## Phase-Based Tool Guide

Use this guide to know **what to run in each phase** of analysis.

### Phase 1 — Initial Triage `[ALWAYS RUN FIRST]`

Run these on **every binary**, no matter what. They are fast and inform all subsequent decisions.

| Priority | Tool | Why |
|----------|------|-----|
| 🔴 Must | `run_file` | File format, arch, 64/32-bit |
| 🔴 Must | `detect_packer` | If packed → all static analysis is unreliable |
| 🔴 Must | `run_strings` | Reveals intent: URLs, registry keys, commands |
| 🔴 Must | `parse_binary_with_lief` | Imports, sections, entropy |
| 🟡 Often | `extract_iocs` | C2 indicators from strings output |
| 🟡 Often | `scan_for_versions` | Vulnerable library versions |

> ⚠️ **If `detect_packer` shows the file is packed**: Stop static analysis. Use `emulate_machine_code` or manual unpacking before proceeding to Phase 2.

---

### Phase 2 — Structural Analysis `[CONDITIONAL — run after Phase 1 confirms not packed]`

These tools provide deeper structural understanding. Choose based on your goal.

| Goal | Tool |
|------|------|
| Capability overview | `run_capa` or `run_capa_quick` |
| Family identification | `run_yara` |
| Import/export deep dive | `Radare2_open_file` → `Radare2_analyze` → `Radare2_list_imports` |
| C++ class layout | `extract_rtti_info` → `Radare2_list_classes` |
| Function list | `Radare2_list_functions` |
| Embedded content | `run_binwalk` → `run_binwalk_extract` |
| Dormant behaviors | `dormant_detector` |

---

### Phase 3 — Deep Analysis `[OPTIONAL — targeted, based on Phase 2 findings]`

These are slow and expensive. Only use when you have a specific target address or question.

| Question | Tool |
|----------|------|
| "What does this function do?" | `smart_decompile` (Ghidra) or `Radare2_decompile_function` |
| "What calls this function?" | `Radare2_xrefs_to` or `analyze_xrefs` |
| "What does this function call?" | `Ghidra_get_call_graph` |
| "Does user input reach system()?" | `trace_execution_path` |
| "What are the register values after this code?" | `emulate_machine_code` |
| "What C++ class is this?" | `recover_structures` |
| "Are there vulnerabilities?" | `vulnerability_hunter` |
| "What changed vs old version?" | `diff_binaries` → `analyze_variant_changes` |

---

### Phase 4 — Reporting `[ALWAYS RUN AT END]`

Capture your analysis in a session and generate a report.

```
start_report_session("{sample_path}", "{analyst_name}")  # Start at beginning of analysis
# ... analysis work ...
add_ioc(...)            # Throughout analysis, add IOCs as you find them
add_analysis_note(...)  # Document key observations
add_mitre_technique(...) # Map behaviors to ATT&CK
set_severity(...)       # Update as threat level becomes clear
create_analysis_report(template_type="full")  # Generate report at the end
```

---

## Analysis Tools

**Plugin:** `AnalysisToolsPlugin` - Tools for binary comparison, signature generation, and static analysis.

### Binary Diffing Tools

#### `diff_binaries` `[STATIC]` `[COMPARISON]`

Compare two binary files to identify code changes and modifications.

Essential for:
- **Patch Analysis (1-day Exploits)**: Compare pre-patch and post-patch binaries to identify security vulnerabilities
- **Game Hacking**: Find offset changes after game updates to maintain functionality
- **Malware Variant Analysis**: Identify code differences between malware variants (e.g., "90% similar to Lazarus malware, but C2 address generation changed")

**Arguments:**
- `file_path_a` (str) - Path to the first binary file (e.g., pre-patch version)
- `file_path_b` (str) - Path to the second binary file (e.g., post-patch version)
- `function_name` (str | None) - Optional function name to compare (default: None)
- `max_output_size` (int) - Maximum output size in bytes (default: 10MB)
- `timeout` (int) - Timeout in seconds (default: 120)

**Returns:**
Structured JSON containing:
- `similarity`: Float between 0.0 and 1.0 indicating code similarity
- `changes`: List of detected changes with addresses and descriptions
- `function_specific`: Boolean indicating if function-level diff was performed
- `total_changes`: Number of changes detected

❌ **NOT USE WHEN:**
- You only have one binary (need two files for comparison)
- Both files are packed — unpack them first or the diff will be meaningless
- You want a natural-language explanation → use `explain_patch` instead

🔗 **SEE ALSO:** `analyze_variant_changes` (richer structural diff), `explain_patch` (human-readable diff), `match_libraries` (filter library noise before diffing)

---

#### `analyze_variant_changes` `[STATIC]` `[COMPARISON]` `[SLOW]`

Analyze structural changes between two binary variants (Lineage Mapper).

Combines binary diffing with control flow analysis to understand *how* a binary has evolved. Identifies the most modified functions and generates their Control Flow Graphs (CFG) for comparison.

**Use Cases:**
- **Malware Lineage**: "How did Lazarus Group modify their backdoor?"
- **Patch Diffing**: "What logic changed in the vulnerable function?"
- **Variant Analysis**: "Is this a new version of the same malware?"

**Arguments:**
- `file_path_a` (str) - Path to the original binary
- `file_path_b` (str) - Path to the variant binary
- `top_n` (int) - Number of top changed functions to analyze in detail (default: 3)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
ToolResult with diff summary and CFG data for top changed functions.

❌ **NOT USE WHEN:**
- You want a fast overview of similarity — use `diff_binaries` first (quicker)
- You need a natural-language patch explanation — use `explain_patch` instead

🔗 **SEE ALSO:** `diff_binaries` (quick similarity score), `generate_function_graph` (CFG for any single function), `smart_decompile` (decompile the changed functions found here)

---

#### `match_libraries` `[STATIC]` `[SLOW]`

Match and filter known library functions to focus on user code.

Uses radare2's zignatures (FLIRT-compatible signature matching) to:
- **Reduce Analysis Noise**: Skip analysis of known library functions (strcpy, malloc, etc.)
- **Focus on User Code**: Identify which functions are original vs library code
- **Save Time & Tokens**: Reduce analysis scope by 80% by filtering out standard libraries
- **Improve Accuracy**: Focus AI analysis on the actual malicious/interesting code

**Arguments:**
- `file_path` (str) - Path to the binary file to analyze
- `signature_db` (str | None) - Optional path to custom signature database file (.sig format) (default: None)
- `max_output_size` (int) - Maximum output size in bytes (default: 10MB)
- `timeout` (int) - Timeout in seconds (default: 600)

**Returns:**
Structured JSON containing:
- `total_functions`: Total number of functions found
- `library_functions`: Number of matched library functions
- `user_functions`: Number of unmatched (user) functions to analyze
- `library_matches`: List of matched library functions with details
- `user_function_list`: List of user function addresses/names for further analysis
- `noise_reduction_percentage`: Percentage of functions filtered out

❌ **NOT USE WHEN:**
- The binary is heavily packed or obfuscated (signatures won't match obfuscated code)
- The binary is a tiny script/shellcode (overhead not worth it for < 50 functions)

🔗 **SEE ALSO:** `Radare2_list_functions` (full function list before filtering), `diff_binaries` (compare user-code only after filtering)

---

### Binary Parsing Tools

#### `parse_binary_with_lief` `[STATIC]` `[QUICK]` `[FIRST]`

Parse binary metadata using LIEF (Library to Instrument Executable Formats).

Extracts comprehensive information about PE/ELF/Mach-O binaries including headers, sections, imports, exports, and more.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `format` (str) - Output format: 'json' or 'text' (default: 'json')

**Returns:**
Structured binary metadata including:
- File format (PE, ELF, Mach-O)
- Architecture and machine type
- Entry point address
- Sections with attributes
- Imported/exported symbols
- Library dependencies

❌ **NOT USE WHEN:**
- The binary is not a standard PE/ELF/Mach-O (e.g., raw shellcode, firmware blob) → use `run_file` + `run_binwalk` instead
- You need live import analysis at runtime → use `Radare2_list_imports` after a session

🔗 **SEE ALSO:** `run_file` (quick format check), `Radare2_list_imports` (session-based import listing), `Radare2_list_sections` (session-based section listing), `detect_packer` (check if imports are fake due to packing)

---

### Signature Generation Tools

#### `generate_signature`

Generate a YARA signature from opcode bytes at a specific address.

Extracts opcode bytes from a function or code section and formats them as a YARA rule, enabling automated malware detection. Attempts to mask variable values (addresses, offsets) to create more flexible signatures.

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `address` (str) - Start address for signature extraction (e.g., 'main', '0x401000')
- `length` (int) - Number of bytes to extract (default: 32, recommended 16-64)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
ToolResult with YARA rule string ready for use in threat hunting.

---

#### `generate_yara_rule`

Generate a YARA rule from function bytes.

Extracts bytes from a function and generates a ready-to-use YARA rule for malware detection and threat hunting.

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `function_address` (str) - Function address to extract bytes from (e.g., 'main', '0x401000')
- `rule_name` (str) - Name for the YARA rule (default: 'auto_generated_rule')
- `byte_length` (int) - Number of bytes to extract (default: 64, max: 1024)
- `timeout` (int) - Execution timeout in seconds (default: 300)

**Returns:**
ToolResult with complete YARA rule string.

---

### Static Analysis Tools

#### `run_strings` `[STATIC]` `[QUICK]` `[FIRST]`

Extract printable strings using the `strings` CLI utility.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `min_length` (int) - Minimum string length (default: 4)
- `max_output_size` (int) - Maximum output size in bytes (default: 10MB)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
List of extracted strings with statistics (total count, unique count).

❌ **NOT USE WHEN:**
- The binary is packed or encrypted (strings will be garbled noise) — check `detect_packer` first
- You need strings with their addresses (virtual offset) → use `Radare2_list_strings` in a session
- Output is too large → reduce with `min_length=10` or `max_output_size`

🔗 **SEE ALSO:** `detect_packer` (run before this), `extract_iocs` (parse strings output for IPs/URLs), `Radare2_list_strings` (strings with addresses)

---

#### `run_binwalk`

Analyze binaries for embedded content using binwalk.

Scans for signatures of embedded files, compressed data, and file systems without extraction.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `depth` (int) - Maximum signature scanning depth (default: 8)
- `max_output_size` (int) - Maximum output size in bytes (default: 10MB)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
List of detected embedded content with offsets and types.

---

#### `run_binwalk_extract`

Extract embedded files and file systems from a binary using binwalk.

Performs deep extraction of embedded content, including:
- Compressed archives (gzip, bzip2, lzma, xz)
- File systems (squashfs, cramfs, jffs2, ubifs)
- Firmware images and bootloaders
- Nested/matryoshka content (files within files)

**Use Cases:**
- **Firmware Analysis**: Extract file systems from router/IoT firmware
- **Malware Unpacking**: Extract payloads from packed/embedded malware
- **Forensics**: Recover embedded files from disk images
- **CTF Challenges**: Extract hidden data from challenge files

**Arguments:**
- `file_path` (str) - Path to the binary file to extract
- `output_dir` (str | None) - Directory to extract files to (default: creates temp dir)
- `matryoshka` (bool) - Enable recursive extraction (files within files) (default: True)
- `depth` (int) - Maximum extraction depth for nested content (default: 8)
- `max_output_size` (int) - Maximum output size in bytes (default: 50MB)
- `timeout` (int) - Extraction timeout in seconds (default: 600)

**Returns:**
Extraction summary including:
- `extracted_files`: List of extracted files with paths and types
- `output_directory`: Path to extraction output
- `total_size`: Total size of extracted content
- `extraction_depth`: Maximum depth reached during extraction

---

#### `scan_for_versions` `[STATIC]` `[QUICK]`

Extract library version strings and CVE clues from a binary.

Acts as a "Version Detective", scanning the binary for strings that look like version numbers or library identifiers (e.g., "OpenSSL 1.0.2g", "GCC 5.4.0"). Helps identify outdated components and potential CVEs.

**Use Cases:**
- **SCA (Software Composition Analysis)**: Identify open source components
- **Vulnerability Scanning**: Find outdated libraries (e.g., Heartbleed-vulnerable OpenSSL)
- **Firmware Analysis**: Determine OS and toolchain versions

**Arguments:**
- `file_path` (str) - Path to the binary file
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
List of detected libraries and versions with confidence scores.

❌ **NOT USE WHEN:**
- The binary strips all version strings (custom/proprietary builds) — results may be empty
- The binary is packed — version strings will be invisible

🔗 **SEE ALSO:** `run_strings` (raw strings for manual inspection), `parse_binary_with_lief` (dependency list), `run_binwalk` (firmware version from image metadata)

---

#### `extract_rtti_info` `[STATIC]` `[QUICK]` `[C++]`

Extract RTTI (Run-Time Type Information) from C++ binaries.

RTTI provides class names and inheritance hierarchies in C++ binaries, invaluable for understanding object-oriented malware and game clients.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
List of extracted class names, type information, and inheritance hierarchies.

❌ **NOT USE WHEN:**
- The binary is compiled in C (no RTTI exists) — check `extract_rtti_info` returns empty, move on
- The binary uses stripped RTTI (some hardened builds) — use `Radare2_list_classes` as fallback

🔗 **SEE ALSO:** `Radare2_list_classes` (r2-based class listing), `recover_structures` (convert class offsets to named fields), `Ghidra_list_structures` (Ghidra type recovery)

---

## Common Tools

**Plugin:** `CommonToolsPlugin` - File operations, memory management, and server monitoring tools.

### Memory Management Tools

The Memory Tools provide AI long-term memory capabilities for multi-session analysis, enabling knowledge transfer across different reverse engineering projects.

#### `create_analysis_session`

Create a new analysis session to store memories.

Use this when starting a new reverse engineering analysis. The session name should be descriptive and follow a template format like 'malware_analysis_2024_001' or 'game_cheat_detection'.

**Arguments:**
- `name` (str) - Template name for the session (e.g., 'malware_sample_001')
- `binary_name` (str | None) - Name of the binary being analyzed (optional)
- `binary_path` (str | None) - Path to binary for automatic hash calculation (optional)

**Returns:**
Session information including ID for future reference.

---

#### `save_analysis_memory`

Save important information to long-term memory.

Use this to remember:
- Function addresses and their purposes
- Vulnerability patterns discovered
- API call sequences
- User instructions and preferences

**Arguments:**
- `session_id` (str) - The session ID to save memory to
- `memory_type` (str) - Type of memory: 'function', 'vulnerability', 'api_sequence', 'instruction', etc.
- `content` (str) - The memory content to save
- `category` (str | None) - Optional category for organization
- `user_prompt` (str | None) - Optional user prompt that triggered this memory
- `importance` (int) - Importance level 1-10 (default: 5)

**Returns:**
Confirmation of memory saved with memory ID.

---

#### `recall_analysis_memory`

Search and recall memories from past analyses.

Query past analysis memories using semantic search to find relevant information from previous sessions.

**Arguments:**
- `query` (str) - Search query to find relevant memories
- `session_id` (str | None) - Optional session ID to limit search (default: searches all sessions)
- `memory_type` (str | None) - Optional memory type filter
- `limit` (int) - Maximum number of memories to return (default: 10)

**Returns:**
List of matching memories with relevance scores.

---

#### `list_analysis_sessions`

List all analysis sessions.

**Arguments:**
- `status` (str | None) - Optional status filter: 'active', 'completed', 'archived'
- `limit` (int) - Maximum number of sessions to return (default: 50)

**Returns:**
List of sessions with metadata.

---

#### `get_session_detail`

Get complete details for a specific session.

**Arguments:**
- `session_id` (str) - The session ID to retrieve

**Returns:**
Complete session information including all memories and metadata.

---

#### `resume_session`

Resume a previous analysis session.

**Arguments:**
- `session_id` (str) - The session ID to resume
- `binary_name` (str | None) - Optional new binary name if context changed

**Returns:**
Session context and recent memories for continuation.

---

#### `complete_session`

Mark a session as completed with a summary.

**Arguments:**
- `session_id` (str) - The session ID to complete
- `summary` (str) - Analysis summary and key findings

**Returns:**
Confirmation of session completion.

---

#### `save_pattern`

Save a code/behavior pattern for cross-session matching.

Enables pattern recognition across different binaries and analyses.

**Arguments:**
- `session_id` (str) - Current session ID
- `pattern_type` (str) - Type: 'code_pattern', 'behavior', 'exploit_technique'
- `pattern_signature` (str) - Pattern signature (hash, regex, or description)
- `description` (str) - Human-readable description

**Returns:**
Pattern ID for future reference.

---

#### `find_similar_patterns`

Find similar patterns from previous analyses.

**Arguments:**
- `pattern_signature` (str) - Pattern to match against
- `pattern_type` (str | None) - Optional pattern type filter
- `current_session_id` (str | None) - Exclude patterns from this session
- `limit` (int) - Maximum matches to return (default: 5)

**Returns:**
List of similar patterns with similarity scores and original contexts.

---

#### `get_relevant_context`

Get relevant context from past analyses.

Automatically finds relevant memories based on current analysis context.

**Arguments:**
- `description` (str) - Description of current analysis task
- `current_session_id` (str | None) - Current session to get context for
- `limit` (int) - Maximum context items to return (default: 5)

**Returns:**
Relevant memories and patterns from previous sessions.

---

#### `update_analysis_time`

Update cumulative analysis time for a session.

**Arguments:**
- `session_id` (str) - Session ID to update
- `duration_seconds` (int) - Duration to add in seconds

**Returns:**
Updated total analysis time.

---

### Server Monitoring Tools

#### `get_server_health`

Get the current health status and resource usage of the MCP server.

Use this to monitor the server's uptime, memory consumption, and tool execution statistics.

**Arguments:** None

**Returns:**
ToolResult containing:
- `status`: 'healthy' or 'degraded'
- `uptime_seconds`: Server uptime
- `uptime_formatted`: Human-readable uptime
- `memory_usage_mb`: Current memory usage in MB
- `total_calls`: Total tool execution count
- `total_errors`: Total error count
- `error_rate`: Percentage error rate
- `active_tools`: Number of tools that have been used

---

#### `get_tool_metrics`

Get detailed execution metrics for specific or all tools.

**Arguments:**
- `tool_name` (str | None) - Optional tool name to filter results (default: None, returns all tools)

**Returns:**
Detailed metrics including:
- Execution times (min, max, average)
- Call counts
- Error rates and error types
- Performance trends

---

### File Operation Tools

#### `run_file` `[STATIC]` `[QUICK]` `[FIRST]`

Identify file metadata using the `file` CLI utility.

**Arguments:**
- `file_path` (str) - Path to the file to identify
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
File type information including format, architecture, and file magic details.

❌ **NOT USE WHEN:**
- The file has a spoofed header (malware may misreport its type) — always combine with `parse_binary_with_lief` for full verification

🔗 **SEE ALSO:** `parse_binary_with_lief` (detailed structure), `detect_packer` (is it protected?), `copy_to_workspace` (run before this if file is not in workspace)

---

#### `copy_to_workspace`

Copy any accessible file to the workspace directory.

Allows copying files from any location (including AI agent upload directories) to the workspace where other reverse engineering tools can access them.

Supports files from:
- Claude Desktop uploads (/mnt/user-data/uploads)
- Cursor uploads
- Windsurf uploads
- Local file paths
- Any other accessible location

**Arguments:**
- `source_path` (str) - Absolute or relative path to the source file
- `destination_name` (str | None) - Optional custom filename in workspace (defaults to original name)

**Returns:**
New file path in workspace.

---

#### `list_workspace`

List all files in the workspace directory.

**Arguments:** None

**Returns:**
List of files with sizes and modification times.

---

#### `scan_workspace`

Batch scan all files in the workspace using multiple tools in parallel.

Performs a comprehensive scan to identify files, analyze binaries, and detect threats. Runs 'run_file', 'parse_binary_with_lief', and 'run_yara' (if rules exist) on all matching files concurrently.

**Workflow:**
1. Identify files matching patterns (default: all files)
2. Run 'file' command on all files
3. Run 'LIEF' analysis on executable files
4. Run 'YARA' scan if rules are available
5. Aggregate results into a single report

**Arguments:**
- `file_patterns` (list | None) - List of glob patterns to include (e.g., ["*.exe", "*.dll"]) (default: ["*"])
- `timeout` (int) - Global timeout for the batch operation in seconds (default: 600)

**Returns:**
Aggregated scan results for all files.

---

### Patch Analysis Tools

#### `explain_patch` `[STATIC]` `[COMPARISON]`

Analyze differences between binaries and explain in natural language.

Uses binary diffing combined with AI to provide human-readable explanations of what changed and why.

**Arguments:**
- `file_path_a` (str) - Path to the original binary
- `file_path_b` (str) - Path to the patched binary
- `function_name` (str | None) - Optional specific function to focus on
- `ctx` - FastMCP Context (auto-injected)

**Returns:**
Natural language explanation of patch changes including:
- Security implications
- Functionality changes
- Risk assessment

❌ **NOT USE WHEN:**
- You need precise byte-level diff data — use `diff_binaries` instead
- The binaries are packed — unpack first

🔗 **SEE ALSO:** `diff_binaries` (raw diff), `analyze_variant_changes` (structural diff + CFG)

---

## Ghidra Tools

**Plugin:** `GhidraToolsPlugin` - Advanced binary analysis using Ghidra decompiler with project caching.

### Structure Management Tools

#### `Ghidra_list_structures`

List all defined structures in the binary.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `offset` (int) - Pagination offset (default: 0)
- `limit` (int) - Maximum structures to return (default: 100)

**Returns:**
List of structure definitions with fields and sizes.

---

#### `Ghidra_get_structure`

Get detailed information about a specific structure.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `name` (str) - Structure name to retrieve

**Returns:**
Complete structure definition including:
- Field names, types, and offsets
- Structure size
- Alignment information

---

#### `Ghidra_create_structure`

Create a new structure definition in Ghidra.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `name` (str) - Structure name
- `fields` (list) - List of field definitions: [{"name": "field1", "type": "int", "offset": 0}, ...]
- `size` (int) - Total structure size

**Returns:**
Confirmation of structure creation.

---

### Enum Management Tools

#### `Ghidra_list_enums`

List all defined enums in the binary.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `offset` (int) - Pagination offset (default: 0)
- `limit` (int) - Maximum enums to return (default: 100)

**Returns:**
List of enum definitions with members and values.

---

### Data Type Tools

#### `Ghidra_list_data_types`

List all data types defined in Ghidra's analysis.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `category` (str | None) - Optional category filter (e.g., "pointer", "struct", "typedef")
- `offset` (int) - Pagination offset (default: 0)
- `limit` (int) - Maximum types to return (default: 100)

**Returns:**
List of data types with categories and sizes.

---

### Bookmark Tools

#### `Ghidra_list_bookmarks`

List all bookmarks in the binary.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `bookmark_type` (str | None) - Optional type filter (e.g., "Note", "Warning", "Error")
- `offset` (int) - Pagination offset (default: 0)
- `limit` (int) - Maximum bookmarks to return (default: 100)

**Returns:**
List of bookmarks with addresses, types, and comments.

---

#### `Ghidra_add_bookmark`

Add a bookmark at a specific address.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `address` (str) - Address to bookmark (e.g., '0x401000')
- `category` (str) - Bookmark category
- `comment` (str) - Bookmark comment
- `bookmark_type` (str) - Type: 'Note', 'Warning', 'Error', etc. (default: 'Note')

**Returns:**
Confirmation of bookmark creation.

---

### Memory Access Tools

#### `Ghidra_read_memory`

Read raw bytes from memory at a specific address.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `address` (str) - Starting address (e.g., '0x401000')
- `length` (int) - Number of bytes to read

**Returns:**
Raw byte array.

---

#### `Ghidra_get_bytes`

Get bytes at address as hex string.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `address` (str) - Starting address (e.g., '0x401000')
- `length` (int) - Number of bytes to read

**Returns:**
Hex string representation of bytes.

---

### Patching Tools

#### `Ghidra_simulate_patch`

Simulate patching bytes in Ghidra's cache (does not modify actual file).

Useful for testing patches before applying them permanently.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `address` (str) - Address to patch (e.g., '0x401000')
- `hex_bytes` (str) - Hex bytes to patch (e.g., '90 90 90')

**Returns:**
Confirmation of simulated patch.

---

### Analysis Tools

#### `Ghidra_analyze_function`

Trigger Ghidra's analysis on a specific function.

Forces re-analysis with Ghidra's full suite of analyzers.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `address` (str) - Function address (e.g., 'main', '0x401000')

**Returns:**
Analysis results and detected patterns.

---

#### `Ghidra_get_call_graph`

Get call graph for a function.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `address` (str) - Function address (e.g., 'main', '0x401000')
- `depth` (int) - Call graph depth (default: 2)
- `direction` (str) - 'callers', 'callees', or 'both' (default: 'both')

**Returns:**
Call graph data in structured format.

---

### Decompilation Tools

#### `emulate_machine_code` `[DYNAMIC]` `[SLOW]`

Emulate machine code execution using radare2 ESIL (Evaluable Strings Intermediate Language).

Provides safe, sandboxed emulation of binary code without actual execution. Perfect for analyzing obfuscated code, understanding register states, and predicting execution outcomes without security risks.

**Key Use Cases:**
- De-obfuscation: Reveal hidden strings by emulating XOR/shift operations
- Register Analysis: See final register values after code execution
- Safe Malware Analysis: Predict behavior without running malicious code

**Safety Features:**
- Virtual CPU simulation (no real execution)
- Instruction count limit (max 1000) prevents infinite loops
- Memory sandboxing (changes don't affect host system)

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `address` (str) - Address to start emulation (e.g., 'main', '0x401000', 'sym.decrypt')
- `steps` (int) - Number of instructions to execute (default: 50, max: 1000)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
Register states and emulation summary.

❌ **NOT USE WHEN:**
- You want to trace multi-function execution across API calls (ESIL doesn't emulate OS APIs)
- The code depends on real system state (file handles, network, etc.) — emulation will diverge
- You want high-level understanding — use `smart_decompile` instead

🔗 **SEE ALSO:** `smart_decompile` (higher-level view), `trace_execution_path` (call chain tracing), `get_pseudo_code` (quick decompile without Ghidra)

---

#### `get_pseudo_code`

Generate pseudo C code (decompilation) for a function using radare2's pdc command.

Decompiles binary code into C-like pseudocode, making it much easier to understand program logic compared to raw assembly.

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `address` (str) - Function address to decompile (e.g., 'main', '0x401000', 'sym.foo')
- `timeout` (int) - Execution timeout in seconds (default: 300)

**Returns:**
Pseudo C code string.

---

#### `smart_decompile` `[GHIDRA]` `[SLOW]`

Decompile a function to pseudo C code using Ghidra or radare2.

**Decompiler Selection:**
- Ghidra (default): More accurate, better type recovery, industry-standard
- radare2 (fallback): Faster, lighter weight, good for quick analysis

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `address` (str) - Function address to decompile (e.g., 'main', '0x401000')
- `timeout` (int) - Execution timeout in seconds (default: 120)
- `use_ghidra` (bool) - Use Ghidra decompiler if available (default: True)

**Returns:**
Decompiled pseudo C code.

❌ **NOT USE WHEN:**
- The binary is packed — decompilation of packed code is noise
- The function is a known library function (e.g., `malloc`) — skip it
- You want assembly-level view — use `Radare2_disassemble_function` instead

🔗 **SEE ALSO:** `get_pseudo_code` (faster r2-only option), `Radare2_decompile_function` (session-based), `emulate_machine_code` (trace register values)

---

#### `recover_structures` `[GHIDRA]` `[SLOW]` `[C++]`

Recover C++ class structures and data types from binary code.

THE game-changer for C++ reverse engineering. Transforms cryptic "this + 0x4" memory accesses into meaningful "Player.health" structure fields. Uses Ghidra's powerful data type propagation and structure recovery algorithms.

**Why Structure Recovery Matters:**
- **C++ Analysis**: 99% of game clients and commercial apps are C++
- **Understanding**: "this + 0x4" means nothing, "Player.health = 100" tells a story
- **AI Comprehension**: AI can't understand raw offsets, but understands named fields
- **Scale**: One structure definition can clarify thousands of lines of code

**Performance Tips (for large binaries like game clients):**
- Use `fast_mode=True` (default) to skip full binary analysis
- Use `use_ghidra=False` for quick radare2-based analysis
- For best results on first run, set `fast_mode=False` but expect longer wait

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `address` (str) - Function to analyze for structure usage (e.g., 'main', '0x401000')
- `timeout` (int) - Execution timeout in seconds (default: 600)
- `use_ghidra` (bool) - Use Ghidra for advanced recovery (default: True)
- `fast_mode` (bool) - Skip full binary analysis for faster startup (default: True)

**Returns:**
Recovered structures in C format with field names, types, and offsets.

❌ **NOT USE WHEN:**
- The binary is C (not C++) — no vtables or RTTI to recover from
- You just need class names — use `extract_rtti_info` first (faster)
- Ghidra is not installed — use `Radare2_list_classes` as fallback

🔗 **SEE ALSO:** `extract_rtti_info` (faster class discovery), `Radare2_list_classes` (r2 fallback), `Ghidra_create_structure` (manually define recovered struct)

---

## Malware Tools

**Plugin:** `MalwareToolsPlugin` - Specialized tools for malware analysis and threat detection.

### `dormant_detector` `[STATIC]` `[SLOW]`

Detect dormant/time-triggered malware behaviors.

Identifies malware that remains dormant until specific conditions are met (time bombs, logic bombs, environment checks).

**Arguments:**
- `file_path` (str) - Path to the binary file
- `timeout` (int) - Execution timeout in seconds (default: 300)

**Returns:**
List of potential dormant behaviors with:
- Trigger conditions (time checks, environment variables, etc.)
- Activation mechanisms
- Risk assessment

❌ **NOT USE WHEN:**
- The binary is packed — analysis is meaningless until unpacked
- You need fast triage — this is a Phase 2/3 tool

🔗 **SEE ALSO:** `vulnerability_hunter` (generic vulnerability scan), `run_capa` (capability-level detection), `emulate_machine_code` (verify dormant logic by emulation)

---

### `adaptive_vaccine`

Generate vaccine/neutralization code for malware.

Creates patches or defensive signatures to neutralize identified malware behaviors.

**Arguments:**
- `file_path` (str) - Path to the malware binary
- `target_behavior` (str) - Specific behavior to neutralize (e.g., "C2_communication", "file_encryption")
- `timeout` (int) - Execution timeout in seconds (default: 300)

**Returns:**
Vaccine code including:
- Binary patch instructions
- YARA detection rules
- Neutralization scripts

---

### `vulnerability_hunter` `[STATIC]` `[SLOW]`

Hunt for vulnerabilities in binary code.

Automatically searches for common vulnerability patterns including:
- Buffer overflows
- Format string vulnerabilities
- Integer overflows
- Use-after-free
- Race conditions

**Arguments:**
- `file_path` (str) - Path to the binary file
- `timeout` (int) - Execution timeout in seconds (default: 300)

**Returns:**
List of potential vulnerabilities with:
- Vulnerability type
- Location (function and address)
- Severity rating
- Exploitation difficulty
- Suggested mitigations

❌ **NOT USE WHEN:**
- The binary is packed — false positives will dominate
- You need formal verification — this provides heuristic findings, not proofs

🔗 **SEE ALSO:** `trace_execution_path` (verify reachability of a vulnerable function), `smart_decompile` (inspect vulnerable code), `adaptive_vaccine` (generate a fix after finding a vuln)

---

### `extract_iocs` `[STATIC]` `[QUICK]`

Extract Indicators of Compromise (IOCs) from text or binary using regex.

Automatically finds and extracts potential IOCs like IP addresses, URLs, email addresses, hashes, Bitcoin addresses, CVEs, Registry keys, and MAC addresses.

**Arguments:**
- `text` (str) - The text to analyze for IOCs (can also be a file path) (default: "")
- `file_path` (str) - Alternative: path to a file to extract IOCs from (default: "")
- `extract_ips` (bool) - Whether to extract IPv4 addresses (default: True)
- `extract_urls` (bool) - Whether to extract URLs (default: True)
- `extract_emails` (bool) - Whether to extract email addresses (default: True)
- `extract_bitcoin` (bool) - Whether to extract Bitcoin addresses (default: True)
- `extract_hashes` (bool) - Whether to extract MD5/SHA1/SHA256 hashes (default: True)
- `extract_others` (bool) - Whether to extract CVEs, Registry keys, MAC addresses (default: True)
- `limit` (int) - Maximum number of IOCs to return per category (default: 100)

**Returns:**
Structured JSON with categorized IOCs:
- `ipv4`: List of IPv4 addresses
- `urls`: List of URLs
- `emails`: List of email addresses
- `bitcoin`: List of Bitcoin addresses
- `hashes`: Dict with MD5, SHA1, SHA256 lists
- `cves`: List of CVE identifiers
- `registry_keys`: List of Windows Registry keys
- `mac_addresses`: List of MAC addresses
- `total_count`: Total IOCs found

❌ **NOT USE WHEN:**
- Passing raw binary bytes (pass the file_path instead, or run `run_strings` first)
- The binary is packed — IOCs will not be visible

🔗 **SEE ALSO:** `run_strings` (get strings first then pass output here), `add_ioc` (save found IOCs to report session)

---

### `run_yara`

Scan binaries against YARA rules via `yara-python`.

**Arguments:**
- `file_path` (str) - Path to the binary file to scan
- `rules_path` (str) - Path to YARA rules file (.yar or .yara)
- `timeout` (int) - Execution timeout in seconds (default: 300)

**Returns:**
List of YARA rule matches with:
- Rule name
- Tags
- Metadata
- Matched strings and offsets

---

## Radare2 Tools

**Plugin:** `Radare2ToolsPlugin` - Comprehensive binary analysis suite powered by radare2.

### File Management Tools

#### `Radare2_open_file` `[QUICK]`

Open a binary file with radare2.

Initializes a radare2 session for analysis.

**Arguments:**
- `file_path` (str) - Path to the binary file

**Returns:**
Session ID for subsequent operations.

> ⚠️ **IMPORTANT**: Save the returned session ID — all Radare2_* tools require it. Always call `Radare2_analyze` after opening before using analysis-dependent tools like `Radare2_list_functions`.

❌ **NOT USE WHEN:**
- You want quick one-off commands without a session — use `run_radare2` instead

🔗 **SEE ALSO:** `Radare2_analyze` (run immediately after), `Radare2_close_file` (clean up when done)

---

#### `Radare2_close_file`

Close the current radare2 session.

**Arguments:**
- `session_id` (str) - Session ID to close

**Returns:**
Confirmation of session closure.

---

#### `Radare2_analyze` `[SLOW]` `[SESSION]`

Analyze the binary with radare2's analysis engine.

**Arguments:**
- `session_id` (str) - Active session ID
- `level` (str) - Analysis level: 'basic', 'standard', 'advanced', 'experimental' (default: 'standard')

**Returns:**
Analysis summary including functions found, strings extracted, and imports identified.

> ⚠️ **IMPORTANT**: Run this before `Radare2_list_functions`, `Radare2_list_classes`, etc. Analysis populates the function and symbol databases that other tools query.

❌ **NOT USE WHEN:**
- You only need to read bytes/headers (no analysis needed for `Radare2_show_headers` or `Radare2_list_sections`)

🔗 **SEE ALSO:** `Radare2_list_functions` (use after this), `match_libraries` (filter library functions post-analysis)

---

### Command Execution Tools

#### `Radare2_run_command`

Execute an arbitrary radare2 command.

**Security Note:** Use with caution. Only vetted commands are allowed.

**Arguments:**
- `session_id` (str) - Active session ID
- `command` (str) - Radare2 command to execute

**Returns:**
Command output.

---

#### `Radare2_calculate`

Calculate expressions using radare2's calculator.

Useful for address calculations, hex/decimal conversions, etc.

**Arguments:**
- `session_id` (str) - Active session ID
- `expression` (str) - Expression to calculate (e.g., "0x401000 + 0x100")

**Returns:**
Calculation result.

---

### Function Analysis Tools

#### `Radare2_list_functions`

List all functions detected in the binary.

**Arguments:**
- `session_id` (str) - Active session ID
- `offset` (int) - Pagination offset (default: 0)
- `limit` (int) - Maximum functions to return (default: 100)

**Returns:**
List of functions with addresses, sizes, and names.

---

#### `Radare2_list_functions_tree`

List functions in a tree/hierarchical view showing call relationships.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
Tree-structured function list.

---

#### `Radare2_show_function_details`

Show detailed information about a specific function.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Function address or name

**Returns:**
Function details including:
- Address and size
- Basic blocks
- Complexity metrics
- Local variables
- Call graph

---

#### `Radare2_get_current_address`

Get the current seek address in radare2.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
Current address.

---

#### `Radare2_get_function_prototype`

Get the function signature/prototype.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Function address or name

**Returns:**
Function prototype with return type and parameters.

---

#### `Radare2_set_function_prototype`

Set a function signature/prototype.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Function address or name
- `prototype` (str) - Function prototype (e.g., "int main(int argc, char** argv)")

**Returns:**
Confirmation of prototype update.

---

### Binary Information Tools

#### `Radare2_show_headers`

Show binary file headers.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
Binary headers including:
- File format (PE, ELF, Mach-O)
- Architecture
- Entry point
- Compilation timestamp

---

#### `Radare2_list_sections`

List all binary sections.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
List of sections with:
- Name
- Virtual address
- Size
- Permissions (read, write, execute)

---

#### `Radare2_list_imports`

List imported functions.

**Arguments:**
- `session_id` (str) - Active session ID
- `offset` (int) - Pagination offset (default: 0)
- `limit` (int) - Maximum imports to return (default: 100)

**Returns:**
List of imported functions with library names.

---

#### `Radare2_list_symbols`

List all symbols in the binary.

**Arguments:**
- `session_id` (str) - Active session ID
- `offset` (int) - Pagination offset (default: 0)
- `limit` (int) - Maximum symbols to return (default: 100)

**Returns:**
List of symbols with addresses, types, and names.

---

#### `Radare2_list_entrypoints`

List entry points.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
List of entry point addresses.

---

#### `Radare2_list_libraries`

List linked libraries.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
List of library dependencies.

---

#### `Radare2_list_strings`

List strings with filters.

**Arguments:**
- `session_id` (str) - Active session ID
- `min_length` (int) - Minimum string length (default: 4)
- `filter` (str | None) - Optional regex filter pattern

**Returns:**
List of strings with addresses and content.

---

#### `Radare2_list_all_strings`

List all strings without filters.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
Complete list of strings in the binary.

---

### OOP Analysis Tools

#### `Radare2_list_classes`

List classes (C++/Objective-C).

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
List of classes with methods and virtual tables.

---

#### `Radare2_list_methods`

List methods for a specific class.

**Arguments:**
- `session_id` (str) - Active session ID
- `class_name` (str) - Name of the class

**Returns:**
List of methods with addresses and signatures.

---

### Disassembly and Decompilation Tools

#### `Radare2_disassemble`

Disassemble code at a specific address.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Address to disassemble
- `instructions` (int) - Number of instructions (default: 20)

**Returns:**
Disassembled instructions.

---

#### `Radare2_disassemble_function`

Disassemble an entire function.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Function address or name

**Returns:**
Complete function disassembly.

---

#### `Radare2_decompile_function`

Decompile a function to C-like pseudocode.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Function address or name

**Returns:**
Decompiled C-like code.

---

### Decompiler Management Tools

#### `Radare2_list_decompilers`

List available decompilers.

**Arguments:**
- `session_id` (str) - Active session ID

**Returns:**
List of available decompiler plugins (pdc, pdg, r2ghidra, etc.).

---

#### `Radare2_use_decompiler`

Switch to a different decompiler.

**Arguments:**
- `session_id` (str) - Active session ID
- `decompiler` (str) - Decompiler name (e.g., 'pdc', 'pdg', 'r2ghidra')

**Returns:**
Confirmation of decompiler switch.

---

### Cross-Reference Tools

#### `Radare2_xrefs_to`

Get cross-references to a specific address.

Shows what code references this address (callers).

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Target address

**Returns:**
List of xrefs TO this address with caller addresses and types (call, jump, data).

---

### Annotation Tools

#### `Radare2_rename_function`

Rename a function.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Function address
- `new_name` (str) - New function name

**Returns:**
Confirmation of rename.

---

#### `Radare2_rename_flag`

Rename a flag/label.

**Arguments:**
- `session_id` (str) - Active session ID
- `old_name` (str) - Current flag name
- `new_name` (str) - New flag name

**Returns:**
Confirmation of rename.

---

#### `Radare2_set_comment`

Set a comment at a specific address.

**Arguments:**
- `session_id` (str) - Active session ID
- `address` (str) - Address to comment
- `comment` (str) - Comment text

**Returns:**
Confirmation of comment addition.

---

### Advanced Analysis Tools

#### `run_radare2`

Execute vetted radare2 commands for binary triage.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `r2_command` (str) - Radare2 command to execute
- `max_output_size` (int) - Maximum output size in bytes (default: 10MB)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
Command output.

---

#### `trace_execution_path` `[STATIC]` `[SLOW]`

Trace function calls backwards from a target function (Sink) to find potential execution paths.

Helps identify "Exploit Paths" by finding which functions call a dangerous target function (like 'system', 'strcpy', 'execve'). Performs recursive cross-reference analysis (backtrace).

**Use Cases:**
- **Vulnerability Analysis**: Check if user input (main/recv) reaches 'system'
- **Reachability Analysis**: Verify if a vulnerable function is actually called
- **Taint Analysis Helper**: Provide the path for AI to perform manual taint checking

**Arguments:**
- `file_path` (str) - Path to the binary file
- `target_function` (str) - Name or address of the target function (e.g., 'sym.imp.system', '0x401000')
- `max_depth` (int) - Maximum depth of backtrace (default: 3)
- `max_paths` (int) - Maximum number of paths to return (default: 5)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
List of execution paths (call chains) from entry points to target.

❌ **NOT USE WHEN:**
- You want forward analysis (what does this function call?) — use `analyze_xrefs` with direction='from'
- The binary is packed or stripped (symbols not available)

🔗 **SEE ALSO:** `analyze_xrefs` (bidirectional xref), `vulnerability_hunter` (find the dangerous sink first), `smart_decompile` (inspect functions in the path)

---

#### `generate_function_graph` `[STATIC]` `[SLOW]`

Generate a Control Flow Graph (CFG) for a specific function.

Uses radare2 to analyze function structure and returns a visualization code (Mermaid by default) or PNG image.

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `function_address` (str) - Function address (e.g., 'main', '0x140001000', 'sym.foo')
- `format` (str) - Output format: 'mermaid', 'json', 'dot', or 'png' (default: 'mermaid')
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
CFG visualization, JSON data, or PNG image.

❌ **NOT USE WHEN:**
- The function is very large (> 500 basic blocks) — graph will be unreadable
- You just need the call graph (who calls whom) — use `Ghidra_get_call_graph` instead

🔗 **SEE ALSO:** `analyze_variant_changes` (compares CFGs between versions), `Ghidra_get_call_graph` (call relationships), `trace_execution_path` (path tracing)

---

#### `analyze_xrefs` `[STATIC]` `[QUICK]`

Analyze cross-references (xrefs) for a specific address using radare2.

Shows relationships between code blocks - who calls this function (callers) and what it calls (callees).

**xref_type Options:**
- **"to"**: Show who references this address (callers/jumps TO here)
- **"from"**: Show what this address references (calls/jumps FROM here)
- **"all"**: Show both directions (complete relationship map)

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `address` (str) - Function or address to analyze (e.g., 'main', '0x401000', 'sym.decrypt')
- `direction` (str) - Direction: 'all', 'to', 'from' (default: 'all')
- `max_depth` (int) - Maximum depth for recursive xref analysis (default: 1)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
Structured JSON with xrefs data:
- `xrefs_to`: List of references TO this address (callers)
- `xrefs_from`: List of references FROM this address (callees)
- `summary`: Human-readable summary
- `total_refs_to`, `total_refs_from`: Count statistics

❌ **NOT USE WHEN:**
- You need a full backward call chain (multiple hops) — use `trace_execution_path` (recursive)
- You need a call graph visualization — use `generate_function_graph`

🔗 **SEE ALSO:** `Radare2_xrefs_to` (session-based, faster for known addresses), `trace_execution_path` (recursive path tracing), `Ghidra_get_call_graph` (Ghidra-powered)

---

## Report Tools

**Plugin:** `ReportToolsPlugin` - Professional malware analysis reporting with session management, IOC tracking, and MITRE ATT&CK mapping.

### Time Management Tools

#### `get_system_time`

Get accurate system timestamp with timezone information.

**Arguments:** None

**Returns:**
Current system time in ISO 8601 format with timezone.

---

#### `set_timezone`

Set the default timezone for timestamps.

**Arguments:**
- `timezone` (str) - Timezone name (e.g., 'America/New_York', 'UTC', 'Asia/Seoul')

**Returns:**
Confirmation of timezone change.

---

#### `get_timezone_info`

Get the current timezone configuration.

**Arguments:** None

**Returns:**
Current timezone name and offset.

---

### Session Management Tools

#### `start_analysis_session`

Start a new malware analysis session with metadata tracking.

**Arguments:**
- `sample_path` (str) - Path to the malware sample
- `analyst` (str) - Analyst name
- `severity` (str) - Initial severity assessment: 'low', 'medium', 'high', 'critical' (default: 'medium')
- `malware_family` (str | None) - Optional malware family classification
- `tags` (list | None) - Optional list of tags

**Returns:**
Session ID and metadata for future reference.

---

#### `end_analysis_session`

End an analysis session with status and summary.

**Arguments:**
- `session_id` (str) - Session ID to end
- `status` (str) - Final status: 'completed', 'incomplete', 'pending_review' (default: 'completed')
- `summary` (str) - Analysis summary and key findings

**Returns:**
Final session report with statistics.

---

#### `get_session_status`

Get the current status and information for a session.

**Arguments:**
- `session_id` (str | None) - Optional session ID (default: current active session)

**Returns:**
Session status including:
- Start time and duration
- Analyst name
- Number of IOCs collected
- MITRE techniques identified
- Analysis notes count

---

#### `list_analysis_sessions`

List all analysis sessions.

**Arguments:**
- `status` (str | None) - Optional status filter: 'active', 'completed', 'incomplete', 'pending_review'
- `limit` (int) - Maximum sessions to return (default: 50)

**Returns:**
List of sessions with summary metadata.

---

### Data Collection Tools

#### `add_ioc`

Add an Indicator of Compromise (IOC) to the current session.

**Arguments:**
- `ioc_type` (str) - IOC type: 'ip', 'domain', 'url', 'hash', 'email', 'filename', 'registry', 'mutex'
- `value` (str) - IOC value
- `session_id` (str | None) - Optional session ID (default: current session)

**Returns:**
Confirmation of IOC addition with IOC ID.

---

#### `add_analysis_note`

Add a timestamped note to the analysis session.

**Arguments:**
- `note` (str) - Note content
- `category` (str) - Note category: 'observation', 'hypothesis', 'finding', 'question' (default: 'observation')
- `session_id` (str | None) - Optional session ID (default: current session)

**Returns:**
Confirmation with note ID and timestamp.

---

#### `add_mitre_technique`

Add a MITRE ATT&CK technique to the session.

**Arguments:**
- `technique_id` (str) - MITRE technique ID (e.g., 'T1055', 'T1053.005')
- `technique_name` (str) - Human-readable technique name
- `tactic` (str) - MITRE tactic (e.g., 'Defense Evasion', 'Persistence')
- `session_id` (str | None) - Optional session ID (default: current session)

**Returns:**
Confirmation of technique addition.

---

#### `set_severity`

Update the severity level of the current analysis.

**Arguments:**
- `severity` (str) - New severity: 'low', 'medium', 'high', 'critical'
- `session_id` (str | None) - Optional session ID (default: current session)

**Returns:**
Confirmation of severity update.

---

### Report Generation Tools

#### `create_analysis_report`

Generate a comprehensive malware analysis report.

Produces a professional report including:
- Executive summary
- Technical analysis details
- IOC list with categorization
- MITRE ATT&CK mapping
- Timeline of analysis
- Recommendations

**Arguments:**
- `template_type` (str) - Report template: 'full', 'executive', 'technical', 'ioc_only' (default: 'full')
- `session_id` (str | None) - Optional session ID (default: current session)
- `sample_path` (str | None) - Path to analyzed sample
- `analyst` (str | None) - Analyst name override
- `classification` (str) - Report classification: 'TLP:WHITE', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED' (default: 'TLP:WHITE')
- `output_format` (str) - Output format: 'markdown', 'html', 'pdf', 'json' (default: 'markdown')

**Returns:**
Generated report content or file path.

---

## Summary Statistics

- **Total Tools**: 96 tools
- **Analysis Tools**: 11 tools
- **Common Tools**: 17 tools (Memory: 11, Server: 2, File: 4, Patch: 1)
- **Ghidra Tools**: 17 tools
- **Malware Tools**: 9 tools (including detect_packer, run_capa, run_yara, extract_iocs)
- **Radare2 Tools**: 34 tools
- **Report Tools**: 12 tools

**AI Agent Guidance** (added in this revision):
- 14-tag classification system for quick filtering
- 6 scenario-based analysis recipes (malware, ransomware, patch, C++, firmware, APT)
- 4-phase tool ordering guide (Triage → Structural → Deep → Report)
- NOT USE WHEN warnings on 20+ critical tools
- SEE ALSO cross-references on 20+ critical tools

---

## Tool Categories by Purpose

### Binary Analysis
- Disassembly: `Radare2_disassemble*`, `run_radare2`
- Decompilation: `smart_decompile`, `get_pseudo_code`, `Radare2_decompile_function`, `Ghidra_*`
- Structure Recovery: `recover_structures`, `Ghidra_list_structures`
- Emulation: `emulate_machine_code`

### Malware Analysis
- Detection: `dormant_detector`, `vulnerability_hunter`, `run_yara`, `run_capa`, `detect_packer`
- IOC Extraction: `extract_iocs`, `add_ioc`
- Defense Generation: `adaptive_vaccine`, `generate_yara_rule`, `generate_signature`
- Reporting: `create_analysis_report`, `start_report_session`

### Binary Comparison
- Diffing: `diff_binaries`, `analyze_variant_changes`
- Patch Analysis: `explain_patch`
- Variant Analysis: `match_libraries`

### Static Analysis
- Strings: `run_strings`, `Radare2_list_strings`
- Imports/Exports: `Radare2_list_imports`, `Radare2_list_symbols`
- Sections: `Radare2_list_sections`, `Radare2_show_headers`
- Embedded Content: `run_binwalk`, `run_binwalk_extract`
- Version Detection: `scan_for_versions`
- RTTI: `extract_rtti_info`

### Control Flow Analysis
- Call Graphs: `Ghidra_get_call_graph`, `Radare2_list_functions_tree`
- CFG Generation: `generate_function_graph`
- Xref Analysis: `analyze_xrefs`, `Radare2_xrefs_to`
- Path Tracing: `trace_execution_path`

### Project Management
- Memory Sessions: `create_memory_session`, `resume_memory_session`
- Memory Store: `save_memory_item`, `recall_memory_item`
- Patterns: `save_pattern`, `find_similar_patterns`
- Monitoring: `get_server_health`, `get_tool_metrics`

---

**Last Updated**: 2025-06-24 (AI Agent guidance — tags, recipes, NOT USE WHEN, SEE ALSO added)
**Reversecore MCP Version**: 1.0.0


### Control Flow Analysis
- Call Graphs: `Ghidra_get_call_graph`, `Radare2_list_functions_tree`
- CFG Generation: `generate_function_graph`
- Xref Analysis: `analyze_xrefs`, `Radare2_xrefs_to`
- Path Tracing: `trace_execution_path`

### Project Management
- Sessions: `create_analysis_session`, `start_analysis_session`, `resume_session`
- Memory: `save_analysis_memory`, `recall_analysis_memory`
- Patterns: `save_pattern`, `find_similar_patterns`
- Monitoring: `get_server_health`, `get_tool_metrics`

---

**Last Updated**: 2024 (Generated from codebase analysis)
**Reversecore MCP Version**: 0.1.0
