# Reversecore MCP Tools Documentation

Comprehensive reference for all 96 tools available in the Reversecore MCP server for reverse engineering and malware analysis.

## Table of Contents

1. [Analysis Tools](#analysis-tools) (11 tools) - Binary diffing, signature generation, static analysis
2. [Common Tools](#common-tools) (17 tools) - Memory management, file operations, server monitoring
3. [Ghidra Tools](#ghidra-tools) (17 tools) - Structure recovery, decompilation, patching
4. [Malware Tools](#malware-tools) (5 tools) - Threat detection, IOC extraction, YARA scanning
5. [Radare2 Tools](#radare2-tools) (34 tools) - Comprehensive binary analysis suite
6. [Report Tools](#report-tools) (12 tools) - Professional malware analysis reporting

---

## Analysis Tools

**Plugin:** `AnalysisToolsPlugin` - Tools for binary comparison, signature generation, and static analysis.

### Binary Diffing Tools

#### `diff_binaries`

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

---

#### `analyze_variant_changes`

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

---

#### `match_libraries`

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

---

### Binary Parsing Tools

#### `parse_binary_with_lief`

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

#### `run_strings`

Extract printable strings using the `strings` CLI utility.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `min_length` (int) - Minimum string length (default: 4)
- `max_output_size` (int) - Maximum output size in bytes (default: 10MB)
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
List of extracted strings with statistics (total count, unique count).

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

#### `scan_for_versions`

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

---

#### `extract_rtti_info`

Extract RTTI (Run-Time Type Information) from C++ binaries.

RTTI provides class names and inheritance hierarchies in C++ binaries, invaluable for understanding object-oriented malware and game clients.

**Arguments:**
- `file_path` (str) - Path to the binary file
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
List of extracted class names, type information, and inheritance hierarchies.

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

#### `run_file`

Identify file metadata using the `file` CLI utility.

**Arguments:**
- `file_path` (str) - Path to the file to identify
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
File type information including format, architecture, and file magic details.

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

#### `explain_patch`

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

#### `emulate_machine_code`

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

#### `smart_decompile`

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

---

#### `recover_structures`

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

---

## Malware Tools

**Plugin:** `MalwareToolsPlugin` - Specialized tools for malware analysis and threat detection.

### `dormant_detector`

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

### `vulnerability_hunter`

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

---

### `extract_iocs`

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

#### `Radare2_open_file`

Open a binary file with radare2.

Initializes a radare2 session for analysis.

**Arguments:**
- `file_path` (str) - Path to the binary file

**Returns:**
Session ID for subsequent operations.

---

#### `Radare2_close_file`

Close the current radare2 session.

**Arguments:**
- `session_id` (str) - Session ID to close

**Returns:**
Confirmation of session closure.

---

#### `Radare2_analyze`

Analyze the binary with radare2's analysis engine.

**Arguments:**
- `session_id` (str) - Active session ID
- `level` (str) - Analysis level: 'basic', 'standard', 'advanced', 'experimental' (default: 'standard')

**Returns:**
Analysis summary including functions found, strings extracted, and imports identified.

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

#### `trace_execution_path`

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

---

#### `generate_function_graph`

Generate a Control Flow Graph (CFG) for a specific function.

Uses radare2 to analyze function structure and returns a visualization code (Mermaid by default) or PNG image.

**Arguments:**
- `file_path` (str) - Path to the binary file (must be in workspace)
- `function_address` (str) - Function address (e.g., 'main', '0x140001000', 'sym.foo')
- `format` (str) - Output format: 'mermaid', 'json', 'dot', or 'png' (default: 'mermaid')
- `timeout` (int) - Execution timeout in seconds (default: 120)

**Returns:**
CFG visualization, JSON data, or PNG image.

---

#### `analyze_xrefs`

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
- **Malware Tools**: 5 tools
- **Radare2 Tools**: 34 tools
- **Report Tools**: 12 tools

---

## Tool Categories by Purpose

### Binary Analysis
- Disassembly: `Radare2_disassemble*`, `run_radare2`
- Decompilation: `smart_decompile`, `get_pseudo_code`, `Radare2_decompile_function`, `Ghidra_*`
- Structure Recovery: `recover_structures`, `Ghidra_list_structures`
- Emulation: `emulate_machine_code`

### Malware Analysis
- Detection: `dormant_detector`, `vulnerability_hunter`, `run_yara`
- IOC Extraction: `extract_iocs`, `add_ioc`
- Defense Generation: `adaptive_vaccine`, `generate_yara_rule`, `generate_signature`
- Reporting: `create_analysis_report`, `start_analysis_session`

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
- Sessions: `create_analysis_session`, `start_analysis_session`, `resume_session`
- Memory: `save_analysis_memory`, `recall_analysis_memory`
- Patterns: `save_pattern`, `find_similar_patterns`
- Monitoring: `get_server_health`, `get_tool_metrics`

---

**Last Updated**: 2024 (Generated from codebase analysis)
**Reversecore MCP Version**: 0.1.0
