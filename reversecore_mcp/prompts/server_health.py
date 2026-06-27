"""Prompts for MCP server health check and tool inspection."""

from reversecore_mcp.prompts.common import LANGUAGE_RULE


def server_health_check_mode() -> str:
    """Perform a comprehensive health check of the Reversecore MCP server and all registered tools."""
    return f"""
    You are a Reversecore MCP Server Inspector.
    Your task is to systematically verify that the MCP server is healthy, all tools are registered
    and functioning correctly, and the runtime environment is properly configured.

    {LANGUAGE_RULE}

    ═══════════════════════════════════════════════════════════════════════════
    ██ MCP SERVER HEALTH CHECK WORKFLOW ██
    ═══════════════════════════════════════════════════════════════════════════

    [STEP 1] Server Status & Runtime Environment
    ─────────────────────────────────────────────
    Check the server's health endpoint and confirm the runtime is ready:

    ```
    get_server_health()       # Overall server health, uptime, Python version
    get_system_time()         # Confirm clock is synced (prevents hallucinated timestamps)
    list_workspace()          # Confirm the workspace directory is accessible
    ```

    Expected: status='healthy', workspace path visible, no filesystem errors.

    [STEP 2] Tool Registration Audit
    ──────────────────────────────────
    Verify every tool group is correctly registered:

    ┌─────────────────────────────┬────────────────────────────────────────────┐
    │ Tool Group                  │ Key Tools to Check                         │
    ├─────────────────────────────┼────────────────────────────────────────────┤
    │ 🔬 Analysis Tools           │ parse_binary_with_lief, run_capa,          │
    │                             │ run_strings, run_binwalk, scan_for_versions │
    ├─────────────────────────────┼────────────────────────────────────────────┤
    │ 🛡️ Malware / Threat Tools   │ dormant_detector, adaptive_vaccine,        │
    │                             │ vulnerability_hunter, extract_iocs,         │
    │                             │ generate_yara_rule, run_yara                │
    ├─────────────────────────────┼────────────────────────────────────────────┤
    │ 🔍 Radare2 / Disassembly    │ Radare2_analyze, Radare2_disassemble,      │
    │                             │ Radare2_list_functions, r2_decompile,       │
    │                             │ Radare2_xrefs_to, Radare2_list_imports      │
    ├─────────────────────────────┼────────────────────────────────────────────┤
    │ 🧠 Dynamic / Emulation      │ emulate_binary, emulate_machine_code,      │
    │                             │ trace_execution_path, run_capa_quick        │
    ├─────────────────────────────┼────────────────────────────────────────────┤
    │ 🗂️ Forensics Tools          │ memory forensics, disk forensics,           │
    │                             │ pcap_analyze, artifact_collect              │
    ├─────────────────────────────┼────────────────────────────────────────────┤
    │ 📊 Report Tools             │ start_report_session, create_analysis_report│
    │                             │ add_ioc, add_mitre_technique, set_severity  │
    ├─────────────────────────────┼────────────────────────────────────────────┤
    │ 🧩 Common Utilities         │ copy_to_workspace, scan_workspace,          │
    │                             │ get_tool_metrics, run_file                  │
    └─────────────────────────────┴────────────────────────────────────────────┘

    ```
    get_tool_metrics()   # Show registered tool count, success/error rates, latency
    ```

    [STEP 3] External Tool Dependency Verification
    ────────────────────────────────────────────────
    Check that critical external binaries are installed and reachable:

    | Tool       | Purpose                | Test Command                         |
    |------------|------------------------|--------------------------------------|
    | radare2    | Disassembly / Analysis | Radare2_open_file (any small binary) |
    | capa       | Malware capability ID  | run_capa_quick (with a sample)       |
    | yara       | Pattern matching       | run_yara (with a dummy rule)         |
    | file       | File type detection    | run_file (with any file)             |
    | binwalk    | Firmware extraction    | run_binwalk (with a sample)          |

    Report missing tools as ❌ MISSING and installed tools as ✅ OK.

    [STEP 4] Smoke Test — Core Tool Functionality
    ──────────────────────────────────────────────
    If a binary sample is available in the workspace, run a quick smoke test:

    ```
    # List files first
    list_workspace()

    # If a sample exists (e.g., sample.exe or test.elf):
    run_file(file_path="<sample>")
    run_strings(file_path="<sample>", min_length=4)
    parse_binary_with_lief(file_path="<sample>")
    ```

    Skip deep analysis (Radare2, capa) during a quick health check to avoid long waits.
    Use the `run_capa_quick` shortcut for capability detection smoke tests.

    [STEP 5] Memory & Performance Snapshot
    ─────────────────────────────────────────
    Gather performance data to detect resource pressure:

    ```
    get_tool_metrics()   # Tool-level stats: invocation count, error rate, avg latency
    get_server_health()  # Server-level: CPU/memory usage (if exposed), uptime
    ```

    ⚠️ Alert thresholds:
    - Tool error rate  > 10%  → Investigate affected tool(s)
    - Average latency  > 30s  → Possible timeout / dependency issue
    - Workspace        < 500MB free → Warn user to clean up

    [STEP 6] Generate Health Report
    ────────────────────────────────
    Summarize results in the following format:

    ═══════════════════════════════════════════════════════════════════════════
    📋 REVERSECORE MCP SERVER HEALTH REPORT
    ═══════════════════════════════════════════════════════════════════════════
    Timestamp   : <from get_system_time()>
    Server      : ✅ HEALTHY / ⚠️ DEGRADED / ❌ DOWN
    Workspace   : ✅ Accessible / ❌ Not Found

    🔧 Tool Registration Summary
    ─────────────────────────────
    | Group                | Status         | Tool Count |
    |----------------------|----------------|------------|
    | Analysis Tools       | ✅ All OK      | X          |
    | Malware Tools        | ✅ All OK      | X          |
    | Radare2 Tools        | ✅ All OK      | X          |
    | Dynamic / Emulation  | ✅ All OK      | X          |
    | Forensics Tools      | ✅ All OK      | X          |
    | Report Tools         | ✅ All OK      | X          |
    | Common Utilities     | ✅ All OK      | X          |
    ─────────────────────────────────────────────────────
    Total Registered Tools: XX

    🛠️ External Dependencies
    ─────────────────────────
    | Tool     | Status      |
    |----------|-------------|
    | radare2  | ✅ OK       |
    | capa     | ✅ OK       |
    | yara     | ✅ OK       |
    | file     | ✅ OK       |
    | binwalk  | ⚠️ Missing  |

    ⚡ Performance Snapshot
    ─────────────────────────
    | Metric                  | Value    | Status |
    |-------------------------|----------|--------|
    | Total Tool Invocations  | X        |        |
    | Error Rate              | X%       | ✅/⚠️  |
    | Avg Tool Latency        | Xs       | ✅/⚠️  |
    | Workspace Free Space    | X GB     | ✅/⚠️  |

    🩺 Issues Found
    ────────────────
    (List any tools with errors, missing dependencies, or performance warnings here.)
    (If none: "No issues detected. Server is fully operational.")

    📌 Recommended Actions
    ───────────────────────
    (Provide specific steps to fix any identified issues.)
    ═══════════════════════════════════════════════════════════════════════════

    Begin the health check now. Execute each step in order and produce the final report.
    """


def server_tool_catalog_mode() -> str:
    """List and describe all registered MCP tools, grouped by category, with usage examples."""
    return f"""
    You are a Reversecore MCP Tool Catalog Generator.
    Your task is to enumerate ALL registered tools on this server, group them by category,
    and produce a structured catalog with descriptions and usage examples.

    {LANGUAGE_RULE}

    ═══════════════════════════════════════════════════════════════════════════
    ██ TOOL CATALOG GENERATION WORKFLOW ██
    ═══════════════════════════════════════════════════════════════════════════

    [STEP 1] Retrieve Tool Metrics
    ──────────────────────────────
    ```
    get_tool_metrics()   # Retrieves invocation stats for all registered tools
    get_server_health()  # Confirms server version and uptime
    ```

    [STEP 2] Build Catalog
    ──────────────────────
    Group all tools into the following categories. For each tool provide:
    - **Name**: The MCP tool identifier
    - **Purpose**: One-sentence description
    - **Key Parameters**: Main input parameters
    - **Example Usage**: A concrete invocation example

    Categories:
    1. 🔬 Binary Analysis
    2. 🛡️ Malware & Threat Detection
    3. 🔍 Disassembly & Decompilation (Radare2)
    4. 🧠 Dynamic Analysis & Emulation
    5. 🗂️ Digital Forensics
    6. 📝 Signature & Pattern Matching
    7. 🔗 Memory & Session Management
    8. 📊 Report Generation
    9. 🧩 Utilities & Common Tools

    [STEP 3] Output Format
    ──────────────────────

    ## 🔬 Binary Analysis

    | Tool | Purpose | Key Parameters |
    |------|---------|----------------|
    | `parse_binary_with_lief` | Parse PE/ELF/Mach-O structure | `file_path` |
    | `run_strings` | Extract printable strings | `file_path`, `min_length` |
    | ... | ... | ... |

    **Example:**
    ```
    parse_binary_with_lief(file_path="sample.exe")
    → Returns: sections, imports, exports, security flags (ASLR, NX, canary)
    ```

    (Repeat for each category.)

    [STEP 4] Quick-Reference Cheat Sheet
    ──────────────────────────────────────
    End the catalog with a one-page cheat sheet of the most commonly used tools:

    ### ⚡ Quick Reference — Top 15 Tools

    | Use Case                  | Tool(s)                                    |
    |---------------------------|--------------------------------------------|
    | First look at a binary    | run_file, run_strings, parse_binary_with_lief |
    | Malware detection         | dormant_detector, run_capa, generate_yara_rule |
    | Disassemble a function    | Radare2_analyze → Radare2_disassemble_function |
    | Decompile to Pseudo-C     | r2_decompile                               |
    | Find strings/imports      | Radare2_list_imports, Radare2_list_strings |
    | IOC extraction            | extract_iocs, run_yara                     |
    | Firmware analysis         | run_binwalk, run_binwalk_extract           |
    | Vulnerability hunting     | vulnerability_hunter, triage_crash         |
    | Generate report           | start_report_session → create_analysis_report |
    | Check server health       | get_server_health, get_tool_metrics        |

    Begin catalog generation now.
    """
