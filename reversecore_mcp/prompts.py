from fastmcp import FastMCP

def register_prompts(mcp: FastMCP):
    """Registers analysis scenarios (prompts) to the server."""

    @mcp.prompt("full_analysis_mode")
    def full_analysis_mode(filename: str) -> str:
        """Expert mode that analyzes a file completely from A to Z."""
        return f"""
        You are a Reverse Engineering Expert AI Agent.
        You must perform a deep analysis of the file '{filename}' to identify security threats and write a technical analysis report.

        [Language Rule]
        - Answer in the same language as the user's request (Korean/English/Chinese, etc.).
        - Do not translate tool names or technical terms (e.g., `run_file`, `C2`, `IP`), but explain the context in the user's language.

        [Analysis SOP (Standard Operating Procedure)]
        Strictly follow these procedures in order and call the tools:

        1. Reconnaissance:
           - Identify the file type with `run_file`.
           - Extract IOCs (IP, URL, Email) with `extract_iocs` after running `run_strings`.
           - Report immediately if traces of packers (UPX, PyInstaller, etc.) are found.

        2. Filtering:
           - Narrow down the analysis target by filtering out standard library functions with `match_libraries`. (Important!)

        3. Deep Analysis:
           - If suspicious functions (encryption, socket, registry, etc.) are found:
             A. Understand the call relationship (context) with `analyze_xrefs`.
             B. Understand the data structure with `recover_structures`.
             C. Analyze the logic by securing pseudo-code (Pseudo-C) with `smart_decompile`.
           - If obfuscation is suspected or execution results are curious, safely execute a part with `emulate_machine_code`.

        4. Reporting:
           - Generate detection rules by running `generate_yara_rule` based on the found threats.
           - Finally, write a final report including the file's function, risk level, found IOCs, and YARA rules.

        Start from step 1 right now.
        """

    @mcp.prompt("basic_analysis_mode")
    def basic_analysis_mode(filename: str) -> str:
        """Rapid analysis mode that quickly identifies basic static analysis and threat elements."""
        return f"""
        You are a Reverse Engineering Security Analyst.
        Perform 'Rapid Static Analysis' on the file '{filename}' to identify initial threats.

        [Language Rule]
        - Answer in the same language as the user's request (Korean/English/Chinese, etc.).
        - Answer in the same language as the user's request.

        [Analysis SOP (Standard Operating Procedure)]
        Never use time-consuming deep analysis tools (Ghidra, Decompile, Emulation).
        Use only the following lightweight tools to get results quickly:

        1. Identification:
           - `run_file("{filename}")`: Identify the exact file type.
           - `parse_binary_with_lief("{filename}")`: Check binary structure, entropy, and section information to determine packing status.

        2. Strings & IOCs Analysis:
           - `run_strings("{filename}", min_length=5)`: Extract meaningful strings.
           - Based on the results, run `extract_iocs` to identify C2 IPs, URLs, emails, Bitcoin addresses, etc.

        3. API & Capabilities Summary:
           - `run_radare2("{filename}", "ii")`: Quickly list import functions to infer the file's main behavior (network connection, file manipulation, etc.).

        4. Quick Triage Report:
           - Summarize the file's identity, major IOCs found, and suspicious API behaviors.
           - Estimate the probability of the file being malicious (High/Medium/Low) and advise if deep analysis via `full_analysis_mode` is needed.
        """

