# Overview

Reversecore MCP is an AI-powered binary analysis platform built on the Model Context Protocol (MCP). It enables AI assistants to perform comprehensive binary analysis through natural language commands.

## What is MCP?

The Model Context Protocol (MCP) is a standard for connecting AI models to external tools and data sources. Reversecore MCP implements this protocol to provide binary analysis capabilities to AI assistants like Claude, GPT, and others.

## Key Capabilities

### Static Analysis

- **Disassembly**: Convert binary code to assembly using Radare2 and Capstone
- **Decompilation**: Generate pseudo-C code using Ghidra integration
- **Structure Recovery**: Automatically recover C++ class structures from binary code
- **Cross-Reference Analysis**: Track function calls and data references

### Dynamic Analysis

- **Code Emulation**: Safely emulate machine code using ESIL
- **Execution Tracing**: Follow code paths without actual execution

### Threat Detection

- **Ghost Trace**: Detect hidden malware behaviors and logic bombs
- **Trinity Defense**: Automated threat detection and response pipeline
- **YARA Integration**: Generate and scan with YARA signatures

### Game Security

- **Cheat Point Detection**: Find exploitable game mechanics
- **Protocol Analysis**: Reverse engineer game network protocols
- **Anti-Cheat Profiling**: Identify protection mechanisms

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    AI Assistant                          │
│              (Claude, GPT, Cursor, etc.)                │
└─────────────────────┬───────────────────────────────────┘
                      │ MCP Protocol
┌─────────────────────▼───────────────────────────────────┐
│                 Reversecore MCP Server                   │
├─────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│  │CLI Tools│  │Lib Tools│  │ Ghost   │  │ Trinity │    │
│  │         │  │         │  │ Trace   │  │ Defense │    │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘    │
├───────┼────────────┼───────────┼────────────┼──────────┤
│       │            │           │            │           │
│  ┌────▼────┐  ┌────▼────┐  ┌───▼───┐  ┌────▼────┐     │
│  │ Radare2 │  │  LIEF   │  │ ESIL  │  │  YARA   │     │
│  │ Ghidra  │  │Capstone │  │Emulate│  │ Sigs    │     │
│  └─────────┘  └─────────┘  └───────┘  └─────────┘     │
└─────────────────────────────────────────────────────────┘
```

## Tool Categories

| Category | Description | Example Tools |
|----------|-------------|---------------|
| **Basic Analysis** | File identification and string extraction | `run_file`, `run_strings` |
| **Disassembly** | Low-level code analysis | `run_radare2`, `disassemble_with_capstone` |
| **Decompilation** | High-level code recovery | `smart_decompile`, `get_pseudo_code` |
| **Advanced** | Structure and reference analysis | `recover_structures`, `analyze_xrefs` |
| **Defense** | Threat detection and response | `generate_yara_rule`, `trinity_defense` |
| **Reporting** | Analysis documentation | `create_analysis_report`, `send_report` |

## Next Steps

- [Binary Analysis Guide](binary-analysis.md) - Learn how to analyze executables
- [Decompilation Guide](decompilation.md) - Advanced decompilation techniques
- [Threat Detection Guide](threat-detection.md) - Malware analysis workflows
