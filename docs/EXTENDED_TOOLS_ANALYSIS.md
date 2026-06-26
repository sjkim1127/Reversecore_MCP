# Extended Binary Analysis Tools Reference

This document provides a detailed overview of the system tools and third-party binaries supported by Reversecore MCP across macOS (development host) and Linux (CI/CD / Docker environment).

---

## 1. System Utility Matrix

Availability of command-line tools by environment:

| Utility | macOS (Host) | Linux (Docker / CI) | Primary Analysis Purpose |
|---------|--------------|----------------------|--------------------------|
| **file** | ✅ | ✅ | File type, MIME, and compiler format detection. |
| **strings** | ✅ | ✅ | ASCII and Unicode printables extraction. |
| **objdump** | ✅ | ✅ | Section headers and basic block disassembly. |
| **nm** | ✅ | ✅ | Symbol table auditing (unstripped binaries). |
| **otool** | ✅ | ❌ | macOS-specific Mach-O load command analysis. |
| **readelf** | ❌ | ✅ | Linux ELF header, sections, and program segments. |
| **ldd** | ❌ | ✅ | Dynamic link library dependency resolution. |
| **strace** | ❌ | ✅ | System call monitoring during process tracing. |
| **ltrace** | ❌ | ✅ | Dynamic library call tracing. |
| **radare2** | ✅ | ✅ | Comprehensive disassembly, scripting, and pool execution. |
| **yara** | ✅ | ✅ | Signature matching using rulesets. |
| **binwalk** | ✅ | ✅ | Firmware extraction and embedded compressed blob detection. |

---

## 2. Tool Details & Commands

### 2.1 file (File Magic Audit)
- **Purpose**: Fast signature identification of target headers.
- **Commands**:
  - `file <path>`: Show basic string (e.g. `ELF 64-bit LSB executable`).
  - `file -b <path>`: Brief mode (suppresses file name).
  - `file --mime-type <path>`: Outputs standardized MIME type.
- **Performance**: `~0.003s` (excellent for initial triage).

### 2.2 strings (ASCII/Unicode Extraction)
- **Purpose**: Discovers C2 domains, user agents, cryptographic keys, and shell commands.
- **Commands**:
  - `strings <path>`: Scan for printables (min-length 4).
  - `strings -n 8 <path>`: Set minimum character length to 8.
  - `strings -t x <path>`: Print the file offset in hexadecimal before the string.

### 2.3 objdump (Assembly Auditing)
- **Purpose**: Quick disassembly of specific section offsets.
- **Commands**:
  - `objdump -d <path>`: Disassemble executable sections.
  - `objdump -h <path>`: List section header details.
  - `objdump -t <path>`: Dump local symbols.

### 2.4 nm (Symbol Table Reader)
- **Purpose**: Extracts internal functions and static variable references.
- **Commands**:
  - `nm <path>`: Show symbols, marked with type codes (T: Text/Function, D: Data, U: Undefined/External import).
  - `nm -C <path>`: Demangles C++ compiler symbols automatically.

### 2.5 otool (macOS Mach-O Utility)
- **Purpose**: Audits loaders and dynamically linked frameworks on macOS.
- **Commands**:
  - `otool -h <path>`: Mach-O file headers.
  - `otool -L <path>`: List dynamically linked shared libraries.
  - `otool -l <path>`: Print Mach-O load commands.

### 2.6 readelf (ELF Format Auditor)
- **Purpose**: Precise ELF structure parsing on Linux.
- **Commands**:
  - `readelf -h <path>`: ELF Header.
  - `readelf -S <path>`: Section Headers.
  - `readelf -s <path>`: Symbol Table.

### 2.7 ldd (Dependency Resolver)
- **Purpose**: Maps shared objects (.so files) loaded at runtime.
- **Commands**:
  - `ldd <path>`: Prints resolution path of dynamic dependencies.

### 2.8 strace & ltrace (Dynamic Call Monitors)
- **Purpose**: Trace file access, processes, and network socket operations.
- **Commands**:
  - `strace ./binary`: Logs all system call entries.
  - `strace -e open,read ./binary`: Limit log to open and read syscalls.
  - `ltrace ./binary`: Logs library calls (e.g. `malloc`, `free`, `printf`).

---

## 3. Recommended Analysis Workflow

For standard manual command execution before using MCP automation:

```bash
# Phase 1: Determine format and packer
file suspicious.bin
detect_packer suspicious.bin

# Phase 2: Read printables
strings -n 6 suspicious.bin | grep -E "(http|https|sh|bash|cmd)"

# Phase 3: List functions
nm -C suspicious.bin
```
