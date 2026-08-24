# Project: Reversecore_MCP Static Binary Analysis & Heuristic Detection Enhancement

## Architecture
Reversecore_MCP enhances static binary analysis and heuristic detection across three specialized pillars:
1. **Pillar 1: YARA & Crypto/Injection Engine**: Modular YARA rule hierarchy (`rules/crypto/`, `rules/injection/`, `rules/exploits/`, `rules/malware/`, `rules/index.yar`), namespace-based compilation, multi-condition crypto constants (AES S-box/AES-NI, RC4 KSA/PRGA, ChaCha20/Poly1305, RSA/ECC OIDs, SHA-256), correlated injection patterns (Process Hollowing, Reflective DLL, Early Bird APC, Thread Hijack, Syscalls), exploit patterns (Egghunters, PEB resolution, ROP pivots), and resilient engine with directory loading and caching.
2. **Pillar 2: Anti-Analysis & Anti-Evasion Engine**: Comprehensive anti-debug, anti-VM, anti-emulation, and opaque predicate detector (`anti_analysis.py`), detecting PEB flags (`BeingDebugged`, `NtGlobalFlag`, `ProcessHeap`), timing deltas (`RDTSC`/`RDTSCP`, `QueryPerformanceCounter`, sleep acceleration), hypervisor artifacts (`CPUID` leaf 1 / 0x40000000, VM MAC OUIs, registry/drivers), SEH/VEH manipulation, composite Evasion Score (0-100), MITRE ATT&CK mapping, and automated neutralization patches.
3. **Pillar 3: Deep Packer & Protector Fingerprinting Engine**: Fast Shannon entropy calculator (whole-file and per-section), overlay inspector (physical extent, size, entropy, payload magic like PyInstaller/Authenticode/ZIP), multi-tier signature matcher (UPX, Themida, VMProtect, ConfuserEx, Enigma, ASPack, PECompact, PyInstaller), section anomaly analyzer ($W \oplus X$, zero raw size, entrypoint anomalies), and zero-dependency pure Python fallback header parsers.
4. **Testing, Benchmarking & Quality Infra**: High-throughput sub-second scanning (<1s on 10MB binaries), synthetic & real sample fixtures, 100% pytest pass rate with >=54% coverage, zero false positives on clean reference binaries, and clean ruff/black code standards.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Modular YARA Rule Structure | Separate rule files by category in `rules/crypto/`, `rules/injection/`, `rules/exploits/`, `rules/malware/`, with `rules/index.yar` | M1 | survey_r1 |
| 2 | Cryptosystem Constant Rules | Multi-condition rules for AES S-box/Rcon/AES-NI, RC4 KSA/PRGA, ChaCha20/Poly1305, RSA/ECC ASN.1 OIDs, SHA-256/MD5/TEA | M1 | survey_r1 |
| 3 | Code Injection Sequence Rules | Correlated signatures for Process Hollowing, Reflective DLL, Early Bird APC, Thread Hijacking, and Direct Syscalls | M1 | survey_r1 |
| 4 | Exploit & Shellcode Rules | Signatures for Egghunters, Shellcode PEB resolution, API hashing (ROR13/ROR7), and ROP stack pivots | M1 | survey_r1 |
| 5 | Enhanced YARA Runner Engine | Multi-namespace compilation (`crypto`, `injection`, `exploits`, `malware`), directory loading, default ruleset resolution, and caching | M1 | survey_r1 |
| 6 | YARA Tooling Bug Fixes | Fix `resources.py` `run_yara` call, register `generate_enhanced_yara_rule` in `AnalysisToolsPlugin`, modernize `test-yara-rules.py` | M1 | survey_r1 |
| 7 | Anti-Debug PEB Checking | Detect `BeingDebugged` (+0x02), `NtGlobalFlag` (+0x68/+0xBC), `ProcessHeap` flags (+0x0C/+0x10/+0x40/+0x44/+0x70/+0x74) | M2 | survey_r2 |
| 8 | Anti-Debug API & Native Calls | Detect `CheckRemoteDebuggerPresent`, `IsDebuggerPresent`, `NtQueryInformationProcess`, `NtSetInformationThread` (0x11), DR0-DR7 breakpoints, trap instructions (int 3, int 2D, icebp) | M2 | survey_r2 |
| 9 | Timing Anomaly Detection | Detect `RDTSC`/`RDTSCP` delta subtractions across blocks, high-resolution timers (`QueryPerformanceCounter`, `timeGetTime`), and sleep acceleration | M2 | survey_r2 |
| 10 | Hypervisor & Anti-VM Artifacts | Detect `CPUID` hypervisor bit / vendor strings (VMware, VBox, KVM, Hyper-V, Xen), VMware I/O port, VM MAC OUIs, VM drivers/registry keys | M2 | survey_r2 |
| 11 | Opaque Predicates & Anti-Emulation | Detect SEH chain overwrite (`fs:[0]`), VEH registration, memory exhaustion loops, junk overlapping instructions | M2 | survey_r2 |
| 12 | Anti-Analysis Scoring & Neutralization | Evasion Score (0-100), threat verdict, MITRE ATT&CK mappings, context awareness (game anti-cheat suppression), and vaccine patch generation | M2 | survey_r2 |
| 13 | Native Shannon Entropy Engine | Fast whole-file and per-section Shannon entropy calculation, block distribution maps, entropy categorization | M3 | survey_r3 |
| 14 | Section Anomaly Detection | Detect non-standard names, empty/whitespace names, $W \oplus X$ violations, virtual vs raw size disparity, entrypoint in suspicious section | M3 | survey_r3 |
| 15 | Overlay Inspection Engine | Physical extent calculation for PE/ELF, overlay size & ratio, overlay entropy, payload classifier (Authenticode, PyInstaller, ZIP, 7z, RAR, NSIS) | M3 | survey_r3 |
| 16 | Deep Packer/Protector Signatures | Signatures and markers for UPX, Themida, VMProtect, ConfuserEx, Dotfuscator, Enigma, ASPack, PECompact, PyInstaller, weighted heuristic score (0-1) | M3 | survey_r3 |
| 17 | Header Parser Fallbacks | Pure Python fallback parser for PE/ELF headers using `struct` when LIEF is unavailable or on malformed binaries; optional DIE CLI integration | M3 | survey_r3 |
| 18 | E2E Verification & Test Fixtures | Fixtures for synthetic crypto, injection, anti-debug/VM, and packed samples; 100% pass on clean binaries (0% FP) and >=95% TPR on evasion | M4 | survey_r1,r2,r3 |
| 19 | High-Throughput Benchmarks | Benchmark suite proving sub-second scanning latency (<1s) for binaries up to 10MB across all engines | M4 | survey_r3 |
| 20 | Code Quality, Hardening & Final Gate | Full test suite regression checks (coverage >=54%), ruff linting, black py312 formatting, adversarial stress testing, forensic integrity audit | M5 | survey_r1,r2,r3 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1: YARA & Crypto/Injection Engine | Features 1-6: Modular rules (`rules/`), crypto constants, injection sequences, exploits, engine enhancements, plugin registration | none | DONE |
| 2 | M2: Anti-Analysis & Anti-Evasion Engine | Features 7-12: `anti_analysis.py`, PEB checks, RDTSC deltas, CPUID/VM artifacts, scoring, MITRE mapping, vaccine integration | none | IN_PROGRESS |
| 3 | M3: Deep Packer & Protector Fingerprinting | Features 13-17: Shannon entropy, section anomalies, overlay inspector, packer signatures, fallback header parsers | none | PLANNED |
| 4 | M4: E2E Verification & Benchmarks | Features 18-19: Comprehensive test suite, fixtures, accuracy validation (TPR>=95%, FP=0%), 10MB sub-second benchmarks | M1, M2, M3 | PLANNED |
| 5 | M5: Adversarial Hardening & Final Gate | Feature 20: White-box adversarial testing, regression verification, code style (ruff, black), Forensic Integrity Audit | M4 | PLANNED |

## Interface Contracts

### M1 YARA Engine Interface
- Tool: `run_yara(file_path: str, rule_file: str | None = None, category: str | None = None, timeout: int = 300, run_async: bool = False, _bypass_queue: bool = False) -> ToolResult`
- Output Schema Content:
  ```json
  {
    "matches": [
      {
        "rule": "AES_Constants_And_SBox",
        "namespace": "crypto",
        "tags": ["crypto", "aes"],
        "meta": {"description": "...", "category": "crypto"},
        "strings": [{"name": "$sbox", "offset": 1024, "data": "..."}]
      }
    ],
    "match_count": 1,
    "categories": {"crypto": 1, "injection": 0, "exploits": 0, "malware": 0},
    "scan_diagnostics": {"rules_compiled": 15, "scan_time_ms": 12.4}
  }
  ```

### M2 Anti-Analysis Engine Interface
- Tool: `detect_anti_analysis(file_path: str, focus_functions: list[str] | None = None, verify_with_esil: bool = True) -> ToolResult`
- Output Schema Content:
  ```json
  {
    "file_path": "...",
    "evasion_score": 75,
    "verdict": "HIGHLY_EVASIVE",
    "summary": {"anti_debug": 2, "timing_evasion": 1, "anti_vm": 0, "anti_emulation": 1},
    "mitre_techniques": ["T1562.001", "T1497.003"],
    "findings": [
      {
        "id": "AD_PEB_BEINGDEBUGGED",
        "category": "anti_debug",
        "technique": "PEB BeingDebugged Flag Check",
        "severity": "critical",
        "confidence": "confirmed",
        "address": "0x401050",
        "function": "sub_401000",
        "instruction_sequence": "mov eax, fs:[0x30]; cmp byte [eax+2], 0; jne 0x401090",
        "evidence": "Direct dereference of PEB BeingDebugged flag",
        "mitre_technique": "T1562.001",
        "remediation_patch": {"type": "NOP_JUMP", "address": "0x401058", "length": 2}
      }
    ],
    "context_evaluation": {"is_game_client": false, "suppression_applied": 0},
    "neutralization_plan": [...]
  }
  ```

### M3 Deep Packer Engine Interface
- Tool: `detect_packer(file_path: str) -> ToolResult`
- Tool: `detect_packer_deep(file_path: str) -> ToolResult`
- Output Schema Content:
  ```json
  {
    "file_path": "...",
    "is_packed": true,
    "packing_confidence": 0.95,
    "packer_category": "commercial",
    "detected_packers": [{"name": "UPX", "version": "3.96", "type": "packer", "confidence": 1.0}],
    "compiler": "Microsoft Visual C/C++",
    "entropy": {
      "overall_file": 7.82,
      "category": "packed_or_encrypted",
      "high_entropy_sections": [{"name": "UPX1", "entropy": 7.91, "virtual_size": 65536, "raw_size": 40960}]
    },
    "section_anomalies": [
      {"section": "UPX0", "anomaly": "zero_raw_size", "severity": "high"},
      {"section": "UPX1", "anomaly": "writable_and_executable", "severity": "critical"}
    ],
    "overlay": {
      "has_overlay": true,
      "offset": 45056,
      "size": 8192,
      "ratio": 0.15,
      "entropy": 7.45,
      "payload_type": "PyInstaller_Archive"
    },
    "reasons": ["Detected UPX signature", "Section UPX1 is high entropy", "Section UPX0 has 0 raw size"]
  }
  ```

## Code Layout
- `rules/`:
  - `index.yar`
  - `crypto/`: `aes.yar`, `rc4.yar`, `chacha_salsa.yar`, `rsa_ecc.yar`, `hash_constants.yar`
  - `injection/`: `process_hollowing.yar`, `reflective_dll.yar`, `apc_earlybird.yar`, `thread_hijack.yar`, `syscalls.yar`
  - `exploits/`: `egghunter.yar`, `shellcode_heuristics.yar`, `rop_pivots.yar`
  - `malware/`: `malware_patterns.yar`
- `reversecore_mcp/tools/malware/yara_tools.py`: Enhanced YARA runner, namespace management, multi-file compilation, caching
- `reversecore_mcp/tools/analysis/signature_tools.py`: Signature and enhanced YARA rule generation
- `reversecore_mcp/tools/analysis/advanced_yara.py`: Instruction masking & advanced YARA rule generator
- `reversecore_mcp/tools/malware/anti_analysis.py`: New comprehensive Anti-Analysis & Anti-Evasion Engine
- `reversecore_mcp/tools/malware/dormant_detector.py`: Integrated with anti-analysis engine
- `reversecore_mcp/tools/analysis/static_analysis.py`: Static string/version/RTTI analysis
- `reversecore_mcp/tools/analysis/die_tools.py`: Enhanced packer detection, Shannon entropy, overlay inspection, fallback parsers
- `reversecore_mcp/tools/analysis/lief_tools.py`: LIEF parsing, mitigations, section characteristics
- `reversecore_mcp/tools/malware/__init__.py` & `reversecore_mcp/tools/analysis/__init__.py`: Plugin tool registrations
- `reversecore_mcp/resources.py`: Fixed resource integration
- `tests/fixtures/`: Clean binaries, synthetic evasion/crypto/injection/packed binaries
- `tests/unit/tools/malware/`: Unit tests for yara, anti-analysis, dormant detector
- `tests/unit/tools/analysis/`: Unit tests for die_tools, lief_tools, signature_tools, advanced_yara
- `tests/performance/test_performance_regression.py`: High-throughput benchmarks (<1s on 10MB)
