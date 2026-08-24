# E2E Test Infra: Reversecore_MCP Static Binary Analysis Enhancement

## Test Philosophy
- Opaque-box, requirement-driven testing. No reliance on internal implementation shortcuts.
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Interaction Testing + Real-World Workload Testing.
- Strict Zero False Positive threshold on clean reference binaries.
- High True Positive Rate (>=95%) on evasion and signature fixtures.
- Sub-second performance SLA (<1.0s) for binary samples up to 10MB.

## Feature Inventory & Test Mapping
| # | Feature | Requirement Source | Tier 1 (Coverage) | Tier 2 (Boundary/Corner) | Tier 3 (Cross-Feature) | Tier 4 (Workloads) |
|---|---------|-------------------|:-----------------:|:-----------------------:|:----------------------:|:------------------:|
| 1 | YARA Crypto Signatures | R1 § Crypto constants | 5 tests (AES, RC4, ChaCha, RSA/ECC, SHA) | 5 tests (partial tables, endianness, truncated keys) | ✓ (Crypto + Packer) | ✓ (Ransomware sample) |
| 2 | YARA Injection Signatures | R1 § Code injection | 5 tests (Hollowing, Reflective, APC, Syscalls, Hijack) | 5 tests (interleaved instructions, split calls) | ✓ (Injection + Anti-Debug) | ✓ (Loader sample) |
| 3 | YARA Exploit Signatures | R1 § Exploit patterns | 5 tests (Egghunter, PEB walk, ROR13, Shellcode, ROP) | 5 tests (corrupted tags, small buffer) | ✓ (Exploit + Anti-Emulation) | ✓ (Stager sample) |
| 4 | Anti-Debug PEB/API | R2 § Anti-debugging | 5 tests (BeingDebugged, NtGlobalFlag, Heap, IsDebugger, Remote) | 5 tests (x86/x64 variants, manipulated flags) | ✓ (PEB + Timing) | ✓ (Evasive malware sample) |
| 5 | Timing Anomaly (RDTSC) | R2 § Timing deltas | 5 tests (RDTSC, RDTSCP, QPC, timeGetTime, Sleep) | 5 tests (inverted branches, fast forward) | ✓ (Timing + Hypervisor) | ✓ (Sandbox evader sample) |
| 6 | Hypervisor / Anti-VM | R2 § Hypervisor artifacts | 5 tests (CPUID leaf 1, leaf 0x40000000, VMWare I/O, MAC, Drivers) | 5 tests (unknown vendor, mixed casing) | ✓ (Anti-VM + Packer) | ✓ (Targeted trojan sample) |
| 7 | Shannon Entropy | R3 § Entropy analysis | 5 tests (uniform data, high entropy, zero bytes, alternating, code) | 5 tests (empty file, single byte, 10MB random) | ✓ (Entropy + Section Anomaly) | ✓ (Packed executable) |
| 8 | Section Anomalies | R3 § Section characteristics | 5 tests (W+X section, 0 raw size, non-standard name, empty name, EP anomaly) | 5 tests (malformed headers, max sections) | ✓ (Section + Overlay) | ✓ (Custom packed dropper) |
| 9 | Overlay Inspection | R3 § Overlay detection | 5 tests (PyInstaller overlay, Authenticode, ZIP, raw blob, no overlay) | 5 tests (0-byte overlay, 1-byte overlay, 5MB overlay) | ✓ (Overlay + Packer) | ✓ (PyInstaller malware) |
| 10 | Packer Fingerprinting | R3 § Deep fingerprinting | 5 tests (UPX, Themida, VMProtect, ConfuserEx, ASPack) | 5 tests (stripped headers, custom versions) | ✓ (Packer + Anti-Analysis) | ✓ (Obfuscated binary) |

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Evasive Ransomware Analysis | Crypto (AES/ChaCha), Anti-Debug (BeingDebugged), Timing (RDTSC), Overlay (Payload) | High |
| 2 | Advanced Reflective Loader | Injection (Reflective DLL, PEB Walk, Syscalls), Anti-VM (CPUID Hypervisor), Entropy | High |
| 3 | VMProtect Commercial Packed Malware | Packer (VMProtect), Section Anomaly ($W \oplus X$), High Entropy, Anti-Debug | High |
| 4 | PyInstaller Steganographic Dropper | Overlay (PyInstaller Archive), Entropy, Anti-Analysis (Sleep Evasion) | Medium |
| 5 | Clean System & Compiler Binaries | 0% False Positive Verification across MSVC, GCC, Clang, Go, Rust binaries | Medium |

## Coverage & SLA Thresholds
- Minimum Tier 1 tests: $\ge 50$ tests
- Minimum Tier 2 tests: $\ge 50$ tests
- Minimum Tier 3 tests: $\ge 10$ tests
- Minimum Tier 4 tests: $\ge 5$ application workloads
- Total test suite count: $\ge 115$ tests
- Accuracy: True Positive Rate $\ge 95\%$, False Positive Rate $= 0\%$ on clean reference binaries
- Latency: Sub-second ($< 1.0\text{s}$) on 10MB binaries
