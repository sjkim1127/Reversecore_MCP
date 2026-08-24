/*
 * Master YARA Rule Index for Reversecore_MCP
 * Imports all modular category rulesets: crypto, injection, exploits, and malware.
 */

// Cryptosystem Constants & Algorithms
include "crypto/aes.yar"
include "crypto/rc4.yar"
include "crypto/chacha_salsa.yar"
include "crypto/rsa_ecc.yar"
include "crypto/hash_constants.yar"

// Code Injection & Evasion Sequences
include "injection/process_hollowing.yar"
include "injection/reflective_dll.yar"
include "injection/apc_earlybird.yar"
include "injection/thread_hijack.yar"
include "injection/syscalls.yar"

// Exploits & Shellcode Heuristics
include "exploits/egghunter.yar"
include "exploits/shellcode_heuristics.yar"
include "exploits/rop_pivots.yar"

// Malware & Behavior Indicators
include "malware/malware_patterns.yar"
