/*
 * Modular YARA Rule: RC4 (Rivest Cipher 4 / ARC4) Stream Cipher Heuristics
 * Category: crypto
 */

rule Crypto_RC4_KSA_Init_Loop {
    meta:
        description = "Detects RC4 Key-Scheduling Algorithm (KSA) 0..255 state array initialization loop"
        category = "crypto"
        algorithm = "RC4"
        confidence = "medium"
    strings:
        // x86/x64 typical KSA init loops (S[i] = i for i in 0..255)
        // 1. mov [reg+i], i_reg; inc i_reg; cmp i_reg, 0x100; jne
        $ksa_loop1 = { 88 ?? ?? 4? 81 ?? 00 01 00 00 75 }
        // 2. mov [reg+i], i_reg; inc i_reg; cmp i_reg, 0x100; jl/jb
        $ksa_loop2 = { 88 ?? ?? 4? 81 ?? 00 01 00 00 72 }
        // 3. x64 variant: mov byte ptr [rdi+rax], al; inc rax; cmp rax, 256; jne
        $ksa_loop3 = { 88 04 ?? 48 FF C? 48 81 F? 00 01 00 00 75 }
        // 4. 32-bit loop with 256 limit (0x100)
        $ksa_loop4 = { B9 00 01 00 00 [0-8] 88 ?? ?? E2 }
    condition:
        any of ($ksa_loop*)
}

rule Crypto_RC4_PRGA_Keystream_Loop {
    meta:
        description = "Detects RC4 Pseudo-Random Generation Algorithm (PRGA) keystream generation & swap sequence"
        category = "crypto"
        algorithm = "RC4"
        confidence = "high"
    strings:
        // PRGA typical sequence: inc i; j += s[i]; swap(s[i], s[j]); output s[(s[i]+s[j])&0xFF]
        $prga_seq1 = { ( FE C? | FF C? ) [0-10] 0F B6 ?? [0-10] 01 ?? [0-10] 88 ?? }
        $prga_seq2 = { 80 C? 01 [0-10] 8A ?? [0-10] 03 ?? [0-10] 86 ?? }

        // Identifiers
        $str_rc4_1 = "RC4_KEY" ascii wide
        $str_rc4_2 = "rc4_init" ascii nocase
        $str_rc4_3 = "rc4_crypt" ascii nocase
        $str_rc4_4 = "arcfour" ascii nocase
    condition:
        $prga_seq1 or $prga_seq2 or 2 of ($str_rc4_*)
}
