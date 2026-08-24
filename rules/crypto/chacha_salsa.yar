/*
 * Modular YARA Rule: ChaCha20, Salsa20, and Poly1305 Constants & Heuristics
 * Category: crypto
 */

rule Crypto_ChaCha20_Salsa20_Constants {
    meta:
        description = "Detects ChaCha20 / Salsa20 stream cipher state initialization constants"
        category = "crypto"
        algorithm = "ChaCha20/Salsa20"
        confidence = "high"
    strings:
        // "expand 32-byte k" (256-bit key sigma constant)
        $expand_32 = "expand 32-byte k" ascii wide
        $expand_32_hex = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }

        // "expand 16-byte k" (128-bit key tau constant)
        $expand_16 = "expand 16-byte k" ascii wide
        $expand_16_hex = { 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }

        // ChaCha20 / Salsa20 32-bit constant words: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        $sigma_words = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
    condition:
        $expand_32 or $expand_32_hex or $expand_16 or $expand_16_hex or $sigma_words
}

rule Crypto_Poly1305_Clamp_Masks {
    meta:
        description = "Detects Poly1305 MAC key clamping masks (r &= 0x0ffffffc0fffffff0ffffffc0fffffff)"
        category = "crypto"
        algorithm = "Poly1305"
        confidence = "high"
    strings:
        // 16-byte clamp mask in little endian (r[3], r[7], r[11], r[15] clamped to 0x0F, r[4], r[8], r[12] clamped to 0xFC)
        $clamp_16_le = { ff ff ff 0f fc ff ff 0f ff ff ff 0f fc ff ff 0f }
        // 64-bit clamp masks: 0x0ffffffc0fffffff, 0x0ffffffc0ffffffc
        $clamp_64_1 = { ff ff ff 0f fc ff ff 0f }
        // Clamping instruction sequence: and rax, 0x0ffffffc0fffffff
        $clamp_inst1 = { 48 81 ?? fc ff ff 0f }
        $clamp_inst2 = { 48 25 ff ff ff 0f }
        $clamp_inst3 = { 81 ?? fc ff ff 0f }
    condition:
        $clamp_16_le or $clamp_64_1 or (2 of ($clamp_inst*))
}
