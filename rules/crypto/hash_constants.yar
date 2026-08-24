/*
 * Modular YARA Rule: Cryptographic Hash & Block Cipher Constants (SHA-256, MD5, TEA/XTEA)
 * Category: crypto
 */

rule Crypto_SHA256_Constants {
    meta:
        description = "Detects SHA-256 initialization vector (H0-H7) or first round constants (K[64])"
        category = "crypto"
        algorithm = "SHA-256"
        confidence = "high"
    strings:
        // SHA-256 H0..H7 initial state (Big Endian)
        $sha256_init_be = { 6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a 51 0e 52 7f 9b 05 68 8c 1f 83 d9 ab 5b e0 cd 19 }
        // SHA-256 H0..H7 initial state (Little Endian)
        $sha256_init_le = { 67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5 7f 52 0e 51 8c 68 05 9b ab d9 83 1f 19 cd e0 5b }

        // SHA-256 first 16 bytes of K constants (Big Endian: 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5)
        $sha256_k_be = { 42 8a 2f 98 71 37 44 91 b5 c0 fb cf e9 b5 db a5 }
        // SHA-256 first 16 bytes of K constants (Little Endian)
        $sha256_k_le = { 98 2f 8a 42 91 44 37 71 cf fb c0 b5 a5 db b5 e9 }
    condition:
        $sha256_init_be or $sha256_init_le or $sha256_k_be or $sha256_k_le
}

rule Crypto_MD5_Constants {
    meta:
        description = "Detects MD5 initialization vector constants (A, B, C, D)"
        category = "crypto"
        algorithm = "MD5"
        confidence = "high"
    strings:
        // A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476 (Little Endian byte sequence)
        $md5_init = { 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 }
        $md5_words_le = { 67 45 23 01 ef cd ab 89 98 ba dc fe 10 32 54 76 }
    condition:
        $md5_init or $md5_words_le
}

rule Crypto_TEA_XTEA_Delta {
    meta:
        description = "Detects Tiny Encryption Algorithm (TEA / XTEA) Golden Ratio delta constant 0x9E3779B9"
        category = "crypto"
        algorithm = "TEA/XTEA"
        confidence = "high"
    strings:
        // Delta constant 0x9E3779B9 in arithmetic instructions (e.g. add sum, 0x9e3779b9)
        // Little Endian: B9 79 37 9E
        $delta_add_32 = { 81 ?? B9 79 37 9E }
        $delta_mov_32 = { ( B8 | B9 | BA | BB | BC | BD | BE | BF ) B9 79 37 9E }
        $delta_add_64 = { 48 81 ?? B9 79 37 9E }

        // TEA/XTEA characteristic shift-xor sequence: (v1 << 4) ^ (v1 >> 5) + v1 ^ sum + key[...]
        $tea_shift_xor = { C1 ?? 04 [0-6] C1 ?? 05 [0-6] 31 }
    condition:
        ($delta_add_32 and $tea_shift_xor) or
        ($delta_mov_32 and $tea_shift_xor) or
        ($delta_add_64 and $tea_shift_xor)
}
