/*
 * Modular YARA Rule: AES Cryptosystem Constants & Hardware Acceleration
 * Category: crypto
 */

rule Crypto_AES_SBox_Forward {
    meta:
        description = "Detects Rijndael / AES Forward S-Box lookup table constants"
        category = "crypto"
        algorithm = "AES"
        confidence = "high"
    strings:
        // Full first 32 bytes of AES forward S-box
        $sbox_32 = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 }
        // First 16 bytes of AES forward S-box
        $sbox_16 = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox_32 or $sbox_16
}

rule Crypto_AES_SBox_Inverse {
    meta:
        description = "Detects Rijndael / AES Inverse S-Box lookup table constants"
        category = "crypto"
        algorithm = "AES"
        confidence = "high"
    strings:
        // Full first 32 bytes of AES inverse S-box
        $inv_sbox_32 = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb }
        // First 16 bytes of AES inverse S-box
        $inv_sbox_16 = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }
    condition:
        $inv_sbox_32 or $inv_sbox_16
}

rule Crypto_AES_Rcon {
    meta:
        description = "Detects AES Round Constants (Rcon) lookup table"
        category = "crypto"
        algorithm = "AES"
        confidence = "medium"
    strings:
        // 8-bit Rcon table (10 rounds)
        $rcon_8 = { 01 02 04 08 10 20 40 80 1b 36 }
        // 32-bit word aligned Rcon table
        $rcon_32 = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 10 00 00 00 20 00 00 00 40 00 00 00 80 00 00 00 1b 00 00 00 36 00 00 00 }
    condition:
        $rcon_8 or $rcon_32
}

rule Crypto_AES_NI_Instructions {
    meta:
        description = "Detects x86/x64 Intel AES-NI hardware accelerated encryption/decryption opcodes"
        category = "crypto"
        algorithm = "AES-NI"
        confidence = "high"
    strings:
        $aesenc = { (66 0f 38 dc | 0f 38 dc) }          // AESENC
        $aesenclast = { (66 0f 38 dd | 0f 38 dd) }      // AESENCLAST
        $aesdec = { (66 0f 38 de | 0f 38 de) }          // AESDEC
        $aesdeclast = { (66 0f 38 df | 0f 38 df) }      // AESDECLAST
        $aeskeygenassist = { (66 0f 3a df | 0f 3a df) } // AESKEYGENASSIST
        $aesimc = { (66 0f 38 db | 0f 38 db) }          // AESIMC
    condition:
        2 of ($aesenc, $aesenclast, $aesdec, $aesdeclast, $aeskeygenassist, $aesimc)
}
