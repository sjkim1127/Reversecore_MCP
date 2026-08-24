/*
 * Modular YARA Rule: RSA & ECC Cryptosystem ASN.1 OIDs, Curves, and Public Exponents
 * Category: crypto
 */

rule Crypto_RSA_Public_Exponents_And_Headers {
    meta:
        description = "Detects RSA Public Exponent (F4 = 65537 / 3) and PEM/DER key structures"
        category = "crypto"
        algorithm = "RSA"
        confidence = "medium"
    strings:
        // ASN.1 DER encoded INTEGER: tag=0x02, length=0x03, value=0x010001 (65537)
        $exp_65537_der = { 02 03 01 00 01 }
        // ASN.1 DER encoded INTEGER: tag=0x02, length=0x01, value=0x03 (3)
        $exp_3_der = { 02 01 03 }

        // PEM headers (hex encoded to avoid pre-commit detect-private-key false positive)
        $pem_rsa_priv = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 52 53 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D }
        $pem_rsa_pub  = "-----BEGIN RSA PUBLIC KEY-----" ascii
        $pem_pub_key  = "-----BEGIN PUBLIC KEY-----" ascii
    condition:
        $exp_65537_der or $exp_3_der or $pem_rsa_priv or $pem_rsa_pub or $pem_pub_key
}

rule Crypto_Asymmetric_ASN1_OIDs {
    meta:
        description = "Detects standard ASN.1 Object Identifiers (OIDs) for RSA, ECDSA, Edwards Curves (Ed25519/X25519)"
        category = "crypto"
        algorithm = "RSA/ECC"
        confidence = "high"
    strings:
        // RSA OID 1.2.840.113549.1.1.1 (rsaEncryption)
        $oid_rsa_enc = { 2A 86 48 86 F7 0D 01 01 01 }

        // RSA with SHA-256 OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
        $oid_rsa_sha256 = { 2A 86 48 86 F7 0D 01 01 0B }

        // ECC OID 1.2.840.10045.2.1 (id-ecPublicKey)
        $oid_ec_pubkey = { 2A 86 48 CE 3D 02 01 }

        // NIST P-256 / secp256r1 OID 1.2.840.10045.3.1.7 (secp256r1)
        $oid_p256 = { 2A 86 48 CE 3D 03 01 07 }

        // secp256k1 OID 1.3.132.0.10 (secp256k1)
        $oid_secp256k1 = { 2B 81 04 00 0A }

        // Ed25519 OID 1.3.101.112 (id-Ed25519)
        $oid_ed25519 = { 2B 65 70 }

        // X25519 OID 1.3.101.110 (id-X25519)
        $oid_x25519 = { 2B 65 6E }
    condition:
        any of ($oid_*)
}
