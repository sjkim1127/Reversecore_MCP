/*
 * OpenSSL BN_mod_sqrt Infinite Loop — CVE-2022-0778
 * Vulnerable version: OpenSSL 3.0.1
 *
 * Root cause: BN_mod_sqrt() does not detect the case where p is not prime,
 * entering an infinite loop when processing a crafted EC certificate.
 * No primality check is performed before the Tonelli-Shanks iteration.
 */
#include <openssl/bn.h>

BIGNUM *BN_mod_sqrt_vulnerable(BIGNUM *in, const BIGNUM *a,
                                const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *ret = in;
    /* VULNERABILITY: missing primality check on p.
     * If p is not prime, the loop never terminates. */
    while (!BN_is_one(ret)) {
        BN_mod_mul(ret, ret, ret, p, ctx); /* infinite for composite p */
    }
    return ret;
}
