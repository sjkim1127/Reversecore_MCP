/*
 * OpenSSL BN_mod_sqrt Patched — CVE-2022-0778 fix
 *
 * Fix: Verify p is prime before entering the iteration.
 * If p is not prime, return NULL to signal an error.
 */
#include <openssl/bn.h>

BIGNUM *BN_mod_sqrt_patched(BIGNUM *in, const BIGNUM *a,
                             const BIGNUM *p, BN_CTX *ctx) {
    /* FIX: primality check added */
    int is_prime = BN_check_prime(p, ctx, NULL);
    if (!is_prime) {
        BNerr(BN_F_BN_MOD_SQRT, BN_R_NOT_A_PRIME);
        return NULL;
    }
    BIGNUM *ret = in;
    int max_iter = BN_num_bits(p) * 2 + 8;
    for (int i = 0; i < max_iter && !BN_is_one(ret); i++) {
        BN_mod_mul(ret, ret, ret, p, ctx);
    }
    return ret;
}
