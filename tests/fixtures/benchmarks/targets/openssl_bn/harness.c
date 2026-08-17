/*
 * LibFuzzer harness for CVE-2022-0778 — OpenSSL BN_mod_sqrt
 */
#include <stdint.h>
#include <stddef.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const unsigned char *p = data;
    X509 *cert = d2i_X509(NULL, &p, (long)size);
    if (cert) {
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey) EVP_PKEY_free(pkey);
        X509_free(cert);
    }
    return 0;
}
