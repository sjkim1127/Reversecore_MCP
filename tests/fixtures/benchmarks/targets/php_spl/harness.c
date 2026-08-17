/*
 * LibFuzzer harness for CVE-2022-31625 — PHP SPL type confusion
 */
#include <stdint.h>
#include <stddef.h>

/* Simulated PHP unserialize entry point for fuzzing */
extern int php_unserialize_data(const char *buf, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    php_unserialize_data((const char *)data, size);
    return 0;
}
