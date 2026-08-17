/*
 * zlib inflateGetHeader Heap Buffer Overflow — CVE-2022-37434
 * Vulnerable version: zlib 1.2.11
 *
 * Root cause: inflateGetHeader() does not validate the FEXTRA length field,
 * allowing an attacker to trigger an OOB write via a crafted gzip header.
 */
#include "zlib.h"

int inflateGetHeader_vulnerable(z_streamp strm, gz_headerp head) {
    /* VULNERABILITY: no bounds check on head->extra_max before memcpy */
    if (head->extra != NULL) {
        unsigned len = head->extra_len - head->extra_max;
        /* copies up to extra_len bytes even if extra buf is smaller */
        memcpy(head->extra + head->extra_max, strm->next_in, len);
    }
    return Z_OK;
}
