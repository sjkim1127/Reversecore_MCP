/*
 * LibFuzzer harness for CVE-2022-37434 — zlib inflateGetHeader
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char outbuf[4096];
    gz_header hdr;
    unsigned char extra[16];
    hdr.extra     = extra;
    hdr.extra_max = sizeof(extra);
    hdr.name      = NULL;
    hdr.comment   = NULL;

    z_stream s = {0};
    if (inflateInit2(&s, 47) != Z_OK) return 0;
    inflateGetHeader(&s, &hdr);
    s.next_in  = (Bytef*)data;
    s.avail_in = (uInt)size;
    s.next_out = outbuf;
    s.avail_out = sizeof(outbuf);
    inflate(&s, Z_FINISH);
    inflateEnd(&s);
    return 0;
}
