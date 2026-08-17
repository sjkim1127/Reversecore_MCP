/*
 * zlib inflateGetHeader Patched — CVE-2022-37434 fix
 *
 * Fix: Clamp the copy length to the remaining space in head->extra.
 */
#include "zlib.h"

int inflateGetHeader_patched(z_streamp strm, gz_headerp head) {
    if (head->extra != NULL) {
        unsigned copy = head->extra_len;
        /* FIX: clamp to available buffer space */
        if (copy > head->extra_max - head->extra_off)
            copy = head->extra_max - head->extra_off;
        memcpy(head->extra + head->extra_off, strm->next_in, copy);
    }
    return Z_OK;
}
