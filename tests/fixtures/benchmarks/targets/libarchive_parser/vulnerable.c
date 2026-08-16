/* LibArchive RAR Format Parser - Vulnerable Implementation (CVE-2019-18408)
 * Source: archive_read_support_format_rar.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct rar {
    uint8_t *tree_nodes;
    size_t tree_size;
    int compression_mode;
};

int rar_alloc_codes(struct rar *rar, size_t size) {
    if (!rar) return -1;
    rar->tree_nodes = (uint8_t *)malloc(size);
    if (!rar->tree_nodes) return -1;
    rar->tree_size = size;
    return 0;
}

void rar_free_codes(struct rar *rar) {
    if (!rar) return;
    if (rar->tree_nodes != NULL) {
        free(rar->tree_nodes);
        /* BUG (Line 482): Double-Free vulnerability.
         * Failing to NULL the pointer leaves a dangling pointer.
         * When subsequent cleanup routines run, rar_free_codes is called again.
         */
    }
}

int rar_read_header_corrupt_handler(struct rar *rar, const uint8_t *data, size_t size) {
    if (size > 10 && data[8] == 0x0d) {
        /* Error detected in corrupted Huffman table header */
        rar_free_codes(rar);
        return -1;
    }
    return 0;
}

void archive_read_format_rar_cleanup(struct rar *rar) {
    if (rar) {
        /* Second free call on dangling pointer */
        rar_free_codes(rar);
    }
}
