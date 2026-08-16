#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct rar {
    uint8_t *tree_nodes;
    size_t tree_size;
    int compression_mode;
};

int rar_alloc_codes(struct rar *rar, size_t size);
int rar_read_header_corrupt_handler(struct rar *rar, const uint8_t *data, size_t size);
void archive_read_format_rar_cleanup(struct rar *rar);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 7 || size > 65536) return 0;

    /* Check RAR magic signature "Rar!\x1a\x07\x00" */
    if (memcmp(data, "Rar!\x1a\x07\x00", 7) != 0) return 0;

    struct rar rar_state;
    rar_state.tree_nodes = NULL;
    rar_state.tree_size = 0;
    rar_state.compression_mode = 0;

    if (rar_alloc_codes(&rar_state, 32) != 0) return 0;

    rar_read_header_corrupt_handler(&rar_state, data, size);
    archive_read_format_rar_cleanup(&rar_state);

    return 0;
}
