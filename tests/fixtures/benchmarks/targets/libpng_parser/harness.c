#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t png_uint_32;
typedef uint8_t png_byte;
typedef png_byte* png_bytep;

typedef struct png_struct_def {
    const uint8_t *read_ptr;
    size_t remaining;
    int error_flag;
} png_struct;

typedef struct png_info_def {
    png_bytep exif;
    png_uint_32 exif_length;
} png_info;

int png_read_chunk(png_struct *png_ptr, png_info *info_ptr);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16 || size > 65536) return 0;

    /* Verify PNG signature */
    if (memcmp(data, "\x89PNG\r\n\x1a\n", 8) != 0) return 0;

    png_struct png_ptr;
    png_ptr.read_ptr = data + 8;
    png_ptr.remaining = size - 8;
    png_ptr.error_flag = 0;

    png_info info_ptr;
    info_ptr.exif = NULL;
    info_ptr.exif_length = 0;

    while (png_ptr.remaining > 8 && !png_ptr.error_flag) {
        if (!png_read_chunk(&png_ptr, &info_ptr)) break;
    }

    if (info_ptr.exif) {
        free(info_ptr.exif);
    }
    return 0;
}
