/* LibPNG eXIf Chunk Parser - Patched Implementation (CVE-2018-13785 Fix)
 * Source: pngrutil.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PNG_UINT_31_MAX 0x7fffffffUL
#define MAX_EXIF_SIZE 65536
#define PNG_PNG_SIGNATURE "\x89PNG\r\n\x1a\n"

typedef uint32_t png_uint_32;
typedef uint8_t png_byte;
typedef png_byte* png_bytep;

typedef struct png_struct_def {
    const uint8_t *read_ptr;
    size_t remaining;
    int error_flag;
} png_struct;
typedef png_struct* png_structrp;

typedef struct png_info_def {
    png_bytep exif;
    png_uint_32 exif_length;
} png_info;
typedef png_info* png_inforp;

void png_crc_read(png_structrp png_ptr, png_bytep buf, png_uint_32 length) {
    if (png_ptr->remaining < length) {
        length = (png_uint_32)png_ptr->remaining;
    }
    memcpy(buf, png_ptr->read_ptr, length);
    png_ptr->read_ptr += length;
    png_ptr->remaining -= length;
}

void png_handle_eXIf(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length) {
    /* PATCH: Prevent integer overflow and enforce maximum chunk size */
    if (length > PNG_UINT_31_MAX - 1 || length > MAX_EXIF_SIZE) {
        png_ptr->error_flag = 1;
        return;
    }

    png_bytep exif_buf = (png_bytep)malloc(length + 1);
    if (exif_buf == NULL) return;

    png_crc_read(png_ptr, exif_buf, length);
    exif_buf[length] = '\0';
    info_ptr->exif = exif_buf;
    info_ptr->exif_length = length;
}

int png_read_chunk(png_structrp png_ptr, png_inforp info_ptr) {
    if (png_ptr->remaining < 8) return 0;

    png_uint_32 length = ((png_uint_32)png_ptr->read_ptr[0] << 24) |
                         ((png_uint_32)png_ptr->read_ptr[1] << 16) |
                         ((png_uint_32)png_ptr->read_ptr[2] << 8)  |
                         ((png_uint_32)png_ptr->read_ptr[3]);
    png_ptr->read_ptr += 4;
    png_ptr->remaining -= 4;

    char chunk_type[5] = {0};
    memcpy(chunk_type, png_ptr->read_ptr, 4);
    png_ptr->read_ptr += 4;
    png_ptr->remaining -= 4;

    if (strcmp(chunk_type, "eXIf") == 0) {
        png_handle_eXIf(png_ptr, info_ptr, length);
    }
    return 1;
}
