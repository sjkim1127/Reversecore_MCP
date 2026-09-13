/* Differential LibFuzzer harness for zlib deflate buffer handling. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char output[2 * 1024 * 1024];
    z_stream stream;
    size_t input_size;

    if (size < 1) return 0;
    input_size = size;
    if (input_size > 1024 * 1024) input_size = 1024 * 1024;

    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS,
                     1, Z_FIXED) != Z_OK) return 0;
    stream.next_in = (Bytef *)data;
    stream.avail_in = (uInt)input_size;
    stream.next_out = output;
    stream.avail_out = sizeof(output);
    (void)deflate(&stream, Z_FINISH);
    deflateEnd(&stream);
    return 0;
}
