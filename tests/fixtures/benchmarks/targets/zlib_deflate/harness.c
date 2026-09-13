/* Differential LibFuzzer harness for zlib deflate buffer handling. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char output[8192];
    z_stream stream;
    size_t input_size;
    int level;
    int flush;

    if (size < 8) return 0;
    input_size = size - 3;
    if (input_size > 65536) input_size = 65536;
    level = (int)(data[0] % 10);
    flush = (int)(data[1] % 5);

    memset(&stream, 0, sizeof(stream));
    if (deflateInit(&stream, level) != Z_OK) return 0;
    stream.next_in = (Bytef *)(data + 3);
    stream.avail_in = (uInt)input_size;
    stream.next_out = output;
    stream.avail_out = sizeof(output);
    (void)deflate(&stream, flush);
    stream.next_out = output;
    stream.avail_out = sizeof(output);
    (void)deflate(&stream, Z_FINISH);
    deflateEnd(&stream);
    return 0;
}
