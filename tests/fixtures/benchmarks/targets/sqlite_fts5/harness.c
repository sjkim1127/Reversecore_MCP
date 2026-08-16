#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct Fts5Tokenizer {
    int flags;
    uint32_t *output_buffer;
    int buffer_size;
} Fts5Tokenizer;

int sqlite3Fts5UnicodeTokenizer(Fts5Tokenizer *pTok, const uint8_t *pText, int nText);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 4096) return 0;

    Fts5Tokenizer tok;
    tok.flags = 0;
    tok.output_buffer = NULL;
    tok.buffer_size = 0;

    sqlite3Fts5UnicodeTokenizer(&tok, data, (int)size);

    if (tok.output_buffer) {
        free(tok.output_buffer);
    }
    return 0;
}
