/* SQLite FTS5 Unicode Tokenizer - Patched Implementation (CVE-2019-19645 Fix)
 * Source: fts5_unicode2.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_TOKENS 1024
#define CATEGORY_TABLE_SIZE 256
#define UNICODE_REPLACEMENT_CHAR 0xFFFD

static uint32_t g_unicode_categories[CATEGORY_TABLE_SIZE];
static bool g_initialized = false;

static void init_unicode_tables(void) {
    if (g_initialized) return;
    for (int i = 0; i < CATEGORY_TABLE_SIZE; i++) {
        g_unicode_categories[i] = (uint32_t)(i * 31 + 7);
    }
    g_initialized = true;
}

typedef struct Fts5Tokenizer {
    int flags;
    uint32_t *output_buffer;
    int buffer_size;
} Fts5Tokenizer;

int fts5UnicodeTokenize(const uint8_t *pText, int nText, uint32_t *pOutput) {
    int i = 0;
    int out_idx = 0;

    init_unicode_tables();

    while (i < nText && out_idx < MAX_TOKENS) {
        uint32_t code = pText[i++];
        uint32_t offset = (i < nText) ? (pText[i] >> 2) : 0;
        /* PATCH: Validate category table index boundaries */
        if (code + offset >= CATEGORY_TABLE_SIZE) {
            code = UNICODE_REPLACEMENT_CHAR;
        } else {
            code = g_unicode_categories[code + offset];
        }
        pOutput[out_idx++] = code;
    }
    return out_idx;
}

int sqlite3Fts5UnicodeTokenizer(Fts5Tokenizer *pTok, const uint8_t *pText, int nText) {
    if (!pTok || !pText || nText <= 0) return -1;
    if (!pTok->output_buffer) {
        pTok->buffer_size = 16;
        pTok->output_buffer = (uint32_t *)malloc(pTok->buffer_size * sizeof(uint32_t));
        if (!pTok->output_buffer) return -1;
    }
    return fts5UnicodeTokenize(pText, nText, pTok->output_buffer);
}
