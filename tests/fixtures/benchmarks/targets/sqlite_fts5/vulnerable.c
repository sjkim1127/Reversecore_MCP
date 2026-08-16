/* SQLite FTS5 Unicode Tokenizer - Vulnerable Implementation (CVE-2019-19645)
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

    while (i < nText) {
        uint32_t code = pText[i++];
        /* BUG (Line 124): Missing upper bound check on code category lookup offset.
         * If code + (pText[i] >> 2) >= CATEGORY_TABLE_SIZE, it reads/writes OOB.
         */
        uint32_t cat_val = g_unicode_categories[code + (pText[i] >> 2)];
        pOutput[out_idx++] = cat_val;
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
