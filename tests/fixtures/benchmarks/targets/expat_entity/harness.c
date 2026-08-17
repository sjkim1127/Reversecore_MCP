/*
 * LibFuzzer harness for CVE-2022-25315 — Expat storeRawNames
 */
#include <stdint.h>
#include <stddef.h>
#include "expat.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    XML_Parser parser = XML_ParserCreate(NULL);
    if (!parser) return 0;
    XML_Parse(parser, (const char *)data, (int)size, 1);
    XML_ParserFree(parser);
    return 0;
}
