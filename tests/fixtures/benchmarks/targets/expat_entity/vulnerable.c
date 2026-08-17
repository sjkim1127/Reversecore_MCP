/*
 * Expat storeRawNames Integer Overflow — CVE-2022-25315
 * Vulnerable version: Expat 2.4.4
 *
 * Root cause: storeRawNames() uses an integer multiplication to compute
 * the byte count for a realloc, which overflows for very large attribute
 * counts, producing a smaller buffer and causing an OOB write.
 */
#include "expat.h"

static XML_Bool storeRawNames_vulnerable(XML_Parser parser) {
    TAG *tag = parser->m_tagStack;
    int bufSize;
    /* VULNERABILITY: nameLen * sizeof(XML_Char) overflows for large inputs */
    bufSize = (tag->rawNameLength + 1) * sizeof(XML_Char); /* integer overflow */
    if (!poolGrow(&parser->m_tempPool))
        return XML_FALSE;
    /* write uses overflowed (small) bufSize — OOB */
    memcpy(tag->buf, tag->rawName, bufSize);
    return XML_TRUE;
}
