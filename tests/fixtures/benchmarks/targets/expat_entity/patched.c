/*
 * Expat storeRawNames Patched — CVE-2022-25315 fix
 *
 * Fix: Use size_t arithmetic with overflow detection before allocating.
 */
#include "expat.h"

static XML_Bool storeRawNames_patched(XML_Parser parser) {
    TAG *tag = parser->m_tagStack;
    /* FIX: detect overflow before multiplication */
    if (tag->rawNameLength > (SIZE_MAX / sizeof(XML_Char)) - 1)
        return XML_FALSE;
    size_t bufSize = ((size_t)tag->rawNameLength + 1) * sizeof(XML_Char);
    if (bufSize > EXPAT_MAX_TAG_LEN)
        return XML_FALSE;
    if (!poolGrow(&parser->m_tempPool))
        return XML_FALSE;
    memcpy(tag->buf, tag->rawName, bufSize);
    return XML_TRUE;
}
