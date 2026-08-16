/* LibXML2 Entity Expansion Parser - Vulnerable Implementation (CVE-2022-2309)
 * Source: parser.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef char xmlChar;

typedef struct _xmlParserInput {
    const xmlChar *cur;
    const xmlChar *base;
    int length;
    int consumed;
} xmlParserInput;
typedef xmlParserInput *xmlParserInputPtr;

typedef struct _xmlEntity {
    xmlChar *name;
    xmlChar *content;
    int length;
} xmlEntity;
typedef xmlEntity *xmlEntityPtr;

typedef struct _xmlDoc {
    xmlEntityPtr entities[16];
    int entity_count;
} xmlDoc;
typedef xmlDoc *xmlDocPtr;

typedef struct _xmlParserCtxt {
    xmlDocPtr myDoc;
    xmlParserInputPtr input;
    int error;
} xmlParserCtxt;
typedef xmlParserCtxt *xmlParserCtxtPtr;

void xmlFreeInputStream(xmlParserInputPtr input) {
    if (input != NULL) {
        free(input);
    }
}

xmlEntityPtr xmlGetDocEntity(xmlDocPtr doc, const xmlChar *name) {
    if (!doc || !name) return NULL;
    for (int i = 0; i < doc->entity_count; i++) {
        if (doc->entities[i] && strcmp((const char *)doc->entities[i]->name, (const char *)name) == 0) {
            return doc->entities[i];
        }
    }
    return NULL;
}

xmlChar *xmlParseAttValueComplex(xmlParserCtxtPtr ctxt, int *attlen, int normalize) {
    if (!ctxt || !ctxt->input) return NULL;

    xmlEntityPtr ent = xmlGetDocEntity(ctxt->myDoc, ctxt->input->cur);
    if (ent != NULL) {
        /* Releases current input stream */
        xmlFreeInputStream(ctxt->input);

        /* BUG (Line 3890): Use-After-Free.
         * Dereferencing and writing to ctxt->input after freeing it.
         */
        ctxt->input->consumed += ent->length;
        return ent->content;
    }
    return NULL;
}

int xmlParseElement(xmlParserCtxtPtr ctxt) {
    int len = 0;
    xmlChar *val = xmlParseAttValueComplex(ctxt, &len, 1);
    return val != NULL ? 1 : 0;
}
