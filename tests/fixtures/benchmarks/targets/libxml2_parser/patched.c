/* LibXML2 Entity Expansion Parser - Patched Implementation (CVE-2022-2309 Fix)
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

void xmlPopInput(xmlParserCtxtPtr ctxt) {
    if (ctxt && ctxt->input) {
        xmlFreeInputStream(ctxt->input);
        ctxt->input = NULL; /* Properly clear context pointer */
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
        /* PATCH: Properly unlink and pop input before entity expansion */
        xmlPopInput(ctxt);
        if (ctxt->input != NULL) {
            ctxt->input->consumed += ent->length;
        }
        return ent->content;
    }
    return NULL;
}

int xmlParseElement(xmlParserCtxtPtr ctxt) {
    int len = 0;
    xmlChar *val = xmlParseAttValueComplex(ctxt, &len, 1);
    return val != NULL ? 1 : 0;
}
