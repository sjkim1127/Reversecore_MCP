#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef char xmlChar;
typedef struct _xmlParserInput {
    const xmlChar *cur;
    const xmlChar *base;
    int length;
    int consumed;
} xmlParserInput;

typedef struct _xmlEntity {
    xmlChar *name;
    xmlChar *content;
    int length;
} xmlEntity;

typedef struct _xmlDoc {
    xmlEntity *entities[16];
    int entity_count;
} xmlDoc;

typedef struct _xmlParserCtxt {
    xmlDoc *myDoc;
    xmlParserInput *input;
    int error;
} xmlParserCtxt;

int xmlParseElement(xmlParserCtxt *ctxt);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10 || size > 65536) return 0;

    xmlDoc doc;
    memset(&doc, 0, sizeof(doc));

    xmlEntity ent;
    ent.name = (xmlChar *)"a";
    ent.content = (xmlChar *)"expanded";
    ent.length = 8;
    doc.entities[0] = &ent;
    doc.entity_count = 1;

    xmlParserInput *input = (xmlParserInput *)malloc(sizeof(xmlParserInput));
    if (!input) return 0;

    input->cur = (const xmlChar *)"a";
    input->base = (const xmlChar *)data;
    input->length = (int)size;
    input->consumed = 0;

    xmlParserCtxt ctxt;
    ctxt.myDoc = &doc;
    ctxt.input = input;
    ctxt.error = 0;

    xmlParseElement(&ctxt);
    return 0;
}
