#!/usr/bin/env python3
"""Generate all benchmark fixture files for 6 new CVE targets."""

from pathlib import Path

BASE = Path("tests/fixtures/benchmarks/targets")

TARGETS = {
    "openssl_bn": {
        "cve": "CVE-2022-0778",
        "symbol": "BN_mod_sqrt",
        "source_file": "bn_sqrt.c",
        "source_line": 231,
        "bug_type": "timeout",
        "access_type": "NONE",
        "access_size": 0,
        "raw_poc": b"\x30\x82\x02\x00" + b"\x00" * 508,  # DER-encoded minimal cert stub
        "min_poc": b"\x30\x82\x00\x40" + b"\x00" * 60,
        "seed": b"\x30\x82\x01\x00" + b"\x00" * 252,
        "dict_tokens": ["-----BEGIN CERTIFICATE-----", "SEQUENCE", "INTEGER"],
        "vulnerable_c": """\
/*
 * OpenSSL BN_mod_sqrt Infinite Loop — CVE-2022-0778
 * Vulnerable version: OpenSSL 3.0.1
 *
 * Root cause: BN_mod_sqrt() does not detect the case where p is not prime,
 * entering an infinite loop when processing a crafted EC certificate.
 * No primality check is performed before the Tonelli-Shanks iteration.
 */
#include <openssl/bn.h>

BIGNUM *BN_mod_sqrt_vulnerable(BIGNUM *in, const BIGNUM *a,
                                const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *ret = in;
    /* VULNERABILITY: missing primality check on p.
     * If p is not prime, the loop never terminates. */
    while (!BN_is_one(ret)) {
        BN_mod_mul(ret, ret, ret, p, ctx); /* infinite for composite p */
    }
    return ret;
}
""",
        "patched_c": """\
/*
 * OpenSSL BN_mod_sqrt Patched — CVE-2022-0778 fix
 *
 * Fix: Verify p is prime before entering the iteration.
 * If p is not prime, return NULL to signal an error.
 */
#include <openssl/bn.h>

BIGNUM *BN_mod_sqrt_patched(BIGNUM *in, const BIGNUM *a,
                             const BIGNUM *p, BN_CTX *ctx) {
    /* FIX: primality check added */
    int is_prime = BN_check_prime(p, ctx, NULL);
    if (!is_prime) {
        BNerr(BN_F_BN_MOD_SQRT, BN_R_NOT_A_PRIME);
        return NULL;
    }
    BIGNUM *ret = in;
    int max_iter = BN_num_bits(p) * 2 + 8;
    for (int i = 0; i < max_iter && !BN_is_one(ret); i++) {
        BN_mod_mul(ret, ret, ret, p, ctx);
    }
    return ret;
}
""",
        "patch_diff": """\
--- a/crypto/bn/bn_sqrt.c
+++ b/crypto/bn/bn_sqrt.c
@@ -228,6 +228,12 @@ BIGNUM *BN_mod_sqrt(BIGNUM *in, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
     }

+    /* CVE-2022-0778 fix: verify p is prime before iteration */
+    int is_prime = BN_check_prime(p, ctx, NULL);
+    if (!is_prime) {
+        BNerr(BN_F_BN_MOD_SQRT, BN_R_NOT_A_PRIME);
+        goto end;
+    }
+
     if (BN_is_zero(A) || BN_is_one(A)) {
""",
        "harness_c": """\
/*
 * LibFuzzer harness for CVE-2022-0778 — OpenSSL BN_mod_sqrt
 */
#include <stdint.h>
#include <stddef.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const unsigned char *p = data;
    X509 *cert = d2i_X509(NULL, &p, (long)size);
    if (cert) {
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey) EVP_PKEY_free(pkey);
        X509_free(cert);
    }
    return 0;
}
""",
        "asan_log": """\
=================================================================
==12345==ERROR: AddressSanitizer: Timeout: loop did not terminate
Timed out after 30 seconds in BN_mod_sqrt bn_sqrt.c:231
    #0 0x7f1234560000 in BN_mod_sqrt bn_sqrt.c:231
    #1 0x7f1234561000 in EC_GROUP_set_curve ec_lib.c:344
    #2 0x7f1234562000 in d2i_ECParameters ec_asn1.c:1157
    #3 0x7f1234563000 in LLVMFuzzerTestOneInput harness.c:10:5
SUMMARY: AddressSanitizer: timeout in BN_mod_sqrt
""",
    },
    "zlib_inflate": {
        "cve": "CVE-2022-37434",
        "symbol": "inflateGetHeader",
        "source_file": "inflate.c",
        "source_line": 848,
        "bug_type": "heap-buffer-overflow",
        "access_type": "WRITE",
        "access_size": 1,
        "raw_poc": b"\x1f\x8b\x08\x0e" + b"\x00" * 44,
        "min_poc": b"\x1f\x8b\x08\x0e" + b"\x00" * 6,
        "seed": b"\x1f\x8b\x08\x00" + b"\x00" * 10 + b"\x03\x00\x00\x00\x00\x00",
        "dict_tokens": ["\\x1f\\x8b", "FNAME", "FCOMMENT", "FHCRC"],
        "vulnerable_c": """\
/*
 * zlib inflateGetHeader Heap Buffer Overflow — CVE-2022-37434
 * Vulnerable version: zlib 1.2.11
 *
 * Root cause: inflateGetHeader() does not validate the FEXTRA length field,
 * allowing an attacker to trigger an OOB write via a crafted gzip header.
 */
#include "zlib.h"

int inflateGetHeader_vulnerable(z_streamp strm, gz_headerp head) {
    /* VULNERABILITY: no bounds check on head->extra_max before memcpy */
    if (head->extra != NULL) {
        unsigned len = head->extra_len - head->extra_max;
        /* copies up to extra_len bytes even if extra buf is smaller */
        memcpy(head->extra + head->extra_max, strm->next_in, len);
    }
    return Z_OK;
}
""",
        "patched_c": """\
/*
 * zlib inflateGetHeader Patched — CVE-2022-37434 fix
 *
 * Fix: Clamp the copy length to the remaining space in head->extra.
 */
#include "zlib.h"

int inflateGetHeader_patched(z_streamp strm, gz_headerp head) {
    if (head->extra != NULL) {
        unsigned copy = head->extra_len;
        /* FIX: clamp to available buffer space */
        if (copy > head->extra_max - head->extra_off)
            copy = head->extra_max - head->extra_off;
        memcpy(head->extra + head->extra_off, strm->next_in, copy);
    }
    return Z_OK;
}
""",
        "patch_diff": """\
--- a/inflate.c
+++ b/inflate.c
@@ -845,7 +845,8 @@ int ZEXPORT inflateGetHeader(z_streamp strm, gz_headerp head)
             if (head->extra != NULL) {
-                copy = state->length;
+                copy = state->length;
+                if (copy > head->extra_max - state->head->extra_off)
+                    copy = head->extra_max - state->head->extra_off;
                 if (copy > have) copy = have;
""",
        "harness_c": """\
/*
 * LibFuzzer harness for CVE-2022-37434 — zlib inflateGetHeader
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char outbuf[4096];
    gz_header hdr;
    unsigned char extra[16];
    hdr.extra     = extra;
    hdr.extra_max = sizeof(extra);
    hdr.name      = NULL;
    hdr.comment   = NULL;

    z_stream s = {0};
    if (inflateInit2(&s, 47) != Z_OK) return 0;
    inflateGetHeader(&s, &hdr);
    s.next_in  = (Bytef*)data;
    s.avail_in = (uInt)size;
    s.next_out = outbuf;
    s.avail_out = sizeof(outbuf);
    inflate(&s, Z_FINISH);
    inflateEnd(&s);
    return 0;
}
""",
        "asan_log": """\
=================================================================
==20001==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000084
WRITE of size 1 at 0x602000000084 thread T0
    #0 0x555555557180 in inflateGetHeader inflate.c:848:8
    #1 0x555555558290 in inflate inflate.c:1094:5
    #2 0x555555559300 in LLVMFuzzerTestOneInput harness.c:18:5
SUMMARY: AddressSanitizer: heap-buffer-overflow in inflateGetHeader
""",
    },
    "curl_cookie": {
        "cve": "CVE-2022-27776",
        "symbol": "Curl_http_output_auth",
        "source_file": "http.c",
        "source_line": 728,
        "bug_type": "heap-buffer-overflow",
        "access_type": "READ",
        "access_size": 4096,
        "raw_poc": b"GET /redirect HTTP/1.1\r\nHost: evil.com\r\n"
        + b"Cookie: secret=AAAA" * 5
        + b"\r\n\r\n",
        "min_poc": b"GET / HTTP/1.1\r\nHost: x\r\nCookie: s=A\r\n\r\n",
        "seed": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "dict_tokens": ["Cookie:", "Authorization:", "Location:"],
        "vulnerable_c": """\
/*
 * cURL HTTP Cookie Leak — CVE-2022-27776
 * Vulnerable version: cURL 7.83.0
 *
 * Root cause: When following a redirect to a different host,
 * Curl_http_output_auth() does not clear auth/cookie headers,
 * leaking sensitive headers to the redirect destination.
 */
#include "curl/curl.h"

static CURLcode output_auth_headers_vulnerable(struct connectdata *conn,
                                               struct auth *authstatus,
                                               const char *request,
                                               const char *path) {
    /* VULNERABILITY: Cookie and Authorization headers forwarded on redirect
     * without checking if the new host matches the original. */
    Curl_safefree(conn->allocptr.cookieheader);
    conn->allocptr.cookieheader = Curl_cookie_list(conn->data);
    /* header appended unconditionally — leaks to attacker-controlled host */
    return CURLE_OK;
}
""",
        "patched_c": """\
/*
 * cURL HTTP Cookie Leak Patched — CVE-2022-27776 fix
 *
 * Fix: Check that the redirect host matches the original before forwarding
 * credential headers.
 */
#include "curl/curl.h"

static CURLcode output_auth_headers_patched(struct connectdata *conn,
                                            struct auth *authstatus,
                                            const char *request,
                                            const char *path) {
    /* FIX: only attach cookies if the host has not changed */
    if (!conn->data->state.this_is_a_follow ||
        Curl_host_is_allowed(conn->data, conn->host.name)) {
        Curl_safefree(conn->allocptr.cookieheader);
        conn->allocptr.cookieheader = Curl_cookie_list(conn->data);
    }
    return CURLE_OK;
}
""",
        "patch_diff": """\
--- a/lib/http.c
+++ b/lib/http.c
@@ -725,6 +725,10 @@ static CURLcode output_auth_headers(struct connectdata *conn,
     Curl_safefree(conn->allocptr.cookieheader);
+    /* CVE-2022-27776: do not forward cookies on cross-host redirect */
+    if (conn->data->state.this_is_a_follow &&
+        !Curl_host_is_allowed(conn->data, conn->host.name))
+        return CURLE_OK;
     conn->allocptr.cookieheader = Curl_cookie_list(conn->data);
""",
        "harness_c": """\
/*
 * LibFuzzer harness for CVE-2022-27776 — cURL cookie leak
 */
#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    char url[256];
    snprintf(url, sizeof(url), "http://127.0.0.1:65535/%.*s", (int)(size > 200 ? 200 : size), data);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1L);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return 0;
}
""",
        "asan_log": """\
=================================================================
==30001==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000001000
READ of size 4096 at 0x603000001000 thread T0
    #0 0x555555558180 in Curl_http_output_auth http.c:728:12
    #1 0x555555558300 in Curl_http http.c:2001:9
    #2 0x555555559400 in LLVMFuzzerTestOneInput harness.c:14:5
SUMMARY: AddressSanitizer: heap-buffer-overflow in Curl_http_output_auth
""",
    },
    "ffmpeg_hevc": {
        "cve": "CVE-2022-3341",
        "symbol": "hevc_parse_slice_header",
        "source_file": "hevc_ps.c",
        "source_line": 1247,
        "bug_type": "heap-buffer-overflow",
        "access_type": "READ",
        "access_size": 4,
        "raw_poc": b"\x00\x00\x00\x01\x26\x01" + b"\xff" * 250,
        "min_poc": b"\x00\x00\x00\x01\x26\x01" + b"\xff" * 42,
        "seed": b"\x00\x00\x00\x01\x40\x01" + b"\x00" * 16,
        "dict_tokens": ["\\x00\\x00\\x01", "HEVC", "NAL"],
        "vulnerable_c": """\
/*
 * FFmpeg HEVC Out-of-Bounds Read — CVE-2022-3341
 * Vulnerable version: FFmpeg 5.1
 *
 * Root cause: hevc_parse_slice_header() does not validate NAL unit
 * slice_segment_address against the number of CTUs in the picture,
 * causing an OOB read when the value exceeds the picture boundary.
 */
#include "hevc.h"

static int hevc_parse_slice_header_vulnerable(HEVCContext *s, HEVCNAL *nal) {
    SliceHeader *sh = &s->sh;
    /* VULNERABILITY: no upper-bound check on slice_segment_address */
    sh->slice_segment_address = get_ue_golomb(&s->HEVClc->gb);
    /* OOB: if slice_segment_address >= s->ps.sps->ctb_width * ctb_height */
    sh->dependent_slice_segment_flag = s->pps->dependent_slice_segments_enabled_flag;
    return 0;
}
""",
        "patched_c": """\
/*
 * FFmpeg HEVC Out-of-Bounds Read Patched — CVE-2022-3341 fix
 *
 * Fix: Validate slice_segment_address before use.
 */
#include "hevc.h"

static int hevc_parse_slice_header_patched(HEVCContext *s, HEVCNAL *nal) {
    SliceHeader *sh = &s->sh;
    sh->slice_segment_address = get_ue_golomb(&s->HEVClc->gb);
    /* FIX: bounds check against picture CTU count */
    int ctb_count = s->ps.sps->ctb_width * s->ps.sps->ctb_height;
    if (sh->slice_segment_address >= ctb_count) {
        av_log(s->avctx, AV_LOG_ERROR,
               "slice_segment_address %d out of range [0, %d)\\n",
               sh->slice_segment_address, ctb_count);
        return AVERROR_INVALIDDATA;
    }
    sh->dependent_slice_segment_flag = s->pps->dependent_slice_segments_enabled_flag;
    return 0;
}
""",
        "patch_diff": """\
--- a/libavcodec/hevc_ps.c
+++ b/libavcodec/hevc_ps.c
@@ -1244,6 +1244,11 @@ static int hevc_parse_slice_header(HEVCContext *s, HEVCNAL *nal)
     sh->slice_segment_address = get_ue_golomb(&s->HEVClc->gb);
+    /* CVE-2022-3341: validate address against picture dimensions */
+    if (sh->slice_segment_address >= s->ps.sps->ctb_width * s->ps.sps->ctb_height) {
+        av_log(s->avctx, AV_LOG_ERROR, "slice_segment_address out of range\\n");
+        return AVERROR_INVALIDDATA;
+    }
""",
        "harness_c": """\
/*
 * LibFuzzer harness for CVE-2022-3341 — FFmpeg HEVC OOB read
 */
#include <stdint.h>
#include <stddef.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AVCodecContext *ctx = avcodec_alloc_context3(avcodec_find_decoder(AV_CODEC_ID_HEVC));
    if (!ctx) return 0;
    if (avcodec_open2(ctx, avcodec_find_decoder(AV_CODEC_ID_HEVC), NULL) < 0) {
        avcodec_free_context(&ctx);
        return 0;
    }
    AVPacket *pkt = av_packet_alloc();
    av_packet_from_data(pkt, (uint8_t*)data, (int)size);
    AVFrame *frame = av_frame_alloc();
    int got = 0;
    avcodec_decode_video2(ctx, frame, &got, pkt);
    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}
""",
        "asan_log": """\
=================================================================
==40001==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x615000003c80
READ of size 4 at 0x615000003c80 thread T0
    #0 0x7f2345670000 in hevc_parse_slice_header hevc_ps.c:1247:8
    #1 0x7f2345671000 in ff_hevc_decode_nal_slice hevc_slice.c:2088:5
    #2 0x7f2345672000 in LLVMFuzzerTestOneInput harness.c:18:5
SUMMARY: AddressSanitizer: heap-buffer-overflow in hevc_parse_slice_header
""",
    },
    "php_spl": {
        "cve": "CVE-2022-31625",
        "symbol": "spl_dllist_object_free_storage",
        "source_file": "ext/spl/spl_dllist.c",
        "source_line": 316,
        "bug_type": "heap-use-after-free",
        "access_type": "READ",
        "access_size": 8,
        "raw_poc": b'O:19:"SplDoublyLinkedList":4:{i:0;i:0;i:1;i:0;i:2;a:1:{i:0;O:19:"SplDoublyLinkedList":1:{}}i:3;i:0;}',
        "min_poc": b'O:19:"SplDoublyLinkedList":1:{i:2;a:0:{}}',
        "seed": b'O:19:"SplDoublyLinkedList":1:{i:2;a:0:{}}',
        "dict_tokens": ["SplDoublyLinkedList", "SplStack", "unserialize"],
        "vulnerable_c": """\
/*
 * PHP SPL Type Confusion — CVE-2022-31625
 * Vulnerable version: PHP 8.1.5
 *
 * Root cause: SplDoublyLinkedList::unserialize() does not validate that
 * the IT_MODE member is properly initialized before calling
 * spl_dllist_object_free_storage(), leading to an uninitialized pointer UAF.
 */
#include "php.h"
#include "spl_dllist.h"

static void spl_dllist_object_free_storage_vulnerable(zend_object *object) {
    spl_dllist_object *intern = spl_dllist_from_obj(object);
    /* VULNERABILITY: intern->llist may be NULL if unserialize partially ran */
    spl_ptr_llist_destroy(intern->llist); /* NULL ptr dereference / UAF */
    zend_object_std_dtor(&intern->std);
}
""",
        "patched_c": """\
/*
 * PHP SPL Type Confusion Patched — CVE-2022-31625 fix
 *
 * Fix: Guard against NULL llist pointer before destruction.
 */
#include "php.h"
#include "spl_dllist.h"

static void spl_dllist_object_free_storage_patched(zend_object *object) {
    spl_dllist_object *intern = spl_dllist_from_obj(object);
    /* FIX: check for NULL before calling destroy */
    if (intern->llist) {
        spl_ptr_llist_destroy(intern->llist);
        intern->llist = NULL;
    }
    zend_object_std_dtor(&intern->std);
}
""",
        "patch_diff": """\
--- a/ext/spl/spl_dllist.c
+++ b/ext/spl/spl_dllist.c
@@ -313,7 +313,10 @@ static void spl_dllist_object_free_storage(zend_object *object)
     spl_dllist_object *intern = spl_dllist_from_obj(object);
-    spl_ptr_llist_destroy(intern->llist);
+    /* CVE-2022-31625: guard against uninitialized llist pointer */
+    if (intern->llist) {
+        spl_ptr_llist_destroy(intern->llist);
+        intern->llist = NULL;
+    }
     zend_object_std_dtor(&intern->std);
""",
        "harness_c": """\
/*
 * LibFuzzer harness for CVE-2022-31625 — PHP SPL type confusion
 */
#include <stdint.h>
#include <stddef.h>

/* Simulated PHP unserialize entry point for fuzzing */
extern int php_unserialize_data(const char *buf, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    php_unserialize_data((const char *)data, size);
    return 0;
}
""",
        "asan_log": """\
=================================================================
==50001==ERROR: AddressSanitizer: heap-use-after-free on address 0x604000003880
READ of size 8 at 0x604000003880 thread T0
    #0 0x5555555a1000 in spl_dllist_object_free_storage ext/spl/spl_dllist.c:316:5
    #1 0x5555555a2000 in zend_objects_store_del Zend/zend_objects_API.c:178:4
    #2 0x5555555a3000 in LLVMFuzzerTestOneInput harness.c:8:5
SUMMARY: AddressSanitizer: heap-use-after-free in spl_dllist_object_free_storage
""",
    },
    "expat_entity": {
        "cve": "CVE-2022-25315",
        "symbol": "storeRawNames",
        "source_file": "xmlparse.c",
        "source_line": 2653,
        "bug_type": "heap-buffer-overflow",
        "access_type": "WRITE",
        "access_size": 8,
        "raw_poc": b'<?xml version="1.0"?>' + b"<a " + b'b="' + b"x" * 60 + b'"/>' * 2,
        "min_poc": b'<?xml version="1.0"?><r b="' + b"x" * 4 + b'"/>',
        "seed": b'<?xml version="1.0"?><root/>',
        "dict_tokens": ["<?xml", "<!ENTITY", "xmlns"],
        "vulnerable_c": """\
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
""",
        "patched_c": """\
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
""",
        "patch_diff": """\
--- a/lib/xmlparse.c
+++ b/lib/xmlparse.c
@@ -2650,7 +2650,11 @@ static XML_Bool storeRawNames(XML_Parser parser)
     TAG *tag = parser->m_tagStack;
-    int bufSize = (tag->rawNameLength + 1) * sizeof(XML_Char);
+    /* CVE-2022-25315: use size_t to prevent integer overflow */
+    if (tag->rawNameLength > (SIZE_MAX / sizeof(XML_Char)) - 1)
+        return XML_FALSE;
+    size_t bufSize = ((size_t)tag->rawNameLength + 1) * sizeof(XML_Char);
     if (!poolGrow(&parser->m_tempPool))
""",
        "harness_c": """\
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
""",
        "asan_log": """\
=================================================================
==60001==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x608000003500
WRITE of size 8 at 0x608000003500 thread T0
    #0 0x555555560000 in storeRawNames xmlparse.c:2653:5
    #1 0x555555561000 in XML_ParseBuffer xmlparse.c:1814:8
    #2 0x555555562000 in LLVMFuzzerTestOneInput harness.c:9:5
SUMMARY: AddressSanitizer: heap-buffer-overflow in storeRawNames
""",
    },
}


def write_file(path: Path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    print(f"  wrote {path.relative_to(BASE.parent.parent.parent)}")


def make_target_json(tid: str, t: dict) -> str:
    import json

    return json.dumps(
        {
            "target_id": tid,
            "cve": t["cve"],
            "faulting_symbol": t["symbol"],
            "source_file": t["source_file"],
            "source_line": t["source_line"],
        },
        indent=2,
    )


for tid, t in TARGETS.items():
    target_dir = BASE / tid
    print(f"\n[{tid}] — {t['cve']}")

    write_file(target_dir / "vulnerable.c", t["vulnerable_c"])
    write_file(target_dir / "patched.c", t["patched_c"])
    write_file(target_dir / "patch.diff", t["patch_diff"])
    write_file(target_dir / "harness.c", t["harness_c"])
    write_file(target_dir / "asan_crash.log", t["asan_log"])
    write_file(target_dir / "poc_raw.bin", t["raw_poc"])
    write_file(target_dir / "poc_minimized.bin", t["min_poc"])
    write_file(target_dir / "seed_valid.bin", t["seed"])

    dict_content = "\n".join(f'"{tok}"' for tok in t["dict_tokens"]) + "\n"
    write_file(target_dir / "dictionary.dict", dict_content)

    write_file(target_dir / "target.json", make_target_json(tid, t))

print("\n✅ All fixture files generated successfully.")
