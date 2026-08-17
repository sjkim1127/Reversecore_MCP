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
