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
