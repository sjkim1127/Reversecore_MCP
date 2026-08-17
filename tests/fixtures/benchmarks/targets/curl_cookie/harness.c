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
