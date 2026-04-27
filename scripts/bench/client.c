/*
 * HTTP benchmark client using libcurl's multi interface.
 *
 * Usage: client <urls-file> <workers>
 * Output: JSON lines to stdout, one per completed request:
 *   {"url":"...","status":200}  or  {"url":"...","error":"..."}
 *
 * Pattern: pre-allocate `workers` easy handles, add them all to a multi
 * handle, then drive curl_multi_perform in a loop. When an easy handle
 * finishes (CURLMSG_DONE), print its result and refill it with the next
 * URL from the queue. Connection reuse happens automatically via libcurl's
 * internal connection cache on the multi handle.
 */

#define _POSIX_C_SOURCE 200809L
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct slot {
    CURL *eh;
    char url[2048];
    char errbuf[CURL_ERROR_SIZE];
};

static size_t discard_cb(char *p, size_t size, size_t nmemb, void *ud) {
    (void)p; (void)ud;
    return size * nmemb;
}

/* Escape a string for inclusion as a JSON string value. Writes into dst
 * (size n) and null-terminates. Handles ", \, and control chars. */
static void json_escape(char *dst, size_t n, const char *src) {
    size_t i = 0;
    for (const unsigned char *s = (const unsigned char *)src; *s && i + 7 < n; s++) {
        unsigned char c = *s;
        if (c == '"' || c == '\\') {
            dst[i++] = '\\'; dst[i++] = (char)c;
        } else if (c == '\n') { dst[i++] = '\\'; dst[i++] = 'n'; }
        else if (c == '\r') { dst[i++] = '\\'; dst[i++] = 'r'; }
        else if (c == '\t') { dst[i++] = '\\'; dst[i++] = 't'; }
        else if (c < 0x20) {
            i += (size_t)snprintf(dst + i, n - i, "\\u%04x", c);
        } else {
            dst[i++] = (char)c;
        }
    }
    dst[i] = 0;
}

static void configure(CURL *eh, struct slot *s, const char *url) {
    strncpy(s->url, url, sizeof(s->url) - 1);
    s->url[sizeof(s->url) - 1] = 0;
    s->errbuf[0] = 0;
    curl_easy_setopt(eh, CURLOPT_URL, s->url);
    curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(eh, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(eh, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(eh, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(eh, CURLOPT_ERRORBUFFER, s->errbuf);
    curl_easy_setopt(eh, CURLOPT_PRIVATE, s);
    /* No redirects to match the other clients' defaults. */
    curl_easy_setopt(eh, CURLOPT_FOLLOWLOCATION, 0L);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <urls-file> <workers>\n", argv[0]);
        return 2;
    }
    const char *urls_path = argv[1];
    int workers = atoi(argv[2]);
    if (workers <= 0) {
        fprintf(stderr, "invalid workers: %s\n", argv[2]);
        return 2;
    }

    /* Slurp URLs into memory — benchmark driver writes small files. */
    FILE *f = fopen(urls_path, "r");
    if (!f) { perror("fopen"); return 1; }
    size_t cap = 1024, n = 0;
    char **urls = malloc(cap * sizeof(char *));
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (!len || line[0] == '#') continue;
        if (n == cap) { cap *= 2; urls = realloc(urls, cap * sizeof(char *)); }
        urls[n++] = strdup(line);
    }
    fclose(f);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURLM *mh = curl_multi_init();
    /* Size the connection cache to match concurrency so every worker can hold
     * its own keepalive connection. Default is 10, which would serialize us. */
    curl_multi_setopt(mh, CURLMOPT_MAXCONNECTS, (long)workers);

    struct slot *slots = calloc((size_t)workers, sizeof(struct slot));
    size_t next_url = 0;
    long in_flight = 0;

    int initial = workers < (int)n ? workers : (int)n;
    for (int i = 0; i < initial; i++) {
        slots[i].eh = curl_easy_init();
        configure(slots[i].eh, &slots[i], urls[next_url++]);
        curl_multi_add_handle(mh, slots[i].eh);
        in_flight++;
    }

    char escaped[8192];
    int still_running = 0;
    do {
        curl_multi_perform(mh, &still_running);

        int msgs_left = 0;
        CURLMsg *msg;
        while ((msg = curl_multi_info_read(mh, &msgs_left))) {
            if (msg->msg != CURLMSG_DONE) continue;

            CURL *eh = msg->easy_handle;
            struct slot *s = NULL;
            curl_easy_getinfo(eh, CURLINFO_PRIVATE, &s);

            if (msg->data.result == CURLE_OK) {
                long status = 0;
                curl_easy_getinfo(eh, CURLINFO_RESPONSE_CODE, &status);
                json_escape(escaped, sizeof(escaped), s->url);
                printf("{\"url\":\"%s\",\"status\":%ld}\n", escaped, status);
            } else {
                const char *em = s->errbuf[0] ? s->errbuf
                                              : curl_easy_strerror(msg->data.result);
                char url_esc[4096], err_esc[4096];
                json_escape(url_esc, sizeof(url_esc), s->url);
                json_escape(err_esc, sizeof(err_esc), em);
                printf("{\"url\":\"%s\",\"error\":\"%s\"}\n", url_esc, err_esc);
            }

            curl_multi_remove_handle(mh, eh);
            if (next_url < n) {
                /* Refill this slot with the next URL. Reset before reuse so
                 * per-request state (err buffer, response code) is clean. */
                curl_easy_reset(eh);
                configure(eh, s, urls[next_url++]);
                curl_multi_add_handle(mh, eh);
            } else {
                curl_easy_cleanup(eh);
                s->eh = NULL;
                in_flight--;
            }
        }

        if (still_running || in_flight > 0) {
            /* Block until there's something to do. */
            int numfds = 0;
            curl_multi_poll(mh, NULL, 0, 1000, &numfds);
        }
    } while (still_running > 0 || in_flight > 0);

    for (int i = 0; i < workers; i++) {
        if (slots[i].eh) {
            curl_multi_remove_handle(mh, slots[i].eh);
            curl_easy_cleanup(slots[i].eh);
        }
    }
    free(slots);
    for (size_t i = 0; i < n; i++) free(urls[i]);
    free(urls);
    curl_multi_cleanup(mh);
    curl_global_cleanup();
    return 0;
}
