// SPDX-License-Identifier: MIT
// lookup_exec_append.c - Output append helpers for lookup exec

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lookup_exec_append.h"

char* wc_lookup_exec_append_and_free(char* base, const char* extra)
{
    size_t la = base ? strlen(base) : 0;
    size_t lb = extra ? strlen(extra) : 0;
    char* n = (char*)malloc(la + lb + 1);
    if (!n) {
        return base;
    }
    if (base) {
        memcpy(n, base, la);
    }
    if (extra) {
        memcpy(n + la, extra, lb);
    }
    n[la + lb] = '\0';
    if (base) {
        free(base);
    }
    return n;
}

char* wc_lookup_exec_append_body(char* combined, char** body, int suppress_current)
{
    if (!body) {
        return combined;
    }
    if (suppress_current) {
        if (*body) {
            free(*body);
            *body = NULL;
        }
        return combined;
    }
    if (!*body) {
        return combined;
    }
    if (!combined) {
        combined = *body;
        *body = NULL;
        return combined;
    }
    combined = wc_lookup_exec_append_and_free(combined, *body);
    free(*body);
    *body = NULL;
    return combined;
}

int wc_lookup_exec_append_redirect_header(char** combined,
                                          const char* next_host,
                                          int* additional_emitted,
                                          int emit_redirect_headers)
{
    if (!emit_redirect_headers || !combined || !next_host) {
        return 0;
    }

    char hdr[256];
    if (!additional_emitted || !*additional_emitted) {
        snprintf(hdr, sizeof(hdr), "\n=== Additional query to %s ===\n", next_host);
        if (additional_emitted) {
            *additional_emitted = 1;
        }
    } else {
        snprintf(hdr, sizeof(hdr), "\n=== Redirected query to %s ===\n", next_host);
    }
    *combined = wc_lookup_exec_append_and_free(*combined, hdr);
    return 0;
}
