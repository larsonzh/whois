// SPDX-License-Identifier: MIT
// lookup_exec_append.c - Output append helpers for lookup exec

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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
                                          const char* next_ip,
                                          int* additional_emitted,
                                          int emit_redirect_headers)
{
    if (!emit_redirect_headers || !combined || !next_host) {
        return 0;
    }

    char hdr[256];
    const char* ip_value = (next_ip && next_ip[0]) ? next_ip : "unknown";
    if (!additional_emitted || !*additional_emitted) {
        snprintf(hdr, sizeof(hdr), "\n=== Additional query to %s @ %s ===\n", next_host, ip_value);
        if (additional_emitted) {
            *additional_emitted = 1;
        }
    } else {
        snprintf(hdr, sizeof(hdr), "\n=== Redirected query to %s @ %s ===\n", next_host, ip_value);
    }
    *combined = wc_lookup_exec_append_and_free(*combined, hdr);
    return 0;
}

int wc_lookup_exec_update_redirect_header_ip(char** combined,
                                             const char* host,
                                             const char* ip)
{
    if (!combined || !*combined || !host || !host[0] || !ip || !ip[0]) {
        return 0;
    }

    const char* add_prefix = "=== Additional query to ";
    const char* redir_prefix = "=== Redirected query to ";
    const char* unknown_tail = " @ unknown ===";

    char* text = *combined;
    char* cursor = text;
    char* match_start = NULL;
    char* match_end = NULL;
    int match_is_additional = 0;

    while (cursor && *cursor) {
        char* line_start = cursor;
        char* line_end = strchr(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start + 1) : strlen(line_start);

        const char* prefix = NULL;
        int is_additional = 0;
        if (strncmp(line_start, add_prefix, strlen(add_prefix)) == 0) {
            prefix = add_prefix;
            is_additional = 1;
        } else if (strncmp(line_start, redir_prefix, strlen(redir_prefix)) == 0) {
            prefix = redir_prefix;
            is_additional = 0;
        }

        if (prefix) {
            const char* host_start = line_start + strlen(prefix);
            const char* host_end = strstr(host_start, " @ ");
            if (host_end) {
                size_t host_len = (size_t)(host_end - host_start);
                if (host_len == strlen(host) && strncasecmp(host_start, host, host_len) == 0) {
                    const char* tail = host_end;
                    size_t tail_need = strlen(unknown_tail);
                    if ((size_t)(line_start + line_len - tail) >= tail_need &&
                        strncmp(tail, unknown_tail, tail_need) == 0) {
                        match_start = line_start;
                        match_end = line_start + line_len;
                        match_is_additional = is_additional;
                    }
                }
            }
        }

        if (!line_end) {
            break;
        }
        cursor = line_end + 1;
    }

    if (!match_start || !match_end) {
        return 0;
    }

    char new_line[320];
    if (match_is_additional) {
        snprintf(new_line, sizeof(new_line), "=== Additional query to %s @ %s ===\n", host, ip);
    } else {
        snprintf(new_line, sizeof(new_line), "=== Redirected query to %s @ %s ===\n", host, ip);
    }

    size_t old_len = (size_t)(match_end - match_start);
    size_t new_len = strlen(new_line);
    size_t full_len = strlen(text);
    size_t prefix_len = (size_t)(match_start - text);
    size_t suffix_len = full_len - prefix_len - old_len;

    char* rebuilt = (char*)malloc(prefix_len + new_len + suffix_len + 1);
    if (!rebuilt) {
        return 0;
    }

    memcpy(rebuilt, text, prefix_len);
    memcpy(rebuilt + prefix_len, new_line, new_len);
    memcpy(rebuilt + prefix_len + new_len, match_end, suffix_len);
    rebuilt[prefix_len + new_len + suffix_len] = '\0';

    free(*combined);
    *combined = rebuilt;
    return 1;
}
