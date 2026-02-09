// SPDX-License-Identifier: MIT
// lookup_output.c - Hop header and body slicing helpers

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

#include "lookup_internal.h"

static char* wc_lookup_append_text(char* base, const char* extra) {
    size_t la = base ? strlen(base) : 0;
    size_t lb = extra ? strlen(extra) : 0;
    char* n = (char*)malloc(la + lb + 1);
    if (!n) return base;
    if (base) memcpy(n, base, la);
    if (extra) memcpy(n + la, extra, lb);
    n[la + lb] = '\0';
    if (base) free(base);
    return n;
}

int wc_lookup_header_matches_host(const char* line, const char* host) {
    if (!line || !host || !*host) return 0;
    const char* p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    const char* prefix_add = "=== Additional query to ";
    const char* prefix_redir = "=== Redirected query to ";
    const char* prefix = NULL;
    if (strncmp(p, prefix_add, strlen(prefix_add)) == 0) {
        prefix = prefix_add;
    } else if (strncmp(p, prefix_redir, strlen(prefix_redir)) == 0) {
        prefix = prefix_redir;
    }
    if (!prefix) return 0;
    const char* host_start = p + strlen(prefix);
    const char* host_end = strstr(host_start, " ===");
    size_t host_len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);
    if (host_len == 0) return 0;
    char host_buf[192];
    if (host_len >= sizeof(host_buf)) host_len = sizeof(host_buf) - 1;
    memcpy(host_buf, host_start, host_len);
    host_buf[host_len] = '\0';
    char norm_line[192];
    char norm_host[192];
    wc_lookup_normalize_host_token(host_buf, norm_line, sizeof(norm_line));
    wc_lookup_normalize_host_token(host, norm_host, sizeof(norm_host));
    if (norm_line[0] == '\0' || norm_host[0] == '\0') return 0;
    return strcasecmp(norm_line, norm_host) == 0;
}

int wc_lookup_is_hop_header_line(const char* line) {
    if (!line) return 0;
    const char* p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncmp(p, "===", 3) != 0) return 0;
    return (strstr(p, "Additional query to ") != NULL ||
            strstr(p, "Redirected query to ") != NULL);
}

void wc_lookup_compact_hop_headers(char* combined) {
    if (!combined) return;
    char* r = combined;
    char* w = combined;
    while (*r) {
        char* line_start = r;
        char* line_end = strchr(r, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start + 1) : strlen(line_start);
        size_t trim_len = line_len;
        while (trim_len > 0 && (line_start[trim_len - 1] == '\n' || line_start[trim_len - 1] == '\r')) {
            --trim_len;
        }
        size_t leading_ws = 0;
        while (leading_ws < trim_len && (line_start[leading_ws] == ' ' || line_start[leading_ws] == '\t')) {
            ++leading_ws;
        }
        int is_blank = (trim_len == leading_ws);
        if (is_blank) {
            char* look = line_end ? line_end + 1 : line_start + line_len;
            while (*look) {
                char* lstart = look;
                char* lend = strchr(look, '\n');
                size_t llen = lend ? (size_t)(lend - lstart + 1) : strlen(lstart);
                size_t tlen = llen;
                while (tlen > 0 && (lstart[tlen - 1] == '\n' || lstart[tlen - 1] == '\r')) {
                    --tlen;
                }
                size_t lws = 0;
                while (lws < tlen && (lstart[lws] == ' ' || lstart[lws] == '\t')) {
                    ++lws;
                }
                if (tlen == lws) {
                    look = lend ? lend + 1 : lstart + llen;
                    continue;
                }
                if (wc_lookup_is_hop_header_line(lstart + lws)) {
                    line_start = NULL;
                }
                break;
            }
            if (!line_start) {
                r = line_end ? line_end + 1 : line_start + line_len;
                continue;
            }
        }

        memmove(w, line_start, line_len);
        w += line_len;
        r = line_end ? line_end + 1 : line_start + line_len;
    }
    *w = '\0';
}

int wc_lookup_extract_hop_host_from_line(const char* line, char* out, size_t out_len) {
    if (!line || !out || out_len == 0) return 0;
    const char* p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncmp(p, "=== Query:", 10) == 0) {
        const char* via = strstr(p, " via ");
        if (!via) return 0;
        via += 5;
        while (*via == ' ' || *via == '\t') via++;
        const char* end = strstr(via, " @");
        if (!end) {
            end = strstr(via, " ===");
        }
        size_t len = end ? (size_t)(end - via) : strlen(via);
        if (len == 0) return 0;
        if (len >= out_len) len = out_len - 1;
        memcpy(out, via, len);
        out[len] = '\0';
        return 1;
    }
    const char* prefix_add = "=== Additional query to ";
    const char* prefix_redir = "=== Redirected query to ";
    const char* prefix = NULL;
    if (strncmp(p, prefix_add, strlen(prefix_add)) == 0) prefix = prefix_add;
    else if (strncmp(p, prefix_redir, strlen(prefix_redir)) == 0) prefix = prefix_redir;
    if (!prefix) return 0;
    const char* host_start = p + strlen(prefix);
    const char* host_end = strstr(host_start, " ===");
    size_t host_len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);
    if (host_len == 0) return 0;
    if (host_len >= out_len) host_len = out_len - 1;
    memcpy(out, host_start, host_len);
    out[host_len] = '\0';
    return 1;
}

void wc_lookup_strip_bodies_after_authoritative_hop(char* combined,
                                                    const char* start_host,
                                                    const char* authoritative_host) {
    if (!combined || !authoritative_host || !*authoritative_host) return;
    if (strcasecmp(authoritative_host, "unknown") == 0) return;
    char* r = combined;
    char* w = combined;
    int in_hop = 0;
    int current_is_auth = wc_lookup_hosts_match(start_host, authoritative_host);
    int seen_auth = current_is_auth ? 1 : 0;
    while (*r) {
        char* line_start = r;
        char* line_end = strchr(r, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start + 1) : strlen(line_start);
        size_t trim_len = line_len;
        while (trim_len > 0 && (line_start[trim_len - 1] == '\n' || line_start[trim_len - 1] == '\r')) {
            --trim_len;
        }
        size_t leading_ws = 0;
        while (leading_ws < trim_len && (line_start[leading_ws] == ' ' || line_start[leading_ws] == '\t')) {
            ++leading_ws;
        }
        int is_author_line = wc_lookup_line_starts_with_case_insensitive_n(
            line_start + leading_ws, trim_len - leading_ws, "=== Authoritative RIR:");
        if (is_author_line) {
            memmove(w, line_start, line_len);
            w += line_len;
            seen_auth = 1;
            r = line_end ? line_end + 1 : line_start + line_len;
            continue;
        }

        char header_host[192];
        header_host[0] = '\0';
        int is_header = wc_lookup_extract_hop_host_from_line(line_start + leading_ws, header_host, sizeof(header_host));
        if (is_header) {
            current_is_auth = wc_lookup_hosts_match(header_host, authoritative_host);
            if (current_is_auth) {
                seen_auth = 1;
            }
            in_hop = 1;
            memmove(w, line_start, line_len);
            w += line_len;
            r = line_end ? line_end + 1 : line_start + line_len;
            continue;
        }

        if (!in_hop && trim_len > leading_ws) {
            in_hop = 1;
            current_is_auth = wc_lookup_hosts_match(start_host, authoritative_host);
            if (current_is_auth) {
                seen_auth = 1;
            }
        }

        if (!seen_auth || current_is_auth) {
            memmove(w, line_start, line_len);
            w += line_len;
        }
        r = line_end ? line_end + 1 : line_start + line_len;
    }
    *w = '\0';
}

void wc_lookup_strip_bodies_before_authoritative_hop(char* combined,
                                                     const char* start_host,
                                                     const char* authoritative_host) {
    if (!combined || !authoritative_host || !*authoritative_host) return;
    if (strcasecmp(authoritative_host, "unknown") == 0) return;
    char* r = combined;
    char* w = combined;
    int in_hop = 0;
    int current_is_auth = wc_lookup_hosts_match(start_host, authoritative_host);
    int seen_auth = current_is_auth ? 1 : 0;
    while (*r) {
        char* line_start = r;
        char* line_end = strchr(r, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start + 1) : strlen(line_start);
        size_t trim_len = line_len;
        while (trim_len > 0 && (line_start[trim_len - 1] == '\n' || line_start[trim_len - 1] == '\r')) {
            --trim_len;
        }
        size_t leading_ws = 0;
        while (leading_ws < trim_len && (line_start[leading_ws] == ' ' || line_start[leading_ws] == '\t')) {
            ++leading_ws;
        }
        int is_author_line = wc_lookup_line_starts_with_case_insensitive_n(
            line_start + leading_ws, trim_len - leading_ws, "=== Authoritative RIR:");
        if (is_author_line) {
            memmove(w, line_start, line_len);
            w += line_len;
            r = line_end ? line_end + 1 : line_start + line_len;
            continue;
        }

        char header_host[192];
        header_host[0] = '\0';
        int is_header = wc_lookup_extract_hop_host_from_line(line_start + leading_ws, header_host, sizeof(header_host));
        if (is_header) {
            current_is_auth = wc_lookup_hosts_match(header_host, authoritative_host);
            if (current_is_auth) {
                seen_auth = 1;
            }
            in_hop = 1;
            memmove(w, line_start, line_len);
            w += line_len;
            r = line_end ? line_end + 1 : line_start + line_len;
            continue;
        }

        if (!in_hop && trim_len > leading_ws) {
            in_hop = 1;
            current_is_auth = wc_lookup_hosts_match(start_host, authoritative_host);
            if (current_is_auth) {
                seen_auth = 1;
            }
        }

        if (seen_auth || current_is_auth) {
            memmove(w, line_start, line_len);
            w += line_len;
        }
        r = line_end ? line_end + 1 : line_start + line_len;
    }
    *w = '\0';
}

int wc_lookup_has_hop_header(const char* combined, const char* host) {
    if (!combined || !host || !*host) return 0;
    const char* p = combined;
    while (p && *p) {
        const char* line_start = p;
        const char* line_end = strchr(p, '\n');
        if (wc_lookup_header_matches_host(line_start, host)) return 1;
        if (!line_end) break;
        p = line_end + 1;
    }
    return 0;
}

char* wc_lookup_insert_header_before_authoritative(char* combined, const char* host) {
    if (!combined || !host || !*host) return combined;
    const char* auth_token = "=== Authoritative RIR:";
    char* auth_pos = strstr(combined, auth_token);
    char header[192];
    snprintf(header, sizeof(header), "=== Redirected query to %s ===\n", host);
    if (!auth_pos) {
        char* out = wc_lookup_append_text(combined, "\n");
        return wc_lookup_append_text(out, header);
    }
    size_t prefix_len = (size_t)(auth_pos - combined);
    size_t header_len = strlen(header);
    size_t combined_len = strlen(combined);
    size_t new_len = combined_len + header_len + 1;
    char* out = (char*)malloc(new_len);
    if (!out) return combined;
    memcpy(out, combined, prefix_len);
    memcpy(out + prefix_len, header, header_len);
    memcpy(out + prefix_len + header_len, combined + prefix_len, combined_len - prefix_len + 1);
    free(combined);
    return out;
}
