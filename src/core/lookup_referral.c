// SPDX-License-Identifier: MIT
// lookup_referral.c - Referral parsing and host helpers

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

#include "wc/wc_dns.h"
#include "wc/wc_known_ips.h"
#include "lookup_internal.h"

const char* wc_lookup_known_ip_host_from_literal(const char* ip_literal) {
    if (!ip_literal || !*ip_literal) return NULL;
    for (size_t i = 0; i < wc_known_ip_count(); ++i) {
        if (strcasecmp(ip_literal, k_wc_known_ips[i].ip) == 0) {
            return k_wc_known_ips[i].host;
        }
    }
    return NULL;
}

void wc_lookup_normalize_host_token(const char* in, char* out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!in || !*in) return;
    while (*in && isspace((unsigned char)*in)) in++;
    size_t len = strlen(in);
    while (len > 0 && isspace((unsigned char)in[len - 1])) len--;
    if (len == 0) return;
    if (len >= out_len) len = out_len - 1;
    memcpy(out, in, len);
    out[len] = '\0';
    while (len > 0 && out[len - 1] == '.') {
        out[len - 1] = '\0';
        len--;
    }
    if (len == 0) return;
    if (out[0] == '[') {
        char* rb = strchr(out, ']');
        if (rb) {
            *rb = '\0';
            memmove(out, out + 1, strlen(out + 1) + 1);
        }
        return;
    }
    int colon_count = 0;
    for (size_t i = 0; i < len; ++i) {
        if (out[i] == ':') colon_count++;
    }
    if (colon_count == 1) {
        char* colon = strchr(out, ':');
        if (colon) *colon = '\0';
    }
}

int wc_lookup_host_tokens_equal(const char* a, const char* b) {
    if (!a || !b) return 0;
    char na[192];
    char nb[192];
    wc_lookup_normalize_host_token(a, na, sizeof(na));
    wc_lookup_normalize_host_token(b, nb, sizeof(nb));
    if (!na[0] || !nb[0]) return 0;
    return strcasecmp(na, nb) == 0;
}

int wc_lookup_ip_matches_host(const char* ip_literal, const char* host) {
    if (!ip_literal || !host || !*ip_literal || !*host) return 0;
    const char* mapped = wc_lookup_known_ip_host_from_literal(ip_literal);
    if (!mapped) return 0;
    return wc_lookup_host_tokens_equal(mapped, host);
}

int wc_lookup_referral_is_explicit(const char* body, const char* ref_host) {
    if (!body || !*body || !ref_host || !*ref_host) return 0;
    char norm_ref[192];
    wc_lookup_normalize_host_token(ref_host, norm_ref, sizeof(norm_ref));
    if (!norm_ref[0]) return 0;
    const char* line = body;
    while (*line) {
        const char* line_end = line;
        while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;
        size_t len = (size_t)(line_end - line);
        while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
        const char* trimmed = line;
        size_t tlen = len;
        while (tlen > 0 && (*trimmed == ' ' || *trimmed == '\t')) { trimmed++; tlen--; }
        if (tlen > 0) {
            const char* prefixes[] = {"ReferralServer:", "refer:", "whois:", "ResourceLink:", NULL};
            for (int i = 0; prefixes[i]; ++i) {
                size_t plen = strlen(prefixes[i]);
                if (tlen >= plen && strncasecmp(trimmed, prefixes[i], plen) == 0) {
                    const char* pos = trimmed + plen;
                    while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
                    if (*pos) {
                        const char* end = pos;
                        while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
                        size_t hlen = (size_t)(end - pos);
                        if (hlen > 0) {
                            char host_buf[192];
                            if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
                            memcpy(host_buf, pos, hlen);
                            host_buf[hlen] = '\0';
                            if (strncmp(host_buf, "whois://", 8) == 0) {
                                memmove(host_buf, host_buf + 8, strlen(host_buf + 8) + 1);
                            } else if (strncmp(host_buf, "rwhois://", 9) == 0) {
                                memmove(host_buf, host_buf + 9, strlen(host_buf + 9) + 1);
                            } else if (strncmp(host_buf, "http://", 7) == 0) {
                                memmove(host_buf, host_buf + 7, strlen(host_buf + 7) + 1);
                            } else if (strncmp(host_buf, "https://", 8) == 0) {
                                memmove(host_buf, host_buf + 8, strlen(host_buf + 8) + 1);
                            }
                            char* slash = strchr(host_buf, '/');
                            if (slash) *slash = '\0';
                            if (wc_lookup_host_tokens_equal(host_buf, norm_ref)) return 1;
                        }
                    }
                }
            }
        }
        if (*line_end == '\r' && line_end[1] == '\n') line = line_end + 2;
        else if (*line_end) line = line_end + 1;
        else line = line_end;
    }
    return 0;
}

char* wc_lookup_extract_referral_fallback(const char* body) {
    if (!body || !*body) return NULL;
    const char* pos = wc_lookup_find_case_insensitive(body, "ReferralServer:");
    if (pos) {
        pos += strlen("ReferralServer:");
    }
    if (pos) {
        while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
        if (*pos) {
            const char* end = pos;
            while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
            size_t len = (size_t)(end - pos);
            if (len > 0) {
                char* out = (char*)malloc(len + 1);
                if (!out) return NULL;
                strncpy(out, pos, len);
                out[len] = '\0';
                if (strncmp(out, "whois://", 8) == 0) {
                    memmove(out, out + 8, strlen(out + 8) + 1);
                } else if (strncmp(out, "rwhois://", 9) == 0) {
                    memmove(out, out + 9, strlen(out + 9) + 1);
                }
                return out;
            }
        }
    }
    pos = wc_lookup_find_case_insensitive(body, "ResourceLink:");
    if (pos) {
        const char* whois_pos = wc_lookup_find_case_insensitive(pos, "whois://");
        if (whois_pos) {
            whois_pos += strlen("whois://");
            const char* end = whois_pos;
            while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
            size_t len = (size_t)(end - whois_pos);
            if (len > 0) {
                char* out = (char*)malloc(len + 1);
                if (!out) return NULL;
                strncpy(out, whois_pos, len);
                out[len] = '\0';
                return out;
            }
        }
    }
    return NULL;
}

int wc_lookup_visited_has(char** visited, int visited_count, const char* host) {
    if (!host || !*host) return 0;
    char norm_host[192];
    wc_lookup_normalize_host_token(host, norm_host, sizeof(norm_host));
    if (!norm_host[0]) return 0;
    for (int i = 0; i < visited_count; ++i) {
        const char* v = visited[i];
        if (!v || !*v) continue;
        char norm_v[192];
        wc_lookup_normalize_host_token(v, norm_v, sizeof(norm_v));
        if (!norm_v[0]) continue;
        if (strcasecmp(norm_v, norm_host) == 0) return 1;
    }
    return 0;
}

void wc_lookup_visited_remove(char** visited, int* visited_count, const char* host) {
    if (!visited || !visited_count || *visited_count <= 0 || !host || !*host) return;
    int count = *visited_count;
    int w = 0;
    for (int i = 0; i < count; ++i) {
        const char* v = visited[i];
        if (v && *v && wc_lookup_hosts_match(v, host)) {
            free(visited[i]);
            visited[i] = NULL;
            continue;
        }
        if (w != i) {
            visited[w] = visited[i];
            visited[i] = NULL;
        }
        ++w;
    }
    *visited_count = w;
}

int wc_lookup_parse_referral_target(const char* ref, char* host, size_t cap, int* out_port) {
    if (!ref || !host || cap == 0) return -1;
    const char* p = ref;
    while (*p == ' ' || *p == '\t') p++;
    const char* end = p + strlen(p);
    while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n' || end[-1] == '.' || end[-1] == ',')) {
        end--;
    }
    if (end <= p) return -1;
    if ((size_t)(end - p) >= 9 && strncasecmp(p, "rwhois://", 9) == 0) {
        p += 9;
    } else if ((size_t)(end - p) >= 8 && strncasecmp(p, "whois://", 8) == 0) {
        p += 8;
    }
    const char* slash = memchr(p, '/', (size_t)(end - p));
    if (slash) end = slash;
    while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n' || end[-1] == '.' || end[-1] == ',')) {
        end--;
    }
    if (end <= p) return -1;

    const char* host_start = p;
    const char* host_end = end;
    int port = 0;

    if (*host_start == '[') {
        const char* rb = memchr(host_start, ']', (size_t)(end - host_start));
        if (!rb) return -1;
        host_start++;
        host_end = rb;
        if (rb + 1 < end && rb[1] == ':') {
            const char* ps = rb + 2;
            if (ps < end) {
                int v = 0;
                for (const char* c = ps; c < end; ++c) {
                    if (!isdigit((unsigned char)*c)) { v = 0; break; }
                    v = v * 10 + (*c - '0');
                    if (v > 65535) { v = 0; break; }
                }
                if (v > 0) port = v;
            }
        }
    } else {
        const char* first_colon = memchr(host_start, ':', (size_t)(end - host_start));
        const char* last_colon = NULL;
        for (const char* c = host_start; c < end; ++c) {
            if (*c == ':') last_colon = c;
        }
        if (first_colon && last_colon && first_colon == last_colon) {
            const char* ps = last_colon + 1;
            if (ps < end) {
                int v = 0;
                int ok = 1;
                for (const char* c = ps; c < end; ++c) {
                    if (!isdigit((unsigned char)*c)) { ok = 0; break; }
                    v = v * 10 + (*c - '0');
                    if (v > 65535) { ok = 0; break; }
                }
                if (ok && v > 0) {
                    port = v;
                    host_end = last_colon;
                }
            }
        }
    }

    size_t hlen = (size_t)(host_end - host_start);
    if (hlen == 0 || hlen + 1 > cap || hlen >= 192) return -1;
    char norm_host[192];
    memcpy(norm_host, host_start, hlen);
    norm_host[hlen] = '\0';
    wc_lookup_normalize_host_token(norm_host, norm_host, sizeof(norm_host));
    if (!norm_host[0] || strchr(norm_host, '.') == NULL || strlen(norm_host) < 4)
        return -1;
    memcpy(host, host_start, hlen);
    host[hlen] = '\0';
    if (out_port) *out_port = port;
    return 0;
}

int wc_lookup_hosts_match(const char* a, const char* b) {
    if (!a || !*a || !b || !*b) return 0;
    if (wc_dns_is_ip_literal(a) && wc_lookup_ip_matches_host(a, b)) return 1;
    if (wc_dns_is_ip_literal(b) && wc_lookup_ip_matches_host(b, a)) return 1;
    char norm_a[192];
    char norm_b[192];
    const char* canon_a = wc_dns_canonical_alias(a);
    const char* canon_b = wc_dns_canonical_alias(b);
    if (!canon_a) canon_a = a;
    if (!canon_b) canon_b = b;
    wc_lookup_normalize_host_token(canon_a, norm_a, sizeof(norm_a));
    wc_lookup_normalize_host_token(canon_b, norm_b, sizeof(norm_b));
    if (!norm_a[0] || !norm_b[0]) return 0;
    return strcasecmp(norm_a, norm_b) == 0;
}
