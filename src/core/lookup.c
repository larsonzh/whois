// SPDX-License-Identifier: MIT
// lookup.c - Phase B skeleton implementation
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "wc/wc_config.h"
#include "wc/wc_runtime.h"
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"
#include "wc/wc_selftest.h"
#include "wc/wc_dns.h"
#include "wc/wc_ip_pref.h"
#include "wc/wc_known_ips.h"
#include "wc/wc_util.h"
#include "wc/wc_signal.h"

static const Config* wc_lookup_resolve_config(const struct wc_lookup_opts* opts)
{
    if (!opts)
        return NULL;
    return opts->config;
}

static int wc_lookup_should_trace_dns(const wc_net_context_t* net_ctx, const Config* cfg) {
    if (cfg && cfg->debug) return 1;
    return wc_net_context_retry_metrics_enabled(net_ctx);
}

static const char* wc_lookup_origin_label(wc_dns_origin_t origin) {
    switch (origin) {
        case WC_DNS_ORIGIN_INPUT: return "input";
        case WC_DNS_ORIGIN_SELFTEST: return "selftest";
        case WC_DNS_ORIGIN_CACHE: return "cache";
        case WC_DNS_ORIGIN_RESOLVER: return "resolver";
        case WC_DNS_ORIGIN_KNOWN: return "known";
        default: break;
    }
    return "unknown";
}

static const char* wc_lookup_family_label(unsigned char fam, const char* token) {
    switch (fam) {
        case WC_DNS_FAMILY_IPV4: return "ipv4";
        case WC_DNS_FAMILY_IPV6: return "ipv6";
        case WC_DNS_FAMILY_HOST: return "host";
        default:
            if (token && wc_dns_is_ip_literal(token)) {
                return (strchr(token, ':') != NULL) ? "ipv6" : "ipv4";
            }
            return "host";
    }
}

static int wc_lookup_family_to_af(unsigned char fam, const char* token) {
    switch (fam) {
        case WC_DNS_FAMILY_IPV4: return AF_INET;
        case WC_DNS_FAMILY_IPV6: return AF_INET6;
        default:
            break;
    }
    if (token && wc_dns_is_ip_literal(token)) {
        return (strchr(token, ':') != NULL) ? AF_INET6 : AF_INET;
    }
    return AF_UNSPEC;
}

static int wc_lookup_effective_family(int family_hint, const char* token) {
    if (family_hint == AF_INET || family_hint == AF_INET6) {
        return family_hint;
    }
    if (token && wc_dns_is_ip_literal(token)) {
        return (strchr(token, ':') != NULL) ? AF_INET6 : AF_INET;
    }
    return AF_UNSPEC;
}

static void wc_lookup_record_backoff_result(const Config* cfg,
                                            const char* token,
                                            int family_hint,
                                            int success) {
    if (!token || !*token) {
        return;
    }
    int effective_family = wc_lookup_effective_family(family_hint, token);
    if (success) {
        wc_dns_note_success(cfg, token, effective_family);
    } else {
        wc_dns_note_failure(cfg, token, effective_family);
    }
}

static void wc_lookup_compute_canonical_host(const char* current_host,
                                             const char* rir,
                                             char* out,
                                             size_t out_len) {
    if (!out || out_len == 0) return;
    const char* fallback = "whois.iana.org";
    if (current_host && !wc_dns_is_ip_literal(current_host)) {
        snprintf(out, out_len, "%s", current_host);
        return;
    }
    const char* canon = wc_dns_canonical_host_for_rir(rir);
    if (canon) {
        snprintf(out, out_len, "%s", canon);
    } else if (current_host && *current_host) {
        snprintf(out, out_len, "%s", current_host);
    } else {
        snprintf(out, out_len, "%s", fallback);
    }
}

static const char* wc_lookup_skip_leading_space(const char* text) {
    if (!text) return "";
    while (*text && isspace((unsigned char)*text)) {
        ++text;
    }
    return text;
}

static int wc_lookup_query_has_arin_prefix(const char* query) {
    const char* p = wc_lookup_skip_leading_space(query);
    if (!p || !*p) return 0;
    /*
     * Simplified rule: ARIN flag prefixes may evolve. If the query already
     * contains a space, treat it as user-supplied flags (e.g., "n + =", "a",
     * or future combos) and skip automatic prefix injection to avoid dupes.
     */
    return strchr(p, ' ') != NULL;
}

char* wc_lookup_strip_query_prefix(const char* query)
{
    const char* p = wc_lookup_skip_leading_space(query);
    if (!p || !*p)
        return NULL;
    const char* last_space = strrchr(p, ' ');
    if (!last_space)
        return NULL;
    const char* start = last_space + 1;
    while (*start == ' ' || *start == '\t')
        ++start;
    if (!*start)
        return NULL;
    size_t len = strlen(start);
    char* out = (char*)malloc(len + 1);
    if (!out)
        return NULL;
    memcpy(out, start, len + 1);
    return out;
}

static int wc_lookup_body_contains_no_match(const char* body) {
    if (!body || !*body) return 0;
    const char* needle = "no match found for";
    size_t nlen = strlen(needle);
        for (const char* p = body; *p; ++p) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == needle[i]) {
            ++i;
        }
        if (i == nlen) return 1;
        if (!p[i]) break;
    }
    return 0;
}

static const char* wc_lookup_find_case_insensitive(const char* haystack, const char* needle) {
    if (!haystack || !needle || *needle == '\0') return NULL;
    size_t needle_len = strlen(needle);
    for (const char* hp = haystack; *hp; hp++) {
        size_t idx = 0;
        while (hp[idx] && idx < needle_len &&
               tolower((unsigned char)hp[idx]) == tolower((unsigned char)needle[idx])) {
            idx++;
        }
        if (idx == needle_len) return hp;
        if (!hp[idx]) break;
    }
    return NULL;
}

static char* append_and_free(char* base, const char* extra);

static const char* wc_lookup_known_ip_host_from_literal(const char* ip_literal) {
    if (!ip_literal || !*ip_literal) return NULL;
    for (size_t i = 0; i < wc_known_ip_count(); ++i) {
        if (strcasecmp(ip_literal, k_wc_known_ips[i].ip) == 0) {
            return k_wc_known_ips[i].host;
        }
    }
    return NULL;
}

static void wc_lookup_normalize_host_token(const char* in, char* out, size_t out_len) {
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

static int wc_lookup_host_tokens_equal(const char* a, const char* b) {
    if (!a || !b) return 0;
    char na[192];
    char nb[192];
    wc_lookup_normalize_host_token(a, na, sizeof(na));
    wc_lookup_normalize_host_token(b, nb, sizeof(nb));
    if (!na[0] || !nb[0]) return 0;
    return strcasecmp(na, nb) == 0;
}

static int wc_lookup_ip_matches_host(const char* ip_literal, const char* host) {
    if (!ip_literal || !host || !*ip_literal || !*host) return 0;
    const char* mapped = wc_lookup_known_ip_host_from_literal(ip_literal);
    if (!mapped) return 0;
    return wc_lookup_host_tokens_equal(mapped, host);
}

static int wc_lookup_referral_is_explicit(const char* body, const char* ref_host) {
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
            const char* prefixes[] = {"ReferralServer:", "refer:", "whois:", NULL};
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
                            }
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

static int wc_lookup_header_matches_host(const char* line, const char* host) {
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

static int wc_lookup_is_hop_header_line(const char* line) {
    if (!line) return 0;
    const char* p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncmp(p, "===", 3) != 0) return 0;
    return (strstr(p, "Additional query to ") != NULL ||
            strstr(p, "Redirected query to ") != NULL);
}

static void wc_lookup_compact_hop_headers(char* combined) {
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
            // look ahead for next non-empty line
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
                    // skip this blank line right before a hop header
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

static void wc_lookup_strip_hop_body_keep_header(char* combined, const char* host) {
    if (!combined || !host || !*host) return;
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
        int is_target_header = wc_lookup_header_matches_host(line_start + leading_ws, host);

        if (is_target_header) {
            memmove(w, line_start, line_len);
            w += line_len;
            r = line_end ? line_end + 1 : line_start + line_len;
            while (*r) {
                size_t ws = 0;
                while (r[ws] == ' ' || r[ws] == '\t') {
                    ++ws;
                }
                if (strncmp(r + ws, "===", 3) == 0) {
                    break;
                }
                char* skip_end = strchr(r, '\n');
                if (!skip_end) {
                    r += strlen(r);
                    break;
                }
                r = skip_end + 1;
            }
            continue;
        }

        memmove(w, line_start, line_len);
        w += line_len;
        r = line_end ? line_end + 1 : line_start + line_len;
    }
    *w = '\0';
}

static int wc_lookup_has_hop_header(const char* combined, const char* host) {
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

static char* wc_lookup_insert_header_before_authoritative(char* combined, const char* host) {
    if (!combined || !host || !*host) return combined;
    const char* auth_token = "=== Authoritative RIR:";
    char* auth_pos = strstr(combined, auth_token);
    char header[192];
    snprintf(header, sizeof(header), "=== Redirected query to %s ===\n", host);
    if (!auth_pos) {
        char* out = append_and_free(combined, "\n");
        return append_and_free(out, header);
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

static int wc_lookup_visited_has(char** visited, int visited_count, const char* host) {
    if (!host || !*host) return 0;
    char norm_host[192];
    wc_lookup_normalize_host_token(host, norm_host, sizeof(norm_host));
    for (int i = 0; i < visited_count; ++i) {
        const char* v = visited[i];
        if (!v) continue;
        char norm_v[192];
        wc_lookup_normalize_host_token(v, norm_v, sizeof(norm_v));
        if (norm_v[0] && norm_host[0] && strcasecmp(norm_v, norm_host) == 0) return 1;
        const char* alias = wc_dns_canonical_alias(v);
        if (alias) {
            char norm_alias[192];
            wc_lookup_normalize_host_token(alias, norm_alias, sizeof(norm_alias));
            if (norm_alias[0] && norm_host[0] && strcasecmp(norm_alias, norm_host) == 0) return 1;
        }
        if (wc_dns_is_ip_literal(v)) {
            const char* mapped = wc_lookup_known_ip_host_from_literal(v);
            if (mapped) {
                char norm_mapped[192];
                wc_lookup_normalize_host_token(mapped, norm_mapped, sizeof(norm_mapped));
                if (norm_mapped[0] && norm_host[0] && strcasecmp(norm_mapped, norm_host) == 0) return 1;
            }
        }
    }
    return 0;
}

static int wc_lookup_starts_with_case_insensitive(const char* str, const char* prefix) {
    if (!str || !prefix) return 0;
    while (*prefix && *str) {
        if (tolower((unsigned char)*str) != tolower((unsigned char)*prefix)) return 0;
        ++str;
        ++prefix;
    }
    return *prefix == '\0';
}

static char* wc_lookup_extract_referral_fallback(const char* body) {
    if (!body || !*body) return NULL;
    const char* pos = wc_lookup_find_case_insensitive(body, "ReferralServer:");
    if (pos) {
        pos += strlen("ReferralServer:");
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

static int wc_lookup_parse_referral_target(const char* ref, char* host, size_t cap, int* out_port) {
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
    if (hlen == 0 || hlen + 1 > cap) return -1;
    memcpy(host, host_start, hlen);
    host[hlen] = '\0';
    if (out_port) *out_port = port;
    return 0;
}

static int wc_lookup_body_contains_apnic_erx_hint(const char* body) {
    if (!body || !*body) return 0;
    const char* needles[] = {
        "apnic-ap-erx",
        "transferred from arin to apnic",
        "transfered from arin to apnic",
        "not registered in the arin database",
        NULL
    };
    for (int n = 0; needles[n]; ++n) { 
        const char* needle = needles[n];
        size_t nlen = strlen(needle);
        for (const char* p = body; *p; ++p) {
            size_t i = 0;
            while (i < nlen && p[i] && tolower((unsigned char)p[i]) == needle[i]) {
                ++i;
            }
            if (i == nlen) return 1;
            if (!p[i]) break;
        }
    }
    return 0;
}

static int wc_lookup_body_contains_apnic_erx_hint_strict(const char* body) {
    if (!body || !*body) return 0;
    const char* needles[] = {
        "apnic-ap-erx",
        "transferred from arin to apnic",
        "transfered from arin to apnic",
        "not registered in the arin database",
        NULL
    };
    for (int n = 0; needles[n]; ++n) {
        const char* needle = needles[n];
        size_t nlen = strlen(needle);
        for (const char* p = body; *p; ++p) {
            size_t i = 0;
            while (i < nlen && p[i] && tolower((unsigned char)p[i]) == needle[i]) {
                ++i;
            }
            if (i == nlen) return 1;
            if (!p[i]) break;
        }
    }
    return 0;
}

static int wc_lookup_body_contains_erx_legacy(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "early registration addresses")) return 1;
    if (wc_lookup_find_case_insensitive(body, "erx-netblock")) return 1;
    return 0;
}

static int wc_lookup_body_contains_apnic_transfer_to_apnic(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "transferred to apnic")) return 1;
    if (wc_lookup_find_case_insensitive(body, "apnic-erx")) return 1;
    if (wc_lookup_find_case_insensitive(body, "early registrations, transferred to apnic")) return 1;
    if (wc_lookup_find_case_insensitive(body, "nettype:") &&
        wc_lookup_find_case_insensitive(body, "early registrations") &&
        wc_lookup_find_case_insensitive(body, "apnic")) {
        return 1;
    }
    if (wc_lookup_find_case_insensitive(body, "netname:") &&
        wc_lookup_find_case_insensitive(body, "apnic") &&
        wc_lookup_find_case_insensitive(body, "orgid:") &&
        wc_lookup_find_case_insensitive(body, "apnic")) {
        return 1;
    }
    if (wc_lookup_find_case_insensitive(body, "orgid:") &&
        wc_lookup_find_case_insensitive(body, "apnic") &&
        wc_lookup_find_case_insensitive(body, "referralserver:") &&
        wc_lookup_find_case_insensitive(body, "whois://whois.apnic.net")) {
        return 1;
    }
    return 0;
}

static int wc_lookup_body_contains_erx_netname(const char* body) {
    if (!body || !*body) return 0;
    if (!wc_lookup_find_case_insensitive(body, "netname:")) return 0;
    if (wc_lookup_find_case_insensitive(body, "erx-netblock")) return 1;
    return 0;
}

static int wc_lookup_body_contains_lacnic_unallocated(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "Unallocated and unassigned in LACNIC block")) return 1;
    if (wc_lookup_find_case_insensitive(body, "whois.lacnic.net accepts only direct match queries")) return 1;
    return 0;
}

static int wc_lookup_line_contains_case_insensitive(const char* line, size_t len, const char* needle) {
    if (!line || !needle || !*needle || len == 0) return 0;
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > len) return 0;
    for (size_t i = 0; i + nlen <= len; ++i) {
        size_t j = 0;
        while (j < nlen && i + j < len &&
            tolower((unsigned char)line[i + j]) == tolower((unsigned char)needle[j])) {
            ++j;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int wc_lookup_line_starts_with_case_insensitive_n(const char* line, size_t len, const char* prefix) {
    if (!line || !prefix) return 0;
    size_t plen = strlen(prefix);
    if (plen == 0 || plen > len) return 0;
    for (size_t i = 0; i < plen; ++i) {
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)prefix[i])) return 0;
    }
    return 1;
}

static const char* wc_lookup_rir_header_from_line(const char* line, size_t len) {
    if (!line || len == 0) return NULL;
    if (wc_lookup_line_starts_with_case_insensitive_n(line, len, "% IANA WHOIS server"))
        return "whois.iana.org";
    if (wc_lookup_line_starts_with_case_insensitive_n(line, len, "% [whois.apnic.net]"))
        return "whois.apnic.net";
    if (wc_lookup_line_starts_with_case_insensitive_n(line, len, "% This is the RIPE Database query service."))
        return "whois.ripe.net";
    if (wc_lookup_line_starts_with_case_insensitive_n(line, len, "% This is the AfriNIC Whois server."))
        return "whois.afrinic.net";
    if (wc_lookup_line_starts_with_case_insensitive_n(line, len, "% IP Client:"))
        return "whois.lacnic.net";
    if (wc_lookup_line_contains_case_insensitive(line, len,
            "ARIN WHOIS data and services are subject to the Terms of Use"))
        return "whois.arin.net";
    return NULL;
}

static const char* wc_lookup_detect_rir_header_host(const char* body) {
    if (!body || !*body) return NULL;
    const int max_lines = 8;
    const char* line = body;
    const char* first = NULL;
    size_t first_len = 0;
    const char* second = NULL;
    size_t second_len = 0;
    int arin_hint = 0;
    int line_count = 0;

    while (*line && line_count < max_lines) {
        const char* line_end = line;
        while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;
        size_t len = (size_t)(line_end - line);
        const char* trimmed = line;
        size_t tlen = len;
        while (tlen > 0 && (*trimmed == ' ' || *trimmed == '\t')) { trimmed++; tlen--; }
        while (tlen > 0 && (trimmed[tlen - 1] == ' ' || trimmed[tlen - 1] == '\t')) { tlen--; }
        if (tlen > 0) {
            if (!first) { first = trimmed; first_len = tlen; }
            else if (!second) { second = trimmed; second_len = tlen; }
            if (wc_lookup_line_contains_case_insensitive(trimmed, tlen,
                    "ARIN WHOIS data and services are subject to the Terms of Use")) {
                arin_hint = 1;
            }
        }
        if (*line_end == '\r' && line_end[1] == '\n') line = line_end + 2;
        else if (*line_end) line = line_end + 1;
        else line = line_end;
        line_count++;
    }

    if (arin_hint)
        return "whois.arin.net";

    const char* first_host = wc_lookup_rir_header_from_line(first, first_len);
    if (first_host && strcasecmp(first_host, "whois.lacnic.net") == 0) {
        const char* second_host = wc_lookup_rir_header_from_line(second, second_len);
        if (second_host && strcasecmp(second_host, "whois.lacnic.net") != 0 &&
            strcasecmp(second_host, "whois.iana.org") != 0) {
            return second_host;
        }
    }
    if (first_host) return first_host;
    const char* second_host = wc_lookup_rir_header_from_line(second, second_len);
    if (second_host) return second_host;
    return NULL;
}

static int wc_lookup_body_contains_full_ipv4_space(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "IANA-BLK")) return 1;
    const char* hit = body;
    while ((hit = wc_lookup_find_case_insensitive(hit, "0.0.0.0 - 255.255.255.255")) != NULL) {
        const char* line_start = hit;
        while (line_start > body && line_start[-1] != '\n' && line_start[-1] != '\r') {
            --line_start;
        }
        while (*line_start == ' ' || *line_start == '\t') ++line_start;
        if (wc_lookup_starts_with_case_insensitive(line_start, "inetnum:") ||
            wc_lookup_starts_with_case_insensitive(line_start, "netrange:")) {
            return 1;
        }
        hit += 1;
    }
    return 0;
}

static int wc_lookup_body_contains_ipv6_root(const char* body) {
    if (!body || !*body) return 0;
    const char* hit = body;
    while ((hit = wc_lookup_find_case_insensitive(hit, "inet6num:")) != NULL) {
        const char* line_start = hit;
        while (line_start > body && line_start[-1] != '\n' && line_start[-1] != '\r') {
            --line_start;
        }
        while (*line_start == ' ' || *line_start == '\t') ++line_start;
        const char* line_end = line_start;
        while (*line_end && *line_end != '\n' && *line_end != '\r') ++line_end;
        if (wc_lookup_line_contains_case_insensitive(line_start, (size_t)(line_end - line_start), "::/0")) {
            if (wc_lookup_find_case_insensitive(body, "netname:") &&
                wc_lookup_find_case_insensitive(body, "root")) {
                return 1;
            }
            return 1;
        }
        hit = line_end;
    }
    return 0;
}

static int wc_lookup_rir_cycle_next(const char* current_rir,
                                    char** visited,
                                    int visited_count,
                                    char* out,
                                    size_t outlen) {
    (void)current_rir;
    static const char* k_rir_cycle[] = {
        "apnic", "arin", "ripe", "afrinic", "lacnic", NULL
    };
    if (!out || outlen == 0) return 0;
    int count = 0;
    for (; k_rir_cycle[count]; ++count) { /* count */ }
    if (count == 0) return 0;

    int start_idx = 0; // always start from APNIC

    for (int i = 0; i < count; ++i) {
        int idx = (start_idx + i) % count;
        const char* rir = k_rir_cycle[idx];
        const char* host = wc_dns_canonical_host_for_rir(rir);
        if (!host || !*host) continue;
        int seen = 0;
        for (int v = 0; v < visited_count; ++v) {
            if (visited[v] && strcasecmp(visited[v], host) == 0) {
                seen = 1;
                break;
            }
        }
        if (seen) continue;
        snprintf(out, outlen, "%s", host);
        return 1;
    }
    return 0;
}

static char* wc_lookup_extract_cidr_base(const char* query)
{
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed)
        return NULL;
    char* stripped = NULL;
    const char* core = trimmed;
    if (strchr(trimmed, ' ')) {
        stripped = wc_lookup_strip_query_prefix(trimmed);
        if (stripped && *stripped)
            core = stripped;
    }
    const char* slash = strchr(core, '/');
    if (!slash) {
        if (stripped) free(stripped);
        return NULL;
    }
    size_t len = (size_t)(slash - core);
    if (len == 0 || len >= 128) {
        if (stripped) free(stripped);
        return NULL;
    }
    char base[128];
    memcpy(base, core, len);
    base[len] = '\0';
    if (!wc_dns_is_ip_literal(base)) {
        if (stripped) free(stripped);
        return NULL;
    }
    char* out = (char*)malloc(len + 1);
    if (!out) {
        if (stripped) free(stripped);
        return NULL;
    }
    memcpy(out, base, len + 1);
    if (stripped) free(stripped);
    return out;
}

static int wc_lookup_query_is_ipv4_literal(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed) return 0;
    if (!wc_dns_is_ip_literal(trimmed)) return 0;
    return strchr(trimmed, ':') == NULL;
}

static int wc_lookup_query_is_ip_literal(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    return (trimmed && *trimmed && wc_dns_is_ip_literal(trimmed) && strchr(trimmed, '/') == NULL);
}

static int wc_lookup_query_is_cidr(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed) return 0;
    const char* slash = strchr(trimmed, '/');
    if (!slash) return 0;
    size_t base_len = (size_t)(slash - trimmed);
    if (base_len == 0 || base_len >= 128) return 0;
    char base[128];
    memcpy(base, trimmed, base_len);
    base[base_len] = '\0';
    if (!wc_dns_is_ip_literal(base)) return 0;
    const char* pfx = slash + 1;
    if (!*pfx) return 0;
    char* endp = NULL;
    long plen = strtol(pfx, &endp, 10);
    if (endp == pfx) return 0;
    while (endp && *endp && isspace((unsigned char)*endp)) ++endp;
    if (endp && *endp) return 0; // trailing junk
    int max_plen = (strchr(base, ':') != NULL) ? 128 : 32;
    if (plen < 0 || plen > max_plen) return 0;
    return 1;
}

static int wc_lookup_query_is_asn(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed) return 0;
    if (strncasecmp(trimmed, "AS", 2) != 0) return 0; // case-insensitive ASN prefix
    const char* p = trimmed + 2;
    if (!isdigit((unsigned char)*p)) return 0;
    while (*p && isdigit((unsigned char)*p)) ++p;
    while (*p && isspace((unsigned char)*p)) ++p;
    return *p == '\0';
}

static int wc_lookup_query_is_arin_nethandle(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed) return 0;
    if (strncasecmp(trimmed, "NET-", 4) != 0) return 0;
    trimmed += 4;
    if (!*trimmed) return 0;
    while (*trimmed && (isalnum((unsigned char)*trimmed) || *trimmed=='-' )) ++trimmed;
    while (*trimmed && isspace((unsigned char)*trimmed)) ++trimmed;
    return *trimmed == '\0';
}

static char* wc_lookup_build_arin_prefixed_query(const char* query, const char* prefix) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed || !prefix) return NULL;
    size_t trimmed_len = strlen(trimmed);
    size_t prefix_len = strlen(prefix);
    char* result = (char*)malloc(prefix_len + trimmed_len + 1);
    if (!result) return NULL;
    memcpy(result, prefix, prefix_len);
    memcpy(result + prefix_len, trimmed, trimmed_len);
    result[prefix_len + trimmed_len] = '\0';
    return result;
}

char* wc_lookup_arin_build_query(const char* query,
                                 int arin_host,
                                 int query_is_ip_literal,
                                 int query_is_cidr,
                                 int query_is_asn,
                                 int query_is_nethandle,
                                 int query_has_arin_prefix)
{
    if (!arin_host || query_has_arin_prefix)
        return NULL;
    const char* prefix = NULL;
    if (query_is_nethandle) {
        prefix = "n + = ! ";
    } else if (query_is_cidr) {
        prefix = "r + = ";
    } else if (query_is_ip_literal) {
        prefix = "n + = ";
    } else if (query_is_asn) {
        prefix = "a + = ";
    }
    if (!prefix)
        return NULL;
    return wc_lookup_build_arin_prefixed_query(query, prefix);
}

static void wc_lookup_format_fallback_flags(unsigned int flags, char* buf, size_t len) {
    if (!buf || len == 0) return;
    buf[0] = '\0';
    const char* names[5];
    int idx = 0;
    if (flags & 0x1) names[idx++] = "known-ip";
    if (flags & 0x2) names[idx++] = "empty-retry";
    if (flags & 0x4) names[idx++] = "forced-ipv4";
    if (flags & 0x8) names[idx++] = "iana-pivot";
    if (flags & 0x10) names[idx++] = "redirect-cap";
    if (idx == 0) {
        snprintf(buf, len, "%s", "none");
        return;
    }
    size_t used = 0;
    for (int i = 0; i < idx; ++i) {
        int written = snprintf(buf + used, (used < len ? len - used : 0), "%s%s", (i == 0 ? "" : "|"), names[i]);
        if (written < 0) break;
        used += (size_t)written;
        if (used >= len) break;
    }
}

static void wc_lookup_log_candidates(int hop,
                                     const char* server,
                                     const char* rir,
                                     const wc_dns_candidate_list_t* cands,
                                     const char* canonical_host,
                                     const char* pref_label,
                                     const wc_net_context_t* net_ctx,
                                     const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg) || !cands) return;
    (void)canonical_host;
    const char* rir_label = (rir && *rir) ? rir : "unknown";
    const char* server_label = (server && *server) ? server : "unknown";
    int limit_hit = (cfg && cfg->dns_max_candidates > 0 && cands->limit_hit);
    if (cands->count == 0) {
        fprintf(stderr,
            "[DNS-CAND] hop=%d server=%s rir=%s idx=-1 target=NONE type=none origin=none",
            hop, server_label, rir_label);
        if (pref_label && *pref_label) fprintf(stderr, " pref=%s", pref_label);
        if (limit_hit) fprintf(stderr, " limit=%d", cfg->dns_max_candidates);
        fputc('\n', stderr);
        return;
    }
    for (int i = 0; i < cands->count; ++i) {
        const char* target = (cands->items && cands->items[i]) ? cands->items[i] : "UNKNOWN";
        unsigned char fam = (cands->families && i < cands->count) ? cands->families[i] : (unsigned char)WC_DNS_FAMILY_UNKNOWN;
        unsigned char origin_code = (cands->origins && i < cands->count) ? cands->origins[i] : (unsigned char)WC_DNS_ORIGIN_RESOLVER;
        const char* type = wc_lookup_family_label(fam, target);
        const char* origin = wc_lookup_origin_label(origin_code);
        fprintf(stderr,
            "[DNS-CAND] hop=%d server=%s rir=%s idx=%d target=%s type=%s origin=%s",
            hop, server_label, rir_label, i, target, type, origin);
        if (pref_label && *pref_label) fprintf(stderr, " pref=%s", pref_label);
        if (limit_hit) fprintf(stderr, " limit=%d", cfg->dns_max_candidates);
        fputc('\n', stderr);
    }

    wc_dns_cache_stats_t stats;
    if (wc_dns_get_cache_stats(&stats) == 0) {
        fprintf(stderr,
                "[DNS-CACHE] hits=%ld neg_hits=%ld misses=%ld\n",
                stats.hits, stats.negative_hits, stats.misses);
    }
}

static void wc_lookup_log_fallback(int hop,
                                   const char* cause,
                                   const char* action,
                                   const char* domain,
                                   const char* target,
                                   const char* status,
                                   unsigned int flags,
                                   int err_no,
                                   int empty_retry_count,
                                   const char* pref_label,
                                   const wc_net_context_t* net_ctx,
                                   const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg)) return;
    char flagbuf[64];
    wc_lookup_format_fallback_flags(flags, flagbuf, sizeof(flagbuf));
    fprintf(stderr,
                "[DNS-FALLBACK] hop=%d cause=%s action=%s domain=%s target=%s status=%s flags=%s",
            hop,
            (cause && *cause) ? cause : "unknown",
            (action && *action) ? action : "unknown",
            (domain && *domain) ? domain : "unknown",
            (target && *target) ? target : "unknown",
            (status && *status) ? status : "unknown",
            flagbuf[0] ? flagbuf : "none");
            if (pref_label && *pref_label) fprintf(stderr, " pref=%s", pref_label);
    if (err_no > 0) fprintf(stderr, " errno=%d", err_no);
    if (empty_retry_count >= 0) fprintf(stderr, " empty_retry=%d", empty_retry_count);
    fputc('\n', stderr);
}

static void wc_lookup_log_dns_error(const char* host,
                    const char* canonical_host,
                    int gai_error,
                    int negative_cache,
                    const wc_net_context_t* net_ctx,
                    const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg) || gai_error == 0) return;
    const char* source = negative_cache ? "negative-cache" : "resolver";
    const char* detail = gai_strerror(gai_error);
    fprintf(stderr,
        "[DNS-ERROR] host=%s canonical=%s source=%s gai_err=%d message=%s\n",
        (host && *host) ? host : "unknown",
        (canonical_host && *canonical_host) ? canonical_host : "unknown",
        source,
        gai_error,
        detail ? detail : "n/a");
}

static int wc_lookup_should_skip_fallback(const char* server,
                                          const char* candidate,
                                          int family,
                                          int allow_skip,
                                          const wc_net_context_t* net_ctx,
                                          const Config* cfg) {
    if (!candidate || !*candidate) {
        return 0;
    }
    wc_dns_health_snapshot_t snap;
    int penalized = wc_dns_should_skip_logged(cfg, server, candidate, family,
        allow_skip ? "skip" : "force-last", &snap, net_ctx);
    return allow_skip ? penalized : 0;
}

static void wc_lookup_log_dns_health(const char* host,
                        int family,
                        const wc_net_context_t* net_ctx,
                        const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg)) return;
    wc_dns_health_snapshot_t snap;
    wc_dns_health_state_t st = wc_dns_health_get_state(cfg, host, family, &snap);
    const char* fam_label = (family == AF_INET) ? "ipv4" :
                (family == AF_INET6) ? "ipv6" : "unknown";
    const char* state_label = (st == WC_DNS_HEALTH_PENALIZED) ? "penalized" : "ok";
    fprintf(stderr,
        "[DNS-HEALTH] host=%s family=%s state=%s consec_fail=%d penalty_ms_left=%ld\n",
        (host && *host) ? host : "unknown",
        fam_label,
        state_label,
        snap.consecutive_failures,
        snap.penalty_ms_left);
}

static void wc_result_init(struct wc_result* r){
    if(!r) return;
    memset(r,0,sizeof(*r));
    r->err = 0;
    r->meta.via_host[0] = 0;
    r->meta.via_ip[0] = 0;
    r->meta.last_host[0] = 0;
    r->meta.last_ip[0] = 0;
    r->meta.authoritative_host[0] = 0;
    r->meta.authoritative_ip[0] = 0;
    r->meta.fallback_flags = 0; // initialize phased-in fallback bitset
        r->meta.last_connect_errno = 0; // initialize last connection errno
}

void wc_lookup_result_free(struct wc_result* r){ if(!r) return; if(r->body){ free(r->body); r->body=NULL; } r->body_len=0; }

// helper to append text to a growing buffer; frees base and returns new buffer
static char* append_and_free(char* base, const char* extra) {
    size_t la = base ? strlen(base) : 0;
    size_t lb = extra ? strlen(extra) : 0;
    char* n = (char*)malloc(la + lb + 1);
    if (!n) return base; // OOM: keep old to avoid leak
    if (base) memcpy(n, base, la);
    if (extra) memcpy(n + la, extra, lb);
    n[la + lb] = '\0';
    if (base) free(base);
    return n;
}

// local strdup to avoid feature-macro dependency differences across toolchains
static char* xstrdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

// Simple IP literal check (IPv4 dotted-decimal or presence of ':')
// Known-IP fallback mapping (defined in whois_client.c); phase-in with minimal coupling
// DNS fallback helper for well-known WHOIS servers.
extern const char* wc_dns_get_known_ip(const char* domain);

int wc_lookup_execute(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out) {
    if(!q || !q->raw || !out) return -1;
    struct wc_lookup_opts zopts = { .max_hops=5, .no_redirect=0, .timeout_sec=5, .retries=2, .net_ctx=NULL, .config=NULL };
    if(opts) zopts = *opts;
    const Config* cfg = wc_lookup_resolve_config(&zopts);
    wc_result_init(out);
    if (!cfg) {
        out->err = EINVAL;
        return -1;
    }
    wc_net_context_t* net_ctx = zopts.net_ctx ? zopts.net_ctx : wc_net_context_get_active();
    if (!net_ctx) {
        out->err = EINVAL;
        return -1;
    }
    if (wc_signal_should_terminate()) {
        out->err = WC_ERR_IO;
        out->meta.last_connect_errno = EINTR;
        return -1;
    }
    const wc_selftest_injection_t* injection = net_ctx ? net_ctx->injection : NULL;
    const wc_selftest_fault_profile_t* fault_profile = injection ? &injection->fault : NULL;
    int query_is_ipv4_literal = wc_lookup_query_is_ipv4_literal(q->raw);
    int query_is_ip_literal = wc_lookup_query_is_ip_literal(q->raw);
    int query_is_cidr = wc_lookup_query_is_cidr(q->raw);
    int query_is_asn = wc_lookup_query_is_asn(q->raw);
    int query_is_nethandle = wc_lookup_query_is_arin_nethandle(q->raw);
    int query_has_arin_prefix = wc_lookup_query_has_arin_prefix(q->raw);
    char* cidr_base_query = NULL;
    if (query_is_cidr) {
        cidr_base_query = wc_lookup_extract_cidr_base(q->raw);
    }
    int query_is_cidr_effective = query_is_cidr;
    int query_is_ip_literal_effective = query_is_ip_literal || (cidr_base_query != NULL);
    int query_is_ipv4_literal_effective = query_is_ipv4_literal ||
        (cidr_base_query && strchr(cidr_base_query, ':') == NULL);

    // Pick starting server: explicit -> canonical; else default to IANA
    // Keep a stable label to display in header: prefer the user-provided token verbatim when present
    char start_host[128];
    char start_label[128];
    if (q->start_server && q->start_server[0]) {
        // Prefer canonical RIR hostname for display even when the user passed
        // an IP literal (e.g., RIR numeric). This keeps headers stable:
        // "via whois.arin.net @ <ip>" instead of "via <ip> @ <ip>".
        const char* rir_guess = wc_guess_rir(q->start_server);
        const char* canon_label = NULL;
        if (rir_guess && strcmp(rir_guess, "unknown") != 0) {
            canon_label = wc_dns_canonical_host_for_rir(rir_guess);
        }
        if (!canon_label) {
            // fallback: allow direct alias mapping (arin/apnic/ripe/etc.).
            canon_label = wc_dns_canonical_host_for_rir(q->start_server);
        }
        char* mapped = NULL;
        if (!canon_label && wc_dns_is_ip_literal(q->start_server)) {
            mapped = wc_dns_rir_fallback_from_ip(cfg, q->start_server);
            if (mapped) {
                canon_label = mapped;
            }
        }

        if (canon_label) {
            snprintf(start_label, sizeof(start_label), "%s", canon_label);
        } else {
            snprintf(start_label, sizeof(start_label), "%s", q->start_server);
        }

        if (mapped) {
            free(mapped);
        }
    } else {
        snprintf(start_label, sizeof(start_label), "%s", "whois.iana.org");
    }
    if (q->start_server && q->start_server[0]) {
        if (wc_normalize_whois_host(q->start_server, start_host, sizeof(start_host)) != 0)
            snprintf(start_host, sizeof(start_host), "%s", q->start_server);
    } else {
        snprintf(start_host, sizeof(start_host), "%s", "whois.iana.org");
    }

    // Redirect loop with simple visited guard
    char* visited[16] = {0};
    int visited_count = 0;
    char current_host[128]; snprintf(current_host, sizeof(current_host), "%s", start_host);
    int current_port = (q->port > 0 ? q->port : 43);
    int hops = 0;
    int additional_emitted = 0; // first referral uses "Additional"
    int redirect_cap_hit = 0; // set when redirect limit stops the chain early
    char* combined = NULL;
    out->meta.hops = 0;
    int emit_redirect_headers = !(cfg && cfg->plain_mode);

    int empty_retry = 0; // retry budget for empty-body anomalies within a hop (fallback hosts)
    char* arin_cidr_retry_query = NULL;
    int apnic_force_ip = 0;
    int apnic_revisit_used = 0;
    int force_original_query = 0;
    int pending_referral = 0;
    int last_hop_authoritative = 0;
    int last_hop_need_redirect = 0;
    int last_hop_has_ref = 0;
    Config cfg_override;
    const Config* cfg_for_dns = NULL;
    int apnic_erx_root = 0;
    char apnic_erx_ref_host[128];
    apnic_erx_ref_host[0] = '\0';
    char apnic_erx_target_rir[16];
    apnic_erx_target_rir[0] = '\0';
    int apnic_erx_stop = 0;
    char apnic_erx_stop_host[128];
    apnic_erx_stop_host[0] = '\0';
    int apnic_erx_stop_unknown = 0;
    int apnic_erx_ripe_non_managed = 0;
    char apnic_erx_root_host[128];
    apnic_erx_root_host[0] = '\0';
    char apnic_erx_root_ip[64];
    apnic_erx_root_ip[0] = '\0';
    char apnic_last_ip[64];
    apnic_last_ip[0] = '\0';
    int apnic_erx_seen_arin = 0;
    int rir_cycle_exhausted = 0;
    int apnic_erx_keep_arin_body = 0;
    int apnic_erx_arin_before_apnic = 0;
    int apnic_erx_authoritative_stop = 0;
    int force_rir_cycle = 0;
    int seen_arin_no_match_cidr = 0;
    int seen_apnic_iana_netblock = 0;
    int seen_ripe_non_managed = 0;
    int seen_afrinic_iana_blk = 0;
    int seen_lacnic_unallocated = 0;
    int seen_real_authoritative = 0;
    while (hops < zopts.max_hops) {
        if (wc_signal_should_terminate()) {
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            break;
        }
        apnic_erx_authoritative_stop = 0;
        force_rir_cycle = 0;
        // default last-hop markers for this iteration (helps error reporting on early failures)
        snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
        snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s", "unknown");
        // mark visited
        int already = 0;
        for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], current_host)==0) { already=1; break; } }
    if (!already && visited_count < 16) visited[visited_count++] = xstrdup(current_host);

        // connect (dynamic DNS-derived candidate list; IPv6 preferred unless overridden)
        const char* rir = wc_guess_rir(current_host);
        int base_prefers_v4 = wc_ip_pref_prefers_ipv4_first(cfg->ip_pref_mode, hops);
        int hop_prefers_v4 = base_prefers_v4;
        int rir_pref = WC_RIR_IP_PREF_UNSET;
        if (rir) {
            if (strcasecmp(rir, "iana") == 0) rir_pref = cfg->rir_pref_iana;
            else if (strcasecmp(rir, "arin") == 0) rir_pref = cfg->rir_pref_arin;
            else if (strcasecmp(rir, "ripe") == 0) rir_pref = cfg->rir_pref_ripe;
            else if (strcasecmp(rir, "apnic") == 0) rir_pref = cfg->rir_pref_apnic;
            else if (strcasecmp(rir, "lacnic") == 0) rir_pref = cfg->rir_pref_lacnic;
            else if (strcasecmp(rir, "afrinic") == 0) rir_pref = cfg->rir_pref_afrinic;
            else if (strcasecmp(rir, "verisign") == 0) rir_pref = cfg->rir_pref_verisign;
        }
        int use_rir_pref = (rir_pref != WC_RIR_IP_PREF_UNSET && !cfg->ipv4_only && !cfg->ipv6_only);
        if (use_rir_pref) {
            hop_prefers_v4 = (rir_pref == WC_RIR_IP_PREF_V4) ? 1 : 0;
        }
        int arin_host = (rir && strcasecmp(rir, "arin") == 0);
        int arin_ipv4_query = (arin_host && query_is_ipv4_literal_effective);
        int arin_ipv4_override = (arin_ipv4_query && !cfg->ipv6_only);
        int arin_retry_active = 0;
        char pref_label[32];
        wc_ip_pref_format_label(cfg->ip_pref_mode, hops, pref_label, sizeof(pref_label));
        struct wc_net_info ni; int rc; ni.connected=0; ni.fd=-1; ni.ip[0]='\0';
        char canonical_host[128]; canonical_host[0]='\0';
        wc_lookup_compute_canonical_host(current_host, rir, canonical_host, sizeof(canonical_host));
        wc_dns_candidate_list_t candidates = {0};
        cfg_for_dns = cfg;
        if (use_rir_pref) {
            cfg_override = *cfg;
            cfg_override.dns_family_mode = (rir_pref == WC_RIR_IP_PREF_V4)
                ? WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK
                : WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
            cfg_override.dns_family_mode_set = 1;
            cfg_override.dns_family_mode_first = cfg_override.dns_family_mode;
            cfg_override.dns_family_mode_next = cfg_override.dns_family_mode;
            cfg_override.dns_family_mode_first_set = 1;
            cfg_override.dns_family_mode_next_set = 1;
            cfg_for_dns = &cfg_override;
            snprintf(pref_label, sizeof(pref_label), "rir-%s", (rir_pref == WC_RIR_IP_PREF_V4) ? "v4" : "v6");
        }
        int dns_build_rc = wc_dns_build_candidates(cfg_for_dns, current_host, rir, hop_prefers_v4, hops, &candidates, injection);
        if (candidates.last_error != 0) {
            wc_lookup_log_dns_error(current_host, canonical_host, candidates.last_error, candidates.negative_cache_hit, net_ctx, cfg);
        }
        // Log current DNS health for both IPv4 and IPv6 families. This is
        // observability-only in Phase 3 step 2 and does not influence
        // candidate ordering or fallback decisions.
        wc_lookup_log_dns_health(canonical_host[0] ? canonical_host : current_host, AF_INET, net_ctx, cfg);
        wc_lookup_log_dns_health(canonical_host[0] ? canonical_host : current_host, AF_INET6, net_ctx, cfg);
        if (dns_build_rc != 0) {
            out->err = -1;
            wc_dns_candidate_list_free(&candidates);
            break;
        }
        wc_lookup_log_candidates(hops+1, current_host, rir, &candidates, canonical_host, pref_label, net_ctx, cfg);
        int arin_forced_index = -1;
        int* arin_candidate_order = NULL;
        if (arin_ipv4_override && arin_forced_index >= 0 && candidates.count > 1) {
            arin_candidate_order = (int*)malloc(sizeof(int) * candidates.count);
            if (arin_candidate_order) {
                int pos = 0;
                arin_candidate_order[pos++] = arin_forced_index;
                for (int i = 0; i < candidates.count; ++i) {
                    if (i == arin_forced_index) continue;
                    arin_candidate_order[pos++] = i;
                }
            }
        }
        int primary_attempts = 0;
        int penalized_skipped = 0;
        char penalized_first_target[128]; penalized_first_target[0] = '\0';
        int penalized_first_family = AF_UNSPEC;
        wc_dns_health_snapshot_t penalized_first_snap; memset(&penalized_first_snap, 0, sizeof(penalized_first_snap));
        char penalized_second_target[128]; penalized_second_target[0] = '\0';
        int penalized_second_family = AF_UNSPEC;
        wc_dns_health_snapshot_t penalized_second_snap; memset(&penalized_second_snap, 0, sizeof(penalized_second_snap));

        int host_attempt_cap = (cfg->max_host_addrs > 0 ? cfg->max_host_addrs : 0);
        int host_attempts = 0;
        int connected_ok = 0; int first_conn_rc = 0;
        for (int order_idx=0; order_idx<candidates.count; ++order_idx){
                if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                    break;
                }
            int i = arin_candidate_order ? arin_candidate_order[order_idx] : order_idx;
            const char* target = candidates.items[i];
            if (!target) continue;
            // avoid duplicate immediate retry of identical token
            if (i>0 && strcasecmp(target, current_host)==0) continue;
            int candidate_family = wc_lookup_family_to_af(
                (candidates.families && i < candidates.count) ?
                    candidates.families[i] : (unsigned char)WC_DNS_FAMILY_UNKNOWN,
                target);
            int is_last_candidate = (order_idx == candidates.count - 1);
            wc_dns_health_snapshot_t backoff_snap;
            int penalized = wc_dns_should_skip_logged(cfg, current_host, target,
                candidate_family,
                is_last_candidate ? "force-last" : "skip",
                &backoff_snap, net_ctx);
            if (penalized && !is_last_candidate) {
                penalized_skipped++;
                if (!penalized_first_target[0]) {
                    snprintf(penalized_first_target, sizeof(penalized_first_target), "%s", target);
                    penalized_first_family = candidate_family;
                    penalized_first_snap = backoff_snap;
                } else if (!penalized_second_target[0] && candidate_family != penalized_first_family) {
                    snprintf(penalized_second_target, sizeof(penalized_second_target), "%s", target);
                    penalized_second_family = candidate_family;
                    penalized_second_snap = backoff_snap;
                }
                continue;
            }
            if (penalized && is_last_candidate) {
                /* Already logged via wc_dns_should_skip_logged */
            }
            int dial_timeout_ms = zopts.timeout_sec * 1000;
            int dial_retries = zopts.retries;
            if (dial_timeout_ms <= 0) dial_timeout_ms = 1000;
            primary_attempts++;
            rc = wc_dial_43(net_ctx, target, (uint16_t)current_port, dial_timeout_ms, dial_retries, &ni);
            host_attempts++;
            int attempt_success = (rc==0 && ni.connected);
            wc_lookup_record_backoff_result(cfg, target, candidate_family, attempt_success);
            if (wc_lookup_should_trace_dns(net_ctx, cfg) && i>0) {
                wc_lookup_log_fallback(hops+1, "connect-fail", "candidate", current_host,
                                       target, attempt_success?"success":"fail",
                                       out->meta.fallback_flags,
                                       attempt_success?0:ni.last_errno,
                                       -1,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            }
            if (attempt_success){
                // Do not mutate logical current_host with numeric dial targets; keep it as the logical server label.
                connected_ok = 1; break;
            } else {
                if (order_idx==0) first_conn_rc = rc;
            }
        }
        if (arin_candidate_order) {
            free(arin_candidate_order);
            arin_candidate_order = NULL;
        }
        if (!connected_ok && primary_attempts == 0 && penalized_skipped > 0 && penalized_first_target[0]) {
            const char* override_targets[2] = { penalized_first_target, penalized_second_target[0]?penalized_second_target:NULL };
            const int override_families[2] = { penalized_first_family, penalized_second_target[0]?penalized_second_family:AF_UNSPEC };
            const wc_dns_health_snapshot_t* override_snaps[2] = { &penalized_first_snap, penalized_second_target[0]?&penalized_second_snap:NULL };
            for (int oi = 0; oi < 2; ++oi) {
                if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                    break;
                }
                if (!override_targets[oi]) continue;
                int dial_timeout_ms = zopts.timeout_sec * 1000;
                int dial_retries = zopts.retries;
                if (dial_timeout_ms <= 0) dial_timeout_ms = 1000;
                primary_attempts++;
                wc_dns_health_snapshot_t log_snap;
                wc_dns_health_snapshot_t* log_snap_ptr = NULL;
                if (override_snaps[oi]) {
                    log_snap = *override_snaps[oi];
                    log_snap_ptr = &log_snap;
                }
                (void)wc_dns_should_skip_logged(cfg, current_host, override_targets[oi],
                    override_families[oi], "force-override",
                    log_snap_ptr, net_ctx);
                rc = wc_dial_43(net_ctx, override_targets[oi], (uint16_t)current_port, dial_timeout_ms, dial_retries, &ni);
                host_attempts++;
                int attempt_success = (rc==0 && ni.connected);
                wc_lookup_record_backoff_result(cfg, override_targets[oi], override_families[oi], attempt_success);
                if (wc_lookup_should_trace_dns(net_ctx, cfg)) {
                    wc_lookup_log_fallback(hops+1, "connect-fail", "candidate", current_host,
                                           override_targets[oi], attempt_success?"success":"fail",
                                           out->meta.fallback_flags,
                                           attempt_success?0:ni.last_errno,
                                           -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
                if (attempt_success) {
                    connected_ok = 1;
                    break;
                } else if (first_conn_rc == 0) {
                    first_conn_rc = rc;
                }
            }
        }
        if(!connected_ok){
            if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                break;
            }
            // Phase-in step 1: try forcing IPv4 for the same domain (if domain is not an IP literal)
            const char* domain_for_ipv4 = NULL;
            if (!wc_dns_is_ip_literal(current_host)) {
                domain_for_ipv4 = current_host;
            } else {
                const char* ch = wc_dns_canonical_host_for_rir(rir);
                domain_for_ipv4 = ch ? ch : NULL;
            }
            const char* domain_for_known = NULL;
            if (!wc_dns_is_ip_literal(current_host)) {
                domain_for_known = current_host;
            } else {
                const char* ch = wc_dns_canonical_host_for_rir(rir);
                domain_for_known = ch ? ch : NULL;
            }
            const char* known_ip_literal_cached = NULL;
            int known_ip_available_for_attempt = 0;
            if (domain_for_known && !cfg->no_dns_known_fallback && !cfg->dns_no_fallback) {
                known_ip_literal_cached = wc_dns_get_known_ip(domain_for_known);
                if (known_ip_literal_cached && known_ip_literal_cached[0]) {
                    known_ip_available_for_attempt = 1;
                }
            }
            int forced_ipv4_attempted = 0;
            int forced_ipv4_success = 0;
            int forced_ipv4_errno = 0;
            char forced_ipv4_target[64]; forced_ipv4_target[0]='\0';
            if (domain_for_ipv4 && !cfg->no_dns_force_ipv4_fallback && !cfg->ipv6_only) {
                if (cfg->dns_no_fallback) {
                    // In dns-no-fallback mode, log a skipped forced-IPv4 fallback and do not actually retry.
                    wc_lookup_log_fallback(hops+1, "connect-fail", "no-op",
                                           domain_for_ipv4 ? domain_for_ipv4 : current_host,
                                           "(none)",
                                           "skipped",
                                           out->meta.fallback_flags,
                                           0,
                                           -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                } else {
                    int skip_forced_ipv4 = wc_lookup_should_skip_fallback(
                        current_host,
                        domain_for_ipv4,
                        AF_INET,
                        known_ip_available_for_attempt,
                        net_ctx,
                        cfg);
                    if (!skip_forced_ipv4) {
                        wc_selftest_record_forced_ipv4_attempt();
                        struct addrinfo hints, *res = NULL;
                        memset(&hints, 0, sizeof(hints));
                        hints.ai_family = AF_INET; // IPv4 only
                        hints.ai_socktype = SOCK_STREAM;
                        int gai = 0, tries=0; int maxtries = (cfg->dns_retry>0?cfg->dns_retry:1);
                        do {
                            gai = getaddrinfo(domain_for_ipv4, NULL, &hints, &res);
                            if(gai==EAI_AGAIN && tries<maxtries-1){ int ms=(cfg->dns_retry_interval_ms>=0?cfg->dns_retry_interval_ms:100); struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)((ms%1000)*1000000L); nanosleep(&ts,NULL); }
                            tries++;
                        } while(gai==EAI_AGAIN && tries<maxtries);
                        if (gai == 0 && res) {
                            char ipbuf[64]; ipbuf[0]='\0';
                            for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
                                if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                                    break;
                                }
                                if (p->ai_family == AF_INET) {
                                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                                    if (inet_ntop(AF_INET, &(ipv4->sin_addr), ipbuf, sizeof(ipbuf))) {
                                        struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                        rc4 = wc_dial_43(net_ctx, ipbuf, (uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries, &ni4);
                                        host_attempts++;
                                        forced_ipv4_attempted = 1;
                                        snprintf(forced_ipv4_target, sizeof(forced_ipv4_target), "%s", ipbuf);
                                        int backoff_success = (rc4==0 && ni4.connected);
                                        wc_lookup_record_backoff_result(cfg, ipbuf, AF_INET, backoff_success);
                                        if (backoff_success) {
                                            ni = ni4;
                                            connected_ok = 1;
                                            out->meta.fallback_flags |= 0x4; // forced_ipv4
                                            forced_ipv4_success = 1;
                                            forced_ipv4_errno = 0;
                                            break;
                                        } else {
                                            forced_ipv4_success = 0;
                                            forced_ipv4_errno = ni4.last_errno;
                                            if (ni4.fd>=0) {
                                                int debug_enabled = cfg ? cfg->debug : 0;
                                                wc_safe_close(&ni4.fd, "wc_lookup_forced_ipv4_fail", debug_enabled);
                                            }
                                        }
                                    }
                                }
                            }
                            freeaddrinfo(res);
                        }
                    }
                }
            }
            if (forced_ipv4_attempted) {
                wc_lookup_log_fallback(hops+1, "connect-fail", "forced-ipv4",
                                       domain_for_ipv4 ? domain_for_ipv4 : current_host,
                                       forced_ipv4_target[0]?forced_ipv4_target:"(none)",
                                       forced_ipv4_success?"success":"fail",
                                       out->meta.fallback_flags,
                                       forced_ipv4_success?0:forced_ipv4_errno,
                                       -1,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            }

            // Phase-in step 2: try known IPv4 fallback for canonical domain (do not change current_host for metadata)
            int known_ip_attempted = 0;
            int known_ip_success = 0;
            int known_ip_errno = 0;
            const char* known_ip_target = NULL;
            if (!connected_ok && domain_for_known && !cfg->no_dns_known_fallback && !cfg->ipv6_only) {
                if (cfg->dns_no_fallback) {
                    // In dns-no-fallback mode, log a skipped known-IP fallback and do not actually retry.
                    wc_lookup_log_fallback(hops+1, "connect-fail", "no-op",
                                           domain_for_known ? domain_for_known : current_host,
                                           "(none)",
                                           "skipped",
                                           out->meta.fallback_flags,
                                           0,
                                           -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                } else {
                    const char* kip = known_ip_literal_cached;
                    if (kip && kip[0]) {
                        wc_lookup_should_skip_fallback(current_host,
                                                       domain_for_known,
                                                       AF_UNSPEC,
                                                       0,
                                                       net_ctx,
                                                       cfg);
                        wc_selftest_record_known_ip_attempt();
                        struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
                        known_ip_attempted = 1;
                        known_ip_target = kip;
                        rc2 = wc_dial_43(net_ctx, kip, (uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries, &ni2);
                        int known_backoff_success = (rc2==0 && ni2.connected);
                        wc_lookup_record_backoff_result(cfg, kip, AF_UNSPEC, known_backoff_success);
                        if (rc2==0 && ni2.connected) {
                            // connected via known IP; keep current_host unchanged (still canonical host)
                            ni = ni2;
                            connected_ok = 1;
                            out->meta.fallback_flags |= 0x1; // used_known_ip
                            // also mark forced IPv4 if the known IP is IPv4 literal
                            if (strchr(kip, ':')==NULL && strchr(kip, '.')!=NULL) {
                                out->meta.fallback_flags |= 0x4; // forced_ipv4
                            }
                            known_ip_success = 1;
                            known_ip_errno = 0;
                        } else {
                            known_ip_success = 0;
                            known_ip_errno = ni2.last_errno;
                            // ensure fd closed in failure path
                            if (ni2.fd>=0) {
                                int debug_enabled = cfg ? cfg->debug : 0;
                                wc_safe_close(&ni2.fd, "wc_lookup_known_ip_fail", debug_enabled);
                            }
                        }
                    }
                }
            }
            if (known_ip_attempted) {
                wc_lookup_log_fallback(hops+1, "connect-fail", "known-ip",
                                       domain_for_known ? domain_for_known : current_host,
                                       known_ip_target ? known_ip_target : "(none)",
                                       known_ip_success?"success":"fail",
                                       out->meta.fallback_flags,
                                       known_ip_success?0:known_ip_errno,
                                       -1,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            }
        }
        wc_dns_candidate_list_free(&candidates);
        if(!connected_ok){
            out->err = first_conn_rc?first_conn_rc:-1;
            out->meta.last_connect_errno = ni.last_errno; // propagate failure errno
            snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
            snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s",
                     ni.ip[0] ? ni.ip : "unknown");
            if (hops == 0) {
                if (out->meta.via_host[0] == 0) {
                    snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_label);
                }
                if (out->meta.via_ip[0] == 0) {
                    snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s",
                             ni.ip[0] ? ni.ip : "unknown");
                }
            }
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        if (wc_signal_should_terminate()) {
            int debug_enabled = cfg ? cfg->debug : 0;
            wc_safe_close(&ni.fd, "wc_lookup_signal_abort", debug_enabled);
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
            snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s",
                     ni.ip[0] ? ni.ip : "unknown");
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        // record last successful hop details
        snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
        snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s", ni.ip[0]?ni.ip:"unknown");
        if (hops == 0) {
            // record first hop meta: show the user-supplied starting server token when available
            snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_label);
            snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s", ni.ip[0]?ni.ip:"unknown");
        }

        // send query (auto prepend "n " for ARIN IPv4 literals when needed)
        arin_retry_active = (arin_cidr_retry_query != NULL);
        int use_original_query = force_original_query;
        force_original_query = 0;
        int query_is_cidr_hop = query_is_cidr_effective || use_original_query;
        int query_is_ip_literal_hop = query_is_ip_literal_effective;
        if (use_original_query) {
            query_is_ip_literal_hop = query_is_ip_literal;
        }
        const char* outbound_query = arin_cidr_retry_query ? arin_cidr_retry_query : q->raw;
        if (!arin_cidr_retry_query && cfg && cfg->cidr_strip_query && cidr_base_query && !use_original_query) {
            outbound_query = cidr_base_query;
        }
        char* stripped_query = NULL;
        int query_has_arin_prefix_effective = query_has_arin_prefix || arin_retry_active;
        if (!arin_retry_active && !arin_host && query_has_arin_prefix_effective) {
            stripped_query = wc_lookup_strip_query_prefix(q->raw);
            if (stripped_query)
                outbound_query = stripped_query;
        }
        if (stripped_query && wc_lookup_should_trace_dns(net_ctx, cfg)) {
            fprintf(stderr,
                "[DNS-ARIN] action=strip-prefix host=%s query=%s stripped=%s\n",
                current_host, q->raw, stripped_query);
        }
        char* arin_prefixed_query = wc_lookup_arin_build_query(outbound_query,
            arin_host,
            query_is_ip_literal_hop,
            query_is_cidr_hop,
            query_is_asn,
            query_is_nethandle,
            query_has_arin_prefix_effective);
        if (arin_prefixed_query) {
            outbound_query = arin_prefixed_query;
        }
        size_t qlen = strlen(outbound_query);
        char* line = (char*)malloc(qlen+3);
        if(!line){
            if (arin_prefixed_query) free(arin_prefixed_query);
            out->err=-1; { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_malloc_fail", debug_enabled); }
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        memcpy(line, outbound_query, qlen); line[qlen]='\r'; line[qlen+1]='\n'; line[qlen+2]='\0';
        if (wc_signal_should_terminate()) {
            free(line);
            if (arin_prefixed_query) free(arin_prefixed_query);
            if (stripped_query) free(stripped_query);
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_signal_abort", debug_enabled); }
            break;
        }
        if (wc_send_all(ni.fd, line, qlen+2, zopts.timeout_sec*1000) < 0){
            free(line);
            if (arin_prefixed_query) free(arin_prefixed_query);
            out->err=-1; { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_send_fail", debug_enabled); }
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        free(line);
        if (arin_prefixed_query) {
            free(arin_prefixed_query);
        }
        if (arin_cidr_retry_query) {
            free(arin_cidr_retry_query);
            arin_cidr_retry_query = NULL;
        }
        if (stripped_query) {
            free(stripped_query);
        }

        // receive
        char* body=NULL; size_t blen=0;
        if (wc_signal_should_terminate()) {
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_signal_abort", debug_enabled); }
            break;
        }
        int max_bytes = 65536;
        if (cfg && cfg->buffer_size > 0) {
            if (cfg->buffer_size > (size_t)INT_MAX) {
                max_bytes = INT_MAX;
            } else {
                max_bytes = (int)cfg->buffer_size;
            }
        }
        if (wc_recv_until_idle(ni.fd, &body, &blen, zopts.timeout_sec*1000, max_bytes) < 0){ out->err=-1; { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_recv_fail", debug_enabled); } if (pending_referral) { snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown"); } break; }
        { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_recv_done", debug_enabled); }

        if (wc_signal_should_terminate()) {
            if (body) free(body);
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }

    // Selftest injection hook (one-shot): simulate empty-body anomaly for retry/fallback validation
    // Controlled via wc_selftest_set_inject_empty() (no environment dependency in release).
        {
            static int injected_once = 0;
            int inject_empty = (injection && injection->inject_empty) ? 1 : 0;
            if (inject_empty && !injected_once) {
                if (body) { free(body); body = NULL; }
                blen = 0; // force empty
                injected_once = 1;
            }
        }

        // Defensive: occasionally a connection succeeds but body is empty.
        // Treat an empty (or all-whitespace) body as transient and try a fallback
        // host (DNS-derived candidates; ARIN more tolerant, others single) to avoid
        // showing an "authoritative" tail with no data section.
        if (blen == 0 || (blen > 0 && strspn(body, " \r\n\t") == blen)) {
            const char* rir_empty = wc_guess_rir(current_host);
            int handled_empty = 0;
            int arin_mode = (rir_empty && strcasecmp(rir_empty, "arin")==0);
            int retry_budget = arin_mode ? 2 : 1; // ARIN allows more tolerance; others once
            int allow_empty_retry = (empty_retry < retry_budget);
            if (allow_empty_retry) {
                // Rebuild candidates and pick a different one than current_host and last connected ip
                wc_dns_candidate_list_t cands2 = {0};
                int cands2_rc = wc_dns_build_candidates(cfg_for_dns ? cfg_for_dns : cfg, current_host, rir_empty, hop_prefers_v4, hops, &cands2, injection);
                if (cands2.last_error != 0) {
                    wc_lookup_log_dns_error(current_host, canonical_host, cands2.last_error, cands2.negative_cache_hit, net_ctx, cfg);
                }
                const char* pick=NULL;
                if (cands2_rc == 0) {
                    for(int i=0;i<cands2.count;i++){
                        const char* t = cands2.items[i];
                        if (strcasecmp(t, current_host)==0) continue;
                        // Prefer IP literal that differs from last connected ip
                        // Update last errno (0 if connected ok)
                        out->meta.last_connect_errno = ni.connected ? 0 : ni.last_errno;
                        if (wc_dns_is_ip_literal(t) && ni.ip[0] && strcmp(t, ni.ip)!=0) { pick=t; break; }
                        // else keep a non-literal as a fallback if nothing better
                        if (!pick) pick=t;
                    }
                }
                if (pick){
                    combined = append_and_free(combined, "\n=== Warning: empty response from ");
                    combined = append_and_free(combined, current_host);
                    combined = append_and_free(combined, ", retrying via fallback host ");
                    combined = append_and_free(combined, pick);
                    combined = append_and_free(combined, " ===\n");
                    /* keep logical current_host unchanged; only change dial target */
                    handled_empty = 1; empty_retry++;
                    wc_lookup_log_fallback(hops+1, "empty-body", "candidate",
                                           current_host, pick, "success",
                                           out->meta.fallback_flags, 0, empty_retry,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
                wc_dns_candidate_list_free(&cands2);
            }
            // Unified fallback extension: if still not handled, attempt IPv4-only re-dial of same logical domain
            if (!handled_empty && allow_empty_retry && !cfg->no_dns_force_ipv4_fallback && !cfg->ipv6_only) {
                const char* domain_for_ipv4 = NULL;
                if (!wc_dns_is_ip_literal(current_host)) domain_for_ipv4 = current_host; else {
                    const char* ch = wc_dns_canonical_host_for_rir(rir_empty);
                    if (ch) domain_for_ipv4 = ch;
                }
                if (domain_for_ipv4) {
                    wc_selftest_record_forced_ipv4_attempt();
                    struct addrinfo hints,*res=NULL; memset(&hints,0,sizeof(hints)); hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
                    int gai=0, tries=0, maxtries=(cfg->dns_retry>0?cfg->dns_retry:1);
                    do { gai=getaddrinfo(domain_for_ipv4, NULL, &hints, &res); if(gai==EAI_AGAIN && tries<maxtries-1){ int ms=(cfg->dns_retry_interval_ms>=0?cfg->dns_retry_interval_ms:100); struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)((ms%1000)*1000000L); nanosleep(&ts,NULL);} tries++; } while(gai==EAI_AGAIN && tries<maxtries);
                    if (gai==0 && res){
                        char ipbuf[64]; ipbuf[0]='\0';
                        int empty_ipv4_attempted = 0;
                        int empty_ipv4_success = 0;
                        int empty_ipv4_errno = 0;
                        int empty_ipv4_retry_metric = -1;
                        for(struct addrinfo* p=res; p; p=p->ai_next){ if(p->ai_family!=AF_INET) continue; struct sockaddr_in* a=(struct sockaddr_in*)p->ai_addr; if(inet_ntop(AF_INET,&(a->sin_addr),ipbuf,sizeof(ipbuf))){
                                struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                rc4 = wc_dial_43(net_ctx, ipbuf,(uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries,&ni4);
                                empty_ipv4_attempted = 1;
                                int empty_backoff_success = (rc4==0 && ni4.connected);
                                wc_lookup_record_backoff_result(cfg, ipbuf, AF_INET, empty_backoff_success);
                                if(empty_backoff_success){
                                    combined = append_and_free(combined, "\n=== Warning: empty response from ");
                                    combined = append_and_free(combined, current_host);
                                    combined = append_and_free(combined, ", retrying forced IPv4 ");
                                    combined = append_and_free(combined, ipbuf);
                                    combined = append_and_free(combined, " ===\n");
                                    // reuse current_host (logical) but replace ni context
                                    ni = ni4; handled_empty = 1; empty_retry++; out->meta.fallback_flags |= 0x4;
                                    empty_ipv4_success = 1;
                                    empty_ipv4_errno = 0;
                                    empty_ipv4_retry_metric = empty_retry;
                                    break; }
                                else { if(ni4.fd>=0) { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni4.fd, "wc_lookup_empty_ipv4_fail", debug_enabled); } }
                                if (!empty_ipv4_success) {
                                    empty_ipv4_errno = ni4.last_errno;
                                }
                            }}
                        if (empty_ipv4_attempted) {
                            wc_lookup_log_fallback(hops+1, "empty-body", "forced-ipv4",
                                                   domain_for_ipv4, ipbuf[0]?ipbuf:"(none)",
                                                   empty_ipv4_success?"success":"fail",
                                                   out->meta.fallback_flags,
                                                   empty_ipv4_success?0:empty_ipv4_errno,
                                                   empty_ipv4_success?empty_ipv4_retry_metric:-1,
                                                   pref_label,
                                                   net_ctx,
                                                   cfg);
                        }
                        freeaddrinfo(res);
                    }
                }
            }

            // Unified fallback extension: try known IPv4 mapping if still unhandled
            if (!handled_empty && allow_empty_retry && !cfg->no_dns_known_fallback && !cfg->ipv6_only) {
                const char* domain_for_known=NULL;
                if (!wc_dns_is_ip_literal(current_host)) domain_for_known=current_host; else {
                    const char* ch = wc_dns_canonical_host_for_rir(rir_empty); if (ch) domain_for_known=ch; }
                if (domain_for_known){
                    wc_selftest_record_known_ip_attempt();
                    const char* kip = wc_dns_get_known_ip(domain_for_known);
                    if (kip && kip[0]){
                        struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
                        rc2 = wc_dial_43(net_ctx, kip,(uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries,&ni2);
                        int empty_known_success = (rc2==0 && ni2.connected);
                        wc_lookup_record_backoff_result(cfg, kip, AF_UNSPEC, empty_known_success);
                        if (empty_known_success){
                            combined = append_and_free(combined, "\n=== Warning: empty response from ");
                            combined = append_and_free(combined, current_host);
                            combined = append_and_free(combined, ", retrying known IP ");
                            combined = append_and_free(combined, kip);
                            combined = append_and_free(combined, " ===\n");
                            ni = ni2; handled_empty=1; empty_retry++; out->meta.fallback_flags |= 0x1; if(strchr(kip,':')==NULL && strchr(kip,'.')!=NULL) out->meta.fallback_flags |= 0x4;
                            wc_lookup_log_fallback(hops+1, "empty-body", "known-ip",
                                                   domain_for_known, kip, "success",
                                                   out->meta.fallback_flags, 0, empty_retry,
                                                   pref_label,
                                                   net_ctx,
                                                   cfg);
                        }
                        else {
                            wc_lookup_log_fallback(hops+1, "empty-body", "known-ip",
                                                   domain_for_known, kip, "fail",
                                                   out->meta.fallback_flags, ni2.last_errno, -1,
                                                   pref_label,
                                                   net_ctx,
                                                   cfg);
                            if(ni2.fd>=0) { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni2.fd, "wc_lookup_empty_known_fail", debug_enabled); } }
                    }
                }

            }
            if (!handled_empty && allow_empty_retry && empty_retry == 0) {
                // last resort: once per host
                combined = append_and_free(combined, "\n=== Warning: empty response from ");
                combined = append_and_free(combined, current_host);
                combined = append_and_free(combined, ", retrying same host ===\n");
                handled_empty = 1; empty_retry++;
                wc_lookup_log_fallback(hops+1, "empty-body", "candidate",
                                       current_host, current_host, "success",
                                       out->meta.fallback_flags, 0, empty_retry,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            }

            if (handled_empty) {
                // mark fallback: empty-body driven retry
                out->meta.fallback_flags |= 0x2; // empty_retry
                if (body) free(body);
                body = NULL; blen = 0;
                if (cfg && cfg->dns_retry_interval_ms != 0) {
                    int backoff_ms = (cfg->dns_retry_interval_ms >= 0) ? cfg->dns_retry_interval_ms : 50;
                    if (backoff_ms > 0) {
                        struct timespec ts;
                        ts.tv_sec = backoff_ms / 1000;
                        ts.tv_nsec = (long)((backoff_ms % 1000) * 1000000L);
                        nanosleep(&ts, NULL);
                    }
                }
                // continue loop WITHOUT incrementing hops to reattempt this logical hop
                continue;
            } else if (blen == 0) {
                // Give up – annotate and proceed (will be treated as non-authoritative and may pivot)
                combined = append_and_free(combined, "\n=== Warning: persistent empty response from ");
                combined = append_and_free(combined, current_host);
                combined = append_and_free(combined, " (giving up) ===\n");
            }
        } else {
            // successful non-empty body resets empty retry budget for next hop
            empty_retry = 0;
        }

        // ARIN CIDR no-match: do not retry with ARIN prefixes; follow normal RIR cycle.

        // Decide next action based on only the latest hop body (not the combined history)
        int auth = is_authoritative_response(body);
        int apnic_iana_netblock_cidr = 0;
        int apnic_erx_legacy = 0;
        /*
         * gTLD registry responses (e.g., whois.verisign-grs.com) often carry a
         * "Registrar WHOIS Server:" line that would trip the generic redirect
         * heuristics. Treat those registry hops as authoritative and suppress
         * redirects/referrals to avoid an unnecessary IANA pivot, even when the
         * hop was initiated via a literal IP (guarded by wc_guess_rir).
         */
        const char* current_rir_guess = wc_guess_rir(current_host);
        if (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 && !apnic_erx_root) {
            apnic_erx_arin_before_apnic = 1;
        }
        int is_gtld_registry = (strcasecmp(current_host, "whois.verisign-grs.com") == 0 ||
                                strcasecmp(current_host, "whois.crsnic.net") == 0 ||
                                (current_rir_guess && strcasecmp(current_rir_guess, "verisign") == 0));
        int need_redir_eval = (!is_gtld_registry) ? needs_redirect(body) : 0; // evaluate even when redirects disabled for logging
        int ripe_non_managed = 0;
        if (current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0) {
            if (wc_lookup_find_case_insensitive(body, "non-ripe-ncc-managed-address-block") ||
                wc_lookup_find_case_insensitive(body, "ip address block not managed by the ripe ncc") ||
                wc_lookup_find_case_insensitive(body, "not managed by the ripe ncc")) {
                ripe_non_managed = 1;
            }
        }
        char* ref = NULL;
        int ref_port = 0;
        char ref_host[128];
        ref_host[0] = '\0';
        if (!is_gtld_registry) {
            // Extract referral even when redirects are disabled, so we can surface
            // the pending hop in output ("=== Additional query to ... ===").
            ref = extract_refer_server(body);
            if (!ref) {
                ref = wc_lookup_extract_referral_fallback(body);
            }
        }
        if (ref) {
            if (wc_lookup_parse_referral_target(ref, ref_host, sizeof(ref_host), &ref_port) != 0 || ref_host[0] == '\0') {
                free(ref);
                ref = NULL;
            }
        }
        if (ref) {
            char ref_norm[128];
            const char* cur_host = wc_dns_canonical_alias(current_host);
            if (!cur_host) {
                cur_host = current_host;
            }
            if (wc_normalize_whois_host(ref_host, ref_norm, sizeof(ref_norm)) != 0) {
                snprintf(ref_norm, sizeof(ref_norm), "%s", ref_host);
            }
            if (strchr(ref_norm, '.') == NULL || strlen(ref_norm) < 4) {
                free(ref);
                ref = NULL;
            } else if (cur_host && strcasecmp(ref_norm, cur_host) == 0) {
                free(ref);
                ref = NULL;
            }
        }
        int ref_explicit = (ref != NULL) ? wc_lookup_referral_is_explicit(body, ref_host) : 0;
        int apnic_erx_keep_ref = 0;
        if (ref && !ref_explicit) {
            char ref_norm_keep[128];
            if (wc_normalize_whois_host(ref_host, ref_norm_keep, sizeof(ref_norm_keep)) != 0) {
                snprintf(ref_norm_keep, sizeof(ref_norm_keep), "%s", ref_host);
            }
            const char* ref_rir_keep = wc_guess_rir(ref_norm_keep);
            if (ref_rir_keep &&
                (strcasecmp(ref_rir_keep, "afrinic") == 0 ||
                 strcasecmp(ref_rir_keep, "lacnic") == 0)) {
                apnic_erx_keep_ref = 1;
            }
        }
        if (ref && !ref_explicit && ripe_non_managed) {
            free(ref);
            ref = NULL;
        }
        if (apnic_erx_root && ref && !ref_explicit && !apnic_erx_keep_ref) {
            free(ref);
            ref = NULL;
        }
        if (ref && current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0 && apnic_erx_legacy && !ref_explicit && !apnic_erx_keep_ref) {
            free(ref);
            ref = NULL;
        }
        if (ref && apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0 && apnic_erx_ripe_non_managed && !ref_explicit) {
            free(ref);
            ref = NULL;
        }
        if (apnic_erx_root && apnic_erx_arin_before_apnic) {
            apnic_erx_keep_arin_body = 1;
        }
        if (apnic_erx_root && ref && ref_host[0] && current_rir_guess &&
            strcasecmp(current_rir_guess, "arin") == 0) {
            char ref_norm3[128];
            if (wc_normalize_whois_host(ref_host, ref_norm3, sizeof(ref_norm3)) != 0) {
                snprintf(ref_norm3, sizeof(ref_norm3), "%s", ref_host);
            }
            if (!apnic_erx_ref_host[0]) {
                snprintf(apnic_erx_ref_host, sizeof(apnic_erx_ref_host), "%s", ref_norm3);
            }
            const char* ref_rir = wc_guess_rir(ref_norm3);
            int ref_visited = 0;
            for (int i = 0; i < visited_count; ++i) {
                if (strcasecmp(visited[i], ref_norm3) == 0) { ref_visited = 1; break; }
            }
            if (!apnic_erx_stop && ref_rir && strcasecmp(ref_rir, "apnic") == 0 && ref_visited) {
                apnic_erx_stop = 1;
                snprintf(apnic_erx_stop_host, sizeof(apnic_erx_stop_host), "%s", ref_norm3);
            }
        }
        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0) {
            apnic_erx_seen_arin = 1;
            if (!apnic_erx_target_rir[0]) {
                if (wc_lookup_find_case_insensitive(body, "transferred to ripe") ||
                    wc_lookup_find_case_insensitive(body, "ripe network coordination centre") ||
                    (wc_lookup_find_case_insensitive(body, "netname:") &&
                     wc_lookup_find_case_insensitive(body, "ripe"))) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "ripe");
                } else if (wc_lookup_find_case_insensitive(body, "transferred to apnic") ||
                    wc_lookup_find_case_insensitive(body, "asia pacific network information centre") ||
                    (wc_lookup_find_case_insensitive(body, "netname:") &&
                     wc_lookup_find_case_insensitive(body, "apnic"))) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "apnic");
                } else if (wc_lookup_find_case_insensitive(body, "transferred to afrinic") ||
                    wc_lookup_find_case_insensitive(body, "afrinic")) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "afrinic");
                } else if (wc_lookup_find_case_insensitive(body, "transferred to lacnic") ||
                    wc_lookup_find_case_insensitive(body, "lacnic")) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "lacnic");
                }
            }
            if (apnic_erx_target_rir[0] && strcasecmp(apnic_erx_target_rir, "apnic") == 0) {
            }
        }
        const char* header_host = wc_lookup_detect_rir_header_host(body);
        int header_is_iana = (header_host && strcasecmp(header_host, "whois.iana.org") == 0);
        int header_matches_current = 0;
        if (header_host && !header_is_iana) {
            char header_normh[128];
            char current_normh[128];
            const char* header_normp = wc_dns_canonical_alias(header_host);
            const char* current_normp = wc_dns_canonical_alias(current_host);
            if (!header_normp) header_normp = header_host;
            if (!current_normp) current_normp = current_host;
            if (wc_normalize_whois_host(header_normp, header_normh, sizeof(header_normh)) != 0) {
                snprintf(header_normh, sizeof(header_normh), "%s", header_normp);
            }
            if (wc_normalize_whois_host(current_normp, current_normh, sizeof(current_normh)) != 0) {
                snprintf(current_normh, sizeof(current_normh), "%s", current_normp);
            }
            if (strcasecmp(header_normh, current_normh) == 0) {
                header_matches_current = 1;
            }
        }
        if (header_matches_current && !auth) {
            auth = 1;
        }
        char header_hint_host[128];
        header_hint_host[0] = '\0';
        int header_hint_valid = 0;
        if (current_rir_guess && strcasecmp(current_rir_guess, "lacnic") == 0) {
            int header_erx_hint = 0;
            if (wc_lookup_body_contains_erx_legacy(body) ||
                wc_lookup_body_contains_erx_netname(body) ||
                wc_lookup_body_contains_apnic_erx_hint(body)) {
                header_erx_hint = 1;
            }
            const char* implicit_host = NULL;
            if (header_host && !header_is_iana && !header_matches_current) {
                implicit_host = header_host;
            } else {
                implicit_host = "whois.apnic.net";
            }
            if (header_erx_hint && implicit_host && strcasecmp(implicit_host, "whois.apnic.net") == 0) {
                if (ref && !ref_explicit) {
                    free(ref);
                    ref = NULL;
                }
                if (!ref) {
                    if (!wc_lookup_visited_has(visited, visited_count, "whois.apnic.net") && visited_count < 16) {
                        visited[visited_count++] = xstrdup("whois.apnic.net");
                    }
                    apnic_erx_legacy = 1;
                    if (!apnic_erx_root) {
                        apnic_erx_root = 1;
                        if (!apnic_erx_root_host[0]) {
                            snprintf(apnic_erx_root_host, sizeof(apnic_erx_root_host), "%s", "whois.apnic.net");
                        }
                    }
                    need_redir_eval = 1;
                }
            }
            if (header_host && !header_is_iana && !header_matches_current) {
                const char* header_rir = wc_guess_rir(header_host);
                if (header_rir && strcasecmp(header_rir, "unknown") != 0) {
                    if (wc_normalize_whois_host(header_host, header_hint_host, sizeof(header_hint_host)) != 0) {
                        snprintf(header_hint_host, sizeof(header_hint_host), "%s", header_host);
                    }
                    header_hint_valid = (header_hint_host[0] != '\0');
                    need_redir_eval = 1;
                }
            }
        }
        int header_non_authoritative = 0;
        if (current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0 && ripe_non_managed) {
            header_non_authoritative = 1;
            need_redir_eval = 1;
            force_rir_cycle = 1;
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0) {
            if (wc_lookup_body_contains_ipv6_root(body)) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
            } else if (wc_lookup_body_contains_erx_legacy(body)) {
                header_non_authoritative = 1;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0) {
            if (wc_lookup_body_contains_ipv6_root(body)) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
                force_rir_cycle = 1;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "afrinic") == 0) {
            if (wc_lookup_body_contains_ipv6_root(body)) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
                force_rir_cycle = 1;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0) {
            if (wc_lookup_body_contains_no_match(body)) {
                header_non_authoritative = 1;
            }
        }
        if (query_is_cidr_effective && current_rir_guess) {
            if (strcasecmp(current_rir_guess, "arin") == 0 && wc_lookup_body_contains_no_match(body)) {
                seen_arin_no_match_cidr = 1;
            } else if (strcasecmp(current_rir_guess, "ripe") == 0 && ripe_non_managed) {
                seen_ripe_non_managed = 1;
            } else if (strcasecmp(current_rir_guess, "afrinic") == 0 &&
                       wc_lookup_body_contains_full_ipv4_space(body)) {
                seen_afrinic_iana_blk = 1;
            } else if (strcasecmp(current_rir_guess, "lacnic") == 0 &&
                       wc_lookup_body_contains_lacnic_unallocated(body)) {
                seen_lacnic_unallocated = 1;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "lacnic") == 0) {
            if (wc_lookup_body_contains_lacnic_unallocated(body)) {
                header_non_authoritative = 1;
                if (!ref) {
                    need_redir_eval = 1;
                }
            }
        }
        if (wc_lookup_body_contains_full_ipv4_space(body)) {
            header_non_authoritative = 1;
        }
        if (header_non_authoritative) {
            auth = 0;
        }
        if (auth && !header_non_authoritative &&
            !(current_rir_guess && strcasecmp(current_rir_guess, "iana") == 0)) {
            seen_real_authoritative = 1;
        }
        int header_authoritative_stop = (header_matches_current && auth && !header_non_authoritative) ? 1 : 0;
        if (header_host && strcasecmp(header_host, "whois.apnic.net") == 0 && ni.ip[0]) {
            snprintf(apnic_last_ip, sizeof(apnic_last_ip), "%s", ni.ip);
        }
        if (ref && header_host && !header_is_iana) {
            char ref_norm2[128];
            const char* header_norm = wc_dns_canonical_alias(header_host);
            if (!header_norm)
                header_norm = header_host;
            if (wc_normalize_whois_host(ref_host, ref_norm2, sizeof(ref_norm2)) != 0) {
                snprintf(ref_norm2, sizeof(ref_norm2), "%s", ref_host);
            }
            if (strcasecmp(ref_norm2, header_norm) == 0) {
                if (!ref_explicit) {
                    free(ref);
                    ref = NULL;
                    need_redir_eval = 0;
                }
            }
        }
        if (header_authoritative_stop && ref && !ref_explicit && !apnic_erx_keep_ref) {
            free(ref);
            ref = NULL;
        }
        if (header_authoritative_stop && need_redir_eval) {
            need_redir_eval = 0;
        }
        if (apnic_erx_root && header_authoritative_stop) {
            apnic_erx_authoritative_stop = 1;
            need_redir_eval = 0;
            if (ref && !ref_explicit && !apnic_erx_keep_ref) {
                free(ref);
                ref = NULL;
            }
        }
        int apnic_transfer_to_apnic = 0;
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0) {
            apnic_transfer_to_apnic = wc_lookup_body_contains_apnic_transfer_to_apnic(body);
            if (apnic_transfer_to_apnic) {
                need_redir_eval = 0;
                if (ref) {
                    free(ref);
                    ref = NULL;
                }
            }
        }
        int erx_netname = wc_lookup_body_contains_erx_netname(body);
        if (auth && erx_netname && header_host && !header_is_iana) {
            if (!(ref && ref_explicit)) {
                need_redir_eval = 0;
                if (ref) {
                    free(ref);
                    ref = NULL;
                }
            }
        }
        if (auth && header_host && !header_is_iana && !ref && !need_redir_eval) {
            need_redir_eval = 0;
        }
        if (need_redir_eval && auth && !ref && current_rir_guess &&
            strcasecmp(current_rir_guess, "apnic") == 0) {
            // Suppress pivot only for APNIC ERX/transfer notes, not generic
            // "allocated by another RIR" messages.
            if (wc_lookup_body_contains_apnic_erx_hint(body)) {
                if (wc_lookup_body_contains_apnic_erx_hint_strict(body))
                    need_redir_eval = 0;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0) {
            if (!apnic_transfer_to_apnic) {
                apnic_erx_legacy = wc_lookup_body_contains_erx_legacy(body);
                if (apnic_erx_legacy && !apnic_iana_netblock_cidr) {
                    need_redir_eval = 1;
                }
            }
        }
        if (need_redir_eval && auth && header_host && !header_is_iana && !ref &&
            (!current_rir_guess || strcasecmp(current_rir_guess, "apnic") != 0)) {
            char header_norm3[128];
            char current_norm3[128];
            const char* header_normp = wc_dns_canonical_alias(header_host);
            const char* current_normp = wc_dns_canonical_alias(current_host);
            if (!header_normp) header_normp = header_host;
            if (!current_normp) current_normp = current_host;
            if (wc_normalize_whois_host(header_normp, header_norm3, sizeof(header_norm3)) != 0) {
                snprintf(header_norm3, sizeof(header_norm3), "%s", header_normp);
            }
            if (wc_normalize_whois_host(current_normp, current_norm3, sizeof(current_norm3)) != 0) {
                snprintf(current_norm3, sizeof(current_norm3), "%s", current_normp);
            }
            if (strcasecmp(header_norm3, current_norm3) == 0) {
                if (!header_non_authoritative) {
                    need_redir_eval = 0;
                }
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0 && apnic_erx_legacy) {
            if (!apnic_erx_root) {
                apnic_erx_root = 1;
            }
            if (!apnic_erx_root_host[0]) {
                snprintf(apnic_erx_root_host, sizeof(apnic_erx_root_host), "%s", current_host);
            }
            if (!apnic_erx_root_ip[0] && ni.ip[0]) {
                snprintf(apnic_erx_root_ip, sizeof(apnic_erx_root_ip), "%s", ni.ip);
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0 && ni.ip[0]) {
            snprintf(apnic_last_ip, sizeof(apnic_last_ip), "%s", ni.ip);
        }
        if (!apnic_transfer_to_apnic && wc_lookup_body_contains_full_ipv4_space(body)) {
            need_redir_eval = 1;
            force_rir_cycle = 1;
        }
        if (apnic_transfer_to_apnic) {
            need_redir_eval = 0;
        }
        int allow_cycle_on_loop = (need_redir_eval || apnic_erx_legacy) ? 1 : 0;
        if (apnic_erx_authoritative_stop) {
            allow_cycle_on_loop = 0;
        }
        if (hops < 1) {
            allow_cycle_on_loop = 0;
        } else if (apnic_iana_netblock_cidr && !seen_arin_no_match_cidr) {
            allow_cycle_on_loop = 0;
        }
        int need_redir = (!zopts.no_redirect) ? need_redir_eval : 0;

        int apnic_erx_suppress_current = 0;

        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0) {
            if (wc_lookup_find_case_insensitive(body, "non-ripe-ncc-managed-address-block") ||
                wc_lookup_find_case_insensitive(body, "ip address block not managed by the ripe ncc") ||
                wc_lookup_find_case_insensitive(body, "not managed by the ripe ncc")) {
                apnic_erx_ripe_non_managed = 1;
            }
        }
        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0) {
            apnic_erx_suppress_current = 0;
        }
        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0 && apnic_erx_ripe_non_managed) {
            apnic_erx_suppress_current = 0;
        }

        if (!force_rir_cycle && apnic_erx_root && !ref && need_redir_eval) {
            const char* stop_rir = NULL;
            if (apnic_erx_target_rir[0]) {
                stop_rir = apnic_erx_target_rir;
            } else if (apnic_erx_ref_host[0]) {
                stop_rir = wc_guess_rir(apnic_erx_ref_host);
            }
            if (stop_rir && current_rir_guess && strcasecmp(stop_rir, current_rir_guess) == 0) {
                apnic_erx_stop = 1;
                if (apnic_erx_ref_host[0]) {
                    snprintf(apnic_erx_stop_host, sizeof(apnic_erx_stop_host), "%s", apnic_erx_ref_host);
                } else {
                    const char* canon = wc_dns_canonical_host_for_rir(stop_rir);
                    snprintf(apnic_erx_stop_host, sizeof(apnic_erx_stop_host), "%s", canon ? canon : current_host);
                }
            }
        }

        last_hop_authoritative = auth ? 1 : 0;
        last_hop_need_redirect = need_redir_eval ? 1 : 0;
        last_hop_has_ref = ref ? 1 : 0;

        char next_host[128];
        next_host[0] = '\0';
        int have_next = 0;
        int next_port = current_port;
        
        if (!ref) {
            int current_is_arin = (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0);
            int arin_no_match = (current_is_arin && wc_lookup_body_contains_no_match(body));
            int arin_no_match_erx = (arin_no_match && apnic_erx_root);
            if (!have_next && header_hint_valid) {
                if (strcasecmp(header_hint_host, current_host) != 0 &&
                    !wc_lookup_visited_has(visited, visited_count, header_hint_host)) {
                    snprintf(next_host, sizeof(next_host), "%s", header_hint_host);
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "header-hint",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
            }
            if (!have_next && arin_no_match && !apnic_erx_root) {
                if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                        next_host, sizeof(next_host))) {
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "no-match", "rir-cycle",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
            }
            int allow_cycle = allow_cycle_on_loop;
            if (apnic_erx_root && current_rir_guess &&
                (strcasecmp(current_rir_guess, "ripe") == 0 ||
                 strcasecmp(current_rir_guess, "afrinic") == 0 ||
                 strcasecmp(current_rir_guess, "lacnic") == 0)) {
                allow_cycle = 1;
            }
            if (apnic_erx_authoritative_stop) {
                allow_cycle = 0;
            }
            if (arin_no_match_erx) {
                allow_cycle = 1;
            }
            if (apnic_erx_root && auth && !need_redir_eval && current_rir_guess &&
                (strcasecmp(current_rir_guess, "afrinic") == 0 ||
                 strcasecmp(current_rir_guess, "lacnic") == 0)) {
                allow_cycle = 0;
            }
            if (!have_next && hops == 0 && (need_redir_eval || apnic_erx_legacy)) {
                int visited_arin = 0;
                for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], "whois.arin.net")==0) { visited_arin=1; break; } }
                if (!visited_arin && (!current_rir_guess || strcasecmp(current_rir_guess, "arin") != 0)) {
                    snprintf(next_host, sizeof(next_host), "%s", "whois.arin.net");
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "rir-direct",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
            }
            if (!have_next && force_rir_cycle) {
                if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                        next_host, sizeof(next_host))) {
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                } else if (apnic_erx_root) {
                    rir_cycle_exhausted = 1;
                }
            }
            if (!have_next && allow_cycle) {
                if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                        next_host, sizeof(next_host))) {
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                } else if (apnic_erx_root) {
                    rir_cycle_exhausted = 1;
                }
            }

            if (!have_next && hops == 0 && need_redir_eval && !allow_cycle) {
                // Restrict IANA pivot: only from non-ARIN RIRs. Avoid ARIN->IANA and stop at ARIN.
                const char* cur_rir = wc_guess_rir(current_host);
                int is_arin = (cur_rir && strcasecmp(cur_rir, "arin") == 0);
                int is_known = (cur_rir &&
                    (strcasecmp(cur_rir, "apnic") == 0 || strcasecmp(cur_rir, "arin") == 0 ||
                     strcasecmp(cur_rir, "ripe") == 0 || strcasecmp(cur_rir, "afrinic") == 0 ||
                     strcasecmp(cur_rir, "lacnic") == 0 || strcasecmp(cur_rir, "iana") == 0));
                if (!is_arin && !is_known && !cfg->no_iana_pivot) {
                    int visited_iana = 0;
                    for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], "whois.iana.org")==0) { visited_iana=1; break; } }
                    if (strcasecmp(current_host, "whois.iana.org") != 0 && !visited_iana) {
                        snprintf(next_host, sizeof(next_host), "%s", "whois.iana.org");
                        have_next = 1;
                        // mark fallback: iana pivot used
                        out->meta.fallback_flags |= 0x8; // iana_pivot
                        wc_lookup_log_fallback(hops, "manual", "iana-pivot",
                                               current_host, "whois.iana.org", "success",
                                               out->meta.fallback_flags, 0, -1,
                                               pref_label,
                                               net_ctx,
                                               cfg);
                    }
                }
            }
        } else {
            // Selftest: optionally force IANA pivot even if explicit referral exists.
            // Updated semantics: pivot at most once so that a 3-hop flow
            // (e.g., apnic -> iana -> arin) can be simulated. If IANA has
            // already been visited, follow the normal referral instead of
            // forcing IANA again, otherwise a loop guard would terminate at IANA.
            if (fault_profile && fault_profile->force_iana_pivot) {
                int visited_iana = 0;
                for (int i=0; i<visited_count; i++) {
                    if (strcasecmp(visited[i], "whois.iana.org") == 0) { visited_iana = 1; break; }
                }
                if (!visited_iana && strcasecmp(current_host, "whois.iana.org") != 0) {
                    snprintf(next_host, sizeof(next_host), "%s", "whois.iana.org");
                    have_next = 1;
                    out->meta.fallback_flags |= 0x8; // iana_pivot
                } else {
                    // Normal referral path after the one-time pivot
                    if (wc_normalize_whois_host(ref_host, next_host, sizeof(next_host)) != 0) {
                        snprintf(next_host, sizeof(next_host), "%s", ref_host);
                    }
                    have_next = 1;
                    if (ref_port > 0) next_port = ref_port;
                }
            } else {
                if (wc_normalize_whois_host(ref_host, next_host, sizeof(next_host)) != 0) {
                    snprintf(next_host, sizeof(next_host), "%s", ref_host);
                }
                if (hops == 0) {
                    have_next = 1;
                    if (ref_port > 0) next_port = ref_port;
                } else {
                    int visited_ref = 0;
                    for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], next_host)==0) { visited_ref=1; break; } }
                    if (!visited_ref) {
                        have_next = 1;
                        if (ref_port > 0) next_port = ref_port;
                    } else {
                        if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                                next_host, sizeof(next_host))) {
                            have_next = 1;
                            
                            wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                                   current_host, next_host, "success",
                                                   out->meta.fallback_flags, 0, -1,
                                                   pref_label,
                                                   net_ctx,
                                                   cfg);
                        } else if (apnic_erx_root) {
                            rir_cycle_exhausted = 1;
                        }
                    }
                }
            }
        }

        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 && have_next) {
            snprintf(apnic_erx_ref_host, sizeof(apnic_erx_ref_host), "%s", next_host);
        }

    // Append current body to combined output (ownership may transfer below); body can be empty string
    if (!apnic_erx_suppress_current) {
        if (!combined) { combined = body; body = NULL; }
        else { combined = append_and_free(combined, body); free(body); }
    } else if (body) {
        free(body);
        body = NULL;
    }
        hops++; out->meta.hops = hops;

        if (apnic_erx_stop && apnic_erx_stop_host[0]) {
            if (apnic_erx_stop_unknown) {
                const char* apnic_host = apnic_erx_root_host[0] ? apnic_erx_root_host : "whois.apnic.net";
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_host);
                if (apnic_erx_root_ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_erx_root_ip);
                } else {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            } else {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_erx_stop_host);
                if (strcasecmp(current_host, apnic_erx_stop_host) == 0 && ni.ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip);
                } else if (out->meta.via_host[0] && strcasecmp(out->meta.via_host, apnic_erx_stop_host) == 0 && out->meta.via_ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", out->meta.via_ip);
                } else {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            }
            if (ref) { free(ref); ref = NULL; }
            break;
        }

        if (zopts.no_redirect) {
            // Treat no-redirect as an explicit cap: identical to -R 1 semantics.
            out->meta.fallback_flags |= 0x10; // redirect-cap
            if (have_next) {
                redirect_cap_hit = 1;
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            } else {
                if (auth) {
                    // No further hop; treat current as authoritative
                    const char* auth_host = (!header_is_iana && header_host)
                        ? header_host
                        : wc_dns_canonical_alias(current_host);
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
                } else {
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            }
            if (ref) free(ref);
            break;
        }

        if (auth && !need_redir && !ref && !have_next) {
            int apnic_erx_continue = 0;
            if (apnic_erx_root && current_rir_guess) {
                if (strcasecmp(current_rir_guess, "ripe") == 0 && apnic_erx_ripe_non_managed) {
                    apnic_erx_continue = 1;
                } else if (strcasecmp(current_rir_guess, "apnic") == 0 && apnic_erx_legacy) {
                    apnic_erx_continue = 1;
                }
            }
            if (!apnic_erx_continue) {
                int non_auth_count = (seen_apnic_iana_netblock ? 1 : 0) + (seen_ripe_non_managed ? 1 : 0) +
                                     (seen_afrinic_iana_blk ? 1 : 0) + (seen_lacnic_unallocated ? 1 : 0);
                int cidr_global_unknown = (query_is_cidr_effective && !seen_real_authoritative && non_auth_count > 0 &&
                    (seen_arin_no_match_cidr || non_auth_count >= 2));
                if (cidr_global_unknown) {
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                    if (ref) free(ref);
                    break;
                }
                // Current server appears authoritative; stop following to avoid redundant self-redirects
                const char* auth_host = (!header_is_iana && header_host)
                    ? header_host
                    : wc_dns_canonical_alias(current_host);
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
                if (ref) free(ref);
                break;
            }
        }

        // If no explicit referral but redirect seems needed, try via IANA as a safe hub
        if (ref) { free(ref); ref = NULL; }

        if (!have_next && apnic_erx_root && current_rir_guess &&
            (strcasecmp(current_rir_guess, "ripe") == 0 ||
             strcasecmp(current_rir_guess, "afrinic") == 0 ||
             strcasecmp(current_rir_guess, "lacnic") == 0)) {
            if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                    next_host, sizeof(next_host))) {
                have_next = 1;
                wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                       current_host, next_host, "success",
                                       out->meta.fallback_flags, 0, -1,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            } else if (apnic_erx_root) {
                rir_cycle_exhausted = 1;
            }
        }

        if (!have_next) {
            if (apnic_erx_root && current_rir_guess &&
                (strcasecmp(current_rir_guess, "ripe") == 0 ||
                 strcasecmp(current_rir_guess, "afrinic") == 0 ||
                 strcasecmp(current_rir_guess, "lacnic") == 0)) {
                rir_cycle_exhausted = 1;
                break;
            }
            {
                int non_auth_count = (seen_apnic_iana_netblock ? 1 : 0) + (seen_ripe_non_managed ? 1 : 0) +
                                     (seen_afrinic_iana_blk ? 1 : 0) + (seen_lacnic_unallocated ? 1 : 0);
                int cidr_global_unknown = (query_is_cidr_effective && !seen_real_authoritative && non_auth_count > 0 &&
                    (seen_arin_no_match_cidr || non_auth_count >= 2));
                if (cidr_global_unknown) {
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                    break;
                }
            }
            if (auth) {
                // No referral and no need to redirect -> treat current as authoritative
                const char* auth_host = (!header_is_iana && header_host)
                    ? header_host
                    : wc_dns_canonical_alias(current_host);
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            } else {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            }
            break;
        }

        if (have_next && auth) {
            pending_referral = 1;
        }

        if (have_next && hops >= zopts.max_hops) {
            // Redirect chain would exceed the configured hop budget; stop immediately.
            redirect_cap_hit = 1;
            out->meta.fallback_flags |= 0x10; // redirect-cap
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            break;
        }

        int force_original_next = (arin_retry_active && have_next && query_is_cidr);
        if (have_next && query_is_cidr_effective && !force_original_next) {
            const char* next_rir = wc_guess_rir(next_host);
            if (next_rir && strcasecmp(next_rir, "apnic") == 0) {
                apnic_force_ip = 1;
            }
        }

        // loop guard
        int loop = 0;
        for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], next_host)==0) { loop=1; break; } }
        if (loop && !apnic_revisit_used && apnic_force_ip &&
            strcasecmp(next_host, start_host) == 0) {
            loop = 0;
            apnic_revisit_used = 1;
        }
        if (loop && allow_cycle_on_loop) {
            char cycle_host[128]; cycle_host[0] = '\0';
            if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                    cycle_host, sizeof(cycle_host))) {
                if (strcasecmp(cycle_host, next_host) != 0) {
                    snprintf(next_host, sizeof(next_host), "%s", cycle_host);
                    loop = 0;
                }
            }
        }
        if (loop || strcasecmp(next_host, current_host)==0) {
            int non_auth_count = (seen_apnic_iana_netblock ? 1 : 0) + (seen_ripe_non_managed ? 1 : 0) +
                                 (seen_afrinic_iana_blk ? 1 : 0) + (seen_lacnic_unallocated ? 1 : 0);
            int cidr_global_unknown = (query_is_cidr_effective && !seen_real_authoritative && non_auth_count > 0 &&
                (seen_arin_no_match_cidr || non_auth_count >= 2));
            if (apnic_erx_root) {
                rir_cycle_exhausted = 1;
            }
            if (cidr_global_unknown) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                break;
            }
            if (auth) {
                const char* auth_host = (!header_is_iana && header_host)
                    ? header_host
                    : wc_dns_canonical_alias(current_host);
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            } else {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            }
            break;
        }

        // insert heading for the upcoming hop
        if (emit_redirect_headers) {
            char hdr[256];
            if (!additional_emitted) {
                snprintf(hdr, sizeof(hdr), "\n=== Additional query to %s ===\n", next_host);
                additional_emitted = 1;
            } else {
                snprintf(hdr, sizeof(hdr), "\n=== Redirected query to %s ===\n", next_host);
            }
            combined = append_and_free(combined, hdr);
        }

        // advance to next
        snprintf(current_host, sizeof(current_host), "%s", next_host);
        current_port = next_port;
        force_original_query = force_original_next;
        // continue loop for next hop
    }
    if (cidr_base_query) {
        free(cidr_base_query);
        cidr_base_query = NULL;
    }

    // finalize result
    if (combined && out->meta.authoritative_host[0] == '\0' && !redirect_cap_hit) {
        // best-effort only when the last hop looks authoritative and no redirect was indicated
        if (last_hop_authoritative && !last_hop_need_redirect && !last_hop_has_ref) {
            const char* fallback_host = current_host[0]?current_host:start_host;
            const char* auth_host = wc_dns_canonical_alias(fallback_host);
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : fallback_host);
        } else {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
        }
    }
    if (redirect_cap_hit && out->meta.authoritative_host[0] == '\0') {
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
    }
    if (redirect_cap_hit && out->meta.authoritative_ip[0] == '\0') {
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
    }
    if (out->meta.authoritative_host[0] &&
        strcasecmp(out->meta.authoritative_host, "unknown") == 0) {
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
    }

    if (apnic_erx_root && apnic_erx_seen_arin && combined) {
        const char* final_rir = (out->meta.authoritative_host[0]
            ? wc_guess_rir(out->meta.authoritative_host)
            : NULL);
        if (!apnic_erx_keep_arin_body &&
            (final_rir && strcasecmp(final_rir, "apnic") == 0)) {
            wc_lookup_strip_hop_body_keep_header(combined, "whois.arin.net");
        }
    }

    if (apnic_erx_root && !redirect_cap_hit) {
        const char* apnic_host = apnic_erx_root_host[0] ? apnic_erx_root_host : "whois.apnic.net";
        if (wc_dns_is_ip_literal(apnic_host)) {
            const char* mapped = wc_lookup_known_ip_host_from_literal(apnic_host);
            apnic_host = mapped ? mapped : "whois.apnic.net";
        }
        const char* final_rir = (out->meta.authoritative_host[0]
            ? wc_guess_rir(out->meta.authoritative_host)
            : NULL);
        int non_apnic_authority = (final_rir &&
            (strcasecmp(final_rir, "ripe") == 0 ||
             strcasecmp(final_rir, "afrinic") == 0 ||
             strcasecmp(final_rir, "lacnic") == 0));
        int authoritative_apnic = (out->meta.authoritative_host[0] && strcasecmp(out->meta.authoritative_host, apnic_host) == 0);
        int apnic_ip_mismatch = (authoritative_apnic && out->meta.authoritative_ip[0] &&
            !wc_lookup_ip_matches_host(out->meta.authoritative_ip, apnic_host));
        int should_collapse = redirect_cap_hit || rir_cycle_exhausted || apnic_ip_mismatch ||
            (authoritative_apnic && (out->meta.authoritative_ip[0] == '\0' || strcasecmp(out->meta.authoritative_ip, "unknown") == 0));
        if (should_collapse) {
            int visited_arin = wc_lookup_visited_has(visited, visited_count, "whois.arin.net");
            int visited_ripe = wc_lookup_visited_has(visited, visited_count, "whois.ripe.net");
            int visited_afrinic = wc_lookup_visited_has(visited, visited_count, "whois.afrinic.net");
            int visited_lacnic = wc_lookup_visited_has(visited, visited_count, "whois.lacnic.net");
            int insert_all = (out->meta.fallback_flags & 0x10) || rir_cycle_exhausted || non_apnic_authority ? 1 : 0;
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_host);
            if (apnic_erx_root_ip[0] && wc_lookup_ip_matches_host(apnic_erx_root_ip, apnic_host)) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_erx_root_ip);
            } else if (apnic_last_ip[0] && wc_lookup_ip_matches_host(apnic_last_ip, apnic_host)) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_last_ip);
            } else if (out->meta.via_host[0] && strcasecmp(out->meta.via_host, apnic_host) == 0 && out->meta.via_ip[0]) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", out->meta.via_ip);
            } else {
                const char* known_apnic_ip = wc_dns_get_known_ip(apnic_host);
                if (known_apnic_ip && known_apnic_ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", known_apnic_ip);
                } else {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            }
            if (!apnic_erx_keep_arin_body) {
                wc_lookup_strip_hop_body_keep_header(combined, "whois.arin.net");
            }
            wc_lookup_strip_hop_body_keep_header(combined, "whois.ripe.net");
            wc_lookup_strip_hop_body_keep_header(combined, "whois.afrinic.net");
            wc_lookup_strip_hop_body_keep_header(combined, "whois.lacnic.net");
            if ((insert_all || visited_arin) && !wc_lookup_has_hop_header(combined, "whois.arin.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.arin.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.arin.net");
            }
            if ((insert_all || visited_ripe) && !wc_lookup_has_hop_header(combined, "whois.ripe.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.ripe.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.ripe.net");
            }
            if ((insert_all || visited_afrinic) && !wc_lookup_has_hop_header(combined, "whois.afrinic.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.afrinic.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.afrinic.net");
            }
            if ((insert_all || visited_lacnic) && !wc_lookup_has_hop_header(combined, "whois.lacnic.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.lacnic.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.lacnic.net");
            }
            wc_lookup_compact_hop_headers(combined);
        }
    }
    if (combined) {
        wc_lookup_compact_hop_headers(combined);
    }
    out->body = combined;
    out->body_len = (combined ? strlen(combined) : 0);

    if (arin_cidr_retry_query) {
        free(arin_cidr_retry_query);
        arin_cidr_retry_query = NULL;
    }

    // free visited list
    for (int i=0;i<16;i++) { if (visited[i]) free(visited[i]); }
    // defensive: free candidates if still allocated
    // (should be NULL unless we broke early before advancing)
    // candidates is local to the loop, but in case of refactor keep this safe-guard here

    // If there is a non-zero error code (e.g., connection failure during the redirection phase), 
    // even if some output has already been accumulated, a failure should be returned to allow the frontend to print the error.
    if (out->err) return out->err;
    return (out->body ? 0 : -1);
}
