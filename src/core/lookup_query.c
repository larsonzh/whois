// SPDX-License-Identifier: MIT
// lookup_query.c - Query parsing helpers for lookup

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

#include "wc/wc_dns.h"
#include "wc/wc_lookup.h"
#include "lookup_internal.h"

static const char* wc_lookup_skip_leading_space(const char* text) {
    if (!text) return "";
    while (*text && isspace((unsigned char)*text)) {
        ++text;
    }
    return text;
}

int wc_lookup_query_has_arin_prefix(const char* query) {
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

char* wc_lookup_extract_cidr_base(const char* query)
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

int wc_lookup_query_is_ipv4_literal(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed) return 0;
    if (!wc_dns_is_ip_literal(trimmed)) return 0;
    return strchr(trimmed, ':') == NULL;
}

int wc_lookup_query_is_ip_literal(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    return (trimmed && *trimmed && wc_dns_is_ip_literal(trimmed) && strchr(trimmed, '/') == NULL);
}

int wc_lookup_query_is_cidr(const char* query) {
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
    if (endp && *endp) return 0;
    int max_plen = (strchr(base, ':') != NULL) ? 128 : 32;
    if (plen < 0 || plen > max_plen) return 0;
    return 1;
}

int wc_lookup_query_is_asn(const char* query) {
    const char* trimmed = wc_lookup_skip_leading_space(query);
    if (!trimmed || !*trimmed) return 0;
    if (strncasecmp(trimmed, "AS", 2) != 0) return 0;
    const char* p = trimmed + 2;
    if (!isdigit((unsigned char)*p)) return 0;
    while (*p && isdigit((unsigned char)*p)) ++p;
    while (*p && isspace((unsigned char)*p)) ++p;
    return *p == '\0';
}

int wc_lookup_query_is_arin_nethandle(const char* query) {
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
