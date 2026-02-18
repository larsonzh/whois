// SPDX-License-Identifier: MIT
// lookup_text.c - Text parsing helpers for lookup

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>

#include "wc/wc_redirect.h"
#include "lookup_internal.h"

const char* wc_lookup_find_case_insensitive(const char* haystack, const char* needle) {
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

int wc_lookup_line_contains_case_insensitive(const char* line, size_t len, const char* needle) {
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

int wc_lookup_line_starts_with_case_insensitive_n(const char* line, size_t len, const char* prefix) {
    if (!line || !prefix) return 0;
    size_t plen = strlen(prefix);
    if (plen == 0 || plen > len) return 0;
    for (size_t i = 0; i < plen; ++i) {
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)prefix[i])) return 0;
    }
    return 1;
}

int wc_lookup_body_contains_no_match(const char* body) {
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

int wc_lookup_body_contains_ripe_non_managed(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "non-ripe-ncc-managed-address-block")) return 1;
    if (wc_lookup_find_case_insensitive(body, "ip address block not managed by the ripe ncc")) return 1;
    if (wc_lookup_find_case_insensitive(body, "not managed by the ripe ncc")) return 1;
    return 0;
}

int wc_lookup_body_has_non_authoritative_marker(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "query terms are ambiguous")) return 1;
    if (wc_lookup_find_case_insensitive(body, "not fully allocated to")) return 1;
    if (wc_lookup_find_case_insensitive(body, "not allocated to")) return 1;
    if (wc_lookup_find_case_insensitive(body, "not registered in")) return 1;
    if (wc_lookup_find_case_insensitive(body, "not in database")) return 1;
    if (wc_lookup_find_case_insensitive(body, "no match")) return 1;
    if (wc_lookup_find_case_insensitive(body, "unallocated and unassigned in lacnic block")) return 1;
    if (wc_lookup_find_case_insensitive(body, "accepts only direct match queries")) return 1;
    if (wc_lookup_body_contains_ripe_non_managed(body)) return 1;
    return 0;
}

int wc_lookup_body_has_strong_redirect_hint(const char* body) {
    return wc_lookup_body_has_non_authoritative_marker(body);
}

int wc_lookup_body_is_semantically_empty(const char* body) {
    if (!body || !*body) return 1;
    if (strspn(body, " \r\n\t") == strlen(body)) return 1;
    if (!wc_lookup_body_is_comment_only(body)) return 0;
    if (wc_lookup_body_has_non_authoritative_marker(body)) return 0;
    return 1;
}

int wc_lookup_body_is_arin_banner_only(const char* body) {
    if (!body || !*body) return 0;
    if (!wc_lookup_find_case_insensitive(body,
            "ARIN WHOIS data and services are subject to the Terms of Use")) {
        return 0;
    }
    if (is_authoritative_response(body)) return 0;
    if (wc_lookup_body_has_strong_redirect_hint(body)) return 0;
    return 1;
}

int wc_lookup_body_contains_apnic_iana_netblock(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "iana-netblock")) return 1;
    if (wc_lookup_find_case_insensitive(body, "not allocated to apnic")) return 1;
    if (wc_lookup_find_case_insensitive(body, "not fully allocated to apnic")) return 1;
    return 0;
}

int wc_lookup_body_contains_apnic_iana_not_allocated_disclaimer(const char* body) {
    if (!body || !*body) return 0;
    return (wc_lookup_find_case_insensitive(body, "iana-netblock-8") &&
            wc_lookup_find_case_insensitive(body, "not allocated to apnic"))
               ? 1
               : 0;
}

int wc_lookup_body_contains_lacnic_rate_limit(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "query rate limit exceeded")) return 1;
    if (wc_lookup_find_case_insensitive(body, "rate limit exceeded")) return 1;
    if (wc_lookup_find_case_insensitive(body, "query limit exceeded")) return 1;
    return 0;
}

int wc_lookup_body_contains_rate_limit(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "query rate limit exceeded")) return 1;
    if (wc_lookup_find_case_insensitive(body, "rate limit exceeded")) return 1;
    if (wc_lookup_find_case_insensitive(body, "query limit exceeded")) return 1;
    if (wc_lookup_find_case_insensitive(body, "excessive querying")) return 1;
    return 0;
}

int wc_lookup_body_contains_access_denied(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "%error:201")) return 1;
    if (wc_lookup_find_case_insensitive(body, "access denied")) return 1;
    if (wc_lookup_find_case_insensitive(body, "excessive querying")) return 1;
    if (wc_lookup_find_case_insensitive(body, "permanently denied")) return 1;
    if (wc_lookup_find_case_insensitive(body, "temporarily denied")) return 1;
    return 0;
}

int wc_lookup_body_contains_temporary_denied(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_body_contains_rate_limit(body)) return 1;
    if (wc_lookup_find_case_insensitive(body, "temporarily denied")) return 1;
    return 0;
}

int wc_lookup_body_contains_permanent_denied(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "permanently denied")) return 1;
    return 0;
}

int wc_lookup_body_contains_ripe_access_denied(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "access denied")) return 1;
    if (wc_lookup_find_case_insensitive(body, "%error:201")) return 1;
    return 0;
}

static int wc_lookup_line_contains_access_denied(const char* line, size_t len) {
    if (!line || len == 0) return 0;
    char stack_buf[512];
    char* buf = NULL;
    if (len + 1 <= sizeof(stack_buf)) {
        buf = stack_buf;
    } else {
        buf = (char*)malloc(len + 1);
        if (!buf) return 0;
    }
    memcpy(buf, line, len);
    buf[len] = '\0';
    int hit = 0;
    if (wc_lookup_find_case_insensitive(buf, "%error:201")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "access denied")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "access from your host has been")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "excessive querying")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "permanently denied")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "temporarily denied")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "for more information, see")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "why-did-i-receive-an-error-201-access-denied")) hit = 1;
    if (buf != stack_buf) free(buf);
    return hit;
}

char* wc_lookup_strip_access_denied_lines(const char* body) {
    if (!body) return NULL;
    size_t total_len = strlen(body);
    char* out = (char*)malloc(total_len + 1);
    if (!out) return NULL;
    const char* r = body;
    char* w = out;
    while (*r) {
        const char* line_end = r;
        while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;
        size_t line_len = (size_t)(line_end - r);
        size_t full_len = line_len;
        if (*line_end == '\r' && line_end[1] == '\n') {
            full_len += 2;
        } else if (*line_end == '\r' || *line_end == '\n') {
            full_len += 1;
        }
        if (!wc_lookup_line_contains_access_denied(r, line_len)) {
            memcpy(w, r, full_len);
            w += full_len;
        }
        if (*line_end == '\r' && line_end[1] == '\n') {
            r = line_end + 2;
        } else if (*line_end == '\r' || *line_end == '\n') {
            r = line_end + 1;
        } else {
            r = line_end;
        }
    }
    *w = '\0';
    return out;
}

static int wc_lookup_line_contains_rate_limit(const char* line, size_t len) {
    if (!line || len == 0) return 0;
    char stack_buf[512];
    char* buf = NULL;
    if (len + 1 <= sizeof(stack_buf)) {
        buf = stack_buf;
    } else {
        buf = (char*)malloc(len + 1);
        if (!buf) return 0;
    }
    memcpy(buf, line, len);
    buf[len] = '\0';
    int hit = 0;
    if (wc_lookup_find_case_insensitive(buf, "query rate limit exceeded")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "rate limit exceeded")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "query limit exceeded")) hit = 1;
    else if (wc_lookup_find_case_insensitive(buf, "excessive querying")) hit = 1;
    if (buf != stack_buf) free(buf);
    return hit;
}

char* wc_lookup_strip_rate_limit_lines(const char* body) {
    if (!body) return NULL;
    size_t total_len = strlen(body);
    char* out = (char*)malloc(total_len + 1);
    if (!out) return NULL;
    const char* r = body;
    char* w = out;
    while (*r) {
        const char* line_end = r;
        while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;
        size_t line_len = (size_t)(line_end - r);
        size_t full_len = line_len;
        if (*line_end == '\r' && line_end[1] == '\n') {
            full_len += 2;
        } else if (*line_end == '\r' || *line_end == '\n') {
            full_len += 1;
        }
        if (!wc_lookup_line_contains_rate_limit(r, line_len)) {
            memcpy(w, r, full_len);
            w += full_len;
        }
        if (*line_end == '\r' && line_end[1] == '\n') {
            r = line_end + 2;
        } else if (*line_end == '\r' || *line_end == '\n') {
            r = line_end + 1;
        } else {
            r = line_end;
        }
    }
    *w = '\0';
    return out;
}

void wc_lookup_format_time(char* buf, size_t cap) {
    if (!buf || cap == 0) return;
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    if (t) {
        if (strftime(buf, cap, "%Y-%m-%d %H:%M:%S", t) != 0) {
            return;
        }
    }
    if (cap > 0) {
        snprintf(buf, cap, "0000-00-00 00:00:00");
    }
}

int wc_lookup_body_contains_apnic_erx_hint(const char* body) {
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

int wc_lookup_body_contains_apnic_erx_hint_strict(const char* body) {
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

int wc_lookup_body_contains_erx_legacy(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "early registration addresses")) return 1;
    if (wc_lookup_find_case_insensitive(body, "erx-netblock")) return 1;
    return 0;
}

int wc_lookup_body_contains_apnic_transfer_to_apnic(const char* body) {
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

int wc_lookup_body_contains_erx_netname(const char* body) {
    if (!body || !*body) return 0;
    if (!wc_lookup_find_case_insensitive(body, "netname:")) return 0;
    if (wc_lookup_find_case_insensitive(body, "erx-netblock")) return 1;
    return 0;
}

int wc_lookup_body_contains_lacnic_unallocated(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "Unallocated and unassigned in LACNIC block")) return 1;
    return 0;
}

int wc_lookup_body_contains_erx_iana_marker(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "erx-netblock")) return 1;
    if (wc_lookup_find_case_insensitive(body, "iana-netblock")) return 1;
    return 0;
}

int wc_lookup_body_is_comment_only(const char* body) {
    if (!body || !*body) return 1;
    const char* p = body;
    while (*p) {
        const char* line_start = p;
        while (*p && *p != '\n' && *p != '\r') {
            ++p;
        }
        const char* line_end = p;
        while (*p == '\r' || *p == '\n') {
            ++p;
        }
        while (line_start < line_end && isspace((unsigned char)*line_start)) {
            ++line_start;
        }
        if (line_start == line_end) {
            continue;
        }
        if (*line_start == '%' || *line_start == '#') {
            continue;
        }
        return 0;
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

const char* wc_lookup_detect_rir_header_host(const char* body) {
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

int wc_lookup_body_contains_full_ipv4_space(const char* body) {
    if (!body || !*body) return 0;
    if (wc_lookup_find_case_insensitive(body, "IANA-BLK")) return 1;
    const char* hit = body;
    while ((hit = wc_lookup_find_case_insensitive(hit, "0.0.0.0 - 255.255.255.255")) != NULL) {
        const char* line_start = hit;
        while (line_start > body && line_start[-1] != '\n' && line_start[-1] != '\r') {
            --line_start;
        }
        while (*line_start == ' ' || *line_start == '\t') ++line_start;
        const char* line_end = line_start;
        while (*line_end && *line_end != '\n' && *line_end != '\r') ++line_end;
        size_t line_len = (size_t)(line_end - line_start);
        if (wc_lookup_line_starts_with_case_insensitive_n(line_start, line_len, "inetnum:") ||
            wc_lookup_line_starts_with_case_insensitive_n(line_start, line_len, "netrange:")) {
            return 1;
        }
        hit += 1;
    }
    return 0;
}

int wc_lookup_body_contains_ipv6_root(const char* body) {
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
