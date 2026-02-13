// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "wc/wc_redirect.h"
#include "wc/wc_output.h"

static int wc_redirect_debug_enabled(void)
{
    return wc_output_is_debug_enabled();
}

// Provide local strdup for strict C11 environments that lack POSIX prototypes
static char* safe_strdup_local(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* p = (char*)malloc(len);
    if (!p) return NULL;
    memcpy(p, s, len);
    return p;
}
#undef strdup
#define strdup safe_strdup_local

// Local helpers (internal to this module)
static int contains_case_insensitive(const char* haystack, const char* needle) {
    if (!haystack || !needle || *needle == '\0') return 0;
    size_t needle_len = strlen(needle);
    for (const char* hp = haystack; *hp; hp++) {
        size_t idx = 0;
        while (hp[idx] && idx < needle_len &&
               tolower((unsigned char)hp[idx]) == tolower((unsigned char)needle[idx])) {
            idx++;
        }
        if (idx == needle_len) return 1;
    }
    return 0;
}

static int is_host_char(unsigned char c) {
    return (isalnum(c) || c == '-' || c == '.');
}

static int has_host_token_boundary(const char* base, const char* pos, size_t len) {
    if (!base || !pos) return 0;
    if (pos > base && is_host_char((unsigned char)pos[-1])) return 0;
    if (pos[len] && is_host_char((unsigned char)pos[len])) return 0;
    return 1;
}

static int starts_with_case_insensitive(const char* str, const char* prefix);

static int is_in_remarks_line(const char* base, const char* pos) {
    if (!base || !pos || pos < base) return 0;

    const char* line_start = pos;
    while (line_start > base && line_start[-1] != '\n' && line_start[-1] != '\r') {
        line_start--;
    }
    while (*line_start == ' ' || *line_start == '\t') {
        line_start++;
    }
    return starts_with_case_insensitive(line_start, "remarks:");
}

static const char* find_case_insensitive(const char* haystack, const char* needle) {
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

static int starts_with_case_insensitive(const char* str, const char* prefix) {
    if (!str || !prefix) return 0;
    while (*prefix && *str) {
        if (tolower((unsigned char)*str) != tolower((unsigned char)*prefix)) return 0;
        str++;
        prefix++;
    }
    return *prefix == '\0';
}

static int has_full_ipv4_guard_line(const char* response) {
    if (!response) return 0;
    const char* patterns[] = {"0.0.0.0 - 255.255.255.255", "0.0.0.0/0", NULL};
    const char* prefixes[] = {"inetnum:", "netrange:", NULL};

    for (int p = 0; patterns[p] != NULL; p++) {
        const char* hit = response;
        while ((hit = strstr(hit, patterns[p])) != NULL) {
            const char* line_start = hit;
            while (line_start > response && line_start[-1] != '\n' && line_start[-1] != '\r') {
                line_start--;
            }
            while (*line_start == ' ' || *line_start == '\t') line_start++;
            for (int pref = 0; prefixes[pref] != NULL; pref++) {
                if (starts_with_case_insensitive(line_start, prefixes[pref])) {
                    return 1;
                }
            }
            hit++;
        }
    }
    return 0;
}

static int has_full_ipv6_guard_line(const char* response) {
    if (!response) return 0;
    const char* patterns[] = {
        "::/0",
        "0:0:0:0:0:0:0:0 - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        NULL
    };
    const char* prefixes[] = {"inet6num:", "netrange:", NULL};

    for (int p = 0; patterns[p] != NULL; p++) {
        const char* hit = response;
        while ((hit = strstr(hit, patterns[p])) != NULL) {
            const char* line_start = hit;
            while (line_start > response && line_start[-1] != '\n' && line_start[-1] != '\r') {
                line_start--;
            }
            while (*line_start == ' ' || *line_start == '\t') line_start++;
            for (int pref = 0; prefixes[pref] != NULL; pref++) {
                if (starts_with_case_insensitive(line_start, prefixes[pref])) {
                    return 1;
                }
            }
            hit++;
        }
    }
    return 0;
}

// Minimal safety validation for redirect target (domain or IP-ish token),
// without relying on client's internal validators to avoid cyclic deps.
static int simple_validate_redirect(const char* s) {
    if (!s || !*s) return 0;
    // Reject obvious local/private markers
    const char* bad[] = {"localhost", "127.", "0.0.0.0", "::1", "10.", "192.168.",
                         "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                         "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                         "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
                         "172.31.", NULL};
    for (int i = 0; bad[i]; i++) {
        if (strstr(s, bad[i])) return 0;
    }
    // Basic charset check (letters, digits, dashes, dots, colons)
    for (const char* p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '-' || c == '.' || c == ':' )) return 0;
    }
    // Very short tokens are suspicious
    if (strlen(s) < 3) return 0;
    return 1;
}

char* extract_refer_server(const char* response) {
    const int debug = wc_redirect_debug_enabled();
    if (debug) printf("[DEBUG] ===== EXTRACTING REFER SERVER =====\n");
    if (!response) return NULL;

    // Invalid IPv4/IPv6 ranges (limited to inetnum/NetRange lines)
    if (has_full_ipv4_guard_line(response) || has_full_ipv6_guard_line(response)) {
        if (wc_redirect_debug_enabled())
            printf("[DEBUG] Invalid full-space response detected, deferring to caller\n");
        return NULL;
    }

    // IANA block hint
    if (strstr(response, "IANA-BLK") != NULL &&
        strstr(response, "whole IPv4 address space") != NULL) {
        if (wc_redirect_debug_enabled())
            printf("[DEBUG] IANA default block hint, deferring to caller\n");
        return NULL;
    }

    // Copy to parse lines safely
    char* response_copy = strdup(response);
    if (!response_copy) {
        if (debug) printf("[DEBUG] Memory allocation failed for response copy\n");
        return NULL;
    }

    char* line = strtok(response_copy, "\n");
    char* whois_server = NULL;

    while (line != NULL) {
        if (strlen(line) > 0 && line[0] != '#') {
            const char* line_trim = line;
            while (*line_trim == ' ' || *line_trim == '\t')
                ++line_trim;
            if (wc_redirect_debug_enabled()) printf("[DEBUG] Analyzing line: %s\n", line_trim);

            char* pos = NULL;
            if (starts_with_case_insensitive(line_trim, "ReferralServer:")) {
                pos = (char*)line_trim + strlen("ReferralServer:");
                while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
                if (strlen(pos) > 0) {
                    char* end = pos;
                    while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
                    size_t len = (size_t)(end - pos);
                    whois_server = (char*)malloc(len + 1);
                    if (!whois_server) { free(response_copy); return NULL; }
                    strncpy(whois_server, pos, len);
                    whois_server[len] = '\0';

                    // Trim trailing spaces/punctuations
                    char* p = whois_server + strlen(whois_server) - 1;
                    while (p >= whois_server && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '.' || *p == ',')) {
                        *p-- = '\0';
                    }
                    // Strip whois:// or rwhois:// prefix if present
                    if (strncmp(whois_server, "whois://", 8) == 0) {
                        memmove(whois_server, whois_server + 8, strlen(whois_server + 8) + 1);
                    } else if (strncmp(whois_server, "rwhois://", 9) == 0) {
                        memmove(whois_server, whois_server + 9, strlen(whois_server + 9) + 1);
                    }
                    if (debug) printf("[DEBUG] Found ReferralServer: %s\n", whois_server);
                }
            }

            if (!whois_server) {
                if (starts_with_case_insensitive(line_trim, "refer:")) {
                    pos = (char*)line_trim + strlen("refer:");
                    while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
                    if (strlen(pos) > 0) {
                        char* end = pos;
                        while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
                        size_t len = (size_t)(end - pos);
                        whois_server = (char*)malloc(len + 1);
                        if (!whois_server) { free(response_copy); return NULL; }
                        strncpy(whois_server, pos, len);
                        whois_server[len] = '\0';
                        if (wc_redirect_debug_enabled()) printf("[DEBUG] Found refer: directive: %s\n", whois_server);
                    }
                } else if (starts_with_case_insensitive(line_trim, "whois:")) {
                    pos = (char*)line_trim + strlen("whois:");
                    while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
                    if (strlen(pos) > 0) {
                        char* end = pos;
                        while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
                        size_t len = (size_t)(end - pos);
                        whois_server = (char*)malloc(len + 1);
                        if (!whois_server) { free(response_copy); return NULL; }
                        strncpy(whois_server, pos, len);
                        whois_server[len] = '\0';
                        if (wc_redirect_debug_enabled()) printf("[DEBUG] Found whois: directive: %s\n", whois_server);
                    }
                } else if (starts_with_case_insensitive(line_trim, "ResourceLink:")) {
                    const char* whois_pos = find_case_insensitive(line_trim, "whois://");
                    if (whois_pos) {
                        whois_pos += strlen("whois://");
                        const char* end = whois_pos;
                        while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
                        size_t len = (size_t)(end - whois_pos);
                        if (len > 0) {
                            whois_server = (char*)malloc(len + 1);
                            if (!whois_server) { free(response_copy); return NULL; }
                            strncpy(whois_server, whois_pos, len);
                            whois_server[len] = '\0';
                            if (wc_redirect_debug_enabled()) printf("[DEBUG] Found ResourceLink whois: %s\n", whois_server);
                        }
                    } else {
                        const char* whois_host = find_case_insensitive(line_trim, "whois.");
                        if (whois_host) {
                            const char* end = whois_host;
                            while (*end && is_host_char((unsigned char)*end)) end++;
                            size_t len = (size_t)(end - whois_host);
                            if (len > 0 && has_host_token_boundary(line_trim, whois_host, len)) {
                                whois_server = (char*)malloc(len + 1);
                                if (!whois_server) { free(response_copy); return NULL; }
                                strncpy(whois_server, whois_host, len);
                                whois_server[len] = '\0';
                                if (wc_redirect_debug_enabled()) printf("[DEBUG] Found ResourceLink whois (no scheme): %s\n", whois_server);
                            }
                        }
                    }
                }
            }
        }
        line = strtok(NULL, "\n");
    }

    free(response_copy);

    // Fallback: find ReferralServer anywhere if line parsing missed it.
    if (!whois_server) {
        const char* pos = find_case_insensitive(response, "ReferralServer:");
        if (pos) {
            pos += strlen("ReferralServer:");
            while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
            if (*pos) {
                const char* end = pos;
                while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
                size_t len = (size_t)(end - pos);
                whois_server = (char*)malloc(len + 1);
                if (whois_server) {
                    strncpy(whois_server, pos, len);
                    whois_server[len] = '\0';
                    if (strncmp(whois_server, "whois://", 8) == 0) {
                        memmove(whois_server, whois_server + 8, strlen(whois_server + 8) + 1);
                    } else if (strncmp(whois_server, "rwhois://", 9) == 0) {
                        memmove(whois_server, whois_server + 9, strlen(whois_server + 9) + 1);
                    }
                    if (wc_redirect_debug_enabled())
                        printf("[DEBUG] Fallback ReferralServer: %s\n", whois_server);
                }
            }
        }
    }

    if (!whois_server) {
        const char* pos = find_case_insensitive(response, "ResourceLink:");
        if (pos) {
            const char* whois_pos = find_case_insensitive(pos, "whois://");
            if (whois_pos) {
                whois_pos += strlen("whois://");
                const char* end = whois_pos;
                while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') end++;
                size_t len = (size_t)(end - whois_pos);
                if (len > 0) {
                    whois_server = (char*)malloc(len + 1);
                    if (whois_server) {
                        strncpy(whois_server, whois_pos, len);
                        whois_server[len] = '\0';
                        if (wc_redirect_debug_enabled())
                            printf("[DEBUG] Fallback ResourceLink whois: %s\n", whois_server);
                    }
                }
            }
        }
    }

    if (!whois_server) {
        const char* candidates[] = {
            "whois.apnic.net",
            "whois.ripe.net",
            "whois.lacnic.net",
            "whois.afrinic.net",
            "whois.arin.net",
            NULL
        };
        for (int i = 0; candidates[i] != NULL && !whois_server; i++) {
            const char* hit = find_case_insensitive(response, candidates[i]);
            if (hit &&
                has_host_token_boundary(response, hit, strlen(candidates[i])) &&
                !is_in_remarks_line(response, hit)) {
                whois_server = strdup(candidates[i]);
                if (whois_server && wc_redirect_debug_enabled())
                    printf("[DEBUG] Fallback whois host hint: %s\n", whois_server);
            }
        }
    }

    if (whois_server && strchr(whois_server, '.') != NULL && strlen(whois_server) > 3) {
        if (!simple_validate_redirect(whois_server)) {
                if (wc_redirect_debug_enabled()) printf("[DEBUG] Invalid redirect target rejected: %s\n", whois_server);
            free(whois_server);
            whois_server = NULL;
        } else {
                if (wc_redirect_debug_enabled()) printf("[DEBUG] Extracted refer server: %s\n", whois_server);
        }
        return whois_server;
    }

    // No explicit refer server found; return NULL and let the caller decide (e.g., via needs_redirect -> IANA)
        if (wc_redirect_debug_enabled()) printf("[DEBUG] No explicit refer server found in response\n");
    return NULL;
}

int is_authoritative_response(const char* response) {
        if (wc_redirect_debug_enabled()) printf("[DEBUG] ===== CHECKING AUTHORITATIVE RESPONSE =====\n");
    if (!response) return 0;

    const char* indicators[] = {
        "inetnum:",   "inet6num:",      "netname:",   "descr:",
        "country:",   "status:",        "person:",    "role:",
        "irt:",       "admin-c:",       "tech-c:",    "abuse-c:",
        "mnt-by:",    "mnt-irt:",       "mnt-lower:", "mnt-routes:",
        "source:",    "last-modified:", "NetRange:",  "CIDR:",
        "NetName:",   "NetHandle:",     "NetType:",   "Organization:",
        "OrgName:",   "OrgId:",         "Address:",   "City:",
        "StateProv:", "PostalCode:",    "Country:",   "RegDate:",
        "Updated:",   "Comment:",       "Ref:",       NULL};

    for (int i = 0; indicators[i] != NULL; i++) {
        if (strstr(response, indicators[i])) {
                if (wc_redirect_debug_enabled()) printf("[DEBUG] Authoritative indicator found: %s\n", indicators[i]);
            return 1;
        }
    }

        if (wc_redirect_debug_enabled()) printf("[DEBUG] No authoritative indicators found\n");
    return 0;
}

int needs_redirect(const char* response) {
        if (wc_redirect_debug_enabled()) printf("[DEBUG] ===== CHECKING REDIRECT NEED =====\n");
    if (!response) return 0;
    int authoritative = is_authoritative_response(response);
    int erx_legacy = contains_case_insensitive(response, "early registration addresses") ||
        contains_case_insensitive(response, "erx-netblock");

    // Invalid full-space ranges (only inetnum/NetRange lines)
    if (has_full_ipv4_guard_line(response) || has_full_ipv6_guard_line(response)) {
            if (wc_redirect_debug_enabled()) printf("[DEBUG] Redirect flag: Whole IPv4/IPv6 space\n");
        return 1;
    }

    // IANA default block
    if (strstr(response, "IANA-BLK") != NULL && strstr(response, "whole IPv4 address space") != NULL) {
            if (wc_redirect_debug_enabled()) printf("[DEBUG] Redirect flag: IANA default block\n");
        return 1;
    }

    // Explicit referral markers always require a redirect.
    const char* referral_flags[] = {
        "refer:",
        "referralserver:",
        "whois:",
        "whois server:",
        NULL
    };
    for (int i = 0; referral_flags[i] != NULL; i++) {
        if (contains_case_insensitive(response, referral_flags[i])) {
            if (wc_redirect_debug_enabled())
                printf("[DEBUG] Redirect referral found: %s\n", referral_flags[i]);
            return 1;
        }
    }

    // Strong redirect hints (case-insensitive)
    const char* strong_flags[] = {
        "not in database",
        "no match",
        "not found",
        "not registered in",
        "not allocated to",
        "not fully allocated to",
        "not allocated by",
        "early registration addresses",
        "allocated by another regional internet registry",
        "non-ripe-ncc-managed-address-block",
        "ip address block not managed by",
        "for more information, see",
        "for details, refer to",
        "see also",
        "please query",
        "query terms are ambiguous",
        "unallocated",
        "unassigned",
        NULL
    };

    if (authoritative && erx_legacy) {
        if (wc_redirect_debug_enabled())
            printf("[DEBUG] ERX legacy response; no redirect\n");
        return 0;
    }

    for (int i = 0; strong_flags[i] != NULL; i++) {
        if (contains_case_insensitive(response, strong_flags[i])) {
            if (wc_redirect_debug_enabled() && i < 10) {
                printf("[DEBUG] Redirect flag found: %s\n", strong_flags[i]);
            }
            return 1;
        }
    }

    // If authoritative and no strong hints, do not redirect.
    if (authoritative) {
        if (wc_redirect_debug_enabled())
            printf("[DEBUG] Authoritative response without redirect hints\n");
        return 0;
    }

    // Fallback: non-authoritative without known markers
    if (wc_redirect_debug_enabled())
        printf("[DEBUG] Response is not authoritative, needs redirect\n");
    return 1;

        if (wc_redirect_debug_enabled()) printf("[DEBUG] No redirect needed\n");
    return 0;
}
