// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "wc/wc_redirect.h"
#include "wc/wc_runtime.h"

static int wc_redirect_debug_enabled(void)
{
    const wc_runtime_cfg_view_t* view = wc_runtime_config_view();
    return view ? view->debug : 0;
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
            printf("[DEBUG] Invalid full-space response detected, redirecting to IANA\n");
        return strdup("whois.iana.org");
    }

    // IANA block hint
    if (strstr(response, "IANA-BLK") != NULL &&
        strstr(response, "whole IPv4 address space") != NULL) {
        if (wc_redirect_debug_enabled())
            printf("[DEBUG] IANA default block hint, redirecting to IANA\n");
        return strdup("whois.iana.org");
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
            if (wc_redirect_debug_enabled()) printf("[DEBUG] Analyzing line: %s\n", line);

            char* pos = strstr(line, "ReferralServer:");
            if (pos) {
                pos += strlen("ReferralServer:");
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
                    // Strip whois:// prefix if present
                    if (strncmp(whois_server, "whois://", 8) == 0) {
                        memmove(whois_server, whois_server + 8, strlen(whois_server) - 7);
                    }
                    if (debug) printf("[DEBUG] Found ReferralServer: %s\n", whois_server);
                }
            }

            if (!whois_server) {
                pos = strstr(line, "whois:");
                if (pos) {
                    pos += strlen("whois:");
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
                }
            }
        }
        line = strtok(NULL, "\n");
    }

    free(response_copy);

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

    // Common phrases (case-insensitive)
    const char* flags[] = {
        "not in database",
        "no match",
        "not found",
        "refer:",
        "referralserver:",
        "whois:",
        "whois server:",
        "not registered in",
        "not allocated to",
        "not allocated by",
        "early registration addresses",
        "allocated by another regional internet registry",
        "non-ripe-ncc-managed-address-block",
        "ip address block not managed by",
        "allocated to",
        "maintained by",
        "for more information, see",
        "for details, refer to",
        "see also",
        "please query",
        "query terms are ambiguous",
        "unallocated",
        "unassigned",
        NULL
    };

    for (int i = 0; flags[i] != NULL; i++) {
        if (contains_case_insensitive(response, flags[i])) {
                if (wc_redirect_debug_enabled() && i < 10) {
                printf("[DEBUG] Redirect flag found: %s\n", flags[i]);
            }
            return 1;
        }
    }

    // Fallback to authoritative check
    if (!is_authoritative_response(response)) {
            if (wc_redirect_debug_enabled()) printf("[DEBUG] Response is not authoritative, needs redirect\n");
        return 1;
    }

        if (wc_redirect_debug_enabled()) printf("[DEBUG] No redirect needed\n");
    return 0;
}
