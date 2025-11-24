// SPDX-License-Identifier: MIT
// dns.c - Resolver helpers for WHOIS client (Phase 2 groundwork)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "wc/wc_dns.h"
#include "wc/wc_server.h"
#include "wc/wc_selftest.h"

// Access global configuration flags (defined in whois_client.c)
extern struct Config {
    int whois_port; size_t buffer_size; int max_retries; int timeout_sec; int retry_interval_ms; int retry_jitter_ms; size_t dns_cache_size; size_t connection_cache_size; int cache_timeout; int debug; int max_redirects; int no_redirect; int plain_mode; int fold_output; char* fold_sep; int fold_upper; int security_logging; int fold_unique; int dns_neg_ttl; int dns_neg_cache_disable; int ipv4_only; int ipv6_only; int prefer_ipv4; int prefer_ipv6;
    int dns_addrconfig; int dns_retry; int dns_retry_interval_ms; int dns_max_candidates; int no_dns_known_fallback; int no_dns_force_ipv4_fallback; int no_iana_pivot; int dns_no_fallback; int dns_use_wc_dns;
} g_config;

#define WC_DNS_CACHE_VALUE_MAX 16

typedef struct {
    char* host;
    char** values;
    unsigned char* families;
    struct sockaddr_storage* addrs;
    socklen_t* addr_lens;
    int count;
    time_t expires_at;
} wc_dns_cache_entry_t;

typedef struct {
    char* host;
    int last_error;
    time_t expires_at;
} wc_dns_neg_entry_t;

static wc_dns_cache_entry_t* g_dns_cache = NULL;
static wc_dns_neg_entry_t* g_dns_neg_cache = NULL;
static size_t g_dns_cache_capacity = 0;
static size_t g_dns_neg_capacity = 0;
static size_t g_dns_cache_next = 0;
static size_t g_dns_neg_next = 0;

static char* wc_dns_strdup(const char* s) {
    if(!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if(!p) return NULL;
    memcpy(p, s, n);
    return p;
}

static long g_wc_dns_cache_hits = 0;
static long g_wc_dns_cache_negative_hits = 0;
static long g_wc_dns_cache_misses = 0;

// Lightweight per-host/per-family health memory (Phase 3, step 1).
// This implementation is deliberately simple: a fixed-size table
// with best-effort eviction and a coarse penalty window.

#define WC_DNS_HEALTH_MAX_ENTRIES 64
#define WC_DNS_HEALTH_DEFAULT_PENALTY_MS 300000
typedef struct {
    char  host[128];
    int   family;               // AF_INET / AF_INET6
    int   consecutive_failures;
    struct timespec last_success;
    struct timespec last_fail;
    struct timespec penalty_until;
} wc_dns_health_entry_t;

// Hard-coded fallback mapping for well-known WHOIS servers. This is used
// as a last resort when DNS is unavailable or misbehaving.
const char* wc_dns_get_known_ip(const char* domain) {
    if (!domain || !*domain) {
        return NULL;
    }

    // Updated IP address mapping (as final fallback)
    if (strcmp(domain, "whois.apnic.net") == 0) {
        return "203.119.102.14";  // Updated APNIC IP
    } else if (strcmp(domain, "whois.ripe.net") == 0) {
        return "193.0.6.135";     // RIPE unchanged
    } else if (strcmp(domain, "whois.arin.net") == 0) {
        return "199.71.0.46";     // Updated ARIN IP
    } else if (strcmp(domain, "whois.lacnic.net") == 0) {
        return "200.3.14.10";     // LACNIC unchanged
    } else if (strcmp(domain, "whois.afrinic.net") == 0) {
        return "196.216.2.6";     // AFRINIC unchanged
    } else if (strcmp(domain, "whois.iana.org") == 0) {
        return "192.0.43.8";      // Updated IANA IP
    }

    return NULL;
}

static wc_dns_health_entry_t g_dns_health[WC_DNS_HEALTH_MAX_ENTRIES];
static long g_dns_health_penalty_ms = WC_DNS_HEALTH_DEFAULT_PENALTY_MS;

static long wc_dns_ms_until(const struct timespec* now, const struct timespec* future) {
    if (!now || !future) return 0;
    if (future->tv_sec < now->tv_sec ||
        (future->tv_sec == now->tv_sec && future->tv_nsec <= now->tv_nsec)) {
        return 0;
    }
    long sec_diff = (long)(future->tv_sec - now->tv_sec);
    long nsec_diff = future->tv_nsec - now->tv_nsec;
    long total_ms = sec_diff * 1000L + nsec_diff / 1000000L;
    if (total_ms < 0) return 0;
    return total_ms;
}

static void wc_dns_health_now(struct timespec* ts) {
    if (!ts) return;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, ts);
#else
    struct timespec tmp; tmp.tv_sec = time(NULL); tmp.tv_nsec = 0; *ts = tmp;
#endif
}

static void wc_dns_candidate_list_reset(wc_dns_candidate_list_t* out) {
    if (!out) return;
    out->items = NULL;
    out->origins = NULL;
    out->families = NULL;
    out->sockaddrs = NULL;
    out->addr_lens = NULL;
    out->count = 0;
    out->capacity = 0;
    out->cache_hit = 0;
    out->negative_cache_hit = 0;
    out->limit_hit = 0;
    out->last_error = 0;
}

int wc_dns_get_cache_stats(wc_dns_cache_stats_t* out) {
    if (!out) return -1;
    out->hits = g_wc_dns_cache_hits;
    out->negative_hits = g_wc_dns_cache_negative_hits;
    out->misses = g_wc_dns_cache_misses;
    return 0;
}

// ----------------------------------------------------------------------------
// RIR fallback helper for IP-literal authoritative servers
// ----------------------------------------------------------------------------

// Best-effort helper to recognize reverse-lookup style domains and map
// them to a canonical RIR hostname. This logic is migrated from
// whois_client.c without behavioral changes so that both client and
// core can reuse it via wc_dns_rir_fallback_from_ip().

static char* wc_dns_reverse_lookup_domain(const char* ip_literal) {
    if (!ip_literal || !*ip_literal)
        return NULL;

    // Only handle IPv4 dotted-quad for now, mirroring legacy behavior.
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip_literal, &addr4) != 1)
        return NULL;

    unsigned char* bytes = (unsigned char*)&addr4.s_addr;
    // IPv4 in network byte order; expand into reversed dotted form.
    char buf[64];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa",
             bytes[3], bytes[2], bytes[1], bytes[0]);
    size_t len = strlen(buf) + 1;
    char* out = (char*)malloc(len);
    if (!out)
        return NULL;
    memcpy(out, buf, len);
    return out;
}

static const char* wc_dns_map_domain_to_rir(const char* domain) {
    if (!domain)
        return NULL;

    // Very small, behavior-preserving mapping table copied from client.
    if (strstr(domain, ".arin.net"))
        return "whois.arin.net";
    if (strstr(domain, ".apnic.net"))
        return "whois.apnic.net";
    if (strstr(domain, ".ripe.net"))
        return "whois.ripe.net";
    if (strstr(domain, ".lacnic.net"))
        return "whois.lacnic.net";
    if (strstr(domain, ".afrinic.net"))
        return "whois.afrinic.net";
    return NULL;
}

char* wc_dns_rir_fallback_from_ip(const char* ip_literal) {
    if (!ip_literal || !*ip_literal)
        return NULL;

    // Caller should have ensured this is an IP literal, but we double-check
    // cheaply here to avoid accidental misuse.
    if (!wc_dns_is_ip_literal(ip_literal))
        return NULL;

    char* rev = wc_dns_reverse_lookup_domain(ip_literal);
    if (!rev)
        return NULL;

    const char* mapped = wc_dns_map_domain_to_rir(rev);
    free(rev);
    if (!mapped)
        return NULL;

    size_t len = strlen(mapped) + 1;
    char* out = (char*)malloc(len);
    if (!out)
        return NULL;
    memcpy(out, mapped, len);
    return out;
}

void wc_dns_health_note_result(const char* host, int family, int success) {
    if (!host || !*host) return;
    if (family != AF_INET && family != AF_INET6) return;

    struct timespec now;
    wc_dns_health_now(&now);

    wc_dns_health_entry_t* slot = NULL;
    wc_dns_health_entry_t* empty = NULL;
    for (int i = 0; i < WC_DNS_HEALTH_MAX_ENTRIES; ++i) {
        wc_dns_health_entry_t* e = &g_dns_health[i];
        if (!e->host[0]) {
            if (!empty) empty = e;
            continue;
        }
        if (e->family == family && strcasecmp(e->host, host) == 0) {
            slot = e;
            break;
        }
    }
    if (!slot) {
        slot = empty ? empty : &g_dns_health[0];
        memset(slot, 0, sizeof(*slot));
        strncpy(slot->host, host, sizeof(slot->host) - 1);
        slot->family = family;
    }

    if (success) {
        slot->consecutive_failures = 0;
        slot->last_success = now;
        struct timespec zero = {0,0};
        slot->penalty_until = zero;
    } else {
        slot->last_fail = now;
        if (slot->consecutive_failures < INT_MAX) slot->consecutive_failures++;
        if (slot->consecutive_failures >= 3) {
            // Enter or extend penalty window.
            long penalty_ms = g_dns_health_penalty_ms;
            if (penalty_ms > 0) {
                slot->penalty_until = now;
                slot->penalty_until.tv_sec += penalty_ms / 1000L;
                slot->penalty_until.tv_nsec += (penalty_ms % 1000L) * 1000000L;
                if (slot->penalty_until.tv_nsec >= 1000000000L) {
                    slot->penalty_until.tv_sec += 1;
                    slot->penalty_until.tv_nsec -= 1000000000L;
                }
            }
        }
    }
}

wc_dns_health_state_t wc_dns_health_get_state(const char* host,
                                              int family,
                                              wc_dns_health_snapshot_t* snap) {
    if (snap) {
        snap->host = host;
        snap->family = family;
        snap->consecutive_failures = 0;
        snap->penalty_ms_left = 0;
    }
    if (!host || !*host) return WC_DNS_HEALTH_OK;
    if (family != AF_INET && family != AF_INET6) return WC_DNS_HEALTH_OK;

    struct timespec now;
    wc_dns_health_now(&now);

    for (int i = 0; i < WC_DNS_HEALTH_MAX_ENTRIES; ++i) {
        wc_dns_health_entry_t* e = &g_dns_health[i];
        if (!e->host[0]) continue;
        if (e->family != family) continue;
        if (strcasecmp(e->host, host) != 0) continue;

        long ms_left = wc_dns_ms_until(&now, &e->penalty_until);
        if (snap) {
            snap->consecutive_failures = e->consecutive_failures;
            snap->penalty_ms_left = ms_left;
        }
        if (ms_left > 0) {
            return WC_DNS_HEALTH_PENALIZED;
        }
        return WC_DNS_HEALTH_OK;
    }
    return WC_DNS_HEALTH_OK;
}

void wc_dns_health_set_penalty_window_ms(long ms) {
    if (ms < 0) {
        ms = 0;
    }
    g_dns_health_penalty_ms = ms;
}

long wc_dns_health_get_penalty_window_ms(void) {
    return g_dns_health_penalty_ms;
}

static wc_dns_family_t wc_dns_family_from_token(const char* token) {
    if (!token) return WC_DNS_FAMILY_UNKNOWN;
    if (wc_dns_is_ip_literal(token)) {
        return (strchr(token, ':') != NULL) ? WC_DNS_FAMILY_IPV6 : WC_DNS_FAMILY_IPV4;
    }
    return WC_DNS_FAMILY_HOST;
}

static wc_dns_family_t wc_dns_family_from_af(int af) {
    if (af == AF_INET) return WC_DNS_FAMILY_IPV4;
    if (af == AF_INET6) return WC_DNS_FAMILY_IPV6;
    return WC_DNS_FAMILY_UNKNOWN;
}

static int wc_dns_candidate_reserve(wc_dns_candidate_list_t* out, int needed) {
    if (!out) return -1;
    if (out->capacity >= needed) return 0;
    int new_cap = (out->capacity > 0) ? out->capacity : 4;
    while (new_cap < needed) {
        if (new_cap > INT_MAX / 2) {
            new_cap = needed;
            break;
        }
        new_cap *= 2;
    }
    char** new_items = (char**)realloc(out->items, (size_t)new_cap * sizeof(char*));
    if (!new_items) return -1;
    out->items = new_items;
    unsigned char* new_origins = (unsigned char*)realloc(out->origins, (size_t)new_cap * sizeof(unsigned char));
    if (!new_origins) return -1;
    out->origins = (unsigned char*)new_origins;
    unsigned char* new_families = (unsigned char*)realloc(out->families, (size_t)new_cap * sizeof(unsigned char));
    if (!new_families) return -1;
    out->families = (unsigned char*)new_families;
    struct sockaddr_storage* new_addrs = (struct sockaddr_storage*)realloc(out->sockaddrs, (size_t)new_cap * sizeof(struct sockaddr_storage));
    if (!new_addrs) return -1;
    out->sockaddrs = new_addrs;
    socklen_t* new_lens = (socklen_t*)realloc(out->addr_lens, (size_t)new_cap * sizeof(socklen_t));
    if (!new_lens) return -1;
    out->addr_lens = new_lens;
    out->capacity = new_cap;
    return 0;
}

static int wc_dns_candidate_append(wc_dns_candidate_list_t* out,
                                   const char* token,
                                   wc_dns_origin_t origin,
                                   wc_dns_family_t family,
                                   const struct sockaddr* addr,
                                   socklen_t addrlen) {
    if (!out || !token) return 0;
    if (g_config.dns_max_candidates > 0 && out->count >= g_config.dns_max_candidates) {
        out->limit_hit = 1;
        return 0;
    }
    if (wc_dns_candidate_reserve(out, out->count + 1) != 0) return -1;
    out->items[out->count] = wc_dns_strdup(token);
    if (!out->items[out->count]) return -1;
    out->origins[out->count] = (unsigned char)origin;
    out->families[out->count] = (unsigned char)family;
    if (addr && addrlen > 0 && addrlen <= (socklen_t)sizeof(struct sockaddr_storage)) {
        memcpy(&out->sockaddrs[out->count], addr, (size_t)addrlen);
        out->addr_lens[out->count] = addrlen;
    } else {
        memset(&out->sockaddrs[out->count], 0, sizeof(struct sockaddr_storage));
        out->addr_lens[out->count] = 0;
    }
    out->count++;
    return 0;
}

static void wc_dns_candidate_fail_memory(wc_dns_candidate_list_t* out) {
    if (!out) return;
    wc_dns_candidate_list_free(out);
    out->last_error = EAI_MEMORY;
}

static time_t wc_dns_now(void) {
    return time(NULL);
}

static void wc_dns_cache_entry_destroy(wc_dns_cache_entry_t* entry) {
    if (!entry) return;
    if (entry->host) {
        free(entry->host);
        entry->host = NULL;
    }
    if (entry->values) {
        for (int i = 0; i < entry->count; ++i) {
            if (entry->values[i]) free(entry->values[i]);
        }
        free(entry->values);
        entry->values = NULL;
    }
    if (entry->families) {
        free(entry->families);
        entry->families = NULL;
    }
    if (entry->addrs) {
        free(entry->addrs);
        entry->addrs = NULL;
    }
    if (entry->addr_lens) {
        free(entry->addr_lens);
        entry->addr_lens = NULL;
    }
    entry->count = 0;
    entry->expires_at = 0;
}

static void wc_dns_neg_entry_destroy(wc_dns_neg_entry_t* entry) {
    if (!entry) return;
    if (entry->host) {
        free(entry->host);
        entry->host = NULL;
    }
    entry->last_error = 0;
    entry->expires_at = 0;
}

static void wc_dns_cache_init_if_needed(void) {
    if (g_dns_cache_capacity > 0 || g_config.dns_cache_size <= 0) return;
    g_dns_cache_capacity = (size_t)g_config.dns_cache_size;
    g_dns_neg_capacity = (size_t)g_config.dns_cache_size;
    g_dns_cache = (wc_dns_cache_entry_t*)calloc(g_dns_cache_capacity, sizeof(*g_dns_cache));
    g_dns_neg_cache = (wc_dns_neg_entry_t*)calloc(g_dns_neg_capacity, sizeof(*g_dns_neg_cache));
    if (!g_dns_cache || !g_dns_neg_cache) {
        free(g_dns_cache);
        free(g_dns_neg_cache);
        g_dns_cache = NULL;
        g_dns_neg_cache = NULL;
        g_dns_cache_capacity = 0;
        g_dns_neg_capacity = 0;
    }
}

static wc_dns_cache_entry_t* wc_dns_cache_find(const char* host, time_t now) {
    if (!g_dns_cache || !host) return NULL;
    for (size_t i = 0; i < g_dns_cache_capacity; ++i) {
        wc_dns_cache_entry_t* e = &g_dns_cache[i];
        if (!e->host) continue;
        if (strcasecmp(e->host, host) != 0) continue;
        if (e->expires_at <= now) {
            wc_dns_cache_entry_destroy(e);
            continue;
        }
        return e;
    }
    return NULL;
}

static void wc_dns_neg_cache_remove(const char* host) {
    if (!g_dns_neg_cache || !host) return;
    for (size_t i = 0; i < g_dns_neg_capacity; ++i) {
        wc_dns_neg_entry_t* e = &g_dns_neg_cache[i];
        if (!e->host) continue;
        if (strcasecmp(e->host, host) == 0) {
            wc_dns_neg_entry_destroy(e);
            break;
        }
    }
}

static void wc_dns_cache_store_positive(const char* host,
                                        char** values,
                                        unsigned char* families,
                                        const struct sockaddr_storage* addrs,
                                        const socklen_t* addr_lens,
                                        int count) {
    if (!host || !values || count <= 0) return;
    if (g_config.dns_cache_size <= 0) return;
    wc_dns_cache_init_if_needed();
    if (!g_dns_cache) return;
    time_t now = wc_dns_now();
    wc_dns_cache_entry_t* slot = NULL;
    for (size_t i = 0; i < g_dns_cache_capacity; ++i) {
        wc_dns_cache_entry_t* e = &g_dns_cache[i];
        if (e->host && strcasecmp(e->host, host) == 0) {
            slot = e;
            break;
        }
        if (!slot && !e->host) slot = e;
    }
    if (!slot) {
        slot = &g_dns_cache[g_dns_cache_next % g_dns_cache_capacity];
        g_dns_cache_next++;
    }
    wc_dns_cache_entry_destroy(slot);
    slot->host = wc_dns_strdup(host);
    if (!slot->host) {
        wc_dns_cache_entry_destroy(slot);
        return;
    }
    int store_count = count;
    if (store_count > WC_DNS_CACHE_VALUE_MAX) store_count = WC_DNS_CACHE_VALUE_MAX;
    slot->values = (char**)calloc((size_t)store_count, sizeof(char*));
    slot->families = (unsigned char*)calloc((size_t)store_count, sizeof(unsigned char));
    slot->addrs = (struct sockaddr_storage*)calloc((size_t)store_count, sizeof(struct sockaddr_storage));
    slot->addr_lens = (socklen_t*)calloc((size_t)store_count, sizeof(socklen_t));
    if (!slot->values || !slot->families || !slot->addrs || !slot->addr_lens) {
        wc_dns_cache_entry_destroy(slot);
        return;
    }
    for (int i = 0; i < store_count; ++i) {
        slot->values[i] = wc_dns_strdup(values[i]);
        if (!slot->values[i]) {
            wc_dns_cache_entry_destroy(slot);
            return;
        }
        slot->families[i] = families ? families[i] : (unsigned char)WC_DNS_FAMILY_UNKNOWN;
        if (addrs && addr_lens && addr_lens[i] > 0 && addr_lens[i] <= (socklen_t)sizeof(struct sockaddr_storage)) {
            memcpy(&slot->addrs[i], &addrs[i], (size_t)addr_lens[i]);
            slot->addr_lens[i] = addr_lens[i];
        } else {
            slot->addr_lens[i] = 0;
        }
    }
    slot->count = store_count;
    int ttl = (g_config.cache_timeout > 0) ? g_config.cache_timeout : 300;
    slot->expires_at = now + ttl;
    wc_dns_neg_cache_remove(host);
}

static void wc_dns_neg_cache_store(const char* host, int err) {
    if (!host || err == 0) return;
    if (g_config.dns_neg_cache_disable) return;
    if (g_config.dns_cache_size <= 0) return;
    wc_dns_cache_init_if_needed();
    if (!g_dns_neg_cache) return;
    time_t now = wc_dns_now();
    wc_dns_neg_entry_t* slot = NULL;
    for (size_t i = 0; i < g_dns_neg_capacity; ++i) {
        wc_dns_neg_entry_t* e = &g_dns_neg_cache[i];
        if (e->host && strcasecmp(e->host, host) == 0) {
            slot = e;
            break;
        }
        if (!slot && !e->host) slot = e;
    }
    if (!slot) {
        slot = &g_dns_neg_cache[g_dns_neg_next % g_dns_neg_capacity];
        g_dns_neg_next++;
    }
    wc_dns_neg_entry_destroy(slot);
    slot->host = wc_dns_strdup(host);
    if (!slot->host) {
        wc_dns_neg_entry_destroy(slot);
        return;
    }
    int ttl = (g_config.dns_neg_ttl > 0) ? g_config.dns_neg_ttl : 30;
    slot->last_error = err;
    slot->expires_at = now + ttl;
}

static int wc_dns_neg_cache_hit(const char* host, time_t now, int* err_out) {
    if (!g_dns_neg_cache || !host) return 0;
    for (size_t i = 0; i < g_dns_neg_capacity; ++i) {
        wc_dns_neg_entry_t* e = &g_dns_neg_cache[i];
        if (!e->host) continue;
        if (strcasecmp(e->host, host) != 0) continue;
        if (e->expires_at <= now) {
            wc_dns_neg_entry_destroy(e);
            continue;
        }
        if (err_out) *err_out = e->last_error;
        return 1;
    }
    return 0;
}

int wc_dns_is_ip_literal(const char* s){
    if(!s || !*s) return 0;
    int has_colon = 0, has_dot = 0;
    for(const char* p = s; *p; ++p){
        if(*p == ':') has_colon = 1;
        else if(*p == '.') has_dot = 1;
    }
    if(has_colon) return 1; // IPv6 heuristic
    if(!has_dot) return 0;
    for(const char* p = s; *p; ++p){
        if(!((*p>='0' && *p<='9') || *p=='.')) return 0;
    }
    return 1;
}

const char* wc_dns_canonical_host_for_rir(const char* rir){
    if(!rir) return NULL;
    if(strcasecmp(rir,"arin")==0) return "whois.arin.net";
    if(strcasecmp(rir,"ripe")==0) return "whois.ripe.net";
    if(strcasecmp(rir,"apnic")==0) return "whois.apnic.net";
    if(strcasecmp(rir,"lacnic")==0) return "whois.lacnic.net";
    if(strcasecmp(rir,"afrinic")==0) return "whois.afrinic.net";
    if(strcasecmp(rir,"iana")==0) return "whois.iana.org";
    return NULL;
}

static void wc_dns_collect_addrinfo(const char* canon,
                                    char*** out_list,
                                    unsigned char** out_family,
                                    struct sockaddr_storage** out_addrs,
                                    socklen_t** out_addr_lens,
                                    int* out_count,
                                    int* out_error) {
    if (out_list) *out_list = NULL;
    if (out_family) *out_family = NULL;
    if (out_addrs) *out_addrs = NULL;
    if (out_addr_lens) *out_addr_lens = NULL;
    if (out_count) *out_count = 0;
    if (out_error) *out_error = 0;
    if (!canon || !*canon) return;
    if (wc_selftest_dns_negative_enabled()) {
        if (out_error) *out_error = EAI_FAIL;
        return;
    }
    int cap = 12;
    int cnt = 0;
    char** list = (char**)malloc(sizeof(char*) * cap);
    unsigned char* fams = (unsigned char*)malloc(sizeof(unsigned char) * cap);
    struct sockaddr_storage* addrs = (struct sockaddr_storage*)malloc(sizeof(struct sockaddr_storage) * cap);
    socklen_t* lens = (socklen_t*)malloc(sizeof(socklen_t) * cap);
    if (!list || !fams || !addrs || !lens) {
        free(list);
        free(fams);
        free(addrs);
        free(lens);
        return;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
#ifdef AI_ADDRCONFIG
    if (g_config.dns_addrconfig) hints.ai_flags = AI_ADDRCONFIG; else hints.ai_flags = 0;
#endif
    struct addrinfo* res = NULL;
    int gai_rc = 0;
    int tries = 0;
    int maxtries = (g_config.dns_retry>0 ? g_config.dns_retry : 1);
    do {
        gai_rc = getaddrinfo(canon, "43", &hints, &res);
        if (gai_rc==EAI_AGAIN && tries < maxtries-1) {
            int ms = (g_config.dns_retry_interval_ms>=0 ? g_config.dns_retry_interval_ms : 100);
            struct timespec ts;
            ts.tv_sec = (time_t)(ms/1000);
            ts.tv_nsec = (long)((ms%1000)*1000000L);
            nanosleep(&ts,NULL);
        }
        tries++;
    } while(gai_rc==EAI_AGAIN && tries<maxtries);

    if(res){
        char* v4[64]; struct sockaddr_storage v4addr[64]; socklen_t v4len[64]; int v4c=0;
        char* v6[64]; struct sockaddr_storage v6addr[64]; socklen_t v6len[64]; int v6c=0;
        for(struct addrinfo* rp=res; rp; rp=rp->ai_next){
            int fam = rp->ai_family;
            if (fam!=AF_INET && fam!=AF_INET6) continue;
            char ipbuf[64];
            if(getnameinfo(rp->ai_addr, rp->ai_addrlen, ipbuf, sizeof(ipbuf), NULL, 0, NI_NUMERICHOST)!=0) continue;
            int dup=0;
            for(int i=0;i<v4c && !dup;i++){ if(strcmp(v4[i], ipbuf)==0) dup=1; }
            for(int i=0;i<v6c && !dup;i++){ if(strcmp(v6[i], ipbuf)==0) dup=1; }
            if(dup) continue;
            if (fam==AF_INET && v4c < (int)(sizeof(v4)/sizeof(v4[0]))) {
                v4[v4c] = wc_dns_strdup(ipbuf);
                if (v4[v4c]) {
                    memcpy(&v4addr[v4c], rp->ai_addr, rp->ai_addrlen);
                    v4len[v4c] = (socklen_t)rp->ai_addrlen;
                    v4c++;
                }
            }
            else if (fam==AF_INET6 && v6c < (int)(sizeof(v6)/sizeof(v6[0]))) {
                v6[v6c] = wc_dns_strdup(ipbuf);
                if (v6[v6c]) {
                    memcpy(&v6addr[v6c], rp->ai_addr, rp->ai_addrlen);
                    v6len[v6c] = (socklen_t)rp->ai_addrlen;
                    v6c++;
                }
            }
        }
        if (g_config.ipv4_only || g_config.ipv6_only) {
            int fam = g_config.ipv4_only ? AF_INET : AF_INET6;
            char** src = (fam==AF_INET)?v4:v6;
            int srcc = (fam==AF_INET)?v4c:v6c;
            struct sockaddr_storage* src_addr = (fam==AF_INET)?v4addr:v6addr;
            socklen_t* src_len = (fam==AF_INET)?v4len:v6len;
            for(int i=0;i<srcc;i++){
                if (g_config.dns_max_candidates>0 && cnt >= g_config.dns_max_candidates) break;
                if(cnt>=cap){
                    cap*=2;
                    char** nl=(char**)realloc(list,sizeof(char*)*cap);
                    unsigned char* nf=(unsigned char*)realloc(fams,sizeof(unsigned char)*cap);
                    struct sockaddr_storage* na=(struct sockaddr_storage*)realloc(addrs,sizeof(struct sockaddr_storage)*cap);
                    socklen_t* nlen=(socklen_t*)realloc(lens,sizeof(socklen_t)*cap);
                    if(!nl || !nf || !na || !nlen){
                        if (nl) list=nl;
                        if (nf) fams=nf;
                        if (na) addrs=na;
                        if (nlen) lens=nlen;
                        break;
                    }
                    list=nl;
                    fams=nf;
                    addrs=na;
                    lens=nlen;
                }
                list[cnt] = src[i]; src[i]=NULL;
                fams[cnt] = (unsigned char)wc_dns_family_from_af(fam);
                memcpy(&addrs[cnt], &src_addr[i], sizeof(struct sockaddr_storage));
                lens[cnt] = src_len[i];
                cnt++;
            }
        } else {
            int prefer_v4_first = g_config.prefer_ipv4 ? 1 : 0;
            int i4=0,i6=0; int turn = prefer_v4_first ? 0 : 1;
            while ((i4<v4c || i6<v6c) && (g_config.dns_max_candidates==0 || cnt < g_config.dns_max_candidates)){
                if(cnt>=cap){
                    cap*=2;
                    char** nl=(char**)realloc(list,sizeof(char*)*cap);
                    unsigned char* nf=(unsigned char*)realloc(fams,sizeof(unsigned char)*cap);
                    struct sockaddr_storage* na=(struct sockaddr_storage*)realloc(addrs,sizeof(struct sockaddr_storage)*cap);
                    socklen_t* nlen=(socklen_t*)realloc(lens,sizeof(socklen_t)*cap);
                    if(!nl || !nf || !na || !nlen){
                        if (nl) list=nl;
                        if (nf) fams=nf;
                        if (na) addrs=na;
                        if (nlen) lens=nlen;
                        break;
                    }
                    list=nl;
                    fams=nf;
                    addrs=na;
                    lens=nlen;
                }
                if (turn==0 && i4<v4c){
                    list[cnt] = v4[i4]; v4[i4]=NULL;
                    fams[cnt] = (unsigned char)WC_DNS_FAMILY_IPV4;
                    memcpy(&addrs[cnt], &v4addr[i4], sizeof(struct sockaddr_storage));
                    lens[cnt] = v4len[i4];
                    i4++;
                } else if (turn==1 && i6<v6c){
                    list[cnt] = v6[i6]; v6[i6]=NULL;
                    fams[cnt] = (unsigned char)WC_DNS_FAMILY_IPV6;
                    memcpy(&addrs[cnt], &v6addr[i6], sizeof(struct sockaddr_storage));
                    lens[cnt] = v6len[i6];
                    i6++;
                } else {
                    break;
                }
                cnt++;
                if (i4>=v4c) turn = 1;
                else if (i6>=v6c) turn = 0;
                else turn ^= 1;
            }
            for(;i4<v4c;i4++){ if(v4[i4]) free(v4[i4]); }
            for(;i6<v6c;i6++){ if(v6[i6]) free(v6[i6]); }
        }
        freeaddrinfo(res);
    }
    if (out_list) *out_list = list; else {
        for (int i=0;i<cnt;i++){ if(list[i]) free(list[i]); }
        free(list);
    }
    if (out_family) *out_family = fams; else free(fams);
    if (out_addrs) *out_addrs = addrs; else free(addrs);
    if (out_addr_lens) *out_addr_lens = lens; else free(lens);
    if (out_count) *out_count = cnt;
    if (out_error) *out_error = gai_rc;
}

int wc_dns_build_candidates(const char* current_host,
                            const char* rir,
                            wc_dns_candidate_list_t* out){
    if(!out) return -1;
    wc_dns_candidate_list_reset(out);

    char canon[128]; canon[0]='\0';
    if(current_host && !wc_dns_is_ip_literal(current_host)){
        if (wc_normalize_whois_host(current_host, canon, sizeof(canon)) != 0)
            snprintf(canon,sizeof(canon),"%s", current_host);
    } else {
        const char* ch = wc_dns_canonical_host_for_rir(rir);
        if (ch) snprintf(canon,sizeof(canon),"%s", ch);
        else snprintf(canon,sizeof(canon),"%s", current_host?current_host:"whois.iana.org");
    }

    int allow_hostname_fallback = !(g_config.ipv4_only || g_config.ipv6_only);

    if (current_host && wc_dns_is_ip_literal(current_host)) {
        if (wc_dns_candidate_append(out, current_host, WC_DNS_ORIGIN_INPUT,
                                    wc_dns_family_from_token(current_host),
                                    NULL, 0) != 0) {
            wc_dns_candidate_fail_memory(out);
            return -1;
        }
    }

    if (wc_selftest_blackhole_iana_enabled() && strcasecmp(canon, "whois.iana.org") == 0) {
        if (wc_dns_candidate_append(out, "192.0.2.1", WC_DNS_ORIGIN_SELFTEST, WC_DNS_FAMILY_IPV4,
                                    NULL, 0) != 0) {
            wc_dns_candidate_fail_memory(out);
            return -1;
        }
        return 0;
    }
    if (wc_selftest_blackhole_arin_enabled() && strcasecmp(canon, "whois.arin.net") == 0) {
        if (wc_dns_candidate_append(out, "192.0.2.1", WC_DNS_ORIGIN_SELFTEST, WC_DNS_FAMILY_IPV4,
                                    NULL, 0) != 0) {
            wc_dns_candidate_fail_memory(out);
            return -1;
        }
        return 0;
    }

    time_t now = wc_dns_now();
    int neg_err = 0;
    if (canon[0] && !wc_dns_is_ip_literal(canon)) {
        if (wc_dns_neg_cache_hit(canon, now, &neg_err)) {
            out->negative_cache_hit = 1;
            out->last_error = neg_err;
            g_wc_dns_cache_negative_hits++;
        } else {
            wc_dns_cache_entry_t* cached = wc_dns_cache_find(canon, now);
            if (cached && cached->count > 0) {
                out->cache_hit = 1;
                g_wc_dns_cache_hits++;
                for (int i = 0; i < cached->count; ++i) {
                    const struct sockaddr* cached_addr = NULL;
                    socklen_t cached_len = 0;
                    if (cached->addrs && cached->addr_lens && i < cached->count && cached->addr_lens[i] > 0) {
                        cached_addr = (const struct sockaddr*)&cached->addrs[i];
                        cached_len = cached->addr_lens[i];
                    }
                    if (wc_dns_candidate_append(out, cached->values[i], WC_DNS_ORIGIN_CACHE,
                                                (wc_dns_family_t)cached->families[i],
                                                cached_addr, cached_len) != 0) {
                        wc_dns_candidate_fail_memory(out);
                        return -1;
                    }
                }
            } else {
                char** resolved = NULL;
                unsigned char* families = NULL;
                struct sockaddr_storage* resolved_addrs = NULL;
                socklen_t* resolved_lens = NULL;
                int resolved_count = 0;
                int gai_error = 0;
                g_wc_dns_cache_misses++;
                wc_dns_collect_addrinfo(canon, &resolved, &families,
                                        &resolved_addrs, &resolved_lens,
                                        &resolved_count, &gai_error);
                if (resolved && resolved_count > 0) {
                    for (int i=0;i<resolved_count;i++){
                        if (!resolved[i]) continue;
                        if (wc_dns_candidate_append(out, resolved[i], WC_DNS_ORIGIN_RESOLVER,
                                                    (wc_dns_family_t)(families ? families[i] : WC_DNS_FAMILY_UNKNOWN),
                                                    resolved_addrs ? (const struct sockaddr*)&resolved_addrs[i] : NULL,
                                                    resolved_lens ? resolved_lens[i] : 0) != 0) {
                            for (int j=i;j<resolved_count;j++){ if(resolved[j]) free(resolved[j]); }
                            free(resolved);
                            free(families);
                            if (resolved_addrs) free(resolved_addrs);
                            if (resolved_lens) free(resolved_lens);
                            wc_dns_candidate_fail_memory(out);
                            return -1;
                        }
                    }
                    wc_dns_cache_store_positive(canon, resolved, families,
                                                resolved_addrs, resolved_lens,
                                                resolved_count);
                } else if (gai_error != 0) {
                    out->last_error = gai_error;
                    wc_dns_neg_cache_store(canon, gai_error);
                }
                if (resolved) {
                    for (int i=0;i<resolved_count;i++){ if(resolved[i]) free(resolved[i]); }
                    free(resolved);
                }
                if (families) free(families);
                if (resolved_addrs) free(resolved_addrs);
                if (resolved_lens) free(resolved_lens);
            }
        }
    }

    if (allow_hostname_fallback) {
        int has_numeric = 0;
        for (int i=0;i<out->count;i++){ if (wc_dns_is_ip_literal(out->items[i])) { has_numeric = 1; break; } }
        if (!has_numeric || (g_config.dns_max_candidates==0 || out->count < g_config.dns_max_candidates)) {
            if (wc_dns_candidate_append(out, canon, WC_DNS_ORIGIN_CANONICAL, WC_DNS_FAMILY_HOST,
                                        NULL, 0) != 0) {
                wc_dns_candidate_fail_memory(out);
                return -1;
            }
        }
    }

    if(out->count==0){
        int err = (out->last_error != 0) ? out->last_error : EAI_FAIL;
        wc_dns_candidate_list_free(out);
        out->last_error = err;
        return -1;
    }
    return 0;
}

void wc_dns_candidate_list_free(wc_dns_candidate_list_t* list){
    if(!list) return;
    if(list->items){
        for(int i=0;i<list->count;i++){
            if(list->items[i]) free(list->items[i]);
        }
        free(list->items);
    }
    if(list->origins) free(list->origins);
    if(list->families) free(list->families);
    if(list->sockaddrs) free(list->sockaddrs);
    if(list->addr_lens) free(list->addr_lens);
    list->items = NULL;
    list->origins = NULL;
    list->families = NULL;
    list->sockaddrs = NULL;
    list->addr_lens = NULL;
    list->count = 0;
    list->capacity = 0;
    list->cache_hit = 0;
    list->negative_cache_hit = 0;
    list->limit_hit = 0;
    list->last_error = 0;
}
