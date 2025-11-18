// wc_dns.h - DNS resolver helpers and candidate management (phase 2 groundwork)
#ifndef WC_DNS_H_
#define WC_DNS_H_

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WC_DNS_ORIGIN_INPUT = 0,
    WC_DNS_ORIGIN_SELFTEST = 1,
    WC_DNS_ORIGIN_CACHE = 2,
    WC_DNS_ORIGIN_RESOLVER = 3,
    WC_DNS_ORIGIN_CANONICAL = 4
} wc_dns_origin_t;

typedef enum {
    WC_DNS_FAMILY_UNKNOWN = 0,
    WC_DNS_FAMILY_IPV4 = 1,
    WC_DNS_FAMILY_IPV6 = 2,
    WC_DNS_FAMILY_HOST = 3
} wc_dns_family_t;

typedef struct wc_dns_candidate_list_s {
    char** items;               // array of malloc'ed strings (IP literals or hostnames)
    unsigned char* origins;     // parallel origin markers (wc_dns_origin_t)
    unsigned char* families;    // parallel family markers (wc_dns_family_t)
    struct sockaddr_storage* sockaddrs; // parallel sockaddr_storage entries when numeric target already resolved
    socklen_t* addr_lens;       // length of each sockaddr entry; zero when not populated
    int count;                  // number of valid entries in items
    int capacity;               // internal allocation capacity (implementation detail)
    int cache_hit;              // 1 when populated from positive cache
    int negative_cache_hit;     // 1 when negative cache short-circuited resolution
    int limit_hit;              // 1 when dns_max_candidates prevented adding more entries
    int last_error;             // last getaddrinfo error code (0 on success/cache hit)
} wc_dns_candidate_list_t;

typedef struct wc_dns_cache_stats_s {
    long hits;                  // positive cache hits
    long negative_hits;         // negative cache hits
    long misses;                // cache lookups that fell through to resolver
} wc_dns_cache_stats_t;

// Lightweight per-host/per-family health state, used to remember
// recent IPv4/IPv6 failures within a single process. This is
// intentionally coarse and only influences soft preferences.
typedef enum {
    WC_DNS_HEALTH_OK = 0,
    WC_DNS_HEALTH_PENALIZED = 1
} wc_dns_health_state_t;

typedef struct wc_dns_health_snapshot_s {
    const char* host;           // canonical host name (borrowed, not owned)
    int family;                 // AF_INET / AF_INET6
    int consecutive_failures;   // recent consecutive failures
    long penalty_ms_left;       // remaining penalty window in milliseconds
} wc_dns_health_snapshot_t;

// Returns 1 if the input string is an IP literal (IPv4 dotted or IPv6 with ':'), else 0.
int wc_dns_is_ip_literal(const char* s);

// Map a RIR alias (arin/apnic/...) to its canonical whois hostname. Returns NULL on unknown input.
const char* wc_dns_canonical_host_for_rir(const char* rir);

// Build numeric/hostname candidates for dialing a WHOIS server. On success returns 0 and
// populates 'out' with heap-allocated entries that must be freed via wc_dns_candidate_list_free().
int wc_dns_build_candidates(const char* current_host,
                            const char* rir,
                            wc_dns_candidate_list_t* out);

// Retrieve aggregate DNS cache statistics for the current process.
// Returns 0 on success and fills 'out'. The statistics are best-effort and
// intended for debugging/metrics only; they do not affect resolver behavior.
int wc_dns_get_cache_stats(wc_dns_cache_stats_t* out);

// Health memory API (Phase 3 step 1: observability only)
// ------------------------------------------------------
// These helpers expose a coarse view of per-host/per-family
// health. They are safe no-ops when health tracking is not
// compiled or configured.

// Record the outcome of a connect attempt for (host,family).
// 'success' should be non-zero on successful connect.
void wc_dns_health_note_result(const char* host, int family, int success);

// Query current health state for (host,family). Returns
// WC_DNS_HEALTH_OK when the entry is considered healthy or
// unknown, WC_DNS_HEALTH_PENALIZED when recent failures suggest
// a temporary penalty. When 'snap' is non-NULL, it is filled
// with a best-effort snapshot of internal state.
wc_dns_health_state_t wc_dns_health_get_state(const char* host,
                                              int family,
                                              wc_dns_health_snapshot_t* snap);

// Free every entry inside the list (if non-NULL) and reset the structure to zero.
void wc_dns_candidate_list_free(wc_dns_candidate_list_t* list);

#ifdef __cplusplus
}
#endif

#endif // WC_DNS_H_
