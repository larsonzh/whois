// wc_lookup.h - Query execution state machine (Phase B skeleton)
#ifndef WC_LOOKUP_H_
#define WC_LOOKUP_H_

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

// Input query descriptor
struct wc_query {
    const char* raw;          // original query string
    const char* start_server; // optional start server (canonical host or alias); may be NULL -> default heuristics
    int port;                 // whois port (usually 43)
};

// Lookup options (subset for phase B)
struct wc_lookup_opts {
    int max_hops;       // referral hop limit
    int no_redirect;    // disable referral following (0/1)
    int timeout_sec;    // connect timeout seconds
    int retries;        // connect retries
};

// Result metadata
struct wc_result_meta {
    char via_host[128];         // first server host (canonical)
    char via_ip[64];            // first server connected IP or "unknown"
    char authoritative_host[128]; // final authoritative server host
    char authoritative_ip[64];  // final authoritative server IP or "unknown"
    int hops;                   // hop count (including initial)
    unsigned int fallback_flags; // bitset (phase-in): 0x1 used_known_ip, 0x2 empty_retry, 0x4 forced_ipv4, 0x8 iana_pivot
    int last_connect_errno;     // errno of last failed connect (0 if success)
};

// Full result
struct wc_result {
    struct wc_result_meta meta;
    char* body;      // full WHOIS response text (heap)
    size_t body_len; // length
    int err;         // 0 on success else error code
};

// Execute WHOIS lookup: populate result (caller frees body). Returns 0 on success else error.
int wc_lookup_execute(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out);

// Release wc_result contents (safe on partial).
void wc_lookup_result_free(struct wc_result* r);

#ifdef __cplusplus
}
#endif

#endif // WC_LOOKUP_H_
