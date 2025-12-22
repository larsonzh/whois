#ifndef WC_RUNTIME_VIEW_H
#define WC_RUNTIME_VIEW_H

#include <stddef.h>

// Lightweight readonly slices of the active runtime configuration for
// modules that only need DNS/cache-related fields.
typedef struct wc_runtime_dns_view_s {
    int dns_retry;
    int dns_retry_interval_ms;
    int dns_max_candidates;
    int dns_addrconfig;
    int dns_family_mode;
    int prefer_ipv4;
    int prefer_ipv6;
    int ip_pref_mode;
} wc_runtime_dns_view_t;

typedef struct wc_runtime_cache_view_s {
    size_t dns_cache_size;
    size_t connection_cache_size;
    int cache_timeout;
    int dns_neg_cache_disable;
    int cache_counter_sampling;
    int debug;
} wc_runtime_cache_view_t;

const wc_runtime_dns_view_t* wc_runtime_dns_view(void);
const wc_runtime_cache_view_t* wc_runtime_cache_view(void);

#endif // WC_RUNTIME_VIEW_H
