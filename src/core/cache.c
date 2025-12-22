// SPDX-License-Identifier: GPL-3.0-or-later
// Cache-related helpers for whois client (server backoff, DNS cache, etc.).

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "wc/wc_backoff.h"
#include "wc/wc_cache.h"
#include "wc/wc_client_util.h"
#include "wc/wc_config.h"
#include "wc/wc_dns.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_runtime.h"
#include "wc/wc_util.h"

// Connection cache structure - stores connections to servers
typedef struct {
    char* host;
    int port;
    int sockfd;
    time_t last_used;
} ConnectionCacheEntry;

typedef struct {
    size_t dns_size;
    size_t conn_size;
    int timeout_seconds;
    int dns_neg_disabled;
    int debug_enabled;
    int initialized;
} wc_cache_runtime_state_t;

typedef struct {
    long dns_hits;
    long dns_misses;
    long dns_shim_hits;
    int neg_hits;
    int neg_sets;
    int neg_shim_hits;
} wc_cache_counter_state_t;

typedef struct {
    ConnectionCacheEntry* connection_cache;
    size_t allocated_connection_cache_size;
    wc_cache_runtime_state_t runtime;
    wc_cache_counter_state_t counters;
    pthread_mutex_t mutex;
    int config_warned;
} wc_cache_ctx_t;

static wc_cache_ctx_t g_cache_ctx = {
    .connection_cache = NULL,
    .allocated_connection_cache_size = 0,
    .runtime = {0},
    .counters = {0},
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .config_warned = 0
};

static int wc_cache_has_config(void)
{
    return g_cache_ctx.runtime.initialized;
}

static int wc_cache_debug_enabled(void)
{
    return g_cache_ctx.runtime.initialized && g_cache_ctx.runtime.debug_enabled;
}

static int wc_cache_global_debug_enabled(void)
{
    const wc_runtime_cfg_view_t* view = wc_runtime_config_view();
    return view ? view->debug : 0;
}

static size_t wc_cache_dns_size(void)
{
    return g_cache_ctx.runtime.dns_size;
}

static size_t wc_cache_conn_size(void)
{
    return g_cache_ctx.runtime.conn_size;
}

static int wc_cache_timeout_seconds(void)
{
    return g_cache_ctx.runtime.timeout_seconds;
}

static int wc_cache_negative_disabled(void)
{
    return g_cache_ctx.runtime.initialized && g_cache_ctx.runtime.dns_neg_disabled;
}

static int wc_cache_config_matches(const Config* config)
{
    if (!config || !g_cache_ctx.runtime.initialized)
        return 0;
    return (size_t)config->dns_cache_size == g_cache_ctx.runtime.dns_size &&
           (size_t)config->connection_cache_size == g_cache_ctx.runtime.conn_size &&
           config->cache_timeout == g_cache_ctx.runtime.timeout_seconds &&
           config->dns_neg_cache_disable == g_cache_ctx.runtime.dns_neg_disabled;
}

static int wc_cache_require_config(const Config* config, const char* where)
{
    if (wc_cache_config_matches(config))
        return 1;
    if (!g_cache_ctx.config_warned) {
        g_cache_ctx.config_warned = 1;
        wc_output_log_message("WARN",
            "%s called without active cache config; skipping cache usage", where);
    }
    return 0;
}

static void wc_cache_reset_runtime_state(void)
{
    memset(&g_cache_ctx.runtime, 0, sizeof(g_cache_ctx.runtime));
}

static void wc_cache_reset_counters(void)
{
    g_cache_ctx.counters.dns_hits = 0;
    g_cache_ctx.counters.dns_misses = 0;
    g_cache_ctx.counters.dns_shim_hits = 0;
    g_cache_ctx.counters.neg_hits = 0;
    g_cache_ctx.counters.neg_sets = 0;
    g_cache_ctx.counters.neg_shim_hits = 0;
}

#define WC_CACHE_LOCK() pthread_mutex_lock(&g_cache_ctx.mutex)
#define WC_CACHE_UNLOCK() pthread_mutex_unlock(&g_cache_ctx.mutex)

// Best-effort per-entry size estimates for wc_dns positive/negative caches.
#define WC_CACHE_ESTIMATED_DNS_ENTRY_BYTES 512
#define WC_CACHE_ESTIMATED_NEG_ENTRY_BYTES 64

int wc_cache_legacy_dns_enabled(void)
{
    return 0; // Legacy shim fully retired
}

void wc_cache_log_legacy_dns_event(const char* domain, const char* status)
{
    (void)domain;
    (void)status;
}

static int wc_cache_store_wcdns_bridge(const Config* config,
                                       const char* domain,
                                       const char* ip,
                                       int sa_family,
                                       const struct sockaddr* addr,
                                       socklen_t addrlen);

void wc_cache_cleanup(void)
{
    WC_CACHE_LOCK();

    if (g_cache_ctx.connection_cache) {
        for (size_t i = 0; i < g_cache_ctx.allocated_connection_cache_size; i++) {
            free(g_cache_ctx.connection_cache[i].host);
            g_cache_ctx.connection_cache[i].host = NULL;
            if (g_cache_ctx.connection_cache[i].sockfd != -1) {
                wc_safe_close(&g_cache_ctx.connection_cache[i].sockfd, "wc_cache_cleanup");
            }
        }
        free(g_cache_ctx.connection_cache);
        g_cache_ctx.connection_cache = NULL;
        g_cache_ctx.allocated_connection_cache_size = 0;
    }

    wc_cache_reset_runtime_state();
    wc_cache_reset_counters();
    g_cache_ctx.config_warned = 0;

    WC_CACHE_UNLOCK();
}

// Drop only connection cache entries while retaining runtime sizing/counters.
// Useful for scenarios where caller wants to force close sockets without
// reinitializing cache config.
void wc_cache_drop_connections(void)
{
    if (!wc_cache_has_config())
        return;

    WC_CACHE_LOCK();

    if (g_cache_ctx.connection_cache) {
        for (size_t i = 0; i < g_cache_ctx.allocated_connection_cache_size; i++) {
            free(g_cache_ctx.connection_cache[i].host);
            g_cache_ctx.connection_cache[i].host = NULL;
            if (g_cache_ctx.connection_cache[i].sockfd != -1) {
                wc_safe_close(&g_cache_ctx.connection_cache[i].sockfd, "wc_cache_drop_connections");
            }
            g_cache_ctx.connection_cache[i].sockfd = -1;
        }
    }

    WC_CACHE_UNLOCK();
}

static int wc_cache_purge_expired_internal(int require_config, const Config* config)
{
    if (require_config) {
        if (!wc_cache_require_config(config, "wc_cache_purge_expired_connections"))
            return 0;
    } else if (!wc_cache_has_config()) {
        return 0;
    }

    if (wc_cache_debug_enabled()) {
        wc_output_log_message("DEBUG", "Starting cache cleanup");
    }

    WC_CACHE_LOCK();

    time_t now = time(NULL);
    int conn_cleaned = 0;

    if (g_cache_ctx.connection_cache) {
        for (size_t i = 0; i < g_cache_ctx.allocated_connection_cache_size; i++) {
            if (g_cache_ctx.connection_cache[i].host) {
                if ((now - g_cache_ctx.connection_cache[i].last_used >= wc_cache_timeout_seconds()) ||
                    !wc_cache_is_connection_alive(g_cache_ctx.connection_cache[i].sockfd)) {
                    if (wc_cache_debug_enabled()) {
                        wc_output_log_message("DEBUG",
                            "Removing expired/dead connection: %s:%d",
                            g_cache_ctx.connection_cache[i].host,
                            g_cache_ctx.connection_cache[i].port);
                    }
                    wc_safe_close(&g_cache_ctx.connection_cache[i].sockfd, "wc_cache_purge_expired_connections");
                    free(g_cache_ctx.connection_cache[i].host);
                    g_cache_ctx.connection_cache[i].host = NULL;
                    g_cache_ctx.connection_cache[i].sockfd = -1;
                    conn_cleaned++;
                }
            }
        }
    }

    WC_CACHE_UNLOCK();

    if (wc_cache_debug_enabled() && conn_cleaned > 0) {
        wc_output_log_message("DEBUG",
            "Cache cleanup completed: %d connection entries removed",
            conn_cleaned);
    }

    return conn_cleaned;
}

void wc_cache_init_with_config(const Config* config)
{
    WC_CACHE_LOCK();

    wc_cache_reset_counters();
    g_cache_ctx.config_warned = 0;

    if (!config) {
        WC_CACHE_UNLOCK();
        return;
    }

    g_cache_ctx.runtime.dns_size = config->dns_cache_size;
    g_cache_ctx.runtime.conn_size = config->connection_cache_size;
    g_cache_ctx.runtime.timeout_seconds = config->cache_timeout;
    g_cache_ctx.runtime.dns_neg_disabled = config->dns_neg_cache_disable;
    g_cache_ctx.runtime.debug_enabled = config->debug;
    g_cache_ctx.runtime.initialized = 1;

    if (wc_cache_dns_size() == 0 ||
        wc_cache_dns_size() > WC_CACHE_MAX_DNS_ENTRIES ||
        wc_cache_conn_size() == 0 ||
        wc_cache_conn_size() > WC_CACHE_MAX_CONNECTION_ENTRIES) {
        wc_output_log_message("ERROR",
                   "Cache sizes misconfigured (dns=%zu, conn=%zu); re-run config prep",
                   wc_cache_dns_size(),
                   wc_cache_conn_size());
        wc_cache_reset_runtime_state();
        WC_CACHE_UNLOCK();
        return;
    }

    g_cache_ctx.connection_cache = wc_safe_malloc(wc_cache_conn_size() * sizeof(ConnectionCacheEntry),
                                  "wc_cache_init_with_config");
    memset(g_cache_ctx.connection_cache, 0, wc_cache_conn_size() * sizeof(ConnectionCacheEntry));
    for (size_t i = 0; i < wc_cache_conn_size(); i++) {
        g_cache_ctx.connection_cache[i].sockfd = -1;
    }
    g_cache_ctx.allocated_connection_cache_size = wc_cache_conn_size();
    if (wc_cache_debug_enabled()) {
        printf("[DEBUG] Connection cache allocated for %zu entries\n",
               wc_cache_conn_size());
    }

    WC_CACHE_UNLOCK();
}

void wc_cache_init(const Config* config)
{
    wc_cache_init_with_config(config);
}

void wc_cache_cleanup_expired_entries(void)
{
    (void)wc_cache_purge_expired_internal(0, NULL);
}

int wc_cache_purge_expired_connections(const Config* config)
{
    return wc_cache_purge_expired_internal(1, config);
}

static char* wc_cache_try_wcdns_bridge(const Config* config,
                                       const char* domain,
                                       wc_cache_dns_source_t* source_out)
{
    if (!config || !domain || !*domain) {
        return NULL;
    }
    wc_dns_bridge_ctx_t bridge = {0};
    wc_dns_bridge_ctx_init(domain, &bridge);
    if (!bridge.canonical_host || !*bridge.canonical_host) {
        return NULL;
    }
    char* bridged = wc_dns_cache_lookup_literal(config, bridge.canonical_host);
    if (bridged) {
        if (wc_cache_has_config()) {
            WC_CACHE_LOCK();
            g_cache_ctx.counters.dns_hits++;
            g_cache_ctx.counters.dns_shim_hits++;
            WC_CACHE_UNLOCK();
        }
        wc_cache_log_legacy_dns_event(domain, "wcdns-hit");
        if (source_out) {
            *source_out = WC_CACHE_DNS_SOURCE_WCDNS;
        }
        return bridged;
    }
    return NULL;
}

char* wc_cache_get_dns_with_source(const Config* config,
                                   const char* domain,
                                   wc_cache_dns_source_t* source_out)
{
    if (source_out) {
        *source_out = WC_CACHE_DNS_SOURCE_NONE;
    }
    if (!config || !wc_client_is_valid_domain_name(domain)) {
        wc_output_log_message("WARN",
                   "Invalid domain name for DNS cache lookup: %s",
                   domain);
        return NULL;
    }

    char* bridged = wc_cache_try_wcdns_bridge(config, domain, source_out);
    if (bridged) {
        return bridged;
    }
    if (wc_cache_has_config()) {
        WC_CACHE_LOCK();
        g_cache_ctx.counters.dns_misses++;
        WC_CACHE_UNLOCK();
    }
    wc_cache_log_legacy_dns_event(domain, "miss");
    return NULL;
}

char* wc_cache_get_dns(const Config* config, const char* domain)
{
    return wc_cache_get_dns_with_source(config, domain, NULL);
}

wc_cache_store_result_t wc_cache_set_dns(const Config* config, const char* domain, const char* ip)
{
    return wc_cache_set_dns_with_addr(config, domain, ip, AF_UNSPEC, NULL, 0);
}

wc_cache_store_result_t wc_cache_set_dns_with_addr(const Config* config,
                                                   const char* domain,
                                                   const char* ip,
                                                   int sa_family,
                                                   const struct sockaddr* addr,
                                                   socklen_t addrlen)
{
    wc_cache_store_result_t result = WC_CACHE_STORE_RESULT_NONE;
    if (!config || !wc_client_is_valid_domain_name(domain)) {
        wc_output_log_message("WARN",
                   "Attempted to cache invalid domain: %s",
                   domain);
        return result;
    }

    if (!wc_client_validate_dns_response(ip)) {
        wc_output_log_message("WARN",
                   "Attempted to cache invalid IP: %s for domain %s",
                   ip,
                   domain);
        return result;
    }

    if (wc_cache_store_wcdns_bridge(config, domain, ip, sa_family, addr, addrlen)) {
        result = (wc_cache_store_result_t)(result | WC_CACHE_STORE_RESULT_WCDNS);
        wc_cache_log_legacy_dns_event(domain, "wcdns-store");
    }
    return result;
}

static int wc_cache_store_wcdns_bridge(const Config* config,
                                       const char* domain,
                                       const char* ip,
                                       int sa_family,
                                       const struct sockaddr* addr,
                                       socklen_t addrlen)
{
    if (!config || !domain || !ip || !wc_dns_is_ip_literal(ip)) {
        return 0;
    }
    wc_dns_bridge_ctx_t bridge = {0};
    wc_dns_bridge_ctx_init(domain, &bridge);
    if (!bridge.canonical_host || !*bridge.canonical_host) {
        return 0;
    }
    const struct sockaddr* addr_ptr = NULL;
    socklen_t addr_len = 0;
    int final_family = sa_family;
    if (addr && addrlen > 0 && addrlen <= (socklen_t)sizeof(struct sockaddr_storage)) {
        addr_ptr = addr;
        addr_len = addrlen;
    }
    wc_dns_cache_store_literal(config,
                               bridge.canonical_host,
                               ip,
                               final_family,
                               addr_ptr,
                               addr_len);
    return 1;
}

static int wc_cache_store_negative_wcdns_bridge(const Config* config, const char* domain, int err)
{
    if (!config || !domain || !*domain) {
        return 0;
    }
    wc_dns_bridge_ctx_t bridge = {0};
    wc_dns_bridge_ctx_init(domain, &bridge);
    if (!bridge.canonical_host || !*bridge.canonical_host) {
        return 0;
    }
    int final_err = (err != 0) ? err : EAI_FAIL;
    wc_dns_negative_cache_store(config, bridge.canonical_host, final_err);
    return 1;
}

static int wc_cache_try_wcdns_negative(const Config* config, const char* domain)
{
    if (!config || !domain || !*domain) {
        return 0;
    }
    wc_dns_bridge_ctx_t bridge = {0};
    wc_dns_bridge_ctx_init(domain, &bridge);
    if (!bridge.canonical_host || !*bridge.canonical_host) {
        return 0;
    }
    int neg_err = 0;
    int hit = wc_dns_negative_cache_lookup(config, bridge.canonical_host, &neg_err);
    if (hit && wc_cache_has_config()) {
        WC_CACHE_LOCK();
        g_cache_ctx.counters.neg_hits++;
        g_cache_ctx.counters.neg_shim_hits++;
        WC_CACHE_UNLOCK();
    }
    return hit;
}

int wc_cache_is_negative_dns_cached_with_source(const Config* config,
                                                const char* domain,
                                                wc_cache_dns_source_t* source_out)
{
    if (source_out) {
        *source_out = WC_CACHE_DNS_SOURCE_NONE;
    }
    if (!config || !wc_cache_has_config() || wc_cache_negative_disabled() || !domain || !*domain) {
        return 0;
    }
    if (wc_cache_try_wcdns_negative(config, domain)) {
        if (source_out) {
            *source_out = WC_CACHE_DNS_SOURCE_WCDNS;
        }
        wc_cache_log_legacy_dns_event(domain, "neg-bridge");
        return 1;
    }
    return 0;
}

int wc_cache_is_negative_dns_cached(const Config* config, const char* domain)
{
    return wc_cache_is_negative_dns_cached_with_source(config, domain, NULL);
}

void wc_cache_set_negative_dns_with_error(const Config* config, const char* domain, int err)
{
    if (!config || !wc_cache_has_config() || wc_cache_negative_disabled() || !domain || !*domain) {
        return;
    }
    if (wc_cache_store_negative_wcdns_bridge(config, domain, err)) {
        g_cache_ctx.counters.neg_sets++;
    }
}

void wc_cache_set_negative_dns(const Config* config, const char* domain)
{
    wc_cache_set_negative_dns_with_error(config, domain, EAI_FAIL);
}

int wc_cache_get_connection(const Config* config, const char* host, int port)
{
    if (!wc_cache_require_config(config, "wc_cache_get_connection")) {
        return -1;
    }

    WC_CACHE_LOCK();

    if (!g_cache_ctx.connection_cache || wc_cache_conn_size() == 0) {
        WC_CACHE_UNLOCK();
        return -1;
    }

    time_t now = time(NULL);
    for (size_t i = 0; i < g_cache_ctx.allocated_connection_cache_size; i++) {
        if (g_cache_ctx.connection_cache[i].host &&
            strcmp(g_cache_ctx.connection_cache[i].host, host) == 0 &&
            g_cache_ctx.connection_cache[i].port == port) {
            if (now - g_cache_ctx.connection_cache[i].last_used < wc_cache_timeout_seconds()) {
                if (wc_cache_is_connection_alive(g_cache_ctx.connection_cache[i].sockfd)) {
                    g_cache_ctx.connection_cache[i].last_used = now;
                    int sockfd = g_cache_ctx.connection_cache[i].sockfd;
                    WC_CACHE_UNLOCK();
                    return sockfd;
                }
                wc_safe_close(&g_cache_ctx.connection_cache[i].sockfd, "wc_cache_get_connection");
                free(g_cache_ctx.connection_cache[i].host);
                g_cache_ctx.connection_cache[i].host = NULL;
            } else {
                wc_safe_close(&g_cache_ctx.connection_cache[i].sockfd, "wc_cache_get_connection");
                free(g_cache_ctx.connection_cache[i].host);
                g_cache_ctx.connection_cache[i].host = NULL;
            }
        }
    }

    WC_CACHE_UNLOCK();
    return -1;
}

void wc_cache_set_connection(const Config* config, const char* host, int port, int sockfd)
{
    if (!wc_cache_require_config(config, "wc_cache_set_connection")) {
        return;
    }

    if (!host || !*host) {
        wc_output_log_message("WARN",
                   "Attempted to cache connection with invalid host");
        return;
    }

    if (port <= 0 || port > 65535) {
        wc_output_log_message("WARN",
                   "Attempted to cache connection with invalid port: %d",
                   port);
        return;
    }

    if (sockfd < 0) {
        wc_output_log_message("WARN",
                   "Attempted to cache invalid socket descriptor: %d",
                   sockfd);
        return;
    }

    if (!wc_cache_is_connection_alive(sockfd)) {
        wc_output_log_message("WARN",
                   "Attempted to cache dead connection to %s:%d",
                   host,
                   port);
        wc_safe_close(&sockfd, "wc_cache_set_connection");
        return;
    }

    WC_CACHE_LOCK();

    if (!g_cache_ctx.connection_cache || wc_cache_conn_size() == 0) {
        WC_CACHE_UNLOCK();
        return;
    }

    int oldest_index = 0;
    time_t oldest_time = time(NULL);

    for (size_t i = 0; i < g_cache_ctx.allocated_connection_cache_size; i++) {
        if (!g_cache_ctx.connection_cache[i].host) {
            g_cache_ctx.connection_cache[i].host = wc_safe_strdup(host, "wc_cache_set_connection");
            g_cache_ctx.connection_cache[i].port = port;
            g_cache_ctx.connection_cache[i].sockfd = sockfd;
            g_cache_ctx.connection_cache[i].last_used = time(NULL);
            if (wc_cache_debug_enabled()) {
                wc_output_log_message("DEBUG",
                           "Cached connection to %s:%d (slot %d)",
                           host,
                           port,
                           (int)i);
            }
            WC_CACHE_UNLOCK();
            return;
        }

        if (g_cache_ctx.connection_cache[i].last_used < oldest_time) {
            oldest_time = g_cache_ctx.connection_cache[i].last_used;
            oldest_index = (int)i;
        }
    }

    if (wc_cache_debug_enabled()) {
        wc_output_log_message("DEBUG",
                   "Replacing oldest connection (slot %d) with %s:%d",
                   oldest_index,
                   host,
                   port);
    }

    wc_safe_close(&g_cache_ctx.connection_cache[oldest_index].sockfd, "wc_cache_set_connection");
    free(g_cache_ctx.connection_cache[oldest_index].host);
    g_cache_ctx.connection_cache[oldest_index].host = wc_safe_strdup(host, "wc_cache_set_connection");
    g_cache_ctx.connection_cache[oldest_index].port = port;
    g_cache_ctx.connection_cache[oldest_index].sockfd = sockfd;
    g_cache_ctx.connection_cache[oldest_index].last_used = time(NULL);

    WC_CACHE_UNLOCK();
}

void wc_cache_validate_integrity(void)
{
    if (!wc_cache_debug_enabled()) {
        return;
    }

    WC_CACHE_LOCK();

    int conn_valid = 0;
    int conn_invalid = 0;

    if (g_cache_ctx.connection_cache) {
        for (size_t i = 0; i < g_cache_ctx.allocated_connection_cache_size; i++) {
            if (g_cache_ctx.connection_cache[i].host) {
                if (wc_client_is_valid_domain_name(g_cache_ctx.connection_cache[i].host) &&
                    g_cache_ctx.connection_cache[i].port > 0 &&
                    g_cache_ctx.connection_cache[i].port <= 65535 &&
                    g_cache_ctx.connection_cache[i].sockfd >= 0 &&
                    wc_cache_is_connection_alive(g_cache_ctx.connection_cache[i].sockfd)) {
                    conn_valid++;
                } else {
                    conn_invalid++;
                    wc_output_log_message("WARN",
                               "Invalid connection cache entry: %s:%d (fd: %d)",
                               g_cache_ctx.connection_cache[i].host,
                               g_cache_ctx.connection_cache[i].port,
                               g_cache_ctx.connection_cache[i].sockfd);
                }
            }
        }
    }

    WC_CACHE_UNLOCK();

    if (conn_invalid > 0) {
        wc_output_log_message("INFO",
                   "Cache integrity check: %d/%d connections valid",
                   conn_valid,
                   conn_valid + conn_invalid);
    }
}

void wc_cache_log_statistics(int sampling_enabled)
{
    const int debug_enabled = wc_cache_debug_enabled();
    if (!debug_enabled && !sampling_enabled) {
        return;
    }

    WC_CACHE_LOCK();

    int conn_entries = 0;
    long dns_hits = 0;
    long dns_misses = 0;
    long dns_shim_hits = 0;
    int neg_hits = 0;
    int neg_sets = 0;
    int neg_shim_hits = 0;

    if (g_cache_ctx.connection_cache) {
        for (size_t i = 0; i < g_cache_ctx.allocated_connection_cache_size; i++) {
            if (g_cache_ctx.connection_cache[i].host) {
                conn_entries++;
            }
        }
    }

    dns_hits = g_cache_ctx.counters.dns_hits;
    dns_misses = g_cache_ctx.counters.dns_misses;
    dns_shim_hits = g_cache_ctx.counters.dns_shim_hits;
    neg_hits = g_cache_ctx.counters.neg_hits;
    neg_sets = g_cache_ctx.counters.neg_sets;
    neg_shim_hits = g_cache_ctx.counters.neg_shim_hits;

    WC_CACHE_UNLOCK();

    if (!debug_enabled && sampling_enabled) {
        if (conn_entries == 0 && dns_hits == 0 && dns_misses == 0 &&
            dns_shim_hits == 0 && neg_hits == 0 && neg_sets == 0 &&
            neg_shim_hits == 0) {
            return;
        }
    }

    wc_output_log_message("DEBUG",
               "Cache statistics: %d/%zu connection entries",
               conn_entries,
               wc_cache_conn_size());
    wc_output_log_message("DEBUG",
               "Cache counters: dns_hits=%ld dns_misses=%ld dns_shim_hits=%ld neg_hits=%d neg_sets=%d neg_shim_hits=%d",
               dns_hits,
               dns_misses,
               dns_shim_hits,
               neg_hits,
               neg_sets,
               neg_shim_hits);
}

int wc_cache_is_server_backed_off(const Config* config, const char* host)
{
    if (!config || !host || !*host) return 0;
    wc_dns_health_snapshot_t snap;
    int backed_off = wc_backoff_should_skip(config, host, AF_UNSPEC, &snap);
    if (backed_off && wc_cache_global_debug_enabled()) {
        wc_output_log_message("DEBUG",
                   "Server %s is backed off (family=%s penalty_ms_left=%ld)",
                   host,
                   (snap.family == AF_INET6) ? "ipv6" : "ipv4",
                   snap.penalty_ms_left);
    }
    return backed_off;
}

void wc_cache_mark_server_failure(const Config* config, const char* host)
{
    if (!config || !host || !*host) return;
    wc_backoff_note_failure(config, host, AF_UNSPEC);
    if (wc_cache_global_debug_enabled()) {
        wc_output_log_message("DEBUG",
                   "Marked server %s failure (backoff counter updated)",
                   host);
    }
}

void wc_cache_mark_server_success(const Config* config, const char* host)
{
    if (!config || !host || !*host) return;
    wc_backoff_note_success(config, host, AF_UNSPEC);
    if (wc_cache_global_debug_enabled()) {
        wc_output_log_message("DEBUG",
                   "Reset failure count for server %s",
                   host);
    }
}

int wc_cache_is_connection_alive(int sockfd)
{
    if (sockfd == -1) return 0;

    int error = 0;
    socklen_t len = sizeof(error);

    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        return error == 0;
    }

    return 0;
}

void wc_cache_get_negative_stats(wc_cache_neg_stats_t* stats)
{
    if (!stats) return;
    WC_CACHE_LOCK();
    stats->hits = g_cache_ctx.counters.neg_hits;
    stats->sets = g_cache_ctx.counters.neg_sets;
    stats->shim_hits = g_cache_ctx.counters.neg_shim_hits;
    WC_CACHE_UNLOCK();
}

size_t wc_cache_estimate_memory_bytes(size_t dns_entries, size_t connection_entries)
{
    const size_t dns_bytes = dns_entries *
            (WC_CACHE_ESTIMATED_DNS_ENTRY_BYTES + WC_CACHE_ESTIMATED_NEG_ENTRY_BYTES);
    const size_t connection_bytes = connection_entries * sizeof(ConnectionCacheEntry);
    return dns_bytes + connection_bytes;
}

void wc_cache_get_dns_stats(wc_cache_dns_stats_t* stats)
{
    if (!stats) return;
    WC_CACHE_LOCK();
    stats->hits = g_cache_ctx.counters.dns_hits;
    stats->misses = g_cache_ctx.counters.dns_misses;
    stats->shim_hits = g_cache_ctx.counters.dns_shim_hits;
    WC_CACHE_UNLOCK();
}
