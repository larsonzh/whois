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
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_util.h"

static const Config* g_cache_config = NULL;

static int wc_cache_has_config(void)
{
    return g_cache_config != NULL;
}

static int wc_cache_debug_enabled(void)
{
    return g_cache_config && g_cache_config->debug;
}

static size_t wc_cache_dns_size(void)
{
    return g_cache_config ? g_cache_config->dns_cache_size : 0;
}

static size_t wc_cache_conn_size(void)
{
    return g_cache_config ? g_cache_config->connection_cache_size : 0;
}

static int wc_cache_timeout_seconds(void)
{
    return g_cache_config ? g_cache_config->cache_timeout : 0;
}

static int wc_cache_negative_disabled(void)
{
    return g_cache_config ? g_cache_config->dns_neg_cache_disable : 0;
}

// Best-effort per-entry size estimates for wc_dns positive/negative caches.
#define WC_CACHE_ESTIMATED_DNS_ENTRY_BYTES 512
#define WC_CACHE_ESTIMATED_NEG_ENTRY_BYTES 64

// Connection cache structure - stores connections to servers
typedef struct {
    char* host;
    int port;
    int sockfd;
    time_t last_used;
} ConnectionCacheEntry;

static ConnectionCacheEntry* connection_cache = NULL;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t allocated_connection_cache_size = 0;
static long g_dns_cache_hits_total = 0;
static long g_dns_cache_misses_total = 0;
static long g_dns_cache_shim_hits_total = 0;
int g_dns_neg_cache_hits = 0;
int g_dns_neg_cache_sets = 0;
int g_dns_neg_cache_shim_hits = 0;

int wc_cache_legacy_dns_enabled(void)
{
    return 0; // Legacy shim fully retired
}

void wc_cache_log_legacy_dns_event(const char* domain, const char* status)
{
    (void)domain;
    (void)status;
}

static int wc_cache_store_wcdns_bridge(const char* domain,
                                       const char* ip,
                                       int sa_family,
                                       const struct sockaddr* addr,
                                       socklen_t addrlen);

void wc_cache_cleanup(void)
{
    pthread_mutex_lock(&cache_mutex);

    if (connection_cache) {
        for (size_t i = 0; i < allocated_connection_cache_size; i++) {
            free(connection_cache[i].host);
            connection_cache[i].host = NULL;
            if (connection_cache[i].sockfd != -1) {
                wc_safe_close(&connection_cache[i].sockfd, "wc_cache_cleanup");
            }
        }
        free(connection_cache);
        connection_cache = NULL;
        allocated_connection_cache_size = 0;
    }

    pthread_mutex_unlock(&cache_mutex);
}

void wc_cache_init_with_config(const Config* config)
{
    pthread_mutex_lock(&cache_mutex);

    g_cache_config = config;
    if (!wc_cache_has_config()) {
        pthread_mutex_unlock(&cache_mutex);
        return;
    }

    if (wc_cache_dns_size() == 0 ||
        wc_cache_dns_size() > WC_CACHE_MAX_DNS_ENTRIES ||
        wc_cache_conn_size() == 0 ||
        wc_cache_conn_size() > WC_CACHE_MAX_CONNECTION_ENTRIES) {
        wc_output_log_message("ERROR",
                   "Cache sizes misconfigured (dns=%zu, conn=%zu); re-run config prep",
                   wc_cache_dns_size(),
                   wc_cache_conn_size());
        pthread_mutex_unlock(&cache_mutex);
        return;
    }

    connection_cache = wc_safe_malloc(wc_cache_conn_size() * sizeof(ConnectionCacheEntry),
                      "wc_cache_init_with_config");
    memset(connection_cache, 0, wc_cache_conn_size() * sizeof(ConnectionCacheEntry));
    for (size_t i = 0; i < wc_cache_conn_size(); i++) {
        connection_cache[i].sockfd = -1;
    }
    allocated_connection_cache_size = wc_cache_conn_size();
    if (wc_cache_debug_enabled()) {
        printf("[DEBUG] Connection cache allocated for %zu entries\n",
               wc_cache_conn_size());
    }

    pthread_mutex_unlock(&cache_mutex);
}

void wc_cache_init(const Config* config)
{
    wc_cache_init_with_config(config);
}

void wc_cache_cleanup_expired_entries(void)
{
    if (!wc_cache_has_config()) {
        return;
    }

    if (wc_cache_debug_enabled()) {
        wc_output_log_message("DEBUG", "Starting cache cleanup");
    }

    pthread_mutex_lock(&cache_mutex);

    time_t now = time(NULL);
    int conn_cleaned = 0;

    if (connection_cache) {
        for (size_t i = 0; i < allocated_connection_cache_size; i++) {
            if (connection_cache[i].host) {
                if ((now - connection_cache[i].last_used >= wc_cache_timeout_seconds()) ||
                    !wc_cache_is_connection_alive(connection_cache[i].sockfd)) {
                    if (wc_cache_debug_enabled()) {
                        wc_output_log_message("DEBUG",
                                   "Removing expired/dead connection: %s:%d",
                                   connection_cache[i].host,
                                   connection_cache[i].port);
                    }
                    wc_safe_close(&connection_cache[i].sockfd, "wc_cache_cleanup_expired_entries");
                    free(connection_cache[i].host);
                    connection_cache[i].host = NULL;
                    connection_cache[i].sockfd = -1;
                    conn_cleaned++;
                }
            }
        }
    }

    pthread_mutex_unlock(&cache_mutex);

    if (wc_cache_debug_enabled() && conn_cleaned > 0) {
        wc_output_log_message("DEBUG",
                   "Cache cleanup completed: %d connection entries removed",
                   conn_cleaned);
    }
}

static char* wc_cache_try_wcdns_bridge(const char* domain, wc_cache_dns_source_t* source_out)
{
    if (!domain || !*domain) {
        return NULL;
    }
    wc_dns_bridge_ctx_t bridge = {0};
    wc_dns_bridge_ctx_init(domain, &bridge);
    if (!bridge.canonical_host || !*bridge.canonical_host) {
        return NULL;
    }
    char* bridged = wc_dns_cache_lookup_literal(bridge.canonical_host);
    if (bridged) {
        wc_cache_log_legacy_dns_event(domain, "wcdns-hit");
        if (source_out) {
            *source_out = WC_CACHE_DNS_SOURCE_WCDNS;
        }
        return bridged;
    }
    return NULL;
}

char* wc_cache_get_dns_with_source(const char* domain, wc_cache_dns_source_t* source_out)
{
    if (source_out) {
        *source_out = WC_CACHE_DNS_SOURCE_NONE;
    }
    if (!wc_client_is_valid_domain_name(domain)) {
        wc_output_log_message("WARN",
                   "Invalid domain name for DNS cache lookup: %s",
                   domain);
        return NULL;
    }

    char* bridged = wc_cache_try_wcdns_bridge(domain, source_out);
    if (bridged) {
        return bridged;
    }
    wc_cache_log_legacy_dns_event(domain, "miss");
    return NULL;
}

char* wc_cache_get_dns(const char* domain)
{
    return wc_cache_get_dns_with_source(domain, NULL);
}

wc_cache_store_result_t wc_cache_set_dns(const char* domain, const char* ip)
{
    return wc_cache_set_dns_with_addr(domain, ip, AF_UNSPEC, NULL, 0);
}

wc_cache_store_result_t wc_cache_set_dns_with_addr(const char* domain,
                                                   const char* ip,
                                                   int sa_family,
                                                   const struct sockaddr* addr,
                                                   socklen_t addrlen)
{
    wc_cache_store_result_t result = WC_CACHE_STORE_RESULT_NONE;
    if (!wc_client_is_valid_domain_name(domain)) {
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

    if (wc_cache_store_wcdns_bridge(domain, ip, sa_family, addr, addrlen)) {
        result = (wc_cache_store_result_t)(result | WC_CACHE_STORE_RESULT_WCDNS);
        wc_cache_log_legacy_dns_event(domain, "wcdns-store");
    }
    return result;
}

static int wc_cache_store_wcdns_bridge(const char* domain,
                                       const char* ip,
                                       int sa_family,
                                       const struct sockaddr* addr,
                                       socklen_t addrlen)
{
    if (!domain || !ip || !wc_dns_is_ip_literal(ip)) {
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
    wc_dns_cache_store_literal(bridge.canonical_host,
                               ip,
                               final_family,
                               addr_ptr,
                               addr_len);
    return 1;
}

static int wc_cache_store_negative_wcdns_bridge(const char* domain, int err)
{
    if (!domain || !*domain) {
        return 0;
    }
    wc_dns_bridge_ctx_t bridge = {0};
    wc_dns_bridge_ctx_init(domain, &bridge);
    if (!bridge.canonical_host || !*bridge.canonical_host) {
        return 0;
    }
    int final_err = (err != 0) ? err : EAI_FAIL;
    wc_dns_negative_cache_store(bridge.canonical_host, final_err);
    return 1;
}

static int wc_cache_try_wcdns_negative(const char* domain)
{
    if (!domain || !*domain) {
        return 0;
    }
    wc_dns_bridge_ctx_t bridge = {0};
    wc_dns_bridge_ctx_init(domain, &bridge);
    if (!bridge.canonical_host || !*bridge.canonical_host) {
        return 0;
    }
    int neg_err = 0;
    return wc_dns_negative_cache_lookup(bridge.canonical_host, &neg_err);
}

int wc_cache_is_negative_dns_cached_with_source(const char* domain, wc_cache_dns_source_t* source_out)
{
    if (source_out) {
        *source_out = WC_CACHE_DNS_SOURCE_NONE;
    }
    if (!wc_cache_has_config() || wc_cache_negative_disabled() || !domain || !*domain) {
        return 0;
    }
    if (wc_cache_try_wcdns_negative(domain)) {
        if (source_out) {
            *source_out = WC_CACHE_DNS_SOURCE_WCDNS;
        }
        wc_cache_log_legacy_dns_event(domain, "neg-bridge");
        return 1;
    }
    return 0;
}

int wc_cache_is_negative_dns_cached(const char* domain)
{
    return wc_cache_is_negative_dns_cached_with_source(domain, NULL);
}

void wc_cache_set_negative_dns_with_error(const char* domain, int err)
{
    if (!wc_cache_has_config() || wc_cache_negative_disabled() || !domain || !*domain) {
        return;
    }
    if (wc_cache_store_negative_wcdns_bridge(domain, err)) {
        g_dns_neg_cache_sets++;
    }
}

void wc_cache_set_negative_dns(const char* domain)
{
    wc_cache_set_negative_dns_with_error(domain, EAI_FAIL);
}

int wc_cache_get_connection(const char* host, int port)
{
    if (!wc_cache_has_config()) {
        return -1;
    }

    pthread_mutex_lock(&cache_mutex);

    if (!connection_cache || wc_cache_conn_size() == 0) {
        pthread_mutex_unlock(&cache_mutex);
        return -1;
    }

    time_t now = time(NULL);
    for (size_t i = 0; i < allocated_connection_cache_size; i++) {
        if (connection_cache[i].host &&
            strcmp(connection_cache[i].host, host) == 0 &&
            connection_cache[i].port == port) {
            if (now - connection_cache[i].last_used < wc_cache_timeout_seconds()) {
                if (wc_cache_is_connection_alive(connection_cache[i].sockfd)) {
                    connection_cache[i].last_used = now;
                    int sockfd = connection_cache[i].sockfd;
                    pthread_mutex_unlock(&cache_mutex);
                    return sockfd;
                }
                wc_safe_close(&connection_cache[i].sockfd, "wc_cache_get_connection");
                free(connection_cache[i].host);
                connection_cache[i].host = NULL;
            } else {
                wc_safe_close(&connection_cache[i].sockfd, "wc_cache_get_connection");
                free(connection_cache[i].host);
                connection_cache[i].host = NULL;
            }
        }
    }

    pthread_mutex_unlock(&cache_mutex);
    return -1;
}

void wc_cache_set_connection(const char* host, int port, int sockfd)
{
    if (!wc_cache_has_config()) {
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

    pthread_mutex_lock(&cache_mutex);

    if (!connection_cache || wc_cache_conn_size() == 0) {
        pthread_mutex_unlock(&cache_mutex);
        return;
    }

    int oldest_index = 0;
    time_t oldest_time = time(NULL);

    for (size_t i = 0; i < allocated_connection_cache_size; i++) {
        if (!connection_cache[i].host) {
            connection_cache[i].host = wc_safe_strdup(host, "wc_cache_set_connection");
            connection_cache[i].port = port;
            connection_cache[i].sockfd = sockfd;
            connection_cache[i].last_used = time(NULL);
            if (wc_cache_debug_enabled()) {
                wc_output_log_message("DEBUG",
                           "Cached connection to %s:%d (slot %d)",
                           host,
                           port,
                           (int)i);
            }
            pthread_mutex_unlock(&cache_mutex);
            return;
        }

        if (connection_cache[i].last_used < oldest_time) {
            oldest_time = connection_cache[i].last_used;
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

    wc_safe_close(&connection_cache[oldest_index].sockfd, "wc_cache_set_connection");
    free(connection_cache[oldest_index].host);
    connection_cache[oldest_index].host = wc_safe_strdup(host, "wc_cache_set_connection");
    connection_cache[oldest_index].port = port;
    connection_cache[oldest_index].sockfd = sockfd;
    connection_cache[oldest_index].last_used = time(NULL);

    pthread_mutex_unlock(&cache_mutex);
}

void wc_cache_validate_integrity(void)
{
    if (!wc_cache_debug_enabled()) {
        return;
    }

    pthread_mutex_lock(&cache_mutex);

    int conn_valid = 0;
    int conn_invalid = 0;

    if (connection_cache) {
        for (size_t i = 0; i < allocated_connection_cache_size; i++) {
            if (connection_cache[i].host) {
                if (wc_client_is_valid_domain_name(connection_cache[i].host) &&
                    connection_cache[i].port > 0 &&
                    connection_cache[i].port <= 65535 &&
                    connection_cache[i].sockfd >= 0 &&
                    wc_cache_is_connection_alive(connection_cache[i].sockfd)) {
                    conn_valid++;
                } else {
                    conn_invalid++;
                    wc_output_log_message("WARN",
                               "Invalid connection cache entry: %s:%d (fd: %d)",
                               connection_cache[i].host,
                               connection_cache[i].port,
                               connection_cache[i].sockfd);
                }
            }
        }
    }

    pthread_mutex_unlock(&cache_mutex);

    if (conn_invalid > 0) {
        wc_output_log_message("INFO",
                   "Cache integrity check: %d/%d connections valid",
                   conn_valid,
                   conn_valid + conn_invalid);
    }
}

void wc_cache_log_statistics(void)
{
    if (!wc_cache_debug_enabled()) {
        return;
    }

    pthread_mutex_lock(&cache_mutex);

    int conn_entries = 0;

    if (connection_cache) {
        for (size_t i = 0; i < allocated_connection_cache_size; i++) {
            if (connection_cache[i].host) {
                conn_entries++;
            }
        }
    }

    pthread_mutex_unlock(&cache_mutex);

    wc_output_log_message("DEBUG",
               "Cache statistics: %d/%zu connection entries",
               conn_entries,
               wc_cache_conn_size());
}

int wc_cache_is_server_backed_off(const char* host)
{
    if (!host || !*host) return 0;
    wc_dns_health_snapshot_t snap;
    int backed_off = wc_backoff_should_skip(host, AF_UNSPEC, &snap);
    if (backed_off && wc_is_debug_enabled()) {
        wc_output_log_message("DEBUG",
                   "Server %s is backed off (family=%s penalty_ms_left=%ld)",
                   host,
                   (snap.family == AF_INET6) ? "ipv6" : "ipv4",
                   snap.penalty_ms_left);
    }
    return backed_off;
}

void wc_cache_mark_server_failure(const char* host)
{
    if (!host || !*host) return;
    wc_backoff_note_failure(host, AF_UNSPEC);
    if (wc_is_debug_enabled()) {
        wc_output_log_message("DEBUG",
                   "Marked server %s failure (backoff counter updated)",
                   host);
    }
}

void wc_cache_mark_server_success(const char* host)
{
    if (!host || !*host) return;
    wc_backoff_note_success(host, AF_UNSPEC);
    if (wc_is_debug_enabled()) {
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
    stats->hits = g_dns_neg_cache_hits;
    stats->sets = g_dns_neg_cache_sets;
    stats->shim_hits = g_dns_neg_cache_shim_hits;
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
    pthread_mutex_lock(&cache_mutex);
    stats->hits = g_dns_cache_hits_total;
    stats->misses = g_dns_cache_misses_total;
    stats->shim_hits = g_dns_cache_shim_hits_total;
    pthread_mutex_unlock(&cache_mutex);
}
