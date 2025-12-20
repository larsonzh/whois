// SPDX-License-Identifier: GPL-3.0-or-later
// Cache-related helpers for whois client (server backoff, connection health, etc.).

#ifndef WC_CACHE_H
#define WC_CACHE_H

#include <stddef.h>
#include <sys/socket.h>

#include "wc_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WC_CACHE_MAX_DNS_ENTRIES 100
#define WC_CACHE_MAX_CONNECTION_ENTRIES 50

// Initialize/cleanup DNS and connection caches. Call init during startup
// and cleanup at exit (wc_runtime registers an atexit hook for cleanup).
// Prefer wc_cache_init_with_config to avoid relying on the global g_config.
void wc_cache_init_with_config(const Config* config);
void wc_cache_init(const Config* config);
void wc_cache_cleanup(void);
void wc_cache_cleanup_expired_entries(void);
int wc_cache_purge_expired_connections(const Config* config);
void wc_cache_drop_connections(void);


// Source identifiers for wc_cache DNS lookups (wc_dns bridge only).
typedef enum {
	WC_CACHE_DNS_SOURCE_NONE = 0,
	WC_CACHE_DNS_SOURCE_WCDNS = 1
} wc_cache_dns_source_t;

typedef enum {
	WC_CACHE_STORE_RESULT_NONE = 0,
	WC_CACHE_STORE_RESULT_WCDNS = 1 << 0
} wc_cache_store_result_t;

// DNS cache helpers. Getter returns a duplicated string that the caller
// must free. When 'source_out' is non-NULL it reports where the entry
// originated (legacy cache vs wc_dns bridge path). Negative cache helpers
// follow the same source reporting and accept errno-style indicators when
// storing failures. They are no-ops when disabled via config.
char* wc_cache_get_dns_with_source(const Config* config, const char* domain, wc_cache_dns_source_t* source_out);
char* wc_cache_get_dns(const Config* config, const char* domain);
wc_cache_store_result_t wc_cache_set_dns(const Config* config, const char* domain, const char* ip);
wc_cache_store_result_t wc_cache_set_dns_with_addr(const Config* config,
				       const char* domain,
				       const char* ip,
				       int sa_family,
				       const struct sockaddr* addr,
				       socklen_t addrlen);
int wc_cache_is_negative_dns_cached_with_source(const Config* config, const char* domain, wc_cache_dns_source_t* source_out);
int wc_cache_is_negative_dns_cached(const Config* config, const char* domain);
void wc_cache_set_negative_dns_with_error(const Config* config, const char* domain, int err);
void wc_cache_set_negative_dns(const Config* config, const char* domain);

// Connection cache helpers. Returned sockets remain owned by caller and
// must be closed or re-cached by the consumer when no longer needed.
int wc_cache_get_connection(const Config* config, const char* host, int port);
void wc_cache_set_connection(const Config* config, const char* host, int port, int sockfd);

// Check whether a server is currently backed off due to repeated failures.
// Returns 1 if backed off, 0 otherwise.
int wc_cache_is_server_backed_off(const Config* config, const char* host);

// Record a connection failure for the given server host.
void wc_cache_mark_server_failure(const Config* config, const char* host);

// Record a successful interaction with the given server host.
void wc_cache_mark_server_success(const Config* config, const char* host);

// Lightweight helper to check whether a given socket file descriptor is
// still considered alive. This is a thin wrapper around getsockopt(SO_ERROR).
int wc_cache_is_connection_alive(int sockfd);

// Debug-only cache integrity validation and statistics helpers.
void wc_cache_validate_integrity(void);
void wc_cache_log_statistics(void);

// Diagnostics helpers for negative DNS cache stats and sizing.
typedef struct {
	int hits;
	int sets;
	int shim_hits;
} wc_cache_neg_stats_t;

void wc_cache_get_negative_stats(wc_cache_neg_stats_t* stats);
size_t wc_cache_estimate_memory_bytes(size_t dns_entries, size_t connection_entries);

typedef struct {
	long hits;
	long misses;
	long shim_hits;
} wc_cache_dns_stats_t;

void wc_cache_get_dns_stats(wc_cache_dns_stats_t* stats);

// Legacy shim retired: keep stubs for compatibility; always disabled/no-op.
int wc_cache_legacy_dns_enabled(void);
void wc_cache_log_legacy_dns_event(const char* domain, const char* status);

#ifdef __cplusplus
}
#endif

#endif // WC_CACHE_H
