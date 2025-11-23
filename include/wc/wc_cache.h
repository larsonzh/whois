// SPDX-License-Identifier: GPL-3.0-or-later
// Cache-related helpers for whois client (server backoff, connection health, etc.).

#ifndef WC_CACHE_H
#define WC_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

// Initialize/cleanup DNS and connection caches. Call init during startup
// and cleanup at exit (wc_runtime registers an atexit hook for cleanup).
void wc_cache_init(void);
void wc_cache_cleanup(void);
void wc_cache_cleanup_expired_entries(void);
int wc_cache_validate_sizes(void);

// DNS cache helpers. Getter returns a duplicated string that the caller
// must free. Negative cache helpers are no-ops when disabled via config.
char* wc_cache_get_dns(const char* domain);
void wc_cache_set_dns(const char* domain, const char* ip);
int wc_cache_is_negative_dns_cached(const char* domain);
void wc_cache_set_negative_dns(const char* domain);

// Connection cache helpers. Returned sockets remain owned by caller and
// must be closed or re-cached by the consumer when no longer needed.
int wc_cache_get_connection(const char* host, int port);
void wc_cache_set_connection(const char* host, int port, int sockfd);

// Check whether a server is currently backed off due to repeated failures.
// Returns 1 if backed off, 0 otherwise.
int wc_cache_is_server_backed_off(const char* host);

// Record a connection failure for the given server host.
void wc_cache_mark_server_failure(const char* host);

// Record a successful interaction with the given server host.
void wc_cache_mark_server_success(const char* host);

// Lightweight helper to check whether a given socket file descriptor is
// still considered alive. This is a thin wrapper around getsockopt(SO_ERROR).
int wc_cache_is_connection_alive(int sockfd);

// Debug-only cache integrity validation and statistics helpers.
void wc_cache_validate_integrity(void);
void wc_cache_log_statistics(void);

// Diagnostics counters exposed for signal/runtime logging.
extern int g_dns_neg_cache_hits;
extern int g_dns_neg_cache_sets;

#ifdef __cplusplus
}
#endif

#endif // WC_CACHE_H
