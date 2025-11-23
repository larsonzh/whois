// SPDX-License-Identifier: GPL-3.0-or-later
// Cache-related helpers for whois client (server backoff, connection health, etc.).

#ifndef WC_CACHE_H
#define WC_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

// Check whether a server is currently backed off due to repeated failures.
// Returns 1 if backed off, 0 otherwise.
int wc_cache_is_server_backed_off(const char* host);

// Record a connection failure for the given server host.
void wc_cache_mark_server_failure(const char* host);

// Record a successful interaction with the given server host.
void wc_cache_mark_server_success(const char* host);

// Lightweight helper to check whether a given socket file descriptor is
// still considered alive. This is a thin wrapper around getsockopt(SO_ERROR)
// and is used by connection cache logic in whois_client.c.
int wc_cache_is_connection_alive(int sockfd);

// Debug-only cache integrity validation and statistics helpers.
// `whois_client.c` currently keeps the actual logic because it owns the
// cache arrays; these helpers allow other modules to access the behavior
// without knowing implementation details.
void wc_cache_validate_integrity(void);
void wc_cache_log_statistics(void);

#ifdef __cplusplus
}
#endif

#endif // WC_CACHE_H
