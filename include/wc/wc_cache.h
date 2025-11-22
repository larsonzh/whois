// SPDX-License-Identifier: GPL-3.0-or-later
// Cache-related helpers for whois client (server backoff, etc.).

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

#ifdef __cplusplus
}
#endif

#endif // WC_CACHE_H
