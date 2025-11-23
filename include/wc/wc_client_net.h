// SPDX-License-Identifier: GPL-3.0-or-later
// Client-side networking helpers for whois CLI.
// Provides legacy resolution and fallback connect routines
// while the new lookup pipeline matures.

#ifndef WC_CLIENT_NET_H
#define WC_CLIENT_NET_H

#ifdef __cplusplus
extern "C" {
#endif

// Resolve a hostname using the legacy cache/selftest-aware path.
// Returns a newly allocated string on success or NULL on failure.
char* wc_client_resolve_domain(const char* domain);

// Attempt to connect to the given host:port, honoring connection cache and
// retry policy. Returns 0 and stores the socket descriptor on success.
int wc_client_connect_to_server(const char* host, int port, int* sockfd);

// Try direct connection, then DNS resolution, then known-IP fallback.
// Mirrors the legacy connect_with_fallback semantics.
int wc_client_connect_with_fallback(const char* domain, int port, int* sockfd);

#ifdef __cplusplus
}
#endif

#endif // WC_CLIENT_NET_H
