// SPDX-License-Identifier: GPL-3.0-or-later
// Shared server backoff helper built on top of DNS health tracking.

#ifndef WC_BACKOFF_H
#define WC_BACKOFF_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "wc_dns.h"

#ifdef __cplusplus
extern "C" {
#endif

// Update health memory with the outcome of a connect attempt. The
// 'family' argument accepts AF_INET/AF_INET6; use AF_UNSPEC to apply the
// outcome to both families for legacy callers.
void wc_backoff_note_result(const struct Config* config, const char* host, int family, int success);
void wc_backoff_note_success(const struct Config* config, const char* host, int family);
void wc_backoff_note_failure(const struct Config* config, const char* host, int family);

// Return 1 when the given host+family is still inside its penalty
// window, 0 otherwise. Passing AF_UNSPEC performs a best effort check
// across IPv4/IPv6 slots. When 'snap' is not NULL, it will be populated
// with the snapshot that triggered the skip decision.
int wc_backoff_should_skip(const struct Config* config,
                          const char* host,
                          int family,
                          wc_dns_health_snapshot_t* snap);

// Penalty window configuration helpers (in milliseconds). A value of 0
// disables the penalty window entirely.
void wc_backoff_set_penalty_window_seconds(int seconds);
long wc_backoff_get_penalty_window_ms(void);

// Lightweight snapshot for batch schedulers: captures IPv4/IPv6 health
// for a given host in a single structure. The wc_dns_health_snapshot_t
// members borrow internal string storage; do not free them.
typedef struct wc_backoff_host_health_s {
    const char* host;
    wc_dns_health_snapshot_t ipv4;
    wc_dns_health_snapshot_t ipv6;
    wc_dns_health_state_t ipv4_state;
    wc_dns_health_state_t ipv6_state;
} wc_backoff_host_health_t;

// Populate a single host health snapshot. 'out' is zeroed on entry and
// only considered valid when a host is provided. Callers typically use
// wc_backoff_collect_host_health() instead of invoking this directly.
void wc_backoff_get_host_health(const struct Config* config,
        const char* host,
        wc_backoff_host_health_t* out);

// Collect health snapshots for up to 'host_count' hosts, storing the
// results (without duplicates) in 'out'. Returns the number of entries
// written, capped at 'out_capacity'.
size_t wc_backoff_collect_host_health(const struct Config* config,
        const char* const* hosts,
        size_t host_count,
        wc_backoff_host_health_t* out,
        size_t out_capacity);

#ifdef __cplusplus
}
#endif

#endif // WC_BACKOFF_H
