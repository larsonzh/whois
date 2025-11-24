// SPDX-License-Identifier: GPL-3.0-or-later
// Shared server backoff helper built on top of DNS health tracking.

#ifndef WC_BACKOFF_H
#define WC_BACKOFF_H

#include <sys/types.h>
#include <sys/socket.h>

#include "wc_dns.h"

#ifdef __cplusplus
extern "C" {
#endif

// Update health memory with the outcome of a connect attempt. The
// 'family' argument accepts AF_INET/AF_INET6; use AF_UNSPEC to apply the
// outcome to both families for legacy callers.
void wc_backoff_note_result(const char* host, int family, int success);
void wc_backoff_note_success(const char* host, int family);
void wc_backoff_note_failure(const char* host, int family);

// Return 1 when the given host+family is still inside its penalty
// window, 0 otherwise. Passing AF_UNSPEC performs a best effort check
// across IPv4/IPv6 slots. When 'snap' is not NULL, it will be populated
// with the snapshot that triggered the skip decision.
int wc_backoff_should_skip(const char* host,
                          int family,
                          wc_dns_health_snapshot_t* snap);

// Penalty window configuration helpers (in milliseconds). A value of 0
// disables the penalty window entirely.
void wc_backoff_set_penalty_window_seconds(int seconds);
long wc_backoff_get_penalty_window_ms(void);

#ifdef __cplusplus
}
#endif

#endif // WC_BACKOFF_H
