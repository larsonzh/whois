// SPDX-License-Identifier: MIT
#ifndef WC_LOG_H
#define WC_LOG_H

#include "wc_dns.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DNS batch logging helpers */
void wc_log_dns_batchf(const char* format, ...);
void wc_log_dns_batch_debug_penalize(const char* host);
void wc_log_dns_batch_query_fail(const char* host, int lookup_rc, int errno_hint, long penalty_ms);
void wc_log_dns_batch_snapshot_entry(const char* host,
    const char* family_label,
    wc_dns_health_state_t state,
    const wc_dns_health_snapshot_t* snap);

/* Retry metrics helpers */
void wc_log_retry_metrics_summary(unsigned attempts,
    unsigned successes,
    unsigned failures,
    unsigned min_ms,
    unsigned max_ms,
    double avg_ms,
    unsigned p95_ms,
    unsigned sleep_ms);

void wc_log_retry_error_breakdown(unsigned timeouts,
    unsigned refused,
    unsigned net_unreach,
    unsigned host_unreach,
    unsigned addr_na,
    unsigned interrupted,
    unsigned other);

void wc_log_retry_metrics_instant(unsigned attempt,
    unsigned latency_ms,
    unsigned total_attempts);

#ifdef __cplusplus
}
#endif

#endif // WC_LOG_H
