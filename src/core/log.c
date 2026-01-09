// SPDX-License-Identifier: MIT
// Centralized logging helpers for tagged stderr diagnostics.

#include <stdio.h>
#include <stdarg.h>

#include "wc/wc_log.h"

void wc_log_dns_batchf(const char* format, ...)
{
    if (!format)
        return;
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void wc_log_dns_batch_debug_penalize(const char* host)
{
    if (!host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=debug-penalize host=%s source=WHOIS_BATCH_DEBUG_PENALIZE\n",
        host);
}

void wc_log_dns_batch_query_fail(const char* host, int lookup_rc, int errno_hint, long penalty_ms)
{
    if (!host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=query-fail host=%s lookup_rc=%d errno=%d penalty_ms=%ld\n",
        host,
        lookup_rc,
        errno_hint,
        penalty_ms);
}

void wc_log_dns_batch_snapshot_entry(const char* host,
    const char* family_label,
    wc_dns_health_state_t state,
    const wc_dns_health_snapshot_t* snap)
{
    if (!host || !family_label || !snap)
        return;
    fprintf(stderr,
        "[DNS-BATCH] host=%s family=%s state=%s consec_fail=%d penalty_ms_left=%ld\n",
        host,
        family_label,
        (state == WC_DNS_HEALTH_PENALIZED) ? "penalized" : "ok",
        snap->consecutive_failures,
        (long)snap->penalty_ms_left);
}

void wc_log_retry_metrics_summary(unsigned attempts,
    unsigned successes,
    unsigned failures,
    unsigned min_ms,
    unsigned max_ms,
    double avg_ms,
    unsigned p95_ms,
    unsigned sleep_ms)
{
    fprintf(stderr,
        "[RETRY-METRICS] attempts=%u successes=%u failures=%u min_ms=%u max_ms=%u avg_ms=%.1f p95_ms=%u sleep_ms=%u\n",
        attempts,
        successes,
        failures,
        min_ms,
        max_ms,
        avg_ms,
        p95_ms,
        sleep_ms);
}

void wc_log_retry_error_breakdown(unsigned timeouts,
    unsigned refused,
    unsigned net_unreach,
    unsigned host_unreach,
    unsigned addr_na,
    unsigned interrupted,
    unsigned other)
{
    fprintf(stderr,
        "[RETRY-ERRORS] timeouts=%u refused=%u net_unreach=%u host_unreach=%u addr_na=%u interrupted=%u other=%u\n",
        timeouts,
        refused,
        net_unreach,
        host_unreach,
        addr_na,
        interrupted,
        other);
}

void wc_log_retry_metrics_instant(unsigned attempt,
    unsigned latency_ms,
    unsigned total_attempts)
{
    fprintf(stderr,
        "[RETRY-METRICS-INSTANT] attempt=%u success=1 latency_ms=%u total_attempts=%u\n",
        attempt,
        latency_ms,
        total_attempts);
}
