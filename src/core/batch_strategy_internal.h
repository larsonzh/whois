// SPDX-License-Identifier: MIT
#ifndef WC_BATCH_STRATEGY_INTERNAL_H
#define WC_BATCH_STRATEGY_INTERNAL_H

#include <stdio.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"
#include "wc/wc_backoff.h"
#include "wc/wc_debug.h"

static inline int wc_batch_strategy_internal_host_penalized(
        const wc_backoff_host_health_t* entry)
{
    if (!entry || !entry->host)
        return 0;
    int ipv4_pen = (entry->ipv4_state == WC_DNS_HEALTH_PENALIZED &&
        entry->ipv4.penalty_ms_left > 0);
    int ipv6_pen = (entry->ipv6_state == WC_DNS_HEALTH_PENALIZED &&
        entry->ipv6.penalty_ms_left > 0);
    return ipv4_pen || ipv6_pen;
}

static inline const wc_backoff_host_health_t*
wc_batch_strategy_internal_find_health(const wc_batch_context_t* ctx,
        const char* host)
{
    if (!ctx || !host || !ctx->health_entries)
        return NULL;
    for (size_t i = 0; i < ctx->health_count; ++i) {
        const wc_backoff_host_health_t* entry = &ctx->health_entries[i];
        if (!entry->host)
            continue;
        if (strcasecmp(entry->host, host) == 0)
            return entry;
    }
    return NULL;
}

static inline void wc_batch_strategy_internal_log_start_skip(
        const wc_backoff_host_health_t* entry,
        const char* fallback)
{
    if (!wc_is_debug_enabled() || !entry || !entry->host)
        return;
    int consec = entry->ipv4.consecutive_failures;
    if (entry->ipv6.consecutive_failures > consec)
        consec = entry->ipv6.consecutive_failures;
    long penalty = entry->ipv4.penalty_ms_left;
    if (entry->ipv6.penalty_ms_left > penalty)
        penalty = entry->ipv6.penalty_ms_left;
    fprintf(stderr,
        "[DNS-BATCH] action=start-skip host=%s fallback=%s consec_fail=%d penalty_ms_left=%ld\n",
        entry->host,
        fallback ? fallback : "(none)",
        consec,
        penalty);
}

static inline void wc_batch_strategy_internal_log_force_last(
        const char* forced_host)
{
    if (!wc_is_debug_enabled() || !forced_host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=force-last host=%s penalty_ms=%ld\n",
        forced_host,
        wc_backoff_get_penalty_window_ms());
}

static inline const char*
wc_batch_strategy_internal_pick_first_healthy(const wc_batch_context_t* ctx)
{
    if (!ctx || !ctx->candidates || ctx->candidate_count == 0)
        return ctx ? ctx->default_host : NULL;
    for (size_t i = 0; i < ctx->candidate_count; ++i) {
        const char* candidate = ctx->candidates[i];
        const wc_backoff_host_health_t* entry =
            wc_batch_strategy_internal_find_health(ctx, candidate);
        if (wc_batch_strategy_internal_host_penalized(entry)) {
            const char* fallback = (i + 1 < ctx->candidate_count)
                ? ctx->candidates[i + 1]
                : ctx->candidates[0];
            wc_batch_strategy_internal_log_start_skip(entry, fallback);
            continue;
        }
        return candidate;
    }
    const char* forced = ctx->candidates[ctx->candidate_count - 1];
    wc_batch_strategy_internal_log_force_last(forced);
    return forced;
}

#endif // WC_BATCH_STRATEGY_INTERNAL_H
