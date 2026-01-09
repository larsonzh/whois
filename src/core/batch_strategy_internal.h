// SPDX-License-Identifier: MIT
#ifndef WC_BATCH_STRATEGY_INTERNAL_H
#define WC_BATCH_STRATEGY_INTERNAL_H

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"
#include "wc/wc_backoff.h"
#include "wc/wc_output.h"
#include "wc/wc_log.h"

static inline int wc_batch_strategy_debug_enabled(const wc_batch_context_t* ctx)
{
    if (ctx && ctx->config)
        return ctx->config->debug;
    return wc_output_is_debug_enabled();
}

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

static inline long wc_batch_strategy_internal_penalty_ms_left(
        const wc_backoff_host_health_t* entry)
{
    if (!entry)
        return 0;
    long penalty = entry->ipv4.penalty_ms_left;
    if (entry->ipv6.penalty_ms_left > penalty)
        penalty = entry->ipv6.penalty_ms_left;
    return penalty;
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

static inline int wc_batch_strategy_internal_resolve_health(
        const wc_batch_context_t* ctx,
        const char* host,
        wc_backoff_host_health_t* out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!ctx || !host || !out)
        return 0;
    const wc_backoff_host_health_t* entry =
        wc_batch_strategy_internal_find_health(ctx, host);
    if (entry) {
        *out = *entry;
        return 1;
    }
    const char* hosts[1] = { host };
    size_t produced = wc_backoff_collect_host_health(ctx->config,
        hosts, 1, out, 1);
    return produced > 0;
}

static inline int wc_batch_strategy_internal_is_penalized(
        const wc_batch_context_t* ctx,
        const char* host,
        wc_backoff_host_health_t* out)
{
    wc_backoff_host_health_t local;
    wc_backoff_host_health_t* target = out ? out : &local;
    memset(target, 0, sizeof(*target));
    if (!ctx || !host)
        return 0;
    int has_health = wc_batch_strategy_internal_resolve_health(ctx, host, target);
    if (has_health)
        return wc_batch_strategy_internal_host_penalized(target);
    if (wc_backoff_should_skip(ctx->config, host, AF_UNSPEC, NULL)) {
        wc_backoff_get_host_health(ctx->config, host, target);
        return wc_batch_strategy_internal_host_penalized(target);
    }
    return 0;
}

static inline void wc_batch_strategy_internal_log_skip_penalized(
        const wc_batch_context_t* ctx,
        const char* host,
        const char* fallback,
        const char* reason,
        const wc_backoff_host_health_t* entry)
{
    if (!wc_batch_strategy_debug_enabled(ctx) || !host)
        return;
    wc_backoff_host_health_t empty;
    if (!entry) {
        memset(&empty, 0, sizeof(empty));
        entry = &empty;
    }
    int consec = entry->ipv4.consecutive_failures;
    if (entry->ipv6.consecutive_failures > consec)
        consec = entry->ipv6.consecutive_failures;
    long penalty = wc_batch_strategy_internal_penalty_ms_left(entry);
    wc_log_dns_batchf(
        "[DNS-BATCH] action=skip-penalized host=%s fallback=%s reason=%s consec_fail=%d penalty_ms_left=%ld window_ms=%ld\n",
        host,
        fallback ? fallback : "(none)",
        reason ? reason : "unknown",
        consec,
        penalty,
        wc_backoff_get_penalty_window_ms());
    /* Compatibility with legacy golden: emit start-skip tag */
    wc_log_dns_batchf(
        "[DNS-BATCH] action=start-skip host=%s fallback=%s consec_fail=%d penalty_ms_left=%ld\n",
        host,
        fallback ? fallback : "(none)",
        consec,
        penalty);
}

static inline void wc_batch_strategy_internal_log_force_last(
        const wc_batch_context_t* ctx,
        const char* forced_host)
{
    if (!wc_batch_strategy_debug_enabled(ctx) || !forced_host)
        return;
    wc_log_dns_batchf(
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
        wc_backoff_host_health_t entry;
        if (wc_batch_strategy_internal_is_penalized(ctx, candidate, &entry)) {
            const char* fallback = (i + 1 < ctx->candidate_count)
                ? ctx->candidates[i + 1]
                : ctx->candidates[0];
            wc_batch_strategy_internal_log_skip_penalized(ctx, candidate,
                fallback, "penalized", &entry);
            continue;
        }
        return candidate;
    }
    const char* forced = ctx->candidates[ctx->candidate_count - 1];
    wc_batch_strategy_internal_log_force_last(ctx, forced);
    return forced;
}

#endif // WC_BATCH_STRATEGY_INTERNAL_H
