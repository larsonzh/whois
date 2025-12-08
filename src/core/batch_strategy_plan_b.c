// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"
#include "wc/wc_backoff.h"
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"

#include "batch_strategy_internal.h"

static char g_plan_b_last_authoritative[128];
static void wc_batch_strategy_plan_b_log_force_override(const char* host,
        long penalty_ms)
{
    if (!wc_is_debug_enabled() || !host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=force-override host=%s penalty_ms=%ld\n",
        host,
        penalty_ms);
}

static void wc_batch_strategy_plan_b_log_force_start(const char* host,
        const char* reason)
{
    if (!wc_is_debug_enabled() || !host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-b-force-start host=%s reason=%s\n",
        host,
        reason ? reason : "unknown");
}

static void wc_batch_strategy_plan_b_log_fallback(const char* host,
        const char* fallback,
        const char* reason)
{
    if (!wc_is_debug_enabled() || !host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-b-fallback host=%s fallback=%s reason=%s\n",
        host,
        fallback ? fallback : "(none)",
        reason ? reason : "unknown");
}

static void wc_batch_strategy_plan_b_clear_cache(void)
{
    if (!g_plan_b_last_authoritative[0])
        return;
    g_plan_b_last_authoritative[0] = '\0';
}

static void wc_batch_strategy_plan_b_store_authoritative(const char* host)
{
    if (!host || !*host || wc_dns_is_ip_literal(host)) {
        wc_batch_strategy_plan_b_clear_cache();
        return;
    }
    const char* canonical = wc_dns_canonical_host_for_rir(host);
    const char* chosen = canonical ? canonical : host;
    snprintf(g_plan_b_last_authoritative,
        sizeof(g_plan_b_last_authoritative), "%s", chosen);
}

static const char* wc_batch_strategy_plan_b_cached_host(void)
{
    return g_plan_b_last_authoritative[0]
        ? g_plan_b_last_authoritative
        : NULL;
}

static int wc_batch_strategy_plan_b_is_penalized(
        const wc_batch_context_t* ctx,
        const char* host,
        wc_backoff_host_health_t* out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!host || !*host)
        return 0;
    const wc_backoff_host_health_t* entry =
        wc_batch_strategy_internal_find_health(ctx, host);
    if (entry) {
        if (out)
            *out = *entry;
        return wc_batch_strategy_internal_host_penalized(entry);
    }
    wc_backoff_host_health_t snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    wc_backoff_get_host_health(host, &snapshot);
    if (out)
        *out = snapshot;
    return wc_batch_strategy_internal_host_penalized(&snapshot);
}

static const char* wc_batch_strategy_plan_b_pick(const wc_batch_context_t* ctx)
{
    const char* cached = wc_batch_strategy_plan_b_cached_host();
    if (cached) {
        wc_backoff_host_health_t entry;
        int penalized = wc_batch_strategy_plan_b_is_penalized(
            ctx, cached, &entry);
        if (!penalized) {
            wc_batch_strategy_plan_b_log_force_start(
                cached, "authoritative-cache");
            return cached;
        }
        const char* fallback = wc_batch_strategy_internal_pick_first_healthy(ctx);
        if (!fallback && ctx && ctx->candidate_count > 0)
            fallback = ctx->candidates[ctx->candidate_count - 1];
        wc_batch_strategy_plan_b_log_fallback(
            cached, fallback, "penalized");
        wc_batch_strategy_internal_log_start_skip(&entry, fallback);
        if (!fallback) {
            long penalty_ms = (entry.ipv4.penalty_ms_left > 0)
                ? entry.ipv4.penalty_ms_left
                : entry.ipv6.penalty_ms_left;
            wc_batch_strategy_plan_b_log_force_override(
                cached,
                penalty_ms ? penalty_ms : wc_backoff_get_penalty_window_ms());
            return cached;
        }
        /* fallback decided; if we skipped cache due to penalty, record that */
        if (wc_batch_strategy_internal_host_penalized(&entry)) {
            wc_batch_strategy_plan_b_log_force_override(
                fallback,
                entry.ipv4.penalty_ms_left > 0 ? entry.ipv4.penalty_ms_left
                    : (entry.ipv6.penalty_ms_left > 0 ? entry.ipv6.penalty_ms_left
                        : wc_backoff_get_penalty_window_ms()));
        }
        /* when penalty pushed us onto the tail candidate, surface force-last */
        if (ctx && fallback && ctx->candidate_count > 0 &&
                ctx->candidates[ctx->candidate_count - 1] &&
                strcasecmp(fallback,
                    ctx->candidates[ctx->candidate_count - 1]) == 0 &&
                (!cached || strcasecmp(fallback, cached) != 0)) {
            wc_batch_strategy_internal_log_force_last(fallback);
        }
        return fallback;
    }

    const char* picked = wc_batch_strategy_internal_pick_first_healthy(ctx);
    if (picked)
        wc_batch_strategy_plan_b_log_force_start(
            picked, cached ? "fallback-to-healthy" : "no-cache");
    return picked ? picked : (ctx ? ctx->default_host : NULL);
}

static void wc_batch_strategy_plan_b_on_result(const wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    (void)ctx;
    if (!result)
        return;
    if (result->lookup_rc != 0) {
        const char* cached = wc_batch_strategy_plan_b_cached_host();
        if (cached && result->start_host &&
                strcasecmp(result->start_host, cached) == 0) {
            wc_batch_strategy_plan_b_clear_cache();
        }
        return;
    }
    if (result->authoritative_host && *result->authoritative_host)
        wc_batch_strategy_plan_b_store_authoritative(
            result->authoritative_host);
}

static const wc_batch_strategy_t k_wc_batch_strategy_plan_b = {
    .name = "plan-b",
    .pick_start_host = wc_batch_strategy_plan_b_pick,
    .on_result = wc_batch_strategy_plan_b_on_result,
};

void wc_batch_strategy_register_plan_b(void)
{
    wc_batch_strategy_register(&k_wc_batch_strategy_plan_b);
}
