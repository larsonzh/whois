// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"
#include "wc/wc_backoff.h"
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"

#include "batch_strategy_internal.h"

static char g_plan_a_last_authoritative[128];

static void wc_batch_strategy_plan_a_log_cache(const char* host)
{
    if (!wc_is_debug_enabled())
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-a-cache host=%s\n",
        host && *host ? host : "(cleared)");
}

static void wc_batch_strategy_plan_a_clear_cache(void)
{
    if (!g_plan_a_last_authoritative[0])
        return;
    g_plan_a_last_authoritative[0] = '\0';
    wc_batch_strategy_plan_a_log_cache(NULL);
}

static void wc_batch_strategy_plan_a_store_authoritative(const char* host)
{
    if (!host || !*host || wc_dns_is_ip_literal(host)) {
        wc_batch_strategy_plan_a_clear_cache();
        return;
    }
    const char* canonical = wc_dns_canonical_host_for_rir(host);
    const char* chosen = canonical ? canonical : host;
    snprintf(g_plan_a_last_authoritative,
        sizeof(g_plan_a_last_authoritative), "%s", chosen);
    wc_batch_strategy_plan_a_log_cache(g_plan_a_last_authoritative);
}

static const char* wc_batch_strategy_plan_a_cached_host(void)
{
    return g_plan_a_last_authoritative[0]
        ? g_plan_a_last_authoritative
        : NULL;
}

static void wc_batch_strategy_plan_a_log_faststart(const char* host)
{
    if (!wc_is_debug_enabled() || !host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-a-faststart host=%s reason=authoritative-cache\n",
        host);
}

static void wc_batch_strategy_plan_a_log_skip(const char* host,
        const char* fallback,
        const char* reason)
{
    if (!wc_is_debug_enabled() || !host)
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-a-skip host=%s fallback=%s reason=%s\n",
        host,
        fallback ? fallback : "(none)",
        reason ? reason : "unknown");
}

static const char* wc_batch_strategy_plan_a_pick_cached(
        const wc_batch_context_t* ctx)
{
    const char* cached = wc_batch_strategy_plan_a_cached_host();
    if (!cached)
        return NULL;
    wc_backoff_host_health_t snapshot;
    wc_backoff_get_host_health(cached, &snapshot);
    if (wc_batch_strategy_internal_host_penalized(&snapshot)) {
        const char* fallback = (ctx && ctx->candidate_count > 0)
            ? ctx->candidates[0]
            : (ctx ? ctx->default_host : NULL);
        wc_batch_strategy_plan_a_log_skip(cached, fallback, "penalized");
        return NULL;
    }
    wc_batch_strategy_plan_a_log_faststart(cached);
    return cached;
}

static const char* wc_batch_strategy_plan_a_pick(const wc_batch_context_t* ctx)
{
    const char* cached = wc_batch_strategy_plan_a_pick_cached(ctx);
    if (cached)
        return cached;
    return wc_batch_strategy_internal_pick_first_healthy(ctx);
}

static void wc_batch_strategy_plan_a_on_result(const wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    (void)ctx;
    if (!result)
        return;
    if (result->lookup_rc != 0) {
        const char* cached = wc_batch_strategy_plan_a_cached_host();
        if (cached && result->start_host &&
                strcasecmp(result->start_host, cached) == 0) {
            wc_batch_strategy_plan_a_clear_cache();
        }
        return;
    }
    if (result->authoritative_host && *result->authoritative_host)
        wc_batch_strategy_plan_a_store_authoritative(
            result->authoritative_host);
}

static const wc_batch_strategy_t k_wc_batch_strategy_plan_a = {
    .name = "plan-a",
    .pick_start_host = wc_batch_strategy_plan_a_pick,
    .on_result = wc_batch_strategy_plan_a_on_result,
};

void wc_batch_strategy_register_plan_a(void)
{
    wc_batch_strategy_register(&k_wc_batch_strategy_plan_a);
}
