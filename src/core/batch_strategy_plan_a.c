// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"
#include "wc/wc_backoff.h"
#include "wc/wc_dns.h"
#include "wc/wc_log.h"

#include "batch_strategy_internal.h"

typedef struct wc_batch_strategy_plan_a_state_s {
    char last_authoritative[128];
} wc_batch_strategy_plan_a_state_t;

static wc_batch_strategy_plan_a_state_t g_plan_a_state;

static wc_batch_strategy_plan_a_state_t*
wc_batch_strategy_plan_a_get_state(const wc_batch_context_t* ctx)
{
    if (ctx && ctx->strategy_state)
        return (wc_batch_strategy_plan_a_state_t*)ctx->strategy_state;
    return &g_plan_a_state;
}

static void wc_batch_strategy_plan_a_log_cache(const wc_batch_context_t* ctx,
        const char* host)
{
    if (!wc_batch_strategy_debug_enabled(ctx))
        return;
    wc_log_dns_batchf(
        "[DNS-BATCH] action=plan-a-cache host=%s\n",
        host && *host ? host : "(cleared)");
}

static void wc_batch_strategy_plan_a_clear_cache(const wc_batch_context_t* ctx,
        wc_batch_strategy_plan_a_state_t* state)
{
    if (!state)
        return;
    if (!state->last_authoritative[0])
        return;
    state->last_authoritative[0] = '\0';
    wc_batch_strategy_plan_a_log_cache(ctx, NULL);
}

static void wc_batch_strategy_plan_a_store_authoritative(
        const wc_batch_context_t* ctx,
        wc_batch_strategy_plan_a_state_t* state,
        const char* host)
{
    if (!state)
        return;
    if (!host || !*host || wc_dns_is_ip_literal(host)) {
        wc_batch_strategy_plan_a_clear_cache(ctx, state);
        return;
    }
    const char* canonical = wc_dns_canonical_host_for_rir(host);
    const char* chosen = canonical ? canonical : host;
    snprintf(state->last_authoritative,
        sizeof(state->last_authoritative), "%s", chosen);
    wc_batch_strategy_plan_a_log_cache(ctx, state->last_authoritative);
}

static const char* wc_batch_strategy_plan_a_cached_host(
        wc_batch_strategy_plan_a_state_t* state)
{
    if (!state)
        return NULL;
    return state->last_authoritative[0]
        ? state->last_authoritative
        : NULL;
}

static void wc_batch_strategy_plan_a_log_faststart(const wc_batch_context_t* ctx,
        const char* host)
{
    if (!wc_batch_strategy_debug_enabled(ctx) || !host)
        return;
    wc_log_dns_batchf(
        "[DNS-BATCH] action=plan-a-faststart host=%s reason=authoritative-cache\n",
        host);
}

static void wc_batch_strategy_plan_a_log_skip(const wc_batch_context_t* ctx,
        const char* host,
        const char* fallback,
        const char* reason)
{
    if (!wc_batch_strategy_debug_enabled(ctx) || !host)
        return;
    wc_log_dns_batchf(
        "[DNS-BATCH] action=plan-a-skip host=%s fallback=%s reason=%s\n",
        host,
        fallback ? fallback : "(none)",
        reason ? reason : "unknown");
    wc_batch_strategy_internal_log_skip_penalized(ctx, host, fallback,
        reason, NULL);
}

static const char* wc_batch_strategy_plan_a_pick_cached(
        const wc_batch_context_t* ctx,
        wc_batch_strategy_plan_a_state_t* state)
{
    const char* cached = wc_batch_strategy_plan_a_cached_host(state);
    if (!cached)
        return NULL;
    wc_backoff_host_health_t snapshot;
    if (wc_batch_strategy_internal_is_penalized(ctx, cached, &snapshot)) {
        const char* fallback = (ctx && ctx->candidate_count > 0)
            ? ctx->candidates[0]
            : (ctx ? ctx->default_host : NULL);
        wc_batch_strategy_plan_a_log_skip(ctx, cached, fallback, "penalized");
        return NULL;
    }
    wc_batch_strategy_plan_a_log_faststart(ctx, cached);
    return cached;
}

static const char* wc_batch_strategy_plan_a_pick(const wc_batch_context_t* ctx)
{
    wc_batch_strategy_plan_a_state_t* state =
        wc_batch_strategy_plan_a_get_state(ctx);
    const char* cached = wc_batch_strategy_plan_a_pick_cached(ctx, state);
    if (cached)
        return cached;
    return wc_batch_strategy_internal_pick_first_healthy(ctx);
}

static int wc_batch_strategy_plan_a_init(wc_batch_context_t* ctx)
{
    if (!ctx)
        return 0;
    ctx->strategy_state = &g_plan_a_state;
    ctx->strategy_state_cleanup = NULL;
    return 1;
}

static void wc_batch_strategy_plan_a_on_result(const wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    wc_batch_strategy_plan_a_state_t* state =
        wc_batch_strategy_plan_a_get_state(ctx);
    if (!result)
        return;
    if (result->lookup_rc != 0) {
        const char* cached = wc_batch_strategy_plan_a_cached_host(state);
        if (cached && result->start_host &&
                strcasecmp(result->start_host, cached) == 0) {
            wc_batch_strategy_plan_a_clear_cache(ctx, state);
        }
        return;
    }
    if (result->authoritative_host && *result->authoritative_host)
        wc_batch_strategy_plan_a_store_authoritative(
            ctx, state, result->authoritative_host);
}

static const wc_batch_strategy_t k_wc_batch_strategy_plan_a = {
    .name = "plan-a",
    .init = wc_batch_strategy_plan_a_init,
    .pick_start_host = wc_batch_strategy_plan_a_pick,
    .on_result = wc_batch_strategy_plan_a_on_result,
    .teardown = NULL,
};

void wc_batch_strategy_register_plan_a_with_registry(
        wc_batch_strategy_registry_t* registry)
{
    if (registry)
        wc_batch_strategy_registry_register(registry, &k_wc_batch_strategy_plan_a);
    else
        wc_batch_strategy_register(&k_wc_batch_strategy_plan_a);
}

void wc_batch_strategy_register_plan_a(void)
{
    wc_batch_strategy_register_plan_a_with_registry(NULL);
}
