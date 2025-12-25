// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

#include "wc/wc_batch_strategy.h"
#include "wc/wc_backoff.h"
#include "wc/wc_dns.h"

#include "batch_strategy_internal.h"

typedef struct wc_batch_strategy_plan_b_state_s {
    char last_authoritative[128];
    long last_success_ms;
} wc_batch_strategy_plan_b_state_t;

static wc_batch_strategy_plan_b_state_t g_plan_b_state;

static wc_batch_strategy_plan_b_state_t*
wc_batch_strategy_plan_b_get_state(const wc_batch_context_t* ctx)
{
    if (ctx && ctx->strategy_state)
        return (wc_batch_strategy_plan_b_state_t*)ctx->strategy_state;
    return &g_plan_b_state;
}

static long wc_batch_strategy_plan_b_now_ms(void)
{
#ifdef CLOCK_MONOTONIC
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (ts.tv_sec * 1000L) + (ts.tv_nsec / 1000000L);
#endif
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0)
        return (tv.tv_sec * 1000L) + (tv.tv_usec / 1000L);
    return 0;
}

static void wc_batch_strategy_plan_b_log_hit(const wc_batch_context_t* ctx,
        const char* host,
        long age_ms,
        long window_ms)
{
    if (!host)
        return;
    if (!wc_batch_strategy_debug_enabled(ctx))
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-b-hit host=%s age_ms=%ld window_ms=%ld\n",
        host,
        age_ms,
        window_ms);
}

static void wc_batch_strategy_plan_b_log_stale(const wc_batch_context_t* ctx,
        const char* host,
        long age_ms,
        long window_ms)
{
    if (!host)
        return;
    if (!wc_batch_strategy_debug_enabled(ctx))
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-b-stale host=%s age_ms=%ld window_ms=%ld\n",
        host,
        age_ms,
        window_ms);
}

static void wc_batch_strategy_plan_b_log_empty(const wc_batch_context_t* ctx,
        long window_ms)
{
    if (!wc_batch_strategy_debug_enabled(ctx))
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-b-empty window_ms=%ld\n",
        window_ms);
}

static void wc_batch_strategy_plan_b_log_force_override(const wc_batch_context_t* ctx,
        const char* host,
        long penalty_ms)
{
    if (!host)
        return;
    if (!wc_batch_strategy_debug_enabled(ctx))
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=force-override host=%s penalty_ms=%ld\n",
        host,
        penalty_ms);
}

static void wc_batch_strategy_plan_b_log_force_start(const wc_batch_context_t* ctx,
        const char* host,
        const char* reason)
{
    if (!host)
        return;
    if (!wc_batch_strategy_debug_enabled(ctx))
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-b-force-start host=%s reason=%s\n",
        host,
        reason ? reason : "unknown");
}

static void wc_batch_strategy_plan_b_log_fallback(const wc_batch_context_t* ctx,
        const char* host,
        const char* fallback,
        const char* reason)
{
    if (!host)
        return;
    if (!wc_batch_strategy_debug_enabled(ctx))
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=plan-b-fallback host=%s fallback=%s reason=%s\n",
        host,
        fallback ? fallback : "(none)",
        reason ? reason : "unknown");
}

static void wc_batch_strategy_plan_b_clear_cache(
        wc_batch_strategy_plan_b_state_t* state)
{
    if (!state)
        return;
    if (!state->last_authoritative[0])
        return;
    state->last_authoritative[0] = '\0';
    state->last_success_ms = 0;
}

static void wc_batch_strategy_plan_b_store_authoritative(
        wc_batch_strategy_plan_b_state_t* state,
        const char* host)
{
    if (!state)
        return;
    if (!host || !*host || wc_dns_is_ip_literal(host)) {
        wc_batch_strategy_plan_b_clear_cache(state);
        return;
    }
    const char* canonical = wc_dns_canonical_host_for_rir(host);
    const char* chosen = canonical ? canonical : host;
    snprintf(state->last_authoritative,
        sizeof(state->last_authoritative), "%s", chosen);
    state->last_success_ms = wc_batch_strategy_plan_b_now_ms();
}

static const char* wc_batch_strategy_plan_b_cached_host(
        wc_batch_strategy_plan_b_state_t* state)
{
    if (!state)
        return NULL;
    return state->last_authoritative[0]
        ? state->last_authoritative
        : NULL;
}

static const char* wc_batch_strategy_plan_b_pick(const wc_batch_context_t* ctx)
{
    wc_batch_strategy_plan_b_state_t* state =
        wc_batch_strategy_plan_b_get_state(ctx);
    long window_ms = wc_backoff_get_penalty_window_ms();
    long now_ms = wc_batch_strategy_plan_b_now_ms();
    const char* cached = wc_batch_strategy_plan_b_cached_host(state);
    if (cached) {
        long age_ms = -1;
        if (state->last_success_ms > 0 && now_ms > 0 &&
                now_ms >= state->last_success_ms) {
            age_ms = now_ms - state->last_success_ms;
        }
        if (age_ms >= 0 && (window_ms <= 0 || age_ms <= window_ms)) {
            wc_batch_strategy_plan_b_log_hit(ctx, cached, age_ms, window_ms);
        } else {
            wc_batch_strategy_plan_b_log_stale(ctx, cached, age_ms, window_ms);
            wc_batch_strategy_plan_b_clear_cache(state);
            cached = NULL;
        }
    }

    if (cached) {
        wc_backoff_host_health_t entry;
        int penalized = wc_batch_strategy_internal_is_penalized(ctx, cached, &entry);
        if (!penalized) {
            wc_batch_strategy_plan_b_log_force_start(ctx, cached, "authoritative-cache");
            return cached;
        }

        wc_batch_strategy_plan_b_clear_cache(state);

        const char* fallback = wc_batch_strategy_internal_pick_first_healthy(ctx);
        if (!fallback && ctx && ctx->candidate_count > 0)
            fallback = ctx->candidates[ctx->candidate_count - 1];

        wc_batch_strategy_plan_b_log_fallback(ctx, cached, fallback, "penalized");
        wc_batch_strategy_internal_log_skip_penalized(ctx, cached, fallback,
            "penalized", &entry);

        if (!fallback) {
            long penalty_ms = (entry.ipv4.penalty_ms_left > 0)
                ? entry.ipv4.penalty_ms_left
                : entry.ipv6.penalty_ms_left;
            wc_batch_strategy_plan_b_log_force_override(
                ctx,
                cached,
                penalty_ms ? penalty_ms : wc_backoff_get_penalty_window_ms());
            return cached;
        }

        if (wc_batch_strategy_internal_host_penalized(&entry)) {
            wc_batch_strategy_plan_b_log_force_override(
                ctx,
                fallback,
                entry.ipv4.penalty_ms_left > 0 ? entry.ipv4.penalty_ms_left
                    : (entry.ipv6.penalty_ms_left > 0 ? entry.ipv6.penalty_ms_left
                        : wc_backoff_get_penalty_window_ms()));
        }

        if (ctx && fallback && ctx->candidate_count > 0 &&
                ctx->candidates[ctx->candidate_count - 1] &&
                strcasecmp(fallback,
                    ctx->candidates[ctx->candidate_count - 1]) == 0 &&
                (!cached || strcasecmp(fallback, cached) != 0)) {
            wc_batch_strategy_internal_log_force_last(ctx, fallback);
        }

        return fallback;
    }

    const char* picked = wc_batch_strategy_internal_pick_first_healthy(ctx);
    if (!cached)
        wc_batch_strategy_plan_b_log_empty(ctx, window_ms);
    if (picked)
        wc_batch_strategy_plan_b_log_force_start(
            ctx, picked, cached ? "fallback-to-healthy" : "no-cache");
    return picked ? picked : (ctx ? ctx->default_host : NULL);
}

static void wc_batch_strategy_plan_b_on_result(const wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    wc_batch_strategy_plan_b_state_t* state =
        wc_batch_strategy_plan_b_get_state(ctx);
    if (!result)
        return;
    if (result->lookup_rc != 0) {
        const char* cached = wc_batch_strategy_plan_b_cached_host(state);
        if (cached && result->start_host &&
                strcasecmp(result->start_host, cached) == 0) {
            wc_batch_strategy_plan_b_clear_cache(state);
        }
        return;
    }
    if (result->authoritative_host && *result->authoritative_host)
        wc_batch_strategy_plan_b_store_authoritative(
            state, result->authoritative_host);
}

static int wc_batch_strategy_plan_b_init(wc_batch_context_t* ctx)
{
    if (!ctx)
        return 0;
    ctx->strategy_state = &g_plan_b_state;
    ctx->strategy_state_cleanup = NULL;
    return 1;
}

static const wc_batch_strategy_t k_wc_batch_strategy_plan_b = {
    .name = "plan-b",
    .init = wc_batch_strategy_plan_b_init,
    .pick_start_host = wc_batch_strategy_plan_b_pick,
    .on_result = wc_batch_strategy_plan_b_on_result,
    .teardown = NULL,
};

void wc_batch_strategy_register_plan_b_with_registry(
        wc_batch_strategy_registry_t* registry)
{
    if (registry)
        wc_batch_strategy_registry_register(registry, &k_wc_batch_strategy_plan_b);
    else
        wc_batch_strategy_register(&k_wc_batch_strategy_plan_b);
}

void wc_batch_strategy_register_plan_b(void)
{
    wc_batch_strategy_register_plan_b_with_registry(NULL);
}
