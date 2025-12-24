// SPDX-License-Identifier: MIT
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"

#define WC_BATCH_MAX_REGISTERED_STRATEGIES 8

static const wc_batch_strategy_iface_t* g_strategies[WC_BATCH_MAX_REGISTERED_STRATEGIES];
static size_t g_strategy_count = 0;
static const wc_batch_strategy_iface_t* g_active_strategy = NULL;

static const wc_batch_strategy_iface_t* wc_batch_strategy_find(const char* name)
{
    if (!name)
        return NULL;
    for (size_t i = 0; i < g_strategy_count; ++i) {
        const wc_batch_strategy_iface_t* strat = g_strategies[i];
        if (!strat || !strat->name)
            continue;
        if (strcasecmp(strat->name, name) == 0)
            return strat;
    }
    return NULL;
}

void wc_batch_strategy_register(const wc_batch_strategy_iface_t* strategy)
{
    if (!strategy || !strategy->name || !strategy->pick_start_host)
        return;
    if (g_strategy_count >= WC_BATCH_MAX_REGISTERED_STRATEGIES)
        return;
    g_strategies[g_strategy_count++] = strategy;
    if (!g_active_strategy)
        g_active_strategy = strategy;
}

void wc_batch_strategy_register_builtins(void)
{
    static int builtins_registered = 0;
    if (builtins_registered)
        return;
    builtins_registered = 1;
    wc_batch_strategy_register_raw();
    wc_batch_strategy_register_health_first();
    wc_batch_strategy_register_plan_a();
    wc_batch_strategy_register_plan_b();
}

int wc_batch_strategy_set_active_name(const char* name)
{
    if (!name || !*name)
        return 0;
    const wc_batch_strategy_iface_t* strat = wc_batch_strategy_find(name);
    if (strat) {
        g_active_strategy = strat;
        return 1;
    }
    return 0;
}

const wc_batch_strategy_iface_t* wc_batch_strategy_get_active(void)
{
    if (!g_active_strategy && g_strategy_count > 0)
        g_active_strategy = g_strategies[0];
    return g_active_strategy;
}

static int wc_batch_strategy_ensure_init(wc_batch_context_t* ctx,
        const wc_batch_strategy_iface_t* strat)
{
    if (!ctx || !strat)
        return 1;
    if (ctx->strategy_state_initialized)
        return 1;
    ctx->strategy_state_initialized = 1;
    if (strat->init)
        return strat->init(ctx);
    return 1;
}

static void wc_batch_strategy_cleanup_state(wc_batch_context_t* ctx)
{
    if (!ctx)
        return;
    if (ctx->strategy_state && ctx->strategy_state_cleanup)
        ctx->strategy_state_cleanup(ctx->strategy_state);
    ctx->strategy_state = NULL;
    ctx->strategy_state_cleanup = NULL;
    ctx->strategy_state_initialized = 0;
}

const char* wc_batch_strategy_pick(wc_batch_context_t* ctx)
{
    const wc_batch_strategy_iface_t* strat = wc_batch_strategy_get_active();
    if (!strat || !strat->pick_start_host)
        return NULL;
    if (!wc_batch_strategy_ensure_init(ctx, strat))
        return NULL;
    return strat->pick_start_host(ctx);
}

void wc_batch_strategy_handle_result(wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    const wc_batch_strategy_iface_t* strat = wc_batch_strategy_get_active();
    if (strat && strat->on_result)
        strat->on_result(ctx, result);
    if (strat && strat->teardown)
        strat->teardown(ctx);
    wc_batch_strategy_cleanup_state(ctx);
}
