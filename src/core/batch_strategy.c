// SPDX-License-Identifier: MIT
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"

static wc_batch_strategy_registry_t g_wc_batch_strategy_registry;

static wc_batch_strategy_registry_t* wc_batch_strategy_resolve_registry(
        wc_batch_strategy_registry_t* registry)
{
    if (registry)
        return registry;
    return &g_wc_batch_strategy_registry;
}

static const wc_batch_strategy_iface_t*
wc_batch_strategy_registry_find(const wc_batch_strategy_registry_t* registry,
        const char* name)
{
    if (!registry || !name)
        return NULL;
    for (size_t i = 0; i < registry->strategy_count; ++i) {
        const wc_batch_strategy_iface_t* strat = registry->strategies[i];
        if (!strat || !strat->name)
            continue;
        if (strcasecmp(strat->name, name) == 0)
            return strat;
    }
    return NULL;
}

void wc_batch_strategy_registry_init(wc_batch_strategy_registry_t* registry)
{
    if (!registry)
        return;
    memset(registry, 0, sizeof(*registry));
}

void wc_batch_strategy_registry_register(wc_batch_strategy_registry_t* registry,
        const wc_batch_strategy_iface_t* strategy)
{
    registry = wc_batch_strategy_resolve_registry(registry);
    if (!strategy || !strategy->name || !strategy->pick_start_host)
        return;
    if (registry->strategy_count >= WC_BATCH_MAX_REGISTERED_STRATEGIES)
        return;
    registry->strategies[registry->strategy_count++] = strategy;
    if (!registry->active)
        registry->active = strategy;
}

void wc_batch_strategy_registry_register_builtins(wc_batch_strategy_registry_t* registry)
{
    registry = wc_batch_strategy_resolve_registry(registry);
    if (registry->builtins_registered)
        return;
    registry->builtins_registered = 1;
    wc_batch_strategy_register_raw_with_registry(registry);
    wc_batch_strategy_register_health_first_with_registry(registry);
    wc_batch_strategy_register_plan_a_with_registry(registry);
    wc_batch_strategy_register_plan_b_with_registry(registry);
}

int wc_batch_strategy_registry_set_active_name(wc_batch_strategy_registry_t* registry,
        const char* name)
{
    registry = wc_batch_strategy_resolve_registry(registry);
    if (!name || !*name)
        return 0;
    const wc_batch_strategy_iface_t* strat =
        wc_batch_strategy_registry_find(registry, name);
    if (strat) {
        registry->active = strat;
        return 1;
    }
    return 0;
}

int wc_batch_strategy_registry_bootstrap(wc_batch_strategy_registry_t* registry,
        const char* name)
{
    if (!registry)
        return 0;
    wc_batch_strategy_registry_init(registry);
    wc_batch_strategy_registry_register_builtins(registry);
    if (!name || !*name)
        return 0;
    if (!wc_batch_strategy_registry_set_active_name(registry, name))
        return -1;
    return 1;
}

const wc_batch_strategy_iface_t* wc_batch_strategy_registry_get_active(
        wc_batch_strategy_registry_t* registry)
{
    registry = wc_batch_strategy_resolve_registry(registry);
    if (!registry->active && registry->strategy_count > 0)
        registry->active = registry->strategies[0];
    return registry->active;
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

const char* wc_batch_strategy_registry_pick(wc_batch_strategy_registry_t* registry,
        wc_batch_context_t* ctx)
{
    registry = wc_batch_strategy_resolve_registry(registry);
    const wc_batch_strategy_iface_t* strat =
        wc_batch_strategy_registry_get_active(registry);
    if (!strat || !strat->pick_start_host)
        return NULL;
    if (!wc_batch_strategy_ensure_init(ctx, strat))
        return NULL;
    return strat->pick_start_host(ctx);
}

void wc_batch_strategy_registry_handle_result(wc_batch_strategy_registry_t* registry,
        wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    registry = wc_batch_strategy_resolve_registry(registry);
    const wc_batch_strategy_iface_t* strat =
        wc_batch_strategy_registry_get_active(registry);
    if (strat && strat->on_result)
        strat->on_result(ctx, result);
    if (strat && strat->teardown)
        strat->teardown(ctx);
    wc_batch_strategy_cleanup_state(ctx);
}

// Legacy global registry wrappers ------------------------------------------------

void wc_batch_strategy_register(const wc_batch_strategy_iface_t* strategy)
{
    wc_batch_strategy_registry_register(NULL, strategy);
}

void wc_batch_strategy_register_builtins(void)
{
    wc_batch_strategy_registry_register_builtins(NULL);
}

int wc_batch_strategy_set_active_name(const char* name)
{
    return wc_batch_strategy_registry_set_active_name(NULL, name);
}

const wc_batch_strategy_iface_t* wc_batch_strategy_get_active(void)
{
    return wc_batch_strategy_registry_get_active(NULL);
}

const char* wc_batch_strategy_pick(wc_batch_context_t* ctx)
{
    return wc_batch_strategy_registry_pick(NULL, ctx);
}

void wc_batch_strategy_handle_result(wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    wc_batch_strategy_registry_handle_result(NULL, ctx, result);
}
