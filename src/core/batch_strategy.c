// SPDX-License-Identifier: MIT
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"

#define WC_BATCH_MAX_REGISTERED_STRATEGIES 8

static const wc_batch_strategy_t* g_strategies[WC_BATCH_MAX_REGISTERED_STRATEGIES];
static size_t g_strategy_count = 0;
static const wc_batch_strategy_t* g_active_strategy = NULL;

static const wc_batch_strategy_t* wc_batch_strategy_find(const char* name)
{
    if (!name)
        return NULL;
    for (size_t i = 0; i < g_strategy_count; ++i) {
        const wc_batch_strategy_t* strat = g_strategies[i];
        if (!strat || !strat->name)
            continue;
        if (strcasecmp(strat->name, name) == 0)
            return strat;
    }
    return NULL;
}

void wc_batch_strategy_register(const wc_batch_strategy_t* strategy)
{
    if (!strategy || !strategy->name || !strategy->pick_start_host)
        return;
    if (g_strategy_count >= WC_BATCH_MAX_REGISTERED_STRATEGIES)
        return;
    g_strategies[g_strategy_count++] = strategy;
    if (!g_active_strategy)
        g_active_strategy = strategy;
}

void wc_batch_strategy_set_active_name(const char* name)
{
    if (!name || !*name)
        return;
    const wc_batch_strategy_t* strat = wc_batch_strategy_find(name);
    if (strat)
        g_active_strategy = strat;
}

const wc_batch_strategy_t* wc_batch_strategy_get_active(void)
{
    if (!g_active_strategy && g_strategy_count > 0)
        g_active_strategy = g_strategies[0];
    return g_active_strategy;
}

const char* wc_batch_strategy_pick(const wc_batch_context_t* ctx)
{
    const wc_batch_strategy_t* strat = wc_batch_strategy_get_active();
    if (!strat || !strat->pick_start_host)
        return NULL;
    return strat->pick_start_host(ctx);
}
