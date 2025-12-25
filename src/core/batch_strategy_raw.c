// SPDX-License-Identifier: MIT
#include "wc/wc_batch_strategy.h"

static const char* wc_batch_strategy_raw_pick(const wc_batch_context_t* ctx)
{
    if (!ctx)
        return NULL;
    if (ctx->candidates && ctx->candidate_count > 0 && ctx->candidates[0])
        return ctx->candidates[0];
    if (ctx->default_host)
        return ctx->default_host;
    return NULL;
}

static const wc_batch_strategy_t k_wc_batch_strategy_raw = {
    .name = "raw",
    .init = NULL,
    .pick_start_host = wc_batch_strategy_raw_pick,
    .on_result = NULL,
    .teardown = NULL,
};

void wc_batch_strategy_register_raw_with_registry(
        wc_batch_strategy_registry_t* registry)
{
    if (registry)
        wc_batch_strategy_registry_register(registry, &k_wc_batch_strategy_raw);
    else
        wc_batch_strategy_register(&k_wc_batch_strategy_raw);
}

void wc_batch_strategy_register_raw(void)
{
    wc_batch_strategy_register_raw_with_registry(NULL);
}
