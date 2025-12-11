// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <strings.h>

#include "wc/wc_batch_strategy.h"
#include "wc/wc_debug.h"
#include "batch_strategy_internal.h"

static const char* wc_batch_strategy_health_pick(const wc_batch_context_t* ctx)
{
    return wc_batch_strategy_internal_pick_first_healthy(ctx);
}

static const wc_batch_strategy_t k_wc_batch_strategy_health_first = {
    .name = "health-first",
    .init = NULL,
    .pick_start_host = wc_batch_strategy_health_pick,
    .on_result = NULL,
    .teardown = NULL,
};

void wc_batch_strategy_register_health_first(void)
{
    wc_batch_strategy_register(&k_wc_batch_strategy_health_first);
}
