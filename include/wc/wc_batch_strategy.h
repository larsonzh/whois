// SPDX-License-Identifier: MIT
#ifndef WC_BATCH_STRATEGY_H
#define WC_BATCH_STRATEGY_H

#include <stddef.h>

#include "wc/wc_backoff.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wc_batch_context_s {
    const char* server_host;              // raw CLI host (may be NULL)
    const char* query;                    // current query string
    const char* default_host;             // default fallback host (IANA)
    const char* const* candidates;        // ordered candidate list
    size_t candidate_count;               // number of entries in candidates
    const wc_backoff_host_health_t* health_entries; // snapshots aligned to hosts
    size_t health_count;                  // number of valid snapshots
} wc_batch_context_t;

typedef struct wc_batch_strategy_s {
    const char* name;                     // human readable name (e.g. "health-first")
    const char* (*pick_start_host)(const wc_batch_context_t* ctx);
} wc_batch_strategy_t;

void wc_batch_strategy_register(const wc_batch_strategy_t* strategy);
void wc_batch_strategy_set_active_name(const char* name);
const wc_batch_strategy_t* wc_batch_strategy_get_active(void);
const char* wc_batch_strategy_pick(const wc_batch_context_t* ctx);

// Built-in strategies --------------------------------------------------------
void wc_batch_strategy_register_health_first(void);

#ifdef __cplusplus
}
#endif

#endif // WC_BATCH_STRATEGY_H
