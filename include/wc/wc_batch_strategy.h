// SPDX-License-Identifier: MIT
#ifndef WC_BATCH_STRATEGY_H
#define WC_BATCH_STRATEGY_H

#include <stddef.h>

#include "wc/wc_backoff.h"

#ifndef WC_BATCH_MAX_CANDIDATES
#define WC_BATCH_MAX_CANDIDATES 8
#endif

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
    void* strategy_state;                 // optional strategy-owned state
    void (*strategy_state_cleanup)(void*); // optional state cleanup hook
    int strategy_state_initialized;       // guard to run init once per query
} wc_batch_context_t;

typedef struct wc_batch_context_builder_s {
    wc_batch_context_t ctx;
    const char* candidate_storage[WC_BATCH_MAX_CANDIDATES];
    wc_backoff_host_health_t health_storage[WC_BATCH_MAX_CANDIDATES];
} wc_batch_context_builder_t;

typedef struct wc_batch_strategy_result_s {
    const char* start_host;               // host actually dialed this round
    const char* authoritative_host;       // authoritative RIR reported by server (may be NULL)
    int lookup_rc;                        // wc_execute_lookup() return code
} wc_batch_strategy_result_t;

typedef struct wc_batch_strategy_iface_s {
    const char* name;                     // human readable name (e.g. "health-first")
    int (*init)(wc_batch_context_t* ctx); // optional state setup; return non-zero on success
    const char* (*pick_start_host)(const wc_batch_context_t* ctx);
    void (*on_result)(const wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result);
    void (*teardown)(wc_batch_context_t* ctx); // optional state cleanup
} wc_batch_strategy_iface_t;

typedef wc_batch_strategy_iface_t wc_batch_strategy_t;

void wc_batch_strategy_register(const wc_batch_strategy_iface_t* strategy);
int wc_batch_strategy_set_active_name(const char* name);
const wc_batch_strategy_iface_t* wc_batch_strategy_get_active(void);
const char* wc_batch_strategy_pick(wc_batch_context_t* ctx);
void wc_batch_strategy_handle_result(wc_batch_context_t* ctx,
    const wc_batch_strategy_result_t* result);

// Built-in strategies --------------------------------------------------------
void wc_batch_strategy_register_health_first(void);
void wc_batch_strategy_register_plan_a(void);
void wc_batch_strategy_register_plan_b(void);

#ifdef __cplusplus
}
#endif

#endif // WC_BATCH_STRATEGY_H
