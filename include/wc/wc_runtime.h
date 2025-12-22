#ifndef WC_RUNTIME_H
#define WC_RUNTIME_H

#include "wc_config.h"
#include "wc_opts.h"

void wc_runtime_init(const wc_opts_t* opts);
void wc_runtime_init_resources(const Config* config);

// Best-effort DNS cache summary printer (stderr). Safe to call multiple
// times; outputs at most once per process when dns-cache-stats is enabled.
void wc_runtime_emit_dns_cache_summary(void);
void wc_runtime_set_cache_counter_sampling(int enabled);
int wc_runtime_cache_counter_sampling_enabled(void);
void wc_runtime_sample_cache_counters(void);

// Snapshot the active Config into caller-provided storage (zeroed if none).
void wc_runtime_snapshot_config(Config* out);

// Temporarily override the active Config pointer (LIFO). Returns 0 on push,
// non-zero if the stack is full or cfg is NULL. Use pop to restore.
int wc_runtime_push_config(const Config* cfg);
void wc_runtime_pop_config(void);

// Apply post-parse configuration toggles that historically lived in the
// CLI entry point (fold separator/defaults, security logging, etc.).
void wc_runtime_apply_post_config(Config* config);

// Runtime-managed housekeeping hooks allow core modules to schedule
// maintenance tasks (cache cleanup, integrity validation, etc.) without
// exposing individual helpers to every caller. Hooks can opt into
// DEBUG-only execution via the WC_RUNTIME_HOOK_FLAG_DEBUG_ONLY flag.
typedef void (*wc_runtime_housekeeping_cb)(void);

enum {
	WC_RUNTIME_HOOK_FLAG_NONE = 0,
	WC_RUNTIME_HOOK_FLAG_DEBUG_ONLY = 1u << 0
};

void wc_runtime_register_housekeeping_callback(wc_runtime_housekeeping_cb cb,
		unsigned int flags);
void wc_runtime_housekeeping_tick(void);

#endif // WC_RUNTIME_H
