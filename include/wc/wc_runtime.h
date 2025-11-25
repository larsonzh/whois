#ifndef WC_RUNTIME_H
#define WC_RUNTIME_H

#include "wc_config.h"
#include "wc_opts.h"

// Runtime initialization that depends only on parsed options
// (RNG seed, signal handlers, DNS cache stats atexit hook).
void wc_runtime_init(const wc_opts_t* opts);

// Runtime initialization for caches and conditional-output resources
// using the global g_config; registers corresponding atexit hooks.
void wc_runtime_init_resources(void);

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
