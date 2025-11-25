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

#endif // WC_RUNTIME_H
