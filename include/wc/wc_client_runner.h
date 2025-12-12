// SPDX-License-Identifier: MIT
#ifndef WC_CLIENT_RUNNER_H
#define WC_CLIENT_RUNNER_H

#include "wc_config.h"
#include "wc_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

// Global configuration instance shared across core modules.
extern Config g_config;

// Expose the active configuration for callers that need a pointer
// without relying on the global symbol directly. The returned pointer
// remains owned by the runner module.
Config* wc_client_runner_config(void);
const Config* wc_client_runner_config_ro(void);

// Initialize runtime and map parsed options into the shared Config.
// Returns 0 on success; WC_EXIT_FAILURE on validation error or other
// fatal conditions. Does not free opts.
int wc_client_runner_bootstrap(const wc_opts_t* opts);

#ifdef __cplusplus
}
#endif

#endif // WC_CLIENT_RUNNER_H
