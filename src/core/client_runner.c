// SPDX-License-Identifier: GPL-3.0-or-later
// Bootstrap/runner glue to slim the CLI entry point.

#include "wc/wc_client_runner.h"

#include <stdio.h>
#include <stdlib.h>

#include "wc/wc_defaults.h"
#include "wc/wc_types.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_client_exit.h"
#include "wc/wc_runtime.h"
#include "wc/wc_output.h"
#include "wc/wc_debug.h"
#include "wc/wc_selftest.h"

// Process-wide Config retained here; access via wc_client_runner_config_ro().
static Config g_client_config = {
    .whois_port = WC_DEFAULT_WHOIS_PORT,
    .buffer_size = WC_DEFAULT_BUFFER_SIZE,
    .max_retries = WC_DEFAULT_MAX_RETRIES,
    .timeout_sec = WC_DEFAULT_TIMEOUT_SEC,
    .retry_interval_ms = 300,
    .retry_jitter_ms = 300,
    .retry_all_addrs = 0,
    .retry_metrics = 0,
    .pacing_disable = -1,
    .pacing_interval_ms = -1,
    .pacing_jitter_ms = -1,
    .pacing_backoff_factor = -1,
    .pacing_max_ms = -1,
    .dns_cache_size = WC_DEFAULT_DNS_CACHE_SIZE,
    .connection_cache_size = WC_DEFAULT_CONNECTION_CACHE_SIZE,
    .cache_timeout = WC_DEFAULT_CACHE_TIMEOUT,
    .cache_counter_sampling = 0,
    .debug = WC_DEFAULT_DEBUG_LEVEL,
    .max_redirects = WC_DEFAULT_MAX_REDIRECTS,
    .no_redirect = 0,
    .plain_mode = 0,
    .fold_output = 0,
    .fold_sep = NULL,
    .fold_upper = 1,
    .security_logging = 0,
    .fold_unique = 0,
    .prefer_ipv4 = 0,
    .prefer_ipv6 = 1,
    .ip_pref_mode = WC_IP_PREF_MODE_AUTO_V6_FIRST,
    .dns_family_mode = WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST,
    .batch_strategy = NULL,
};

int wc_is_debug_enabled(void)
{
    return wc_output_is_debug_enabled();
}

const Config* wc_client_runner_config_ro(void) { return &g_client_config; }

int wc_client_runner_bootstrap(const wc_opts_t* opts)
{
    if (!opts)
        return WC_EXIT_FAILURE;

    // Stage 1: runtime init that only depends on opts
    wc_runtime_init(opts);

    // Stage 2: map opts into config and normalize
    wc_client_apply_opts_to_config(opts, &g_client_config);
    if (!wc_config_prepare_cache_settings(&g_client_config)) {
        return WC_EXIT_FAILURE;
    }
    wc_runtime_apply_post_config(&g_client_config);

    // Stage 3: validate config before continuing
    if (!wc_config_validate(&g_client_config))
        return WC_EXIT_FAILURE;

    // Stage 4: selftest trigger (uses opts, does not mutate config)
    wc_selftest_run_if_enabled(opts);

    if (wc_is_debug_enabled()) {
        printf("[DEBUG] Parsed command line arguments\n");
        printf("[DEBUG] Final configuration:\n");
        printf("        Buffer size: %zu bytes\n", g_client_config.buffer_size);
        printf("        DNS cache size: %zu entries\n", g_client_config.dns_cache_size);
        printf("        Connection cache size: %zu entries\n", g_client_config.connection_cache_size);
        printf("        Timeout: %d seconds\n", g_client_config.timeout_sec);
        printf("        Max retries: %d\n", g_client_config.max_retries);
        printf("        Retry interval: %d ms\n", g_client_config.retry_interval_ms);
        printf("        Retry jitter: %d ms\n", g_client_config.retry_jitter_ms);
        printf("        DNS retry: %d (interval %d ms, addrconfig %s, max candidates %d)\n",
            g_client_config.dns_retry, g_client_config.dns_retry_interval_ms,
            g_client_config.dns_addrconfig ? "on" : "off", g_client_config.dns_max_candidates);
    }

    return WC_EXIT_SUCCESS;
}
