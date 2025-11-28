// SPDX-License-Identifier: GPL-3.0-or-later
// Centralized exit helpers for CLI usage errors.

#include "wc/wc_client_exit.h"
#include "wc/wc_meta.h"
#include "wc/wc_defaults.h"
#include "wc/wc_types.h"

int wc_client_exit_usage_error(const char* progname, const Config* cfg)
{
    wc_meta_print_usage(progname,
        WC_DEFAULT_WHOIS_PORT,
        WC_DEFAULT_BUFFER_SIZE,
        WC_DEFAULT_MAX_RETRIES,
        WC_DEFAULT_TIMEOUT_SEC,
        cfg ? cfg->retry_interval_ms : 300,
        cfg ? cfg->retry_jitter_ms : 300,
        WC_DEFAULT_MAX_REDIRECTS,
        WC_DEFAULT_DNS_CACHE_SIZE,
        WC_DEFAULT_CONNECTION_CACHE_SIZE,
        WC_DEFAULT_CACHE_TIMEOUT,
        WC_DEFAULT_DEBUG_LEVEL);
    return WC_EXIT_FAILURE;
}
