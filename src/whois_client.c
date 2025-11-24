// whois client (version 3.2.9) - migrated from lzispro
// License: GPL-3.0-or-later

// ============================================================================
// 1. Feature toggles and includes
// ============================================================================

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "wc/wc_cache.h"
#include "wc/wc_client_legacy.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_client_net.h"
#include "wc/wc_client_transport.h"
#include "wc/wc_client_util.h"
#include "wc/wc_config.h"
#include "wc/wc_defaults.h"
#include "wc/wc_dns.h"
#include "wc/wc_fold.h"
#include "wc/wc_grep.h"
#include "wc/wc_lookup.h"
#include "wc/wc_meta.h"
#include "wc/wc_net.h"
#include "wc/wc_opts.h"
#include "wc/wc_output.h"
#include "wc/wc_protocol_safety.h"
#include "wc/wc_query_exec.h"
#include "wc/wc_redirect.h"
#include "wc/wc_runtime.h"
#include "wc/wc_seclog.h"
#include "wc/wc_selftest.h"
#include "wc/wc_signal.h"
#include "wc/wc_title.h"
#include "wc/wc_util.h"

// Provide a portable replacement for strdup for strict C11 builds on CI while
// keeping call sites unchanged and enforcing fatal-on-OOM semantics.
#undef strdup
#define strdup(s) wc_safe_strdup((s), "strdup")

// ============================================================================
// 2. Defaults and shared constants
// ============================================================================

#define DEFAULT_WHOIS_PORT WC_DEFAULT_WHOIS_PORT
#define BUFFER_SIZE WC_DEFAULT_BUFFER_SIZE
#define MAX_RETRIES WC_DEFAULT_MAX_RETRIES
#define TIMEOUT_SEC WC_DEFAULT_TIMEOUT_SEC
#define DNS_CACHE_SIZE WC_DEFAULT_DNS_CACHE_SIZE
#define CONNECTION_CACHE_SIZE WC_DEFAULT_CONNECTION_CACHE_SIZE
#define CACHE_TIMEOUT WC_DEFAULT_CACHE_TIMEOUT
#define DEBUG WC_DEFAULT_DEBUG_LEVEL
#define MAX_REDIRECTS WC_DEFAULT_MAX_REDIRECTS

#define RESPONSE_SEPARATOR "\n=== %s query to %s ===\n"
#define FINAL_QUERY_TEXT "Final"
#define REDIRECTED_QUERY_TEXT "Redirected"
#define ADDITIONAL_QUERY_TEXT "Additional"

#define PROTOCOL_TIMEOUT_EXTENDED 30 // Extended timeout for large responses

// ============================================================================
// 3. Global configuration and debug helpers
// ============================================================================

Config g_config = {
	.whois_port = DEFAULT_WHOIS_PORT,
	.buffer_size = BUFFER_SIZE,
	.max_retries = MAX_RETRIES,
	.timeout_sec = TIMEOUT_SEC,
	.retry_interval_ms = 300,
	.retry_jitter_ms = 300,
	.dns_cache_size = DNS_CACHE_SIZE,
	.connection_cache_size = CONNECTION_CACHE_SIZE,
	.cache_timeout = CACHE_TIMEOUT,
	.debug = DEBUG,
	.max_redirects = MAX_REDIRECTS,
	.no_redirect = 0,
	.plain_mode = 0,
	.fold_output = 0,
	.fold_sep = NULL,
	.fold_upper = 1,
	.security_logging = 0,
	.fold_unique = 0,
};

int wc_is_debug_enabled(void) { return g_config.debug; }

// ============================================================================
// 4. Forward declarations
// ============================================================================


// Keep legacy helpers referenced so -Wunused-function stays quiet while the
// new core modules gradually absorb the remaining logic.
static void wc_reference_legacy_helpers(void) {
	(void)&wc_client_perform_legacy_query;
}

// ============================================================================
// 5. Networking helpers
// ============================================================================

// ============================================================================
// 6. WHOIS execution helpers
// ============================================================================

// ============================================================================
// 11. Implementation of the main entry function
// ============================================================================

// Helpers for lookup/response handling are implemented in
// src/core/whois_query_exec.c

// Meta/display handling has been moved to src/core/client_meta.c

int main(int argc, char* argv[]) {
	// Reference legacy helpers so compilers keep them available until the
	// new query exec module fully replaces the old flow.
	wc_reference_legacy_helpers();
	// Parse options via wc_opts module
	wc_opts_t opts;
	if (wc_opts_parse(argc, argv, &opts) != 0) {
		// CLI usage/parameter error: keep returning 1 via
		// WC_EXIT_FAILURE for now, but route through a helper to
		// make the intent explicit.
		return wc_client_exit_usage_error(argv[0], &g_config);
	}

    // Runtime initialization and atexit registration that depend only
	// on parsed options but not yet on derived config.
	wc_runtime_init(&opts);

	// Map parsed options back to legacy global config (incremental migration)
	wc_client_apply_opts_to_config(&opts, &g_config);

	// Apply fold unique behavior
	extern void wc_fold_set_unique(int on);
	wc_fold_set_unique(g_config.fold_unique);

	// Ensure fold separator default if still unset
	if (!g_config.fold_sep) g_config.fold_sep = strdup(" ");

	// Configure security logging module according to parsed options (already set in parse)
	wc_seclog_set_enabled(g_config.security_logging);

	// Language option removed; always use English outputs

	// Validate configuration
	if (!wc_config_validate(&g_config)) return WC_EXIT_FAILURE;

#ifdef WHOIS_SECLOG_TEST
	// Run optional security log self-test if enabled via environment
	maybe_run_seclog_self_test();
#endif

#ifdef WHOIS_GREP_TEST
	// Optional grep self-test driven by env var
	maybe_run_grep_self_test();
#endif

	// Check if cache sizes are reasonable
	if (!wc_cache_validate_sizes()) {
		fprintf(stderr, "Error: Invalid cache sizes, using defaults\n");
		g_config.dns_cache_size = DNS_CACHE_SIZE;
		g_config.connection_cache_size = CONNECTION_CACHE_SIZE;
	}

	if (g_config.debug) printf("[DEBUG] Parsed command line arguments\n");
	if (g_config.debug) {
		printf("[DEBUG] Final configuration:\n");
		printf("        Buffer size: %zu bytes\n", g_config.buffer_size);
		printf("        DNS cache size: %zu entries\n",
			   g_config.dns_cache_size);
		printf("        Connection cache size: %zu entries\n",
			   g_config.connection_cache_size);
		printf("        Timeout: %d seconds\n", g_config.timeout_sec);
		printf("        Max retries: %d\n", g_config.max_retries);
		printf("        Retry interval: %d ms\n", g_config.retry_interval_ms);
		printf("        Retry jitter: %d ms\n", g_config.retry_jitter_ms);
		printf("        DNS retry: %d (interval %d ms, addrconfig %s, max candidates %d)\n",
			g_config.dns_retry, g_config.dns_retry_interval_ms, g_config.dns_addrconfig?"on":"off", g_config.dns_max_candidates);
	}

	// 2. Delegate remaining logic (meta handling, mode detection,
	// resource initialization and single vs batch dispatch) to the
	// core orchestrator.
	int rc = wc_client_run_with_mode(&opts, argc, argv, &g_config);
	wc_opts_free(&opts);
	return rc;
}

