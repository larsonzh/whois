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
#include "wc/wc_client_flow.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_client_net.h"
#include "wc/wc_client_transport.h"
#include "wc/wc_client_util.h"
#include "wc/wc_client_runner.h"
#include "wc/wc_config.h"
#include "wc/wc_defaults.h"
#include "wc/wc_dns.h"
#include "wc/wc_grep.h"
#include "wc/wc_lookup.h"
#include "wc/wc_meta.h"
#include "wc/wc_net.h"
#include "wc/wc_opts.h"
#include "wc/wc_output.h"
#include "wc/wc_pipeline.h"
#include "wc/wc_protocol_safety.h"
#include "wc/wc_redirect.h"
#include "wc/wc_runtime.h"
#include "wc/wc_selftest.h"
#include "wc/wc_signal.h"
#include "wc/wc_title.h"
#include "wc/wc_util.h"

// Provide a portable replacement for strdup for strict C11 builds on CI while
// keeping call sites unchanged and enforcing fatal-on-OOM semantics.
#undef strdup
#define strdup(s) wc_safe_strdup((s), "strdup")

// ============================================================================
// 2. Implementation of the main entry function (thin wrapper)
// ============================================================================

int main(int argc, char* argv[]) {
	// Parse options via wc_opts module
	wc_opts_t opts;
	if (wc_opts_parse(argc, argv, &opts) != 0) {
		return wc_client_handle_usage_error(argv[0], wc_client_runner_config_ro());
	}

	// Bootstrap runtime + config; early exit on failure
	int boot_rc = wc_client_runner_bootstrap(&opts);
	if (boot_rc != WC_EXIT_SUCCESS) {
		wc_opts_free(&opts);
		return boot_rc;
	}

	// Delegate remaining logic to the pipeline facade (currently a thin
	// wrapper around the legacy client_flow orchestrator).
	int rc = wc_pipeline_run(&opts, argc, argv, wc_client_runner_config());
	wc_opts_free(&opts);
	return rc;
}

