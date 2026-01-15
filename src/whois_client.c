// whois client (version 3.2.10) - migrated from lzispro
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

#include <stdlib.h>

#include "wc/wc_client_exit.h"
#include "wc/wc_client_frontend.h"
#include "wc/wc_opts.h"
#include "wc/wc_types.h"
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
		return wc_client_exit_usage_error(argv[0], NULL);
	}

	int rc = wc_client_frontend_run(argc, argv, &opts);
	wc_opts_free(&opts);
	return rc;
}

