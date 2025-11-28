#pragma once

#include "wc_opts.h"
#include "wc_config.h"

// Apply parsed CLI options back to a Config instance.
// This keeps whois_client.c thin and allows other modules
// to reuse the same mapping logic if needed.
void wc_client_apply_opts_to_config(const wc_opts_t* opts, Config* cfg);

// Handle meta/display options (help/version/about/examples/servers/selftest).
// Return values:
//   0  -> no meta option consumed, continue normal flow
//   >0 -> meta handled successfully, caller should exit(0)
//   <0 -> meta handled but indicates failure (e.g. selftest failed)
int wc_client_handle_meta_requests(const wc_opts_t* opts, const char* progname,
		const Config* cfg);

// Detect batch vs single-query mode and extract positional query.
// Returns 0 on success, non-zero on error (after printing usage
// message). Mirrors the legacy wc_detect_mode_and_query semantics
// but lives in core to keep whois_client.c thin.
int wc_client_detect_mode_and_query(const wc_opts_t* opts,
		int argc, char* argv[], int* out_batch_mode,
		const char** out_single_query,
		const Config* cfg);

// Emit usage text for CLI errors and return WC_EXIT_FAILURE. The
// Config pointer supplies runtime-tuned retry intervals; when NULL
// defaults are used.
int wc_client_exit_usage_error(const char* progname, const Config* cfg);

