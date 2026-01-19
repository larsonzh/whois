// SPDX-License-Identifier: GPL-3.0-or-later

#include "wc/wc_client_frontend.h"

#include "wc/wc_client_runner.h"
#include "wc/wc_client_flow.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_runtime.h"
#include "wc/wc_types.h"

int wc_client_frontend_run(int argc, char* argv[], const wc_opts_t* opts)
{
	if (!opts)
		return WC_EXIT_FAILURE;

	if (wc_client_is_meta_only(opts)) {
		int meta_rc = wc_client_handle_meta_requests(
			opts, argv && argv[0] ? argv[0] : "whois",
			wc_client_runner_config_ro());
		if (meta_rc != 0)
			return (meta_rc > 0) ? WC_EXIT_SUCCESS : WC_EXIT_FAILURE;
	}

	int boot_rc = wc_client_runner_bootstrap(opts);
	if (boot_rc != WC_EXIT_SUCCESS)
		return boot_rc;

	int rc = wc_client_run_with_mode(opts, argc, argv, wc_client_runner_config_ro());
	wc_runtime_exit_flush();
	return rc;
}
