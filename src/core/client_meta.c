#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "wc/wc_client_meta.h"
#include "wc/wc_client_usage.h"
#include "wc/wc_util.h"
#include "wc/wc_meta.h"
#include "wc/wc_defaults.h"
#include "wc/wc_types.h"

// optind is provided by getopt; declare it here for core module.
extern int optind;

void wc_client_apply_opts_to_config(const wc_opts_t* opts, Config* cfg) {
	if (!opts || !cfg) return;
	// Map parsed options back to legacy global config (incremental migration)
	cfg->whois_port = opts->port;
	cfg->timeout_sec = opts->timeout_sec;
	cfg->max_retries = opts->retries;
	cfg->retry_interval_ms = opts->retry_interval_ms;
	cfg->retry_jitter_ms = opts->retry_jitter_ms;
	cfg->retry_all_addrs = opts->retry_all_addrs;
	cfg->retry_metrics = opts->retry_metrics;
	cfg->pacing_disable = opts->pacing_disable;
	cfg->pacing_interval_ms = opts->pacing_interval_ms;
	cfg->pacing_jitter_ms = opts->pacing_jitter_ms;
	cfg->pacing_backoff_factor = opts->pacing_backoff_factor;
	cfg->pacing_max_ms = opts->pacing_max_ms;
	cfg->max_redirects = opts->max_hops;
	cfg->no_redirect = opts->no_redirect;
	cfg->plain_mode = opts->plain_mode;
	cfg->debug = opts->debug;
	if (opts->debug_verbose)
		cfg->debug = (cfg->debug < 2 ? 2 : cfg->debug);
	// Note: WHOIS_DEBUG env is deprecated; CLI flags control debug.
	cfg->buffer_size = opts->buffer_size;
	cfg->dns_cache_size = opts->dns_cache_size;
	cfg->connection_cache_size = opts->connection_cache_size;
	cfg->cache_timeout = opts->cache_timeout;
	cfg->ipv4_only = opts->ipv4_only;
	cfg->ipv6_only = opts->ipv6_only;
	cfg->prefer_ipv4 = opts->prefer_ipv4;
	cfg->prefer_ipv6 = opts->prefer_ipv6;
	cfg->dns_neg_ttl = opts->dns_neg_ttl;
	cfg->dns_neg_cache_disable = opts->dns_neg_cache_disable;
	// DNS resolver controls and fallbacks
	cfg->dns_addrconfig = opts->dns_addrconfig;
	cfg->dns_retry = opts->dns_retry;
	cfg->dns_retry_interval_ms = opts->dns_retry_interval_ms;
	cfg->dns_max_candidates = opts->dns_max_candidates;
	cfg->no_dns_known_fallback = opts->no_dns_known_fallback;
	cfg->no_dns_force_ipv4_fallback = opts->no_dns_force_ipv4_fallback;
	cfg->no_iana_pivot = opts->no_iana_pivot;
	cfg->dns_no_fallback = opts->dns_no_fallback;
	cfg->batch_strategy = opts->batch_strategy;
	cfg->fold_output = opts->fold;
	cfg->fold_upper = opts->fold_upper;
	cfg->fold_unique = opts->fold_unique;
	if (opts->fold_sep) {
		if (cfg->fold_sep)
			free(cfg->fold_sep);
		size_t len = strlen(opts->fold_sep) + 1;
		char* sep_copy = (char*)wc_safe_malloc(len, __func__);
		memcpy(sep_copy, opts->fold_sep, len);
		cfg->fold_sep = sep_copy;
	}
	cfg->security_logging = opts->security_log;
}

int wc_client_handle_meta_requests(const wc_opts_t* opts,
		const char* progname,
		const Config* cfg) {
	if (!opts)
		return 0;
	if (opts->show_help) {
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
		return 1;
	}
	if (opts->show_version) {
		wc_meta_print_version();
		return 1;
	}
	if (opts->show_about) {
		wc_meta_print_about();
		return 1;
	}
	if (opts->show_examples) {
		wc_meta_print_examples(progname);
		return 1;
	}
	if (opts->show_servers) {
		wc_client_print_server_catalog();
		return 1;
	}
	if (opts->show_selftest) {
		extern int wc_selftest_run(void);
		int rc = wc_selftest_run();
		return (rc == 0) ? 1 : -1;
	}
	return 0;
}

int wc_client_detect_mode_and_query(const wc_opts_t* opts,
		int argc, char* argv[], int* out_batch_mode,
		const char** out_single_query,
		const Config* cfg) {
	(void)cfg;
	if (!out_batch_mode || !out_single_query)
		return -1;
	*out_batch_mode = 0;
	*out_single_query = NULL;

	int explicit_batch = opts ? opts->explicit_batch : 0;
	if (explicit_batch) {
		*out_batch_mode = 1;
		if (optind < argc) {
			fprintf(stderr,
				"Error: --batch/-B does not accept a positional query. Provide input via stdin.\n");
			wc_meta_print_usage(argv[0],
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
			return -1;
		}
		return 0;
	}

	if (optind >= argc) {
		if (!isatty(STDIN_FILENO)) {
			// Auto batch when no positional arg and stdin is piped.
			*out_batch_mode = 1;
			return 0;
		}
		fprintf(stderr, "Error: Missing query argument\n");
		wc_meta_print_usage(argv[0],
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
		return -1;
	}

	*out_single_query = argv[optind];
	return 0;
}
