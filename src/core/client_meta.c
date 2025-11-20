#include <stdlib.h>
#include <string.h>

#include "wc/wc_client_meta.h"
#include "wc/wc_util.h"

void wc_client_apply_opts_to_config(const wc_opts_t* opts, Config* cfg) {
	if (!opts || !cfg) return;
	// Map parsed options back to legacy global config (incremental migration)
	cfg->whois_port = opts->port;
	cfg->timeout_sec = opts->timeout_sec;
	cfg->max_retries = opts->retries;
	cfg->retry_interval_ms = opts->retry_interval_ms;
	cfg->retry_jitter_ms = opts->retry_jitter_ms;
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
