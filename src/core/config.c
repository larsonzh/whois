// SPDX-License-Identifier: GPL-3.0-or-later
// Config validation helpers shared by CLI and core modules.

#include <stdio.h>
#include "wc/wc_config.h"
#include "wc/wc_cache.h"
#include "wc/wc_client_util.h"
#include "wc/wc_defaults.h"

int wc_config_validate(const Config* config) {
	if (!config) {
		fprintf(stderr, "Error: Config pointer is NULL\n");
		return 0;
	}

	if (config->whois_port <= 0 || config->whois_port > 65535) {
		fprintf(stderr, "Error: Invalid port number in config\n");
		return 0;
	}

	if (config->buffer_size == 0) {
		fprintf(stderr, "Error: Invalid buffer size in config\n");
		return 0;
	}

	if (config->max_retries < 0) {
		fprintf(stderr, "Error: Invalid retry count in config\n");
		return 0;
	}

	if (config->timeout_sec <= 0) {
		fprintf(stderr, "Error: Invalid timeout value in config\n");
		return 0;
	}

	if (config->dns_cache_size == 0) {
		fprintf(stderr, "Error: Invalid DNS cache size in config\n");
		return 0;
	}

	if (config->connection_cache_size == 0) {
		fprintf(stderr, "Error: Invalid connection cache size in config\n");
		return 0;
	}

	if (config->cache_timeout <= 0) {
		fprintf(stderr, "Error: Invalid cache timeout in config\n");
		return 0;
	}

	if (config->max_redirects < 0) {
		fprintf(stderr, "Error: Invalid max redirects in config\n");
		return 0;
	}

	if (!config->fold_sep) {
		fprintf(stderr, "Error: fold separator is missing in config\n");
		return 0;
	}

	if (config->retry_interval_ms < 0) {
		fprintf(stderr, "Error: Invalid retry interval in config\n");
		return 0;
	}

	if (config->retry_jitter_ms < 0) {
		fprintf(stderr, "Error: Invalid retry jitter in config\n");
		return 0;
	}

	return 1;
}

int wc_config_prepare_cache_settings(Config* config)
{
	if (!config) {
		fprintf(stderr, "Error: Config pointer is NULL\n");
		return 0;
	}

	if (config->dns_cache_size == 0 ||
	    config->dns_cache_size > WC_CACHE_MAX_DNS_ENTRIES) {
		fprintf(stderr,
		        "Warning: DNS cache size %zu is unreasonable, using default\n",
		        config->dns_cache_size);
		config->dns_cache_size = WC_DEFAULT_DNS_CACHE_SIZE;
	}

	if (config->connection_cache_size == 0 ||
	    config->connection_cache_size > WC_CACHE_MAX_CONNECTION_ENTRIES) {
		fprintf(stderr,
		        "Warning: Connection cache size %zu is unreasonable, using default\n",
		        config->connection_cache_size);
		config->connection_cache_size = WC_DEFAULT_CONNECTION_CACHE_SIZE;
	}

	size_t free_mem = wc_client_get_free_memory();
	if (free_mem == 0) {
		return 1;
	}

	size_t required_mem = wc_cache_estimate_memory_bytes(config->dns_cache_size,
		config->connection_cache_size);
	required_mem = required_mem * 110 / 100;

	if (required_mem > free_mem * 1024) {
		fprintf(stderr,
		        "Warning: Requested cache size (%zu bytes) exceeds available memory (%zu KB)\n",
		        required_mem,
		        free_mem);
		config->dns_cache_size = WC_DEFAULT_DNS_CACHE_SIZE;
		config->connection_cache_size = WC_DEFAULT_CONNECTION_CACHE_SIZE;
	}

	return 1;
}
