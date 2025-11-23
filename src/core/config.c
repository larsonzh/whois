// SPDX-License-Identifier: GPL-3.0-or-later
// Config validation helpers shared by CLI and core modules.

#include <stdio.h>
#include "wc/wc_config.h"

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
