// Runtime init/atexit glue shared by client entry and core.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "wc/wc_opts.h"
#include "wc/wc_config.h"
#include "wc/wc_signal.h"
#include "wc/wc_cache.h"
#include "wc/wc_dns.h"
#include "wc/wc_title.h"
#include "wc/wc_grep.h"
#include "wc/wc_output.h"

static void free_fold_resources(void);

static int g_dns_cache_stats_enabled = 0;

// Local helper to free fold-related resources (currently only fold_sep),
// mirroring the behavior previously implemented in whois_client.c.
static void free_fold_resources(void) {
	extern Config g_config;
	if (g_config.fold_sep) {
		free(g_config.fold_sep);
		g_config.fold_sep = NULL;
	}
}

static void wc_print_dns_cache_summary_at_exit(void) {
	if (!g_dns_cache_stats_enabled) return;
	wc_dns_cache_stats_t stats;
	if (wc_dns_get_cache_stats(&stats) == 0) {
		fprintf(stderr,
			"[DNS-CACHE-SUM] hits=%ld neg_hits=%ld misses=%ld\n",
			stats.hits, stats.negative_hits, stats.misses);
	}
}

static void wc_print_legacy_dns_cache_summary_at_exit(void) {
	if (!g_dns_cache_stats_enabled) return;
	wc_cache_dns_stats_t stats = {0};
	wc_cache_get_dns_stats(&stats);
	fprintf(stderr,
		"[DNS-CACHE-LGCY-SUM] hits=%ld misses=%ld\n",
		stats.hits,
		stats.misses);
}

void wc_runtime_init(const wc_opts_t* opts) {
	// Seed RNG for retry jitter if used
	srand((unsigned)time(NULL));

	// Set up signal handlers for graceful shutdown
	wc_signal_setup_handlers();
	atexit(wc_signal_atexit_cleanup);

	// Process-level DNS cache summary flag; printed once at exit
	if (opts) {
		g_dns_cache_stats_enabled = opts->dns_cache_stats;
		if (g_dns_cache_stats_enabled) {
			atexit(wc_print_dns_cache_summary_at_exit);
			atexit(wc_print_legacy_dns_cache_summary_at_exit);
		}
	}
}

void wc_runtime_init_resources(void) {
	extern Config g_config;
	if (g_config.debug)
		printf("[DEBUG] Initializing caches with final configuration...\n");
	wc_cache_init();
	atexit(wc_cache_cleanup);
	atexit(wc_title_free);
	atexit(wc_grep_free);
	atexit(free_fold_resources);
	if (g_config.debug)
		printf("[DEBUG] Caches initialized successfully\n");
}
