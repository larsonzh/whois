// Runtime init/atexit glue shared by client entry and core.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "wc/wc_runtime.h"
#include "wc/wc_opts.h"
#include "wc/wc_config.h"
#include "wc/wc_signal.h"
#include "wc/wc_cache.h"
#include "wc/wc_dns.h"
#include "wc/wc_title.h"
#include "wc/wc_grep.h"
#include "wc/wc_output.h"
#include "wc/wc_fold.h"
#include "wc/wc_seclog.h"
#include "wc/wc_util.h"
#include "wc/wc_debug.h"

static void free_fold_resources(void);
static void wc_runtime_register_default_housekeeping(void);

static int g_dns_cache_stats_enabled = 0;
static int g_housekeeping_hooks_registered = 0;

typedef struct {
	wc_runtime_housekeeping_cb cb;
	unsigned int flags;
} wc_runtime_hook_entry_t;

#define WC_RUNTIME_MAX_HOOKS 8

static wc_runtime_hook_entry_t g_housekeeping_hooks[WC_RUNTIME_MAX_HOOKS];
static size_t g_housekeeping_hook_count = 0;

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
	wc_cache_dns_stats_t dns_stats = {0};
	wc_cache_neg_stats_t neg_stats = {0};
	wc_cache_get_dns_stats(&dns_stats);
	wc_cache_get_negative_stats(&neg_stats);
	fprintf(stderr,
		"[DNS-CACHE-LGCY-SUM] hits=%ld misses=%ld shim_hits=%ld neg_hits=%d neg_shim_hits=%d\n",
		dns_stats.hits,
		dns_stats.misses,
		dns_stats.shim_hits,
		neg_stats.hits,
		neg_stats.shim_hits);
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
	wc_cache_log_statistics();
	atexit(wc_cache_cleanup);
	atexit(wc_title_free);
	atexit(wc_grep_free);
	atexit(free_fold_resources);
	wc_runtime_register_default_housekeeping();
	if (g_config.debug)
		printf("[DEBUG] Caches initialized successfully\n");
}

void wc_runtime_apply_post_config(Config* config) {
	if (!config) return;
	wc_fold_set_unique(config->fold_unique);
	if (!config->fold_sep)
		config->fold_sep = wc_safe_strdup(" ", "fold_sep_default");
	wc_seclog_set_enabled(config->security_logging);
}

void wc_runtime_register_housekeeping_callback(wc_runtime_housekeeping_cb cb,
		unsigned int flags)
{
	if (!cb)
		return;
	for (size_t i = 0; i < g_housekeeping_hook_count; ++i) {
		if (g_housekeeping_hooks[i].cb == cb)
			return;
	}
	if (g_housekeeping_hook_count >= WC_RUNTIME_MAX_HOOKS) {
		wc_output_log_message("WARN",
			"Housekeeping hook limit (%d) reached; ignoring registration",
			WC_RUNTIME_MAX_HOOKS);
		return;
	}
	g_housekeeping_hooks[g_housekeeping_hook_count].cb = cb;
	g_housekeeping_hooks[g_housekeeping_hook_count].flags = flags;
	++g_housekeeping_hook_count;
}

void wc_runtime_housekeeping_tick(void)
{
	for (size_t i = 0; i < g_housekeeping_hook_count; ++i) {
		wc_runtime_housekeeping_cb cb = g_housekeeping_hooks[i].cb;
		unsigned int flags = g_housekeeping_hooks[i].flags;
		if (!cb)
			continue;
		if ((flags & WC_RUNTIME_HOOK_FLAG_DEBUG_ONLY) &&
		    !wc_is_debug_enabled())
			continue;
		cb();
	}
}

static void wc_runtime_register_default_housekeeping(void)
{
	if (g_housekeeping_hooks_registered)
		return;
	g_housekeeping_hooks_registered = 1;
	wc_runtime_register_housekeeping_callback(wc_cache_cleanup_expired_entries,
		WC_RUNTIME_HOOK_FLAG_NONE);
	wc_runtime_register_housekeeping_callback(wc_cache_validate_integrity,
		WC_RUNTIME_HOOK_FLAG_DEBUG_ONLY);
}
