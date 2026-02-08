// Runtime init/atexit glue shared by client entry and core.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

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
#include "wc/wc_net.h"
#include "wc/wc_selftest.h"

// Forward declaration to inject Config into signal module once available.
void wc_signal_set_config(const Config* config);

static Config g_runtime_config;
static int g_runtime_config_valid = 0;
static Config g_runtime_config_stack[4];
static int g_runtime_config_valid_stack[4];
static int g_runtime_config_depth = 0;
static int g_dns_cache_summary_emitted = 0;
static int g_cache_counter_sampling_enabled = 0;

static void free_fold_resources(void);
static void wc_runtime_register_default_housekeeping(void);
static void wc_runtime_refresh_cfg_view(const Config* cfg);
static void wc_runtime_purge_cache_connections(void);
static void wc_runtime_emit_cache_stats_once(void);

static int g_dns_cache_stats_enabled = 0;
static int g_housekeeping_hooks_registered = 0;
static int g_net_ctx_initialized = 0;
static int g_runtime_exit_flushed = 0;
static int g_runtime_resources_initialized = 0;
static wc_net_context_t g_runtime_net_ctx;
#ifdef _WIN32
static int g_wsa_started = 0;
static void wc_runtime_win32_wsa_cleanup(void) {
	if (!g_wsa_started)
		return;
	WSACleanup();
	g_wsa_started = 0;
}
#endif

typedef struct {
	wc_runtime_housekeeping_cb cb;
	unsigned int flags;
} wc_runtime_hook_entry_t;

#define WC_RUNTIME_MAX_HOOKS 8

static wc_runtime_hook_entry_t g_housekeeping_hooks[WC_RUNTIME_MAX_HOOKS];
static size_t g_housekeeping_hook_count = 0;

typedef struct {
	int debug;
	int pacing_disable;
	int pacing_interval_ms;
	int pacing_jitter_ms;
	int pacing_backoff_factor;
	int pacing_max_ms;
	int retry_all_addrs;
	int retry_metrics;
	int max_host_addrs;
	int fold_unique;
	const char* fold_sep;
} wc_runtime_cfg_view_t;

typedef struct {
	int dns_retry;
	int dns_retry_interval_ms;
	int dns_max_candidates;
	int dns_addrconfig;
	int dns_family_mode;
	int dns_family_mode_first;
	int dns_family_mode_next;
	int dns_family_mode_first_set;
	int dns_family_mode_next_set;
	int prefer_ipv4;
	int prefer_ipv6;
	int ip_pref_mode;
} wc_runtime_dns_view_t;

static wc_runtime_cfg_view_t g_runtime_cfg_view = {0};
static wc_runtime_dns_view_t g_runtime_dns_view = {0};
static wc_net_probe_result_t g_runtime_net_probe = {0, 0, 0, 0};
static int g_runtime_net_probe_notice_emitted = 0;

static int wc_runtime_is_debug_enabled(void)
{
	return g_runtime_cfg_view.debug;
}

wc_net_context_t* wc_runtime_get_net_context(void)
{
	return g_net_ctx_initialized ? &g_runtime_net_ctx : NULL;
}

// Local helper to free fold-related resources (currently only fold_sep),
// mirroring the behavior previously implemented in whois_client.c.
static void free_fold_resources(void) {
	if (!g_runtime_config_valid)
		return;
	Config* cfg = &g_runtime_config;
	if (cfg->fold_sep) {
		free((void*)cfg->fold_sep);
		cfg->fold_sep = NULL;
	}
}

static void wc_runtime_refresh_cfg_view(const Config* cfg)
{
	if (!cfg) {
		memset(&g_runtime_cfg_view, 0, sizeof(g_runtime_cfg_view));
		memset(&g_runtime_dns_view, 0, sizeof(g_runtime_dns_view));
		wc_output_set_debug_enabled(0);
		return;
	}
	g_runtime_cfg_view.debug = cfg->debug;
	g_runtime_cfg_view.pacing_disable = cfg->pacing_disable;
	g_runtime_cfg_view.pacing_interval_ms = cfg->pacing_interval_ms;
	g_runtime_cfg_view.pacing_jitter_ms = cfg->pacing_jitter_ms;
	g_runtime_cfg_view.pacing_backoff_factor = cfg->pacing_backoff_factor;
	g_runtime_cfg_view.pacing_max_ms = cfg->pacing_max_ms;
	g_runtime_cfg_view.retry_all_addrs = cfg->retry_all_addrs;
	g_runtime_cfg_view.retry_metrics = cfg->retry_metrics;
	g_runtime_cfg_view.max_host_addrs = cfg->max_host_addrs;
	g_runtime_cfg_view.fold_unique = cfg->fold_unique;
	g_runtime_cfg_view.fold_sep = cfg->fold_sep;

	g_runtime_dns_view.dns_retry = cfg->dns_retry;
	g_runtime_dns_view.dns_retry_interval_ms = cfg->dns_retry_interval_ms;
	g_runtime_dns_view.dns_max_candidates = cfg->dns_max_candidates;
	g_runtime_dns_view.dns_addrconfig = cfg->dns_addrconfig;
	g_runtime_dns_view.dns_family_mode = cfg->dns_family_mode;
	g_runtime_dns_view.dns_family_mode_first = cfg->dns_family_mode_first;
	g_runtime_dns_view.dns_family_mode_next = cfg->dns_family_mode_next;
	g_runtime_dns_view.dns_family_mode_first_set = cfg->dns_family_mode_first_set;
	g_runtime_dns_view.dns_family_mode_next_set = cfg->dns_family_mode_next_set;
	g_runtime_dns_view.prefer_ipv4 = cfg->prefer_ipv4;
	g_runtime_dns_view.prefer_ipv6 = cfg->prefer_ipv6;
	g_runtime_dns_view.ip_pref_mode = cfg->ip_pref_mode;

	wc_output_set_debug_enabled(cfg->debug);
}

static void wc_runtime_log_probe_debug(const wc_net_probe_result_t* probe)
{
	if (!probe || !g_runtime_cfg_view.debug)
		return;
	fprintf(stderr, "[NET-PROBE] ipv4=%s ipv6=%s ipv6_global=%s\n",
		(probe->ipv4_ok ? "ok" : "fail"),
		(probe->ipv6_ok ? "ok" : "fail"),
		(probe->ipv6_global_ok ? "ok" : "fail"));
}

static void wc_runtime_log_probe_notice(const char* msg)
{
	if (g_runtime_net_probe_notice_emitted)
		return;
	g_runtime_net_probe_notice_emitted = 1;
	if (msg)
		fprintf(stderr, "%s\n", msg);
}

static void wc_runtime_apply_family_probe(Config* cfg)
{
	if (!cfg)
		return;
	wc_net_probe_result_t probe = {0};
	if (wc_net_probe_families(&probe) != 0)
		return;
	g_runtime_net_probe = probe;
	wc_runtime_log_probe_debug(&probe);

	if (!probe.ipv4_ok && !probe.ipv6_ok) {
		fprintf(stderr, "[NET-PROBE] fatal: no ip family available (ipv4=fail ipv6=fail)\n");
		exit(1);
	}

	if (probe.ipv4_ok && probe.ipv6_ok) {
		// Dual stack available: default to prefer-ipv4-ipv6 with mixed family ordering
		// when user did not force only or explicitly flip preferences.
		if (!cfg->ipv4_only && !cfg->ipv6_only && !cfg->prefer_ipv4 && !cfg->prefer_ipv6) {
			cfg->prefer_ipv4 = 1;
			cfg->prefer_ipv6 = 0;
			cfg->ip_pref_mode = WC_IP_PREF_MODE_V4_THEN_V6;
			if (!cfg->dns_family_mode_first_set) {
				cfg->dns_family_mode_first = WC_DNS_FAMILY_MODE_INTERLEAVE_V4_FIRST;
			}
			if (!cfg->dns_family_mode_next_set) {
				cfg->dns_family_mode_next = WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4;
			}
			if (!cfg->dns_family_mode_set) {
				cfg->dns_family_mode = WC_DNS_FAMILY_MODE_SEQUENTIAL_V4_THEN_V6;
			}
		}
		return;
	}

	if (probe.ipv4_ok && !probe.ipv6_ok) {
		int had_v6_pref = cfg->ipv6_only || cfg->prefer_ipv6 || cfg->ip_pref_mode == WC_IP_PREF_MODE_FORCE_V6_FIRST || cfg->ip_pref_mode == WC_IP_PREF_MODE_V6_THEN_V4 || cfg->dns_family_mode == WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST || cfg->dns_family_mode == WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4;
		cfg->ipv4_only = 1;
		cfg->ipv6_only = 0;
		cfg->prefer_ipv4 = 1;
		cfg->prefer_ipv6 = 0;
		cfg->ip_pref_mode = WC_IP_PREF_MODE_FORCE_V4_FIRST;
		cfg->dns_family_mode = WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK;
		cfg->dns_family_mode_first = WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK;
		cfg->dns_family_mode_next = WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK;
		cfg->dns_family_mode_first_set = 1;
		cfg->dns_family_mode_next_set = 1;
		cfg->dns_family_mode_set = 1;
		if (had_v6_pref)
			wc_runtime_log_probe_notice("[NET-PROBE] notice: ipv6 unavailable, ignoring prefer-ipv6/ipv6-only");
		return;
	}

	if (!probe.ipv4_ok && probe.ipv6_ok) {
		int had_v4_pref = cfg->ipv4_only || cfg->prefer_ipv4 || cfg->ip_pref_mode == WC_IP_PREF_MODE_FORCE_V4_FIRST || cfg->ip_pref_mode == WC_IP_PREF_MODE_V4_THEN_V6 || cfg->dns_family_mode == WC_DNS_FAMILY_MODE_INTERLEAVE_V4_FIRST || cfg->dns_family_mode == WC_DNS_FAMILY_MODE_SEQUENTIAL_V4_THEN_V6;
		cfg->ipv4_only = 0;
		cfg->ipv6_only = 1;
		cfg->prefer_ipv4 = 0;
		cfg->prefer_ipv6 = 1;
		cfg->ip_pref_mode = WC_IP_PREF_MODE_FORCE_V6_FIRST;
		cfg->dns_family_mode = WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
		cfg->dns_family_mode_first = WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
		cfg->dns_family_mode_next = WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
		cfg->dns_family_mode_first_set = 1;
		cfg->dns_family_mode_next_set = 1;
		cfg->dns_family_mode_set = 1;
		if (had_v4_pref)
			wc_runtime_log_probe_notice("[NET-PROBE] notice: ipv4 unavailable, ignoring prefer-ipv4/ipv4-only");
		return;
	}
}

static void wc_runtime_emit_dns_cache_summary_internal(void)
{
	if (!g_dns_cache_stats_enabled || g_dns_cache_summary_emitted)
		return;
	wc_dns_cache_stats_t stats;
	if (wc_dns_get_cache_stats(&stats) == 0) {
		fprintf(stderr,
			"[DNS-CACHE-SUM] hits=%ld neg_hits=%ld misses=%ld\n",
			stats.hits, stats.negative_hits, stats.misses);
		g_dns_cache_summary_emitted = 1;
	}
}

static void wc_runtime_shutdown_net_context(void)
{
	if (!g_net_ctx_initialized)
		return;
	wc_net_context_shutdown(&g_runtime_net_ctx);
	g_net_ctx_initialized = 0;
}

static void wc_runtime_init_net_context(void)
{
	if (g_net_ctx_initialized)
		return;
	wc_net_context_config_t cfg;
	wc_net_context_config_init(&cfg);
	if (g_runtime_cfg_view.pacing_disable >= 0)
		cfg.pacing_disable = g_runtime_cfg_view.pacing_disable ? 1 : 0;
	if (g_runtime_cfg_view.pacing_interval_ms >= 0)
		cfg.pacing_interval_ms = g_runtime_cfg_view.pacing_interval_ms;
	if (g_runtime_cfg_view.pacing_jitter_ms >= 0)
		cfg.pacing_jitter_ms = g_runtime_cfg_view.pacing_jitter_ms;
	if (g_runtime_cfg_view.pacing_backoff_factor >= 0)
		cfg.pacing_backoff_factor = g_runtime_cfg_view.pacing_backoff_factor;
	if (g_runtime_cfg_view.pacing_max_ms >= 0)
		cfg.pacing_max_ms = g_runtime_cfg_view.pacing_max_ms;
	cfg.retry_scope_all_addrs = g_runtime_cfg_view.retry_all_addrs ? 1 : 0;
	cfg.retry_metrics_enabled = g_runtime_cfg_view.retry_metrics ? 1 : 0;
	cfg.max_host_addrs = g_runtime_cfg_view.max_host_addrs;
	cfg.config = g_runtime_config_valid ? &g_runtime_config : NULL;
	cfg.injection = wc_selftest_injection_view();
	if (wc_net_context_init(&g_runtime_net_ctx, &cfg) != 0) {
		fprintf(stderr, "[WARN] Failed to initialize network context; using built-in defaults\n");
		return;
	}
	wc_net_context_set_active(&g_runtime_net_ctx);
	g_net_ctx_initialized = 1;
	if (wc_net_register_flush_hook())
		atexit(wc_net_flush_registered_contexts);
	atexit(wc_runtime_shutdown_net_context);
}

void wc_runtime_init(const wc_opts_t* opts) {
	// Seed RNG for retry jitter if used
	srand((unsigned)time(NULL));

#ifdef _WIN32
	{
		WSADATA wsa_data;
		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
			fprintf(stderr, "[WARN] WSAStartup failed; winsock may be unavailable\n");
		} else {
			g_wsa_started = 1;
			atexit(wc_runtime_win32_wsa_cleanup);
		}
	}
#endif

	// Set up signal handlers for graceful shutdown
	wc_signal_setup_handlers();
	atexit(wc_signal_atexit_cleanup);

	// Process-level DNS cache summary flag; printed once at exit
	if (opts) {
		wc_runtime_set_cache_counter_sampling(opts->cache_counter_sampling);
		g_dns_cache_stats_enabled = opts->dns_cache_stats;
		if (g_dns_cache_stats_enabled)
			atexit(wc_runtime_emit_dns_cache_summary_internal);
	}
}

void wc_runtime_init_resources(const Config* config) {
	if (g_runtime_resources_initialized)
		return;
	int sampling_enabled = g_cache_counter_sampling_enabled;
	if (config && config->cache_counter_sampling)
		sampling_enabled = 1;
	wc_runtime_set_cache_counter_sampling(sampling_enabled);

	g_runtime_config_valid = 0;
	if (config) {
		g_runtime_config = *config;
		g_runtime_config_valid = 1;
	}
	wc_runtime_refresh_cfg_view(config);
	wc_runtime_apply_family_probe(&g_runtime_config);
	wc_runtime_refresh_cfg_view(&g_runtime_config);
	if (config && config->debug)
		printf("[DEBUG] Initializing runtime resources with final configuration...\n");
	wc_signal_set_config(config);
	wc_runtime_init_net_context();
	wc_cache_log_statistics(wc_runtime_cache_counter_sampling_enabled());
	if (config && config->retry_metrics &&
	    !wc_runtime_cache_counter_sampling_enabled()) {
		static int cache_stats_exit_registered = 0;
		if (!cache_stats_exit_registered) {
			cache_stats_exit_registered = 1;
			atexit(wc_runtime_emit_cache_stats_once);
		}
	}
	atexit(wc_cache_cleanup);
	atexit(wc_dns_cache_cleanup);
	atexit(wc_title_free);
	atexit(wc_grep_free);
	atexit(free_fold_resources);
	if (config && config->debug)
		printf("[DEBUG] Runtime resources initialized successfully\n");
	g_runtime_resources_initialized = 1;
}

void wc_runtime_apply_post_config(Config* config) {
	if (!config) return;
	wc_fold_set_unique(config->fold_unique);
	wc_seclog_set_enabled(config->security_logging);
}

void wc_runtime_emit_dns_cache_summary(void)
{
	wc_runtime_emit_dns_cache_summary_internal();
}

void wc_runtime_exit_flush(void)
{
	if (g_runtime_exit_flushed)
		return;
	g_runtime_exit_flushed = 1;
	// Ensure pending shutdown logic runs even on normal exit.
	wc_signal_handle_pending_shutdown();
	// Emit DNS cache summary once (guarded inside).
	wc_runtime_emit_dns_cache_summary_internal();
	// Flush any registered net contexts (idempotent, guarded internally).
	wc_net_flush_registered_contexts();
	// Keep legacy cleanup side effects (active connection closure, neg stats).
	wc_signal_atexit_cleanup();
}

void wc_runtime_set_cache_counter_sampling(int enabled)
{
	g_cache_counter_sampling_enabled = enabled ? 1 : 0;
}

int wc_runtime_cache_counter_sampling_enabled(void)
{
	return g_cache_counter_sampling_enabled;
}

void wc_runtime_sample_cache_counters(void)
{
	if (!g_cache_counter_sampling_enabled)
		return;
	wc_cache_log_statistics(1);
}

void wc_runtime_snapshot_config(Config* out)
{
	if (!out)
		return;
	if (g_runtime_config_valid) {
		*out = g_runtime_config;
	} else {
		memset(out, 0, sizeof(*out));
	}
}

int wc_runtime_push_config(const Config* cfg)
{
	if (!cfg)
		return -1;
	if (g_runtime_config_depth >= (int)(sizeof(g_runtime_config_stack) / sizeof(g_runtime_config_stack[0])))
		return -1;
	g_runtime_config_valid_stack[g_runtime_config_depth] = g_runtime_config_valid;
	if (g_runtime_config_valid)
		g_runtime_config_stack[g_runtime_config_depth] = g_runtime_config;
	else
		memset(&g_runtime_config_stack[g_runtime_config_depth], 0, sizeof(Config));
	++g_runtime_config_depth;
	g_runtime_config = *cfg;
	g_runtime_config_valid = 1;
	wc_runtime_refresh_cfg_view(cfg);
	wc_signal_set_config(cfg);
	return 0;
}

void wc_runtime_pop_config(void)
{
	if (g_runtime_config_depth <= 0)
		return;
	--g_runtime_config_depth;
	g_runtime_config_valid = g_runtime_config_valid_stack[g_runtime_config_depth];
	if (g_runtime_config_valid)
		g_runtime_config = g_runtime_config_stack[g_runtime_config_depth];
	else
		memset(&g_runtime_config, 0, sizeof(g_runtime_config));
	if (g_runtime_config_valid)
		wc_runtime_refresh_cfg_view(&g_runtime_config);
	else
		wc_runtime_refresh_cfg_view(NULL);
	wc_signal_set_config(g_runtime_config_valid ? &g_runtime_config : NULL);
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
	if (!g_housekeeping_hooks_registered)
		wc_runtime_register_default_housekeeping();
	for (size_t i = 0; i < g_housekeeping_hook_count; ++i) {
		wc_runtime_housekeeping_cb cb = g_housekeeping_hooks[i].cb;
		unsigned int flags = g_housekeeping_hooks[i].flags;
		if (!cb)
			continue;
		if ((flags & WC_RUNTIME_HOOK_FLAG_DEBUG_ONLY) &&
		    !wc_runtime_is_debug_enabled())
			continue;
		cb();
	}
}

static void wc_runtime_register_default_housekeeping(void)
{
	if (g_housekeeping_hooks_registered)
		return;
	g_housekeeping_hooks_registered = 1;
	wc_runtime_register_housekeeping_callback(wc_runtime_purge_cache_connections,
		WC_RUNTIME_HOOK_FLAG_NONE);
	wc_runtime_register_housekeeping_callback(wc_cache_validate_integrity,
		WC_RUNTIME_HOOK_FLAG_DEBUG_ONLY);
	wc_runtime_register_housekeeping_callback(wc_runtime_sample_cache_counters,
		WC_RUNTIME_HOOK_FLAG_NONE);
}

static void wc_runtime_purge_cache_connections(void)
{
	const Config* cfg = g_runtime_config_valid ? &g_runtime_config : NULL;
	wc_cache_purge_expired_connections(cfg);
}

static void wc_runtime_emit_cache_stats_once(void)
{
	int prev_sampling = wc_runtime_cache_counter_sampling_enabled();
	if (!prev_sampling)
		wc_runtime_set_cache_counter_sampling(1);
	wc_cache_log_statistics(1);
	if (!prev_sampling)
		wc_runtime_set_cache_counter_sampling(0);
}
