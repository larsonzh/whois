#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "wc/wc_client_flow.h"
#include "wc/wc_client_runner.h"

/* Phase3-netglue map:
 * - Signals/exit: wc_signal_check_shutdown() already wraps should/handle paths;
 *   long-term target is runtime/signal facade owning init/teardown.
 * - DNS/backoff: wc_dns_* facade drives health/penalty (wc_backoff underneath);
 *   remaining references are types only, pending deeper downshift into net/dns.
 * - Connection/cache: wc_net_* and wc_cache_* touched via backoff/health logging;
 *   keep references noted for later relocation.
 */
#include "wc/wc_batch_strategy.h"
#include "wc/wc_client_exit.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"
#include "wc/wc_log.h"
#include "wc/wc_fold.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_pipeline.h"
#include "wc/wc_query_exec.h"
#include "wc/wc_runtime.h"
#include "wc/wc_selftest.h"
#include "wc/wc_signal.h"
#include "wc/wc_server.h"

static int wc_client_debug_enabled(const Config* config)
{
    return config && config->debug;
}

static int g_wc_batch_strategy_enabled = 0;
static wc_batch_strategy_registry_t g_wc_batch_strategy_registry;

static int wc_client_should_abort_due_to_signal(void)
{
    return wc_signal_check_shutdown();
}

static int wc_client_is_batch_strategy_enabled(void)
{
    return g_wc_batch_strategy_enabled;
}

static const char* wc_client_guess_query_rir_host(const char* query);

static int wc_client_batch_host_list_contains(const char* const* hosts,
        size_t count,
        const char* candidate)
{
    if (!candidate)
        return 1;
    for (size_t i = 0; i < count; ++i) {
        if (!hosts[i])
            continue;
        if (strcasecmp(hosts[i], candidate) == 0)
            return 1;
    }
    return 0;
}

static size_t wc_client_collect_batch_start_candidates(const char* server_host,
        const char* query,
        const char* out[],
        size_t capacity)
{
    if (!out || capacity == 0)
        return 0;
    size_t count = 0;
    const char* normalized_server = server_host ?
        wc_dns_normalize_batch_host(server_host) : NULL;
    if (normalized_server && *normalized_server && count < capacity)
        out[count++] = normalized_server;
    const char* guessed = wc_client_guess_query_rir_host(query);
    if (guessed && *guessed &&
        !wc_client_batch_host_list_contains(out, count, guessed) &&
        count < capacity) {
        out[count++] = guessed;
    }
    const char* iana = wc_server_default_batch_host();
    if (!wc_client_batch_host_list_contains(out, count, iana) &&
        count < capacity)
        out[count++] = iana;
    if (count == 0)
        out[count++] = iana;
    if (count > capacity)
        count = capacity;
    return count;
}

static const char* wc_client_pick_raw_batch_host(
        const wc_batch_context_t* ctx)
{
    if (!ctx)
        return NULL;
    if (ctx->candidates && ctx->candidate_count > 0 && ctx->candidates[0])
        return ctx->candidates[0];
    if (ctx->default_host)
        return ctx->default_host;
    return wc_server_default_batch_host();
}

static size_t wc_client_build_batch_health_hosts(const char* server_host,
        const char* extra_host,
        const char* out[],
        size_t capacity)
{
    size_t count = 0;
    if (!out || capacity == 0)
        return 0;
    const char* primary = wc_dns_normalize_batch_host(server_host);
    if (primary && *primary)
        out[count++] = primary;
    const char* normalized_extra = NULL;
    if (extra_host && *extra_host)
        normalized_extra = wc_dns_normalize_batch_host(extra_host);
    if (normalized_extra && *normalized_extra &&
        !wc_client_batch_host_list_contains(out, count, normalized_extra)) {
        out[count++] = normalized_extra;
    }
    const char* const* defaults = NULL;
    size_t defaults_count = wc_server_get_default_batch_hosts(&defaults);
    for (size_t i = 0; i < defaults_count; ++i) {
        if (count >= capacity)
            break;
        const char* candidate = defaults ? defaults[i] : NULL;
        if (!candidate)
            continue;
        if (wc_client_batch_host_list_contains(out, count, candidate))
            continue;
        out[count++] = candidate;
    }
    return count;
}

static void wc_client_apply_debug_batch_penalties_once(const Config* config)
{
    wc_dns_apply_debug_batch_penalties_once(config);
}

static void wc_client_log_batch_snapshot_entry(const char* host,
        const char* family_label,
        wc_dns_health_state_t state,
        const wc_dns_health_snapshot_t* snap)
{
    if (!host || !family_label || !snap)
        return;
    if (state == WC_DNS_HEALTH_OK && snap->consecutive_failures == 0)
        return;
    wc_log_dns_batch_snapshot_entry(host, family_label, state, snap);
}

static void wc_client_log_batch_host_health(const Config* config,
    const char* server_host,
    const char* start_host)
{
    if (!wc_client_debug_enabled(config))
        return;
    const char* hosts[16];
    wc_dns_host_health_t health[16];
    size_t host_count = wc_client_build_batch_health_hosts(server_host, start_host,
        hosts, 16);
    size_t produced = wc_dns_collect_host_health(config, hosts, host_count, health, 16);
    for (size_t i = 0; i < produced; ++i) {
        const wc_dns_host_health_t* entry = &health[i];
        wc_client_log_batch_snapshot_entry(entry->host, "ipv4",
            entry->ipv4_state, &entry->ipv4);
        wc_client_log_batch_snapshot_entry(entry->host, "ipv6",
            entry->ipv6_state, &entry->ipv6);
    }
}

static const char* wc_client_guess_query_rir_host(const char* query)
{
    if (!query || !*query)
        return NULL;
    const char* rir = wc_guess_rir(query);
    if (!rir || strcasecmp(rir, "unknown") == 0)
        return NULL;
    return wc_dns_canonical_host_for_rir(rir);
}

static void wc_client_penalize_batch_failure(const Config* config,
        const char* host,
        int lookup_rc,
        int errno_hint)
{
    if (!host || !*host)
        return;
    wc_dns_note_failure(config, host, AF_UNSPEC);
    if (!wc_client_debug_enabled(config))
        return;
    wc_log_dns_batch_query_fail(host, lookup_rc, errno_hint,
        wc_dns_penalty_window_ms());
}

static void wc_client_init_batch_strategy_system(const Config* config)
{
    g_wc_batch_strategy_enabled = 0;
    if (!config || !config->batch_strategy || !*config->batch_strategy)
        return;
    int boot_rc = wc_batch_strategy_registry_bootstrap(&g_wc_batch_strategy_registry,
        config->batch_strategy);
    g_wc_batch_strategy_enabled = 1;
    if (boot_rc < 0) {
        wc_log_dns_batchf(
            "[DNS-BATCH] action=unknown-strategy name=%s fallback=health-first\n",
            config->batch_strategy);
        wc_batch_strategy_registry_set_active_name(&g_wc_batch_strategy_registry,
            "health-first");
    }
}

static const char* wc_client_select_batch_start_host(const Config* config,
    const char* server_host,
    const char* query,
    wc_batch_context_builder_t* builder)
{
    const char* local_candidates[WC_BATCH_MAX_CANDIDATES];
    wc_dns_host_health_t local_health[WC_BATCH_MAX_CANDIDATES];
    wc_batch_context_t temp_ctx;
    memset(&temp_ctx, 0, sizeof(temp_ctx));

    if (builder)
        memset(builder, 0, sizeof(*builder));

    wc_batch_context_t* ctx = builder ? &builder->ctx : &temp_ctx;
    const char** candidates = builder
        ? builder->candidate_storage
        : local_candidates;
    wc_dns_host_health_t* health = builder
        ? builder->health_storage
        : local_health;

    ctx->server_host = server_host;
    ctx->query = query;
    ctx->default_host = wc_server_default_batch_host();
    ctx->candidates = candidates;
    ctx->health_entries = health;
    ctx->config = config;

    size_t candidate_count = wc_client_collect_batch_start_candidates(
        server_host, query, candidates, WC_BATCH_MAX_CANDIDATES);
    if (candidate_count == 0) {
        candidates[0] = wc_server_default_batch_host();
        candidate_count = 1;
    }
    ctx->candidate_count = candidate_count;

    size_t health_count = (size_t)wc_dns_collect_host_health(config,
        candidates, candidate_count, health, WC_BATCH_MAX_CANDIDATES);
    ctx->health_count = health_count;

    if (wc_client_is_batch_strategy_enabled()) {
        const char* picked = wc_batch_strategy_registry_pick(
            &g_wc_batch_strategy_registry, ctx);
        if (picked)
            return picked;
        if (ctx->candidate_count > 0)
            return ctx->candidates[ctx->candidate_count - 1];
    }
    return wc_client_pick_raw_batch_host(ctx);
}

static int wc_client_batch_entry_prepare(const Config* config)
{
    if (wc_client_debug_enabled(config))
        printf("[DEBUG] ===== BATCH STDIN MODE START =====\n");

    wc_client_apply_debug_batch_penalties_once(config);

    if (wc_client_should_abort_due_to_signal())
        return WC_EXIT_SIGINT;

    return 0;
}

static const char* wc_client_normalize_batch_line(char* linebuf)
{
    if (!linebuf)
        return NULL;
    char* p = linebuf;
    while (*p && (*p == ' ' || *p == '\t'))
        p++;
    char* start = p;
    size_t len = strlen(start);
    while (len > 0 && (start[len - 1] == '\n' ||
            start[len - 1] == '\r' || start[len - 1] == ' ' ||
            start[len - 1] == '\t')) {
        start[--len] = '\0';
    }
    if (len == 0)
        return NULL;
    if (start[0] == '#')
        return NULL;
    return start;
}

static int wc_client_handle_batch_query(const Config* cfg,
    const wc_client_render_opts_t* render_opts,
    const wc_selftest_injection_t* injection,
    const char* server_host,
    int port,
    wc_net_context_t* net_ctx,
    const char* query)
{
    wc_batch_context_builder_t ctx_builder;
    struct wc_result res;
    int rc = 0;
    const char* start_host =
        wc_client_select_batch_start_host(cfg, server_host, query, &ctx_builder);
    if (!start_host)
        start_host = server_host ? server_host : wc_server_default_batch_host();

    wc_client_log_batch_host_health(cfg, server_host, start_host);
    memset(&res, 0, sizeof(res));

    if (wc_query_exec_validate_ip_or_cidr(cfg, query)) {
        wc_runtime_housekeeping_tick();
        return 0;
    }

    rc = wc_execute_lookup(cfg, query, start_host, port, net_ctx, &res);

    if (!rc && res.body) {
        wc_pipeline_render(cfg, render_opts,
            query, start_host, &res, 1);
    } else {
        wc_client_penalize_batch_failure(cfg, start_host, rc,
            res.meta.last_connect_errno);
        wc_report_query_failure(cfg, query, start_host,
            res.meta.last_connect_errno, &res);
    }

    if (wc_client_is_batch_strategy_enabled()) {
        wc_batch_strategy_result_t strat_result = {
            .start_host = start_host,
            .authoritative_host = (res.meta.authoritative_host[0]
                ? res.meta.authoritative_host
                : NULL),
            .lookup_rc = rc,
        };
        wc_batch_strategy_registry_handle_result(
            &g_wc_batch_strategy_registry, &ctx_builder.ctx, &strat_result);
    }

    wc_lookup_result_free(&res);
    wc_runtime_housekeeping_tick();

    if (wc_client_should_abort_due_to_signal())
        rc = WC_EXIT_SIGINT;
    (void)injection; /* retained for symmetry with single-path helpers */
    return rc;
}

static int wc_client_prepare_mode(const wc_opts_t* opts,
    int argc,
    char* const* argv,
    const Config* config,
    int* batch_mode,
    const char** single_query,
    int* out_exit_code)
{
    if (!batch_mode || !single_query || !out_exit_code)
        return -1;
    *out_exit_code = 0;

    int meta_rc = wc_client_handle_meta_requests(opts, argv[0], config);
    if (meta_rc != 0) {
        *out_exit_code = (meta_rc > 0) ? WC_EXIT_SUCCESS : WC_EXIT_FAILURE;
        return -1;
    }

    if (wc_client_detect_mode_and_query(opts, argc, (char**)argv,
            batch_mode, single_query, config) != 0) {
        *out_exit_code = wc_client_handle_usage_error(argv[0], config);
        return -1;
    }

    return 0;
}

static int wc_client_dispatch_queries(const Config* config,
    const wc_opts_t* opts,
    const wc_client_render_opts_t* render_opts,
    int batch_mode,
    const char* single_query,
    wc_net_context_t* net_ctx)
{
    const char* server_host = opts->host;
    int port = opts->port;
    if (wc_client_should_abort_due_to_signal())
        return WC_EXIT_SIGINT;
    if (!batch_mode)
        return wc_client_run_single_query(config, render_opts, single_query, server_host, port, net_ctx);
    return wc_client_run_batch_stdin(config, render_opts, server_host, port, net_ctx);
}

int wc_client_run_batch_stdin(const Config* config,
        const wc_client_render_opts_t* render_opts_override,
        const char* server_host,
        int port,
        wc_net_context_t* net_ctx) {
    const Config* cfg = config;
    wc_client_render_opts_t render_opts_local =
        wc_client_render_opts_init(cfg);
    const wc_client_render_opts_t* render_opts =
        render_opts_override ? render_opts_override : &render_opts_local;

    int rc = wc_client_batch_entry_prepare(cfg);
    if (rc)
        return rc;

    wc_net_context_t* active_net_ctx = net_ctx;
    int resources_ready = active_net_ctx ? 1 : 0;
    // Prefer the active net context injection once initialized; fall back to
    // the shared view until runtime resources are ready.
    const wc_selftest_injection_t* injection =
        (active_net_ctx && active_net_ctx->injection)
            ? active_net_ctx->injection
            : wc_selftest_injection_view();

    char linebuf[512];
    rc = 0;
    while (!wc_client_should_abort_due_to_signal()) {
        if (!fgets(linebuf, sizeof(linebuf), stdin)) {
            if (wc_client_should_abort_due_to_signal())
                rc = WC_EXIT_SIGINT;
            break;
        }
        const char* query = wc_client_normalize_batch_line(linebuf);
        if (!query)
            continue;
        if (wc_handle_suspicious_query(query, 1, injection))
            continue;
        if (wc_handle_private_ip(cfg, query, query, 1, injection))
            continue;

        if (!resources_ready) {
            wc_runtime_init_resources(cfg);
            active_net_ctx = wc_net_context_get_active();
            if (active_net_ctx && active_net_ctx->injection)
                injection = active_net_ctx->injection;
            resources_ready = 1;
        }

        int step_rc = wc_client_handle_batch_query(cfg, render_opts,
            injection, server_host, port, active_net_ctx, query);
        if (step_rc == WC_EXIT_SIGINT) {
            rc = WC_EXIT_SIGINT;
            break;
        }
        if (cfg && cfg->batch_interval_ms > 0 && !wc_client_should_abort_due_to_signal()) {
            int delay_ms = cfg->batch_interval_ms;
            if (cfg->batch_jitter_ms > 0) {
                int jitter = rand() % (cfg->batch_jitter_ms + 1);
                delay_ms += jitter;
            }
            struct timespec ts;
            ts.tv_sec = (time_t)(delay_ms / 1000);
            ts.tv_nsec = (long)((delay_ms % 1000) * 1000000L);
            nanosleep(&ts, NULL);
        }
    }
    if (wc_client_should_abort_due_to_signal())
        rc = WC_EXIT_SIGINT;
    return rc;
}

int wc_client_run_with_mode(const wc_opts_t* opts,
        int argc,
        char* const* argv,
    const Config* config) {
    int batch_mode = 0;
    const char* single_query = NULL;
    int exit_code = 0;

    wc_client_render_opts_t render_opts =
        wc_client_render_opts_init(config);

    if (wc_client_prepare_mode(opts, argc, argv, config,
            &batch_mode, &single_query, &exit_code) != 0)
        return exit_code;

    wc_client_init_batch_strategy_system(config);
    wc_net_context_t* net_ctx = wc_runtime_get_net_context();

    return wc_client_dispatch_queries(config, opts, &render_opts, batch_mode,
        single_query, net_ctx);
}

int wc_client_handle_usage_error(const char* progname, const Config* cfg)
{
	return wc_client_exit_usage_error(progname, cfg);
}
