#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_client_flow.h"
#include "wc/wc_backoff.h"
#include "wc/wc_batch_strategy.h"
#include "wc/wc_client_exit.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"
#include "wc/wc_fold.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_query_exec.h"
#include "wc/wc_runtime.h"
#include "wc/wc_selftest.h"
#include "wc/wc_signal.h"
#include "wc/wc_server.h"
#include "wc/wc_util.h"

static int wc_client_debug_enabled(const Config* config)
{
    return config && config->debug;
}

static const char* const k_wc_batch_default_hosts[] = {
    "whois.iana.org",
    "whois.arin.net",
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.lacnic.net",
    "whois.afrinic.net",
    "whois.verisign-grs.com",
};

static int g_wc_batch_strategy_enabled = 0;
static wc_batch_strategy_registry_t g_wc_batch_strategy_registry;

static int wc_client_should_abort_due_to_signal(void)
{
    if (!wc_signal_should_terminate())
        return 0;
    wc_signal_handle_pending_shutdown();
    return 1;
}

static int wc_client_is_batch_strategy_enabled(void)
{
    return g_wc_batch_strategy_enabled;
}

static const char* wc_client_normalize_batch_host(const char* host)
{
    if (!host || !*host)
        return k_wc_batch_default_hosts[0];
    if (!wc_dns_is_ip_literal(host)) {
        const char* canon = wc_dns_canonical_host_for_rir(host);
        if (canon)
            return canon;
    }
    return host;
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
        wc_client_normalize_batch_host(server_host) : NULL;
    if (normalized_server && *normalized_server && count < capacity)
        out[count++] = normalized_server;
    const char* guessed = wc_client_guess_query_rir_host(query);
    if (guessed && *guessed &&
        !wc_client_batch_host_list_contains(out, count, guessed) &&
        count < capacity) {
        out[count++] = guessed;
    }
    const char* iana = k_wc_batch_default_hosts[0];
    if (!wc_client_batch_host_list_contains(out, count, iana) &&
        count < capacity)
        out[count++] = iana;
    if (count == 0)
        out[count++] = iana;
    if (count > capacity)
        count = capacity;
    return count;
}

static size_t wc_client_collect_candidate_health(const Config* config,
        const char* const* candidates,
        size_t candidate_count,
        wc_backoff_host_health_t* out,
        size_t capacity)
{
    if (!out || capacity == 0)
        return 0;
    size_t produced = 0;
    for (size_t i = 0; i < candidate_count && produced < capacity; ++i) {
        wc_backoff_get_host_health(config, candidates[i], &out[produced]);
        ++produced;
    }
    return produced;
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
    return k_wc_batch_default_hosts[0];
}

static size_t wc_client_build_batch_health_hosts(const char* server_host,
        const char* extra_host,
        const char* out[],
        size_t capacity)
{
    size_t count = 0;
    if (!out || capacity == 0)
        return 0;
    const char* primary = wc_client_normalize_batch_host(server_host);
    if (primary && *primary)
        out[count++] = primary;
    const char* normalized_extra = NULL;
    if (extra_host && *extra_host)
        normalized_extra = wc_client_normalize_batch_host(extra_host);
    if (normalized_extra && *normalized_extra &&
        !wc_client_batch_host_list_contains(out, count, normalized_extra)) {
        out[count++] = normalized_extra;
    }
    for (size_t i = 0; i < sizeof(k_wc_batch_default_hosts) / sizeof(k_wc_batch_default_hosts[0]); ++i) {
        if (count >= capacity)
            break;
        const char* candidate = k_wc_batch_default_hosts[i];
        if (!candidate)
            continue;
        if (wc_client_batch_host_list_contains(out, count, candidate))
            continue;
        out[count++] = candidate;
    }
    return count;
}

static char* wc_client_trim_token(char* token)
{
    if (!token)
        return NULL;
    while (*token && isspace((unsigned char)*token))
        ++token;
    char* end = token + strlen(token);
    while (end > token && isspace((unsigned char)*(end - 1)))
        *--end = '\0';
    return token;
}

static void wc_client_apply_debug_batch_penalties_once(const Config* config)
{
    const int debug = wc_client_debug_enabled(config);
    static int applied = 0;
    if (applied)
        return;
    applied = 1;
    const char* env = getenv("WHOIS_BATCH_DEBUG_PENALIZE");
    if (!env || !*env)
        return;
    char* list = wc_safe_strdup(env, __func__);
    char* cursor = list;
    while (cursor && *cursor) {
        char* next = strchr(cursor, ',');
        if (next)
            *next++ = '\0';
        char* token = wc_client_trim_token(cursor);
        if (token && *token) {
            const char* canon = wc_client_normalize_batch_host(token);
            if (canon && *canon) {
                /*
                 * Penalty window only kicks in after three consecutive failures
                 * (see wc_dns_health_note_result). Inject enough failures so
                 * WHOIS_BATCH_DEBUG_PENALIZE always marks the host as penalized.
                 */
                for (int i = 0; i < 3; ++i)
                    wc_backoff_note_failure(config, canon, AF_UNSPEC);
                if (debug) {
                    fprintf(stderr,
                        "[DNS-BATCH] action=debug-penalize host=%s source=WHOIS_BATCH_DEBUG_PENALIZE\n",
                        canon);
                }
            }
        }
        cursor = next;
        if (!cursor)
            break;
    }
    free(list);
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
    fprintf(stderr,
        "[DNS-BATCH] host=%s family=%s state=%s consec_fail=%d penalty_ms_left=%ld\n",
        host,
        family_label,
        (state == WC_DNS_HEALTH_PENALIZED) ? "penalized" : "ok",
        snap->consecutive_failures,
        (long)snap->penalty_ms_left);
}

static void wc_client_log_batch_host_health(const Config* config,
    const char* server_host,
    const char* start_host)
{
    if (!wc_client_debug_enabled(config))
        return;
    const char* hosts[16];
    wc_backoff_host_health_t health[16];
    size_t host_count = wc_client_build_batch_health_hosts(server_host, start_host,
        hosts, 16);
    size_t produced = wc_backoff_collect_host_health(config, hosts, host_count, health, 16);
    for (size_t i = 0; i < produced; ++i) {
        const wc_backoff_host_health_t* entry = &health[i];
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
    wc_backoff_note_failure(config, host, AF_UNSPEC);
    if (!wc_client_debug_enabled(config))
        return;
    fprintf(stderr,
        "[DNS-BATCH] action=query-fail host=%s lookup_rc=%d errno=%d penalty_ms=%ld\n",
        host,
        lookup_rc,
        errno_hint,
        wc_backoff_get_penalty_window_ms());
}

static void wc_client_init_batch_strategy_system(const Config* config)
{
    g_wc_batch_strategy_enabled = 0;
    if (!config || !config->batch_strategy || !*config->batch_strategy)
        return;
    wc_batch_strategy_registry_init(&g_wc_batch_strategy_registry);
    wc_batch_strategy_registry_register_builtins(&g_wc_batch_strategy_registry);
    g_wc_batch_strategy_enabled = 1;
    if (!wc_batch_strategy_registry_set_active_name(&g_wc_batch_strategy_registry,
            config->batch_strategy)) {
        fprintf(stderr,
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
    wc_backoff_host_health_t local_health[WC_BATCH_MAX_CANDIDATES];
    wc_batch_context_t temp_ctx;
    memset(&temp_ctx, 0, sizeof(temp_ctx));

    if (builder)
        memset(builder, 0, sizeof(*builder));

    wc_batch_context_t* ctx = builder ? &builder->ctx : &temp_ctx;
    const char** candidates = builder
        ? builder->candidate_storage
        : local_candidates;
    wc_backoff_host_health_t* health = builder
        ? builder->health_storage
        : local_health;

    ctx->server_host = server_host;
    ctx->query = query;
    ctx->default_host = k_wc_batch_default_hosts[0];
    ctx->candidates = candidates;
    ctx->health_entries = health;
    ctx->config = config;

    size_t candidate_count = wc_client_collect_batch_start_candidates(
        server_host, query, candidates, WC_BATCH_MAX_CANDIDATES);
    if (candidate_count == 0) {
        candidates[0] = k_wc_batch_default_hosts[0];
        candidate_count = 1;
    }
    ctx->candidate_count = candidate_count;

    size_t health_count = wc_client_collect_candidate_health(config,
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

int wc_client_run_batch_stdin(const Config* config,
        const char* server_host,
        int port,
        wc_net_context_t* net_ctx) {
    const Config* cfg = config;
    int debug = cfg && cfg->debug;
    int fold_output = cfg && cfg->fold_output;
    int plain_mode = cfg && cfg->plain_mode;
    const char* fold_sep = (cfg && cfg->fold_sep) ? cfg->fold_sep : " ";
    int fold_upper = cfg ? cfg->fold_upper : 0;

    if (debug)
        printf("[DEBUG] ===== BATCH STDIN MODE START =====\n");

    wc_client_apply_debug_batch_penalties_once(cfg);

    // Use the injection baseline already bound to the active net context; avoid
    // reaching back into global selftest state for batch mode.
    const wc_selftest_injection_t* injection =
        net_ctx ? net_ctx->injection : NULL;

    char linebuf[512];
    int rc = 0;
    while (!wc_client_should_abort_due_to_signal()) {
        if (!fgets(linebuf, sizeof(linebuf), stdin)) {
            if (wc_client_should_abort_due_to_signal())
                rc = WC_EXIT_SIGINT;
            break;
        }
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
            continue;
        if (start[0] == '#')
            continue;

        const char* query = start;
        if (wc_handle_suspicious_query(query, 1, injection))
            continue;
        if (wc_handle_private_ip(cfg, query, query, 1, injection))
            continue;

        wc_batch_context_builder_t ctx_builder;
        const char* start_host =
            wc_client_select_batch_start_host(cfg, server_host, query, &ctx_builder);
        if (!start_host)
            start_host = server_host ? server_host : k_wc_batch_default_hosts[0];

        wc_client_log_batch_host_health(cfg, server_host, start_host);

        struct wc_result res;
        int lrc = wc_execute_lookup(cfg, query, start_host, port, net_ctx, &res);

        if (!lrc && res.body) {
            char* result = res.body;
            res.body = NULL;
            if (debug)
                fprintf(stderr,
                    "[TRACE][batch] after header; body_ptr=%p len=%zu (stage=initial)\n",
                    (void*)result, res.body_len);
            if (!fold_output && !plain_mode) {
                const char* via_host = res.meta.via_host[0]
                    ? res.meta.via_host
                    : (start_host ? start_host : "whois.iana.org");
                const char* via_ip = res.meta.via_ip[0]
                    ? res.meta.via_ip
                    : NULL;
                if (via_ip)
                    wc_output_header_via_ip(query, via_host, via_ip);
                else
                    wc_output_header_via_unknown(query, via_host);
                /* Ensure header line is fully flushed before debug traces on stderr. */
                fflush(stdout);
            }
            char* filtered = wc_apply_response_filters(cfg, query, result, 1);
            free(result);
            result = filtered;

            char* authoritative_display_owned = NULL;
            const char* authoritative_display =
                (res.meta.authoritative_host[0]
                    ? res.meta.authoritative_host
                    : NULL);
            if (authoritative_display &&
                    wc_dns_is_ip_literal(authoritative_display)) {
                char* mapped =
                    wc_dns_rir_fallback_from_ip(cfg, authoritative_display);
                if (mapped) {
                    authoritative_display_owned = mapped;
                    authoritative_display = mapped;
                }
            }

            if (fold_output) {
                const char* rirv =
                    (authoritative_display && *authoritative_display)
                        ? authoritative_display
                        : "unknown";
                char* folded = wc_fold_build_line(
                    result, query, rirv,
                    fold_sep,
                    fold_upper);
                printf("%s", folded);
                free(folded);
            } else {
                printf("%s", result);
                if (!plain_mode) {
                    if (authoritative_display && *authoritative_display) {
                        const char* auth_ip =
                            (res.meta.authoritative_ip[0]
                                ? res.meta.authoritative_ip
                                : "unknown");
                        wc_output_tail_authoritative_ip(
                            authoritative_display, auth_ip);
                    } else {
                        wc_output_tail_unknown_unknown();
                    }
                }
            }
            if (authoritative_display_owned)
                free(authoritative_display_owned);
            free(result);
        } else {
            wc_client_penalize_batch_failure(cfg, start_host, lrc,
                res.meta.last_connect_errno);
            wc_report_query_failure(cfg, query, start_host,
                res.meta.last_connect_errno);
        }

        if (wc_client_is_batch_strategy_enabled()) {
            wc_batch_strategy_result_t strat_result = {
                .start_host = start_host,
                .authoritative_host = (res.meta.authoritative_host[0]
                    ? res.meta.authoritative_host
                    : NULL),
                .lookup_rc = lrc,
            };
            wc_batch_strategy_registry_handle_result(
                &g_wc_batch_strategy_registry, &ctx_builder.ctx, &strat_result);
        }
        wc_lookup_result_free(&res);
        wc_runtime_housekeeping_tick();
        if (wc_client_should_abort_due_to_signal()) {
            rc = WC_EXIT_SIGINT;
            break;
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

    int meta_rc = wc_client_handle_meta_requests(opts, argv[0], config);
    if (meta_rc != 0) {
        return (meta_rc > 0) ? WC_EXIT_SUCCESS : WC_EXIT_FAILURE;
    }

    if (wc_client_detect_mode_and_query(opts, argc, (char**)argv,
            &batch_mode, &single_query, config) != 0) {
        return wc_client_handle_usage_error(argv[0], config);
    }

    wc_runtime_init_resources(config);
    wc_client_init_batch_strategy_system(config);
    wc_net_context_t* net_ctx = wc_net_context_get_active();

    const char* server_host = opts->host;
    int port = opts->port;
    if (wc_client_should_abort_due_to_signal())
        return WC_EXIT_SIGINT;
    if (!batch_mode) {
        return wc_client_run_single_query(config, single_query, server_host, port, net_ctx);
    }
    return wc_client_run_batch_stdin(config, server_host, port, net_ctx);
}

int wc_client_handle_usage_error(const char* progname, const Config* cfg)
{
	return wc_client_exit_usage_error(progname, cfg);
}
