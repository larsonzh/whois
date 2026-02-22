// SPDX-License-Identifier: MIT
// lookup_exec_loop.c - Phase B execution flow
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "wc/wc_config.h"
#include "wc/wc_runtime.h"
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"
#include "wc/wc_selftest.h"
#include "wc/wc_dns.h"
#include "wc/wc_ip_pref.h"
#include "wc/wc_known_ips.h"
#include "wc/wc_util.h"
#include "wc/wc_signal.h"
#include "lookup_internal.h"
#include "lookup_exec_finalize.h"
#include "lookup_exec_connect.h"
#include "lookup_exec_empty.h"
#include "lookup_exec_redirect.h"
#include "lookup_exec_next.h"
#include "lookup_exec_referral.h"
#include "lookup_exec_authority.h"
#include "lookup_exec_constants.h"
#include "lookup_exec_start.h"
#include "lookup_exec_send.h"
#include "lookup_exec_recv.h"
#include "lookup_exec_guard.h"
#include "lookup_exec_append.h"
#include "lookup_exec_visit.h"
#include "lookup_exec_decision.h"
#include "lookup_exec_tail.h"
#include "lookup_exec_post.h"


static const Config* wc_lookup_resolve_config(const struct wc_lookup_opts* opts)
{
    if (!opts)
        return NULL;
    return opts->config;
}

static void wc_lookup_exec_sleep_ms(int ms)
{
    if (ms <= 0)
        return;
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)((ms % 1000) * 1000000L);
    nanosleep(&ts, NULL);
}

static void wc_lookup_exec_log_cidr_body_action(
    const Config* cfg,
    const char* action,
    const char* query,
    const char* host)
{
    if (!cfg || !cfg->debug || !action)
        return;
    fprintf(stderr,
        "[CIDR-BODY] action=%s query=%s host=%s\n",
        action,
        query ? query : "",
        host ? host : "unknown");
}

static int wc_lookup_exec_cidr_consistency_replace_body(
    const struct wc_query* q,
    const struct wc_lookup_opts* zopts,
    const Config* cfg,
    wc_net_context_t* net_ctx,
    const char* current_host,
    int current_port,
    char** body,
    int* body_replaced,
    int* body_consistent_authoritative)
{
    if (body_replaced)
        *body_replaced = 0;
    if (body_consistent_authoritative)
        *body_consistent_authoritative = 0;
    if (!q || !zopts || !cfg || !current_host || !*current_host || !body)
        return 0;

    struct wc_lookup_opts consistency_opts = *zopts;
    Config cfg_override = *cfg;
    struct wc_result consistency_res;
    memset(&consistency_res, 0, sizeof(consistency_res));
    struct wc_query consistency_q = {
        .raw = q->raw,
        .start_server = current_host,
        .port = current_port
    };

    cfg_override.cidr_strip_query = 0;
    consistency_opts.no_redirect = 1;
    consistency_opts.max_hops = 1;
    consistency_opts.net_ctx = net_ctx;
    consistency_opts.config = &cfg_override;

    wc_lookup_erx_baseline_recheck_guard_set(1);
    int consistency_rc = wc_lookup_execute(&consistency_q, &consistency_opts, &consistency_res);
    wc_lookup_erx_baseline_recheck_guard_set(0);

    if (*body) {
        free(*body);
        *body = NULL;
    }

    if (consistency_rc == 0 && consistency_res.body && consistency_res.body[0]) {
        int consistency_non_auth = wc_lookup_body_has_strong_redirect_hint(consistency_res.body);
        int consistency_erx = wc_lookup_body_contains_erx_iana_marker(consistency_res.body);
        *body = consistency_res.body;
        consistency_res.body = NULL;
        if (body_replaced)
            *body_replaced = 1;
        if (!consistency_non_auth && !consistency_erx && body_consistent_authoritative)
            *body_consistent_authoritative = 1;
    } else {
        *body = (char*)malloc(1);
        if (*body) {
            (*body)[0] = '\0';
            if (body_replaced)
                *body_replaced = 1;
        }
    }

    wc_lookup_result_free(&consistency_res);
    return 0;
}

static void wc_lookup_exec_cidr_add_pre_apnic_candidate(
    char candidates[][128],
    int* count,
    const char* host)
{
    if (!candidates || !count || !host || !*host)
        return;
    if (*count >= 5)
        return;

    const char* candidate_host = host;
    if (wc_dns_is_ip_literal(candidate_host)) {
        const char* mapped = wc_lookup_known_ip_host_from_literal(candidate_host);
        if (!mapped || !*mapped)
            return;
        candidate_host = mapped;
    }

    {
        const char* canon = wc_dns_canonical_alias(candidate_host);
        if (canon && *canon)
            candidate_host = canon;
    }

    const char* rir = wc_guess_rir(candidate_host);
    if (!rir ||
        strcasecmp(rir, "unknown") == 0 ||
        strcasecmp(rir, "iana") == 0 ||
        strcasecmp(rir, "apnic") == 0) {
        return;
    }

    for (int i = 0; i < *count; ++i) {
        if (strcasecmp(candidates[i], candidate_host) == 0)
            return;
    }

    if (strcasecmp(rir, "arin") == 0 && *count > 0) {
        for (int i = *count; i > 0; --i) {
            snprintf(candidates[i], 128, "%s", candidates[i - 1]);
        }
        snprintf(candidates[0], 128, "%s", candidate_host);
        (*count)++;
        return;
    }

    snprintf(candidates[*count], 128, "%s", candidate_host);
    (*count)++;
}

static int wc_lookup_exec_cidr_pre_apnic_lookback_hit(
    const struct wc_query* q,
    const struct wc_lookup_opts* zopts,
    const Config* cfg,
    wc_net_context_t* net_ctx,
    const char* candidate_host,
    const char* cidr_base_query)
{
    if (!q || !zopts || !cfg || !candidate_host || !*candidate_host ||
        !cidr_base_query || !*cidr_base_query) {
        return 0;
    }

    struct wc_lookup_opts lookback_opts = *zopts;
    Config cfg_override = *cfg;
    struct wc_result lookback_res;
    memset(&lookback_res, 0, sizeof(lookback_res));
    struct wc_query lookback_q = {
        .raw = cidr_base_query,
        .start_server = candidate_host,
        .port = q->port
    };

    cfg_override.cidr_strip_query = 0;
    lookback_opts.no_redirect = 1;
    lookback_opts.max_hops = 1;
    lookback_opts.net_ctx = net_ctx;
    lookback_opts.config = &cfg_override;

    wc_lookup_erx_baseline_recheck_guard_set(1);
    int lookback_rc = wc_lookup_execute(&lookback_q, &lookback_opts, &lookback_res);
    wc_lookup_erx_baseline_recheck_guard_set(0);

    int hit = 0;
    if (lookback_rc == 0 && lookback_res.body && lookback_res.body[0]) {
        int has_redirect_hint = wc_lookup_body_has_strong_redirect_hint(lookback_res.body);
        int has_erx_marker = wc_lookup_body_contains_erx_iana_marker(lookback_res.body);
        int is_auth = is_authoritative_response(lookback_res.body);
        if (is_auth && !has_redirect_hint && !has_erx_marker)
            hit = 1;
    }

    wc_lookup_result_free(&lookback_res);
    return hit;
}

static int wc_lookup_exec_cidr_recheck_body_hit(const char* body)
{
    if (!body || !body[0])
        return 0;
    {
        int has_redirect_hint = wc_lookup_body_has_strong_redirect_hint(body);
        int has_erx_marker = wc_lookup_body_contains_erx_iana_marker(body);
        int is_auth = is_authoritative_response(body);
        return (is_auth && !has_redirect_hint && !has_erx_marker) ? 1 : 0;
    }
}

static void wc_result_init(struct wc_result* r){
    if(!r) return;
    memset(r,0,sizeof(*r));
    r->err = 0;
    r->meta.via_host[0] = 0;
    r->meta.via_ip[0] = 0;
    r->meta.last_host[0] = 0;
    r->meta.last_ip[0] = 0;
    r->meta.authoritative_host[0] = 0;
    r->meta.authoritative_ip[0] = 0;
    r->meta.fallback_flags = 0; // initialize phased-in fallback bitset
        r->meta.last_connect_errno = 0; // initialize last connection errno
}

void wc_lookup_result_free(struct wc_result* r){ if(!r) return; if(r->body){ free(r->body); r->body=NULL; } r->body_len=0; }

// Simple IP literal check (IPv4 dotted-decimal or presence of ':')
// Known-IP fallback mapping (defined in whois_client.c); phase-in with minimal coupling
// DNS fallback helper for well-known WHOIS servers.
extern const char* wc_dns_get_known_ip(const char* domain);

int wc_lookup_exec_run(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out) {
    if(!q || !q->raw || !out) return -1;
    struct wc_lookup_opts zopts = { .max_hops=5, .no_redirect=0, .timeout_sec=5, .retries=2, .net_ctx=NULL, .config=NULL };
    if(opts) zopts = *opts;
    const Config* cfg = wc_lookup_resolve_config(&zopts);
    wc_result_init(out);
    if (!cfg) {
        out->err = EINVAL;
        return -1;
    }
    wc_net_context_t* net_ctx = zopts.net_ctx ? zopts.net_ctx : wc_net_context_get_active();
    if (!net_ctx) {
        out->err = EINVAL;
        return -1;
    }
    if (wc_signal_should_terminate()) {
        out->err = WC_ERR_IO;
        out->meta.last_connect_errno = EINTR;
        return -1;
    }
    const wc_selftest_injection_t* injection = net_ctx ? net_ctx->injection : NULL;
    const wc_selftest_fault_profile_t* fault_profile = injection ? &injection->fault : NULL;
    int query_is_ipv4_literal = wc_lookup_query_is_ipv4_literal(q->raw);
    int query_is_ip_literal = wc_lookup_query_is_ip_literal(q->raw);
    int query_is_cidr = wc_lookup_query_is_cidr(q->raw);
    int query_is_asn = wc_lookup_query_is_asn(q->raw);
    int query_is_nethandle = wc_lookup_query_is_arin_nethandle(q->raw);
    int query_has_arin_prefix = wc_lookup_query_has_arin_prefix(q->raw);
    char* cidr_base_query = NULL;
    if (query_is_cidr) {
        cidr_base_query = wc_lookup_extract_cidr_base(q->raw);
    }
    int query_is_cidr_effective = query_is_cidr;
    int query_is_ip_literal_effective = query_is_ip_literal || (cidr_base_query != NULL);
    int query_is_ipv4_literal_effective = query_is_ipv4_literal ||
        (cidr_base_query && strchr(cidr_base_query, ':') == NULL);

    // Pick starting server: explicit -> canonical; else default to IANA
    // Keep a stable label to display in header: prefer the user-provided token verbatim when present
    char start_host[128];
    char start_label[128];
    if (wc_lookup_exec_resolve_start(q, cfg,
            start_host, sizeof(start_host),
            start_label, sizeof(start_label)) != 0) {
        out->err = EINVAL;
        return -1;
    }

    // Redirect loop with simple visited guard
    char* visited[16] = {0};
    int visited_count = 0;
    char current_host[128]; snprintf(current_host, sizeof(current_host), "%s", start_host);
    int current_port = (q->port > 0 ? q->port : 43);
    int hops = 0;
    int additional_emitted = 0; // first referral uses "Additional"
    int redirect_cap_hit = 0; // set when redirect limit stops the chain early
    char* combined = NULL;
    out->meta.hops = 0;
    int emit_redirect_headers = 1;

    int empty_retry = 0; // retry budget for empty-body anomalies within a hop (fallback hosts)
    char* arin_cidr_retry_query = NULL;
    int apnic_force_ip = 0;
    int apnic_revisit_used = 0;
    int apnic_ambiguous_revisit_used = 0;
    int stop_with_apnic_authority = 0;
    int stop_with_header_authority = 0;
    char header_authority_host[128];
    header_authority_host[0] = '\0';
    int apnic_redirect_reason = APNIC_REDIRECT_NONE;
    int force_original_query = 0;
    int pending_referral = 0;
    int last_hop_authoritative = 0;
    int last_hop_need_redirect = 0;
    int last_hop_has_ref = 0;
    Config cfg_override;
    const Config* cfg_for_dns = NULL;
    int apnic_erx_root = 0;
    char apnic_erx_ref_host[128];
    apnic_erx_ref_host[0] = '\0';
    char apnic_erx_target_rir[16];
    apnic_erx_target_rir[0] = '\0';
    int apnic_erx_stop = 0;
    char apnic_erx_stop_host[128];
    apnic_erx_stop_host[0] = '\0';
    int apnic_erx_stop_unknown = 0;
    int apnic_erx_ripe_non_managed = 0;
    char apnic_erx_root_host[128];
    apnic_erx_root_host[0] = '\0';
    char apnic_erx_root_ip[64];
    apnic_erx_root_ip[0] = '\0';
    int failure_emitted = 0;
    char last_failure_host[128];
    char last_failure_ip[64];
    char last_failure_rir[32];
    const char* last_failure_status = "unknown";
    const char* last_failure_desc = "unknown";
    last_failure_host[0] = '\0';
    last_failure_ip[0] = '\0';
    snprintf(last_failure_rir, sizeof(last_failure_rir), "%s", "unknown");
    char apnic_last_ip[64];
    apnic_last_ip[0] = '\0';
    int apnic_erx_seen_arin = 0;
    int rir_cycle_exhausted = 0;
    int apnic_erx_arin_before_apnic = 0;
    int apnic_erx_authoritative_stop = 0;
    int force_rir_cycle = 0;
    int apnic_iana_not_allocated_disclaimer = 0;
    int apnic_iana_not_allocated_disclaimer_seen = 0;
    int seen_arin_no_match_cidr = 0;
    int seen_apnic_iana_netblock = 0;
    int seen_ripe_non_managed = 0;
    int seen_afrinic_iana_blk = 0;
    int seen_lacnic_unallocated = 0;
    int seen_real_authoritative = 0;
    int erx_marker_seen = 0;
    int saw_rate_limit_or_denied = 0;
    int erx_baseline_recheck_attempted = 0;
    char erx_marker_host[128];
    erx_marker_host[0] = '\0';
    char erx_marker_ip[64];
    erx_marker_ip[0] = '\0';
    int erx_fast_recheck_done = 0;
    int erx_fast_authoritative = 0;
    char erx_fast_authoritative_host[128];
    char erx_fast_authoritative_ip[64];
    erx_fast_authoritative_host[0] = '\0';
    erx_fast_authoritative_ip[0] = '\0';
    char pre_apnic_rir_candidates[5][128];
    int pre_apnic_rir_candidate_count = 0;
    int pre_apnic_rir_capture_closed = 0;
    char last_hop_rir[16];
    last_hop_rir[0] = '\0';
    char last_lacnic_internal_hint_host[128];
    last_lacnic_internal_hint_host[0] = '\0';
    int last_lacnic_internal_hint_valid = 0;
    char* last_hop_body_snapshot = NULL;
    int cidr_consistency_check_done = 0;
    while (hops < zopts.max_hops) {
        if (wc_signal_should_terminate()) {
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            break;
        }
        apnic_erx_authoritative_stop = 0;
        force_rir_cycle = 0;
        // default last-hop markers for this iteration (helps error reporting on early failures)
        snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
        snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s", "unknown");
        wc_lookup_exec_mark_visited(current_host, visited, &visited_count);

        int app_retry_attempt = 0;
    retry_same_hop:
        ;

        // connect (dynamic DNS-derived candidate list; IPv6 preferred unless overridden)
        int arin_host = 0;
        int arin_retry_active = 0;
        int hop_prefers_v4 = 0;
        char pref_label[32];
        struct wc_net_info ni;
        int connected_ok = 0;
        int first_conn_rc = 0;
        int attempt_cap_hit = 0;
        char canonical_host[128];
        int connect_rc = 0;

        struct wc_lookup_exec_connect_ctx conn_ctx = {
            .out = out,
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .current_host = current_host,
            .hops = hops,
            .current_port = current_port,
            .query_is_ipv4_literal_effective = query_is_ipv4_literal_effective,
            .cfg_override = &cfg_override,
            .cfg_for_dns = &cfg_for_dns,
            .hop_prefers_v4 = &hop_prefers_v4,
            .arin_host = &arin_host,
            .canonical_host = canonical_host,
            .canonical_host_len = sizeof(canonical_host),
            .pref_label = pref_label,
            .pref_label_len = sizeof(pref_label),
            .ni = &ni,
            .connected_ok = &connected_ok,
            .first_conn_rc = &first_conn_rc,
            .attempt_cap_hit = &attempt_cap_hit
        };
        connect_rc = wc_lookup_exec_connect(&conn_ctx);
        if (connect_rc != 0) {
            break;
        }
        if (!connected_ok) {
            if (attempt_cap_hit) {
                break;
            }
            out->err = first_conn_rc ? first_conn_rc : -1;
            out->meta.last_connect_errno = ni.last_errno; // propagate failure errno
            snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
            snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s",
                     ni.ip[0] ? ni.ip : "unknown");
            if (hops == 0) {
                if (out->meta.via_host[0] == 0) {
                    snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_label);
                }
                if (out->meta.via_ip[0] == 0) {
                    snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s", "unknown");
                }
            }
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        if (wc_signal_should_terminate()) {
            int debug_enabled = cfg ? cfg->debug : 0;
            wc_safe_close(&ni.fd, "wc_lookup_signal_abort", debug_enabled);
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
            snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s",
                     ni.ip[0] ? ni.ip : "unknown");
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        // record last successful hop details
        snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
        snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s", ni.ip[0]?ni.ip:"unknown");
        if (hops == 0) {
            // record first hop meta: show the user-supplied starting server token when available
            snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_label);
            snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s", ni.ip[0]?ni.ip:"unknown");
        }

        // send query (auto prepend "n " for ARIN IPv4 literals when needed)
        arin_retry_active = (arin_cidr_retry_query != NULL);
        int use_original_query = force_original_query;
        force_original_query = 0;
        int force_cidr_base_query =
            (query_is_cidr_effective && (erx_marker_seen || seen_apnic_iana_netblock) && cidr_base_query &&
             !arin_retry_active && !use_original_query)
            ? 1
            : 0;
        int sent_cidr_baseline_query =
            (query_is_cidr_effective && cidr_base_query && !arin_retry_active &&
             !use_original_query &&
             ((cfg && cfg->cidr_strip_query) || force_cidr_base_query))
            ? 1
            : 0;
        struct wc_lookup_exec_send_ctx send_ctx = {
            .out = out,
            .q = q,
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .current_host = current_host,
            .arin_host = arin_host,
            .query_is_cidr_effective = query_is_cidr_effective,
            .query_is_ip_literal_effective = query_is_ip_literal_effective,
            .query_is_ip_literal = query_is_ip_literal,
            .query_is_cidr = query_is_cidr,
            .query_is_asn = query_is_asn,
            .query_is_nethandle = query_is_nethandle,
            .query_has_arin_prefix = query_has_arin_prefix,
            .force_cidr_base_query = force_cidr_base_query,
            .cidr_base_query = cidr_base_query,
            .use_original_query = use_original_query,
            .arin_cidr_retry_query = &arin_cidr_retry_query,
            .ni = &ni,
            .pending_referral = &pending_referral
        };
        if (wc_lookup_exec_send_query(&send_ctx) != 0) {
            break;
        }

        // receive
        char* body=NULL; size_t blen=0;
        struct wc_lookup_exec_recv_ctx recv_ctx = {
            .out = out,
            .zopts = &zopts,
            .cfg = cfg,
            .ni = &ni,
            .pending_referral = &pending_referral,
            .body = &body,
            .blen = &blen
        };
        if (wc_lookup_exec_recv_body(&recv_ctx) != 0) {
            break;
        }

    // Selftest injection hook (one-shot): simulate empty-body anomaly for retry/fallback validation
    // Controlled via wc_selftest_set_inject_empty() (no environment dependency in release).
        {
            static int injected_once = 0;
            int inject_empty = (injection && injection->inject_empty) ? 1 : 0;
            if (inject_empty && !injected_once) {
                if (body) { free(body); body = NULL; }
                blen = 0; // force empty
                injected_once = 1;
            }
        }

        // Defensive: occasionally a connection succeeds but body is empty.
        // Treat empty or banner-only bodies as transient and use a dedicated handler.
        int persistent_empty = 0;
        struct wc_lookup_exec_empty_ctx empty_ctx = {
            .out = out,
            .q = q,
            .zopts = &zopts,
            .cfg = cfg,
            .cfg_for_dns = cfg_for_dns,
            .net_ctx = net_ctx,
            .current_host = current_host,
            .canonical_host = canonical_host,
            .pref_label = pref_label,
            .hops = hops,
            .hop_prefers_v4 = hop_prefers_v4,
            .current_port = current_port,
            .empty_retry = &empty_retry,
            .ni = &ni,
            .body = &body,
            .blen = &blen,
            .persistent_empty = &persistent_empty
        };
        if (wc_lookup_exec_handle_empty_body(&empty_ctx)) {
            continue;
        }
        if (blen > 0) {
            empty_retry = 0;
        }

        {
            int temporary_denied = wc_lookup_body_contains_temporary_denied(body);
            int permanent_denied = wc_lookup_body_contains_permanent_denied(body);
            if (!permanent_denied && temporary_denied &&
                cfg->app_retry_rate_limit > app_retry_attempt) {
                int max_retries = cfg->app_retry_rate_limit;
                int wait_ms = cfg->app_retry_interval_ms;
                app_retry_attempt++;
                if (cfg->debug || cfg->retry_metrics) {
                    fprintf(stderr,
                            "[APP-RETRY] action=rate-limit-retry hop=%d attempt=%d/%d host=%s wait_ms=%d\n",
                            hops,
                            app_retry_attempt,
                            max_retries,
                            current_host,
                            wait_ms);
                }
                if (body) {
                    free(body);
                    body = NULL;
                }
                blen = 0;
                if (wc_signal_should_terminate()) {
                    out->err = WC_ERR_IO;
                    out->meta.last_connect_errno = EINTR;
                    break;
                }
                wc_lookup_exec_sleep_ms(wait_ms);
                goto retry_same_hop;
            }
        }

        // ARIN CIDR no-match: do not retry with ARIN prefixes; follow normal RIR cycle.

        // Decide next action based on only the latest hop body (not the combined history)
        int auth = is_authoritative_response(body);
        int apnic_iana_netblock_cidr = 0;
        int apnic_erx_legacy = 0;
        const char* current_rir_guess = NULL;
        int need_redir_eval = 0;
        const char* header_host = NULL;
        int header_is_iana = 0;
        char* ref = NULL;
        int ref_port = 0;
        int ref_explicit = 0;
        char ref_host[128];
        ref_host[0] = '\0';
        char header_hint_host[128];
        int header_hint_valid = 0;
        int allow_cycle_on_loop = 0;
        int need_redir = 0;
        int force_stop_authoritative = 0;
        int apnic_erx_suppress_current = 0;
        char next_host[128];
        next_host[0] = '\0';
        int have_next = 0;
        int next_port = current_port;
        int allow_apnic_ambiguous_revisit = 0;
        int ref_explicit_allow_visited = 0;

        struct wc_lookup_exec_decision_ctx decision_ctx = {
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .fault_profile = fault_profile,
            .ni = &ni,
            .current_host = current_host,
            .current_port = current_port,
            .hops = hops,
            .query_is_cidr = query_is_cidr,
            .query_is_cidr_effective = query_is_cidr_effective,
            .query_is_ip_literal_raw = query_is_ip_literal,
            .query_is_ip_literal_effective = query_is_ip_literal_effective,
            .cidr_base_query = cidr_base_query,
            .body = &body,
            .auth = &auth,
            .need_redir_eval = &need_redir_eval,
            .current_rir_guess = &current_rir_guess,
            .header_host = &header_host,
            .header_is_iana = &header_is_iana,
            .allow_cycle_on_loop = &allow_cycle_on_loop,
            .need_redir = &need_redir,
            .force_stop_authoritative = &force_stop_authoritative,
            .apnic_erx_suppress_current = &apnic_erx_suppress_current,
            .ref = &ref,
            .ref_port = &ref_port,
            .ref_explicit = &ref_explicit,
            .ref_host = ref_host,
            .ref_host_len = sizeof(ref_host),
            .header_authority_host = header_authority_host,
            .header_authority_host_len = sizeof(header_authority_host),
            .stop_with_header_authority = &stop_with_header_authority,
            .force_rir_cycle = &force_rir_cycle,
            .apnic_erx_root = &apnic_erx_root,
            .apnic_redirect_reason = &apnic_redirect_reason,
            .apnic_erx_ripe_non_managed = &apnic_erx_ripe_non_managed,
            .apnic_erx_arin_before_apnic = &apnic_erx_arin_before_apnic,
            .apnic_erx_stop = &apnic_erx_stop,
            .apnic_erx_stop_host = apnic_erx_stop_host,
            .apnic_erx_stop_host_len = sizeof(apnic_erx_stop_host),
            .apnic_erx_seen_arin = &apnic_erx_seen_arin,
            .apnic_erx_target_rir = apnic_erx_target_rir,
            .apnic_erx_target_rir_len = sizeof(apnic_erx_target_rir),
            .apnic_erx_ref_host = apnic_erx_ref_host,
            .apnic_erx_ref_host_len = sizeof(apnic_erx_ref_host),
            .apnic_erx_keep_ref = NULL,
            .apnic_iana_netblock_cidr = &apnic_iana_netblock_cidr,
            .apnic_iana_not_allocated_disclaimer = &apnic_iana_not_allocated_disclaimer,
            .apnic_erx_legacy = &apnic_erx_legacy,
            .apnic_last_ip = apnic_last_ip,
            .apnic_last_ip_len = sizeof(apnic_last_ip),
            .apnic_ambiguous_revisit_used = &apnic_ambiguous_revisit_used,
            .stop_with_apnic_authority = &stop_with_apnic_authority,
            .rir_cycle_exhausted = &rir_cycle_exhausted,
            .apnic_erx_authoritative_stop = &apnic_erx_authoritative_stop,
            .apnic_erx_stop_unknown = &apnic_erx_stop_unknown,
            .apnic_erx_root_host = apnic_erx_root_host,
            .apnic_erx_root_host_len = sizeof(apnic_erx_root_host),
            .apnic_erx_root_ip = apnic_erx_root_ip,
            .apnic_erx_root_ip_len = sizeof(apnic_erx_root_ip),
            .erx_marker_seen = &erx_marker_seen,
            .erx_marker_host = erx_marker_host,
            .erx_marker_host_len = sizeof(erx_marker_host),
            .erx_marker_ip = erx_marker_ip,
            .erx_marker_ip_len = sizeof(erx_marker_ip),
            .erx_baseline_recheck_attempted = &erx_baseline_recheck_attempted,
            .erx_fast_recheck_done = &erx_fast_recheck_done,
            .erx_fast_authoritative = &erx_fast_authoritative,
            .erx_fast_authoritative_host = erx_fast_authoritative_host,
            .erx_fast_authoritative_host_len = sizeof(erx_fast_authoritative_host),
            .erx_fast_authoritative_ip = erx_fast_authoritative_ip,
            .erx_fast_authoritative_ip_len = sizeof(erx_fast_authoritative_ip),
            .last_hop_authoritative = &last_hop_authoritative,
            .last_hop_need_redirect = &last_hop_need_redirect,
            .last_hop_has_ref = &last_hop_has_ref,
            .saw_rate_limit_or_denied = &saw_rate_limit_or_denied,
            .last_failure_host = last_failure_host,
            .last_failure_host_len = sizeof(last_failure_host),
            .last_failure_ip = last_failure_ip,
            .last_failure_ip_len = sizeof(last_failure_ip),
            .last_failure_rir = last_failure_rir,
            .last_failure_rir_len = sizeof(last_failure_rir),
            .last_failure_status = &last_failure_status,
            .last_failure_desc = &last_failure_desc,
            .seen_real_authoritative = &seen_real_authoritative,
            .seen_apnic_iana_netblock = &seen_apnic_iana_netblock,
            .seen_ripe_non_managed = &seen_ripe_non_managed,
            .seen_afrinic_iana_blk = &seen_afrinic_iana_blk,
            .seen_arin_no_match_cidr = &seen_arin_no_match_cidr,
            .seen_lacnic_unallocated = &seen_lacnic_unallocated,
            .header_hint_host = header_hint_host,
            .header_hint_host_len = sizeof(header_hint_host),
            .header_hint_valid = &header_hint_valid,
            .next_host = next_host,
            .next_host_len = sizeof(next_host),
            .have_next = &have_next,
            .next_port = &next_port,
            .ref_explicit_allow_visited = &ref_explicit_allow_visited,
            .visited = visited,
            .visited_count = &visited_count,
            .pref_label = pref_label,
            .combined = combined,
            .fallback_flags = &out->meta.fallback_flags,
            .persistent_empty = persistent_empty
        };
        int erx_marker_seen_before_decision = erx_marker_seen;
        wc_lookup_exec_decide_next(&decision_ctx);

        if (last_hop_rir[0]) {
            last_hop_rir[0] = '\0';
        }
        if (current_rir_guess && *current_rir_guess) {
            snprintf(last_hop_rir, sizeof(last_hop_rir), "%s", current_rir_guess);
        }
        if (last_hop_body_snapshot) {
            free(last_hop_body_snapshot);
            last_hop_body_snapshot = NULL;
        }
        if (body && body[0]) {
            size_t body_len = strlen(body);
            last_hop_body_snapshot = (char*)malloc(body_len + 1);
            if (last_hop_body_snapshot) {
                memcpy(last_hop_body_snapshot, body, body_len + 1);
            }
        }
        last_lacnic_internal_hint_valid = 0;
        if (current_rir_guess && strcasecmp(current_rir_guess, "lacnic") == 0 &&
            header_hint_valid && header_hint_host[0]) {
            const char* hint_canon = wc_dns_canonical_alias(header_hint_host);
            snprintf(last_lacnic_internal_hint_host,
                     sizeof(last_lacnic_internal_hint_host),
                     "%s",
                     hint_canon ? hint_canon : header_hint_host);
            last_lacnic_internal_hint_valid = 1;
        }

        if (apnic_iana_not_allocated_disclaimer) {
            apnic_iana_not_allocated_disclaimer_seen = 1;
        }

        if (query_is_cidr_effective) {
            if (!pre_apnic_rir_capture_closed && !erx_marker_seen_before_decision &&
                !erx_marker_seen && !apnic_iana_not_allocated_disclaimer_seen &&
                !apnic_iana_not_allocated_disclaimer) {
                wc_lookup_exec_cidr_add_pre_apnic_candidate(
                    pre_apnic_rir_candidates,
                    &pre_apnic_rir_candidate_count,
                    current_host);
            }
            if ((!erx_marker_seen_before_decision && erx_marker_seen) ||
                apnic_iana_not_allocated_disclaimer) {
                pre_apnic_rir_capture_closed = 1;
            }
        }

        if (query_is_cidr_effective && !cidr_consistency_check_done) {
            int skip_arin_consistency_recheck =
                (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 &&
                 !apnic_iana_not_allocated_disclaimer_seen)
                ? 1
                : 0;
            int baseline_has_redirect_hint =
                (body && wc_lookup_body_has_strong_redirect_hint(body)) ? 1 : 0;
            int baseline_is_ambiguous =
                (body && wc_lookup_find_case_insensitive(body, "query terms are ambiguous")) ? 1 : 0;
            if (sent_cidr_baseline_query && auth && !need_redir && (!ref || !*ref) &&
                !baseline_has_redirect_hint && !baseline_is_ambiguous &&
                !skip_arin_consistency_recheck &&
                !(cfg && cfg->cidr_strip_query)) {
                int body_replaced = 0;
                int body_consistent_authoritative = 0;
                (void)wc_lookup_exec_cidr_consistency_replace_body(
                    q,
                    &zopts,
                    cfg,
                    net_ctx,
                    current_host,
                    current_port,
                    &body,
                    &body_replaced,
                    &body_consistent_authoritative);
                cidr_consistency_check_done = 1;
                if (body_replaced) {
                    wc_lookup_exec_log_cidr_body_action(
                        cfg,
                        "consistency-replace",
                        q ? q->raw : NULL,
                        current_host);
                }
                if (body_consistent_authoritative) {
                    wc_lookup_exec_log_cidr_body_action(
                        cfg,
                        "consistency-stop-authoritative",
                        q ? q->raw : NULL,
                        current_host);
                    auth = 1;
                    need_redir = 0;
                    have_next = 0;
                    if (ref) {
                        free(ref);
                        ref = NULL;
                    }
                    const char* auth_host = wc_dns_canonical_alias(current_host);
                    snprintf(out->meta.authoritative_host,
                             sizeof(out->meta.authoritative_host),
                             "%s",
                             auth_host ? auth_host : current_host);
                    snprintf(out->meta.authoritative_ip,
                             sizeof(out->meta.authoritative_ip),
                             "%s",
                             ni.ip[0] ? ni.ip : "unknown");
                } else {
                    wc_lookup_exec_log_cidr_body_action(
                        cfg,
                        "consistency-stop-unknown",
                        q ? q->raw : NULL,
                        current_host);
                    auth = 0;
                    need_redir = 0;
                    have_next = 0;
                    out->meta.fallback_flags |= 0x20;
                    if (ref) {
                        free(ref);
                        ref = NULL;
                    }
                    snprintf(out->meta.authoritative_host,
                             sizeof(out->meta.authoritative_host),
                             "%s",
                             "unknown");
                    snprintf(out->meta.authoritative_ip,
                             sizeof(out->meta.authoritative_ip),
                             "%s",
                             "unknown");
                }
            }
        }

    // Append current body to combined output (ownership may transfer below); body can be empty string
    combined = wc_lookup_exec_append_body(combined, &body, apnic_erx_suppress_current);
        hops++; out->meta.hops = hops;

        struct wc_lookup_exec_tail_ctx tail_ctx = {
            .out = out,
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .ni = &ni,
            .start_host = start_host,
            .current_host = current_host,
            .current_host_len = sizeof(current_host),
            .current_port = &current_port,
            .hops = hops,
            .current_rir_guess = current_rir_guess,
            .header_host = header_host,
            .header_is_iana = header_is_iana,
            .auth = auth,
            .need_redir = need_redir,
            .have_next = have_next,
            .next_host = next_host,
            .next_host_len = sizeof(next_host),
            .next_port = &next_port,
            .ref = &ref,
            .pending_referral = &pending_referral,
            .redirect_cap_hit = &redirect_cap_hit,
            .apnic_force_ip = &apnic_force_ip,
            .apnic_revisit_used = &apnic_revisit_used,
            .allow_apnic_ambiguous_revisit = allow_apnic_ambiguous_revisit,
            .ref_explicit_allow_visited = ref_explicit_allow_visited,
            .allow_cycle_on_loop = allow_cycle_on_loop,
            .apnic_erx_root = apnic_erx_root,
            .apnic_redirect_reason = apnic_redirect_reason,
            .apnic_erx_ripe_non_managed = apnic_erx_ripe_non_managed,
            .apnic_erx_legacy = apnic_erx_legacy,
            .apnic_erx_stop = apnic_erx_stop,
            .apnic_erx_stop_unknown = apnic_erx_stop_unknown,
            .apnic_erx_root_host = apnic_erx_root_host,
            .apnic_erx_root_ip = apnic_erx_root_ip,
            .apnic_erx_stop_host = apnic_erx_stop_host,
            .apnic_last_ip = apnic_last_ip,
            .stop_with_header_authority = stop_with_header_authority,
            .header_authority_host = header_authority_host,
            .stop_with_apnic_authority = stop_with_apnic_authority,
            .seen_real_authoritative = seen_real_authoritative,
            .seen_apnic_iana_netblock = seen_apnic_iana_netblock,
            .seen_ripe_non_managed = seen_ripe_non_managed,
            .seen_afrinic_iana_blk = seen_afrinic_iana_blk,
            .seen_lacnic_unallocated = seen_lacnic_unallocated,
            .seen_arin_no_match_cidr = seen_arin_no_match_cidr,
            .query_is_cidr_effective = query_is_cidr_effective,
            .query_is_cidr = query_is_cidr,
            .arin_retry_active = arin_retry_active,
            .force_original_query = &force_original_query,
            .erx_fast_authoritative = erx_fast_authoritative,
            .erx_fast_authoritative_host = erx_fast_authoritative_host,
            .erx_fast_authoritative_ip = erx_fast_authoritative_ip,
            .last_hop_authoritative = &last_hop_authoritative,
            .last_hop_need_redirect = &last_hop_need_redirect,
            .last_hop_has_ref = &last_hop_has_ref,
            .visited = visited,
            .visited_count = visited_count,
            .pref_label = pref_label,
            .rir_cycle_exhausted = &rir_cycle_exhausted,
            .combined = &combined,
            .additional_emitted = &additional_emitted,
            .emit_redirect_headers = emit_redirect_headers
        };
        if (wc_lookup_exec_handle_tail(&tail_ctx)) {
            break;
        }
        // continue loop for next hop
    }

    if (query_is_cidr_effective && cidr_base_query && apnic_erx_root &&
        pre_apnic_rir_candidate_count > 0 && rir_cycle_exhausted &&
        !(out->meta.fallback_flags & 0x20)) {
        int authority_unresolved =
            (!out->meta.authoritative_host[0] ||
             strcasecmp(out->meta.authoritative_host, "unknown") == 0 ||
             strcasecmp(out->meta.authoritative_host, "error") == 0);
        if (authority_unresolved) {
            int pre_apnic_lookback_hit = 0;
            for (int i = 0; i < pre_apnic_rir_candidate_count; ++i) {
                const char* candidate_host = pre_apnic_rir_candidates[i];
                int candidate_hit = 0;
                int used_lacnic_internal_body = 0;

                if (last_lacnic_internal_hint_valid &&
                    last_hop_rir[0] && strcasecmp(last_hop_rir, "lacnic") == 0 &&
                    last_hop_body_snapshot && last_hop_body_snapshot[0] &&
                    strcasecmp(candidate_host, last_lacnic_internal_hint_host) == 0) {
                    candidate_hit = wc_lookup_exec_cidr_recheck_body_hit(last_hop_body_snapshot);
                    used_lacnic_internal_body = 1;
                    wc_lookup_exec_log_cidr_body_action(
                        cfg,
                        candidate_hit
                            ? "pre-apnic-lookback-lacnic-internal-hit"
                            : "pre-apnic-lookback-lacnic-internal-miss",
                        q ? q->raw : NULL,
                        candidate_host);
                }

                if (!used_lacnic_internal_body) {
                    candidate_hit = wc_lookup_exec_cidr_pre_apnic_lookback_hit(
                        q,
                        &zopts,
                        cfg,
                        net_ctx,
                        candidate_host,
                        cidr_base_query);
                }

                if (candidate_hit) {
                    wc_lookup_exec_log_cidr_body_action(
                        cfg,
                        "pre-apnic-lookback-hit",
                        q ? q->raw : NULL,
                        candidate_host);
                    pre_apnic_lookback_hit = 1;
                    break;
                }

                wc_lookup_exec_log_cidr_body_action(
                    cfg,
                    "pre-apnic-lookback-miss",
                    q ? q->raw : NULL,
                    candidate_host);
            }

            if (pre_apnic_lookback_hit) {
                out->meta.fallback_flags |= 0x20;
                snprintf(out->meta.authoritative_host,
                         sizeof(out->meta.authoritative_host),
                         "%s",
                         "unknown");
                snprintf(out->meta.authoritative_ip,
                         sizeof(out->meta.authoritative_ip),
                         "%s",
                         "unknown");
            } else {
                const char* apnic_host = (apnic_erx_root_host[0]) ? apnic_erx_root_host : "whois.apnic.net";
                const char* apnic_canon = wc_dns_canonical_alias(apnic_host);
                const char* apnic_ip = (apnic_erx_root_ip[0]) ? apnic_erx_root_ip : wc_dns_get_known_ip(apnic_host);
                snprintf(out->meta.authoritative_host,
                         sizeof(out->meta.authoritative_host),
                         "%s",
                         apnic_canon ? apnic_canon : apnic_host);
                snprintf(out->meta.authoritative_ip,
                         sizeof(out->meta.authoritative_ip),
                         "%s",
                         (apnic_ip && apnic_ip[0]) ? apnic_ip : "unknown");
            }
        }
    }

    if (last_hop_body_snapshot) {
        free(last_hop_body_snapshot);
        last_hop_body_snapshot = NULL;
    }

    {
        struct wc_lookup_exec_post_ctx post_ctx = {
            .out = out,
            .q = q,
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .start_host = start_host,
            .start_label = start_label,
            .current_host = current_host,
            .combined = &combined,
            .redirect_cap_hit = redirect_cap_hit,
            .last_hop_authoritative = last_hop_authoritative,
            .last_hop_need_redirect = last_hop_need_redirect,
            .last_hop_has_ref = last_hop_has_ref,
            .apnic_erx_root = apnic_erx_root,
            .apnic_erx_seen_arin = apnic_erx_seen_arin,
            .apnic_redirect_is_erx = (apnic_redirect_reason == APNIC_REDIRECT_ERX),
            .erx_marker_seen = erx_marker_seen,
            .rir_cycle_exhausted = rir_cycle_exhausted,
            .saw_rate_limit_or_denied = saw_rate_limit_or_denied,
            .erx_baseline_recheck_attempted = erx_baseline_recheck_attempted,
            .erx_marker_host = erx_marker_host,
            .erx_marker_ip = erx_marker_ip,
            .apnic_erx_root_host = apnic_erx_root_host,
            .apnic_erx_root_ip = apnic_erx_root_ip,
            .apnic_last_ip = apnic_last_ip,
            .query_is_cidr_effective = query_is_cidr_effective,
            .cidr_base_query = &cidr_base_query,
            .arin_cidr_retry_query = &arin_cidr_retry_query,
            .visited = visited,
            .visited_count = visited_count,
            .visited_len = 16,
            .failure_emitted = &failure_emitted,
            .last_failure_host = last_failure_host,
            .last_failure_host_len = sizeof(last_failure_host),
            .last_failure_ip = last_failure_ip,
            .last_failure_ip_len = sizeof(last_failure_ip),
            .last_failure_rir = last_failure_rir,
            .last_failure_rir_len = sizeof(last_failure_rir),
            .last_failure_status = last_failure_status,
            .last_failure_desc = last_failure_desc
        };
        return wc_lookup_exec_post_finalize(&post_ctx);
    }
}

