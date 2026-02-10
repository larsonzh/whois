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


static const Config* wc_lookup_resolve_config(const struct wc_lookup_opts* opts)
{
    if (!opts)
        return NULL;
    return opts->config;
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

// helper to append text to a growing buffer; frees base and returns new buffer
static char* append_and_free(char* base, const char* extra) {
    size_t la = base ? strlen(base) : 0;
    size_t lb = extra ? strlen(extra) : 0;
    char* n = (char*)malloc(la + lb + 1);
    if (!n) return base; // OOM: keep old to avoid leak
    if (base) memcpy(n, base, la);
    if (extra) memcpy(n + la, extra, lb);
    n[la + lb] = '\0';
    if (base) free(base);
    return n;
}

// local strdup to avoid feature-macro dependency differences across toolchains
static char* xstrdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

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
        // mark visited
        int already = 0;
        for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], current_host)==0) { already=1; break; } }
        if (!already && visited_count < 16) visited[visited_count++] = xstrdup(current_host);
        if (wc_dns_is_ip_literal(current_host)) {
            const char* mapped_host = wc_lookup_known_ip_host_from_literal(current_host);
            if (mapped_host && *mapped_host &&
                !wc_lookup_visited_has(visited, visited_count, mapped_host) && visited_count < 16) {
                visited[visited_count++] = xstrdup(mapped_host);
            }
        }
        const char* canon_visit = wc_dns_canonical_alias(current_host);
        if (canon_visit && canon_visit[0] && strcasecmp(canon_visit, current_host) != 0) {
            if (!wc_lookup_visited_has(visited, visited_count, canon_visit) && visited_count < 16) {
                visited[visited_count++] = xstrdup(canon_visit);
            }
        }

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
                    snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s",
                             ni.ip[0] ? ni.ip : "unknown");
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

        // ARIN CIDR no-match: do not retry with ARIN prefixes; follow normal RIR cycle.

        // Decide next action based on only the latest hop body (not the combined history)
        int auth = is_authoritative_response(body);
        int apnic_iana_netblock_cidr = 0;
        int apnic_erx_legacy = 0;
        /*
         * gTLD registry responses (e.g., whois.verisign-grs.com) often carry a
         * "Registrar WHOIS Server:" line that would trip the generic redirect
         * heuristics. Treat those registry hops as authoritative and suppress
         * redirects/referrals to avoid an unnecessary IANA pivot, even when the
         * hop was initiated via a literal IP (guarded by wc_guess_rir).
         */
        const char* current_rir_guess = wc_guess_rir(current_host);
        if (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 && !apnic_erx_root) {
            apnic_erx_arin_before_apnic = 1;
        }
        int is_gtld_registry = (strcasecmp(current_host, "whois.verisign-grs.com") == 0 ||
                                strcasecmp(current_host, "whois.crsnic.net") == 0 ||
                                (current_rir_guess && strcasecmp(current_rir_guess, "verisign") == 0));
        int need_redir_eval = (!is_gtld_registry) ? needs_redirect(body) : 0; // evaluate even when redirects disabled for logging
        const char* header_host = NULL;
        int header_is_iana = 0;
        int ripe_non_managed = wc_lookup_body_contains_ripe_non_managed(body);
        int access_denied = wc_lookup_body_contains_access_denied(body);
        int rate_limited = wc_lookup_body_contains_rate_limit(body);
        char* ref = NULL;
        int ref_port = 0;
        char ref_host[128];
        ref_host[0] = '\0';
        if (!is_gtld_registry) {
            // Extract referral even when redirects are disabled, so we can surface
            // the pending hop in output ("=== Additional query to ... ===").
            ref = extract_refer_server(body);
            if (!ref) {
                ref = wc_lookup_extract_referral_fallback(body);
            }
        }
        if (ref) {
            int ref_parse_rc = wc_lookup_parse_referral_target(ref, ref_host, sizeof(ref_host), &ref_port);
            if (wc_lookup_exec_referral_fallback(ref, ref_host, sizeof(ref_host), &ref_port, ref_parse_rc) != 0) {
                if (ref_parse_rc != 0 || ref_host[0] == '\0') {
                    free(ref);
                    ref = NULL;
                }
            } else {
                ref_parse_rc = 0;
            }
        }
        int ref_explicit = 0;
        int apnic_erx_keep_ref = 0;
        struct wc_lookup_exec_referral_ctx referral_ctx = {
            .current_host = current_host,
            .current_rir_guess = current_rir_guess,
            .body = body,
            .ripe_non_managed = ripe_non_managed,
            .apnic_erx_root = apnic_erx_root,
            .apnic_redirect_reason = apnic_redirect_reason,
            .apnic_erx_legacy = apnic_erx_legacy,
            .apnic_erx_ripe_non_managed = apnic_erx_ripe_non_managed,
            .apnic_erx_arin_before_apnic = apnic_erx_arin_before_apnic,
            .visited = visited,
            .visited_count = &visited_count,
            .ref = &ref,
            .ref_host = ref_host,
            .ref_host_len = sizeof(ref_host),
            .ref_explicit = &ref_explicit,
            .apnic_erx_keep_ref = &apnic_erx_keep_ref,
            .apnic_erx_ref_host = apnic_erx_ref_host,
            .apnic_erx_ref_host_len = sizeof(apnic_erx_ref_host),
            .apnic_erx_stop = &apnic_erx_stop,
            .apnic_erx_stop_host = apnic_erx_stop_host,
            .apnic_erx_stop_host_len = sizeof(apnic_erx_stop_host),
            .apnic_erx_seen_arin = &apnic_erx_seen_arin,
            .apnic_erx_target_rir = apnic_erx_target_rir,
            .apnic_erx_target_rir_len = sizeof(apnic_erx_target_rir)
        };
        wc_lookup_exec_referral_parse(&referral_ctx);
        char header_hint_host[128];
        int header_hint_valid = 0;
        int header_non_authoritative = 0;
        int allow_cycle_on_loop = 0;
        int need_redir = 0;
        int force_stop_authoritative = 0;
        int apnic_erx_suppress_current = 0;
        struct wc_lookup_exec_redirect_ctx redir_ctx = {
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .ni = &ni,
            .body = body,
            .auth = &auth,
            .current_host = current_host,
            .current_rir_guess = current_rir_guess,
            .hops = hops,
            .current_port = current_port,
            .query_is_cidr = query_is_cidr,
            .query_is_cidr_effective = query_is_cidr_effective,
            .cidr_base_query = cidr_base_query,
            .ripe_non_managed = ripe_non_managed,
            .access_denied = access_denied,
            .rate_limited = rate_limited,
            .need_redir_eval = &need_redir_eval,
            .force_rir_cycle = &force_rir_cycle,
            .stop_with_header_authority = &stop_with_header_authority,
            .header_authority_host = header_authority_host,
            .header_authority_host_len = sizeof(header_authority_host),
            .header_hint_host = header_hint_host,
            .header_hint_host_len = sizeof(header_hint_host),
            .header_hint_valid = &header_hint_valid,
            .header_host = &header_host,
            .header_is_iana = &header_is_iana,
            .header_non_authoritative = &header_non_authoritative,
            .allow_cycle_on_loop = &allow_cycle_on_loop,
            .need_redir = &need_redir,
            .force_stop_authoritative = &force_stop_authoritative,
            .apnic_erx_suppress_current = &apnic_erx_suppress_current,
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
            .apnic_erx_root = &apnic_erx_root,
            .apnic_redirect_reason = &apnic_redirect_reason,
            .apnic_erx_ripe_non_managed = &apnic_erx_ripe_non_managed,
            .apnic_erx_arin_before_apnic = &apnic_erx_arin_before_apnic,
            .apnic_erx_ref_host = apnic_erx_ref_host,
            .apnic_erx_ref_host_len = sizeof(apnic_erx_ref_host),
            .apnic_erx_stop = &apnic_erx_stop,
            .apnic_erx_stop_host = apnic_erx_stop_host,
            .apnic_erx_stop_host_len = sizeof(apnic_erx_stop_host),
            .apnic_erx_target_rir = apnic_erx_target_rir,
            .apnic_erx_target_rir_len = sizeof(apnic_erx_target_rir),
            .apnic_erx_seen_arin = &apnic_erx_seen_arin,
            .apnic_erx_root_host = apnic_erx_root_host,
            .apnic_erx_root_host_len = sizeof(apnic_erx_root_host),
            .apnic_erx_root_ip = apnic_erx_root_ip,
            .apnic_erx_root_ip_len = sizeof(apnic_erx_root_ip),
            .apnic_erx_stop_unknown = &apnic_erx_stop_unknown,
            .apnic_erx_authoritative_stop = &apnic_erx_authoritative_stop,
            .apnic_erx_keep_ref = &apnic_erx_keep_ref,
            .apnic_iana_netblock_cidr = &apnic_iana_netblock_cidr,
            .apnic_erx_legacy = &apnic_erx_legacy,
            .apnic_last_ip = apnic_last_ip,
            .apnic_last_ip_len = sizeof(apnic_last_ip),
            .apnic_ambiguous_revisit_used = &apnic_ambiguous_revisit_used,
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
            .ref = &ref,
            .ref_host = ref_host,
            .ref_host_len = sizeof(ref_host),
            .ref_port = &ref_port,
            .ref_explicit = &ref_explicit,
            .visited = visited,
            .visited_count = &visited_count,
            .persistent_empty = persistent_empty
        };
        wc_lookup_exec_eval_redirect(&redir_ctx);
        body = redir_ctx.body;

        char next_host[128];
        next_host[0] = '\0';
        int have_next = 0;
        int next_port = current_port;
        int allow_apnic_ambiguous_revisit = 0;
        int ref_explicit_allow_visited = 0;
        struct wc_lookup_exec_next_ctx next_ctx = {
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .fault_profile = fault_profile,
            .current_host = current_host,
            .current_rir_guess = current_rir_guess,
            .current_port = current_port,
            .body = body,
            .hops = hops,
            .auth = auth,
            .need_redir_eval = need_redir_eval,
            .header_hint_valid = header_hint_valid,
            .header_hint_host = header_hint_host,
            .allow_cycle_on_loop = allow_cycle_on_loop,
            .force_stop_authoritative = force_stop_authoritative,
            .force_rir_cycle = force_rir_cycle,
            .apnic_erx_root = apnic_erx_root,
            .apnic_redirect_reason = apnic_redirect_reason,
            .apnic_erx_authoritative_stop = apnic_erx_authoritative_stop,
            .apnic_erx_legacy = apnic_erx_legacy,
            .apnic_erx_ripe_non_managed = apnic_erx_ripe_non_managed,
            .ref = ref,
            .ref_host = ref_host,
            .ref_port = ref_port,
            .ref_explicit = ref_explicit,
            .combined = combined,
            .fallback_flags = &out->meta.fallback_flags,
            .pref_label = pref_label,
            .visited = visited,
            .visited_count = &visited_count,
            .apnic_ambiguous_revisit_used = &apnic_ambiguous_revisit_used,
            .stop_with_apnic_authority = &stop_with_apnic_authority,
            .rir_cycle_exhausted = &rir_cycle_exhausted,
            .apnic_erx_ref_host = apnic_erx_ref_host,
            .apnic_erx_ref_host_len = sizeof(apnic_erx_ref_host),
            .next_host = next_host,
            .next_host_len = sizeof(next_host),
            .have_next = &have_next,
            .next_port = &next_port,
            .ref_explicit_allow_visited = &ref_explicit_allow_visited
        };
        wc_lookup_exec_pick_next_hop(&next_ctx);

    // Append current body to combined output (ownership may transfer below); body can be empty string
    if (!apnic_erx_suppress_current) {
        if (!combined) { combined = body; body = NULL; }
        else { combined = append_and_free(combined, body); free(body); }
    } else if (body) {
        free(body);
        body = NULL;
    }
        hops++; out->meta.hops = hops;

        struct wc_lookup_exec_authority_ctx authority_ctx = {
            .out = out,
            .zopts = &zopts,
            .ni = &ni,
            .current_host = current_host,
            .current_rir_guess = current_rir_guess,
            .header_authority_host = header_authority_host,
            .header_host = header_host,
            .header_is_iana = header_is_iana,
            .stop_with_header_authority = stop_with_header_authority,
            .stop_with_apnic_authority = stop_with_apnic_authority,
            .apnic_erx_stop = apnic_erx_stop,
            .apnic_erx_stop_unknown = apnic_erx_stop_unknown,
            .apnic_erx_root_host = apnic_erx_root_host,
            .apnic_erx_root_ip = apnic_erx_root_ip,
            .apnic_erx_stop_host = apnic_erx_stop_host,
            .apnic_last_ip = apnic_last_ip,
            .apnic_erx_root = apnic_erx_root,
            .apnic_erx_ripe_non_managed = apnic_erx_ripe_non_managed,
            .apnic_erx_legacy = apnic_erx_legacy,
            .seen_real_authoritative = seen_real_authoritative,
            .seen_apnic_iana_netblock = seen_apnic_iana_netblock,
            .seen_ripe_non_managed = seen_ripe_non_managed,
            .seen_afrinic_iana_blk = seen_afrinic_iana_blk,
            .seen_lacnic_unallocated = seen_lacnic_unallocated,
            .seen_arin_no_match_cidr = seen_arin_no_match_cidr,
            .query_is_cidr_effective = query_is_cidr_effective,
            .auth = auth,
            .need_redir = need_redir,
            .have_next = have_next,
            .erx_fast_authoritative = erx_fast_authoritative,
            .erx_fast_authoritative_host = erx_fast_authoritative_host,
            .erx_fast_authoritative_ip = erx_fast_authoritative_ip,
            .redirect_cap_hit = &redirect_cap_hit,
            .ref = &ref
        };
        if (wc_lookup_exec_check_authority(&authority_ctx)) {
            break;
        }

        // If no explicit referral but redirect seems needed, try via IANA as a safe hub
        if (ref) { free(ref); ref = NULL; }

        struct wc_lookup_exec_guard_no_next_ctx guard_no_next_ctx = {
            .out = out,
            .current_host = current_host,
            .current_rir_guess = current_rir_guess,
            .header_host = header_host,
            .header_is_iana = header_is_iana,
            .auth = auth,
            .apnic_erx_root = apnic_erx_root,
            .query_is_cidr_effective = query_is_cidr_effective,
            .seen_real_authoritative = seen_real_authoritative,
            .seen_apnic_iana_netblock = seen_apnic_iana_netblock,
            .seen_ripe_non_managed = seen_ripe_non_managed,
            .seen_afrinic_iana_blk = seen_afrinic_iana_blk,
            .seen_lacnic_unallocated = seen_lacnic_unallocated,
            .seen_arin_no_match_cidr = seen_arin_no_match_cidr,
            .have_next = &have_next,
            .next_host = next_host,
            .next_host_len = sizeof(next_host),
            .visited = visited,
            .visited_count = visited_count,
            .pref_label = pref_label,
            .net_ctx = net_ctx,
            .cfg = cfg,
            .ni = &ni,
            .rir_cycle_exhausted = &rir_cycle_exhausted
        };
        if (wc_lookup_exec_guard_no_next(&guard_no_next_ctx)) {
            break;
        }

        if (have_next && auth) {
            pending_referral = 1;
        }

        if (have_next && hops >= zopts.max_hops) {
            // Redirect chain would exceed the configured hop budget; stop immediately.
            redirect_cap_hit = 1;
            out->meta.fallback_flags |= 0x10; // redirect-cap
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            break;
        }

        int force_original_next = (arin_retry_active && have_next && query_is_cidr);
        if (have_next && query_is_cidr_effective && !force_original_next) {
            const char* next_rir = wc_guess_rir(next_host);
            if (next_rir && strcasecmp(next_rir, "apnic") == 0) {
                apnic_force_ip = 1;
            }
        }

        struct wc_lookup_exec_guard_loop_ctx guard_loop_ctx = {
            .out = out,
            .current_host = current_host,
            .current_rir_guess = current_rir_guess,
            .start_host = start_host,
            .header_host = header_host,
            .header_is_iana = header_is_iana,
            .auth = auth,
            .apnic_erx_root = apnic_erx_root,
            .query_is_cidr_effective = query_is_cidr_effective,
            .seen_real_authoritative = seen_real_authoritative,
            .seen_apnic_iana_netblock = seen_apnic_iana_netblock,
            .seen_ripe_non_managed = seen_ripe_non_managed,
            .seen_afrinic_iana_blk = seen_afrinic_iana_blk,
            .seen_lacnic_unallocated = seen_lacnic_unallocated,
            .seen_arin_no_match_cidr = seen_arin_no_match_cidr,
            .visited = visited,
            .visited_count = visited_count,
            .next_host = next_host,
            .next_host_len = sizeof(next_host),
            .ref_explicit_allow_visited = ref_explicit_allow_visited,
            .allow_apnic_ambiguous_revisit = allow_apnic_ambiguous_revisit,
            .apnic_revisit_used = &apnic_revisit_used,
            .apnic_force_ip = apnic_force_ip,
            .allow_cycle_on_loop = allow_cycle_on_loop,
            .ni = &ni,
            .rir_cycle_exhausted = &rir_cycle_exhausted
        };
        if (wc_lookup_exec_guard_loop(&guard_loop_ctx)) {
            break;
        }

        // insert heading for the upcoming hop
        if (emit_redirect_headers) {
            char hdr[256];
            if (!additional_emitted) {
                snprintf(hdr, sizeof(hdr), "\n=== Additional query to %s ===\n", next_host);
                additional_emitted = 1;
            } else {
                snprintf(hdr, sizeof(hdr), "\n=== Redirected query to %s ===\n", next_host);
            }
            combined = append_and_free(combined, hdr);
        }

        // advance to next
        snprintf(current_host, sizeof(current_host), "%s", next_host);
        current_port = next_port;
        force_original_query = force_original_next;
        // continue loop for next hop
    }
    {
        struct wc_lookup_exec_finalize_ctx finalize_ctx = {
            .out = out,
            .q = q,
            .zopts = &zopts,
            .cfg = cfg,
            .net_ctx = net_ctx,
            .start_host = start_host,
            .start_label = start_label,
            .current_host = current_host,
            .combined = combined,
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
            .cidr_base_query = cidr_base_query,
            .visited = visited,
            .visited_count = visited_count,
            .failure_emitted = failure_emitted,
            .last_failure_host = last_failure_host,
            .last_failure_host_len = sizeof(last_failure_host),
            .last_failure_ip = last_failure_ip,
            .last_failure_ip_len = sizeof(last_failure_ip),
            .last_failure_rir = last_failure_rir,
            .last_failure_rir_len = sizeof(last_failure_rir),
            .last_failure_status = last_failure_status,
            .last_failure_desc = last_failure_desc
        };
        wc_lookup_exec_finalize(&finalize_ctx);
        combined = finalize_ctx.combined;
        failure_emitted = finalize_ctx.failure_emitted;
    }

    if (cidr_base_query) {
        free(cidr_base_query);
        cidr_base_query = NULL;
    }

    if (arin_cidr_retry_query) {
        free(arin_cidr_retry_query);
        arin_cidr_retry_query = NULL;
    }

    // free visited list
    for (int i=0;i<16;i++) { if (visited[i]) free(visited[i]); }
    // defensive: free candidates if still allocated
    // (should be NULL unless we broke early before advancing)
    // candidates is local to the loop, but in case of refactor keep this safe-guard here

    // If there is a non-zero error code (e.g., connection failure during the redirection phase), 
    // even if some output has already been accumulated, a failure should be returned to allow the frontend to print the error.
    if (out->err) return out->err;
    return (out->body ? 0 : -1);
}

