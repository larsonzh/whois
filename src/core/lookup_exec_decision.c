// SPDX-License-Identifier: MIT
// lookup_exec_decision.c - Redirect and next-hop decision helpers

#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "wc/wc_dns.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"
#include "wc/wc_server.h"
#include "wc/wc_selftest.h"
#include "lookup_internal.h"
#include "lookup_exec_constants.h"
#include "lookup_exec_referral.h"
#include "lookup_exec_redirect.h"
#include "lookup_exec_next.h"
#include "lookup_exec_decision.h"

void wc_lookup_exec_decide_next(struct wc_lookup_exec_decision_ctx* ctx)
{
    if (!ctx || !ctx->body || !ctx->auth) {
        return;
    }

    const char* current_rir_guess = wc_guess_rir(ctx->current_host);
    if (ctx->current_rir_guess) {
        *ctx->current_rir_guess = current_rir_guess;
    }
    if (!*ctx->body) {
        return;
    }
    if (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 &&
        ctx->apnic_erx_root && !*ctx->apnic_erx_root && ctx->apnic_erx_arin_before_apnic) {
        *ctx->apnic_erx_arin_before_apnic = 1;
    }

    int is_gtld_registry = (strcasecmp(ctx->current_host, "whois.verisign-grs.com") == 0 ||
                            strcasecmp(ctx->current_host, "whois.crsnic.net") == 0 ||
                            (current_rir_guess && strcasecmp(current_rir_guess, "verisign") == 0));

    int need_redir_eval = (!is_gtld_registry) ? needs_redirect(*ctx->body) : 0;
    if (ctx->need_redir_eval) {
        *ctx->need_redir_eval = need_redir_eval;
    }

    const char* header_host = NULL;
    int header_is_iana = 0;
    if (ctx->header_host) {
        *ctx->header_host = header_host;
    }
    if (ctx->header_is_iana) {
        *ctx->header_is_iana = header_is_iana;
    }

    int ripe_non_managed = wc_lookup_body_contains_ripe_non_managed(*ctx->body);
    int access_denied = wc_lookup_body_contains_access_denied(*ctx->body);
    int rate_limited = wc_lookup_body_contains_rate_limit(*ctx->body);

    char* ref = NULL;
    int ref_port = 0;
    if (ctx->ref_host && ctx->ref_host_len > 0) {
        ctx->ref_host[0] = '\0';
    }

    if (!is_gtld_registry) {
        ref = extract_refer_server(*ctx->body);
        if (!ref) {
            ref = wc_lookup_extract_referral_fallback(*ctx->body);
        }
    }

    if (ref) {
        int ref_parse_rc = wc_lookup_parse_referral_target(ref,
                                                           ctx->ref_host,
                                                           ctx->ref_host_len,
                                                           &ref_port);
        if (wc_lookup_exec_referral_fallback(ref,
                                             ctx->ref_host,
                                             ctx->ref_host_len,
                                             &ref_port,
                                             ref_parse_rc) != 0) {
            if (ref_parse_rc != 0 || !ctx->ref_host || ctx->ref_host[0] == '\0') {
                free(ref);
                ref = NULL;
            }
        } else {
            ref_parse_rc = 0;
        }
    }

    if (ctx->ref) {
        *ctx->ref = ref;
    }
    if (ctx->ref_port) {
        *ctx->ref_port = ref_port;
    }

    int ref_explicit = 0;
    int apnic_erx_keep_ref = 0;
    if (ctx->header_hint_host && ctx->header_hint_host_len > 0) {
        ctx->header_hint_host[0] = '\0';
    }
    if (ctx->header_hint_valid) {
        *ctx->header_hint_valid = 0;
    }
    if (ctx->allow_cycle_on_loop) {
        *ctx->allow_cycle_on_loop = 0;
    }
    if (ctx->need_redir) {
        *ctx->need_redir = 0;
    }
    if (ctx->force_stop_authoritative) {
        *ctx->force_stop_authoritative = 0;
    }
    if (ctx->apnic_erx_suppress_current) {
        *ctx->apnic_erx_suppress_current = 0;
    }

    struct wc_lookup_exec_referral_ctx referral_ctx = {
        .current_host = ctx->current_host,
        .current_rir_guess = current_rir_guess,
        .body = *ctx->body,
        .ripe_non_managed = ripe_non_managed,
        .apnic_erx_root = ctx->apnic_erx_root ? *ctx->apnic_erx_root : 0,
        .apnic_redirect_reason = ctx->apnic_redirect_reason ? *ctx->apnic_redirect_reason : 0,
        .apnic_erx_legacy = ctx->apnic_erx_legacy ? *ctx->apnic_erx_legacy : 0,
        .apnic_erx_ripe_non_managed = ctx->apnic_erx_ripe_non_managed ? *ctx->apnic_erx_ripe_non_managed : 0,
        .apnic_erx_arin_before_apnic = ctx->apnic_erx_arin_before_apnic ? *ctx->apnic_erx_arin_before_apnic : 0,
        .visited = ctx->visited,
        .visited_count = ctx->visited_count,
        .ref = ctx->ref,
        .ref_host = ctx->ref_host,
        .ref_host_len = ctx->ref_host_len,
        .ref_explicit = &ref_explicit,
        .apnic_erx_keep_ref = &apnic_erx_keep_ref,
        .apnic_erx_ref_host = ctx->apnic_erx_ref_host,
        .apnic_erx_ref_host_len = ctx->apnic_erx_ref_host_len,
        .apnic_erx_stop = ctx->apnic_erx_stop,
        .apnic_erx_stop_host = ctx->apnic_erx_stop_host,
        .apnic_erx_stop_host_len = ctx->apnic_erx_stop_host_len,
        .apnic_erx_seen_arin = ctx->apnic_erx_seen_arin,
        .apnic_erx_target_rir = ctx->apnic_erx_target_rir,
        .apnic_erx_target_rir_len = ctx->apnic_erx_target_rir_len
    };
    wc_lookup_exec_referral_parse(&referral_ctx);

    if (ctx->ref_explicit) {
        *ctx->ref_explicit = ref_explicit;
    }
    if (ctx->apnic_erx_keep_ref) {
        *ctx->apnic_erx_keep_ref = apnic_erx_keep_ref;
    }

    int header_non_authoritative = 0;
    struct wc_lookup_exec_redirect_ctx redir_ctx = {
        .zopts = ctx->zopts,
        .cfg = ctx->cfg,
        .net_ctx = ctx->net_ctx,
        .ni = ctx->ni,
        .body = *ctx->body,
        .auth = ctx->auth,
        .current_host = ctx->current_host,
        .current_rir_guess = current_rir_guess,
        .hops = ctx->hops,
        .current_port = ctx->current_port,
        .query_is_cidr = ctx->query_is_cidr,
        .query_is_cidr_effective = ctx->query_is_cidr_effective,
        .cidr_base_query = ctx->cidr_base_query,
        .ripe_non_managed = ripe_non_managed,
        .access_denied = access_denied,
        .rate_limited = rate_limited,
        .need_redir_eval = ctx->need_redir_eval,
        .force_rir_cycle = ctx->force_rir_cycle,
        .stop_with_header_authority = ctx->stop_with_header_authority,
        .header_authority_host = ctx->header_authority_host,
        .header_authority_host_len = ctx->header_authority_host_len,
        .header_hint_host = ctx->header_hint_host,
        .header_hint_host_len = ctx->header_hint_host_len,
        .header_hint_valid = ctx->header_hint_valid,
        .header_host = ctx->header_host,
        .header_is_iana = ctx->header_is_iana,
        .header_non_authoritative = &header_non_authoritative,
        .allow_cycle_on_loop = ctx->allow_cycle_on_loop,
        .need_redir = ctx->need_redir,
        .force_stop_authoritative = ctx->force_stop_authoritative,
        .apnic_erx_suppress_current = ctx->apnic_erx_suppress_current,
        .last_hop_authoritative = ctx->last_hop_authoritative,
        .last_hop_need_redirect = ctx->last_hop_need_redirect,
        .last_hop_has_ref = ctx->last_hop_has_ref,
        .saw_rate_limit_or_denied = ctx->saw_rate_limit_or_denied,
        .last_failure_host = ctx->last_failure_host,
        .last_failure_host_len = ctx->last_failure_host_len,
        .last_failure_ip = ctx->last_failure_ip,
        .last_failure_ip_len = ctx->last_failure_ip_len,
        .last_failure_rir = ctx->last_failure_rir,
        .last_failure_rir_len = ctx->last_failure_rir_len,
        .last_failure_status = ctx->last_failure_status,
        .last_failure_desc = ctx->last_failure_desc,
        .seen_real_authoritative = ctx->seen_real_authoritative,
        .seen_apnic_iana_netblock = ctx->seen_apnic_iana_netblock,
        .seen_ripe_non_managed = ctx->seen_ripe_non_managed,
        .seen_afrinic_iana_blk = ctx->seen_afrinic_iana_blk,
        .seen_arin_no_match_cidr = ctx->seen_arin_no_match_cidr,
        .seen_lacnic_unallocated = ctx->seen_lacnic_unallocated,
        .apnic_erx_root = ctx->apnic_erx_root,
        .apnic_redirect_reason = ctx->apnic_redirect_reason,
        .apnic_erx_ripe_non_managed = ctx->apnic_erx_ripe_non_managed,
        .apnic_erx_arin_before_apnic = ctx->apnic_erx_arin_before_apnic,
        .apnic_erx_ref_host = ctx->apnic_erx_ref_host,
        .apnic_erx_ref_host_len = ctx->apnic_erx_ref_host_len,
        .apnic_erx_stop = ctx->apnic_erx_stop,
        .apnic_erx_stop_host = ctx->apnic_erx_stop_host,
        .apnic_erx_stop_host_len = ctx->apnic_erx_stop_host_len,
        .apnic_erx_target_rir = ctx->apnic_erx_target_rir,
        .apnic_erx_target_rir_len = ctx->apnic_erx_target_rir_len,
        .apnic_erx_seen_arin = ctx->apnic_erx_seen_arin,
        .apnic_erx_root_host = ctx->apnic_erx_root_host,
        .apnic_erx_root_host_len = ctx->apnic_erx_root_host_len,
        .apnic_erx_root_ip = ctx->apnic_erx_root_ip,
        .apnic_erx_root_ip_len = ctx->apnic_erx_root_ip_len,
        .apnic_erx_stop_unknown = ctx->apnic_erx_stop_unknown,
        .apnic_erx_authoritative_stop = ctx->apnic_erx_authoritative_stop,
        .apnic_erx_keep_ref = &apnic_erx_keep_ref,
        .apnic_iana_netblock_cidr = ctx->apnic_iana_netblock_cidr,
        .apnic_erx_legacy = ctx->apnic_erx_legacy,
        .apnic_last_ip = ctx->apnic_last_ip,
        .apnic_last_ip_len = ctx->apnic_last_ip_len,
        .apnic_ambiguous_revisit_used = ctx->apnic_ambiguous_revisit_used,
        .erx_marker_seen = ctx->erx_marker_seen,
        .erx_marker_host = ctx->erx_marker_host,
        .erx_marker_host_len = ctx->erx_marker_host_len,
        .erx_marker_ip = ctx->erx_marker_ip,
        .erx_marker_ip_len = ctx->erx_marker_ip_len,
        .erx_baseline_recheck_attempted = ctx->erx_baseline_recheck_attempted,
        .erx_fast_recheck_done = ctx->erx_fast_recheck_done,
        .erx_fast_authoritative = ctx->erx_fast_authoritative,
        .erx_fast_authoritative_host = ctx->erx_fast_authoritative_host,
        .erx_fast_authoritative_host_len = ctx->erx_fast_authoritative_host_len,
        .erx_fast_authoritative_ip = ctx->erx_fast_authoritative_ip,
        .erx_fast_authoritative_ip_len = ctx->erx_fast_authoritative_ip_len,
        .ref = ctx->ref,
        .ref_host = ctx->ref_host,
        .ref_host_len = ctx->ref_host_len,
        .ref_port = ctx->ref_port,
        .ref_explicit = &ref_explicit,
        .visited = ctx->visited,
        .visited_count = ctx->visited_count,
        .persistent_empty = ctx->persistent_empty
    };
    wc_lookup_exec_eval_redirect(&redir_ctx);
    if (ctx->body) {
        *ctx->body = redir_ctx.body;
    }

    struct wc_lookup_exec_next_ctx next_ctx = {
        .zopts = ctx->zopts,
        .cfg = ctx->cfg,
        .net_ctx = ctx->net_ctx,
        .fault_profile = ctx->fault_profile,
        .current_host = ctx->current_host,
        .current_rir_guess = current_rir_guess,
        .current_port = ctx->current_port,
        .body = *ctx->body,
        .hops = ctx->hops,
        .auth = *ctx->auth,
        .need_redir_eval = ctx->need_redir_eval ? *ctx->need_redir_eval : need_redir_eval,
        .header_hint_valid = ctx->header_hint_valid ? *ctx->header_hint_valid : 0,
        .header_hint_host = ctx->header_hint_host,
        .allow_cycle_on_loop = ctx->allow_cycle_on_loop ? *ctx->allow_cycle_on_loop : 0,
        .force_stop_authoritative = ctx->force_stop_authoritative ? *ctx->force_stop_authoritative : 0,
        .force_rir_cycle = ctx->force_rir_cycle ? *ctx->force_rir_cycle : 0,
        .apnic_erx_root = ctx->apnic_erx_root ? *ctx->apnic_erx_root : 0,
        .apnic_redirect_reason = ctx->apnic_redirect_reason ? *ctx->apnic_redirect_reason : 0,
        .apnic_erx_authoritative_stop = ctx->apnic_erx_authoritative_stop ? *ctx->apnic_erx_authoritative_stop : 0,
        .apnic_erx_legacy = ctx->apnic_erx_legacy ? *ctx->apnic_erx_legacy : 0,
        .erx_fast_authoritative = ctx->erx_fast_authoritative ? *ctx->erx_fast_authoritative : 0,
        .apnic_erx_ripe_non_managed = ctx->apnic_erx_ripe_non_managed ? *ctx->apnic_erx_ripe_non_managed : 0,
        .ref = ctx->ref ? *ctx->ref : NULL,
        .ref_host = ctx->ref_host,
        .ref_port = ctx->ref_port ? *ctx->ref_port : 0,
        .ref_explicit = ref_explicit,
        .combined = ctx->combined,
        .fallback_flags = ctx->fallback_flags,
        .pref_label = ctx->pref_label,
        .visited = ctx->visited,
        .visited_count = ctx->visited_count,
        .apnic_ambiguous_revisit_used = ctx->apnic_ambiguous_revisit_used,
        .stop_with_apnic_authority = ctx->stop_with_apnic_authority,
        .rir_cycle_exhausted = ctx->rir_cycle_exhausted,
        .apnic_erx_ref_host = ctx->apnic_erx_ref_host,
        .apnic_erx_ref_host_len = ctx->apnic_erx_ref_host_len,
        .next_host = ctx->next_host,
        .next_host_len = ctx->next_host_len,
        .have_next = ctx->have_next,
        .next_port = ctx->next_port,
        .ref_explicit_allow_visited = ctx->ref_explicit_allow_visited
    };
    wc_lookup_exec_pick_next_hop(&next_ctx);
}
