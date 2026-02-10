// SPDX-License-Identifier: MIT
// lookup_exec_tail.c - Authority and guard tail handling

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

#include "wc/wc_lookup.h"
#include "wc/wc_dns.h"
#include "wc/wc_server.h"
#include "lookup_exec_authority.h"
#include "lookup_exec_guard.h"
#include "lookup_exec_append.h"
#include "lookup_exec_tail.h"

int wc_lookup_exec_handle_tail(struct wc_lookup_exec_tail_ctx* ctx)
{
    if (!ctx || !ctx->out || !ctx->zopts || !ctx->ni) {
        return 0;
    }

    struct wc_lookup_exec_authority_ctx authority_ctx = {
        .out = ctx->out,
        .zopts = ctx->zopts,
        .ni = ctx->ni,
        .current_host = ctx->current_host,
        .current_rir_guess = ctx->current_rir_guess,
        .header_authority_host = ctx->header_authority_host,
        .header_host = ctx->header_host,
        .header_is_iana = ctx->header_is_iana,
        .stop_with_header_authority = ctx->stop_with_header_authority,
        .stop_with_apnic_authority = ctx->stop_with_apnic_authority,
        .apnic_erx_stop = ctx->apnic_erx_stop,
        .apnic_erx_stop_unknown = ctx->apnic_erx_stop_unknown,
        .apnic_erx_root_host = ctx->apnic_erx_root_host,
        .apnic_erx_root_ip = ctx->apnic_erx_root_ip,
        .apnic_erx_stop_host = ctx->apnic_erx_stop_host,
        .apnic_last_ip = ctx->apnic_last_ip,
        .apnic_erx_root = ctx->apnic_erx_root,
        .apnic_erx_ripe_non_managed = ctx->apnic_erx_ripe_non_managed,
        .apnic_erx_legacy = ctx->apnic_erx_legacy,
        .seen_real_authoritative = ctx->seen_real_authoritative,
        .seen_apnic_iana_netblock = ctx->seen_apnic_iana_netblock,
        .seen_ripe_non_managed = ctx->seen_ripe_non_managed,
        .seen_afrinic_iana_blk = ctx->seen_afrinic_iana_blk,
        .seen_lacnic_unallocated = ctx->seen_lacnic_unallocated,
        .seen_arin_no_match_cidr = ctx->seen_arin_no_match_cidr,
        .query_is_cidr_effective = ctx->query_is_cidr_effective,
        .auth = ctx->auth,
        .need_redir = ctx->need_redir,
        .have_next = ctx->have_next,
        .erx_fast_authoritative = ctx->erx_fast_authoritative,
        .erx_fast_authoritative_host = ctx->erx_fast_authoritative_host,
        .erx_fast_authoritative_ip = ctx->erx_fast_authoritative_ip,
        .redirect_cap_hit = ctx->redirect_cap_hit,
        .ref = ctx->ref
    };
    if (wc_lookup_exec_check_authority(&authority_ctx)) {
        return 1;
    }

    if (ctx->ref && *ctx->ref) {
        free(*ctx->ref);
        *ctx->ref = NULL;
    }

    struct wc_lookup_exec_guard_no_next_ctx guard_no_next_ctx = {
        .out = ctx->out,
        .current_host = ctx->current_host,
        .current_rir_guess = ctx->current_rir_guess,
        .header_host = ctx->header_host,
        .header_is_iana = ctx->header_is_iana,
        .auth = ctx->auth,
        .apnic_erx_root = ctx->apnic_erx_root,
        .query_is_cidr_effective = ctx->query_is_cidr_effective,
        .seen_real_authoritative = ctx->seen_real_authoritative,
        .seen_apnic_iana_netblock = ctx->seen_apnic_iana_netblock,
        .seen_ripe_non_managed = ctx->seen_ripe_non_managed,
        .seen_afrinic_iana_blk = ctx->seen_afrinic_iana_blk,
        .seen_lacnic_unallocated = ctx->seen_lacnic_unallocated,
        .seen_arin_no_match_cidr = ctx->seen_arin_no_match_cidr,
        .have_next = &ctx->have_next,
        .next_host = ctx->next_host,
        .next_host_len = ctx->next_host_len,
        .visited = ctx->visited,
        .visited_count = ctx->visited_count,
        .pref_label = ctx->pref_label,
        .net_ctx = ctx->net_ctx,
        .cfg = ctx->cfg,
        .ni = ctx->ni,
        .rir_cycle_exhausted = ctx->rir_cycle_exhausted
    };
    if (wc_lookup_exec_guard_no_next(&guard_no_next_ctx)) {
        return 1;
    }

    if (ctx->have_next && ctx->auth && ctx->pending_referral) {
        *ctx->pending_referral = 1;
    }

    if (ctx->have_next && ctx->hops >= ctx->zopts->max_hops) {
        if (ctx->redirect_cap_hit) {
            *ctx->redirect_cap_hit = 1;
        }
        ctx->out->meta.fallback_flags |= 0x10; // redirect-cap
        snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", "unknown");
        return 1;
    }

    int force_original_next = (ctx->arin_retry_active && ctx->have_next && ctx->query_is_cidr);
    if (ctx->have_next && ctx->query_is_cidr_effective && !force_original_next) {
        const char* next_rir = wc_guess_rir(ctx->next_host);
        if (next_rir && strcasecmp(next_rir, "apnic") == 0 && ctx->apnic_force_ip) {
            *ctx->apnic_force_ip = 1;
        }
    }

    struct wc_lookup_exec_guard_loop_ctx guard_loop_ctx = {
        .out = ctx->out,
        .current_host = ctx->current_host,
        .current_rir_guess = ctx->current_rir_guess,
        .start_host = ctx->start_host,
        .header_host = ctx->header_host,
        .header_is_iana = ctx->header_is_iana,
        .auth = ctx->auth,
        .apnic_erx_root = ctx->apnic_erx_root,
        .query_is_cidr_effective = ctx->query_is_cidr_effective,
        .seen_real_authoritative = ctx->seen_real_authoritative,
        .seen_apnic_iana_netblock = ctx->seen_apnic_iana_netblock,
        .seen_ripe_non_managed = ctx->seen_ripe_non_managed,
        .seen_afrinic_iana_blk = ctx->seen_afrinic_iana_blk,
        .seen_lacnic_unallocated = ctx->seen_lacnic_unallocated,
        .seen_arin_no_match_cidr = ctx->seen_arin_no_match_cidr,
        .visited = ctx->visited,
        .visited_count = ctx->visited_count,
        .next_host = ctx->next_host,
        .next_host_len = ctx->next_host_len,
        .ref_explicit_allow_visited = ctx->ref_explicit_allow_visited,
        .allow_apnic_ambiguous_revisit = ctx->allow_apnic_ambiguous_revisit,
        .apnic_revisit_used = ctx->apnic_revisit_used,
        .apnic_force_ip = ctx->apnic_force_ip ? *ctx->apnic_force_ip : 0,
        .allow_cycle_on_loop = ctx->allow_cycle_on_loop,
        .ni = ctx->ni,
        .rir_cycle_exhausted = ctx->rir_cycle_exhausted
    };
    if (wc_lookup_exec_guard_loop(&guard_loop_ctx)) {
        return 1;
    }

    if (ctx->combined && ctx->additional_emitted) {
        wc_lookup_exec_append_redirect_header(ctx->combined,
                                              ctx->next_host,
                                              ctx->additional_emitted,
                                              ctx->emit_redirect_headers);
    }

    if (ctx->current_host && ctx->current_host_len > 0) {
        snprintf(ctx->current_host, ctx->current_host_len, "%s", ctx->next_host);
    }
    if (ctx->current_port && ctx->next_port) {
        *ctx->current_port = *ctx->next_port;
    }
    if (ctx->force_original_query) {
        *ctx->force_original_query = force_original_next;
    }

    return 0;
}
