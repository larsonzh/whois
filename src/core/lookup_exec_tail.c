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

static struct wc_lookup_exec_authority_ctx wc_lookup_exec_make_authority_ctx(
    struct wc_lookup_exec_tail_ctx* ctx)
{
    struct wc_lookup_exec_authority_ctx authority_ctx = {0};

    authority_ctx.out = ctx->out;
    authority_ctx.zopts = ctx->zopts;
    authority_ctx.ni = ctx->ni;
    authority_ctx.current_host = ctx->current_host;
    authority_ctx.current_rir_guess = ctx->current_rir_guess;
    authority_ctx.header_authority_host = ctx->header_authority_host;
    authority_ctx.header_host = ctx->header_host;
    authority_ctx.header_is_iana = ctx->header_is_iana;
    authority_ctx.stop_with_header_authority = ctx->stop_with_header_authority;
    authority_ctx.stop_with_apnic_authority = ctx->stop_with_apnic_authority;
    authority_ctx.apnic_erx_stop = ctx->apnic_erx_stop;
    authority_ctx.apnic_erx_stop_unknown = ctx->apnic_erx_stop_unknown;
    authority_ctx.apnic_erx_root_host = ctx->apnic_erx_root_host;
    authority_ctx.apnic_erx_root_ip = ctx->apnic_erx_root_ip;
    authority_ctx.apnic_erx_stop_host = ctx->apnic_erx_stop_host;
    authority_ctx.apnic_last_ip = ctx->apnic_last_ip;
    authority_ctx.apnic_erx_root = ctx->apnic_erx_root;
    authority_ctx.apnic_erx_ripe_non_managed = ctx->apnic_erx_ripe_non_managed;
    authority_ctx.apnic_erx_legacy = ctx->apnic_erx_legacy;
    authority_ctx.seen_real_authoritative = ctx->seen_real_authoritative;
    authority_ctx.seen_apnic_iana_netblock = ctx->seen_apnic_iana_netblock;
    authority_ctx.seen_ripe_non_managed = ctx->seen_ripe_non_managed;
    authority_ctx.seen_afrinic_iana_blk = ctx->seen_afrinic_iana_blk;
    authority_ctx.seen_lacnic_unallocated = ctx->seen_lacnic_unallocated;
    authority_ctx.seen_arin_no_match_cidr = ctx->seen_arin_no_match_cidr;
    authority_ctx.query_is_cidr_effective = ctx->query_is_cidr_effective;
    authority_ctx.auth = ctx->auth;
    authority_ctx.need_redir = ctx->need_redir;
    authority_ctx.have_next = ctx->have_next;
    authority_ctx.erx_fast_authoritative = ctx->erx_fast_authoritative;
    authority_ctx.erx_fast_authoritative_host = ctx->erx_fast_authoritative_host;
    authority_ctx.erx_fast_authoritative_ip = ctx->erx_fast_authoritative_ip;
    authority_ctx.redirect_cap_hit = ctx->redirect_cap_hit;
    authority_ctx.ref = ctx->ref;

    return authority_ctx;
}

static struct wc_lookup_exec_guard_no_next_ctx wc_lookup_exec_make_guard_no_next_ctx(
    struct wc_lookup_exec_tail_ctx* ctx)
{
    struct wc_lookup_exec_guard_no_next_ctx guard_no_next_ctx = {0};

    guard_no_next_ctx.out = ctx->out;
    guard_no_next_ctx.current_host = ctx->current_host;
    guard_no_next_ctx.current_rir_guess = ctx->current_rir_guess;
    guard_no_next_ctx.header_host = ctx->header_host;
    guard_no_next_ctx.header_is_iana = ctx->header_is_iana;
    guard_no_next_ctx.auth = ctx->auth;
    guard_no_next_ctx.apnic_erx_root = ctx->apnic_erx_root;
    guard_no_next_ctx.query_is_cidr_effective = ctx->query_is_cidr_effective;
    guard_no_next_ctx.seen_real_authoritative = ctx->seen_real_authoritative;
    guard_no_next_ctx.seen_apnic_iana_netblock = ctx->seen_apnic_iana_netblock;
    guard_no_next_ctx.seen_ripe_non_managed = ctx->seen_ripe_non_managed;
    guard_no_next_ctx.seen_afrinic_iana_blk = ctx->seen_afrinic_iana_blk;
    guard_no_next_ctx.seen_lacnic_unallocated = ctx->seen_lacnic_unallocated;
    guard_no_next_ctx.seen_arin_no_match_cidr = ctx->seen_arin_no_match_cidr;
    guard_no_next_ctx.have_next = &ctx->have_next;
    guard_no_next_ctx.next_host = ctx->next_host;
    guard_no_next_ctx.next_host_len = ctx->next_host_len;
    guard_no_next_ctx.visited = ctx->visited;
    guard_no_next_ctx.visited_count = ctx->visited_count;
    guard_no_next_ctx.pref_label = ctx->pref_label;
    guard_no_next_ctx.net_ctx = ctx->net_ctx;
    guard_no_next_ctx.cfg = ctx->cfg;
    guard_no_next_ctx.ni = ctx->ni;
    guard_no_next_ctx.rir_cycle_exhausted = ctx->rir_cycle_exhausted;

    return guard_no_next_ctx;
}

static struct wc_lookup_exec_guard_loop_ctx wc_lookup_exec_make_guard_loop_ctx(
    struct wc_lookup_exec_tail_ctx* ctx)
{
    struct wc_lookup_exec_guard_loop_ctx guard_loop_ctx = {0};

    guard_loop_ctx.out = ctx->out;
    guard_loop_ctx.current_host = ctx->current_host;
    guard_loop_ctx.current_rir_guess = ctx->current_rir_guess;
    guard_loop_ctx.start_host = ctx->start_host;
    guard_loop_ctx.header_host = ctx->header_host;
    guard_loop_ctx.header_is_iana = ctx->header_is_iana;
    guard_loop_ctx.auth = ctx->auth;
    guard_loop_ctx.apnic_erx_root = ctx->apnic_erx_root;
    guard_loop_ctx.query_is_cidr_effective = ctx->query_is_cidr_effective;
    guard_loop_ctx.seen_real_authoritative = ctx->seen_real_authoritative;
    guard_loop_ctx.seen_apnic_iana_netblock = ctx->seen_apnic_iana_netblock;
    guard_loop_ctx.seen_ripe_non_managed = ctx->seen_ripe_non_managed;
    guard_loop_ctx.seen_afrinic_iana_blk = ctx->seen_afrinic_iana_blk;
    guard_loop_ctx.seen_lacnic_unallocated = ctx->seen_lacnic_unallocated;
    guard_loop_ctx.seen_arin_no_match_cidr = ctx->seen_arin_no_match_cidr;
    guard_loop_ctx.visited = ctx->visited;
    guard_loop_ctx.visited_count = ctx->visited_count;
    guard_loop_ctx.next_host = ctx->next_host;
    guard_loop_ctx.next_host_len = ctx->next_host_len;
    guard_loop_ctx.ref_explicit_allow_visited = ctx->ref_explicit_allow_visited;
    guard_loop_ctx.allow_apnic_ambiguous_revisit = ctx->allow_apnic_ambiguous_revisit;
    guard_loop_ctx.apnic_revisit_used = ctx->apnic_revisit_used;
    guard_loop_ctx.apnic_force_ip = ctx->apnic_force_ip ? *ctx->apnic_force_ip : 0;
    guard_loop_ctx.allow_cycle_on_loop = ctx->allow_cycle_on_loop;
    guard_loop_ctx.ni = ctx->ni;
    guard_loop_ctx.rir_cycle_exhausted = ctx->rir_cycle_exhausted;

    return guard_loop_ctx;
}

static int wc_lookup_exec_run_redirect_cap_check(struct wc_lookup_exec_tail_ctx* ctx)
{
    if (!(ctx->have_next && ctx->hops >= ctx->zopts->max_hops)) {
        return 0;
    }

    if (ctx->redirect_cap_hit) {
        *ctx->redirect_cap_hit = 1;
    }
    ctx->out->meta.fallback_flags |= 0x10; // redirect-cap
    snprintf(ctx->out->meta.authoritative_host,
             sizeof(ctx->out->meta.authoritative_host),
             "%s",
             "unknown");
    snprintf(ctx->out->meta.authoritative_ip,
             sizeof(ctx->out->meta.authoritative_ip),
             "%s",
             "unknown");
    return 1;
}

static int wc_lookup_exec_run_tail_guard_loop_capture_check(
    struct wc_lookup_exec_tail_ctx* ctx,
    int* force_original_next)
{
    int computed_force_original_next =
        (ctx->arin_retry_active && ctx->have_next && ctx->query_is_cidr);
    if (ctx->have_next && ctx->query_is_cidr_effective && !computed_force_original_next) {
        const char* next_rir = wc_guess_rir(ctx->next_host);
        if (next_rir && strcasecmp(next_rir, "apnic") == 0 && ctx->apnic_force_ip) {
            *ctx->apnic_force_ip = 1;
        }
    }

    struct wc_lookup_exec_guard_loop_ctx guard_loop_check_ctx =
        wc_lookup_exec_make_guard_loop_ctx(ctx);

    if (wc_lookup_exec_guard_loop(&guard_loop_check_ctx)) {
        return 1;
    }

    if (force_original_next) {
        *force_original_next = computed_force_original_next;
    }
    return 0;
}

static int wc_lookup_exec_run_tail_pre_checks(
    struct wc_lookup_exec_tail_ctx* ctx)
{
    struct wc_lookup_exec_authority_ctx authority_check_ctx =
        wc_lookup_exec_make_authority_ctx(ctx);
    if (wc_lookup_exec_check_authority(&authority_check_ctx)) {
        return 1;
    }

    if (ctx->ref && *ctx->ref) {
        free(*ctx->ref);
        *ctx->ref = NULL;
    }

    struct wc_lookup_exec_guard_no_next_ctx guard_no_next_check_ctx =
        wc_lookup_exec_make_guard_no_next_ctx(ctx);
    if (wc_lookup_exec_guard_no_next(&guard_no_next_check_ctx)) {
        return 1;
    }

    if (ctx->have_next && ctx->auth && ctx->pending_referral) {
        *ctx->pending_referral = 1;
    }

    return wc_lookup_exec_run_redirect_cap_check(ctx);
}

static int wc_lookup_exec_run_tail_post_checks(
    struct wc_lookup_exec_tail_ctx* ctx)
{
    int next_state_force_original = 0;

    if (wc_lookup_exec_run_tail_guard_loop_capture_check(
            ctx,
            &next_state_force_original)) {
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
        *ctx->force_original_query = next_state_force_original;
    }

    return 0;
}

static int wc_lookup_exec_run_tail_checks_pipeline(
    struct wc_lookup_exec_tail_ctx* ctx)
{
    return wc_lookup_exec_run_tail_pre_checks(ctx) ||
           wc_lookup_exec_run_tail_post_checks(ctx);
}

static int wc_lookup_exec_is_tail_context_valid(
    const struct wc_lookup_exec_tail_ctx* ctx)
{
    return (ctx && ctx->out && ctx->zopts && ctx->ni) ? 1 : 0;
}

int wc_lookup_exec_handle_tail(struct wc_lookup_exec_tail_ctx* ctx)
{
    if (!wc_lookup_exec_is_tail_context_valid(ctx)) {
        return 0;
    }

    return wc_lookup_exec_run_tail_checks_pipeline(ctx);
}
