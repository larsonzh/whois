// SPDX-License-Identifier: MIT
// lookup_exec_post.c - Post-loop finalize and cleanup

#include <stdlib.h>

#include "lookup_exec_finalize.h"
#include "lookup_exec_post.h"

int wc_lookup_exec_post_finalize(struct wc_lookup_exec_post_ctx* ctx)
{
    if (!ctx || !ctx->out) {
        return -1;
    }

    struct wc_lookup_exec_finalize_ctx finalize_ctx = {
        .out = ctx->out,
        .q = ctx->q,
        .zopts = ctx->zopts,
        .cfg = ctx->cfg,
        .net_ctx = ctx->net_ctx,
        .start_host = ctx->start_host,
        .start_label = ctx->start_label,
        .current_host = ctx->current_host,
        .combined = ctx->combined ? *ctx->combined : NULL,
        .redirect_cap_hit = ctx->redirect_cap_hit,
        .last_hop_authoritative = ctx->last_hop_authoritative,
        .last_hop_need_redirect = ctx->last_hop_need_redirect,
        .last_hop_has_ref = ctx->last_hop_has_ref,
        .apnic_erx_root = ctx->apnic_erx_root,
        .apnic_erx_seen_arin = ctx->apnic_erx_seen_arin,
        .apnic_redirect_is_erx = ctx->apnic_redirect_is_erx,
        .erx_marker_seen = ctx->erx_marker_seen,
        .rir_cycle_exhausted = ctx->rir_cycle_exhausted,
        .saw_rate_limit_or_denied = ctx->saw_rate_limit_or_denied,
        .erx_baseline_recheck_attempted = ctx->erx_baseline_recheck_attempted,
        .erx_marker_host = ctx->erx_marker_host,
        .erx_marker_ip = ctx->erx_marker_ip,
        .apnic_erx_root_host = ctx->apnic_erx_root_host,
        .apnic_erx_root_ip = ctx->apnic_erx_root_ip,
        .apnic_last_ip = ctx->apnic_last_ip,
        .query_is_cidr_effective = ctx->query_is_cidr_effective,
        .cidr_base_query = ctx->cidr_base_query ? *ctx->cidr_base_query : NULL,
        .visited = ctx->visited,
        .visited_count = ctx->visited_count,
        .failure_emitted = ctx->failure_emitted ? *ctx->failure_emitted : 0,
        .last_failure_host = ctx->last_failure_host,
        .last_failure_host_len = ctx->last_failure_host_len,
        .last_failure_ip = ctx->last_failure_ip,
        .last_failure_ip_len = ctx->last_failure_ip_len,
        .last_failure_rir = ctx->last_failure_rir,
        .last_failure_rir_len = ctx->last_failure_rir_len,
        .last_failure_status = ctx->last_failure_status,
        .last_failure_desc = ctx->last_failure_desc
    };
    wc_lookup_exec_finalize(&finalize_ctx);

    if (ctx->combined) {
        *ctx->combined = finalize_ctx.combined;
    }
    if (ctx->failure_emitted) {
        *ctx->failure_emitted = finalize_ctx.failure_emitted;
    }

    if (ctx->cidr_base_query && *ctx->cidr_base_query) {
        free(*ctx->cidr_base_query);
        *ctx->cidr_base_query = NULL;
    }
    if (ctx->arin_cidr_retry_query && *ctx->arin_cidr_retry_query) {
        free(*ctx->arin_cidr_retry_query);
        *ctx->arin_cidr_retry_query = NULL;
    }

    if (ctx->visited && ctx->visited_len > 0) {
        for (int i = 0; i < ctx->visited_len; ++i) {
            if (ctx->visited[i]) {
                free(ctx->visited[i]);
                ctx->visited[i] = NULL;
            }
        }
    }

    if (ctx->out->err) {
        return ctx->out->err;
    }
    return (ctx->out->body ? 0 : -1);
}
