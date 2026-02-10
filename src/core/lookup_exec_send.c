// SPDX-License-Identifier: MIT
// lookup_exec_send.c - Query build/send for lookup exec

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "wc/wc_dns.h"
#include "wc/wc_net.h"
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"
#include "lookup_internal.h"
#include "lookup_exec_send.h"

int wc_lookup_exec_send_query(struct wc_lookup_exec_send_ctx* ctx)
{
    if (!ctx || !ctx->out || !ctx->q || !ctx->zopts || !ctx->cfg || !ctx->ni) {
        return -1;
    }

    int arin_retry_active = (ctx->arin_cidr_retry_query && *ctx->arin_cidr_retry_query != NULL);
    int query_is_cidr_hop = ctx->query_is_cidr_effective || ctx->use_original_query;
    int query_is_ip_literal_hop = ctx->query_is_ip_literal_effective;
    if (ctx->use_original_query) {
        query_is_ip_literal_hop = ctx->query_is_ip_literal;
    }

    const char* outbound_query = arin_retry_active ? *ctx->arin_cidr_retry_query : ctx->q->raw;
    if (!arin_retry_active && ctx->cfg->cidr_strip_query && ctx->cidr_base_query && !ctx->use_original_query) {
        outbound_query = ctx->cidr_base_query;
    }

    char* stripped_query = NULL;
    int query_has_arin_prefix_effective = ctx->query_has_arin_prefix || arin_retry_active;
    if (!arin_retry_active && !ctx->arin_host && query_has_arin_prefix_effective) {
        stripped_query = wc_lookup_strip_query_prefix(ctx->q->raw);
        if (stripped_query) {
            outbound_query = stripped_query;
        }
    }
    if (stripped_query && wc_lookup_should_trace_dns(ctx->net_ctx, ctx->cfg)) {
        fprintf(stderr,
            "[DNS-ARIN] action=strip-prefix host=%s query=%s stripped=%s\n",
            ctx->current_host, ctx->q->raw, stripped_query);
    }

    char* arin_prefixed_query = wc_lookup_arin_build_query(outbound_query,
        ctx->arin_host,
        query_is_ip_literal_hop,
        query_is_cidr_hop,
        ctx->query_is_asn,
        ctx->query_is_nethandle,
        query_has_arin_prefix_effective);
    if (arin_prefixed_query) {
        outbound_query = arin_prefixed_query;
    }

    size_t qlen = strlen(outbound_query);
    char* line = (char*)malloc(qlen + 3);
    if (!line) {
        if (arin_prefixed_query) {
            free(arin_prefixed_query);
        }
        if (stripped_query) {
            free(stripped_query);
        }
        ctx->out->err = -1;
        { int debug_enabled = ctx->cfg ? ctx->cfg->debug : 0; wc_safe_close(&ctx->ni->fd, "wc_lookup_malloc_fail", debug_enabled); }
        if (ctx->pending_referral && *ctx->pending_referral) {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        }
        return -1;
    }

    memcpy(line, outbound_query, qlen);
    line[qlen] = '\r';
    line[qlen + 1] = '\n';
    line[qlen + 2] = '\0';

    if (wc_signal_should_terminate()) {
        free(line);
        if (arin_prefixed_query) {
            free(arin_prefixed_query);
        }
        if (stripped_query) {
            free(stripped_query);
        }
        ctx->out->err = WC_ERR_IO;
        ctx->out->meta.last_connect_errno = EINTR;
        if (ctx->pending_referral && *ctx->pending_referral) {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        }
        { int debug_enabled = ctx->cfg ? ctx->cfg->debug : 0; wc_safe_close(&ctx->ni->fd, "wc_lookup_signal_abort", debug_enabled); }
        return -1;
    }

    if (wc_send_all(ctx->ni->fd, line, qlen + 2, ctx->zopts->timeout_sec * 1000) < 0) {
        free(line);
        if (arin_prefixed_query) {
            free(arin_prefixed_query);
        }
        if (stripped_query) {
            free(stripped_query);
        }
        ctx->out->err = -1;
        { int debug_enabled = ctx->cfg ? ctx->cfg->debug : 0; wc_safe_close(&ctx->ni->fd, "wc_lookup_send_fail", debug_enabled); }
        if (ctx->pending_referral && *ctx->pending_referral) {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        }
        return -1;
    }

    free(line);
    if (arin_prefixed_query) {
        free(arin_prefixed_query);
    }
    if (stripped_query) {
        free(stripped_query);
    }
    if (ctx->arin_cidr_retry_query && *ctx->arin_cidr_retry_query) {
        free(*ctx->arin_cidr_retry_query);
        *ctx->arin_cidr_retry_query = NULL;
    }

    return 0;
}
