// SPDX-License-Identifier: MIT
// lookup_exec_recv.c - Receive body for lookup exec

#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include "wc/wc_config.h"
#include "wc/wc_net.h"
#include "wc/wc_util.h"
#include "wc/wc_signal.h"
#include "wc/wc_lookup.h"
#include "lookup_exec_recv.h"

int wc_lookup_exec_recv_body(struct wc_lookup_exec_recv_ctx* ctx)
{
    if (!ctx || !ctx->out || !ctx->zopts || !ctx->cfg || !ctx->ni || !ctx->body || !ctx->blen) {
        return -1;
    }

    if (wc_signal_should_terminate()) {
        ctx->out->err = WC_ERR_IO;
        ctx->out->meta.last_connect_errno = EINTR;
        if (ctx->pending_referral && *ctx->pending_referral) {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        }
        { int debug_enabled = ctx->cfg ? ctx->cfg->debug : 0; wc_safe_close(&ctx->ni->fd, "wc_lookup_signal_abort", debug_enabled); }
        return -1;
    }

    int max_bytes = 65536;
    if (ctx->cfg->buffer_size > 0) {
        if (ctx->cfg->buffer_size > (size_t)INT_MAX) {
            max_bytes = INT_MAX;
        } else {
            max_bytes = (int)ctx->cfg->buffer_size;
        }
    }

    if (wc_recv_until_idle(ctx->ni->fd, ctx->body, ctx->blen, ctx->zopts->timeout_sec * 1000, max_bytes) < 0) {
        ctx->out->err = -1;
        { int debug_enabled = ctx->cfg ? ctx->cfg->debug : 0; wc_safe_close(&ctx->ni->fd, "wc_lookup_recv_fail", debug_enabled); }
        if (ctx->pending_referral && *ctx->pending_referral) {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        }
        return -1;
    }

    { int debug_enabled = ctx->cfg ? ctx->cfg->debug : 0; wc_safe_close(&ctx->ni->fd, "wc_lookup_recv_done", debug_enabled); }

    if (wc_signal_should_terminate()) {
        if (*ctx->body) {
            free(*ctx->body);
            *ctx->body = NULL;
        }
        *ctx->blen = 0;
        ctx->out->err = WC_ERR_IO;
        ctx->out->meta.last_connect_errno = EINTR;
        if (ctx->pending_referral && *ctx->pending_referral) {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        }
        return -1;
    }

    return 0;
}
