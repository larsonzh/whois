// SPDX-License-Identifier: MIT
// lookup_exec_authority.c - Authority tail handling for lookup exec

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

#include "wc/wc_dns.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "lookup_internal.h"
#include "lookup_exec_authority.h"

static void wc_lookup_exec_free_ref(char** ref)
{
    if (ref && *ref) {
        free(*ref);
        *ref = NULL;
    }
}

int wc_lookup_exec_check_authority(struct wc_lookup_exec_authority_ctx* ctx)
{
    if (!ctx || !ctx->out || !ctx->zopts || !ctx->ni) {
        return 0;
    }

    if (ctx->stop_with_header_authority && ctx->header_authority_host && ctx->header_authority_host[0]) {
        snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", ctx->header_authority_host);
        const char* known_ip = wc_dns_get_known_ip(ctx->header_authority_host);
        snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
            (known_ip && known_ip[0]) ? known_ip : "unknown");
        wc_lookup_exec_free_ref(ctx->ref);
        return 1;
    }

    if (ctx->stop_with_apnic_authority) {
        const char* apnic_host = "whois.apnic.net";
        snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", apnic_host);
        if (ctx->apnic_last_ip && ctx->apnic_last_ip[0] && wc_lookup_ip_matches_host(ctx->apnic_last_ip, apnic_host)) {
            snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", ctx->apnic_last_ip);
        } else {
            const char* known_apnic_ip = wc_dns_get_known_ip(apnic_host);
            snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                (known_apnic_ip && known_apnic_ip[0]) ? known_apnic_ip : "unknown");
        }
        wc_lookup_exec_free_ref(ctx->ref);
        return 1;
    }

    if (ctx->apnic_erx_stop && ctx->apnic_erx_stop_host && ctx->apnic_erx_stop_host[0]) {
        if (ctx->apnic_erx_stop_unknown) {
            const char* apnic_host = (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host[0])
                ? ctx->apnic_erx_root_host
                : "whois.apnic.net";
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", apnic_host);
            if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip[0]) {
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", ctx->apnic_erx_root_ip);
            } else {
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", "unknown");
            }
        } else {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", ctx->apnic_erx_stop_host);
            if (ctx->current_host && strcasecmp(ctx->current_host, ctx->apnic_erx_stop_host) == 0 && ctx->ni->ip[0]) {
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", ctx->ni->ip);
            } else if (ctx->out->meta.via_host[0] && strcasecmp(ctx->out->meta.via_host, ctx->apnic_erx_stop_host) == 0 &&
                ctx->out->meta.via_ip[0]) {
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", ctx->out->meta.via_ip);
            } else {
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", "unknown");
            }
        }
        wc_lookup_exec_free_ref(ctx->ref);
        return 1;
    }

    if (ctx->zopts->no_redirect) {
        // Treat no-redirect as an explicit cap: identical to -R 1 semantics.
        ctx->out->meta.fallback_flags |= 0x10; // redirect-cap
        if (ctx->have_next) {
            if (ctx->redirect_cap_hit) {
                *ctx->redirect_cap_hit = 1;
            }
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
            snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", "unknown");
        } else {
            if (ctx->auth) {
                // No further hop; treat current as authoritative
                const char* header_canon = (!ctx->header_is_iana && ctx->header_host)
                    ? wc_dns_canonical_alias(ctx->header_host)
                    : NULL;
                const char* auth_host = header_canon
                    ? header_canon
                    : wc_dns_canonical_alias(ctx->current_host);
                snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s",
                    auth_host ? auth_host : ctx->current_host);
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                    ctx->ni->ip[0] ? ctx->ni->ip : "unknown");
            } else {
                snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", "unknown");
            }
        }
        wc_lookup_exec_free_ref(ctx->ref);
        return 1;
    }

    if (ctx->auth && !ctx->need_redir && (!ctx->ref || !*ctx->ref)) {
        if (ctx->erx_fast_authoritative) {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s",
                ctx->erx_fast_authoritative_host && ctx->erx_fast_authoritative_host[0]
                    ? ctx->erx_fast_authoritative_host
                    : ctx->current_host);
            if (ctx->erx_fast_authoritative_ip && ctx->erx_fast_authoritative_ip[0]) {
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                    ctx->erx_fast_authoritative_ip);
            } else {
                const char* known_ip = wc_dns_get_known_ip(ctx->current_host);
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                    (known_ip && known_ip[0]) ? known_ip : "unknown");
            }
            wc_lookup_exec_free_ref(ctx->ref);
            return 1;
        }
        int apnic_erx_continue = 0;
        if (ctx->apnic_erx_root && ctx->current_rir_guess) {
            if (strcasecmp(ctx->current_rir_guess, "ripe") == 0 && ctx->apnic_erx_ripe_non_managed) {
                apnic_erx_continue = 1;
            } else if (strcasecmp(ctx->current_rir_guess, "apnic") == 0 && ctx->apnic_erx_legacy) {
                apnic_erx_continue = 1;
            }
        }
        if (!apnic_erx_continue) {
            // Current server appears authoritative; stop following to avoid redundant self-redirects
            const char* header_canon = (!ctx->header_is_iana && ctx->header_host)
                ? wc_dns_canonical_alias(ctx->header_host)
                : NULL;
            const char* auth_host = header_canon
                ? header_canon
                : wc_dns_canonical_alias(ctx->current_host);
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s",
                auth_host ? auth_host : ctx->current_host);
            snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                ctx->ni->ip[0] ? ctx->ni->ip : "unknown");
            wc_lookup_exec_free_ref(ctx->ref);
            return 1;
        }
    }

    return 0;
}
