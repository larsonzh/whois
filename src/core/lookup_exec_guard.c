// SPDX-License-Identifier: MIT
// lookup_exec_guard.c - Loop guard helpers for lookup exec

#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "wc/wc_dns.h"
#include "wc/wc_lookup.h"
#include "lookup_internal.h"
#include "lookup_exec_guard.h"

static int wc_lookup_is_rir_cycle_root(const char* rir)
{
    return (rir && (strcasecmp(rir, "ripe") == 0 ||
                    strcasecmp(rir, "afrinic") == 0 ||
                    strcasecmp(rir, "lacnic") == 0));
}

int wc_lookup_exec_guard_no_next(struct wc_lookup_exec_guard_no_next_ctx* ctx)
{
    if (!ctx || !ctx->out || !ctx->have_next) {
        return 0;
    }

    if (!*ctx->have_next && ctx->apnic_erx_root && wc_lookup_is_rir_cycle_root(ctx->current_rir_guess)) {
        if (wc_lookup_rir_cycle_next(ctx->current_rir_guess, ctx->visited, ctx->visited_count,
                ctx->next_host, ctx->next_host_len)) {
            *ctx->have_next = 1;
            wc_lookup_log_fallback(ctx->out->meta.hops, "manual", "rir-cycle",
                                   ctx->current_host, ctx->next_host, "success",
                                   ctx->out->meta.fallback_flags, 0, -1,
                                   ctx->pref_label,
                                   ctx->net_ctx,
                                   ctx->cfg);
        } else if (ctx->rir_cycle_exhausted) {
            *ctx->rir_cycle_exhausted = 1;
        }
    }

    if (*ctx->have_next) {
        return 0;
    }

    {
        int non_auth_count = (ctx->seen_apnic_iana_netblock ? 1 : 0) + (ctx->seen_ripe_non_managed ? 1 : 0) +
                             (ctx->seen_afrinic_iana_blk ? 1 : 0) + (ctx->seen_lacnic_unallocated ? 1 : 0);

        if (ctx->apnic_erx_root && wc_lookup_is_rir_cycle_root(ctx->current_rir_guess)) {
            if (ctx->rir_cycle_exhausted) {
                *ctx->rir_cycle_exhausted = 1;
            }
            if (ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "lacnic") == 0 &&
                non_auth_count > 0 && !ctx->seen_lacnic_unallocated) {
                const char* auth_host = wc_dns_canonical_alias("whois.apnic.net");
                const char* auth_ip = wc_dns_get_known_ip("whois.apnic.net");
                snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s",
                         auth_host ? auth_host : "whois.apnic.net");
                snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                         (auth_ip && auth_ip[0]) ? auth_ip : "unknown");
            }
            return 1;
        }
    }

    if (ctx->auth) {
        const char* header_canon = (!ctx->header_is_iana && ctx->header_host)
            ? wc_dns_canonical_alias(ctx->header_host)
            : NULL;
        const char* auth_host = header_canon
            ? header_canon
            : wc_dns_canonical_alias(ctx->current_host);
        snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s",
                 auth_host ? auth_host : ctx->current_host);
        snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                 ctx->ni && ctx->ni->ip[0] ? ctx->ni->ip : "unknown");
    } else {
        snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
        snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", "unknown");
    }

    return 1;
}

int wc_lookup_exec_guard_loop(struct wc_lookup_exec_guard_loop_ctx* ctx)
{
    if (!ctx || !ctx->out || !ctx->next_host || !ctx->current_host) {
        return 0;
    }

    int loop = 0;
    for (int i = 0; i < ctx->visited_count; ++i) {
        if (strcasecmp(ctx->visited[i], ctx->next_host) == 0) {
            loop = 1;
            break;
        }
    }
    if (loop && ctx->ref_explicit_allow_visited) {
        loop = 0;
    }
    if (loop && ctx->allow_apnic_ambiguous_revisit &&
        strcasecmp(ctx->next_host, "whois.apnic.net") == 0) {
        loop = 0;
    }
    if (loop && ctx->apnic_revisit_used && !*ctx->apnic_revisit_used && ctx->apnic_force_ip &&
        strcasecmp(ctx->next_host, ctx->start_host) == 0) {
        loop = 0;
        *ctx->apnic_revisit_used = 1;
    }
    if (loop && ctx->allow_cycle_on_loop) {
        char cycle_host[128];
        cycle_host[0] = '\0';
        if (wc_lookup_rir_cycle_next(ctx->current_rir_guess, ctx->visited, ctx->visited_count,
                cycle_host, sizeof(cycle_host))) {
            if (strcasecmp(cycle_host, ctx->next_host) != 0) {
                snprintf(ctx->next_host, ctx->next_host_len, "%s", cycle_host);
                loop = 0;
            }
        }
    }

    if (loop || strcasecmp(ctx->next_host, ctx->current_host) == 0) {
        int non_auth_count = (ctx->seen_apnic_iana_netblock ? 1 : 0) + (ctx->seen_ripe_non_managed ? 1 : 0) +
                             (ctx->seen_afrinic_iana_blk ? 1 : 0) + (ctx->seen_lacnic_unallocated ? 1 : 0);
        if (ctx->apnic_erx_root &&
            ctx->current_rir_guess &&
            strcasecmp(ctx->current_rir_guess, "lacnic") == 0 &&
            non_auth_count > 0 && !ctx->seen_lacnic_unallocated) {
            const char* auth_host = wc_dns_canonical_alias("whois.apnic.net");
            const char* auth_ip = wc_dns_get_known_ip("whois.apnic.net");
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s",
                     auth_host ? auth_host : "whois.apnic.net");
            snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                     (auth_ip && auth_ip[0]) ? auth_ip : "unknown");
            return 1;
        }
        if (ctx->apnic_erx_root && ctx->rir_cycle_exhausted) {
            *ctx->rir_cycle_exhausted = 1;
        }
        if (ctx->auth) {
            const char* auth_host = (!ctx->header_is_iana && ctx->header_host)
                ? ctx->header_host
                : wc_dns_canonical_alias(ctx->current_host);
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s",
                     auth_host ? auth_host : ctx->current_host);
            snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s",
                     ctx->ni && ctx->ni->ip[0] ? ctx->ni->ip : "unknown");
        } else {
            snprintf(ctx->out->meta.authoritative_host, sizeof(ctx->out->meta.authoritative_host), "%s", "unknown");
            snprintf(ctx->out->meta.authoritative_ip, sizeof(ctx->out->meta.authoritative_ip), "%s", "unknown");
        }
        return 1;
    }

    return 0;
}
