// SPDX-License-Identifier: MIT
// lookup_exec_referral.c - Referral parsing for lookup exec

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

#include "wc/wc_dns.h"
#include "wc/wc_server.h"
#include "lookup_internal.h"
#include "lookup_exec_referral.h"
#include "lookup_exec_constants.h"

void wc_lookup_exec_referral_parse(struct wc_lookup_exec_referral_ctx* ctx)
{
    if (!ctx || !ctx->ref || !ctx->ref_host || !ctx->ref_explicit || !ctx->apnic_erx_keep_ref) {
        return;
    }

    char* ref = *ctx->ref;

    if (ref) {
        char ref_norm[128];
        const char* cur_host = wc_dns_canonical_alias(ctx->current_host);
        if (!cur_host) {
            cur_host = ctx->current_host;
        }
        if (wc_normalize_whois_host(ctx->ref_host, ref_norm, sizeof(ref_norm)) != 0) {
            snprintf(ref_norm, sizeof(ref_norm), "%s", ctx->ref_host);
        }
        if (strchr(ref_norm, '.') == NULL || strlen(ref_norm) < 4) {
            free(ref);
            ref = NULL;
        } else if (cur_host && strcasecmp(ref_norm, cur_host) == 0) {
            free(ref);
            ref = NULL;
        }
    }

    *ctx->ref_explicit = (ref != NULL) ? wc_lookup_referral_is_explicit(ctx->body, ctx->ref_host) : 0;
    if (ref && !*ctx->ref_explicit) {
        const char* ref_rir_explicit = wc_guess_rir(ctx->ref_host);
        if (ctx->current_rir_guess && ref_rir_explicit &&
            strcasecmp(ref_rir_explicit, "unknown") != 0 &&
            strcasecmp(ref_rir_explicit, ctx->current_rir_guess) != 0) {
            *ctx->ref_explicit = 1;
        }
    }

    *ctx->apnic_erx_keep_ref = 0;
    if (ref && !*ctx->ref_explicit) {
        char ref_norm_keep[128];
        if (wc_normalize_whois_host(ctx->ref_host, ref_norm_keep, sizeof(ref_norm_keep)) != 0) {
            snprintf(ref_norm_keep, sizeof(ref_norm_keep), "%s", ctx->ref_host);
        }
        const char* ref_rir_keep = wc_guess_rir(ref_norm_keep);
        if (ref_rir_keep &&
            (strcasecmp(ref_rir_keep, "afrinic") == 0 ||
             strcasecmp(ref_rir_keep, "lacnic") == 0)) {
            *ctx->apnic_erx_keep_ref = 1;
        }
    }
    if (ref && !*ctx->ref_explicit && ctx->ripe_non_managed) {
        free(ref);
        ref = NULL;
    }
    if (ctx->apnic_erx_root && ctx->apnic_redirect_reason == APNIC_REDIRECT_ERX &&
        ref && !*ctx->ref_explicit && !*ctx->apnic_erx_keep_ref) {
        free(ref);
        ref = NULL;
    }
    if (ref && ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "apnic") == 0 &&
        ctx->apnic_erx_legacy && !*ctx->ref_explicit && !*ctx->apnic_erx_keep_ref) {
        free(ref);
        ref = NULL;
    }
    if (ref && ctx->apnic_erx_root && ctx->apnic_redirect_reason == APNIC_REDIRECT_ERX &&
        ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "ripe") == 0 &&
        ctx->apnic_erx_ripe_non_managed && !*ctx->ref_explicit) {
        free(ref);
        ref = NULL;
    }
    if (ctx->apnic_erx_root && ctx->apnic_redirect_reason == APNIC_REDIRECT_ERX &&
        ctx->apnic_erx_arin_before_apnic) {
    }
    if (ctx->apnic_erx_root && ctx->apnic_redirect_reason == APNIC_REDIRECT_ERX &&
        ref && ctx->ref_host[0] && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "arin") == 0) {
        char ref_norm3[128];
        if (wc_normalize_whois_host(ctx->ref_host, ref_norm3, sizeof(ref_norm3)) != 0) {
            snprintf(ref_norm3, sizeof(ref_norm3), "%s", ctx->ref_host);
        }
        if (ctx->apnic_erx_ref_host && ctx->apnic_erx_ref_host_len && !ctx->apnic_erx_ref_host[0]) {
            snprintf(ctx->apnic_erx_ref_host, ctx->apnic_erx_ref_host_len, "%s", ref_norm3);
        }
        const char* ref_rir = wc_guess_rir(ref_norm3);
        int ref_visited = 0;
        for (int i = 0; i < *ctx->visited_count; ++i) {
            if (strcasecmp(ctx->visited[i], ref_norm3) == 0) {
                ref_visited = 1;
                break;
            }
        }
        if (ctx->apnic_erx_stop && !*ctx->apnic_erx_stop &&
            ref_rir && strcasecmp(ref_rir, "apnic") == 0 && ref_visited) {
            *ctx->apnic_erx_stop = 1;
            if (ctx->apnic_erx_stop_host && ctx->apnic_erx_stop_host_len) {
                snprintf(ctx->apnic_erx_stop_host, ctx->apnic_erx_stop_host_len, "%s", ref_norm3);
            }
        }
    }
    if (ctx->apnic_erx_root && ctx->apnic_redirect_reason == APNIC_REDIRECT_ERX &&
        ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "arin") == 0) {
        if (ctx->apnic_erx_seen_arin) {
            *ctx->apnic_erx_seen_arin = 1;
        }
        if (ctx->apnic_erx_target_rir && ctx->apnic_erx_target_rir_len && !ctx->apnic_erx_target_rir[0]) {
            if (wc_lookup_find_case_insensitive(ctx->body, "transferred to ripe") ||
                wc_lookup_find_case_insensitive(ctx->body, "ripe network coordination centre") ||
                (wc_lookup_find_case_insensitive(ctx->body, "netname:") &&
                 wc_lookup_find_case_insensitive(ctx->body, "ripe"))) {
                snprintf(ctx->apnic_erx_target_rir, ctx->apnic_erx_target_rir_len, "%s", "ripe");
            } else if (wc_lookup_find_case_insensitive(ctx->body, "transferred to apnic") ||
                wc_lookup_find_case_insensitive(ctx->body, "asia pacific network information centre") ||
                (wc_lookup_find_case_insensitive(ctx->body, "netname:") &&
                 wc_lookup_find_case_insensitive(ctx->body, "apnic"))) {
                snprintf(ctx->apnic_erx_target_rir, ctx->apnic_erx_target_rir_len, "%s", "apnic");
            } else if (wc_lookup_find_case_insensitive(ctx->body, "transferred to afrinic") ||
                wc_lookup_find_case_insensitive(ctx->body, "afrinic")) {
                snprintf(ctx->apnic_erx_target_rir, ctx->apnic_erx_target_rir_len, "%s", "afrinic");
            } else if (wc_lookup_find_case_insensitive(ctx->body, "transferred to lacnic") ||
                wc_lookup_find_case_insensitive(ctx->body, "lacnic")) {
                snprintf(ctx->apnic_erx_target_rir, ctx->apnic_erx_target_rir_len, "%s", "lacnic");
            }
        }
        if (ctx->apnic_erx_target_rir && ctx->apnic_erx_target_rir[0] &&
            strcasecmp(ctx->apnic_erx_target_rir, "apnic") == 0) {
        }
    }

    *ctx->ref = ref;
}
