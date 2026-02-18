// SPDX-License-Identifier: MIT
// lookup_exec_next.c - Next-hop selection for lookup exec

#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "wc/wc_lookup.h"
#include "wc/wc_selftest.h"
#include "wc/wc_server.h"
#include "lookup_internal.h"
#include "lookup_exec_next.h"
#include "lookup_exec_constants.h"
#include "lookup_exec_rules.h"

static int wc_lookup_exec_is_referral_rir_visited(
    const struct wc_lookup_exec_next_ctx* ctx,
    const char* referral_host)
{
    if (!ctx || !referral_host || !*referral_host || !ctx->visited || !ctx->visited_count) {
        return 0;
    }

    const char* referral_rir = wc_guess_rir(referral_host);
    if (!referral_rir || strcasecmp(referral_rir, "unknown") == 0) {
        return 0;
    }

    for (int i = 0; i < *ctx->visited_count; ++i) {
        const char* seen = ctx->visited[i];
        if (!seen || !*seen) {
            continue;
        }
        const char* seen_rir = wc_guess_rir(seen);
        if (seen_rir && strcasecmp(seen_rir, "unknown") != 0 &&
            strcasecmp(seen_rir, referral_rir) == 0) {
            return 1;
        }
    }

    return 0;
}

static int wc_lookup_exec_pick_cycle_when_referral_rir_visited(
    struct wc_lookup_exec_next_ctx* ctx)
{
    if (!ctx || !ctx->next_host || !ctx->next_host_len || !ctx->have_next || !ctx->fallback_flags) {
        return 0;
    }

    if (wc_lookup_rir_cycle_next(ctx->current_rir_guess,
                                 ctx->visited,
                                 *ctx->visited_count,
                                 ctx->next_host,
                                 ctx->next_host_len)) {
        *ctx->have_next = 1;
        wc_lookup_log_fallback(ctx->hops, "manual", "rir-cycle",
                               ctx->current_host, ctx->next_host, "success",
                               *ctx->fallback_flags, 0, -1,
                               ctx->pref_label,
                               ctx->net_ctx,
                               ctx->cfg);
        return 1;
    }

    if (ctx->apnic_erx_root && ctx->rir_cycle_exhausted) {
        *ctx->rir_cycle_exhausted = 1;
    }

    return 0;
}

void wc_lookup_exec_pick_next_hop(struct wc_lookup_exec_next_ctx* ctx)
{
    if (!ctx) {
        return;
    }

    if (!ctx->next_host || !ctx->next_host_len || !ctx->have_next || !ctx->next_port) {
        return;
    }

    ctx->next_host[0] = '\0';
    *ctx->have_next = 0;
    *ctx->next_port = ctx->current_port;

    if (wc_lookup_exec_rule_should_short_circuit_first_hop_apnic(
            ctx->hops,
            ctx->erx_fast_authoritative,
            ctx->auth,
            ctx->need_redir_eval,
            ctx->ref,
            ctx->current_rir_guess)) {
        if (ctx->stop_with_apnic_authority) {
            *ctx->stop_with_apnic_authority = 1;
        }
        return;
    }

    int force_stop_authoritative = ctx->force_stop_authoritative;
    if (ctx->need_redir_eval) {
        force_stop_authoritative = 0;
    }

    if (!force_stop_authoritative && !ctx->ref) {
        int current_is_arin = (ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "arin") == 0);
        int arin_no_match = (current_is_arin && wc_lookup_body_contains_no_match(ctx->body));
        int arin_no_match_erx = (arin_no_match && ctx->apnic_erx_root);
        if (!*ctx->have_next && ctx->header_hint_valid) {
            if (strcasecmp(ctx->header_hint_host, ctx->current_host) != 0 &&
                !wc_lookup_visited_has(ctx->visited, *ctx->visited_count, ctx->header_hint_host)) {
                snprintf(ctx->next_host, ctx->next_host_len, "%s", ctx->header_hint_host);
                *ctx->have_next = 1;
                wc_lookup_log_fallback(ctx->hops, "manual", "header-hint",
                                       ctx->current_host, ctx->next_host, "success",
                                       *ctx->fallback_flags, 0, -1,
                                       ctx->pref_label,
                                       ctx->net_ctx,
                                       ctx->cfg);
            }
        }
        if (!*ctx->have_next && wc_lookup_find_case_insensitive(ctx->body, "query terms are ambiguous")) {
            if (ctx->apnic_ambiguous_revisit_used &&
                !*ctx->apnic_ambiguous_revisit_used &&
                wc_lookup_visited_has(ctx->visited, *ctx->visited_count, "whois.apnic.net") &&
                strcasecmp(ctx->current_host, "whois.apnic.net") != 0) {
                *ctx->apnic_ambiguous_revisit_used = 1;
                if (ctx->stop_with_apnic_authority) {
                    *ctx->stop_with_apnic_authority = 1;
                }
                wc_lookup_log_fallback(ctx->hops, "manual", "ambiguous-stop-apnic",
                                       ctx->current_host, "whois.apnic.net", "success",
                                       *ctx->fallback_flags, 0, -1,
                                       ctx->pref_label,
                                       ctx->net_ctx,
                                       ctx->cfg);
            }
        }
        if (!*ctx->have_next && arin_no_match && !ctx->apnic_erx_root) {
            if (wc_lookup_rir_cycle_next(ctx->current_rir_guess, ctx->visited, *ctx->visited_count,
                    ctx->next_host, ctx->next_host_len)) {
                *ctx->have_next = 1;
                wc_lookup_log_fallback(ctx->hops, "no-match", "rir-cycle",
                                       ctx->current_host, ctx->next_host, "success",
                                       *ctx->fallback_flags, 0, -1,
                                       ctx->pref_label,
                                       ctx->net_ctx,
                                       ctx->cfg);
            }
        }
        int allow_cycle = ctx->allow_cycle_on_loop;
        if (ctx->apnic_erx_root && ctx->current_rir_guess &&
            (strcasecmp(ctx->current_rir_guess, "ripe") == 0 ||
             strcasecmp(ctx->current_rir_guess, "afrinic") == 0 ||
             strcasecmp(ctx->current_rir_guess, "lacnic") == 0)) {
            allow_cycle = 1;
        }
        if (ctx->apnic_erx_authoritative_stop && ctx->current_rir_guess &&
            strcasecmp(ctx->current_rir_guess, "apnic") == 0 &&
            !ctx->need_redir_eval) {
            allow_cycle = 0;
        }
        if (arin_no_match_erx) {
            allow_cycle = 1;
        }
        if (!*ctx->have_next && ctx->hops == 0 &&
            (ctx->need_redir_eval || (ctx->apnic_erx_legacy && !ctx->erx_fast_authoritative))) {
            int visited_arin = 0;
            for (int i = 0; i < *ctx->visited_count; i++) {
                if (strcasecmp(ctx->visited[i], "whois.arin.net") == 0) {
                    visited_arin = 1;
                    break;
                }
            }
            if (!visited_arin && (!ctx->current_rir_guess || strcasecmp(ctx->current_rir_guess, "arin") != 0)) {
                snprintf(ctx->next_host, ctx->next_host_len, "%s", "whois.arin.net");
                *ctx->have_next = 1;
                wc_lookup_log_fallback(ctx->hops, "manual", "rir-direct",
                                       ctx->current_host, ctx->next_host, "success",
                                       *ctx->fallback_flags, 0, -1,
                                       ctx->pref_label,
                                       ctx->net_ctx,
                                       ctx->cfg);
            }
        }
        if (!*ctx->have_next && ctx->force_rir_cycle) {
            if (wc_lookup_rir_cycle_next(ctx->current_rir_guess, ctx->visited, *ctx->visited_count,
                    ctx->next_host, ctx->next_host_len)) {
                *ctx->have_next = 1;
                wc_lookup_log_fallback(ctx->hops, "manual", "rir-cycle",
                                       ctx->current_host, ctx->next_host, "success",
                                       *ctx->fallback_flags, 0, -1,
                                       ctx->pref_label,
                                       ctx->net_ctx,
                                       ctx->cfg);
            } else if (ctx->apnic_erx_root && ctx->rir_cycle_exhausted) {
                *ctx->rir_cycle_exhausted = 1;
            }
        }
        if (!*ctx->have_next && allow_cycle) {
            if (wc_lookup_rir_cycle_next(ctx->current_rir_guess, ctx->visited, *ctx->visited_count,
                    ctx->next_host, ctx->next_host_len)) {
                *ctx->have_next = 1;
                wc_lookup_log_fallback(ctx->hops, "manual", "rir-cycle",
                                       ctx->current_host, ctx->next_host, "success",
                                       *ctx->fallback_flags, 0, -1,
                                       ctx->pref_label,
                                       ctx->net_ctx,
                                       ctx->cfg);
            } else if (ctx->apnic_erx_root && ctx->rir_cycle_exhausted) {
                *ctx->rir_cycle_exhausted = 1;
            }
        }

        if (!*ctx->have_next && ctx->hops == 0 && ctx->need_redir_eval && !allow_cycle) {
            // Restrict IANA pivot: only from non-ARIN RIRs. Avoid ARIN->IANA and stop at ARIN.
            const char* cur_rir = wc_guess_rir(ctx->current_host);
            int is_arin = (cur_rir && strcasecmp(cur_rir, "arin") == 0);
            int is_known = (cur_rir &&
                (strcasecmp(cur_rir, "apnic") == 0 || strcasecmp(cur_rir, "arin") == 0 ||
                 strcasecmp(cur_rir, "ripe") == 0 || strcasecmp(cur_rir, "afrinic") == 0 ||
                 strcasecmp(cur_rir, "lacnic") == 0 || strcasecmp(cur_rir, "iana") == 0));
            if (!is_arin && !is_known && !ctx->cfg->no_iana_pivot) {
                int visited_iana = 0;
                for (int i = 0; i < *ctx->visited_count; i++) {
                    if (strcasecmp(ctx->visited[i], "whois.iana.org") == 0) {
                        visited_iana = 1;
                        break;
                    }
                }
                if (strcasecmp(ctx->current_host, "whois.iana.org") != 0 && !visited_iana) {
                    snprintf(ctx->next_host, ctx->next_host_len, "%s", "whois.iana.org");
                    *ctx->have_next = 1;
                    if (ctx->fallback_flags) {
                        *ctx->fallback_flags |= 0x8; // iana_pivot
                    }
                    wc_lookup_log_fallback(ctx->hops, "manual", "iana-pivot",
                                           ctx->current_host, "whois.iana.org", "success",
                                           *ctx->fallback_flags, 0, -1,
                                           ctx->pref_label,
                                           ctx->net_ctx,
                                           ctx->cfg);
                }
            }
        }

        if (!*ctx->have_next && ctx->hops > 0 && ctx->need_redir_eval && !allow_cycle) {
            if (wc_lookup_rir_cycle_next(ctx->current_rir_guess, ctx->visited, *ctx->visited_count,
                    ctx->next_host, ctx->next_host_len)) {
                *ctx->have_next = 1;
                wc_lookup_log_fallback(ctx->hops, "manual", "rir-cycle-gate-recover",
                                       ctx->current_host, ctx->next_host, "success",
                                       *ctx->fallback_flags, 0, -1,
                                       ctx->pref_label,
                                       ctx->net_ctx,
                                       ctx->cfg);
            } else if (ctx->apnic_erx_root && ctx->rir_cycle_exhausted) {
                *ctx->rir_cycle_exhausted = 1;
            }
        }
    } else if (!force_stop_authoritative) {
        // Selftest: optionally force IANA pivot even if explicit referral exists.
        // Updated semantics: pivot at most once so that a 3-hop flow
        // (e.g., apnic -> iana -> arin) can be simulated. If IANA has
        // already been visited, follow the normal referral instead of
        // forcing IANA again, otherwise a loop guard would terminate at IANA.
        if (ctx->fault_profile && ctx->fault_profile->force_iana_pivot) {
            int visited_iana = 0;
            for (int i = 0; i < *ctx->visited_count; i++) {
                if (strcasecmp(ctx->visited[i], "whois.iana.org") == 0) {
                    visited_iana = 1;
                    break;
                }
            }
            if (!visited_iana && strcasecmp(ctx->current_host, "whois.iana.org") != 0) {
                snprintf(ctx->next_host, ctx->next_host_len, "%s", "whois.iana.org");
                *ctx->have_next = 1;
                if (ctx->fallback_flags) {
                    *ctx->fallback_flags |= 0x8; // iana_pivot
                }
            } else {
                // Normal referral path after the one-time pivot
                if (wc_normalize_whois_host(ctx->ref_host, ctx->next_host, ctx->next_host_len) != 0) {
                    snprintf(ctx->next_host, ctx->next_host_len, "%s", ctx->ref_host);
                }
                *ctx->have_next = 1;
                if (ctx->ref_port > 0) {
                    *ctx->next_port = ctx->ref_port;
                }
            }
        } else {
            if (wc_normalize_whois_host(ctx->ref_host, ctx->next_host, ctx->next_host_len) != 0) {
                snprintf(ctx->next_host, ctx->next_host_len, "%s", ctx->ref_host);
            }
            int visited_ref = 0;
            if (wc_lookup_visited_has(ctx->visited, *ctx->visited_count, ctx->next_host)) {
                visited_ref = 1;
            }
            if (!visited_ref && wc_lookup_exec_is_referral_rir_visited(ctx, ctx->next_host)) {
                visited_ref = 1;
            }
            if (!visited_ref && ctx->apnic_erx_root &&
                ctx->apnic_redirect_reason == APNIC_REDIRECT_IANA &&
                ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "arin") == 0) {
                const char* next_rir = wc_guess_rir(ctx->next_host);
                if (next_rir && strcasecmp(next_rir, "apnic") == 0) {
                    visited_ref = 1;
                }
            }
            if (!visited_ref) {
                *ctx->have_next = 1;
                if (ctx->ref_port > 0) {
                    *ctx->next_port = ctx->ref_port;
                }
            } else {
                wc_lookup_exec_pick_cycle_when_referral_rir_visited(ctx);
            }
        }
    }

    if (ctx->apnic_erx_root && ctx->apnic_redirect_reason == APNIC_REDIRECT_ERX &&
        ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "arin") == 0 && *ctx->have_next) {
        if (ctx->apnic_erx_ref_host && ctx->apnic_erx_ref_host_len) {
            snprintf(ctx->apnic_erx_ref_host, ctx->apnic_erx_ref_host_len, "%s", ctx->next_host);
        }
    }
}
