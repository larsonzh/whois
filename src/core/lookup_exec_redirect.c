// SPDX-License-Identifier: MIT
// lookup_exec_redirect.c - Redirect/authority evaluation for lookup exec
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include "wc/wc_dns.h"
#include "wc/wc_known_ips.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "wc/wc_server.h"
#include "lookup_internal.h"
#include "lookup_exec_redirect.h"

// local strdup to avoid feature-macro dependency differences across toolchains
static char* xstrdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

static void wc_lookup_exec_prepare_lacnic_erx_hint_inputs(
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    int* header_erx_hint,
    const char** implicit_host);
static void wc_lookup_exec_apply_lacnic_erx_hint_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* implicit_host,
    int header_erx_hint,
    int ref_explicit,
    char** ref,
    int* need_redir_eval);
static void wc_lookup_exec_run_lacnic_erx_hint_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    int ref_explicit,
    char** ref,
    int* need_redir_eval);
static void wc_lookup_exec_run_lacnic_header_rir_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval);

static void wc_lookup_exec_set_apnic_redirect_reason_value(
    int* apnic_redirect_reason,
    int reason);

static int wc_lookup_exec_header_matches_current(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana) {
    if (!ctx || !header_host || header_is_iana) return 0;

    char header_normh[128];
    char current_normh[128];
    const char* header_normp = wc_dns_canonical_alias(header_host);
    const char* current_normp = wc_dns_canonical_alias(ctx->current_host);
    if (!header_normp) header_normp = header_host;
    if (!current_normp) current_normp = ctx->current_host;
    if (wc_normalize_whois_host(header_normp, header_normh, sizeof(header_normh)) != 0) {
        snprintf(header_normh, sizeof(header_normh), "%s", header_normp);
    }
    if (wc_normalize_whois_host(current_normp, current_normh, sizeof(current_normh)) != 0) {
        snprintf(current_normh, sizeof(current_normh), "%s", current_normp);
    }
    return (strcasecmp(header_normh, current_normh) == 0) ? 1 : 0;
}

static void wc_lookup_exec_write_header_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host);
static void wc_lookup_exec_write_header_is_iana_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_is_iana);

static void wc_lookup_exec_prepare_header_authority(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* auth,
    int* banner_only,
    const char** header_host,
    int* header_is_iana,
    int* header_matches_current) {
    if (!ctx || !body || !auth || !banner_only || !header_host ||
        !header_is_iana || !header_matches_current) {
        return;
    }

    *banner_only = (!(*auth) && body && *body && wc_lookup_body_is_comment_only(body));
    *header_host = wc_lookup_detect_rir_header_host(body);
    *header_is_iana = (*header_host && strcasecmp(*header_host, "whois.iana.org") == 0);

    wc_lookup_exec_write_header_host_output_step(ctx, *header_host);
    wc_lookup_exec_write_header_is_iana_output_step(ctx, *header_is_iana);

    *header_matches_current = wc_lookup_exec_header_matches_current(
        ctx,
        *header_host,
        *header_is_iana);

    if (*header_matches_current && !*auth && !*banner_only) {
        if (!(ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "arin") == 0)) {
            *auth = 1;
        }
    }
}

static void wc_lookup_exec_write_header_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host) {
    if (!ctx) return;

    if (ctx->header_host) {
        *ctx->header_host = header_host;
    }
}

static void wc_lookup_exec_write_header_is_iana_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_is_iana) {
    if (!ctx) return;

    if (ctx->header_is_iana) {
        *ctx->header_is_iana = header_is_iana;
    }
}

static int wc_lookup_exec_header_has_erx_hint(const char* body) {
    if (!body) return 0;

    return (wc_lookup_body_contains_erx_legacy(body) ||
            wc_lookup_body_contains_erx_netname(body) ||
            wc_lookup_body_contains_apnic_erx_hint(body));
}

static void wc_lookup_exec_mark_seen_ripe_non_managed_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_mark_seen_afrinic_iana_blk_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static int wc_lookup_exec_is_non_auth_internal_for_rir(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_rir,
    const char* body) {
    if (!ctx || !header_rir || !body) return 0;

    if (strcasecmp(header_rir, "apnic") == 0) {
        if (wc_lookup_body_contains_apnic_iana_netblock(body) ||
            wc_lookup_body_contains_erx_legacy(body)) {
            return 1;
        }
    } else if (strcasecmp(header_rir, "ripe") == 0) {
        if (wc_lookup_body_contains_ripe_non_managed(body)) {
            wc_lookup_exec_mark_seen_ripe_non_managed_output_step(ctx);
            return 1;
        }
    } else if (strcasecmp(header_rir, "afrinic") == 0) {
        if (wc_lookup_body_contains_full_ipv4_space(body)) {
            wc_lookup_exec_mark_seen_afrinic_iana_blk_output_step(ctx);
            return 1;
        }
    }
    return 0;
}

static void wc_lookup_exec_mark_seen_ripe_non_managed_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->seen_ripe_non_managed) {
        *ctx->seen_ripe_non_managed = 1;
    }
}

static void wc_lookup_exec_mark_seen_afrinic_iana_blk_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->seen_afrinic_iana_blk) {
        *ctx->seen_afrinic_iana_blk = 1;
    }
}

static const char* wc_lookup_exec_get_lacnic_implicit_host(
    const char* header_host,
    int header_is_iana,
    int header_matches_current) {
    if (header_host && !header_is_iana && !header_matches_current) {
        return header_host;
    }
    return "whois.apnic.net";
}

static void wc_lookup_exec_apply_non_auth_cycle_outputs_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_apply_access_denied_override(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* non_auth_internal) {
    if (!ctx || !non_auth_internal) return;

    if (ctx->access_denied && ctx->hops == 0) {
        *non_auth_internal = 1;
        wc_lookup_exec_apply_non_auth_cycle_outputs_step(ctx);
    }
}

static void wc_lookup_exec_mark_stop_with_header_authority_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_header_authority_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_hint_host);

static void wc_lookup_exec_apply_header_authority_stop(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_hint_host) {
    if (!ctx || !body || !header_hint_host) return;

    if (*ctx->auth && !wc_lookup_body_has_strong_redirect_hint(body)) {
        wc_lookup_exec_mark_stop_with_header_authority_output_step(ctx);
        wc_lookup_exec_write_header_authority_host_output_step(ctx, header_hint_host);
    }
}

static void wc_lookup_exec_mark_stop_with_header_authority_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->stop_with_header_authority) {
        *ctx->stop_with_header_authority = 1;
    }
}

static void wc_lookup_exec_write_header_authority_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_hint_host) {
    if (!ctx || !header_hint_host) return;

    if (ctx->header_authority_host && ctx->header_authority_host_len > 0) {
        snprintf(ctx->header_authority_host,
            ctx->header_authority_host_len,
            "%s",
            header_hint_host);
    }
}

static void wc_lookup_exec_apply_non_auth_cycle(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    wc_lookup_exec_apply_non_auth_cycle_outputs_step(ctx);
}

static void wc_lookup_exec_mark_force_rir_cycle_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_apply_non_auth_cycle_outputs_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->header_hint_valid) {
        *ctx->header_hint_valid = 0;
    }
    wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
}

static void wc_lookup_exec_mark_force_rir_cycle_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->force_rir_cycle) {
        *ctx->force_rir_cycle = 1;
    }
}

static void wc_lookup_exec_apply_header_authority_decision(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int non_auth_internal,
    const char* header_hint_host) {
    if (!ctx || !body || !header_hint_host) return;

    if (!non_auth_internal) {
        wc_lookup_exec_apply_header_authority_stop(ctx, body, header_hint_host);
    } else {
        wc_lookup_exec_apply_non_auth_cycle(ctx);
    }
}

static void wc_lookup_exec_maybe_track_lacnic_header_host(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_hint_host) {
    if (!ctx || !header_hint_host) return;

    if (!ctx->access_denied && ctx->visited && ctx->visited_count &&
        !wc_lookup_visited_has(ctx->visited, *ctx->visited_count, header_hint_host) &&
        *ctx->visited_count < 16) {
        ctx->visited[(*ctx->visited_count)++] = xstrdup(header_hint_host);
    }
}

static void wc_lookup_exec_write_header_hint_valid_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_hint_host);

static void wc_lookup_exec_mark_header_hint_valid(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_hint_host) {
    if (!ctx || !header_hint_host) return;

    wc_lookup_exec_write_header_hint_valid_output_step(ctx, header_hint_host);
}

static void wc_lookup_exec_write_header_hint_valid_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_hint_host) {
    if (!ctx || !header_hint_host) return;

    if (ctx->header_hint_valid) {
        *ctx->header_hint_valid = (header_hint_host[0] != '\0');
    }
}

static void wc_lookup_exec_normalize_lacnic_header_hint(
    const char* header_host,
    char* header_hint_host,
    size_t header_hint_host_len) {
    if (!header_host || !header_hint_host || header_hint_host_len == 0) return;

    if (wc_normalize_whois_host(header_host, header_hint_host, header_hint_host_len) != 0) {
        snprintf(header_hint_host, header_hint_host_len, "%s", header_host);
    }
}

static void wc_lookup_exec_prepare_lacnic_header_hint(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval) {
    if (!ctx || !header_host || !header_hint_host || !need_redir_eval) return;

    wc_lookup_exec_normalize_lacnic_header_hint(
        header_host,
        header_hint_host,
        header_hint_host_len);
    wc_lookup_exec_mark_header_hint_valid(ctx, header_hint_host);
    *need_redir_eval = 1;
}

static int wc_lookup_exec_should_handle_lacnic_known_rir(const char* header_rir) {
    if (!header_rir) return 0;

    return (strcasecmp(header_rir, "apnic") == 0 ||
            strcasecmp(header_rir, "ripe") == 0 ||
            strcasecmp(header_rir, "afrinic") == 0);
}

static const char* wc_lookup_exec_get_valid_header_rir(const char* header_host) {
    if (!header_host) return NULL;

    const char* header_rir = wc_guess_rir(header_host);
    if (!header_rir || strcasecmp(header_rir, "unknown") == 0) {
        return NULL;
    }
    return header_rir;
}

static void wc_lookup_exec_clear_lacnic_ref_if_implicit(
    int ref_explicit,
    char** ref) {
    if (!ref) return;

    if (*ref && !ref_explicit) {
        free(*ref);
        *ref = NULL;
    }
}

static void wc_lookup_exec_track_lacnic_apnic_visit(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->visited && ctx->visited_count &&
        !wc_lookup_visited_has(ctx->visited, *ctx->visited_count, "whois.apnic.net") &&
        *ctx->visited_count < 16) {
        ctx->visited[(*ctx->visited_count)++] = xstrdup("whois.apnic.net");
    }
}

static void wc_lookup_exec_mark_apnic_erx_legacy_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_should_mark_apnic_erx_root_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_mark_apnic_erx_root_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_apnic_erx_root_host_literal_if_empty_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* host_literal);

static void wc_lookup_exec_mark_lacnic_apnic_root(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    wc_lookup_exec_mark_apnic_erx_legacy_output_step(ctx);
    if (wc_lookup_exec_should_mark_apnic_erx_root_step(ctx)) {
        wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
        wc_lookup_exec_set_apnic_redirect_reason_value(
            ctx->apnic_redirect_reason,
            1);
        wc_lookup_exec_write_apnic_erx_root_host_literal_if_empty_step(
            ctx,
            "whois.apnic.net");
    }
}

static void wc_lookup_exec_mark_apnic_erx_legacy_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_legacy) {
        *ctx->apnic_erx_legacy = 1;
    }
}

static int wc_lookup_exec_should_mark_apnic_erx_root_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root && !*ctx->apnic_erx_root) ? 1 : 0;
}

static void wc_lookup_exec_mark_apnic_erx_root_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->apnic_erx_root) return;

    *ctx->apnic_erx_root = 1;
}

static void wc_lookup_exec_write_apnic_erx_root_host_literal_if_empty_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* host_literal) {
    if (!ctx || !host_literal) return;

    if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
        ctx->apnic_erx_root_host[0] == '\0') {
        snprintf(ctx->apnic_erx_root_host,
            ctx->apnic_erx_root_host_len,
            "%s",
            host_literal);
    }
}

static void wc_lookup_exec_handle_lacnic_erx_hint_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* implicit_host,
    int header_erx_hint,
    int ref_explicit,
    char** ref,
    int* need_redir_eval) {
    if (!ctx || !implicit_host || !ref || !need_redir_eval) return;

    if (!header_erx_hint || strcasecmp(implicit_host, "whois.apnic.net") != 0) {
        return;
    }

    wc_lookup_exec_clear_lacnic_ref_if_implicit(ref_explicit, ref);
    if (!*ref) {
        wc_lookup_exec_track_lacnic_apnic_visit(ctx);
        wc_lookup_exec_mark_lacnic_apnic_root(ctx);
        *need_redir_eval = 1;
    }
}

static void wc_lookup_exec_prepare_lacnic_redirect_inputs(
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    int* header_erx_hint,
    const char** implicit_host) {
    if (!body || !header_erx_hint || !implicit_host) return;

    *header_erx_hint = wc_lookup_exec_header_has_erx_hint(body);
    *implicit_host = wc_lookup_exec_get_lacnic_implicit_host(
        header_host,
        header_is_iana,
        header_matches_current);
}

static int wc_lookup_exec_compute_lacnic_non_auth_internal(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_rir,
    const char* body) {
    if (!ctx || !header_rir || !body) return 0;

    int non_auth_internal = wc_lookup_exec_is_non_auth_internal_for_rir(
        ctx,
        header_rir,
        body);
    wc_lookup_exec_apply_access_denied_override(ctx, &non_auth_internal);
    return non_auth_internal;
}

static void wc_lookup_exec_handle_lacnic_known_rir_flow(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_rir,
    const char* header_hint_host) {
    if (!ctx || !body || !header_rir || !header_hint_host) return;

    if (!wc_lookup_exec_should_handle_lacnic_known_rir(header_rir)) return;

    int non_auth_internal = wc_lookup_exec_compute_lacnic_non_auth_internal(
        ctx,
        header_rir,
        body);
    wc_lookup_exec_apply_header_authority_decision(
        ctx,
        body,
        non_auth_internal,
        header_hint_host);
    wc_lookup_exec_maybe_track_lacnic_header_host(ctx, header_hint_host);
}

static void wc_lookup_exec_apply_lacnic_header_rir_flow(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_rir,
    const char* header_host,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval) {
    if (!ctx || !body || !header_rir || !header_host ||
        !header_hint_host || !need_redir_eval) {
        return;
    }

    wc_lookup_exec_prepare_lacnic_header_hint(
        ctx,
        header_host,
        header_hint_host,
        header_hint_host_len,
        need_redir_eval);
    wc_lookup_exec_handle_lacnic_known_rir_flow(
        ctx,
        body,
        header_rir,
        header_hint_host);
}

static int wc_lookup_exec_should_eval_lacnic_header_rir(
    const char* header_host,
    int header_is_iana,
    int header_matches_current) {
    return (header_host && !header_is_iana && !header_matches_current);
}

static const char* wc_lookup_exec_get_lacnic_header_rir(const char* header_host) {
    return wc_lookup_exec_get_valid_header_rir(header_host);
}

static int wc_lookup_exec_should_apply_lacnic_header_rir(
    const char* header_host,
    int header_is_iana,
    int header_matches_current) {
    return wc_lookup_exec_should_eval_lacnic_header_rir(
        header_host,
        header_is_iana,
        header_matches_current);
}

static void wc_lookup_exec_apply_lacnic_header_rir_flow_if_needed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval) {
    if (!ctx || !body || !header_host || !header_hint_host || !need_redir_eval) {
        return;
    }

    if (!wc_lookup_exec_should_apply_lacnic_header_rir(
            header_host,
            header_is_iana,
            header_matches_current)) {
        return;
    }

    const char* header_rir = wc_lookup_exec_get_lacnic_header_rir(header_host);
    if (!header_rir) return;

    wc_lookup_exec_apply_lacnic_header_rir_flow(
        ctx,
        body,
        header_rir,
        header_host,
        header_hint_host,
        header_hint_host_len,
        need_redir_eval);
}

static void wc_lookup_exec_apply_lacnic_header_rir_if_allowed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval) {
    if (!ctx || !body || !header_host || !header_hint_host || !need_redir_eval) {
        return;
    }

    wc_lookup_exec_apply_lacnic_header_rir_flow_if_needed(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        need_redir_eval);
}

static void wc_lookup_exec_handle_lacnic_header_rir(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval) {
    if (!ctx || !body || !header_host || !header_hint_host || !need_redir_eval) {
        return;
    }

    wc_lookup_exec_apply_lacnic_header_rir_if_allowed(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        need_redir_eval);
}

static void wc_lookup_exec_handle_lacnic_erx_hint_flow(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    int ref_explicit,
    char** ref,
    int* need_redir_eval) {
    if (!ctx || !body || !ref || !need_redir_eval) return;

    int header_erx_hint = 0;
    const char* implicit_host = NULL;
    wc_lookup_exec_prepare_lacnic_erx_hint_inputs(
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        &header_erx_hint,
        &implicit_host);
    wc_lookup_exec_apply_lacnic_erx_hint_redirect(
        ctx,
        implicit_host,
        header_erx_hint,
        ref_explicit,
        ref,
        need_redir_eval);
}

static void wc_lookup_exec_prepare_lacnic_erx_hint_inputs(
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    int* header_erx_hint,
    const char** implicit_host) {
    if (!body || !header_erx_hint || !implicit_host) return;

    wc_lookup_exec_prepare_lacnic_redirect_inputs(
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_erx_hint,
        implicit_host);
}

static void wc_lookup_exec_apply_lacnic_erx_hint_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* implicit_host,
    int header_erx_hint,
    int ref_explicit,
    char** ref,
    int* need_redir_eval) {
    if (!ctx || !implicit_host || !ref || !need_redir_eval) return;

    wc_lookup_exec_handle_lacnic_erx_hint_redirect(
        ctx,
        implicit_host,
        header_erx_hint,
        ref_explicit,
        ref,
        need_redir_eval);
}

static void wc_lookup_exec_apply_lacnic_header_rir_if_needed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval) {
    if (!ctx || !body || !header_host || !header_hint_host || !need_redir_eval) {
        return;
    }

    if (wc_lookup_exec_should_eval_lacnic_header_rir(
            header_host,
            header_is_iana,
            header_matches_current)) {
        wc_lookup_exec_handle_lacnic_header_rir(
            ctx,
            body,
            header_host,
            header_is_iana,
            header_matches_current,
            header_hint_host,
            header_hint_host_len,
            need_redir_eval);
    }
}

static void wc_lookup_exec_handle_lacnic_redirect_core(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval);
static void wc_lookup_exec_run_lacnic_redirect_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval);

static int wc_lookup_exec_is_lacnic_redirect_ready(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_hint_host,
    char** ref,
    int* need_redir_eval) {
    return (ctx && body && header_hint_host && ref && need_redir_eval);
}

static void wc_lookup_exec_handle_lacnic_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval) {
    if (!wc_lookup_exec_is_lacnic_redirect_ready(
            ctx,
            body,
            header_hint_host,
            ref,
            need_redir_eval)) {
        return;
    }

    wc_lookup_exec_handle_lacnic_redirect_core(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        ref,
        ref_explicit,
        need_redir_eval);
}

static void wc_lookup_exec_handle_lacnic_redirect_core(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval) {
        return;
    }

    wc_lookup_exec_run_lacnic_redirect_steps(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        ref,
        ref_explicit,
        need_redir_eval);
}

static void wc_lookup_exec_run_lacnic_redirect_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval) {
        return;
    }

    wc_lookup_exec_run_lacnic_erx_hint_step(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        ref_explicit,
        ref,
        need_redir_eval);
    wc_lookup_exec_run_lacnic_header_rir_step(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        need_redir_eval);
}

static void wc_lookup_exec_run_lacnic_erx_hint_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    int ref_explicit,
    char** ref,
    int* need_redir_eval) {
    if (!ctx || !body || !ref || !need_redir_eval) return;

    wc_lookup_exec_handle_lacnic_erx_hint_flow(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        ref_explicit,
        ref,
        need_redir_eval);
}

static void wc_lookup_exec_run_lacnic_header_rir_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    int* need_redir_eval) {
    if (!ctx || !body || !header_hint_host || !need_redir_eval) return;

    wc_lookup_exec_apply_lacnic_header_rir_if_needed(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        need_redir_eval);
}

static void wc_lookup_exec_log_access_denied_or_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host);
static void wc_lookup_exec_record_access_failure(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host);
static void wc_lookup_exec_filter_failure_body(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current);
static void wc_lookup_exec_mark_access_failure(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current);
static void wc_lookup_exec_mark_non_auth(
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_mark_non_auth_and_cycle(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_handle_ripe_non_auth_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_handle_afrinic_non_auth_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_handle_lacnic_rate_limit_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval);
static int wc_lookup_exec_should_first_hop_cycle(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int rate_limit_current);
static void wc_lookup_exec_handle_first_hop_cycle_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_update_apnic_root_if_needed(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_mark_header_non_auth(int* header_non_authoritative);
static void wc_lookup_exec_set_apnic_redirect_reason_value(
    int* apnic_redirect_reason,
    int reason);
static int wc_lookup_exec_is_ipv6_root(const char* body);
static int wc_lookup_exec_is_ripe_non_auth(const char* body);
static int wc_lookup_exec_is_apnic_netblock(const char* body);
static int wc_lookup_exec_is_full_ipv4_space(const char* body);
static int wc_lookup_exec_should_mark_full_ipv4(const char* body);
static int wc_lookup_exec_is_lacnic_unallocated(const char* body);
static int wc_lookup_exec_is_lacnic_rate_limited(const char* body);
static int wc_lookup_exec_is_lacnic_cidr_unallocated(const char* body);
static int wc_lookup_exec_should_set_lacnic_cidr_unallocated(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body);
static void wc_lookup_exec_set_seen_lacnic_unallocated(
    struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_missing_ref(const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_is_current_rir_lacnic(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_should_handle_lacnic_non_auth(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_should_record_erx_marker(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_set_erx_fast_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref);
static void wc_lookup_exec_update_allow_cycle_on_loop(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval,
    int* allow_cycle_on_loop);
static int wc_lookup_exec_initial_allow_cycle_on_loop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval);
static void wc_lookup_exec_apply_allow_cycle_overrides(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop);
static void wc_lookup_exec_apply_allow_cycle_authoritative_stop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop);
static void wc_lookup_exec_apply_allow_cycle_hop_limits(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop);
static void wc_lookup_exec_update_force_stop_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval,
    int* force_stop_authoritative);
static int wc_lookup_exec_erx_fast_authoritative_flag(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_should_force_stop_authoritative(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval);
static int wc_lookup_exec_is_authority_valid(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative);
static int wc_lookup_exec_is_current_rir_iana(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_update_apnic_suppress_current(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* apnic_erx_suppress_current);
static int wc_lookup_exec_should_suppress_apnic_current(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body);
static void wc_lookup_exec_update_apnic_ripe_non_managed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body);
static void wc_lookup_exec_apply_apnic_suppress_overrides(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* apnic_erx_suppress_current);
static void wc_lookup_exec_apply_apnic_arin_suppress_override(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* apnic_erx_suppress_current);
static void wc_lookup_exec_apply_apnic_ripe_suppress_override(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* apnic_erx_suppress_current);
static void wc_lookup_exec_apply_apnic_stop_on_target(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval);
static int wc_lookup_exec_should_apply_apnic_stop_on_target(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval);
static const char* wc_lookup_exec_apnic_stop_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_apnic_write_stop_host(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* stop_rir);
static void wc_lookup_exec_update_last_hop_stats(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int need_redir_eval,
    const char* ref);
static void wc_lookup_exec_run_apnic_header_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_run_apnic_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static void wc_lookup_exec_run_apnic_post_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref);
struct wc_lookup_exec_eval_state;
struct wc_lookup_exec_header_state;
static void wc_lookup_exec_run_pre_apnic_header_access_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state);
static void wc_lookup_exec_run_pre_apnic_erx_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state);
static void wc_lookup_exec_apply_apnic_erx_logic_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    const struct wc_lookup_exec_header_state* header_state);
static void wc_lookup_exec_prepare_eval_io_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st);
static void wc_lookup_exec_prepare_eval_hint_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st);
static void wc_lookup_exec_prepare_eval_redirect_step(
    struct wc_lookup_exec_eval_state* st);
static void wc_lookup_exec_writeback_with_need_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* body,
    int auth,
    int need_redir_eval,
    char* ref,
    int ref_explicit,
    int ref_port,
    int header_non_authoritative,
    int allow_cycle_on_loop,
    int force_stop_authoritative,
    int apnic_erx_suppress_current);
static void wc_lookup_exec_prepare_eval_header_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state);
static void wc_lookup_exec_prepare_eval_access_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state);
static void wc_lookup_exec_finalize_flags_stage(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int* need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current);
static void wc_lookup_exec_finalize_writeback_stage(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int* need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current,
    char* ref,
    int ref_explicit,
    int ref_port);
static void wc_lookup_exec_prepare_eval_header_fields(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state);
static void wc_lookup_exec_prepare_eval_io(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st);
static void wc_lookup_exec_prepare_eval_hint(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st);
static void wc_lookup_exec_prepare_eval_redirect(
    struct wc_lookup_exec_eval_state* st);
static void wc_lookup_exec_run_eval_flow(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state);
static void wc_lookup_exec_handle_lacnic_redirect_core(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval);
static void wc_lookup_exec_handle_lacnic_header_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval);
static void wc_lookup_exec_handle_access_rate_limit_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current);
static void wc_lookup_exec_apply_access_rate_limit_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current);
static void wc_lookup_exec_init_access_flags(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_matches_current,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current);
static void wc_lookup_exec_run_access_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host);
static void wc_lookup_exec_handle_access_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int first_hop_persistent_empty,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_init_access_signal_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current);
static void wc_lookup_exec_apply_access_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int first_hop_persistent_empty,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_apply_persistent_empty_signal(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int first_hop_persistent_empty,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_apply_non_auth_and_cidr_signals_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_apply_rir_non_auth_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_apply_hop_and_ripe_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_apply_cidr_and_lacnic_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_apply_cidr_side_effects_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int ripe_non_managed);
static void wc_lookup_exec_apply_lacnic_non_auth_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_apply_full_ipv4_signal_step(
    const char* body,
    int* header_non_authoritative);
static void wc_lookup_exec_handle_persistent_empty_signal(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int first_hop_persistent_empty,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_run_erx_marker_recheck(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* erx_marker_this_hop);
static void wc_lookup_exec_update_redirect_flags_core(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current);
static void wc_lookup_exec_run_update_redirect_flag_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current);
static int wc_lookup_exec_apnic_header_authoritative_stop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int auth,
    int header_non_authoritative);
static void wc_lookup_exec_apnic_handle_header_ref_flow(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static void wc_lookup_exec_apnic_run_header_last_ip_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host);
static void wc_lookup_exec_apnic_run_header_refs_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static void wc_lookup_exec_apnic_handle_erx_netname_flow(
    int auth,
    int header_is_iana,
    const char* header_host,
    const char* body,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_apnic_detect_erx_netname_step(const char* body);
static void wc_lookup_exec_apnic_apply_erx_netname_step(
    int auth,
    int header_is_iana,
    const char* header_host,
    int erx_netname,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static void wc_lookup_exec_apnic_handle_erx_hint_and_match(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref);
static void wc_lookup_exec_apnic_run_erx_hint_strict_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* need_redir_eval,
    char* ref);
static void wc_lookup_exec_apnic_run_erx_header_match_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref);
static void wc_lookup_exec_apnic_handle_erx_hints(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_apnic_handle_header_phase(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_apnic_run_header_phase_authority_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_apnic_handle_transfer_and_hints(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_apnic_run_apply_header_authority_compute_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int auth,
    int header_non_authoritative);
static void wc_lookup_exec_apnic_run_apply_header_authority_ref_flow_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_apnic_run_transfer_hint_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* need_redir_eval,
    char** ref);
static void wc_lookup_exec_run_apnic_transfer_post_chain_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int erx_marker_this_hop,
    int ripe_non_managed,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_run_apnic_transfer_chain_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static void wc_lookup_exec_run_apnic_transfer_chain_post_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref);
static void wc_lookup_exec_apnic_run_transfer_hint_erx_hints_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static void wc_lookup_exec_apnic_handle_post_fast_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref);
static void wc_lookup_exec_apnic_run_post_transfer_flags_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval);
static void wc_lookup_exec_apnic_run_post_transfer_fast_auth_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref);
static void wc_lookup_exec_apnic_handle_post_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval);
static void wc_lookup_exec_apnic_run_post_flags_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_post_flags(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        need_redir_eval);
}

static void wc_lookup_exec_apnic_run_post_fast_authoritative_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_post_fast_authoritative(
        ctx,
        auth,
        erx_marker_this_hop,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_handle_post_transfer(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref);
static void wc_lookup_exec_apnic_handle_post_fast_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref);
static void wc_lookup_exec_apnic_update_header_refs(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static void wc_lookup_exec_apnic_handle_post_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval);
static int wc_lookup_exec_apnic_should_stop_target(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed);
static void wc_lookup_exec_apnic_mark_stop_target(
    struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_should_handle_full_ipv4_space(
    const char* body,
    int apnic_transfer_to_apnic);
static int wc_lookup_exec_apnic_should_cancel_need_redir_on_transfer(
    int apnic_transfer_to_apnic);
static int wc_lookup_exec_apnic_transfer_to_apnic(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body);
static void wc_lookup_exec_apnic_clear_ref_on_transfer(
    int* need_redir_eval,
    char** ref);
static int wc_lookup_exec_apnic_header_matches_current_host(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host);
static void wc_lookup_exec_apnic_prepare_header_current_norm_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    char* header_norm,
    size_t header_norm_len,
    char* current_norm,
    size_t current_norm_len);
static void wc_lookup_exec_erx_mark_this_hop(
    const char* body,
    int* erx_marker_this_hop);
static void wc_lookup_exec_erx_handle_marker_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int erx_marker_this_hop,
    const char* erx_marker_host_local,
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_erx_run_fast_recheck_if_needed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int erx_marker_this_hop,
    const char* erx_marker_host_local,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref);
static void wc_lookup_exec_erx_apply_batch_delay(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_erx_prepare_recheck(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    struct wc_lookup_opts* recheck_opts,
    struct wc_query* recheck_q);
static void wc_lookup_exec_erx_set_fast_authoritative_host(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);
static void wc_lookup_exec_erx_set_fast_authoritative_ip(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res);
static int wc_lookup_exec_erx_has_valid_recheck_body(
    int recheck_rc,
    const struct wc_result* recheck_res);
static void wc_lookup_exec_erx_log_fast_recheck_result(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int recheck_erx,
    int recheck_non_auth);
static void wc_lookup_exec_erx_log_fast_recheck_failure(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int recheck_rc);
static int wc_lookup_exec_apnic_should_update_legacy_root(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_apnic_set_legacy_root_flag(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_apnic_update_legacy_root_host(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_apnic_update_legacy_root_ip(
    struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_should_ensure_root_on_need_redir(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval);
static void wc_lookup_exec_apnic_mark_root_on_need_redir(
    struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_should_update_last_ip_current(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_apnic_update_last_ip_value(
    struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_should_update_legacy_flags(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int apnic_transfer_to_apnic);
static void wc_lookup_exec_apnic_update_legacy_marker(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body);
static int wc_lookup_exec_apnic_should_force_iana_netblock(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_refs_should_cross_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_apnic_handle_ref_cleanup_on_auth_stop(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit);
static int wc_lookup_exec_apnic_refs_match_header(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host);
static void wc_lookup_exec_handle_apnic_netblock_root(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body);
static void wc_lookup_exec_handle_lacnic_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval);

static void wc_lookup_exec_run_access_rate_limit_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host) {
    if (!ctx || !body || !*body) return;

    wc_lookup_exec_log_access_denied_or_rate_limit(
        ctx,
        access_denied_current,
        access_denied_internal,
        rate_limit_current,
        header_host);
    wc_lookup_exec_record_access_failure(
        ctx,
        access_denied_current,
        access_denied_internal,
        rate_limit_current,
        header_host);
    wc_lookup_exec_filter_failure_body(
        ctx,
        body,
        access_denied_current,
        access_denied_internal,
        rate_limit_current);
    wc_lookup_exec_mark_access_failure(
        ctx,
        access_denied_current,
        access_denied_internal,
        rate_limit_current);
}

static void wc_lookup_exec_handle_access_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host) {
    if (!ctx || !body || !*body) return;

    wc_lookup_exec_run_access_rate_limit_steps(
        ctx,
        body,
        access_denied_current,
        access_denied_internal,
        rate_limit_current,
        header_host);
}

static void wc_lookup_exec_log_access_denied_or_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host) {
    if (!ctx) return;

    if ((access_denied_current || access_denied_internal || rate_limit_current) &&
        ctx->cfg && ctx->cfg->debug) {
        const char* dbg_host = access_denied_internal ? header_host : ctx->current_host;
        const char* dbg_rir = dbg_host ? wc_guess_rir(dbg_host) : NULL;
        const char* dbg_ip = "unknown";
        if (access_denied_internal) {
            const char* known_ip = dbg_host ? wc_dns_get_known_ip(dbg_host) : NULL;
            if (known_ip && known_ip[0]) {
                dbg_ip = known_ip;
            }
        } else if (ctx->ni && ctx->ni->ip[0]) {
            dbg_ip = ctx->ni->ip;
        }
        fprintf(stderr,
            "[RIR-RESP] action=%s scope=%s host=%s rir=%s ip=%s\n",
            (access_denied_current || access_denied_internal) ? "denied" : "rate-limit",
            access_denied_internal ? "internal" : "current",
            (dbg_host && *dbg_host) ? dbg_host : "unknown",
            (dbg_rir && *dbg_rir) ? dbg_rir : "unknown",
            dbg_ip);
    }
}

static const char* wc_lookup_exec_select_last_failure_ip_candidate_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_internal,
    const char* err_host);
static void wc_lookup_exec_write_last_failure_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

static void wc_lookup_exec_fill_last_failure_ip(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_internal,
    const char* err_host) {
    if (!ctx || !err_host) return;

    if (ctx->last_failure_ip && ctx->last_failure_ip_len > 0 &&
        (!ctx->last_failure_ip[0])) {
        const char* ip = wc_lookup_exec_select_last_failure_ip_candidate_step(
            ctx,
            access_denied_internal,
            err_host);
        wc_lookup_exec_write_last_failure_ip_output_step(ctx, ip);
    }
}

static const char* wc_lookup_exec_select_last_failure_ip_candidate_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_internal,
    const char* err_host) {
    if (!ctx || !err_host) return NULL;

    if (!access_denied_internal && ctx->ni && ctx->ni->ip[0]) {
        return ctx->ni->ip;
    }

    const char* known_ip = wc_dns_get_known_ip(err_host);
    return (known_ip && known_ip[0]) ? known_ip : NULL;
}

static void wc_lookup_exec_write_last_failure_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip) {
    if (!ctx || !ip || !*ip) return;

    snprintf(ctx->last_failure_ip, ctx->last_failure_ip_len, "%s", ip);
}

static void wc_lookup_exec_write_last_failure_status_desc_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* status,
    const char* desc);

static void wc_lookup_exec_write_last_failure_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* err_host);
static void wc_lookup_exec_write_last_failure_rir_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* err_rir);

static void wc_lookup_exec_record_access_failure(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host) {
    if (!ctx) return;

    if (access_denied_current || access_denied_internal || rate_limit_current) {
        const char* err_host = access_denied_internal ? header_host : ctx->current_host;
        wc_lookup_exec_write_last_failure_host_output_step(ctx, err_host);
        const char* err_rir = wc_guess_rir(err_host);
        wc_lookup_exec_write_last_failure_rir_output_step(ctx, err_rir);
        if (access_denied_current || access_denied_internal) {
            wc_lookup_exec_write_last_failure_status_desc_output_step(
                ctx,
                "denied",
                "access-denied");
        } else {
            wc_lookup_exec_write_last_failure_status_desc_output_step(
                ctx,
                "rate-limit",
                "rate-limit-exceeded");
        }
        wc_lookup_exec_fill_last_failure_ip(
            ctx,
            access_denied_internal,
            err_host);
    }
}

static void wc_lookup_exec_write_last_failure_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* err_host) {
    if (!ctx || !err_host) return;

    if (ctx->last_failure_host && ctx->last_failure_host_len > 0 && *err_host) {
        snprintf(ctx->last_failure_host, ctx->last_failure_host_len, "%s", err_host);
    }
}

static void wc_lookup_exec_write_last_failure_rir_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* err_rir) {
    if (!ctx || !err_rir) return;

    if (ctx->last_failure_rir && ctx->last_failure_rir_len > 0 && *err_rir) {
        snprintf(ctx->last_failure_rir, ctx->last_failure_rir_len, "%s", err_rir);
    }
}

static void wc_lookup_exec_write_last_failure_status_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* status);
static void wc_lookup_exec_write_last_failure_desc_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* desc);

static void wc_lookup_exec_write_last_failure_status_desc_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* status,
    const char* desc) {
    if (!ctx) return;

    wc_lookup_exec_write_last_failure_status_output_step(ctx, status);
    wc_lookup_exec_write_last_failure_desc_output_step(ctx, desc);
}

static void wc_lookup_exec_write_last_failure_status_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* status) {
    if (!ctx) return;

    if (ctx->last_failure_status) {
        *ctx->last_failure_status = status;
    }
}

static void wc_lookup_exec_write_last_failure_desc_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* desc) {
    if (!ctx) return;

    if (ctx->last_failure_desc) {
        *ctx->last_failure_desc = desc;
    }
}

static void wc_lookup_exec_filter_failure_body(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current) {
    if (!ctx || !body || !*body) return;

    if (ctx->cfg && ctx->cfg->hide_failure_body && *body && **body) {
        if (access_denied_current || access_denied_internal) {
            char* filtered_body = wc_lookup_strip_access_denied_lines(*body);
            if (filtered_body) {
                free(*body);
                *body = filtered_body;
                ctx->body = *body;
            }
        } else if (rate_limit_current) {
            char* filtered_body = wc_lookup_strip_rate_limit_lines(*body);
            if (filtered_body) {
                free(*body);
                *body = filtered_body;
                ctx->body = *body;
            }
        }
    }
}

static void wc_lookup_exec_mark_saw_rate_limit_or_denied_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_mark_access_failure(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current) {
    if (!ctx) return;

    if (access_denied_current || access_denied_internal || rate_limit_current) {
        wc_lookup_exec_mark_saw_rate_limit_or_denied_output_step(ctx);
    }
}

static void wc_lookup_exec_mark_saw_rate_limit_or_denied_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->saw_rate_limit_or_denied) {
        *ctx->saw_rate_limit_or_denied = 1;
    }
}

static void wc_lookup_exec_remove_current_host_from_visited_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_remove_mapped_host_from_visited_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_remove_canonical_host_from_visited_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_remove_current_from_visited(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->visited || !ctx->visited_count) return;

    wc_lookup_exec_remove_current_host_from_visited_step(ctx);
    wc_lookup_exec_remove_mapped_host_from_visited_step(ctx);
    wc_lookup_exec_remove_canonical_host_from_visited_step(ctx);
}

static void wc_lookup_exec_remove_current_host_from_visited_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->visited || !ctx->visited_count) return;

    wc_lookup_visited_remove(ctx->visited, ctx->visited_count, ctx->current_host);
}

static void wc_lookup_exec_remove_mapped_host_from_visited_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->visited || !ctx->visited_count) return;

    if (wc_dns_is_ip_literal(ctx->current_host)) {
        const char* mapped_host = wc_lookup_known_ip_host_from_literal(ctx->current_host);
        if (mapped_host && *mapped_host) {
            wc_lookup_visited_remove(ctx->visited, ctx->visited_count, mapped_host);
        }
    }
}

static void wc_lookup_exec_remove_canonical_host_from_visited_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->visited || !ctx->visited_count) return;

    const char* canon_visit = wc_dns_canonical_alias(ctx->current_host);
    if (canon_visit && *canon_visit) {
        wc_lookup_visited_remove(ctx->visited, ctx->visited_count, canon_visit);
    }
}

static void wc_lookup_exec_handle_persistent_empty(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int first_hop_persistent_empty,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    if (ctx->persistent_empty && ctx->current_rir_guess) {
        *header_non_authoritative = 1;
        *need_redir_eval = 1;
        if (first_hop_persistent_empty) {
            if (strcasecmp(ctx->current_rir_guess, "arin") == 0) {
                wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
            }
            wc_lookup_exec_remove_current_from_visited(ctx);
        } else {
            wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
        }
    }
}

static void wc_lookup_exec_handle_apnic_ipv6_root(
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_ipv6_root(body)) {
        wc_lookup_exec_mark_non_auth(header_non_authoritative, need_redir_eval);
    }
}

static void wc_lookup_exec_handle_apnic_erx_legacy_signal(
    const char* body,
    int* header_non_authoritative) {
    if (!body || !header_non_authoritative) return;

    if (wc_lookup_body_contains_erx_legacy(body)) {
        wc_lookup_exec_mark_header_non_auth(header_non_authoritative);
    }
}

static void wc_lookup_exec_mark_header_non_auth(int* header_non_authoritative) {
    if (!header_non_authoritative) return;

    *header_non_authoritative = 1;
}

static void wc_lookup_exec_handle_apnic_non_auth_root(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_apnic_ipv6_root(
        body,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_handle_apnic_erx_legacy_signal(
        body,
        header_non_authoritative);
}

static int wc_lookup_exec_is_current_rir_apnic(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    return ctx && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "apnic") == 0;
}

static void wc_lookup_exec_handle_apnic_non_auth_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_current_rir_apnic(ctx)) {
        wc_lookup_exec_handle_apnic_non_auth_root(
            ctx,
            body,
            header_non_authoritative,
            need_redir_eval);
        wc_lookup_exec_handle_apnic_netblock_root(ctx, body);
    }
}

static void wc_lookup_exec_set_apnic_redirect_reason(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int reason) {
    if (!ctx || !ctx->apnic_redirect_reason) return;

    if (*ctx->apnic_redirect_reason == 0) {
        wc_lookup_exec_set_apnic_redirect_reason_value(ctx->apnic_redirect_reason, reason);
    }
}

static void wc_lookup_exec_set_apnic_redirect_reason_value(
    int* apnic_redirect_reason,
    int reason) {
    if (!apnic_redirect_reason) return;

    *apnic_redirect_reason = reason;
}

static int wc_lookup_exec_should_write_apnic_erx_root_host_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static const char* wc_lookup_exec_select_apnic_erx_root_host_value_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_apnic_erx_root_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* apnic_root);

static int wc_lookup_exec_should_write_apnic_erx_root_ip_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static const char* wc_lookup_exec_select_apnic_erx_root_ip_value_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_apnic_erx_root_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

static void wc_lookup_exec_set_apnic_root_host_ip(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (wc_lookup_exec_should_write_apnic_erx_root_host_output_step(ctx)) {
        const char* apnic_root = wc_lookup_exec_select_apnic_erx_root_host_value_step(ctx);
        wc_lookup_exec_write_apnic_erx_root_host_output_step(ctx, apnic_root);
    }
    if (wc_lookup_exec_should_write_apnic_erx_root_ip_output_step(ctx)) {
        const char* ip = wc_lookup_exec_select_apnic_erx_root_ip_value_step(ctx);
        wc_lookup_exec_write_apnic_erx_root_ip_output_step(ctx, ip);
    }
}

static int wc_lookup_exec_should_write_apnic_erx_root_host_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
            ctx->apnic_erx_root_host[0] == '\0') ? 1 : 0;
}

static const char* wc_lookup_exec_select_apnic_erx_root_host_value_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return NULL;

    const char* apnic_root = wc_dns_canonical_alias(ctx->current_host);
    return apnic_root ? apnic_root : ctx->current_host;
}

static void wc_lookup_exec_write_apnic_erx_root_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* apnic_root) {
    if (!ctx || !apnic_root) return;

    snprintf(ctx->apnic_erx_root_host, ctx->apnic_erx_root_host_len, "%s", apnic_root);
}

static int wc_lookup_exec_should_write_apnic_erx_root_ip_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip_len > 0 &&
            ctx->apnic_erx_root_ip[0] == '\0' && ctx->ni && ctx->ni->ip[0]) ? 1 : 0;
}

static const char* wc_lookup_exec_select_apnic_erx_root_ip_value_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->ni) return NULL;

    return ctx->ni->ip;
}

static void wc_lookup_exec_write_apnic_erx_root_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip) {
    if (!ctx || !ip || !*ip) return;

    snprintf(ctx->apnic_erx_root_ip, ctx->apnic_erx_root_ip_len, "%s", ip);
}

static void wc_lookup_exec_mark_seen_apnic_iana_netblock_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_set_seen_apnic_iana_netblock(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_apnic_iana_netblock) return;

    wc_lookup_exec_mark_seen_apnic_iana_netblock_output_step(ctx);
}

static void wc_lookup_exec_mark_seen_apnic_iana_netblock_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_apnic_iana_netblock) return;

    *ctx->seen_apnic_iana_netblock = 1;
}

static void wc_lookup_exec_handle_apnic_netblock_root(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return;

    if (wc_lookup_exec_is_apnic_netblock(body)) {
        wc_lookup_exec_set_seen_apnic_iana_netblock(ctx);
        wc_lookup_exec_update_apnic_root_if_needed(ctx);
        wc_lookup_exec_set_apnic_redirect_reason(ctx, 2);
    }
}

static int wc_lookup_exec_is_apnic_netblock(const char* body) {
    return body && wc_lookup_body_contains_apnic_iana_netblock(body);
}

static int wc_lookup_exec_is_ripe_non_auth(const char* body) {
    return body && (wc_lookup_body_contains_ipv6_root(body) ||
        wc_lookup_body_contains_ripe_access_denied(body));
}

static int wc_lookup_exec_is_current_rir_ripe(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    return ctx && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "ripe") == 0;
}

static void wc_lookup_exec_handle_ripe_non_auth(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_current_rir_ripe(ctx)) {
        if (wc_lookup_exec_is_ripe_non_auth(body)) {
            wc_lookup_exec_handle_ripe_non_auth_state(
                ctx,
                header_non_authoritative,
                need_redir_eval);
        }
    }
}

static void wc_lookup_exec_handle_ripe_non_auth_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    *header_non_authoritative = 1;
    *need_redir_eval = 1;
    wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
}

static int wc_lookup_exec_is_ipv6_root(const char* body) {
    return body && wc_lookup_body_contains_ipv6_root(body);
}

static int wc_lookup_exec_is_current_rir_afrinic(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    return ctx && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "afrinic") == 0;
}

static void wc_lookup_exec_handle_afrinic_non_auth(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_current_rir_afrinic(ctx)) {
        if (wc_lookup_exec_is_ipv6_root(body)) {
            wc_lookup_exec_handle_afrinic_non_auth_state(
                ctx,
                header_non_authoritative,
                need_redir_eval);
        }
    }
}

static void wc_lookup_exec_handle_afrinic_non_auth_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_mark_non_auth_and_cycle(
        ctx,
        header_non_authoritative,
        need_redir_eval);
}

static int wc_lookup_exec_is_arin_no_match(const char* body) {
    return body && wc_lookup_body_contains_no_match(body);
}

static int wc_lookup_exec_is_current_rir_arin(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    return ctx && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "arin") == 0;
}

static void wc_lookup_exec_handle_arin_non_auth(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_current_rir_arin(ctx)) {
        if (wc_lookup_exec_is_arin_no_match(body) || !auth) {
            wc_lookup_exec_mark_non_auth(header_non_authoritative, need_redir_eval);
        }
    }
}

static void wc_lookup_exec_mark_non_auth(
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!header_non_authoritative || !need_redir_eval) return;

    *header_non_authoritative = 1;
    *need_redir_eval = 1;
}

static void wc_lookup_exec_mark_non_auth_and_cycle(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_mark_non_auth(header_non_authoritative, need_redir_eval);
    wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
}

static void wc_lookup_exec_update_apnic_root_if_needed(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->apnic_erx_root) return;

    if (!*ctx->apnic_erx_root) {
        wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
        wc_lookup_exec_set_apnic_root_host_ip(ctx);
    }
}

static void wc_lookup_exec_handle_other_rir_non_auth_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_ripe_non_auth(
        ctx,
        body,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_handle_afrinic_non_auth(
        ctx,
        body,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_handle_arin_non_auth(
        ctx,
        body,
        auth,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_handle_first_hop_denied_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int rate_limit_current,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_should_first_hop_cycle(ctx, access_denied_current, rate_limit_current)) {
        wc_lookup_exec_handle_first_hop_cycle_state(
            ctx,
            header_non_authoritative,
            need_redir_eval);
    }
}

static void wc_lookup_exec_handle_first_hop_cycle_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_mark_non_auth_and_cycle(ctx, header_non_authoritative, need_redir_eval);
    wc_lookup_exec_remove_current_from_visited(ctx);
}

static int wc_lookup_exec_should_first_hop_cycle(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int rate_limit_current) {
    if (!ctx) return 0;

    return ctx->current_rir_guess && ctx->hops == 0 &&
        (access_denied_current || rate_limit_current);
}

static int wc_lookup_exec_should_set_arin_cidr_no_match(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return 0;

    return wc_lookup_exec_is_current_rir_arin(ctx) &&
        wc_lookup_exec_is_arin_no_match(body);
}

static int wc_lookup_exec_should_set_ripe_cidr_non_managed(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed) {
    if (!ctx) return 0;

    return wc_lookup_exec_is_current_rir_ripe(ctx) && ripe_non_managed;
}

static int wc_lookup_exec_should_set_afrinic_cidr_full_ipv4(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return 0;

    return wc_lookup_exec_is_current_rir_afrinic(ctx) &&
        wc_lookup_exec_is_full_ipv4_space(body);
}

static void wc_lookup_exec_mark_seen_arin_no_match_cidr_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_set_seen_arin_no_match_cidr(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_arin_no_match_cidr) return;

    wc_lookup_exec_mark_seen_arin_no_match_cidr_output_step(ctx);
}

static void wc_lookup_exec_mark_seen_arin_no_match_cidr_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_arin_no_match_cidr) return;

    *ctx->seen_arin_no_match_cidr = 1;
}

static void wc_lookup_exec_set_seen_ripe_non_managed(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_ripe_non_managed) return;

    wc_lookup_exec_mark_seen_ripe_non_managed_output_step(ctx);
}

static void wc_lookup_exec_set_seen_afrinic_iana_blk(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_afrinic_iana_blk) return;

    wc_lookup_exec_mark_seen_afrinic_iana_blk_output_step(ctx);
}

static void wc_lookup_exec_handle_arin_cidr_effects(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return;

    if (wc_lookup_exec_should_set_arin_cidr_no_match(ctx, body)) {
        wc_lookup_exec_set_seen_arin_no_match_cidr(ctx);
    }
}

static void wc_lookup_exec_handle_ripe_cidr_effects(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed) {
    if (!ctx) return;

    if (wc_lookup_exec_should_set_ripe_cidr_non_managed(ctx, ripe_non_managed)) {
        wc_lookup_exec_set_seen_ripe_non_managed(ctx);
    }
}

static int wc_lookup_exec_is_full_ipv4_space(const char* body) {
    return body && wc_lookup_body_contains_full_ipv4_space(body);
}

static void wc_lookup_exec_handle_afrinic_cidr_effects(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return;

    if (wc_lookup_exec_should_set_afrinic_cidr_full_ipv4(ctx, body)) {
        wc_lookup_exec_set_seen_afrinic_iana_blk(ctx);
    }
}

static int wc_lookup_exec_should_set_lacnic_cidr_unallocated(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return 0;

    return ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "lacnic") == 0 &&
        wc_lookup_exec_is_lacnic_cidr_unallocated(body);
}

static int wc_lookup_exec_is_lacnic_cidr_unallocated(const char* body) {
    return wc_lookup_exec_is_lacnic_unallocated(body);
}

static void wc_lookup_exec_handle_lacnic_cidr_effects(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return;

    if (wc_lookup_exec_should_set_lacnic_cidr_unallocated(ctx, body)) {
        wc_lookup_exec_set_seen_lacnic_unallocated(ctx);
    }
}

static void wc_lookup_exec_mark_seen_lacnic_unallocated_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_set_seen_lacnic_unallocated(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_lacnic_unallocated) return;

    wc_lookup_exec_mark_seen_lacnic_unallocated_output_step(ctx);
}

static void wc_lookup_exec_mark_seen_lacnic_unallocated_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_lacnic_unallocated) return;

    *ctx->seen_lacnic_unallocated = 1;
}

static void wc_lookup_exec_handle_cidr_side_effects(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int ripe_non_managed) {
    if (!ctx || !body) return;

    if (ctx->query_is_cidr_effective && ctx->current_rir_guess) {
        wc_lookup_exec_handle_arin_cidr_effects(ctx, body);
        wc_lookup_exec_handle_ripe_cidr_effects(ctx, ripe_non_managed);
        wc_lookup_exec_handle_afrinic_cidr_effects(ctx, body);
        wc_lookup_exec_handle_lacnic_cidr_effects(ctx, body);
    }
}

static void wc_lookup_exec_handle_lacnic_unallocated(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_lacnic_unallocated(body)) {
        wc_lookup_exec_mark_header_non_auth(header_non_authoritative);
        if (wc_lookup_exec_missing_ref(ctx)) {
            *need_redir_eval = 1;
        }
    }
}

static int wc_lookup_exec_missing_ref(const struct wc_lookup_exec_redirect_ctx* ctx) {
    return !ctx || !ctx->ref || !*ctx->ref;
}

static int wc_lookup_exec_is_lacnic_unallocated(const char* body) {
    return body && wc_lookup_body_contains_lacnic_unallocated(body);
}

static void wc_lookup_exec_handle_lacnic_non_auth_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_current_rir_lacnic(ctx)) {
        wc_lookup_exec_handle_lacnic_unallocated(
            ctx,
            body,
            header_non_authoritative,
            need_redir_eval);
        wc_lookup_exec_handle_lacnic_rate_limit(
            ctx,
            body,
            header_non_authoritative,
            need_redir_eval);
    }
}

static void wc_lookup_exec_handle_lacnic_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    if (wc_lookup_exec_is_lacnic_rate_limited(body)) {
        wc_lookup_exec_handle_lacnic_rate_limit_state(
            ctx,
            header_non_authoritative,
            need_redir_eval);
    }
}

static int wc_lookup_exec_is_current_rir_lacnic(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    return ctx && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "lacnic") == 0;
}

static void wc_lookup_exec_handle_lacnic_rate_limit_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_mark_non_auth(header_non_authoritative, need_redir_eval);
    wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
    if (ctx->hops == 0 && ctx->visited && ctx->visited_count) {
        wc_lookup_exec_remove_current_from_visited(ctx);
    }
}

static int wc_lookup_exec_is_lacnic_rate_limited(const char* body) {
    return body && wc_lookup_body_contains_lacnic_rate_limit(body);
}

static void wc_lookup_exec_handle_ripe_non_managed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    if (ripe_non_managed) {
        wc_lookup_exec_mark_non_auth_and_cycle(
            ctx,
            header_non_authoritative,
            need_redir_eval);
    }
}

static void wc_lookup_exec_handle_full_ipv4_space_signal(
    const char* body,
    int* header_non_authoritative) {
    if (!body || !header_non_authoritative) return;

    if (wc_lookup_exec_should_mark_full_ipv4(body)) {
        wc_lookup_exec_mark_header_non_auth(header_non_authoritative);
    }
}

static int wc_lookup_exec_should_mark_full_ipv4(const char* body) {
    return wc_lookup_exec_is_full_ipv4_space(body);
}

static void wc_lookup_exec_apply_rir_non_auth_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_apnic_non_auth_signals(
        ctx,
        body,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_handle_other_rir_non_auth_signals(
        ctx,
        body,
        auth,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_run_rir_non_auth_signal_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_apply_rir_non_auth_signals(
        ctx,
        body,
        auth,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_apply_hop_and_ripe_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_first_hop_denied_rate_limit(
        ctx,
        access_denied_current,
        rate_limit_current,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_handle_ripe_non_managed(
        ctx,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_run_hop_and_ripe_signal_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_apply_hop_and_ripe_signals(
        ctx,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_apply_cidr_side_effects_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int ripe_non_managed) {
    if (!ctx || !body) return;

    wc_lookup_exec_handle_cidr_side_effects(
        ctx,
        body,
        ripe_non_managed);
}

static void wc_lookup_exec_apply_lacnic_non_auth_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_lacnic_non_auth_signals(
        ctx,
        body,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_apply_full_ipv4_signal_step(
    const char* body,
    int* header_non_authoritative) {
    if (!body || !header_non_authoritative) return;

    wc_lookup_exec_handle_full_ipv4_space_signal(
        body,
        header_non_authoritative);
}

static void wc_lookup_exec_apply_cidr_and_lacnic_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_apply_cidr_side_effects_step(
        ctx,
        body,
        ripe_non_managed);
    wc_lookup_exec_apply_lacnic_non_auth_step(
        ctx,
        body,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_apply_full_ipv4_signal_step(
        body,
        header_non_authoritative);
}

static void wc_lookup_exec_run_cidr_and_lacnic_signal_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_apply_cidr_and_lacnic_signals(
        ctx,
        body,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_run_non_auth_and_cidr_signal_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_run_rir_non_auth_signal_steps(
        ctx,
        body,
        auth,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_run_hop_and_ripe_signal_steps(
        ctx,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_run_cidr_and_lacnic_signal_steps(
        ctx,
        body,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_handle_non_auth_and_cidr_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_run_non_auth_and_cidr_signal_steps(
        ctx,
        body,
        auth,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static const char* wc_lookup_exec_erx_marker_host(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    const char* header_hint_host) {
    const char* erx_marker_host_local = ctx ? ctx->current_host : NULL;
    if (wc_lookup_exec_should_handle_lacnic_non_auth(ctx)) {
        if (header_hint_host && header_hint_host[0])
            erx_marker_host_local = header_hint_host;
        else
            erx_marker_host_local = header_host;
    }
    return erx_marker_host_local;
}

static int wc_lookup_exec_should_write_erx_marker_ip_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);
static const char* wc_lookup_exec_select_erx_marker_ip_value_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);
static void wc_lookup_exec_write_erx_marker_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

static void wc_lookup_exec_set_erx_marker_ip(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local || !ctx->erx_marker_ip || ctx->erx_marker_ip_len == 0) {
        return;
    }

    if (!wc_lookup_exec_should_write_erx_marker_ip_output_step(ctx, erx_marker_host_local)) {
        return;
    }

    const char* ip = wc_lookup_exec_select_erx_marker_ip_value_step(ctx, erx_marker_host_local);
    wc_lookup_exec_write_erx_marker_ip_output_step(ctx, ip);
}

static int wc_lookup_exec_should_write_erx_marker_ip_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return 0;

    if (erx_marker_host_local && strcasecmp(erx_marker_host_local, ctx->current_host) == 0) {
        return (ctx->ni && ctx->ni->ip[0]) ? 1 : 0;
    }

    const char* known_ip = wc_dns_get_known_ip(erx_marker_host_local);
    return (known_ip && known_ip[0]) ? 1 : 0;
}

static const char* wc_lookup_exec_select_erx_marker_ip_value_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return NULL;

    if (erx_marker_host_local && strcasecmp(erx_marker_host_local, ctx->current_host) == 0) {
        return (ctx->ni && ctx->ni->ip[0]) ? ctx->ni->ip : NULL;
    }

    const char* known_ip = wc_dns_get_known_ip(erx_marker_host_local);
    return (known_ip && known_ip[0]) ? known_ip : NULL;
}

static void wc_lookup_exec_write_erx_marker_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip) {
    if (!ctx || !ip || !*ip) return;

    snprintf(ctx->erx_marker_ip, ctx->erx_marker_ip_len, "%s", ip);
}

static int wc_lookup_exec_should_handle_lacnic_non_auth(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    return wc_lookup_exec_is_current_rir_lacnic(ctx);
}

static int wc_lookup_exec_should_record_erx_marker(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->erx_marker_seen && ctx->erx_marker_host && ctx->erx_marker_ip &&
        ctx->erx_marker_host_len > 0 && ctx->erx_marker_ip_len > 0 &&
        !*ctx->erx_marker_seen;
}

static void wc_lookup_exec_erx_marker_apply_output_flags_step(
    int* header_non_authoritative,
    int* need_redir_eval);
static void wc_lookup_exec_erx_marker_record_metadata_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);
static void wc_lookup_exec_erx_marker_record_seen_and_host_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);
static void wc_lookup_exec_erx_marker_record_ip_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);
static void wc_lookup_exec_erx_fast_authoritative_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res);
static void wc_lookup_exec_erx_fast_authoritative_writeback_host_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);
static void wc_lookup_exec_erx_fast_authoritative_writeback_ip_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res);
static void wc_lookup_exec_erx_fast_authoritative_mark_flag_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_erx_fast_authoritative_cleanup_redirect_step(
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref);
static void wc_lookup_exec_erx_fast_authoritative_set_auth_step(int* auth);

static void wc_lookup_exec_erx_marker_set_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_erx_marker_apply_output_flags_step(
        header_non_authoritative,
        need_redir_eval);
    wc_lookup_exec_erx_marker_record_metadata_step(
        ctx,
        erx_marker_host_local);
}

static void wc_lookup_exec_erx_marker_apply_output_flags_step(
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!header_non_authoritative || !need_redir_eval) return;

    *header_non_authoritative = 1;
    *need_redir_eval = 1;
}

static void wc_lookup_exec_erx_marker_record_metadata_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return;

    if (wc_lookup_exec_should_record_erx_marker(ctx)) {
        wc_lookup_exec_erx_marker_record_seen_and_host_step(
            ctx,
            erx_marker_host_local);
        wc_lookup_exec_erx_marker_record_ip_step(
            ctx,
            erx_marker_host_local);
    }
}

static void wc_lookup_exec_mark_erx_marker_seen_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_erx_marker_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);

static void wc_lookup_exec_erx_marker_record_seen_and_host_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return;

    wc_lookup_exec_mark_erx_marker_seen_output_step(ctx);
    wc_lookup_exec_write_erx_marker_host_output_step(ctx, erx_marker_host_local);
}

static void wc_lookup_exec_mark_erx_marker_seen_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    *ctx->erx_marker_seen = 1;
}

static void wc_lookup_exec_write_erx_marker_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return;

    snprintf(ctx->erx_marker_host, ctx->erx_marker_host_len, "%s", erx_marker_host_local);
}

static void wc_lookup_exec_erx_marker_record_ip_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return;

    wc_lookup_exec_set_erx_marker_ip(ctx, erx_marker_host_local);
}

static void wc_lookup_exec_set_erx_fast_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !erx_marker_host_local || !recheck_res || !auth ||
        !header_non_authoritative || !need_redir_eval || !ref) {
        return;
    }

    wc_lookup_exec_erx_fast_authoritative_writeback_step(
        ctx,
        erx_marker_host_local,
        recheck_res);
    wc_lookup_exec_erx_fast_authoritative_cleanup_redirect_step(
        header_non_authoritative,
        need_redir_eval,
        ref);
    wc_lookup_exec_erx_fast_authoritative_set_auth_step(auth);
}

static void wc_lookup_exec_erx_fast_authoritative_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res) {
    if (!ctx || !erx_marker_host_local || !recheck_res) {
        return;
    }

    wc_lookup_exec_erx_fast_authoritative_writeback_host_step(
        ctx,
        erx_marker_host_local);
    wc_lookup_exec_erx_fast_authoritative_writeback_ip_step(
        ctx,
        erx_marker_host_local,
        recheck_res);
    wc_lookup_exec_erx_fast_authoritative_mark_flag_step(ctx);
}

static void wc_lookup_exec_erx_fast_authoritative_writeback_host_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return;

    wc_lookup_exec_erx_set_fast_authoritative_host(
        ctx,
        erx_marker_host_local);
}

static void wc_lookup_exec_erx_fast_authoritative_writeback_ip_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res) {
    if (!ctx || !erx_marker_host_local || !recheck_res) return;

    wc_lookup_exec_erx_set_fast_authoritative_ip(
        ctx,
        erx_marker_host_local,
        recheck_res);
}

static void wc_lookup_exec_mark_erx_fast_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_erx_fast_authoritative_mark_flag_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    wc_lookup_exec_mark_erx_fast_authoritative_output_step(ctx);
}

static void wc_lookup_exec_mark_erx_fast_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->erx_fast_authoritative) {
        *ctx->erx_fast_authoritative = 1;
    }
}

static void wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(
    int* need_redir_eval,
    char** ref) {
    if (!need_redir_eval || !ref) return;

    *need_redir_eval = 0;
    if (*ref) {
        free(*ref);
        *ref = NULL;
    }
}

static void wc_lookup_exec_erx_fast_authoritative_cleanup_redirect_step(
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!header_non_authoritative || !need_redir_eval || !ref) {
        return;
    }

    *header_non_authoritative = 0;
    wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
}

static void wc_lookup_exec_erx_fast_authoritative_set_auth_step(int* auth) {
    if (!auth) return;

    *auth = 1;
}

static const char* wc_lookup_exec_erx_select_fast_authoritative_host_value_step(
    const char* erx_marker_host_local);
static void wc_lookup_exec_write_erx_fast_authoritative_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* host_value);

static void wc_lookup_exec_erx_set_fast_authoritative_host(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local) return;

    if (ctx->erx_fast_authoritative_host && ctx->erx_fast_authoritative_host_len > 0) {
        const char* host_value = wc_lookup_exec_erx_select_fast_authoritative_host_value_step(
            erx_marker_host_local);
        wc_lookup_exec_write_erx_fast_authoritative_host_output_step(ctx, host_value);
    }
}

static const char* wc_lookup_exec_erx_select_fast_authoritative_host_value_step(
    const char* erx_marker_host_local) {
    if (!erx_marker_host_local) return NULL;

    const char* canon_host = wc_dns_canonical_alias(erx_marker_host_local);
    return canon_host ? canon_host : erx_marker_host_local;
}

static void wc_lookup_exec_write_erx_fast_authoritative_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* host_value) {
    if (!ctx || !host_value) return;

    snprintf(ctx->erx_fast_authoritative_host,
        ctx->erx_fast_authoritative_host_len,
        "%s",
        host_value);
}

static const char* wc_lookup_exec_erx_select_fast_authoritative_ip(
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res);

static void wc_lookup_exec_write_erx_fast_authoritative_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip_value);

static void wc_lookup_exec_erx_set_fast_authoritative_ip(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res) {
    if (!ctx || !erx_marker_host_local || !recheck_res) return;

    if (ctx->erx_fast_authoritative_ip && ctx->erx_fast_authoritative_ip_len > 0) {
        const char* ip_value = wc_lookup_exec_erx_select_fast_authoritative_ip(
            erx_marker_host_local,
            recheck_res);
        wc_lookup_exec_write_erx_fast_authoritative_ip_output_step(ctx, ip_value);
    }
}

static void wc_lookup_exec_write_erx_fast_authoritative_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip_value) {
    if (!ctx) return;

    snprintf(ctx->erx_fast_authoritative_ip,
        ctx->erx_fast_authoritative_ip_len,
        "%s",
        (ip_value && ip_value[0]) ? ip_value : "unknown");
}

static const char* wc_lookup_exec_erx_select_fast_authoritative_ip(
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res) {
    if (!erx_marker_host_local || !recheck_res) return "unknown";

    if (recheck_res->meta.authoritative_ip[0] &&
        strcasecmp(recheck_res->meta.authoritative_ip, "unknown") != 0) {
        return recheck_res->meta.authoritative_ip;
    }
    if (recheck_res->meta.last_ip[0]) {
        return recheck_res->meta.last_ip;
    }

    const char* known_ip = wc_dns_get_known_ip(erx_marker_host_local);
    return (known_ip && known_ip[0]) ? known_ip : "unknown";
}

static void wc_lookup_exec_erx_extract_recheck_signals(
    const char* recheck_body,
    int* recheck_erx,
    int* recheck_non_auth) {
    if (!recheck_erx || !recheck_non_auth) return;

    *recheck_erx = wc_lookup_body_contains_erx_iana_marker(recheck_body);
    *recheck_non_auth = wc_lookup_body_has_strong_redirect_hint(recheck_body);
}

static int wc_lookup_exec_erx_should_set_fast_authoritative(
    int recheck_erx,
    int recheck_non_auth) {
    return (!recheck_erx && !recheck_non_auth);
}

static void wc_lookup_exec_erx_handle_valid_recheck_body(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    const struct wc_result* recheck_res,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !recheck_res || !erx_marker_host_local || !auth || !header_non_authoritative ||
        !need_redir_eval || !ref) {
        return;
    }

    int recheck_erx = 0;
    int recheck_non_auth = 0;
    wc_lookup_exec_erx_extract_recheck_signals(
        recheck_res->body,
        &recheck_erx,
        &recheck_non_auth);
    wc_lookup_exec_erx_log_fast_recheck_result(
        ctx,
        recheck_erx,
        recheck_non_auth);

    if (wc_lookup_exec_erx_should_set_fast_authoritative(recheck_erx, recheck_non_auth)) {
        wc_lookup_exec_set_erx_fast_authoritative(
            ctx,
            erx_marker_host_local,
            recheck_res,
            auth,
            header_non_authoritative,
            need_redir_eval,
            ref);
    }
}

static void wc_lookup_exec_erx_handle_invalid_recheck_body(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int recheck_rc) {
    wc_lookup_exec_erx_log_fast_recheck_failure(
        ctx,
        recheck_rc);
}

static void wc_lookup_exec_erx_handle_fast_recheck_result(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    int recheck_rc,
    const struct wc_result* recheck_res,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !recheck_res || !erx_marker_host_local || !auth || !header_non_authoritative ||
        !need_redir_eval || !ref) {
        return;
    }

    if (wc_lookup_exec_erx_has_valid_recheck_body(recheck_rc, recheck_res)) {
        wc_lookup_exec_erx_handle_valid_recheck_body(
            ctx,
            erx_marker_host_local,
            recheck_res,
            auth,
            header_non_authoritative,
            need_redir_eval,
            ref);
    } else {
        wc_lookup_exec_erx_handle_invalid_recheck_body(
            ctx,
            recheck_rc);
    }
}

static int wc_lookup_exec_erx_has_valid_recheck_body(
    int recheck_rc,
    const struct wc_result* recheck_res) {
    return recheck_rc == 0 && recheck_res && recheck_res->body && recheck_res->body[0];
}

static void wc_lookup_exec_erx_log_fast_recheck_result(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int recheck_erx,
    int recheck_non_auth) {
    if (!ctx || !ctx->cfg || !ctx->cfg->debug) return;

    fprintf(stderr,
        "[DEBUG] ERX fast recheck result: erx=%d non_auth=%d\n",
        recheck_erx,
        recheck_non_auth);
}

static void wc_lookup_exec_erx_log_fast_recheck_failure(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int recheck_rc) {
    if (!ctx || !ctx->cfg || !ctx->cfg->debug) return;

    fprintf(stderr,
        "[DEBUG] ERX fast recheck failed: rc=%d\n",
        recheck_rc);
}

static void wc_lookup_exec_mark_erx_baseline_recheck_attempted_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_mark_erx_fast_recheck_done_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_erx_fast_recheck_begin(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    struct wc_lookup_opts* recheck_opts,
    struct wc_query* recheck_q) {
    if (!ctx || !erx_marker_host_local || !recheck_opts || !recheck_q) {
        return;
    }

    wc_lookup_exec_erx_apply_batch_delay(ctx);
    *recheck_opts = *ctx->zopts;
    wc_lookup_exec_erx_prepare_recheck(
        ctx,
        erx_marker_host_local,
        recheck_opts,
        recheck_q);

    wc_lookup_erx_baseline_recheck_guard_set(1);
    wc_lookup_exec_mark_erx_baseline_recheck_attempted_output_step(ctx);
    wc_lookup_exec_mark_erx_fast_recheck_done_output_step(ctx);

    if (ctx->cfg && ctx->cfg->debug) {
        fprintf(stderr,
            "[DEBUG] ERX fast recheck: query=%s host=%s\n",
            ctx->cidr_base_query,
            erx_marker_host_local);
    }
}

static void wc_lookup_exec_mark_erx_baseline_recheck_attempted_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->erx_baseline_recheck_attempted) {
        *ctx->erx_baseline_recheck_attempted = 1;
    }
}

static void wc_lookup_exec_mark_erx_fast_recheck_done_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    *ctx->erx_fast_recheck_done = 1;
}

static void wc_lookup_exec_erx_fast_recheck_finish(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    struct wc_lookup_opts* recheck_opts,
    struct wc_query* recheck_q,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !erx_marker_host_local || !recheck_opts || !recheck_q || !auth ||
        !header_non_authoritative || !need_redir_eval || !ref) {
        return;
    }

    struct wc_result recheck_res;
    int recheck_rc = wc_lookup_execute(recheck_q, recheck_opts, &recheck_res);
    wc_lookup_erx_baseline_recheck_guard_set(0);

    wc_lookup_exec_erx_handle_fast_recheck_result(
        ctx,
        erx_marker_host_local,
        recheck_rc,
        &recheck_res,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref);
    wc_lookup_result_free(&recheck_res);
}

static void wc_lookup_exec_erx_fast_recheck(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !erx_marker_host_local || !auth || !header_non_authoritative ||
        !need_redir_eval || !ref) {
        return;
    }

    struct wc_lookup_opts recheck_opts;
    struct wc_query recheck_q;
    wc_lookup_exec_erx_fast_recheck_begin(
        ctx,
        erx_marker_host_local,
        &recheck_opts,
        &recheck_q);
    wc_lookup_exec_erx_fast_recheck_finish(
        ctx,
        erx_marker_host_local,
        &recheck_opts,
        &recheck_q,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_erx_apply_batch_delay(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->cfg || ctx->cfg->batch_interval_ms <= 0) return;

    int delay_ms = ctx->cfg->batch_interval_ms;
    struct timespec ts;
    ts.tv_sec = (time_t)(delay_ms / 1000);
    ts.tv_nsec = (long)((delay_ms % 1000) * 1000000L);
    nanosleep(&ts, NULL);
}

static void wc_lookup_exec_erx_prepare_recheck(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    struct wc_lookup_opts* recheck_opts,
    struct wc_query* recheck_q) {
    if (!ctx || !erx_marker_host_local || !recheck_opts || !recheck_q) return;

    *recheck_q = (struct wc_query){
        .raw = ctx->cidr_base_query,
        .start_server = erx_marker_host_local,
        .port = ctx->current_port
    };
    recheck_opts->no_redirect = 1;
    recheck_opts->max_hops = 1;
    recheck_opts->net_ctx = ctx->net_ctx;
    recheck_opts->config = ctx->cfg;
}

static void wc_lookup_exec_erx_recheck_skip_log(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    if (!ctx || !erx_marker_host_local || !ctx->cfg || !ctx->cfg->debug) return;

    fprintf(stderr,
        "[ERX-RECHECK] action=skip reason=disabled query=%s host=%s\n",
        ctx->cidr_base_query,
        erx_marker_host_local);
}

static int wc_lookup_exec_should_erx_fast_recheck(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int erx_marker_this_hop) {
    if (!ctx || !erx_marker_this_hop) return 0;

    return ctx->query_is_cidr && ctx->cidr_base_query &&
        ctx->erx_fast_recheck_done && !*ctx->erx_fast_recheck_done &&
        !wc_lookup_erx_baseline_recheck_guard_get() &&
        (!ctx->cfg || ctx->cfg->cidr_erx_recheck);
}

static int wc_lookup_exec_should_erx_recheck_skip_log(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int erx_marker_this_hop) {
    if (!ctx || !erx_marker_this_hop) return 0;

    return ctx->query_is_cidr && ctx->cidr_base_query &&
        ctx->erx_fast_recheck_done && !*ctx->erx_fast_recheck_done && ctx->cfg &&
        !ctx->cfg->cidr_erx_recheck && ctx->cfg->debug;
}

static void wc_lookup_exec_erx_prepare_marker_host_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    const char* header_hint_host,
    const char** erx_marker_host_local);
static void wc_lookup_exec_erx_mark_this_hop_step(
    const char* body,
    int* erx_marker_this_hop);

static void wc_lookup_exec_prepare_erx_marker_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* erx_marker_this_hop,
    const char** erx_marker_host_local) {
    if (!erx_marker_this_hop || !erx_marker_host_local) return;

    wc_lookup_exec_erx_prepare_marker_host_step(
        ctx,
        header_host,
        header_hint_host,
        erx_marker_host_local);
    wc_lookup_exec_erx_mark_this_hop_step(
        body,
        erx_marker_this_hop);
}

static void wc_lookup_exec_erx_prepare_marker_host_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    const char* header_hint_host,
    const char** erx_marker_host_local) {
    if (!erx_marker_host_local) return;

    *erx_marker_host_local = wc_lookup_exec_erx_marker_host(
        ctx,
        header_host,
        header_hint_host);
}

static void wc_lookup_exec_erx_mark_this_hop_step(
    const char* body,
    int* erx_marker_this_hop) {
    wc_lookup_exec_erx_mark_this_hop(
        body,
        erx_marker_this_hop);
}

static void wc_lookup_exec_run_erx_marker_recheck_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* erx_marker_this_hop) {
    if (!ctx || !body || !auth || !header_non_authoritative || !need_redir_eval ||
        !ref || !erx_marker_this_hop) {
        return;
    }

    const char* erx_marker_host_local = NULL;
    wc_lookup_exec_prepare_erx_marker_state(
        ctx,
        body,
        header_host,
        header_hint_host,
        erx_marker_this_hop,
        &erx_marker_host_local);

    wc_lookup_exec_erx_handle_marker_flags(
        ctx,
        *erx_marker_this_hop,
        erx_marker_host_local,
        header_non_authoritative,
        need_redir_eval);

    wc_lookup_exec_erx_run_fast_recheck_if_needed(
        ctx,
        *erx_marker_this_hop,
        erx_marker_host_local,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_handle_erx_marker_recheck(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* erx_marker_this_hop) {
    if (!ctx || !body || !auth || !header_non_authoritative || !need_redir_eval || !ref || !erx_marker_this_hop) {
        return;
    }

    wc_lookup_exec_run_erx_marker_recheck_steps(
        ctx,
        body,
        header_host,
        header_hint_host,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref,
        erx_marker_this_hop);
}

static void wc_lookup_exec_erx_fast_recheck_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref);
static void wc_lookup_exec_erx_recheck_skip_log_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local);

static void wc_lookup_exec_erx_run_fast_recheck_if_needed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int erx_marker_this_hop,
    const char* erx_marker_host_local,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !auth || !header_non_authoritative || !need_redir_eval || !ref) return;

    if (wc_lookup_exec_should_erx_fast_recheck(ctx, erx_marker_this_hop)) {
        wc_lookup_exec_erx_fast_recheck_step(
            ctx,
            erx_marker_host_local,
            auth,
            header_non_authoritative,
            need_redir_eval,
            ref);
    } else if (wc_lookup_exec_should_erx_recheck_skip_log(ctx, erx_marker_this_hop)) {
        wc_lookup_exec_erx_recheck_skip_log_step(ctx, erx_marker_host_local);
    }
}

static void wc_lookup_exec_erx_fast_recheck_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    wc_lookup_exec_erx_fast_recheck(
        ctx,
        erx_marker_host_local,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_erx_recheck_skip_log_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* erx_marker_host_local) {
    wc_lookup_exec_erx_recheck_skip_log(ctx, erx_marker_host_local);
}

static void wc_lookup_exec_erx_mark_this_hop(
    const char* body,
    int* erx_marker_this_hop) {
    if (!erx_marker_this_hop) return;

    *erx_marker_this_hop = wc_lookup_body_contains_erx_iana_marker(body);
}

static void wc_lookup_exec_erx_handle_marker_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int erx_marker_this_hop,
    const char* erx_marker_host_local,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    if (erx_marker_this_hop) {
        wc_lookup_exec_erx_marker_set_flags(
            ctx,
            erx_marker_host_local,
            header_non_authoritative,
            need_redir_eval);
    }
}

static int wc_lookup_exec_apnic_should_update_last_ip(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host);
static void wc_lookup_exec_apnic_update_last_ip_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_write_apnic_last_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

static void wc_lookup_exec_apnic_update_last_ip(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host) {
    if (!ctx || !header_host) return;

    if (!wc_lookup_exec_apnic_should_update_last_ip(ctx, header_host)) return;

    wc_lookup_exec_apnic_update_last_ip_writeback_step(ctx);
}

static int wc_lookup_exec_apnic_should_update_last_ip(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host) {
    if (!ctx || !header_host) return 0;
    if (strcasecmp(header_host, "whois.apnic.net") != 0) return 0;
    if (!ctx->ni || !ctx->ni->ip[0]) return 0;
    if (!ctx->apnic_last_ip || ctx->apnic_last_ip_len == 0) return 0;

    return 1;
}

static void wc_lookup_exec_apnic_update_last_ip_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->ni) return;

    wc_lookup_exec_write_apnic_last_ip_output_step(ctx, ctx->ni->ip);
}

static void wc_lookup_exec_write_apnic_last_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip) {
    if (!ctx || !ip) return;

    snprintf(ctx->apnic_last_ip, ctx->apnic_last_ip_len, "%s", ip);
}

static int wc_lookup_exec_apnic_should_clear_ref_on_header_match(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    const char* ref,
    int ref_explicit);
static void wc_lookup_exec_apnic_clear_ref_on_header_match_writeback_step(
    int* need_redir_eval,
    char** ref);

static void wc_lookup_exec_apnic_clear_ref_if_matches_header(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return;

    if (!wc_lookup_exec_apnic_should_clear_ref_on_header_match(
            ctx,
            header_host,
            header_is_iana,
            *ref,
            *ref_explicit)) {
        return;
    }

    wc_lookup_exec_apnic_clear_ref_on_header_match_writeback_step(
        need_redir_eval,
        ref);
}

static int wc_lookup_exec_apnic_should_clear_ref_on_header_match(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    const char* ref,
    int ref_explicit) {
    if (!ctx || !header_host || !ref) return 0;

    if (header_is_iana) return 0;
    if (ref_explicit) return 0;

    return wc_lookup_exec_apnic_refs_match_header(ctx, header_host);
}

static void wc_lookup_exec_apnic_clear_ref_on_header_match_writeback_step(
    int* need_redir_eval,
    char** ref) {
    if (!need_redir_eval || !ref || !*ref) return;

    wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
}

static const char* wc_lookup_exec_apnic_header_norm_ptr_step(
    const char* header_host) {
    const char* header_norm = wc_dns_canonical_alias(header_host);
    return header_norm ? header_norm : header_host;
}

static void wc_lookup_exec_apnic_normalize_ref_host_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    char* ref_norm,
    size_t ref_norm_len) {
    if (!ctx || !ref_norm || ref_norm_len == 0) return;

    if (wc_normalize_whois_host(ctx->ref_host, ref_norm, ref_norm_len) != 0) {
        snprintf(ref_norm, ref_norm_len, "%s", ctx->ref_host);
    }
}

static int wc_lookup_exec_apnic_ref_matches_header_norm_step(
    const char* ref_norm,
    const char* header_norm) {
    if (!ref_norm || !header_norm) return 0;

    return (strcasecmp(ref_norm, header_norm) == 0) ? 1 : 0;
}

static void wc_lookup_exec_apnic_prepare_ref_header_norm_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    char* ref_norm,
    size_t ref_norm_len,
    const char** header_norm) {
    if (!ctx || !header_host || !ref_norm || ref_norm_len == 0 || !header_norm) return;

    *header_norm = wc_lookup_exec_apnic_header_norm_ptr_step(header_host);
    wc_lookup_exec_apnic_normalize_ref_host_step(ctx, ref_norm, ref_norm_len);
}

static int wc_lookup_exec_apnic_refs_match_header(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host) {
    if (!ctx || !header_host) return 0;

    char ref_norm2[128];
    const char* header_norm = NULL;
    wc_lookup_exec_apnic_prepare_ref_header_norm_step(
        ctx,
        header_host,
        ref_norm2,
        sizeof(ref_norm2),
        &header_norm);
    return wc_lookup_exec_apnic_ref_matches_header_norm_step(ref_norm2, header_norm);
}

static int wc_lookup_exec_apnic_should_apply_header_auth_stop_ref_policy(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int header_authoritative_stop,
    const char* ref,
    int ref_explicit) {
    if (!ctx || !ref) return 0;

    return (header_authoritative_stop && ref && !ref_explicit &&
            (!ctx->apnic_erx_keep_ref || !*ctx->apnic_erx_keep_ref)) ? 1 : 0;
}

static void wc_lookup_exec_apnic_apply_header_auth_stop_ref_policy_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !ref || !ref_explicit) return;

    if (wc_lookup_exec_apnic_refs_should_cross_rir(ctx)) {
        *ref_explicit = 1;
        return;
    }

    free(*ref);
    *ref = NULL;
}

static int wc_lookup_exec_apnic_should_apply_authoritative_stop_cleanup(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int header_authoritative_stop) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
            ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1 &&
            header_authoritative_stop) ? 1 : 0;
}

static void wc_lookup_exec_mark_apnic_erx_authoritative_stop_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_apnic_mark_authoritative_stop_flag_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    wc_lookup_exec_mark_apnic_erx_authoritative_stop_output_step(ctx);
}

static void wc_lookup_exec_mark_apnic_erx_authoritative_stop_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_authoritative_stop) {
        *ctx->apnic_erx_authoritative_stop = 1;
    }
}

static void wc_lookup_exec_apnic_run_header_auth_stop_ref_policy_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_authoritative_stop,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !ref || !ref_explicit) return;

    if (wc_lookup_exec_apnic_should_apply_header_auth_stop_ref_policy(
            ctx,
            header_authoritative_stop,
            *ref,
            *ref_explicit)) {
        wc_lookup_exec_apnic_apply_header_auth_stop_ref_policy_step(
            ctx,
            ref,
            ref_explicit);
    }
}

static void wc_lookup_exec_apnic_run_authoritative_stop_cleanup_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !need_redir_eval || !ref || !ref_explicit) return;

    if (wc_lookup_exec_apnic_should_apply_authoritative_stop_cleanup(ctx, header_authoritative_stop)) {
        wc_lookup_exec_apnic_mark_authoritative_stop_flag_step(ctx);
        wc_lookup_exec_apnic_handle_ref_cleanup_on_auth_stop(
            ctx,
            need_redir_eval,
            ref,
            ref_explicit);
    }
}

static void wc_lookup_exec_apnic_handle_authoritative_stop(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_run_header_auth_stop_ref_policy_step(
        ctx,
        header_authoritative_stop,
        ref,
        ref_explicit);

    wc_lookup_exec_apnic_run_authoritative_stop_cleanup_step(
        ctx,
        header_authoritative_stop,
        need_redir_eval,
        ref,
        ref_explicit);
}

static int wc_lookup_exec_apnic_refs_should_cross_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    const char* ref_rir = wc_guess_rir(ctx->ref_host);
    return (ref_rir && ctx->current_rir_guess &&
        strcasecmp(ref_rir, ctx->current_rir_guess) != 0) ? 1 : 0;
}

static void wc_lookup_exec_apnic_set_need_redir_zero_step(
    int* need_redir_eval);
static int wc_lookup_exec_apnic_should_clear_ref_on_auth_stop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ref,
    int ref_explicit);
static void wc_lookup_exec_apnic_apply_auth_stop_ref_clear_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    char** ref,
    int ref_explicit);

static void wc_lookup_exec_apnic_handle_ref_cleanup_on_auth_stop(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_set_need_redir_zero_step(need_redir_eval);
    wc_lookup_exec_apnic_apply_auth_stop_ref_clear_step(
        ctx,
        ref,
        *ref_explicit);
}

static void wc_lookup_exec_apnic_set_need_redir_zero_step(
    int* need_redir_eval) {
    if (!need_redir_eval) return;

    *need_redir_eval = 0;
}

static int wc_lookup_exec_apnic_should_clear_ref_on_auth_stop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ref,
    int ref_explicit) {
    if (!ctx || !ref) return 0;
    if (ref_explicit) return 0;

    return (!ctx->apnic_erx_keep_ref || !*ctx->apnic_erx_keep_ref) ? 1 : 0;
}

static void wc_lookup_exec_apnic_apply_auth_stop_ref_clear_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    char** ref,
    int ref_explicit) {
    if (!ctx || !ref || !*ref) return;
    if (!wc_lookup_exec_apnic_should_clear_ref_on_auth_stop(ctx, *ref, ref_explicit)) return;

    free(*ref);
    *ref = NULL;
}

static int wc_lookup_exec_apnic_should_clear_ref_on_transfer(
    int apnic_transfer_to_apnic);
static void wc_lookup_exec_apnic_apply_transfer_ref_clear_step(
    int apnic_transfer_to_apnic,
    int* need_redir_eval,
    char** ref);

static int wc_lookup_exec_apnic_handle_transfer(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !body || !need_redir_eval || !ref) return 0;

    int apnic_transfer_to_apnic = wc_lookup_exec_apnic_transfer_to_apnic(ctx, body);
    wc_lookup_exec_apnic_apply_transfer_ref_clear_step(
        apnic_transfer_to_apnic,
        need_redir_eval,
        ref);
    return apnic_transfer_to_apnic;
}

static int wc_lookup_exec_apnic_should_clear_ref_on_transfer(
    int apnic_transfer_to_apnic) {
    return apnic_transfer_to_apnic ? 1 : 0;
}

static void wc_lookup_exec_apnic_apply_transfer_ref_clear_step(
    int apnic_transfer_to_apnic,
    int* need_redir_eval,
    char** ref) {
    if (!need_redir_eval || !ref) return;
    if (!wc_lookup_exec_apnic_should_clear_ref_on_transfer(apnic_transfer_to_apnic)) return;

    wc_lookup_exec_apnic_clear_ref_on_transfer(
        need_redir_eval,
        ref);
}

static int wc_lookup_exec_apnic_is_current_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_body_has_transfer_marker(
    const char* body);

static int wc_lookup_exec_apnic_transfer_to_apnic(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return 0;

    return (wc_lookup_exec_apnic_is_current_rir(ctx) &&
            wc_lookup_exec_apnic_body_has_transfer_marker(body)) ? 1 : 0;
}

static int wc_lookup_exec_apnic_is_current_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->current_rir_guess) return 0;

    return (strcasecmp(ctx->current_rir_guess, "apnic") == 0) ? 1 : 0;
}

static int wc_lookup_exec_apnic_body_has_transfer_marker(
    const char* body) {
    return (body && wc_lookup_body_contains_apnic_transfer_to_apnic(body)) ? 1 : 0;
}

static void wc_lookup_exec_apnic_clear_ref_on_transfer(
    int* need_redir_eval,
    char** ref) {
    if (!need_redir_eval || !ref) return;

    wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
}

static int wc_lookup_exec_apnic_should_handle_erx_netname(
    int auth,
    int header_is_iana,
    const char* header_host,
    int erx_netname);
static void wc_lookup_exec_apnic_cancel_need_redir_and_clear_ref_step(
    int* need_redir_eval,
    char** ref);

static void wc_lookup_exec_apnic_handle_erx_netname(
    int auth,
    int header_is_iana,
    const char* header_host,
    int erx_netname,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!need_redir_eval || !ref || !ref_explicit) return;

    if (!wc_lookup_exec_apnic_should_handle_erx_netname(
            auth,
            header_is_iana,
            header_host,
            erx_netname)) {
        return;
    }
    if (*ref && *ref_explicit) return;

    wc_lookup_exec_apnic_cancel_need_redir_and_clear_ref_step(
        need_redir_eval,
        ref);
}

static int wc_lookup_exec_apnic_should_handle_erx_netname(
    int auth,
    int header_is_iana,
    const char* header_host,
    int erx_netname) {
    return (auth && erx_netname && header_host && !header_is_iana) ? 1 : 0;
}

static void wc_lookup_exec_apnic_cancel_need_redir_and_clear_ref_step(
    int* need_redir_eval,
    char** ref) {
    if (!need_redir_eval || !ref) return;

    wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
}

static int wc_lookup_exec_apnic_header_match_base_guard(
    int auth,
    int header_is_iana,
    const char* header_host,
    const char* ref) {
    return (auth && header_host && !header_is_iana && !ref) ? 1 : 0;
}

static int wc_lookup_exec_apnic_header_match_should_noop_cancel(
    int auth,
    int header_is_iana,
    const char* header_host,
    const char* ref,
    int need_redir_eval) {
    return (wc_lookup_exec_apnic_header_match_base_guard(
                auth,
                header_is_iana,
                header_host,
                ref) &&
            !need_redir_eval) ? 1 : 0;
}

static int wc_lookup_exec_apnic_header_match_current_rir_allows_cancel(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (!ctx->current_rir_guess ||
            strcasecmp(ctx->current_rir_guess, "apnic") != 0) ? 1 : 0;
}

static int wc_lookup_exec_apnic_header_match_should_consider_cancel(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_is_iana,
    const char* header_host,
    const char* ref,
    int need_redir_eval) {
    return (wc_lookup_exec_apnic_header_match_base_guard(
                auth,
                header_is_iana,
                header_host,
                ref) &&
            need_redir_eval &&
            wc_lookup_exec_apnic_header_match_current_rir_allows_cancel(ctx)) ? 1 : 0;
}

static int wc_lookup_exec_apnic_header_match_allows_cancel_by_body(
    const char* body,
    int header_non_authoritative) {
    if (!body) return 0;
    if (header_non_authoritative) return 0;

    return wc_lookup_body_has_strong_redirect_hint(body) ? 0 : 1;
}

static void wc_lookup_exec_apnic_cancel_need_redir_eval_step(int* need_redir_eval) {
    if (!need_redir_eval) return;

    *need_redir_eval = 0;
}

static const char* wc_lookup_exec_apnic_host_or_canonical_step(
    const char* host) {
    const char* canon = wc_dns_canonical_alias(host);
    return canon ? canon : host;
}

static void wc_lookup_exec_apnic_normalize_host_step(
    const char* host,
    char* out,
    size_t out_len) {
    if (!host || !out || out_len == 0) return;

    if (wc_normalize_whois_host(host, out, out_len) != 0) {
        snprintf(out, out_len, "%s", host);
    }
}

static int wc_lookup_exec_apnic_hosts_equal_step(
    const char* lhs,
    const char* rhs) {
    if (!lhs || !rhs) return 0;

    return (strcasecmp(lhs, rhs) == 0) ? 1 : 0;
}

static void wc_lookup_exec_apnic_handle_header_match(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !body || !need_redir_eval || !ref) return;

    if (wc_lookup_exec_apnic_header_match_should_noop_cancel(
            auth,
            header_is_iana,
            header_host,
            *ref,
            *need_redir_eval)) {
        wc_lookup_exec_apnic_cancel_need_redir_eval_step(need_redir_eval);
    }

    if (!wc_lookup_exec_apnic_header_match_should_consider_cancel(
            ctx,
            auth,
            header_is_iana,
            header_host,
            *ref,
            *need_redir_eval)) {
        return;
    }

    if (!wc_lookup_exec_apnic_header_matches_current_host(ctx, header_host)) return;
    if (!wc_lookup_exec_apnic_header_match_allows_cancel_by_body(body, header_non_authoritative)) return;

    wc_lookup_exec_apnic_cancel_need_redir_eval_step(need_redir_eval);
}

static int wc_lookup_exec_apnic_header_matches_current_host(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host) {
    if (!ctx || !header_host) return 0;

    char header_norm3[128];
    char current_norm3[128];
    wc_lookup_exec_apnic_prepare_header_current_norm_step(
        ctx,
        header_host,
        header_norm3,
        sizeof(header_norm3),
        current_norm3,
        sizeof(current_norm3));

    return wc_lookup_exec_apnic_hosts_equal_step(header_norm3, current_norm3);
}

static void wc_lookup_exec_apnic_prepare_header_current_norm_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    char* header_norm,
    size_t header_norm_len,
    char* current_norm,
    size_t current_norm_len) {
    if (!ctx || !header_host || !header_norm || header_norm_len == 0 ||
        !current_norm || current_norm_len == 0) {
        return;
    }

    const char* header_normp = wc_lookup_exec_apnic_host_or_canonical_step(header_host);
    const char* current_normp = wc_lookup_exec_apnic_host_or_canonical_step(ctx->current_host);

    wc_lookup_exec_apnic_normalize_host_step(
        header_normp,
        header_norm,
        header_norm_len);
    wc_lookup_exec_apnic_normalize_host_step(
        current_normp,
        current_norm,
        current_norm_len);
}

static void wc_lookup_exec_apnic_update_legacy_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* need_redir_eval,
    int apnic_transfer_to_apnic) {
    if (!ctx || !body || !need_redir_eval) return;

    if (!wc_lookup_exec_apnic_should_update_legacy_flags(ctx, apnic_transfer_to_apnic)) return;

    wc_lookup_exec_apnic_update_legacy_marker(ctx, body);
    if (wc_lookup_exec_apnic_should_force_iana_netblock(ctx)) {
        *need_redir_eval = 1;
    }
}

static int wc_lookup_exec_apnic_should_update_legacy_flags(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int apnic_transfer_to_apnic) {
    if (!ctx) return 0;

    return ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "apnic") == 0 &&
        !apnic_transfer_to_apnic;
}

static void wc_lookup_exec_apnic_update_legacy_marker(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return;

    if (ctx->apnic_erx_legacy) {
        *ctx->apnic_erx_legacy = wc_lookup_body_contains_erx_legacy(body);
    }
}

static int wc_lookup_exec_apnic_should_force_iana_netblock(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy &&
        ctx->apnic_iana_netblock_cidr && !*ctx->apnic_iana_netblock_cidr;
}

static void wc_lookup_exec_apnic_update_legacy_root_hosts(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (!wc_lookup_exec_apnic_should_update_legacy_root(ctx)) return;

    wc_lookup_exec_apnic_set_legacy_root_flag(ctx);
    wc_lookup_exec_apnic_update_legacy_root_host(ctx);
    wc_lookup_exec_apnic_update_legacy_root_ip(ctx);
}

static int wc_lookup_exec_apnic_should_update_legacy_root(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "apnic") == 0 &&
        ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy;
}

static void wc_lookup_exec_apnic_set_legacy_root_flag(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
        wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
        wc_lookup_exec_set_apnic_redirect_reason(ctx, 1);
    }
}

static void wc_lookup_exec_apnic_update_legacy_root_host(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (wc_lookup_exec_should_write_apnic_erx_root_host_output_step(ctx)) {
        const char* apnic_root = wc_lookup_exec_select_apnic_erx_root_host_value_step(ctx);
        wc_lookup_exec_write_apnic_erx_root_host_output_step(ctx, apnic_root);
    }
}

static void wc_lookup_exec_apnic_update_legacy_root_ip(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (wc_lookup_exec_should_write_apnic_erx_root_ip_output_step(ctx)) {
        const char* ip = wc_lookup_exec_select_apnic_erx_root_ip_value_step(ctx);
        wc_lookup_exec_write_apnic_erx_root_ip_output_step(ctx, ip);
    }
}

static void wc_lookup_exec_apnic_update_last_ip_current(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (wc_lookup_exec_apnic_should_update_last_ip_current(ctx)) {
        wc_lookup_exec_apnic_update_last_ip_value(ctx);
    }
}

static int wc_lookup_exec_apnic_should_update_last_ip_current(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "apnic") == 0 &&
        ctx->ni && ctx->ni->ip[0] && ctx->apnic_last_ip && ctx->apnic_last_ip_len > 0;
}

static void wc_lookup_exec_apnic_update_last_ip_value(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    wc_lookup_exec_write_apnic_last_ip_output_step(ctx, ctx->ni->ip);
}

static void wc_lookup_exec_apnic_ensure_root_on_need_redir(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx || !need_redir_eval) return;

    if (wc_lookup_exec_apnic_should_ensure_root_on_need_redir(ctx, need_redir_eval)) {
        wc_lookup_exec_apnic_mark_root_on_need_redir(ctx);
    }
}

static int wc_lookup_exec_apnic_should_ensure_root_on_need_redir(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx || !need_redir_eval) return 0;

    if (ctx->current_rir_guess &&
        ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy) {
        return 1;
    }
    return 0;
}

static void wc_lookup_exec_apnic_mark_root_on_need_redir(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
        wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
    }
}

static void wc_lookup_exec_apnic_handle_legacy_root(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* need_redir_eval,
    int apnic_transfer_to_apnic) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_update_legacy_flags(
        ctx,
        body,
        need_redir_eval,
        apnic_transfer_to_apnic);
    wc_lookup_exec_apnic_update_legacy_root_hosts(ctx);
    wc_lookup_exec_apnic_update_last_ip_current(ctx);
    wc_lookup_exec_apnic_ensure_root_on_need_redir(
        ctx,
        *need_redir_eval);
}

static void wc_lookup_exec_apnic_handle_stop_target(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed) {
    if (!ctx) return;

    if (!wc_lookup_exec_apnic_should_stop_target(ctx, ripe_non_managed)) return;

    wc_lookup_exec_apnic_mark_stop_target(ctx);
}

static int wc_lookup_exec_apnic_stop_target_has_required_state(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
            ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1 &&
            ctx->apnic_erx_target_rir && ctx->apnic_erx_target_rir[0] &&
            ctx->current_rir_guess) ? 1 : 0;
}

static int wc_lookup_exec_apnic_stop_target_matches_current_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->apnic_erx_target_rir || !ctx->current_rir_guess) return 0;

    return (strcasecmp(ctx->apnic_erx_target_rir, ctx->current_rir_guess) == 0) ? 1 : 0;
}

static int wc_lookup_exec_apnic_stop_target_is_disallowed(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed) {
    if (!ctx || !ctx->apnic_erx_target_rir) return 0;

    if (strcasecmp(ctx->apnic_erx_target_rir, "apnic") == 0) {
        return 1;
    }
    if (strcasecmp(ctx->apnic_erx_target_rir, "ripe") == 0 && ripe_non_managed) {
        return 1;
    }
    return 0;
}

static int wc_lookup_exec_apnic_should_stop_target(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed) {
    if (!ctx) return 0;

    if (!wc_lookup_exec_apnic_stop_target_has_required_state(ctx)) {
        return 0;
    }

    if (!wc_lookup_exec_apnic_stop_target_matches_current_rir(ctx)) {
        return 0;
    }

    if (wc_lookup_exec_apnic_stop_target_is_disallowed(ctx, ripe_non_managed)) {
        return 0;
    }

    return 1;
}

static void wc_lookup_exec_mark_apnic_erx_stop_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_clear_apnic_erx_stop_unknown_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_apnic_erx_stop_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_apnic_erx_stop_host_value_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* host_value);

static void wc_lookup_exec_apnic_mark_stop_target(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    wc_lookup_exec_mark_apnic_erx_stop_output_step(ctx);
    wc_lookup_exec_clear_apnic_erx_stop_unknown_output_step(ctx);
    wc_lookup_exec_write_apnic_erx_stop_host_output_step(ctx);
}

static void wc_lookup_exec_mark_apnic_erx_stop_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_stop) {
        *ctx->apnic_erx_stop = 1;
    }
}

static void wc_lookup_exec_clear_apnic_erx_stop_unknown_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_stop_unknown) {
        *ctx->apnic_erx_stop_unknown = 0;
    }
}

static void wc_lookup_exec_write_apnic_erx_stop_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    wc_lookup_exec_write_apnic_erx_stop_host_value_output_step(ctx, ctx->current_host);
}

static void wc_lookup_exec_write_apnic_erx_stop_host_value_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* host_value) {
    if (!ctx) return;

    if (ctx->apnic_erx_stop_host && ctx->apnic_erx_stop_host_len > 0) {
        snprintf(ctx->apnic_erx_stop_host,
            ctx->apnic_erx_stop_host_len,
            "%s",
            host_value ? host_value : "");
    }
}

static void wc_lookup_exec_apnic_apply_full_ipv4_redirect_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int* need_redir_eval) {
    if (!ctx || !need_redir_eval) return;

    *need_redir_eval = 1;
    wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
}

static void wc_lookup_exec_apnic_apply_transfer_cancel_step(int* need_redir_eval) {
    wc_lookup_exec_apnic_cancel_need_redir_eval_step(need_redir_eval);
}

static void wc_lookup_exec_apnic_handle_full_ipv4_space(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    if (wc_lookup_exec_apnic_should_handle_full_ipv4_space(body, apnic_transfer_to_apnic)) {
        wc_lookup_exec_apnic_apply_full_ipv4_redirect_step(ctx, need_redir_eval);
    }
    if (wc_lookup_exec_apnic_should_cancel_need_redir_on_transfer(apnic_transfer_to_apnic)) {
        wc_lookup_exec_apnic_apply_transfer_cancel_step(need_redir_eval);
    }
}

static int wc_lookup_exec_apnic_should_skip_full_ipv4_space_step(
    int apnic_transfer_to_apnic);

static int wc_lookup_exec_apnic_should_handle_full_ipv4_space(
    const char* body,
    int apnic_transfer_to_apnic) {
    if (wc_lookup_exec_apnic_should_skip_full_ipv4_space_step(apnic_transfer_to_apnic)) {
        return 0;
    }

    return wc_lookup_body_contains_full_ipv4_space(body);
}

static int wc_lookup_exec_apnic_should_skip_full_ipv4_space_step(
    int apnic_transfer_to_apnic) {
    return apnic_transfer_to_apnic ? 1 : 0;
}

static int wc_lookup_exec_apnic_should_cancel_need_redir_on_transfer(
    int apnic_transfer_to_apnic) {
    return apnic_transfer_to_apnic ? 1 : 0;
}

static int wc_lookup_exec_apnic_cancel_need_redir_base_condition(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval,
    int auth,
    const char* ref) {
    if (!ctx) return 0;

    return (need_redir_eval && auth && !ref && ctx->current_rir_guess &&
            strcasecmp(ctx->current_rir_guess, "apnic") == 0) ? 1 : 0;
}

static int wc_lookup_exec_apnic_body_has_hint_strict(
    const char* body) {
    return (body && wc_lookup_body_contains_apnic_erx_hint(body) &&
            wc_lookup_body_contains_apnic_erx_hint_strict(body)) ? 1 : 0;
}

static void wc_lookup_exec_apnic_cancel_need_redir_step(int* need_redir_eval) {
    if (!need_redir_eval) return;

    *need_redir_eval = 0;
}

static void wc_lookup_exec_apnic_handle_hint_strict(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !body || !need_redir_eval) return;

    if (!wc_lookup_exec_apnic_cancel_need_redir_base_condition(
            ctx,
            *need_redir_eval,
            auth,
            ref)) {
        return;
    }
    if (!wc_lookup_exec_apnic_body_has_hint_strict(body)) return;

    wc_lookup_exec_apnic_cancel_need_redir_step(need_redir_eval);
}

static int wc_lookup_exec_apnic_fast_authoritative_flag(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->erx_fast_authoritative) return 0;

    return *ctx->erx_fast_authoritative ? 1 : 0;
}

static int wc_lookup_exec_apnic_should_cancel_need_redir_on_fast_authoritative(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval,
    int auth,
    const char* ref,
    int erx_marker_this_hop) {
    if (!wc_lookup_exec_apnic_cancel_need_redir_base_condition(ctx, need_redir_eval, auth, ref)) {
        return 0;
    }
    if (erx_marker_this_hop) return 0;

    return wc_lookup_exec_apnic_fast_authoritative_flag(ctx);
}

static int wc_lookup_exec_apnic_run_fast_authoritative_should_cancel_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval,
    int auth,
    const char* ref,
    int erx_marker_this_hop) {
    if (!ctx) return 0;

    return wc_lookup_exec_apnic_should_cancel_need_redir_on_fast_authoritative(
        ctx,
        need_redir_eval,
        auth,
        ref,
        erx_marker_this_hop);
}

static void wc_lookup_exec_apnic_run_fast_authoritative_cancel_step(int* need_redir_eval) {
    wc_lookup_exec_apnic_cancel_need_redir_step(need_redir_eval);
}

static void wc_lookup_exec_apnic_handle_fast_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !need_redir_eval) return;

    if (!wc_lookup_exec_apnic_run_fast_authoritative_should_cancel_step(
            ctx,
            *need_redir_eval,
            auth,
            ref,
            erx_marker_this_hop)) {
        return;
    }

    wc_lookup_exec_apnic_run_fast_authoritative_cancel_step(need_redir_eval);
}

static int wc_lookup_exec_apnic_header_authoritative_stop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int auth,
    int header_non_authoritative) {
    if (!ctx || !header_host) return 0;

    return (header_host && ctx->current_host && header_host[0] && ctx->current_host[0] &&
            auth && !header_non_authoritative &&
            strcasecmp(header_host, ctx->current_host) == 0) ? 1 : 0;
}

static void wc_lookup_exec_apnic_handle_header_ref_flow(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_run_header_last_ip_step(ctx, header_host);
    wc_lookup_exec_apnic_run_header_refs_step(
        ctx,
        header_host,
        header_is_iana,
        header_authoritative_stop,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_apnic_run_header_last_ip_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host) {
    if (!ctx || !header_host) return;

    wc_lookup_exec_apnic_update_last_ip(ctx, header_host);
}

static void wc_lookup_exec_apnic_run_header_refs_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_update_header_refs(
        ctx,
        header_host,
        header_is_iana,
        header_authoritative_stop,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_apnic_update_header_refs(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_clear_ref_if_matches_header(
        ctx,
        header_host,
        header_is_iana,
        need_redir_eval,
        ref,
        ref_explicit);
    wc_lookup_exec_apnic_handle_authoritative_stop(
        ctx,
        header_authoritative_stop,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_apnic_handle_erx_netname_flow(
    int auth,
    int header_is_iana,
    const char* header_host,
    const char* body,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!body || !need_redir_eval || !ref || !ref_explicit) return;

    int erx_netname = wc_lookup_exec_apnic_detect_erx_netname_step(body);
    wc_lookup_exec_apnic_apply_erx_netname_step(
        auth,
        header_is_iana,
        header_host,
        erx_netname,
        need_redir_eval,
        ref,
        ref_explicit);
}

static int wc_lookup_exec_apnic_detect_erx_netname_step(const char* body) {
    if (!body) return 0;

    return wc_lookup_body_contains_erx_netname(body);
}

static void wc_lookup_exec_apnic_apply_erx_netname_step(
    int auth,
    int header_is_iana,
    const char* header_host,
    int erx_netname,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_handle_erx_netname(
        auth,
        header_is_iana,
        header_host,
        erx_netname,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_apnic_handle_erx_hint_and_match(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !body || !need_redir_eval || !ref) return;

    wc_lookup_exec_apnic_run_erx_hint_strict_step(
        ctx,
        body,
        auth,
        need_redir_eval,
        *ref);
    wc_lookup_exec_apnic_run_erx_header_match_step(
        ctx,
        body,
        auth,
        header_is_iana,
        header_host,
        header_non_authoritative,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_run_erx_hint_strict_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_hint_strict(
        ctx,
        body,
        auth,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_run_erx_header_match_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !body || !need_redir_eval || !ref) return;

    wc_lookup_exec_apnic_handle_header_match(
        ctx,
        body,
        auth,
        header_is_iana,
        header_host,
        header_non_authoritative,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_run_erx_netname_flow_step(
    int auth,
    int header_is_iana,
    const char* header_host,
    const char* body,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!body || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_handle_erx_netname_flow(
        auth,
        header_is_iana,
        header_host,
        body,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_apnic_run_erx_hint_match_flow_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !body || !need_redir_eval || !ref) return;

    wc_lookup_exec_apnic_handle_erx_hint_and_match(
        ctx,
        body,
        auth,
        header_is_iana,
        header_host,
        header_non_authoritative,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_handle_erx_hints(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !body || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_run_erx_netname_flow_step(
        auth,
        header_is_iana,
        header_host,
        body,
        need_redir_eval,
        ref,
        ref_explicit);
    wc_lookup_exec_apnic_run_erx_hint_match_flow_step(
        ctx,
        body,
        auth,
        header_is_iana,
        header_host,
        header_non_authoritative,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_handle_post_transfer(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_run_post_transfer_flags_step(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        need_redir_eval);
    wc_lookup_exec_apnic_run_post_transfer_fast_auth_step(
        ctx,
        auth,
        erx_marker_this_hop,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_run_post_transfer_flags_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_run_post_flags_step(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        need_redir_eval);
}

static void wc_lookup_exec_apnic_run_post_transfer_fast_auth_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !need_redir_eval) return;

    wc_lookup_exec_apnic_run_post_fast_authoritative_step(
        ctx,
        auth,
        erx_marker_this_hop,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_run_post_legacy_root_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_legacy_root(
        ctx,
        body,
        need_redir_eval,
        apnic_transfer_to_apnic);
}

static void wc_lookup_exec_apnic_run_post_stop_target_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ripe_non_managed) {
    if (!ctx) return;

    wc_lookup_exec_apnic_handle_stop_target(ctx, ripe_non_managed);
}

static void wc_lookup_exec_apnic_handle_post_root_and_stop(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_run_post_legacy_root_step(
        ctx,
        body,
        apnic_transfer_to_apnic,
        need_redir_eval);
    wc_lookup_exec_apnic_run_post_stop_target_step(ctx, ripe_non_managed);
}

static void wc_lookup_exec_apnic_run_post_root_stop_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_post_root_and_stop(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        need_redir_eval);
}

static void wc_lookup_exec_apnic_run_post_full_ipv4_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_full_ipv4_space(
        ctx,
        body,
        apnic_transfer_to_apnic,
        need_redir_eval);
}

static void wc_lookup_exec_apnic_handle_post_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int* need_redir_eval) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_run_post_root_stop_step(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        need_redir_eval);
    wc_lookup_exec_apnic_run_post_full_ipv4_step(
        ctx,
        body,
        apnic_transfer_to_apnic,
        need_redir_eval);
}

static void wc_lookup_exec_apnic_handle_post_fast_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_fast_authoritative(
        ctx,
        auth,
        erx_marker_this_hop,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_run_apnic_header_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_handle_header_phase(
        ctx,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        need_redir_eval,
        ref,
        ref_explicit);
}

static int wc_lookup_exec_run_apnic_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !body || !need_redir_eval || !ref || !ref_explicit) return 0;

    return wc_lookup_exec_apnic_handle_transfer_and_hints(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_run_apnic_post_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_apnic_handle_post_transfer(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        auth,
        erx_marker_this_hop,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_handle_apnic_erx_logic(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int erx_marker_this_hop,
    int ripe_non_managed,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !body || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_run_apnic_header_step(
        ctx,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        need_redir_eval,
        ref,
        ref_explicit);

    wc_lookup_exec_run_apnic_transfer_post_chain_step(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        erx_marker_this_hop,
        ripe_non_managed,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_run_apnic_transfer_post_chain_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int erx_marker_this_hop,
    int ripe_non_managed,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !body || !need_redir_eval || !ref || !ref_explicit) return;

    int apnic_transfer_to_apnic = wc_lookup_exec_run_apnic_transfer_chain_transfer_step(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        need_redir_eval,
        ref,
        ref_explicit);
    wc_lookup_exec_run_apnic_transfer_chain_post_step(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        auth,
        erx_marker_this_hop,
        need_redir_eval,
        *ref);
}

static int wc_lookup_exec_run_apnic_transfer_chain_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !body || !need_redir_eval || !ref || !ref_explicit) return 0;

    return wc_lookup_exec_run_apnic_transfer_step(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        need_redir_eval,
        ref,
        ref_explicit);
}

static void wc_lookup_exec_run_apnic_transfer_chain_post_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int apnic_transfer_to_apnic,
    int ripe_non_managed,
    int auth,
    int erx_marker_this_hop,
    int* need_redir_eval,
    char* ref) {
    if (!ctx || !body || !need_redir_eval) return;

    wc_lookup_exec_run_apnic_post_transfer_step(
        ctx,
        body,
        apnic_transfer_to_apnic,
        ripe_non_managed,
        auth,
        erx_marker_this_hop,
        need_redir_eval,
        ref);
}

static int wc_lookup_exec_apnic_handle_transfer_and_hints(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !body || !need_redir_eval || !ref || !ref_explicit) return 0;

    int apnic_transfer_to_apnic = wc_lookup_exec_apnic_run_transfer_hint_transfer_step(
        ctx,
        body,
        need_redir_eval,
        ref);
    wc_lookup_exec_apnic_run_transfer_hint_erx_hints_step(
        ctx,
        body,
        auth,
        header_is_iana,
        header_host,
        header_non_authoritative,
        need_redir_eval,
        ref,
        ref_explicit);
    return apnic_transfer_to_apnic;
}

static int wc_lookup_exec_apnic_run_transfer_hint_transfer_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* need_redir_eval,
    char** ref) {
    if (!ctx || !body || !need_redir_eval || !ref) return 0;

    return wc_lookup_exec_apnic_handle_transfer(
        ctx,
        body,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apnic_run_transfer_hint_erx_hints_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_is_iana,
    const char* header_host,
    int header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !body || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_handle_erx_hints(
        ctx,
        body,
        auth,
        header_is_iana,
        header_host,
        header_non_authoritative,
        need_redir_eval,
        ref,
        ref_explicit);
}

static int wc_lookup_exec_apnic_apply_header_authority(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return 0;

    int header_authoritative_stop =
        wc_lookup_exec_apnic_run_apply_header_authority_compute_step(
            ctx,
            header_host,
            auth,
            header_non_authoritative);
    wc_lookup_exec_apnic_run_apply_header_authority_ref_flow_step(
        ctx,
        header_host,
        header_is_iana,
        header_authoritative_stop,
        need_redir_eval,
        ref,
        ref_explicit);
    return header_authoritative_stop;
}

static int wc_lookup_exec_apnic_run_apply_header_authority_compute_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int auth,
    int header_non_authoritative) {
    if (!ctx || !header_host) return 0;

    return wc_lookup_exec_apnic_header_authoritative_stop(
        ctx,
        header_host,
        auth,
        header_non_authoritative);
}

static void wc_lookup_exec_apnic_run_apply_header_authority_ref_flow_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_authoritative_stop,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return;

    wc_lookup_exec_apnic_handle_header_ref_flow(
        ctx,
        header_host,
        header_is_iana,
        header_authoritative_stop,
        need_redir_eval,
        ref,
        ref_explicit);
}

static int wc_lookup_exec_apnic_handle_header_phase(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return 0;

    return wc_lookup_exec_apnic_run_header_phase_authority_step(
        ctx,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        need_redir_eval,
        ref,
        ref_explicit);
}

static int wc_lookup_exec_apnic_run_header_phase_authority_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_is_iana,
    int header_non_authoritative,
    int auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit) {
    if (!ctx || !header_host || !need_redir_eval || !ref || !ref_explicit) return 0;

    return wc_lookup_exec_apnic_apply_header_authority(
        ctx,
        header_host,
        header_is_iana,
        header_non_authoritative,
        auth,
        need_redir_eval,
        ref,
        ref_explicit);
}

static int wc_lookup_exec_init_persistent_empty_flag(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->persistent_empty && ctx->hops == 0) ? 1 : 0;
}

static void wc_lookup_exec_prepare_access_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current) {
    if (!ctx || !first_hop_persistent_empty || !access_denied_current ||
        !access_denied_internal || !rate_limit_current) {
        return;
    }

    *first_hop_persistent_empty = wc_lookup_exec_init_persistent_empty_flag(ctx);
    wc_lookup_exec_init_access_flags(
        ctx,
        header_host,
        header_matches_current,
        access_denied_current,
        access_denied_internal,
        rate_limit_current);
}

static void wc_lookup_exec_init_access_flags(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_matches_current,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current) {
    if (!ctx || !access_denied_current || !access_denied_internal || !rate_limit_current) return;

    *access_denied_current = (ctx->access_denied && (!header_host || header_matches_current));
    *access_denied_internal = (ctx->access_denied && header_host && !header_matches_current);
    *rate_limit_current = (ctx->rate_limited && (!header_host || header_matches_current));
}

static void wc_lookup_exec_select_header_hint_storage(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    char* fallback_buf,
    size_t fallback_len,
    char** header_hint_host,
    size_t* header_hint_host_len) {
    if (!ctx || !fallback_buf || !header_hint_host || !header_hint_host_len) return;

    *header_hint_host = ctx->header_hint_host ? ctx->header_hint_host : fallback_buf;
    *header_hint_host_len = ctx->header_hint_host_len ? ctx->header_hint_host_len : fallback_len;
}

static void wc_lookup_exec_clear_header_hint_buffer(
    char* header_hint_host,
    size_t header_hint_host_len) {
    if (!header_hint_host || header_hint_host_len == 0) return;

    header_hint_host[0] = '\0';
}

static void wc_lookup_exec_clear_header_hint_valid_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_reset_header_hint_valid(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->header_hint_valid) return;

    wc_lookup_exec_clear_header_hint_valid_output_step(ctx);
}

static void wc_lookup_exec_clear_header_hint_valid_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->header_hint_valid) return;

    *ctx->header_hint_valid = 0;
}

static void wc_lookup_exec_prepare_header_hint(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* fallback_buf,
    size_t fallback_len,
    char** header_hint_host,
    size_t* header_hint_host_len) {
    if (!ctx || !fallback_buf || !header_hint_host || !header_hint_host_len) return;

    wc_lookup_exec_select_header_hint_storage(
        ctx,
        fallback_buf,
        fallback_len,
        header_hint_host,
        header_hint_host_len);
    wc_lookup_exec_clear_header_hint_buffer(
        *header_hint_host,
        *header_hint_host_len);
    wc_lookup_exec_reset_header_hint_valid(ctx);
}

static void wc_lookup_exec_init_redirect_state(
    int* header_non_authoritative,
    int* allow_cycle_on_loop,
    int* need_redir,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current) {
    if (!header_non_authoritative || !allow_cycle_on_loop || !need_redir ||
        !force_stop_authoritative || !apnic_erx_suppress_current) {
        return;
    }

    *header_non_authoritative = 0;
    *allow_cycle_on_loop = 0;
    *need_redir = 0;
    *force_stop_authoritative = 0;
    *apnic_erx_suppress_current = 0;
}

static void wc_lookup_exec_prepare_local_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int* auth,
    int* need_redir_eval,
    char** ref,
    int* ref_explicit,
    int* ref_port,
    int* ripe_non_managed) {
    if (!ctx || !body || !auth || !need_redir_eval || !ref ||
        !ref_explicit || !ref_port || !ripe_non_managed) {
        return;
    }

    *body = ctx->body;
    *auth = ctx->auth ? *ctx->auth : 0;
    *need_redir_eval = ctx->need_redir_eval ? *ctx->need_redir_eval : 0;
    *ref = (ctx->ref && *ctx->ref) ? *ctx->ref : NULL;
    *ref_explicit = ctx->ref_explicit ? *ctx->ref_explicit : 0;
    *ref_port = ctx->ref_port ? *ctx->ref_port : 0;
    *ripe_non_managed = ctx->ripe_non_managed;
}

static void wc_lookup_exec_prepare_header_state(
    int* banner_only,
    const char** header_host,
    int* header_is_iana,
    int* header_matches_current) {
    if (!banner_only || !header_host || !header_is_iana || !header_matches_current) {
        return;
    }

    *banner_only = 0;
    *header_host = NULL;
    *header_is_iana = 0;
    *header_matches_current = 0;
}

static void wc_lookup_exec_prepare_header_fields(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* auth,
    int* banner_only,
    const char** header_host,
    int* header_is_iana,
    int* header_matches_current) {
    if (!ctx || !body || !auth || !banner_only || !header_host ||
        !header_is_iana || !header_matches_current) {
        return;
    }

    wc_lookup_exec_prepare_header_state(
        banner_only,
        header_host,
        header_is_iana,
        header_matches_current);
    wc_lookup_exec_prepare_header_authority(
        ctx,
        body,
        auth,
        banner_only,
        header_host,
        header_is_iana,
        header_matches_current);
}

static void wc_lookup_exec_apply_lacnic_header_redirect_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval) return;

    wc_lookup_exec_handle_lacnic_header_redirect(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        ref,
        ref_explicit,
        need_redir_eval);
}

static void wc_lookup_exec_prepare_header_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* auth,
    int* banner_only,
    const char** header_host,
    int* header_is_iana,
    int* header_matches_current) {
    if (!ctx || !body || !auth || !banner_only || !header_host ||
        !header_is_iana || !header_matches_current) {
        return;
    }

    wc_lookup_exec_prepare_header_fields(
        ctx,
        body,
        auth,
        banner_only,
        header_host,
        header_is_iana,
        header_matches_current);
}

static void wc_lookup_exec_prepare_lacnic_header_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval) return;

    wc_lookup_exec_apply_lacnic_header_redirect_step(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        ref,
        ref_explicit,
        need_redir_eval);
}

static void wc_lookup_exec_run_header_and_lacnic_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval,
    int* auth,
    int* banner_only,
    const char** header_host,
    int* header_is_iana,
    int* header_matches_current) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval ||
        !auth || !banner_only || !header_host || !header_is_iana || !header_matches_current) {
        return;
    }

    wc_lookup_exec_prepare_header_step(
        ctx,
        body,
        auth,
        banner_only,
        header_host,
        header_is_iana,
        header_matches_current);

    wc_lookup_exec_prepare_lacnic_header_step(
        ctx,
        body,
        *header_host,
        *header_is_iana,
        *header_matches_current,
        header_hint_host,
        header_hint_host_len,
        ref,
        ref_explicit,
        need_redir_eval);
}

static void wc_lookup_exec_prepare_header_and_lacnic(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval,
    int* auth,
    int* banner_only,
    const char** header_host,
    int* header_is_iana,
    int* header_matches_current) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval ||
        !auth || !banner_only || !header_host || !header_is_iana || !header_matches_current) {
        return;
    }

    wc_lookup_exec_run_header_and_lacnic_steps(
        ctx,
        body,
        header_hint_host,
        header_hint_host_len,
        ref,
        ref_explicit,
        need_redir_eval,
        auth,
        banner_only,
        header_host,
        header_is_iana,
        header_matches_current);
}

static void wc_lookup_exec_apply_lacnic_header_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval) return;

    wc_lookup_exec_handle_lacnic_redirect(
        ctx,
        body,
        header_host,
        header_is_iana,
        header_matches_current,
        header_hint_host,
        header_hint_host_len,
        ref,
        ref_explicit,
        need_redir_eval);
}

static void wc_lookup_exec_handle_lacnic_header_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    int header_is_iana,
    int header_matches_current,
    char* header_hint_host,
    size_t header_hint_host_len,
    char** ref,
    int ref_explicit,
    int* need_redir_eval) {
    if (!ctx || !body || !header_hint_host || !ref || !need_redir_eval) return;

    if (wc_lookup_exec_is_current_rir_lacnic(ctx)) {
        wc_lookup_exec_apply_lacnic_header_redirect(
            ctx,
            body,
            header_host,
            header_is_iana,
            header_matches_current,
            header_hint_host,
            header_hint_host_len,
            ref,
            ref_explicit,
            need_redir_eval);
    }
}

static void wc_lookup_exec_handle_access_and_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    const char* header_host,
    int header_matches_current,
    int auth,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !*body || !header_non_authoritative || !need_redir_eval) return;

    int first_hop_persistent_empty = 0;
    int access_denied_current = 0;
    int access_denied_internal = 0;
    int rate_limit_current = 0;
    wc_lookup_exec_init_access_signal_flags(
        ctx,
        body,
        header_host,
        header_matches_current,
        &first_hop_persistent_empty,
        &access_denied_current,
        &access_denied_internal,
        &rate_limit_current);

    wc_lookup_exec_apply_access_signals(
        ctx,
        *body,
        first_hop_persistent_empty,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        auth,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_init_access_signal_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current) {
    if (!ctx || !body || !*body || !first_hop_persistent_empty ||
        !access_denied_current || !access_denied_internal || !rate_limit_current) {
        return;
    }

    wc_lookup_exec_handle_access_rate_limit_state(
        ctx,
        body,
        header_host,
        header_matches_current,
        first_hop_persistent_empty,
        access_denied_current,
        access_denied_internal,
        rate_limit_current);
}

static void wc_lookup_exec_apply_access_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int first_hop_persistent_empty,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_access_signals(
        ctx,
        body,
        first_hop_persistent_empty,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        auth,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_run_access_signal_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int first_hop_persistent_empty,
    int auth,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_apply_persistent_empty_signal(
        ctx,
        first_hop_persistent_empty,
        header_non_authoritative,
        need_redir_eval);

    wc_lookup_exec_apply_non_auth_and_cidr_signals_step(
        ctx,
        body,
        auth,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_handle_access_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int first_hop_persistent_empty,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int auth,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_run_access_signal_steps(
        ctx,
        body,
        first_hop_persistent_empty,
        auth,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_apply_persistent_empty_signal(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int first_hop_persistent_empty,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_persistent_empty_signal(
        ctx,
        first_hop_persistent_empty,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_apply_non_auth_and_cidr_signals_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int access_denied_current,
    int rate_limit_current,
    int ripe_non_managed,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !body || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_non_auth_and_cidr_signals(
        ctx,
        body,
        auth,
        access_denied_current,
        rate_limit_current,
        ripe_non_managed,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_handle_persistent_empty_signal(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int first_hop_persistent_empty,
    int* header_non_authoritative,
    int* need_redir_eval) {
    if (!ctx || !header_non_authoritative || !need_redir_eval) return;

    wc_lookup_exec_handle_persistent_empty(
        ctx,
        first_hop_persistent_empty,
        header_non_authoritative,
        need_redir_eval);
}

static void wc_lookup_exec_handle_access_rate_limit_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current) {
    if (!ctx || !body || !*body || !first_hop_persistent_empty ||
        !access_denied_current || !access_denied_internal || !rate_limit_current) {
        return;
    }

    wc_lookup_exec_apply_access_rate_limit_state(
        ctx,
        body,
        header_host,
        header_matches_current,
        first_hop_persistent_empty,
        access_denied_current,
        access_denied_internal,
        rate_limit_current);
}

static void wc_lookup_exec_prepare_access_rate_limit_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current) {
    if (!ctx || !first_hop_persistent_empty || !access_denied_current ||
        !access_denied_internal || !rate_limit_current) {
        return;
    }

    wc_lookup_exec_prepare_access_state(
        ctx,
        header_host,
        header_matches_current,
        first_hop_persistent_empty,
        access_denied_current,
        access_denied_internal,
        rate_limit_current);
}

static void wc_lookup_exec_run_access_rate_limit_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host) {
    if (!ctx || !body || !*body) return;

    wc_lookup_exec_run_access_rate_limit(
        ctx,
        body,
        access_denied_current,
        access_denied_internal,
        rate_limit_current,
        header_host);
}

static void wc_lookup_exec_apply_access_rate_limit_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    const char* header_host,
    int header_matches_current,
    int* first_hop_persistent_empty,
    int* access_denied_current,
    int* access_denied_internal,
    int* rate_limit_current) {
    if (!ctx || !body || !*body || !first_hop_persistent_empty ||
        !access_denied_current || !access_denied_internal || !rate_limit_current) {
        return;
    }

    wc_lookup_exec_prepare_access_rate_limit_flags(
        ctx,
        header_host,
        header_matches_current,
        first_hop_persistent_empty,
        access_denied_current,
        access_denied_internal,
        rate_limit_current);

    wc_lookup_exec_run_access_rate_limit_step(
        ctx,
        body,
        *access_denied_current,
        *access_denied_internal,
        *rate_limit_current,
        header_host);
}

static void wc_lookup_exec_run_access_rate_limit(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char** body,
    int access_denied_current,
    int access_denied_internal,
    int rate_limit_current,
    const char* header_host) {
    if (!ctx || !body || !*body) return;

    wc_lookup_exec_handle_access_rate_limit(
        ctx,
        body,
        access_denied_current,
        access_denied_internal,
        rate_limit_current,
        header_host);
}

static void wc_lookup_exec_apply_header_non_auth_to_auth(
    int header_non_authoritative,
    int* auth);
static void wc_lookup_exec_record_seen_real_authoritative_if_valid(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative);
static void wc_lookup_exec_run_erx_and_authority_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* erx_marker_this_hop);

static void wc_lookup_exec_finalize_authority_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_non_authoritative,
    int* auth) {
    if (!ctx || !auth) return;

    wc_lookup_exec_apply_header_non_auth_to_auth(
        header_non_authoritative,
        auth);
    wc_lookup_exec_record_seen_real_authoritative_if_valid(
        ctx,
        *auth,
        header_non_authoritative);
}

static void wc_lookup_exec_apply_header_non_auth_to_auth(
    int header_non_authoritative,
    int* auth) {
    if (!auth) return;

    if (header_non_authoritative) {
        *auth = 0;
    }
}

static void wc_lookup_exec_mark_seen_real_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_record_seen_real_authoritative_if_valid(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative) {
    if (!ctx) return;

    if (wc_lookup_exec_is_authority_valid(ctx, auth, header_non_authoritative)) {
        wc_lookup_exec_mark_seen_real_authoritative_output_step(ctx);
    }
}

static void wc_lookup_exec_mark_seen_real_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->seen_real_authoritative) {
        *ctx->seen_real_authoritative = 1;
    }
}

static void wc_lookup_exec_finalize_authority_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_non_authoritative,
    int* auth) {
    if (!ctx || !auth) return;

    wc_lookup_exec_finalize_authority_state(
        ctx,
        header_non_authoritative,
        auth);
}

static int wc_lookup_exec_is_authority_valid(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative) {
    if (!ctx) return 0;

    return auth && !header_non_authoritative &&
        !wc_lookup_exec_is_current_rir_iana(ctx);
}

static void wc_lookup_exec_handle_erx_and_authority(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* erx_marker_this_hop) {
    if (!ctx || !body || !auth || !header_non_authoritative || !need_redir_eval ||
        !ref || !erx_marker_this_hop) {
        return;
    }

    wc_lookup_exec_run_erx_and_authority_steps(
        ctx,
        body,
        header_host,
        header_hint_host,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref,
        erx_marker_this_hop);
}

static void wc_lookup_exec_run_erx_and_authority_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* erx_marker_this_hop) {
    if (!ctx || !body || !auth || !header_non_authoritative || !need_redir_eval ||
        !ref || !erx_marker_this_hop) {
        return;
    }

    wc_lookup_exec_run_erx_marker_recheck(
        ctx,
        body,
        header_host,
        header_hint_host,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref,
        erx_marker_this_hop);

    wc_lookup_exec_finalize_authority_step(
        ctx,
        *header_non_authoritative,
        auth);
}

static void wc_lookup_exec_reset_erx_marker_this_hop(int* erx_marker_this_hop) {
    if (!erx_marker_this_hop) return;

    *erx_marker_this_hop = 0;
}

static void wc_lookup_exec_run_erx_marker_recheck(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    const char* header_host,
    const char* header_hint_host,
    int* auth,
    int* header_non_authoritative,
    int* need_redir_eval,
    char** ref,
    int* erx_marker_this_hop) {
    if (!ctx || !body || !auth || !header_non_authoritative || !need_redir_eval ||
        !ref || !erx_marker_this_hop) {
        return;
    }

    wc_lookup_exec_reset_erx_marker_this_hop(erx_marker_this_hop);
    wc_lookup_exec_handle_erx_marker_recheck(
        ctx,
        body,
        header_host,
        header_hint_host,
        auth,
        header_non_authoritative,
        need_redir_eval,
        ref,
        erx_marker_this_hop);
}

struct wc_lookup_exec_eval_io_state {
    char* body;
    int auth;
    int need_redir_eval;
    char* ref;
    int ref_explicit;
    int ref_port;
    int ripe_non_managed;
};

struct wc_lookup_exec_eval_hint_state {
    char header_hint_host_buf[128];
    char* header_hint_host;
    size_t header_hint_host_len;
};

struct wc_lookup_exec_eval_redirect_state {
    int header_non_authoritative;
    int allow_cycle_on_loop;
    int need_redir;
    int force_stop_authoritative;
    int apnic_erx_suppress_current;
};

struct wc_lookup_exec_header_state {
    const char* host;
    int is_iana;
    int matches_current;
    int erx_marker_this_hop;
};

struct wc_lookup_exec_eval_state {
    struct wc_lookup_exec_eval_io_state io;
    struct wc_lookup_exec_eval_hint_state hint;
    struct wc_lookup_exec_eval_redirect_state redirect;
};

static void wc_lookup_exec_apply_access_signals_for_eval(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    const struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !header_state) {
        return;
    }

    wc_lookup_exec_handle_access_and_signals(
        ctx,
        &st->io.body,
        header_state->host,
        header_state->matches_current,
        st->io.auth,
        st->io.ripe_non_managed,
        &st->redirect.header_non_authoritative,
        &st->io.need_redir_eval);
}

static void wc_lookup_exec_prepare_eval_header_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    wc_lookup_exec_prepare_eval_header_fields(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_prepare_eval_access_signals(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !header_state) {
        return;
    }

    wc_lookup_exec_apply_access_signals_for_eval(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_prepare_eval_header_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    wc_lookup_exec_prepare_eval_header_state(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_prepare_eval_access_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !header_state) {
        return;
    }

    wc_lookup_exec_prepare_eval_access_signals(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_prepare_header_and_access(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    wc_lookup_exec_prepare_eval_header_step(
        ctx,
        st,
        header_state);

    wc_lookup_exec_prepare_eval_access_step(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_prepare_eval_header_fields(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    int banner_only = 0;
    wc_lookup_exec_prepare_header_and_lacnic(
        ctx,
        st->io.body,
        st->hint.header_hint_host,
        st->hint.header_hint_host_len,
        &st->io.ref,
        st->io.ref_explicit,
        &st->io.need_redir_eval,
        &st->io.auth,
        &banner_only,
        &header_state->host,
        &header_state->is_iana,
        &header_state->matches_current);
}

static void wc_lookup_exec_run_pre_apnic_erx_stage(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    wc_lookup_exec_handle_erx_and_authority(
        ctx,
        st->io.body,
        header_state->host,
        st->hint.header_hint_host,
        &st->io.auth,
        &st->redirect.header_non_authoritative,
        &st->io.need_redir_eval,
        &st->io.ref,
        &header_state->erx_marker_this_hop);
}

static void wc_lookup_exec_run_pre_apnic_stage(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    wc_lookup_exec_run_pre_apnic_header_access_step(
        ctx,
        st,
        header_state);

    wc_lookup_exec_run_pre_apnic_erx_step(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_run_pre_apnic_header_access_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    wc_lookup_exec_prepare_header_and_access(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_run_pre_apnic_erx_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !header_state) {
        return;
    }

    wc_lookup_exec_run_pre_apnic_erx_stage(
        ctx,
        st,
        header_state);
}

static int wc_lookup_exec_should_disable_redirect_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);

static int wc_lookup_exec_compute_need_redirect(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx || !ctx->zopts) return 0;

    if (wc_lookup_exec_should_disable_redirect_step(ctx)) {
        return 0;
    }

    return need_redir_eval;
}

static int wc_lookup_exec_should_disable_redirect_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->zopts) return 0;

    return ctx->zopts->no_redirect ? 1 : 0;
}

static int wc_lookup_exec_compute_initial_allow_cycle_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    return wc_lookup_exec_initial_allow_cycle_on_loop(ctx, need_redir_eval);
}

static void wc_lookup_exec_update_allow_cycle_on_loop(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval,
    int* allow_cycle_on_loop) {
    if (!ctx || !allow_cycle_on_loop) return;

    *allow_cycle_on_loop = wc_lookup_exec_compute_initial_allow_cycle_step(ctx, need_redir_eval);
    wc_lookup_exec_apply_allow_cycle_overrides(ctx, allow_cycle_on_loop);
}

static int wc_lookup_exec_initial_allow_cycle_on_loop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx) return 0;

    return (need_redir_eval || (ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy)) ? 1 : 0;
}

static void wc_lookup_exec_apply_allow_cycle_overrides(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop) {
    if (!ctx || !allow_cycle_on_loop) return;

    wc_lookup_exec_apply_allow_cycle_authoritative_stop(ctx, allow_cycle_on_loop);
    wc_lookup_exec_apply_allow_cycle_hop_limits(ctx, allow_cycle_on_loop);
}

static int wc_lookup_exec_should_disable_allow_cycle_on_authoritative_stop_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_authoritative_stop && *ctx->apnic_erx_authoritative_stop) ? 1 : 0;
}

static void wc_lookup_exec_disable_allow_cycle_on_authoritative_stop_step(
    int* allow_cycle_on_loop) {
    if (!allow_cycle_on_loop) return;

    *allow_cycle_on_loop = 0;
}

static void wc_lookup_exec_apply_allow_cycle_authoritative_stop(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop) {
    if (!ctx || !allow_cycle_on_loop) return;

    if (!wc_lookup_exec_should_disable_allow_cycle_on_authoritative_stop_step(ctx)) {
        return;
    }

    wc_lookup_exec_disable_allow_cycle_on_authoritative_stop_step(allow_cycle_on_loop);
}

static int wc_lookup_exec_should_block_allow_cycle_by_cidr(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_iana_netblock_cidr && *ctx->apnic_iana_netblock_cidr &&
            ctx->seen_arin_no_match_cidr && !*ctx->seen_arin_no_match_cidr);
}

static void wc_lookup_exec_apply_allow_cycle_min_hops_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop);
static void wc_lookup_exec_apply_allow_cycle_cidr_block_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop);

static void wc_lookup_exec_apply_allow_cycle_hop_limits(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop) {
    if (!ctx || !allow_cycle_on_loop) return;

    wc_lookup_exec_apply_allow_cycle_min_hops_step(ctx, allow_cycle_on_loop);
    wc_lookup_exec_apply_allow_cycle_cidr_block_step(ctx, allow_cycle_on_loop);
}

static void wc_lookup_exec_apply_allow_cycle_min_hops_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop) {
    if (!ctx || !allow_cycle_on_loop) return;

    if (ctx->hops < 1) {
        *allow_cycle_on_loop = 0;
    }
}

static void wc_lookup_exec_apply_allow_cycle_cidr_block_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* allow_cycle_on_loop) {
    if (!ctx || !allow_cycle_on_loop) return;

    if (*allow_cycle_on_loop && wc_lookup_exec_should_block_allow_cycle_by_cidr(ctx)) {
        *allow_cycle_on_loop = 0;
    }
}

static int wc_lookup_exec_force_stop_should_consider_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int need_redir_eval);
static int wc_lookup_exec_force_stop_base_condition(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int need_redir_eval);

static void wc_lookup_exec_update_force_stop_authoritative(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval,
    int* force_stop_authoritative) {
    if (!ctx || !force_stop_authoritative) return;

    *force_stop_authoritative = wc_lookup_exec_erx_fast_authoritative_flag(ctx);
    if (wc_lookup_exec_should_force_stop_authoritative(
            ctx,
            auth,
            header_non_authoritative,
            erx_marker_this_hop,
            need_redir_eval)) {
        *force_stop_authoritative = 1;
    }
}

static int wc_lookup_exec_erx_fast_authoritative_flag(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->erx_fast_authoritative) return 0;

    return *ctx->erx_fast_authoritative ? 1 : 0;
}

static int wc_lookup_exec_should_force_stop_authoritative(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval) {
    if (!ctx) return 0;

    if (!wc_lookup_exec_force_stop_should_consider_step(
            ctx,
            auth,
            header_non_authoritative,
            need_redir_eval)) {
        return 0;
    }

    return erx_marker_this_hop ? 0 : 1;
}

static int wc_lookup_exec_force_stop_should_consider_step(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int need_redir_eval) {
    if (!ctx) return 0;

    if (!wc_lookup_exec_force_stop_base_condition(
            ctx,
            auth,
            header_non_authoritative,
            need_redir_eval)) {
        return 0;
    }

    if (wc_lookup_exec_is_current_rir_iana(ctx)) return 0;

    return 1;
}

static int wc_lookup_exec_force_stop_base_condition(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int need_redir_eval) {
    if (!ctx) return 0;

    return ((auth && !header_non_authoritative && !need_redir_eval && !ctx->ref) ||
            (ctx->ref && !*ctx->ref)) ? 1 : 0;
}

static int wc_lookup_exec_is_current_rir_iana(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "iana") == 0;
}

static void wc_lookup_exec_finalize_apnic_suppress_current(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* apnic_erx_suppress_current) {
    if (!ctx || !body || !apnic_erx_suppress_current) return;
    wc_lookup_exec_update_apnic_ripe_non_managed(ctx, body);
    wc_lookup_exec_apply_apnic_suppress_overrides(ctx, apnic_erx_suppress_current);
}

static void wc_lookup_exec_update_apnic_suppress_current(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int* apnic_erx_suppress_current) {
    if (!ctx || !body || !apnic_erx_suppress_current) return;

    *apnic_erx_suppress_current = wc_lookup_exec_should_suppress_apnic_current(ctx, body);
    wc_lookup_exec_finalize_apnic_suppress_current(ctx, body, apnic_erx_suppress_current);
}

static int wc_lookup_exec_apnic_suppress_current_ctx_conditions_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_suppress_current_body_condition_step(
    const char* body);

static int wc_lookup_exec_should_suppress_apnic_current(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return 0;

    if (!wc_lookup_exec_apnic_suppress_current_ctx_conditions_step(ctx)) {
        return 0;
    }

    return wc_lookup_exec_apnic_suppress_current_body_condition_step(body);
}

static int wc_lookup_exec_apnic_suppress_current_ctx_conditions_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->seen_apnic_iana_netblock && *ctx->seen_apnic_iana_netblock &&
            ctx->apnic_ambiguous_revisit_used && *ctx->apnic_ambiguous_revisit_used &&
            ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "apnic") == 0 &&
            ctx->hops > 0) ? 1 : 0;
}

static int wc_lookup_exec_apnic_suppress_current_body_condition_step(
    const char* body) {
    return (body && wc_lookup_body_contains_apnic_iana_netblock(body)) ? 1 : 0;
}

static void wc_lookup_exec_mark_apnic_erx_ripe_non_managed_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_update_apnic_ripe_non_managed(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body) {
    if (!ctx || !body) return;

    if (ctx->apnic_erx_root && *ctx->apnic_erx_root && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "ripe") == 0) {
        if (wc_lookup_body_contains_ripe_non_managed(body)) {
            wc_lookup_exec_mark_apnic_erx_ripe_non_managed_output_step(ctx);
        }
    }
}

static void wc_lookup_exec_mark_apnic_erx_ripe_non_managed_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_ripe_non_managed) {
        *ctx->apnic_erx_ripe_non_managed = 1;
    }
}

static void wc_lookup_exec_apply_apnic_suppress_overrides(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* apnic_erx_suppress_current) {
    if (!ctx || !apnic_erx_suppress_current) return;

    wc_lookup_exec_apply_apnic_arin_suppress_override(ctx, apnic_erx_suppress_current);
    wc_lookup_exec_apply_apnic_ripe_suppress_override(ctx, apnic_erx_suppress_current);
}

static int wc_lookup_exec_should_apply_apnic_arin_suppress_override_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_should_apply_apnic_ripe_suppress_override_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_apply_apnic_suppress_zero_step(int* apnic_erx_suppress_current);

static void wc_lookup_exec_apply_apnic_arin_suppress_override(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* apnic_erx_suppress_current) {
    if (!ctx || !apnic_erx_suppress_current) return;

    if (!wc_lookup_exec_should_apply_apnic_arin_suppress_override_step(ctx)) {
        return;
    }

    wc_lookup_exec_apply_apnic_suppress_zero_step(apnic_erx_suppress_current);
}

static int wc_lookup_exec_should_apply_apnic_arin_suppress_override_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root && *ctx->apnic_erx_root && ctx->current_rir_guess &&
            strcasecmp(ctx->current_rir_guess, "arin") == 0) ? 1 : 0;
}

static void wc_lookup_exec_apply_apnic_suppress_zero_step(int* apnic_erx_suppress_current) {
    if (!apnic_erx_suppress_current) return;

    *apnic_erx_suppress_current = 0;
}

static void wc_lookup_exec_apply_apnic_ripe_suppress_override(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int* apnic_erx_suppress_current) {
    if (!ctx || !apnic_erx_suppress_current) return;

    if (!wc_lookup_exec_should_apply_apnic_ripe_suppress_override_step(ctx)) {
        return;
    }

    wc_lookup_exec_apply_apnic_suppress_zero_step(apnic_erx_suppress_current);
}

static int wc_lookup_exec_should_apply_apnic_ripe_suppress_override_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root && *ctx->apnic_erx_root && ctx->current_rir_guess &&
            strcasecmp(ctx->current_rir_guess, "ripe") == 0 &&
            ctx->apnic_erx_ripe_non_managed && *ctx->apnic_erx_ripe_non_managed) ? 1 : 0;
}

static int wc_lookup_exec_should_stop_on_apnic_target(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* stop_rir) {
    if (!ctx || !stop_rir || !ctx->current_rir_guess) return 0;

    return strcasecmp(stop_rir, ctx->current_rir_guess) == 0;
}

static void wc_lookup_exec_apnic_apply_stop_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* stop_rir) {
    if (!ctx || !stop_rir) return;

    wc_lookup_exec_mark_apnic_erx_stop_output_step(ctx);
    wc_lookup_exec_clear_apnic_erx_stop_unknown_output_step(ctx);

    wc_lookup_exec_apnic_write_stop_host(ctx, stop_rir);
}

static void wc_lookup_exec_apply_apnic_stop_on_target(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx) return;

    if (!wc_lookup_exec_should_apply_apnic_stop_on_target(ctx, need_redir_eval)) return;

    const char* stop_rir = wc_lookup_exec_apnic_stop_rir(ctx);
    if (!wc_lookup_exec_should_stop_on_apnic_target(ctx, stop_rir)) return;

    wc_lookup_exec_apnic_apply_stop_writeback_step(ctx, stop_rir);
}

static int wc_lookup_exec_apnic_stop_target_blocked_by_force_cycle(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_stop_target_root_and_reason_ok(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static int wc_lookup_exec_apnic_stop_target_ref_empty(
    const struct wc_lookup_exec_redirect_ctx* ctx);

static int wc_lookup_exec_should_apply_apnic_stop_on_target(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx) return 0;

    if (wc_lookup_exec_apnic_stop_target_blocked_by_force_cycle(ctx)) {
        return 0;
    }
    if (!wc_lookup_exec_apnic_stop_target_root_and_reason_ok(ctx)) {
        return 0;
    }
    if (!wc_lookup_exec_apnic_stop_target_ref_empty(ctx)) {
        return 0;
    }

    return need_redir_eval ? 1 : 0;
}

static int wc_lookup_exec_apnic_stop_target_blocked_by_force_cycle(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->force_rir_cycle && *ctx->force_rir_cycle) ? 1 : 0;
}

static int wc_lookup_exec_apnic_stop_target_root_and_reason_ok(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
            ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1) ? 1 : 0;
}

static int wc_lookup_exec_apnic_stop_target_ref_empty(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return (!ctx->ref || !*ctx->ref) ? 1 : 0;
}

static const char* wc_lookup_exec_apnic_stop_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return NULL;

    if (ctx->apnic_erx_target_rir && ctx->apnic_erx_target_rir[0]) {
        return ctx->apnic_erx_target_rir;
    }

    if (ctx->apnic_erx_ref_host && ctx->apnic_erx_ref_host[0]) {
        const char* guessed = wc_guess_rir(ctx->apnic_erx_ref_host);
        if (guessed) return guessed;
    }

    return NULL;
}

static void wc_lookup_exec_apnic_write_stop_host_from_fallback_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* stop_rir) {
    if (!ctx) return;

    const char* canon = wc_dns_canonical_host_for_rir(stop_rir);
    const char* fallback_value = canon ? canon : ctx->current_host;
    wc_lookup_exec_write_apnic_erx_stop_host_value_output_step(
        ctx,
        fallback_value);
}

static void wc_lookup_exec_apnic_write_stop_host(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* stop_rir) {
    if (!ctx || !stop_rir) return;

    if (!ctx->apnic_erx_stop_host || ctx->apnic_erx_stop_host_len <= 0) return;

    if (ctx->apnic_erx_ref_host && ctx->apnic_erx_ref_host[0]) {
        wc_lookup_exec_write_apnic_erx_stop_host_value_output_step(
            ctx,
            ctx->apnic_erx_ref_host);
        return;
    }

    wc_lookup_exec_apnic_write_stop_host_from_fallback_step(ctx, stop_rir);
}

static void wc_lookup_exec_finalize_redirect_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int* need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current) {
    if (!ctx || !body || !need_redir_eval || !allow_cycle_on_loop ||
        !force_stop_authoritative || !apnic_erx_suppress_current) {
        return;
    }

    wc_lookup_exec_update_redirect_flags_core(
        ctx,
        body,
        auth,
        header_non_authoritative,
        erx_marker_this_hop,
        *need_redir_eval,
        allow_cycle_on_loop,
        force_stop_authoritative,
        apnic_erx_suppress_current);
    wc_lookup_exec_apply_apnic_stop_on_target(
        ctx,
        *need_redir_eval);
}

static void wc_lookup_exec_update_cycle_and_stop_flags(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative) {
    if (!ctx || !allow_cycle_on_loop || !force_stop_authoritative) {
        return;
    }

    wc_lookup_exec_update_allow_cycle_on_loop(
        ctx,
        need_redir_eval,
        allow_cycle_on_loop);
    wc_lookup_exec_update_force_stop_authoritative(
        ctx,
        auth,
        header_non_authoritative,
        erx_marker_this_hop,
        need_redir_eval,
        force_stop_authoritative);
}

static void wc_lookup_exec_run_update_redirect_flag_steps(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current) {
    if (!ctx || !body || !allow_cycle_on_loop ||
        !force_stop_authoritative || !apnic_erx_suppress_current) {
        return;
    }

    wc_lookup_exec_update_cycle_and_stop_flags(
        ctx,
        auth,
        header_non_authoritative,
        erx_marker_this_hop,
        need_redir_eval,
        allow_cycle_on_loop,
        force_stop_authoritative);
    wc_lookup_exec_update_apnic_suppress_current(
        ctx,
        body,
        apnic_erx_suppress_current);
}

static void wc_lookup_exec_update_redirect_flags_core(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current) {
    if (!ctx || !body || !allow_cycle_on_loop ||
        !force_stop_authoritative || !apnic_erx_suppress_current) {
        return;
    }

    wc_lookup_exec_run_update_redirect_flag_steps(
        ctx,
        body,
        auth,
        header_non_authoritative,
        erx_marker_this_hop,
        need_redir_eval,
        allow_cycle_on_loop,
        force_stop_authoritative,
        apnic_erx_suppress_current);
}

static int wc_lookup_exec_should_write_last_hop_authoritative_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_last_hop_authoritative_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth);
static int wc_lookup_exec_should_write_last_hop_need_redirect_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_last_hop_need_redirect_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval);
static int wc_lookup_exec_should_write_last_hop_has_ref_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_last_hop_has_ref_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ref);

static void wc_lookup_exec_write_last_hop_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth);
static void wc_lookup_exec_write_last_hop_need_redirect_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval);
static void wc_lookup_exec_write_last_hop_has_ref_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ref);

static void wc_lookup_exec_update_last_hop_stats(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int need_redir_eval,
    const char* ref) {
    if (!ctx) return;

    wc_lookup_exec_write_last_hop_authoritative_output_step(ctx, auth);
    wc_lookup_exec_write_last_hop_need_redirect_output_step(ctx, need_redir_eval);
    wc_lookup_exec_write_last_hop_has_ref_output_step(ctx, ref);
}

static void wc_lookup_exec_write_last_hop_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth) {
    if (!ctx) return;

    if (!wc_lookup_exec_should_write_last_hop_authoritative_output_step(ctx)) {
        return;
    }

    wc_lookup_exec_write_last_hop_authoritative_output_apply_step(ctx, auth);
}

static int wc_lookup_exec_should_write_last_hop_authoritative_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->last_hop_authoritative ? 1 : 0;
}

static void wc_lookup_exec_write_last_hop_authoritative_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth) {
    if (!ctx) return;

    *ctx->last_hop_authoritative = auth ? 1 : 0;
}

static void wc_lookup_exec_write_last_hop_need_redirect_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx) return;

    if (!wc_lookup_exec_should_write_last_hop_need_redirect_output_step(ctx)) {
        return;
    }

    wc_lookup_exec_write_last_hop_need_redirect_output_apply_step(ctx, need_redir_eval);
}

static int wc_lookup_exec_should_write_last_hop_need_redirect_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->last_hop_need_redirect ? 1 : 0;
}

static void wc_lookup_exec_write_last_hop_need_redirect_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir_eval) {
    if (!ctx) return;

    *ctx->last_hop_need_redirect = need_redir_eval ? 1 : 0;
}

static void wc_lookup_exec_write_last_hop_has_ref_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ref) {
    if (!ctx) return;

    if (!wc_lookup_exec_should_write_last_hop_has_ref_output_step(ctx)) {
        return;
    }

    wc_lookup_exec_write_last_hop_has_ref_output_apply_step(ctx, ref);
}

static int wc_lookup_exec_should_write_last_hop_has_ref_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->last_hop_has_ref ? 1 : 0;
}

static void wc_lookup_exec_write_last_hop_has_ref_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ref) {
    if (!ctx) return;

    *ctx->last_hop_has_ref = ref ? 1 : 0;
}

static int wc_lookup_exec_should_write_allow_cycle_on_loop_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_allow_cycle_on_loop_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int allow_cycle_on_loop);
static void wc_lookup_exec_write_header_non_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_non_authoritative);

static void wc_lookup_exec_write_allow_cycle_on_loop_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int allow_cycle_on_loop) {
    if (!ctx) return;

    if (!wc_lookup_exec_should_write_allow_cycle_on_loop_output_step(ctx)) {
        return;
    }

    wc_lookup_exec_write_allow_cycle_on_loop_output_apply_step(ctx, allow_cycle_on_loop);
}

static int wc_lookup_exec_should_write_allow_cycle_on_loop_output_step(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return 0;

    return ctx->allow_cycle_on_loop ? 1 : 0;
}

static void wc_lookup_exec_write_allow_cycle_on_loop_output_apply_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int allow_cycle_on_loop) {
    if (!ctx) return;

    *ctx->allow_cycle_on_loop = allow_cycle_on_loop;
}

static void wc_lookup_exec_write_need_redirect_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir);


static void wc_lookup_exec_update_redirect_flags_outputs(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_non_authoritative,
    int allow_cycle_on_loop,
    int need_redir) {
    if (!ctx) return;

    wc_lookup_exec_write_header_non_authoritative_output_step(ctx, header_non_authoritative);
    wc_lookup_exec_write_allow_cycle_on_loop_output_step(ctx, allow_cycle_on_loop);
    wc_lookup_exec_write_need_redirect_output_step(ctx, need_redir);
}

static void wc_lookup_exec_write_need_redirect_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int need_redir) {
    if (!ctx) return;

    if (ctx->need_redir) {
        *ctx->need_redir = need_redir;
    }
}

static void wc_lookup_exec_write_header_non_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_non_authoritative) {
    if (!ctx) return;

    if (ctx->header_non_authoritative) {
        *ctx->header_non_authoritative = header_non_authoritative;
    }
}

static void wc_lookup_exec_write_apnic_suppress_current_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int apnic_erx_suppress_current);

static void wc_lookup_exec_write_force_stop_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int force_stop_authoritative);

static void wc_lookup_exec_update_redirect_control_outputs(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int force_stop_authoritative,
    int apnic_erx_suppress_current) {
    if (!ctx) return;

    wc_lookup_exec_write_force_stop_authoritative_output_step(ctx, force_stop_authoritative);
    wc_lookup_exec_write_apnic_suppress_current_output_step(ctx, apnic_erx_suppress_current);
}

static void wc_lookup_exec_write_force_stop_authoritative_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int force_stop_authoritative) {
    if (!ctx) return;

    if (ctx->force_stop_authoritative) {
        *ctx->force_stop_authoritative = force_stop_authoritative;
    }
}

static void wc_lookup_exec_write_apnic_suppress_current_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int apnic_erx_suppress_current) {
    if (!ctx) return;

    if (ctx->apnic_erx_suppress_current) {
        *ctx->apnic_erx_suppress_current = apnic_erx_suppress_current;
    }
}

static void wc_lookup_exec_update_redirect_outputs_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int header_non_authoritative,
    int allow_cycle_on_loop,
    int need_redir,
    int force_stop_authoritative,
    int apnic_erx_suppress_current) {
    if (!ctx) return;

    wc_lookup_exec_update_redirect_flags_outputs(
        ctx,
        header_non_authoritative,
        allow_cycle_on_loop,
        need_redir);
    wc_lookup_exec_update_redirect_control_outputs(
        ctx,
        force_stop_authoritative,
        apnic_erx_suppress_current);
}


static void wc_lookup_exec_update_core_flags_outputs(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int need_redir_eval) {
    if (!ctx) return;

    *ctx->auth = auth;
    *ctx->need_redir_eval = need_redir_eval;
}

static void wc_lookup_exec_write_ref_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* ref);
static void wc_lookup_exec_write_ref_explicit_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ref_explicit);
static void wc_lookup_exec_write_ref_port_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ref_port);

static void wc_lookup_exec_update_core_ref_outputs(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* ref,
    int ref_explicit,
    int ref_port) {
    if (!ctx) return;

    wc_lookup_exec_write_ref_output_step(ctx, ref);
    wc_lookup_exec_write_ref_explicit_output_step(ctx, ref_explicit);
    wc_lookup_exec_write_ref_port_output_step(ctx, ref_port);
}

static void wc_lookup_exec_write_ref_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* ref) {
    if (!ctx) return;

    if (ctx->ref) {
        *ctx->ref = ref;
    }
}

static void wc_lookup_exec_write_ref_explicit_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ref_explicit) {
    if (!ctx) return;

    if (ctx->ref_explicit) {
        *ctx->ref_explicit = ref_explicit;
    }
}

static void wc_lookup_exec_write_ref_port_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int ref_port) {
    if (!ctx) return;

    if (ctx->ref_port) {
        *ctx->ref_port = ref_port;
    }
}

static void wc_lookup_exec_apply_writeback_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* body,
    int auth,
    int need_redir_eval,
    char* ref) {
    if (!ctx) return;

    ctx->body = body;
    wc_lookup_exec_update_last_hop_stats(
        ctx,
        auth,
        need_redir_eval,
        ref);
}

static void wc_lookup_exec_apply_writeback_outputs(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int auth,
    int need_redir_eval,
    char* ref,
    int ref_explicit,
    int ref_port,
    int header_non_authoritative,
    int allow_cycle_on_loop,
    int need_redir,
    int force_stop_authoritative,
    int apnic_erx_suppress_current) {
    if (!ctx) return;

    wc_lookup_exec_update_redirect_outputs_step(
        ctx,
        header_non_authoritative,
        allow_cycle_on_loop,
        need_redir,
        force_stop_authoritative,
        apnic_erx_suppress_current);

    wc_lookup_exec_update_core_flags_outputs(
        ctx,
        auth,
        need_redir_eval);
    wc_lookup_exec_update_core_ref_outputs(
        ctx,
        ref,
        ref_explicit,
        ref_port);
}

static void wc_lookup_exec_writeback_results(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* body,
    int auth,
    int need_redir_eval,
    char* ref,
    int ref_explicit,
    int ref_port,
    int header_non_authoritative,
    int allow_cycle_on_loop,
    int need_redir,
    int force_stop_authoritative,
    int apnic_erx_suppress_current) {
    if (!ctx) return;

    wc_lookup_exec_apply_writeback_state(
        ctx,
        body,
        auth,
        need_redir_eval,
        ref);
    wc_lookup_exec_apply_writeback_outputs(
        ctx,
        auth,
        need_redir_eval,
        ref,
        ref_explicit,
        ref_port,
        header_non_authoritative,
        allow_cycle_on_loop,
        need_redir,
        force_stop_authoritative,
        apnic_erx_suppress_current);
}

static void wc_lookup_exec_writeback_with_need_redirect(
    struct wc_lookup_exec_redirect_ctx* ctx,
    char* body,
    int auth,
    int need_redir_eval,
    char* ref,
    int ref_explicit,
    int ref_port,
    int header_non_authoritative,
    int allow_cycle_on_loop,
    int force_stop_authoritative,
    int apnic_erx_suppress_current) {
    if (!ctx) return;

    int need_redir = wc_lookup_exec_compute_need_redirect(ctx, need_redir_eval);
    wc_lookup_exec_writeback_results(
        ctx,
        body,
        auth,
        need_redir_eval,
        ref,
        ref_explicit,
        ref_port,
        header_non_authoritative,
        allow_cycle_on_loop,
        need_redir,
        force_stop_authoritative,
        apnic_erx_suppress_current);
}

static void wc_lookup_exec_writeback_finalize_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int need_redir_eval,
    char* ref,
    int ref_explicit,
    int ref_port,
    int header_non_authoritative,
    int allow_cycle_on_loop,
    int force_stop_authoritative,
    int apnic_erx_suppress_current) {
    if (!ctx || !body) return;

    wc_lookup_exec_writeback_with_need_redirect(
        ctx,
        (char*)body,
        auth,
        need_redir_eval,
        ref,
        ref_explicit,
        ref_port,
        header_non_authoritative,
        allow_cycle_on_loop,
        force_stop_authoritative,
        apnic_erx_suppress_current);
}

static void wc_lookup_exec_finalize_flags_stage(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int* need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current) {
    if (!ctx || !body || !need_redir_eval || !allow_cycle_on_loop ||
        !force_stop_authoritative || !apnic_erx_suppress_current) {
        return;
    }

    wc_lookup_exec_finalize_redirect_flags(
        ctx,
        body,
        auth,
        header_non_authoritative,
        erx_marker_this_hop,
        need_redir_eval,
        allow_cycle_on_loop,
        force_stop_authoritative,
        apnic_erx_suppress_current);
}

static void wc_lookup_exec_finalize_writeback_stage(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int* need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current,
    char* ref,
    int ref_explicit,
    int ref_port) {
    if (!ctx || !body || !need_redir_eval || !allow_cycle_on_loop ||
        !force_stop_authoritative || !apnic_erx_suppress_current) {
        return;
    }

    wc_lookup_exec_writeback_finalize_step(
        ctx,
        body,
        auth,
        *need_redir_eval,
        ref,
        ref_explicit,
        ref_port,
        header_non_authoritative,
        *allow_cycle_on_loop,
        *force_stop_authoritative,
        *apnic_erx_suppress_current);
}

static void wc_lookup_exec_finalize_and_writeback(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* body,
    int auth,
    int header_non_authoritative,
    int erx_marker_this_hop,
    int* need_redir_eval,
    int* allow_cycle_on_loop,
    int* force_stop_authoritative,
    int* apnic_erx_suppress_current,
    char* ref,
    int ref_explicit,
    int ref_port) {
    if (!ctx || !body || !need_redir_eval || !allow_cycle_on_loop ||
        !force_stop_authoritative || !apnic_erx_suppress_current) {
        return;
    }

    wc_lookup_exec_finalize_flags_stage(
        ctx,
        body,
        auth,
        header_non_authoritative,
        erx_marker_this_hop,
        need_redir_eval,
        allow_cycle_on_loop,
        force_stop_authoritative,
        apnic_erx_suppress_current);

    wc_lookup_exec_finalize_writeback_stage(
        ctx,
        body,
        auth,
        header_non_authoritative,
        need_redir_eval,
        allow_cycle_on_loop,
        force_stop_authoritative,
        apnic_erx_suppress_current,
        ref,
        ref_explicit,
        ref_port);
}

static void wc_lookup_exec_apply_post_apnic_logic(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    const struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !header_state || !header_state->host) {
        return;
    }
    wc_lookup_exec_apply_apnic_erx_logic_step(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_apply_apnic_erx_logic_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    const struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !header_state || !header_state->host) {
        return;
    }

    wc_lookup_exec_handle_apnic_erx_logic(
        ctx,
        st->io.body,
        header_state->host,
        header_state->is_iana,
        st->redirect.header_non_authoritative,
        st->io.auth,
        header_state->erx_marker_this_hop,
        st->io.ripe_non_managed,
        &st->io.need_redir_eval,
        &st->io.ref,
        &st->io.ref_explicit);
}

static void wc_lookup_exec_finish_post_apnic(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    const struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !header_state) {
        return;
    }

    wc_lookup_exec_finalize_and_writeback(
        ctx,
        st->io.body,
        st->io.auth,
        st->redirect.header_non_authoritative,
        header_state->erx_marker_this_hop,
        &st->io.need_redir_eval,
        &st->redirect.allow_cycle_on_loop,
        &st->redirect.force_stop_authoritative,
        &st->redirect.apnic_erx_suppress_current,
        st->io.ref,
        st->io.ref_explicit,
        st->io.ref_port);
}

static void wc_lookup_exec_run_post_apnic_stage(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    const struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !st->io.body || !header_state || !header_state->host) {
        return;
    }

    wc_lookup_exec_apply_post_apnic_logic(
        ctx,
        st,
        header_state);

    wc_lookup_exec_finish_post_apnic(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_prepare_eval_io(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st) return;

    wc_lookup_exec_prepare_local_state(
        ctx,
        &st->io.body,
        &st->io.auth,
        &st->io.need_redir_eval,
        &st->io.ref,
        &st->io.ref_explicit,
        &st->io.ref_port,
        &st->io.ripe_non_managed);
}

static void wc_lookup_exec_prepare_eval_hint(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st) return;

    wc_lookup_exec_prepare_header_hint(
        ctx,
        st->hint.header_hint_host_buf,
        sizeof(st->hint.header_hint_host_buf),
        &st->hint.header_hint_host,
        &st->hint.header_hint_host_len);
}

static void wc_lookup_exec_prepare_eval_redirect(
    struct wc_lookup_exec_eval_state* st) {
    if (!st) return;

    wc_lookup_exec_init_redirect_state(
        &st->redirect.header_non_authoritative,
        &st->redirect.allow_cycle_on_loop,
        &st->redirect.need_redir,
        &st->redirect.force_stop_authoritative,
        &st->redirect.apnic_erx_suppress_current);
}

static void wc_lookup_exec_prepare_eval_state(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st) {
        return;
    }

    wc_lookup_exec_prepare_eval_io_step(ctx, st);
    wc_lookup_exec_prepare_eval_hint_step(ctx, st);
    wc_lookup_exec_prepare_eval_redirect_step(st);
}

static void wc_lookup_exec_prepare_eval_io_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st) return;

    wc_lookup_exec_prepare_eval_io(ctx, st);
}

static void wc_lookup_exec_prepare_eval_hint_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st) return;

    wc_lookup_exec_prepare_eval_hint(ctx, st);
}

static void wc_lookup_exec_prepare_eval_redirect_step(
    struct wc_lookup_exec_eval_state* st) {
    if (!st) return;

    wc_lookup_exec_prepare_eval_redirect(st);
}

static void wc_lookup_exec_run_eval_flow(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st,
    struct wc_lookup_exec_header_state* header_state) {
    if (!ctx || !st || !header_state) return;

    wc_lookup_exec_run_pre_apnic_stage(
        ctx,
        st,
        header_state);

    wc_lookup_exec_run_post_apnic_stage(
        ctx,
        st,
        header_state);
}

static void wc_lookup_exec_run_eval_stages(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st || !st->io.body || !st->hint.header_hint_host || !st->io.ref) {
        return;
    }

    struct wc_lookup_exec_header_state header_state = {0};
    wc_lookup_exec_run_eval_flow(
        ctx,
        st,
        &header_state);
}

static int wc_lookup_exec_is_eval_ready(const struct wc_lookup_exec_redirect_ctx* ctx) {
    return (ctx && ctx->body && ctx->auth && ctx->need_redir_eval) ? 1 : 0;
}

static void wc_lookup_exec_init_eval_state(struct wc_lookup_exec_eval_state* st) {
    if (!st) return;

    *st = (struct wc_lookup_exec_eval_state){0};
}

static void wc_lookup_exec_run_eval(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st) return;

    wc_lookup_exec_prepare_eval_state(ctx, st);
    wc_lookup_exec_run_eval_stages(ctx, st);
}

void wc_lookup_exec_eval_redirect(struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!wc_lookup_exec_is_eval_ready(ctx)) return;

    struct wc_lookup_exec_eval_state st;
    wc_lookup_exec_init_eval_state(&st);
    wc_lookup_exec_run_eval(ctx, &st);
}
