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
#include "lookup_exec_rules.h"

// local strdup to avoid feature-macro dependency differences across toolchains
static char* xstrdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

static void wc_lookup_exec_set_apnic_redirect_reason_value(
    int* apnic_redirect_reason,
    int reason);

static void wc_lookup_exec_mark_seen_ripe_non_managed_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_mark_seen_afrinic_iana_blk_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

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

static void wc_lookup_exec_apply_non_auth_cycle_outputs_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

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

static void wc_lookup_exec_mark_apnic_erx_legacy_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_mark_apnic_erx_root_writeback_step(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_write_apnic_erx_root_host_literal_if_empty_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* host_literal);

static void wc_lookup_exec_mark_apnic_erx_legacy_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return;

    if (ctx->apnic_erx_legacy) {
        *ctx->apnic_erx_legacy = 1;
    }
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

    int header_erx_hint = 0;
    const char* implicit_host = NULL;
    header_erx_hint = body &&
        (wc_lookup_body_contains_erx_legacy(body) ||
         wc_lookup_body_contains_erx_netname(body) ||
         wc_lookup_body_contains_apnic_erx_hint(body));
    implicit_host =
        (header_host && !header_is_iana && !header_matches_current)
            ? header_host
            : "whois.apnic.net";
    if (header_erx_hint && strcasecmp(implicit_host, "whois.apnic.net") == 0) {
        if (*ref && !ref_explicit) {
            free(*ref);
            *ref = NULL;
        }
        if (!*ref) {
            if (ctx->visited && ctx->visited_count &&
                !wc_lookup_visited_has(ctx->visited, *ctx->visited_count, "whois.apnic.net") &&
                *ctx->visited_count < 16) {
                ctx->visited[(*ctx->visited_count)++] = xstrdup("whois.apnic.net");
            }
            wc_lookup_exec_mark_apnic_erx_legacy_output_step(ctx);
            if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
                wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
                wc_lookup_exec_set_apnic_redirect_reason_value(
                    ctx->apnic_redirect_reason,
                    1);
                wc_lookup_exec_write_apnic_erx_root_host_literal_if_empty_step(
                    ctx,
                    "whois.apnic.net");
            }
            *need_redir_eval = 1;
        }
    }
    if (header_host && !header_is_iana && !header_matches_current) {
        const char* header_rir = wc_guess_rir(header_host);
        if (header_rir && strcasecmp(header_rir, "unknown") != 0) {
            if (wc_normalize_whois_host(header_host, header_hint_host, header_hint_host_len) != 0) {
                snprintf(header_hint_host, header_hint_host_len, "%s", header_host);
            }
            if (ctx->header_hint_valid) {
                *ctx->header_hint_valid = (header_hint_host[0] != '\0');
            }
            *need_redir_eval = 1;

            if (strcasecmp(header_rir, "apnic") == 0 ||
                strcasecmp(header_rir, "ripe") == 0 ||
                strcasecmp(header_rir, "afrinic") == 0) {
                int non_auth_internal = 0;
                if (strcasecmp(header_rir, "apnic") == 0) {
                    if (wc_lookup_body_contains_apnic_iana_netblock(body) ||
                        wc_lookup_body_contains_erx_legacy(body)) {
                        non_auth_internal = 1;
                    }
                } else if (strcasecmp(header_rir, "ripe") == 0) {
                    if (wc_lookup_body_contains_ripe_non_managed(body)) {
                        wc_lookup_exec_mark_seen_ripe_non_managed_output_step(ctx);
                        non_auth_internal = 1;
                    }
                } else if (strcasecmp(header_rir, "afrinic") == 0) {
                    if (wc_lookup_body_contains_full_ipv4_space(body)) {
                        wc_lookup_exec_mark_seen_afrinic_iana_blk_output_step(ctx);
                        non_auth_internal = 1;
                    }
                }
                if (ctx->access_denied && ctx->hops == 0) {
                    non_auth_internal = 1;
                    wc_lookup_exec_apply_non_auth_cycle_outputs_step(ctx);
                }
                if (!non_auth_internal) {
                    if (*ctx->auth && !wc_lookup_body_has_strong_redirect_hint(body)) {
                        if (ctx->stop_with_header_authority) {
                            *ctx->stop_with_header_authority = 1;
                        }
                        if (ctx->header_authority_host && ctx->header_authority_host_len > 0) {
                            snprintf(ctx->header_authority_host,
                                ctx->header_authority_host_len,
                                "%s",
                                header_hint_host);
                        }
                    }
                } else {
                    wc_lookup_exec_apply_non_auth_cycle_outputs_step(ctx);
                }
                if (!ctx->access_denied && ctx->visited && ctx->visited_count &&
                    !wc_lookup_visited_has(ctx->visited, *ctx->visited_count, header_hint_host) &&
                    *ctx->visited_count < 16) {
                    ctx->visited[(*ctx->visited_count)++] = xstrdup(header_hint_host);
                }
            }
        }
    }
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
static void wc_lookup_exec_update_apnic_root_if_needed(
    struct wc_lookup_exec_redirect_ctx* ctx);
static void wc_lookup_exec_mark_header_non_auth(int* header_non_authoritative);
static void wc_lookup_exec_set_apnic_redirect_reason_value(
    int* apnic_redirect_reason,
    int reason);
static int wc_lookup_exec_is_ipv6_root(const char* body);
static int wc_lookup_exec_is_apnic_netblock(const char* body);
static int wc_lookup_exec_is_full_ipv4_space(const char* body);
static int wc_lookup_exec_is_lacnic_unallocated(const char* body);
static int wc_lookup_exec_is_lacnic_rate_limited(const char* body);
static int wc_lookup_exec_is_current_rir_lacnic(
    const struct wc_lookup_exec_redirect_ctx* ctx);
struct wc_lookup_exec_eval_state;
struct wc_lookup_exec_header_state;
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
static void wc_lookup_exec_set_apnic_redirect_reason(
    struct wc_lookup_exec_redirect_ctx* ctx,
    int reason);
static void wc_lookup_exec_write_apnic_erx_root_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* apnic_root);
static void wc_lookup_exec_write_apnic_erx_root_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

static const char* wc_lookup_exec_get_effective_current_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx) return NULL;

    if (ctx->current_rir_guess && *ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "unknown") != 0) {
        return ctx->current_rir_guess;
    }

    if (!ctx->current_host || !*ctx->current_host) {
        return ctx->current_rir_guess;
    }

    const char* host_for_guess = ctx->current_host;
    if (wc_dns_is_ip_literal(host_for_guess)) {
        const char* mapped = wc_lookup_known_ip_host_from_literal(host_for_guess);
        if (mapped && *mapped) {
            host_for_guess = mapped;
        }
    }

    const char* canon = wc_dns_canonical_alias(host_for_guess);
    if (canon && *canon) {
        host_for_guess = canon;
    }

    const char* rir = wc_guess_rir(host_for_guess);
    if (rir && *rir && strcasecmp(rir, "unknown") != 0) {
        return rir;
    }

    return ctx->current_rir_guess;
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

static void wc_lookup_exec_write_last_failure_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

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
        if (ctx->last_failure_ip && ctx->last_failure_ip_len > 0 &&
            (!ctx->last_failure_ip[0])) {
            const char* ip = NULL;
            if (!access_denied_internal && ctx->ni && ctx->ni->ip[0]) {
                ip = ctx->ni->ip;
            } else {
                const char* known_ip = wc_dns_get_known_ip(err_host);
                ip = (known_ip && known_ip[0]) ? known_ip : NULL;
            }
            wc_lookup_exec_write_last_failure_ip_output_step(ctx, ip);
        }
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

static void wc_lookup_exec_remove_current_from_visited(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->visited || !ctx->visited_count) return;

    wc_lookup_visited_remove(ctx->visited, ctx->visited_count, ctx->current_host);

    if (wc_dns_is_ip_literal(ctx->current_host)) {
        const char* mapped_host = wc_lookup_known_ip_host_from_literal(ctx->current_host);
        if (mapped_host && *mapped_host) {
            wc_lookup_visited_remove(ctx->visited, ctx->visited_count, mapped_host);
        }
    }

    const char* canon_visit = wc_dns_canonical_alias(ctx->current_host);
    if (canon_visit && *canon_visit) {
        wc_lookup_visited_remove(ctx->visited, ctx->visited_count, canon_visit);
    }
}

static void wc_lookup_exec_mark_header_non_auth(int* header_non_authoritative) {
    if (!header_non_authoritative) return;

    *header_non_authoritative = 1;
}

static int wc_lookup_exec_is_effective_current_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* rir_name) {
    if (!ctx || !rir_name || !*rir_name) return 0;
    const char* rir = wc_lookup_exec_get_effective_current_rir(ctx);
    return (rir && strcasecmp(rir, rir_name) == 0) ? 1 : 0;
}

static int wc_lookup_exec_is_header_rir(
    const char* header_host,
    const char* rir_name) {
    if (!header_host || !*header_host || !rir_name || !*rir_name) return 0;
    const char* canon = wc_dns_canonical_alias(header_host);
    const char* host_for_guess = (canon && *canon) ? canon : header_host;
    const char* rir = wc_guess_rir(host_for_guess);
    return (rir && *rir && strcasecmp(rir, rir_name) == 0) ? 1 : 0;
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

static void wc_lookup_exec_write_apnic_erx_root_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* apnic_root);
static void wc_lookup_exec_write_apnic_erx_root_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

static void wc_lookup_exec_write_apnic_erx_root_host_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* apnic_root) {
    if (!ctx || !apnic_root) return;

    snprintf(ctx->apnic_erx_root_host, ctx->apnic_erx_root_host_len, "%s", apnic_root);
}

static void wc_lookup_exec_write_apnic_erx_root_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip) {
    if (!ctx || !ip || !*ip) return;

    snprintf(ctx->apnic_erx_root_ip, ctx->apnic_erx_root_ip_len, "%s", ip);
}

static void wc_lookup_exec_mark_seen_apnic_iana_netblock_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx);

static void wc_lookup_exec_mark_seen_apnic_iana_netblock_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->seen_apnic_iana_netblock) return;

    *ctx->seen_apnic_iana_netblock = 1;
}

static int wc_lookup_exec_is_apnic_netblock(const char* body) {
    return body && wc_lookup_body_contains_apnic_iana_netblock(body);
}

static int wc_lookup_exec_is_current_rir_ripe(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    const char* rir = wc_lookup_exec_get_effective_current_rir(ctx);
    return rir && strcasecmp(rir, "ripe") == 0;
}

static int wc_lookup_exec_is_ipv6_root(const char* body) {
    return body && wc_lookup_body_contains_ipv6_root(body);
}

static int wc_lookup_exec_is_current_rir_afrinic(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    const char* rir = wc_lookup_exec_get_effective_current_rir(ctx);
    return rir && strcasecmp(rir, "afrinic") == 0;
}

static int wc_lookup_exec_is_arin_no_match(const char* body) {
    return body && wc_lookup_body_contains_no_match(body);
}

static int wc_lookup_exec_is_current_rir_arin(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    const char* rir = wc_lookup_exec_get_effective_current_rir(ctx);
    return rir && strcasecmp(rir, "arin") == 0;
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
        if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
            ctx->apnic_erx_root_host[0] == '\0') {
            const char* apnic_root = wc_dns_canonical_alias(ctx->current_host);
            wc_lookup_exec_write_apnic_erx_root_host_output_step(
                ctx,
                apnic_root ? apnic_root : ctx->current_host);
        }
        if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip_len > 0 &&
            ctx->apnic_erx_root_ip[0] == '\0' && ctx->ni && ctx->ni->ip[0]) {
            wc_lookup_exec_write_apnic_erx_root_ip_output_step(ctx, ctx->ni->ip);
        }
    }
}

static int wc_lookup_exec_is_full_ipv4_space(const char* body) {
    return body && wc_lookup_body_contains_full_ipv4_space(body);
}

static int wc_lookup_exec_is_lacnic_unallocated(const char* body) {
    return body && wc_lookup_body_contains_lacnic_unallocated(body);
}

static int wc_lookup_exec_is_current_rir_lacnic(
    const struct wc_lookup_exec_redirect_ctx* ctx) {
    const char* rir = wc_lookup_exec_get_effective_current_rir(ctx);
    return rir && strcasecmp(rir, "lacnic") == 0;
}

static int wc_lookup_exec_is_lacnic_rate_limited(const char* body) {
    return body && wc_lookup_body_contains_lacnic_rate_limit(body);
}

static void wc_lookup_exec_write_erx_marker_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip);

static void wc_lookup_exec_write_erx_marker_ip_output_step(
    struct wc_lookup_exec_redirect_ctx* ctx,
    const char* ip) {
    if (!ctx || !ip || !*ip) return;

    snprintf(ctx->erx_marker_ip, ctx->erx_marker_ip_len, "%s", ip);
}

static void wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(
    int* need_redir_eval,
    char** ref);

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

    const char* erx_marker_host_local = ctx ? ctx->current_host : NULL;
    if (wc_lookup_exec_is_current_rir_lacnic(ctx)) {
        if (header_hint_host && header_hint_host[0])
            erx_marker_host_local = header_hint_host;
        else
            erx_marker_host_local = header_host;
    }
    *erx_marker_this_hop = wc_lookup_body_contains_erx_iana_marker(body);

    if (*erx_marker_this_hop) {
        *header_non_authoritative = 1;
        *need_redir_eval = 1;
        if (ctx->erx_marker_seen && ctx->erx_marker_host && ctx->erx_marker_ip &&
            ctx->erx_marker_host_len > 0 && ctx->erx_marker_ip_len > 0 &&
            !*ctx->erx_marker_seen) {
            *ctx->erx_marker_seen = 1;
            snprintf(ctx->erx_marker_host, ctx->erx_marker_host_len, "%s", erx_marker_host_local);

            if (erx_marker_host_local && ctx->erx_marker_ip && ctx->erx_marker_ip_len > 0) {
                const char* ip = NULL;
                if (strcasecmp(erx_marker_host_local, ctx->current_host) == 0) {
                    if (ctx->ni && ctx->ni->ip[0]) {
                        ip = ctx->ni->ip;
                    }
                } else {
                    const char* known_ip = wc_dns_get_known_ip(erx_marker_host_local);
                    if (known_ip && known_ip[0]) {
                        ip = known_ip;
                    }
                }
                wc_lookup_exec_write_erx_marker_ip_output_step(ctx, ip);
            }
        }
    }

    if (ctx && *erx_marker_this_hop && ctx->query_is_cidr && ctx->cidr_base_query &&
        ctx->erx_fast_recheck_done && !*ctx->erx_fast_recheck_done &&
        !wc_lookup_erx_baseline_recheck_guard_get() &&
        (!ctx->cfg || ctx->cfg->cidr_erx_recheck)) {
        struct wc_lookup_opts recheck_opts;
        struct wc_query recheck_q;

        if (ctx->cfg && ctx->cfg->batch_interval_ms > 0) {
            int delay_ms = ctx->cfg->batch_interval_ms;
            struct timespec ts;
            ts.tv_sec = (time_t)(delay_ms / 1000);
            ts.tv_nsec = (long)((delay_ms % 1000) * 1000000L);
            nanosleep(&ts, NULL);
        }
        recheck_opts = *ctx->zopts;
        recheck_q = (struct wc_query){
            .raw = ctx->cidr_base_query,
            .start_server = erx_marker_host_local,
            .port = ctx->current_port
        };
        recheck_opts.no_redirect = 0;
        if (recheck_opts.max_hops < 6) {
            recheck_opts.max_hops = 6;
        }
        recheck_opts.net_ctx = ctx->net_ctx;
        recheck_opts.config = ctx->cfg;

        wc_lookup_erx_baseline_recheck_guard_set(1);
        if (ctx->erx_baseline_recheck_attempted) {
            *ctx->erx_baseline_recheck_attempted = 1;
        }
        *ctx->erx_fast_recheck_done = 1;

        if (ctx->cfg && ctx->cfg->debug) {
            fprintf(stderr,
                "[DEBUG] ERX fast recheck: query=%s host=%s\n",
                ctx->cidr_base_query,
                erx_marker_host_local);
        }

        struct wc_result recheck_res;
        int recheck_rc = wc_lookup_execute(&recheck_q, &recheck_opts, &recheck_res);
        wc_lookup_erx_baseline_recheck_guard_set(0);

        if (recheck_rc == 0) {
            int recheck_erx = (recheck_res.body && recheck_res.body[0])
                ? wc_lookup_body_contains_erx_iana_marker(recheck_res.body)
                : 0;
            int recheck_non_auth = (recheck_res.body && recheck_res.body[0])
                ? wc_lookup_body_has_strong_redirect_hint(recheck_res.body)
                : 0;
            int recheck_authority_known =
                (recheck_res.meta.authoritative_host[0] &&
                 strcasecmp(recheck_res.meta.authoritative_host, "unknown") != 0 &&
                 strcasecmp(recheck_res.meta.authoritative_host, "error") != 0) ? 1 : 0;
            if (ctx->cfg && ctx->cfg->debug) {
                fprintf(stderr,
                    "[DEBUG] ERX fast recheck result: erx=%d non_auth=%d auth_host=%s\n",
                    recheck_erx,
                    recheck_non_auth,
                    recheck_authority_known ? recheck_res.meta.authoritative_host : "unknown");
            }

            if (wc_lookup_exec_rule_should_promote_fast_authoritative(
                recheck_authority_known,
                recheck_non_auth,
                recheck_res.meta.authoritative_host)) {
                if (ctx->erx_fast_authoritative_host && ctx->erx_fast_authoritative_host_len > 0) {
                    const char* host_value = NULL;
                    if (recheck_res.meta.authoritative_host[0] &&
                        strcasecmp(recheck_res.meta.authoritative_host, "unknown") != 0 &&
                        strcasecmp(recheck_res.meta.authoritative_host, "error") != 0) {
                        host_value = recheck_res.meta.authoritative_host;
                    } else {
                        const char* canon_host = wc_dns_canonical_alias(erx_marker_host_local);
                        host_value = canon_host ? canon_host : erx_marker_host_local;
                    }
                    snprintf(ctx->erx_fast_authoritative_host,
                        ctx->erx_fast_authoritative_host_len,
                        "%s",
                        host_value);
                }

                if (ctx->erx_fast_authoritative_ip && ctx->erx_fast_authoritative_ip_len > 0) {
                    const char* ip_value = "unknown";
                    if (recheck_res.meta.authoritative_ip[0] &&
                        strcasecmp(recheck_res.meta.authoritative_ip, "unknown") != 0) {
                        ip_value = recheck_res.meta.authoritative_ip;
                    } else if (recheck_res.meta.last_ip[0]) {
                        ip_value = recheck_res.meta.last_ip;
                    } else {
                        const char* known_ip = wc_dns_get_known_ip(erx_marker_host_local);
                        if (known_ip && known_ip[0]) {
                            ip_value = known_ip;
                        }
                    }

                    snprintf(ctx->erx_fast_authoritative_ip,
                        ctx->erx_fast_authoritative_ip_len,
                        "%s",
                        (ip_value && ip_value[0]) ? ip_value : "unknown");
                }
                if (ctx->erx_fast_authoritative) {
                    *ctx->erx_fast_authoritative = 1;
                }

                *header_non_authoritative = 0;
                wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
                *auth = 1;
            }
        } else {
            if (ctx->cfg && ctx->cfg->debug) {
                fprintf(stderr,
                    "[DEBUG] ERX fast recheck failed: rc=%d\n",
                    recheck_rc);
            }
        }
        wc_lookup_result_free(&recheck_res);
    } else if (ctx && *erx_marker_this_hop && ctx->query_is_cidr && ctx->cidr_base_query &&
               ctx->erx_fast_recheck_done && !*ctx->erx_fast_recheck_done && ctx->cfg &&
               !ctx->cfg->cidr_erx_recheck && ctx->cfg->debug) {
        fprintf(stderr,
            "[ERX-RECHECK] action=skip reason=disabled query=%s host=%s\n",
            ctx->cidr_base_query,
            erx_marker_host_local);
    }
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

    int header_authoritative_stop =
        (ctx && header_host && ctx->current_host && header_host[0] && ctx->current_host[0] &&
         auth && !header_non_authoritative &&
         strcasecmp(header_host, ctx->current_host) == 0) ? 1 : 0;
    if (ctx && header_host && strcasecmp(header_host, "whois.apnic.net") == 0 &&
        ctx->ni && ctx->ni->ip[0] &&
        ctx->apnic_last_ip && ctx->apnic_last_ip_len > 0) {
        snprintf(ctx->apnic_last_ip, ctx->apnic_last_ip_len, "%s", ctx->ni->ip);
    }
    if (header_host && *ref && !header_is_iana && !*ref_explicit) {
        char ref_norm2[128];
        const char* header_norm = wc_dns_canonical_alias(header_host);
        header_norm = header_norm ? header_norm : header_host;
        if (wc_normalize_whois_host(ctx->ref_host, ref_norm2, sizeof(ref_norm2)) != 0) {
            snprintf(ref_norm2, sizeof(ref_norm2), "%s", ctx->ref_host);
        }
        if (strcasecmp(ref_norm2, header_norm) == 0) {
            wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
        }
    }

    if (header_authoritative_stop && *ref && !*ref_explicit &&
        (!ctx->apnic_erx_keep_ref || !*ctx->apnic_erx_keep_ref)) {
        const char* ref_rir = wc_guess_rir(ctx->ref_host);
        if (ref_rir && ctx->current_rir_guess &&
            strcasecmp(ref_rir, ctx->current_rir_guess) != 0) {
            *ref_explicit = 1;
        } else {
            free(*ref);
            *ref = NULL;
        }
    }

    if (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
        ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1 &&
        header_authoritative_stop) {
        if (ctx->apnic_erx_authoritative_stop) {
            *ctx->apnic_erx_authoritative_stop = 1;
        }
        *need_redir_eval = 0;
        if (*ref && !*ref_explicit &&
            !(ctx->apnic_erx_keep_ref && *ctx->apnic_erx_keep_ref)) {
            free(*ref);
            *ref = NULL;
        }
    }

    int apnic_transfer_to_apnic = (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
            wc_lookup_body_contains_apnic_transfer_to_apnic(body)) ? 1 : 0;
    if (apnic_transfer_to_apnic) {
        wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
    }

    int erx_netname = wc_lookup_body_contains_erx_netname(body);
    if (auth && erx_netname && header_host && !header_is_iana &&
        !(*ref && *ref_explicit)) {
        wc_lookup_exec_cancel_need_redir_eval_and_clear_ref_step(need_redir_eval, ref);
    }

    if (!ctx->apnic_redirect_reason || *ctx->apnic_redirect_reason == 0) {
        if ((!ctx->apnic_iana_netblock_cidr || !*ctx->apnic_iana_netblock_cidr) &&
            *need_redir_eval && auth && !*ref &&
            wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
            wc_lookup_exec_rule_allow_apnic_hint_strict(body)) {
            *need_redir_eval = 0;
        }
    }

    {
        int base_guard = (auth && header_host && !header_is_iana && !*ref) ? 1 : 0;
        int header_matches_current_host = 0;
        if (ctx && header_host) {
            char header_norm3[128];
            char current_norm3[128];
            const char* header_normp = wc_dns_canonical_alias(header_host);
            header_normp = header_normp ? header_normp : header_host;
            const char* current_normp = wc_dns_canonical_alias(ctx->current_host);
            current_normp = current_normp ? current_normp : ctx->current_host;
            if (wc_normalize_whois_host(header_normp, header_norm3, sizeof(header_norm3)) != 0) {
                snprintf(header_norm3, sizeof(header_norm3), "%s", header_normp);
            }
            if (wc_normalize_whois_host(current_normp, current_norm3, sizeof(current_norm3)) != 0) {
                snprintf(current_norm3, sizeof(current_norm3), "%s", current_normp);
            }
            header_matches_current_host =
                (strcasecmp(header_norm3, current_norm3) == 0) ? 1 : 0;
        }
        if (base_guard && !*need_redir_eval) {
            *need_redir_eval = 0;
        }

        if (base_guard && *need_redir_eval &&
            !wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
            header_matches_current_host &&
            !header_non_authoritative &&
            !wc_lookup_body_has_strong_redirect_hint(body)) {
            *need_redir_eval = 0;
        }
    }

    if (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") && !apnic_transfer_to_apnic) {
        if (ctx->apnic_erx_legacy) {
            *ctx->apnic_erx_legacy = wc_lookup_body_contains_erx_legacy(body);
        }
        if (ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy &&
            ctx->apnic_iana_netblock_cidr && !*ctx->apnic_iana_netblock_cidr &&
            !(ctx->erx_fast_authoritative && *ctx->erx_fast_authoritative)) {
            *need_redir_eval = 1;
        }
    }

    if (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
        ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy) {
        if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
            wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
            wc_lookup_exec_set_apnic_redirect_reason(ctx, 1);
        }

        if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
            ctx->apnic_erx_root_host[0] == '\0') {
            const char* apnic_root = wc_dns_canonical_alias(ctx->current_host);
            wc_lookup_exec_write_apnic_erx_root_host_output_step(
                ctx,
                apnic_root ? apnic_root : ctx->current_host);
        }

        if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip_len > 0 &&
            ctx->apnic_erx_root_ip[0] == '\0' && ctx->ni && ctx->ni->ip[0]) {
            wc_lookup_exec_write_apnic_erx_root_ip_output_step(ctx, ctx->ni->ip);
        }
    }
    if (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
        ctx->ni && ctx->ni->ip[0] && ctx->apnic_last_ip && ctx->apnic_last_ip_len > 0) {
        snprintf(ctx->apnic_last_ip, ctx->apnic_last_ip_len, "%s", ctx->ni->ip);
    }
    if (*need_redir_eval &&
        ctx->current_rir_guess &&
        ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy) {
        if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
            wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
        }
    }

    if (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
        ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1 &&
        ctx->apnic_erx_target_rir && ctx->apnic_erx_target_rir[0] &&
        wc_lookup_exec_is_effective_current_rir(ctx, ctx->apnic_erx_target_rir) &&
        strcasecmp(ctx->apnic_erx_target_rir, "apnic") != 0 &&
        !(strcasecmp(ctx->apnic_erx_target_rir, "ripe") == 0 && ripe_non_managed)) {
        if (ctx->apnic_erx_stop) {
            *ctx->apnic_erx_stop = 1;
        }
        if (ctx->apnic_erx_stop_unknown) {
            *ctx->apnic_erx_stop_unknown = 0;
        }
        if (ctx->apnic_erx_stop_host && ctx->apnic_erx_stop_host_len > 0) {
            snprintf(ctx->apnic_erx_stop_host,
                ctx->apnic_erx_stop_host_len,
                "%s",
                ctx->current_host ? ctx->current_host : "");
        }
    }

    if (!apnic_transfer_to_apnic && wc_lookup_body_contains_full_ipv4_space(body)) {
        *need_redir_eval = 1;
        wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
    }
    if (apnic_transfer_to_apnic) {
        *need_redir_eval = 0;
    }

    if (*need_redir_eval && auth && !*ref &&
        wc_lookup_exec_is_effective_current_rir(ctx, "apnic")) {
        if (!(erx_marker_this_hop &&
              !(ctx->erx_fast_authoritative && *ctx->erx_fast_authoritative)) &&
            (ctx->erx_fast_authoritative && *ctx->erx_fast_authoritative)) {
            *need_redir_eval = 0;
        }
    }
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

static void wc_lookup_exec_run_eval(
    struct wc_lookup_exec_redirect_ctx* ctx,
    struct wc_lookup_exec_eval_state* st) {
    if (!ctx || !st) return;

    st->io.body = ctx->body;
    st->io.auth = ctx->auth ? *ctx->auth : 0;
    st->io.need_redir_eval = ctx->need_redir_eval ? *ctx->need_redir_eval : 0;
    st->io.ref = (ctx->ref && *ctx->ref) ? *ctx->ref : NULL;
    st->io.ref_explicit = ctx->ref_explicit ? *ctx->ref_explicit : 0;
    st->io.ref_port = ctx->ref_port ? *ctx->ref_port : 0;
    st->io.ripe_non_managed = ctx->ripe_non_managed;

    st->hint.header_hint_host =
        ctx->header_hint_host ? ctx->header_hint_host : st->hint.header_hint_host_buf;
    st->hint.header_hint_host_len =
        ctx->header_hint_host_len ? ctx->header_hint_host_len : sizeof(st->hint.header_hint_host_buf);
    if (st->hint.header_hint_host && st->hint.header_hint_host_len > 0) {
        st->hint.header_hint_host[0] = '\0';
    }
    if (ctx->header_hint_valid) {
        *ctx->header_hint_valid = 0;
    }

    st->redirect.header_non_authoritative = 0;
    st->redirect.allow_cycle_on_loop = 0;
    st->redirect.need_redir = 0;
    st->redirect.force_stop_authoritative = 0;
    st->redirect.apnic_erx_suppress_current = 0;

    if (!st->io.body || !st->hint.header_hint_host) {
        return;
    }

    struct wc_lookup_exec_header_state header_state = {0};
    {
        int banner_only = 0;
        header_state.host = NULL;
        header_state.is_iana = 0;
        header_state.matches_current = 0;

        banner_only = (!st->io.auth && st->io.body && *st->io.body &&
                       wc_lookup_body_is_comment_only(st->io.body));
        header_state.host = wc_lookup_detect_rir_header_host(st->io.body);
        header_state.is_iana =
            (header_state.host && strcasecmp(header_state.host, "whois.iana.org") == 0);

        if (ctx->header_host) {
            *ctx->header_host = header_state.host;
        }
        if (ctx->header_is_iana) {
            *ctx->header_is_iana = header_state.is_iana;
        }

        if (!header_state.host || header_state.is_iana) {
            header_state.matches_current = 0;
        } else {
            char header_normh[128];
            char current_normh[128];
            const char* header_normp = wc_dns_canonical_alias(header_state.host);
            const char* current_normp = wc_dns_canonical_alias(ctx->current_host);
            if (!header_normp) header_normp = header_state.host;
            if (!current_normp) current_normp = ctx->current_host;
            if (wc_normalize_whois_host(header_normp, header_normh, sizeof(header_normh)) != 0) {
                snprintf(header_normh, sizeof(header_normh), "%s", header_normp);
            }
            if (wc_normalize_whois_host(current_normp, current_normh, sizeof(current_normh)) != 0) {
                snprintf(current_normh, sizeof(current_normh), "%s", current_normp);
            }
            header_state.matches_current = (strcasecmp(header_normh, current_normh) == 0) ? 1 : 0;
        }

        if (header_state.matches_current && !st->io.auth && !banner_only) {
            if (!(ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "arin") == 0)) {
                st->io.auth = 1;
            }
        }

        if (wc_lookup_exec_is_current_rir_lacnic(ctx)) {
            wc_lookup_exec_handle_lacnic_redirect_core(
                ctx,
                st->io.body,
                header_state.host,
                header_state.is_iana,
                header_state.matches_current,
                st->hint.header_hint_host,
                st->hint.header_hint_host_len,
                &st->io.ref,
                st->io.ref_explicit,
                &st->io.need_redir_eval);
        }
    }

    int first_hop_persistent_empty = 0;
    int access_denied_current = 0;
    int access_denied_internal = 0;
    int rate_limit_current = 0;
    if (ctx && st->io.body) {
        first_hop_persistent_empty = (ctx->persistent_empty && ctx->hops == 0) ? 1 : 0;
        access_denied_current =
            (ctx->access_denied && (!header_state.host || header_state.matches_current));
        access_denied_internal =
            (ctx->access_denied && header_state.host && !header_state.matches_current);
        rate_limit_current =
            (ctx->rate_limited && (!header_state.host || header_state.matches_current));

        wc_lookup_exec_log_access_denied_or_rate_limit(
            ctx,
            access_denied_current,
            access_denied_internal,
            rate_limit_current,
            header_state.host);
        wc_lookup_exec_record_access_failure(
            ctx,
            access_denied_current,
            access_denied_internal,
            rate_limit_current,
            header_state.host);
        wc_lookup_exec_filter_failure_body(
            ctx,
            &st->io.body,
            access_denied_current,
            access_denied_internal,
            rate_limit_current);
        wc_lookup_exec_mark_access_failure(
            ctx,
            access_denied_current,
            access_denied_internal,
            rate_limit_current);
    }

    if (st->io.body) {
        if (ctx->persistent_empty && ctx->current_rir_guess) {
            st->redirect.header_non_authoritative = 1;
            st->io.need_redir_eval = 1;
            if (first_hop_persistent_empty) {
                if (strcasecmp(ctx->current_rir_guess, "arin") == 0) {
                    wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
                }
                wc_lookup_exec_remove_current_from_visited(ctx);
            } else {
                wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
            }
        }

        {
            const char* current_rir = wc_lookup_exec_get_effective_current_rir(ctx);
            if ((current_rir && strcasecmp(current_rir, "apnic") == 0) ||
                wc_lookup_exec_is_header_rir(header_state.host, "apnic")) {
                int apnic_iana_netblock = wc_lookup_exec_is_apnic_netblock(st->io.body) ? 1 : 0;

                if (wc_lookup_exec_is_ipv6_root(st->io.body)) {
                    wc_lookup_exec_mark_non_auth(
                        &st->redirect.header_non_authoritative,
                        &st->io.need_redir_eval);
                }
                if (wc_lookup_body_contains_erx_legacy(st->io.body)) {
                    wc_lookup_exec_mark_non_auth(
                        &st->redirect.header_non_authoritative,
                        &st->io.need_redir_eval);
                }

                if (wc_lookup_exec_is_apnic_netblock(st->io.body)) {
                    wc_lookup_exec_mark_seen_apnic_iana_netblock_output_step(ctx);
                    wc_lookup_exec_update_apnic_root_if_needed(ctx);
                    wc_lookup_exec_set_apnic_redirect_reason(ctx, 2);
                }

                if (apnic_iana_netblock) {
                    wc_lookup_exec_mark_non_auth_and_cycle(
                        ctx,
                        &st->redirect.header_non_authoritative,
                        &st->io.need_redir_eval);
                }

                if (wc_lookup_exec_is_header_rir(header_state.host, "apnic") &&
                    wc_lookup_body_contains_erx_legacy(st->io.body)) {
                    if (ctx->apnic_erx_legacy) {
                        *ctx->apnic_erx_legacy = 1;
                    }
                    if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
                        wc_lookup_exec_mark_apnic_erx_root_writeback_step(ctx);
                        wc_lookup_exec_set_apnic_redirect_reason(ctx, 1);
                    }
                    if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
                        ctx->apnic_erx_root_host[0] == '\0') {
                        wc_lookup_exec_write_apnic_erx_root_host_output_step(
                            ctx,
                            "whois.apnic.net");
                    }
                    if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip_len > 0 &&
                        ctx->apnic_erx_root_ip[0] == '\0') {
                        const char* apnic_ip = wc_dns_get_known_ip("whois.apnic.net");
                        if (apnic_ip && apnic_ip[0]) {
                            wc_lookup_exec_write_apnic_erx_root_ip_output_step(ctx, apnic_ip);
                        }
                    }
                }
            }

            if (wc_lookup_exec_is_current_rir_ripe(ctx) ||
                wc_lookup_exec_is_header_rir(header_state.host, "ripe")) {
                if (wc_lookup_body_contains_ipv6_root(st->io.body) ||
                    wc_lookup_body_contains_ripe_access_denied(st->io.body) ||
                    wc_lookup_body_contains_ripe_non_managed(st->io.body)) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                    wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
                }
            }

            if (wc_lookup_exec_is_current_rir_afrinic(ctx) ||
                wc_lookup_exec_is_header_rir(header_state.host, "afrinic")) {
                if (wc_lookup_exec_is_ipv6_root(st->io.body) ||
                    wc_lookup_exec_is_full_ipv4_space(st->io.body)) {
                    wc_lookup_exec_mark_non_auth_and_cycle(
                        ctx,
                        &st->redirect.header_non_authoritative,
                        &st->io.need_redir_eval);
                }
            }

            if (wc_lookup_exec_is_current_rir_arin(ctx)) {
                int apnic_erx_legacy_chain =
                    (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
                     ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1) ? 1 : 0;
                int arin_erx_transferred_to_ripe =
                    (st->io.body && wc_lookup_find_case_insensitive(
                        st->io.body,
                        "early registrations, transferred to ripe ncc")) ? 1 : 0;

                if (wc_lookup_exec_is_arin_no_match(st->io.body) || !st->io.auth) {
                    wc_lookup_exec_mark_non_auth(
                        &st->redirect.header_non_authoritative,
                        &st->io.need_redir_eval);
                } else if (apnic_erx_legacy_chain && arin_erx_transferred_to_ripe) {
                    wc_lookup_exec_mark_non_auth_and_cycle(
                        ctx,
                        &st->redirect.header_non_authoritative,
                        &st->io.need_redir_eval);
                }
            }
        }
        if (ctx->current_rir_guess && ctx->hops == 0 &&
            (access_denied_current || rate_limit_current)) {
            wc_lookup_exec_mark_non_auth_and_cycle(
                ctx,
                &st->redirect.header_non_authoritative,
                &st->io.need_redir_eval);
            wc_lookup_exec_remove_current_from_visited(ctx);
        }
        if (st->io.ripe_non_managed) {
            wc_lookup_exec_mark_non_auth_and_cycle(
                ctx,
                &st->redirect.header_non_authoritative,
                &st->io.need_redir_eval);
        }

        if (ctx->query_is_cidr_effective && ctx->current_rir_guess) {
            if (wc_lookup_exec_is_current_rir_arin(ctx) &&
                wc_lookup_exec_is_arin_no_match(st->io.body)) {
                if (ctx->seen_arin_no_match_cidr) {
                    *ctx->seen_arin_no_match_cidr = 1;
                }
            }
            if (wc_lookup_exec_is_current_rir_ripe(ctx) && st->io.ripe_non_managed) {
                wc_lookup_exec_mark_seen_ripe_non_managed_output_step(ctx);
            }
            if (wc_lookup_exec_is_current_rir_afrinic(ctx) &&
                wc_lookup_exec_is_full_ipv4_space(st->io.body)) {
                wc_lookup_exec_mark_seen_afrinic_iana_blk_output_step(ctx);
            }
            if (ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "lacnic") == 0 &&
                wc_lookup_exec_is_lacnic_unallocated(st->io.body)) {
                if (ctx->seen_lacnic_unallocated) {
                    *ctx->seen_lacnic_unallocated = 1;
                }
            }
        }
        if (wc_lookup_exec_is_current_rir_lacnic(ctx)) {
            if (wc_lookup_exec_is_lacnic_unallocated(st->io.body)) {
                wc_lookup_exec_mark_header_non_auth(&st->redirect.header_non_authoritative);
                st->io.need_redir_eval = 1;
                if (ctx->ref && *ctx->ref && ctx->ref_host && ctx->ref_host[0]) {
                    const char* ref_rir = wc_guess_rir(ctx->ref_host);
                    if (ref_rir && strcasecmp(ref_rir, "lacnic") == 0) {
                        free(*ctx->ref);
                        *ctx->ref = NULL;
                    }
                }
            }
            if (wc_lookup_exec_is_lacnic_rate_limited(st->io.body)) {
                wc_lookup_exec_mark_non_auth(
                    &st->redirect.header_non_authoritative,
                    &st->io.need_redir_eval);
                wc_lookup_exec_mark_force_rir_cycle_output_step(ctx);
                if (ctx->hops == 0 && ctx->visited && ctx->visited_count) {
                    wc_lookup_exec_remove_current_from_visited(ctx);
                }
            }
        }
        if (st->io.body && wc_lookup_exec_is_full_ipv4_space(st->io.body)) {
            wc_lookup_exec_mark_header_non_auth(&st->redirect.header_non_authoritative);
        }
    }

    header_state.erx_marker_this_hop = 0;
    if (st->io.body) {
        wc_lookup_exec_handle_erx_marker_recheck(
            ctx,
            st->io.body,
            header_state.host,
            st->hint.header_hint_host,
            &st->io.auth,
            &st->redirect.header_non_authoritative,
            &st->io.need_redir_eval,
            &st->io.ref,
            &header_state.erx_marker_this_hop);
    }

    if (st->redirect.header_non_authoritative) {
        st->io.auth = 0;
    }
    if (st->io.auth && !st->redirect.header_non_authoritative &&
        !(ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "iana") == 0) &&
        ctx->seen_real_authoritative) {
        *ctx->seen_real_authoritative = 1;
    }

    wc_lookup_exec_handle_apnic_erx_logic(
        ctx,
        st->io.body,
        header_state.host,
        header_state.is_iana,
        st->redirect.header_non_authoritative,
        st->io.auth,
        header_state.erx_marker_this_hop,
        st->io.ripe_non_managed,
        &st->io.need_redir_eval,
        &st->io.ref,
        &st->io.ref_explicit);

    st->redirect.allow_cycle_on_loop =
        (st->io.need_redir_eval || (ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy)) ? 1 : 0;
    if (ctx->apnic_erx_authoritative_stop && *ctx->apnic_erx_authoritative_stop &&
        wc_lookup_exec_is_effective_current_rir(ctx, "apnic")) {
        st->redirect.allow_cycle_on_loop = 0;
    }
    if (ctx->hops < 1) {
        st->redirect.allow_cycle_on_loop = 0;
    }
    if (st->redirect.allow_cycle_on_loop &&
        ctx->apnic_iana_netblock_cidr && *ctx->apnic_iana_netblock_cidr &&
        wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
        ctx->seen_arin_no_match_cidr && !*ctx->seen_arin_no_match_cidr) {
        st->redirect.allow_cycle_on_loop = 0;
    }

    {
        int fast_authoritative_stop =
            (ctx->erx_fast_authoritative && *ctx->erx_fast_authoritative &&
             wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
             ctx->apnic_erx_root && *ctx->apnic_erx_root &&
             ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1 &&
             (!ctx->ref || !*ctx->ref)) ? 1 : 0;

        st->redirect.force_stop_authoritative = fast_authoritative_stop;
        if (((st->io.auth && !st->redirect.header_non_authoritative &&
              !st->io.need_redir_eval && !ctx->ref) ||
             (ctx->ref && !*ctx->ref)) &&
            !(ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "iana") == 0) &&
            !header_state.erx_marker_this_hop) {
            st->redirect.force_stop_authoritative = 1;
        }
    }
    st->redirect.apnic_erx_suppress_current =
        (ctx->seen_apnic_iana_netblock && *ctx->seen_apnic_iana_netblock &&
         ctx->apnic_ambiguous_revisit_used && *ctx->apnic_ambiguous_revisit_used &&
         wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
         ctx->hops > 0 && wc_lookup_body_contains_apnic_iana_netblock(st->io.body)) ? 1 : 0;

    if (ctx->apnic_erx_root && *ctx->apnic_erx_root && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "ripe") == 0 &&
        wc_lookup_body_contains_ripe_non_managed(st->io.body) &&
        ctx->apnic_erx_ripe_non_managed) {
        *ctx->apnic_erx_ripe_non_managed = 1;
    }

    if (ctx->apnic_erx_root && *ctx->apnic_erx_root && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "arin") == 0) {
        st->redirect.apnic_erx_suppress_current = 0;
    }
    if (ctx->apnic_erx_root && *ctx->apnic_erx_root && ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "ripe") == 0 &&
        ctx->apnic_erx_ripe_non_managed && *ctx->apnic_erx_ripe_non_managed) {
        st->redirect.apnic_erx_suppress_current = 0;
    }

    if (!((ctx->force_rir_cycle && *ctx->force_rir_cycle) ||
          !(ctx->apnic_erx_root && *ctx->apnic_erx_root &&
            ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1) ||
          !(!ctx->ref || !*ctx->ref) ||
          !st->io.need_redir_eval)) {
        const char* stop_rir = NULL;
        if (ctx->apnic_erx_target_rir && ctx->apnic_erx_target_rir[0]) {
            stop_rir = ctx->apnic_erx_target_rir;
        } else if (ctx->apnic_erx_ref_host && ctx->apnic_erx_ref_host[0]) {
            stop_rir = wc_guess_rir(ctx->apnic_erx_ref_host);
        }
        if (stop_rir && ctx->current_rir_guess &&
            strcasecmp(stop_rir, ctx->current_rir_guess) == 0) {
            if (ctx->apnic_erx_stop) {
                *ctx->apnic_erx_stop = 1;
            }
            if (ctx->apnic_erx_stop_unknown) {
                *ctx->apnic_erx_stop_unknown = 0;
            }
            if (ctx->apnic_erx_stop_host && ctx->apnic_erx_stop_host_len > 0) {
                if (ctx->apnic_erx_ref_host && ctx->apnic_erx_ref_host[0]) {
                    snprintf(ctx->apnic_erx_stop_host,
                        ctx->apnic_erx_stop_host_len,
                        "%s",
                        ctx->apnic_erx_ref_host);
                } else {
                    const char* canon = wc_dns_canonical_host_for_rir(stop_rir);
                    const char* fallback_value = canon ? canon : ctx->current_host;
                    snprintf(ctx->apnic_erx_stop_host,
                        ctx->apnic_erx_stop_host_len,
                        "%s",
                        fallback_value ? fallback_value : "");
                }
            }
        }
    }

    {
        int need_redir =
            (ctx->zopts && !ctx->zopts->no_redirect) ? st->io.need_redir_eval : 0;

        ctx->body = st->io.body;
        if (ctx->last_hop_authoritative) {
            *ctx->last_hop_authoritative = st->io.auth ? 1 : 0;
        }
        if (ctx->last_hop_need_redirect) {
            *ctx->last_hop_need_redirect = st->io.need_redir_eval ? 1 : 0;
        }
        if (ctx->last_hop_has_ref) {
            *ctx->last_hop_has_ref = st->io.ref ? 1 : 0;
        }

        if (ctx->header_non_authoritative) {
            *ctx->header_non_authoritative = st->redirect.header_non_authoritative;
        }
        if (ctx->allow_cycle_on_loop) {
            *ctx->allow_cycle_on_loop = st->redirect.allow_cycle_on_loop;
        }
        if (ctx->need_redir) {
            *ctx->need_redir = need_redir;
        }
        if (ctx->force_stop_authoritative) {
            *ctx->force_stop_authoritative = st->redirect.force_stop_authoritative;
        }
        if (ctx->apnic_erx_suppress_current) {
            *ctx->apnic_erx_suppress_current = st->redirect.apnic_erx_suppress_current;
        }

        *ctx->auth = st->io.auth;
        *ctx->need_redir_eval = st->io.need_redir_eval;
        if (ctx->ref) {
            *ctx->ref = st->io.ref;
        }
        if (ctx->ref_explicit) {
            *ctx->ref_explicit = st->io.ref_explicit;
        }
        if (ctx->ref_port) {
            *ctx->ref_port = st->io.ref_port;
        }
    }
}

void wc_lookup_exec_eval_redirect(struct wc_lookup_exec_redirect_ctx* ctx) {
    if (!ctx || !ctx->body || !ctx->auth || !ctx->need_redir_eval) return;

    struct wc_lookup_exec_eval_state st = {0};
    wc_lookup_exec_run_eval(ctx, &st);
}
