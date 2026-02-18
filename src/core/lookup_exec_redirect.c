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

struct wc_lookup_exec_eval_state;
struct wc_lookup_exec_header_state;

static int wc_lookup_exec_is_effective_current_rir(
    const struct wc_lookup_exec_redirect_ctx* ctx,
    const char* rir_name) {
    if (!ctx || !rir_name || !*rir_name) return 0;

    const char* rir = NULL;
    if (ctx->current_rir_guess && *ctx->current_rir_guess &&
        strcasecmp(ctx->current_rir_guess, "unknown") != 0) {
        rir = ctx->current_rir_guess;
    }

    if (!rir) {
        const char* host_for_guess = ctx->current_host;
        if (host_for_guess && *host_for_guess) {
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

            const char* guessed = wc_guess_rir(host_for_guess);
            if (guessed && *guessed && strcasecmp(guessed, "unknown") != 0) {
                rir = guessed;
            }
        }

        if (!rir) {
            rir = ctx->current_rir_guess;
        }
    }

    return (rir && strcasecmp(rir, rir_name) == 0) ? 1 : 0;
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

        if (wc_lookup_exec_is_effective_current_rir(ctx, "lacnic")) {
            int header_erx_hint =
                st->io.body &&
                (wc_lookup_body_contains_erx_legacy(st->io.body) ||
                 wc_lookup_body_contains_erx_netname(st->io.body) ||
                 wc_lookup_body_contains_apnic_erx_hint(st->io.body));
            const char* implicit_host =
                (header_state.host && !header_state.is_iana && !header_state.matches_current)
                    ? header_state.host
                    : "whois.apnic.net";

            if (header_erx_hint && strcasecmp(implicit_host, "whois.apnic.net") == 0) {
                if (st->io.ref && !st->io.ref_explicit) {
                    free(st->io.ref);
                    st->io.ref = NULL;
                }
                if (!st->io.ref) {
                    if (ctx->visited && ctx->visited_count &&
                        !wc_lookup_visited_has(ctx->visited, *ctx->visited_count, "whois.apnic.net") &&
                        *ctx->visited_count < 16) {
                        {
                            const char* dup_src = "whois.apnic.net";
                            size_t dup_len = strlen(dup_src) + 1;
                            char* dup_mem = (char*)malloc(dup_len);
                            if (dup_mem) memcpy(dup_mem, dup_src, dup_len);
                            ctx->visited[(*ctx->visited_count)++] = dup_mem;
                        }
                    }
                    if (ctx->apnic_erx_legacy) {
                        *ctx->apnic_erx_legacy = 1;
                    }
                    if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
                        *ctx->apnic_erx_root = 1;
                        if (ctx->apnic_redirect_reason) {
                            *ctx->apnic_redirect_reason = 1;
                        }
                        if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
                            ctx->apnic_erx_root_host[0] == '\0') {
                            snprintf(ctx->apnic_erx_root_host,
                                ctx->apnic_erx_root_host_len,
                                "%s",
                                "whois.apnic.net");
                        }
                    }
                    st->io.need_redir_eval = 1;
                }
            }

            if (header_state.host && !header_state.is_iana && !header_state.matches_current) {
                const char* header_rir_local = wc_guess_rir(header_state.host);
                if (header_rir_local && strcasecmp(header_rir_local, "unknown") != 0) {
                    if (wc_normalize_whois_host(
                            header_state.host,
                            st->hint.header_hint_host,
                            st->hint.header_hint_host_len) != 0) {
                        snprintf(st->hint.header_hint_host,
                            st->hint.header_hint_host_len,
                            "%s",
                            header_state.host);
                    }
                    if (ctx->header_hint_valid) {
                        *ctx->header_hint_valid = (st->hint.header_hint_host[0] != '\0');
                    }
                    st->io.need_redir_eval = 1;

                    if (strcasecmp(header_rir_local, "apnic") == 0 ||
                        strcasecmp(header_rir_local, "ripe") == 0 ||
                        strcasecmp(header_rir_local, "afrinic") == 0) {
                        int non_auth_internal = 0;
                        if (strcasecmp(header_rir_local, "apnic") == 0) {
                            if (wc_lookup_body_contains_apnic_iana_netblock(st->io.body) ||
                                wc_lookup_body_contains_erx_legacy(st->io.body)) {
                                non_auth_internal = 1;
                            }
                        } else if (strcasecmp(header_rir_local, "ripe") == 0) {
                            if (wc_lookup_body_contains_ripe_non_managed(st->io.body)) {
                                if (ctx->seen_ripe_non_managed) {
                                    *ctx->seen_ripe_non_managed = 1;
                                }
                                non_auth_internal = 1;
                            }
                        } else if (strcasecmp(header_rir_local, "afrinic") == 0) {
                            if (wc_lookup_body_contains_full_ipv4_space(st->io.body)) {
                                if (ctx->seen_afrinic_iana_blk) {
                                    *ctx->seen_afrinic_iana_blk = 1;
                                }
                                non_auth_internal = 1;
                            }
                        }

                        if (ctx->access_denied && ctx->hops == 0) {
                            non_auth_internal = 1;
                            if (ctx->header_hint_valid) {
                                *ctx->header_hint_valid = 0;
                            }
                            if (ctx->force_rir_cycle) {
                                *ctx->force_rir_cycle = 1;
                            }
                        }

                        if (!non_auth_internal) {
                            if (*ctx->auth && !wc_lookup_body_has_strong_redirect_hint(st->io.body)) {
                                if (ctx->stop_with_header_authority) {
                                    *ctx->stop_with_header_authority = 1;
                                }
                                if (ctx->header_authority_host && ctx->header_authority_host_len > 0) {
                                    snprintf(ctx->header_authority_host,
                                        ctx->header_authority_host_len,
                                        "%s",
                                        st->hint.header_hint_host);
                                }
                            }
                        } else {
                            if (ctx->header_hint_valid) {
                                *ctx->header_hint_valid = 0;
                            }
                            if (ctx->force_rir_cycle) {
                                *ctx->force_rir_cycle = 1;
                            }
                        }

                        if (!ctx->access_denied && ctx->visited && ctx->visited_count &&
                            !wc_lookup_visited_has(
                                ctx->visited,
                                *ctx->visited_count,
                                st->hint.header_hint_host) &&
                            *ctx->visited_count < 16) {
                            const char* dup_src = st->hint.header_hint_host;
                            size_t dup_len = dup_src ? (strlen(dup_src) + 1) : 0;
                            char* dup_mem = (dup_len > 0) ? (char*)malloc(dup_len) : NULL;
                            if (dup_mem) memcpy(dup_mem, dup_src, dup_len);
                            ctx->visited[(*ctx->visited_count)++] = dup_mem;
                        }
                    }
                }
            }
        }
    }

    int first_hop_persistent_empty = 0;
    int access_denied_current = 0;
    int access_denied_internal = 0;
    int rate_limit_current = 0;
    if (ctx && st->io.body) {
        int host_matches_current = (!header_state.host || header_state.matches_current) ? 1 : 0;
        first_hop_persistent_empty = (ctx->persistent_empty && ctx->hops == 0) ? 1 : 0;
        access_denied_current = (ctx->access_denied && host_matches_current);
        access_denied_internal = (ctx->access_denied && !host_matches_current);
        rate_limit_current = (ctx->rate_limited && host_matches_current);
        int denied_current_or_internal =
            (access_denied_current || access_denied_internal) ? 1 : 0;
        int denied_or_rate_limited =
            (denied_current_or_internal || rate_limit_current) ? 1 : 0;
        int should_hide_failure_body =
            (ctx->cfg && ctx->cfg->hide_failure_body && st->io.body && *st->io.body) ? 1 : 0;
        const char* active_resp_host =
            access_denied_internal ? header_state.host : ctx->current_host;

        if (denied_or_rate_limited && ctx->cfg && ctx->cfg->debug) {
            const char* dbg_host = active_resp_host;
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
                denied_current_or_internal ? "denied" : "rate-limit",
                access_denied_internal ? "internal" : "current",
                (dbg_host && *dbg_host) ? dbg_host : "unknown",
                (dbg_rir && *dbg_rir) ? dbg_rir : "unknown",
                dbg_ip);
        }

        if (denied_or_rate_limited) {
            const char* err_host = active_resp_host;
            if (ctx->last_failure_host && ctx->last_failure_host_len > 0 &&
                err_host && *err_host) {
                snprintf(ctx->last_failure_host, ctx->last_failure_host_len, "%s", err_host);
            }
            {
                const char* err_rir = wc_guess_rir(err_host);
                if (ctx->last_failure_rir && ctx->last_failure_rir_len > 0 && err_rir && *err_rir) {
                    snprintf(ctx->last_failure_rir, ctx->last_failure_rir_len, "%s", err_rir);
                }
            }
            {
                const char* failure_status =
                    denied_current_or_internal ? "denied" : "rate-limit";
                const char* failure_desc =
                    denied_current_or_internal ? "access-denied" : "rate-limit-exceeded";
                if (ctx->last_failure_status) {
                    *ctx->last_failure_status = failure_status;
                }
                if (ctx->last_failure_desc) {
                    *ctx->last_failure_desc = failure_desc;
                }
            }
            if (ctx->last_failure_ip && ctx->last_failure_ip_len > 0 &&
                !ctx->last_failure_ip[0]) {
                const char* ip = NULL;
                int use_current_ip = (!access_denied_internal && ctx->ni && ctx->ni->ip[0]) ? 1 : 0;
                if (use_current_ip) {
                    ip = ctx->ni->ip;
                } else {
                    const char* known_ip = wc_dns_get_known_ip(err_host);
                    ip = (known_ip && known_ip[0]) ? known_ip : NULL;
                }
                if (ip && *ip) {
                    snprintf(ctx->last_failure_ip, ctx->last_failure_ip_len, "%s", ip);
                }
            }
        }

        if (should_hide_failure_body && denied_or_rate_limited) {
            if (denied_current_or_internal) {
                char* filtered_body = wc_lookup_strip_access_denied_lines(st->io.body);
                if (filtered_body) {
                    free(st->io.body);
                    st->io.body = filtered_body;
                    ctx->body = st->io.body;
                }
            } else if (rate_limit_current) {
                char* filtered_body = wc_lookup_strip_rate_limit_lines(st->io.body);
                if (filtered_body) {
                    free(st->io.body);
                    st->io.body = filtered_body;
                    ctx->body = st->io.body;
                }
            }
        }

        if (denied_or_rate_limited && ctx->saw_rate_limit_or_denied) {
            *ctx->saw_rate_limit_or_denied = 1;
        }
    }

    if (st->io.body) {
        if (ctx->persistent_empty && ctx->current_rir_guess) {
            st->redirect.header_non_authoritative = 1;
            st->io.need_redir_eval = 1;
            if (first_hop_persistent_empty) {
                if (strcasecmp(ctx->current_rir_guess, "arin") == 0) {
                    if (ctx->force_rir_cycle) {
                        *ctx->force_rir_cycle = 1;
                    }
                }
                if (ctx->visited && ctx->visited_count) {
                    wc_lookup_visited_remove(ctx->visited, ctx->visited_count, ctx->current_host);
                    if (wc_dns_is_ip_literal(ctx->current_host)) {
                        const char* mapped_host = wc_lookup_known_ip_host_from_literal(ctx->current_host);
                        if (mapped_host && *mapped_host) {
                            wc_lookup_visited_remove(ctx->visited, ctx->visited_count, mapped_host);
                        }
                    }
                    {
                        const char* canon_visit = wc_dns_canonical_alias(ctx->current_host);
                        if (canon_visit && *canon_visit) {
                            wc_lookup_visited_remove(ctx->visited, ctx->visited_count, canon_visit);
                        }
                    }
                }
            } else {
                if (ctx->force_rir_cycle) {
                    *ctx->force_rir_cycle = 1;
                }
            }
        }

        {
            const char* header_rir = NULL;
            if (header_state.host && *header_state.host) {
                const char* header_canon = wc_dns_canonical_alias(header_state.host);
                const char* header_for_guess =
                    (header_canon && *header_canon) ? header_canon : header_state.host;
                header_rir = wc_guess_rir(header_for_guess);
            }

            if (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") ||
                (header_rir && *header_rir && strcasecmp(header_rir, "apnic") == 0)) {
                int apnic_iana_netblock =
                    (st->io.body && wc_lookup_body_contains_apnic_iana_netblock(st->io.body))
                        ? 1
                        : 0;

                if (st->io.body && wc_lookup_body_contains_ipv6_root(st->io.body)) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                }
                if (wc_lookup_body_contains_erx_legacy(st->io.body)) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                }

                if (st->io.body && wc_lookup_body_contains_apnic_iana_netblock(st->io.body)) {
                    if (ctx->seen_apnic_iana_netblock) {
                        *ctx->seen_apnic_iana_netblock = 1;
                    }
                    if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
                        *ctx->apnic_erx_root = 1;
                        if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
                            ctx->apnic_erx_root_host[0] == '\0') {
                            const char* apnic_root = wc_dns_canonical_alias(ctx->current_host);
                            snprintf(ctx->apnic_erx_root_host,
                                ctx->apnic_erx_root_host_len,
                                "%s",
                                apnic_root ? apnic_root : ctx->current_host);
                        }
                        if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip_len > 0 &&
                            ctx->apnic_erx_root_ip[0] == '\0' && ctx->ni && ctx->ni->ip[0]) {
                            snprintf(ctx->apnic_erx_root_ip,
                                ctx->apnic_erx_root_ip_len,
                                "%s",
                                ctx->ni->ip);
                        }
                    }
                    if (ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 0) {
                        *ctx->apnic_redirect_reason = 2;
                    }
                }

                if (apnic_iana_netblock) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                    if (ctx->force_rir_cycle) {
                        *ctx->force_rir_cycle = 1;
                    }
                }

                if ((header_rir && *header_rir && strcasecmp(header_rir, "apnic") == 0) &&
                    wc_lookup_body_contains_erx_legacy(st->io.body)) {
                    if (ctx->apnic_erx_legacy) {
                        *ctx->apnic_erx_legacy = 1;
                    }
                    if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
                        *ctx->apnic_erx_root = 1;
                        if (ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 0) {
                            *ctx->apnic_redirect_reason = 1;
                        }
                    }
                    if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
                        ctx->apnic_erx_root_host[0] == '\0') {
                        snprintf(ctx->apnic_erx_root_host,
                            ctx->apnic_erx_root_host_len,
                            "%s",
                            "whois.apnic.net");
                    }
                    if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip_len > 0 &&
                        ctx->apnic_erx_root_ip[0] == '\0') {
                        const char* apnic_ip = wc_dns_get_known_ip("whois.apnic.net");
                        if (apnic_ip && apnic_ip[0]) {
                            snprintf(ctx->apnic_erx_root_ip,
                                ctx->apnic_erx_root_ip_len,
                                "%s",
                                apnic_ip);
                        }
                    }
                }
            }

            if (wc_lookup_exec_is_effective_current_rir(ctx, "ripe") ||
                (header_rir && *header_rir && strcasecmp(header_rir, "ripe") == 0)) {
                if (wc_lookup_body_contains_ipv6_root(st->io.body) ||
                    wc_lookup_body_contains_ripe_access_denied(st->io.body) ||
                    wc_lookup_body_contains_ripe_non_managed(st->io.body)) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                    if (ctx->force_rir_cycle) {
                        *ctx->force_rir_cycle = 1;
                    }
                }
            }

            if (wc_lookup_exec_is_effective_current_rir(ctx, "afrinic") ||
                (header_rir && *header_rir && strcasecmp(header_rir, "afrinic") == 0)) {
                if ((st->io.body && wc_lookup_body_contains_ipv6_root(st->io.body)) ||
                    (st->io.body && wc_lookup_body_contains_full_ipv4_space(st->io.body))) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                    if (ctx->force_rir_cycle) {
                        *ctx->force_rir_cycle = 1;
                    }
                }
            }

            if (wc_lookup_exec_is_effective_current_rir(ctx, "arin")) {
                int apnic_erx_legacy_chain =
                    (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
                     ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1) ? 1 : 0;
                int arin_erx_transferred_to_ripe =
                    (st->io.body && wc_lookup_find_case_insensitive(
                        st->io.body,
                        "early registrations, transferred to ripe ncc")) ? 1 : 0;

                if ((st->io.body && wc_lookup_body_contains_no_match(st->io.body)) || !st->io.auth) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                } else if (apnic_erx_legacy_chain && arin_erx_transferred_to_ripe) {
                    st->redirect.header_non_authoritative = 1;
                    st->io.need_redir_eval = 1;
                    if (ctx->force_rir_cycle) {
                        *ctx->force_rir_cycle = 1;
                    }
                }
            }
        }
        if (ctx->current_rir_guess && ctx->hops == 0 &&
            (access_denied_current || rate_limit_current)) {
            st->redirect.header_non_authoritative = 1;
            st->io.need_redir_eval = 1;
            if (ctx->force_rir_cycle) {
                *ctx->force_rir_cycle = 1;
            }
            if (ctx->visited && ctx->visited_count) {
                wc_lookup_visited_remove(ctx->visited, ctx->visited_count, ctx->current_host);
                if (wc_dns_is_ip_literal(ctx->current_host)) {
                    const char* mapped_host = wc_lookup_known_ip_host_from_literal(ctx->current_host);
                    if (mapped_host && *mapped_host) {
                        wc_lookup_visited_remove(ctx->visited, ctx->visited_count, mapped_host);
                    }
                }
                {
                    const char* canon_visit = wc_dns_canonical_alias(ctx->current_host);
                    if (canon_visit && *canon_visit) {
                        wc_lookup_visited_remove(ctx->visited, ctx->visited_count, canon_visit);
                    }
                }
            }
        }
        if (st->io.ripe_non_managed) {
            st->redirect.header_non_authoritative = 1;
            st->io.need_redir_eval = 1;
            if (ctx->force_rir_cycle) {
                *ctx->force_rir_cycle = 1;
            }
        }

        if (ctx->query_is_cidr_effective && ctx->current_rir_guess) {
            if (wc_lookup_exec_is_effective_current_rir(ctx, "arin") &&
                (st->io.body && wc_lookup_body_contains_no_match(st->io.body))) {
                if (ctx->seen_arin_no_match_cidr) {
                    *ctx->seen_arin_no_match_cidr = 1;
                }
            }
            if (wc_lookup_exec_is_effective_current_rir(ctx, "ripe") && st->io.ripe_non_managed) {
                if (ctx->seen_ripe_non_managed) {
                    *ctx->seen_ripe_non_managed = 1;
                }
            }
            if (wc_lookup_exec_is_effective_current_rir(ctx, "afrinic") &&
                (st->io.body && wc_lookup_body_contains_full_ipv4_space(st->io.body))) {
                if (ctx->seen_afrinic_iana_blk) {
                    *ctx->seen_afrinic_iana_blk = 1;
                }
            }
            if (ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "lacnic") == 0 &&
                (st->io.body && wc_lookup_body_contains_lacnic_unallocated(st->io.body))) {
                if (ctx->seen_lacnic_unallocated) {
                    *ctx->seen_lacnic_unallocated = 1;
                }
            }
        }
        if (wc_lookup_exec_is_effective_current_rir(ctx, "lacnic")) {
            if (st->io.body && wc_lookup_body_contains_lacnic_unallocated(st->io.body)) {
                st->redirect.header_non_authoritative = 1;
                st->io.need_redir_eval = 1;
                if (ctx->ref && *ctx->ref && ctx->ref_host && ctx->ref_host[0]) {
                    const char* ref_rir = wc_guess_rir(ctx->ref_host);
                    if (ref_rir && strcasecmp(ref_rir, "lacnic") == 0) {
                        free(*ctx->ref);
                        *ctx->ref = NULL;
                    }
                }
            }
            if (st->io.body && wc_lookup_body_contains_lacnic_rate_limit(st->io.body)) {
                st->redirect.header_non_authoritative = 1;
                st->io.need_redir_eval = 1;
                if (ctx->force_rir_cycle) {
                    *ctx->force_rir_cycle = 1;
                }
                if (ctx->hops == 0 && ctx->visited && ctx->visited_count) {
                    wc_lookup_visited_remove(ctx->visited, ctx->visited_count, ctx->current_host);
                    if (wc_dns_is_ip_literal(ctx->current_host)) {
                        const char* mapped_host = wc_lookup_known_ip_host_from_literal(ctx->current_host);
                        if (mapped_host && *mapped_host) {
                            wc_lookup_visited_remove(ctx->visited, ctx->visited_count, mapped_host);
                        }
                    }
                    {
                        const char* canon_visit = wc_dns_canonical_alias(ctx->current_host);
                        if (canon_visit && *canon_visit) {
                            wc_lookup_visited_remove(ctx->visited, ctx->visited_count, canon_visit);
                        }
                    }
                }
            }
        }
        if (st->io.body && wc_lookup_body_contains_full_ipv4_space(st->io.body)) {
            st->redirect.header_non_authoritative = 1;
        }
    }

    header_state.erx_marker_this_hop = 0;
    if (st->io.body) {
        const char* erx_marker_host_local = ctx ? ctx->current_host : NULL;
        if (wc_lookup_exec_is_effective_current_rir(ctx, "lacnic")) {
            if (st->hint.header_hint_host && st->hint.header_hint_host[0]) {
                erx_marker_host_local = st->hint.header_hint_host;
            } else {
                erx_marker_host_local = header_state.host;
            }
        }
        header_state.erx_marker_this_hop = wc_lookup_body_contains_erx_iana_marker(st->io.body);

        if (header_state.erx_marker_this_hop) {
            st->redirect.header_non_authoritative = 1;
            st->io.need_redir_eval = 1;
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
                    if (ip && *ip) {
                        snprintf(ctx->erx_marker_ip, ctx->erx_marker_ip_len, "%s", ip);
                    }
                }
            }
        }

        if (ctx && header_state.erx_marker_this_hop && ctx->query_is_cidr && ctx->cidr_base_query &&
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
                int recheck_non_auth = (recheck_res.body && recheck_res.body[0])
                    ? wc_lookup_body_has_strong_redirect_hint(recheck_res.body)
                    : 0;
                int recheck_authority_known =
                    (recheck_res.meta.authoritative_host[0] &&
                     strcasecmp(recheck_res.meta.authoritative_host, "unknown") != 0 &&
                     strcasecmp(recheck_res.meta.authoritative_host, "error") != 0) ? 1 : 0;
                if (ctx->cfg && ctx->cfg->debug) {
                    int recheck_erx = (recheck_res.body && recheck_res.body[0])
                        ? wc_lookup_body_contains_erx_iana_marker(recheck_res.body)
                        : 0;
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

                    st->redirect.header_non_authoritative = 0;
                    st->io.need_redir_eval = 0;
                    if (st->io.ref) {
                        free(st->io.ref);
                        st->io.ref = NULL;
                    }
                    st->io.auth = 1;
                }
            } else {
                if (ctx->cfg && ctx->cfg->debug) {
                    fprintf(stderr,
                        "[DEBUG] ERX fast recheck failed: rc=%d\n",
                        recheck_rc);
                }
            }
            wc_lookup_result_free(&recheck_res);
        } else if (ctx && header_state.erx_marker_this_hop && ctx->query_is_cidr && ctx->cidr_base_query &&
                   ctx->erx_fast_recheck_done && !*ctx->erx_fast_recheck_done && ctx->cfg &&
                   !ctx->cfg->cidr_erx_recheck && ctx->cfg->debug) {
            fprintf(stderr,
                "[ERX-RECHECK] action=skip reason=disabled query=%s host=%s\n",
                ctx->cidr_base_query,
                erx_marker_host_local);
        }
    }

    if (st->redirect.header_non_authoritative) {
        st->io.auth = 0;
    }
    if (st->io.auth && !st->redirect.header_non_authoritative &&
        !(ctx->current_rir_guess && strcasecmp(ctx->current_rir_guess, "iana") == 0) &&
        ctx->seen_real_authoritative) {
        *ctx->seen_real_authoritative = 1;
    }

    if (ctx && st->io.body) {
        int header_authoritative_stop =
            (ctx && header_state.host && ctx->current_host && header_state.host[0] &&
             ctx->current_host[0] && st->io.auth && !st->redirect.header_non_authoritative &&
             strcasecmp(header_state.host, ctx->current_host) == 0) ? 1 : 0;
        if (ctx && header_state.host && strcasecmp(header_state.host, "whois.apnic.net") == 0 &&
            ctx->ni && ctx->ni->ip[0] &&
            ctx->apnic_last_ip && ctx->apnic_last_ip_len > 0) {
            snprintf(ctx->apnic_last_ip, ctx->apnic_last_ip_len, "%s", ctx->ni->ip);
        }
        if (header_state.host && st->io.ref && !header_state.is_iana && !st->io.ref_explicit) {
            char ref_norm2[128];
            const char* header_norm = wc_dns_canonical_alias(header_state.host);
            header_norm = header_norm ? header_norm : header_state.host;
            if (wc_normalize_whois_host(ctx->ref_host, ref_norm2, sizeof(ref_norm2)) != 0) {
                snprintf(ref_norm2, sizeof(ref_norm2), "%s", ctx->ref_host);
            }
            if (strcasecmp(ref_norm2, header_norm) == 0) {
                st->io.need_redir_eval = 0;
                if (st->io.ref) {
                    free(st->io.ref);
                    st->io.ref = NULL;
                }
            }
        }

        if (header_authoritative_stop && st->io.ref && !st->io.ref_explicit &&
            (!ctx->apnic_erx_keep_ref || !*ctx->apnic_erx_keep_ref)) {
            const char* ref_rir = wc_guess_rir(ctx->ref_host);
            if (ref_rir && ctx->current_rir_guess &&
                strcasecmp(ref_rir, ctx->current_rir_guess) != 0) {
                st->io.ref_explicit = 1;
            } else {
                free(st->io.ref);
                st->io.ref = NULL;
            }
        }

        if (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
            ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1 &&
            header_authoritative_stop) {
            if (ctx->apnic_erx_authoritative_stop) {
                *ctx->apnic_erx_authoritative_stop = 1;
            }
            st->io.need_redir_eval = 0;
            if (st->io.ref && !st->io.ref_explicit &&
                !(ctx->apnic_erx_keep_ref && *ctx->apnic_erx_keep_ref)) {
                free(st->io.ref);
                st->io.ref = NULL;
            }
        }

        int apnic_transfer_to_apnic =
            (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
             wc_lookup_body_contains_apnic_transfer_to_apnic(st->io.body)) ? 1 : 0;
        if (apnic_transfer_to_apnic) {
            st->io.need_redir_eval = 0;
            if (st->io.ref) {
                free(st->io.ref);
                st->io.ref = NULL;
            }
        }

        {
            int erx_netname = wc_lookup_body_contains_erx_netname(st->io.body);
            if (st->io.auth && erx_netname && header_state.host && !header_state.is_iana &&
                !(st->io.ref && st->io.ref_explicit)) {
                st->io.need_redir_eval = 0;
                if (st->io.ref) {
                    free(st->io.ref);
                    st->io.ref = NULL;
                }
            }
        }

        if (!ctx->apnic_redirect_reason || *ctx->apnic_redirect_reason == 0) {
            if ((!ctx->apnic_iana_netblock_cidr || !*ctx->apnic_iana_netblock_cidr) &&
                st->io.need_redir_eval && st->io.auth && !st->io.ref &&
                wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
                wc_lookup_exec_rule_allow_apnic_hint_strict(st->io.body)) {
                st->io.need_redir_eval = 0;
            }
        }

        {
            int base_guard = (st->io.auth && header_state.host && !header_state.is_iana &&
                              !st->io.ref) ? 1 : 0;
            int header_matches_current_host = 0;
            if (ctx && header_state.host) {
                char header_norm3[128];
                char current_norm3[128];
                const char* header_normp = wc_dns_canonical_alias(header_state.host);
                header_normp = header_normp ? header_normp : header_state.host;
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
            if (base_guard && !st->io.need_redir_eval) {
                st->io.need_redir_eval = 0;
            }

            if (base_guard && st->io.need_redir_eval &&
                !wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
                header_matches_current_host &&
                !st->redirect.header_non_authoritative &&
                !wc_lookup_body_has_strong_redirect_hint(st->io.body)) {
                st->io.need_redir_eval = 0;
            }
        }

        if (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") && !apnic_transfer_to_apnic) {
            if (ctx->apnic_erx_legacy) {
                *ctx->apnic_erx_legacy = wc_lookup_body_contains_erx_legacy(st->io.body);
            }
            if (ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy &&
                ctx->apnic_iana_netblock_cidr && !*ctx->apnic_iana_netblock_cidr &&
                !(ctx->erx_fast_authoritative && *ctx->erx_fast_authoritative)) {
                st->io.need_redir_eval = 1;
            }
        }

        if (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
            ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy) {
            if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
                *ctx->apnic_erx_root = 1;
                if (ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 0) {
                    *ctx->apnic_redirect_reason = 1;
                }
            }

            if (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host_len > 0 &&
                ctx->apnic_erx_root_host[0] == '\0') {
                const char* apnic_root = wc_dns_canonical_alias(ctx->current_host);
                snprintf(ctx->apnic_erx_root_host,
                    ctx->apnic_erx_root_host_len,
                    "%s",
                    apnic_root ? apnic_root : ctx->current_host);
            }

            if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip_len > 0 &&
                ctx->apnic_erx_root_ip[0] == '\0' && ctx->ni && ctx->ni->ip[0]) {
                snprintf(ctx->apnic_erx_root_ip, ctx->apnic_erx_root_ip_len, "%s", ctx->ni->ip);
            }
        }
        if (wc_lookup_exec_is_effective_current_rir(ctx, "apnic") &&
            ctx->ni && ctx->ni->ip[0] && ctx->apnic_last_ip && ctx->apnic_last_ip_len > 0) {
            snprintf(ctx->apnic_last_ip, ctx->apnic_last_ip_len, "%s", ctx->ni->ip);
        }
        if (st->io.need_redir_eval &&
            ctx->current_rir_guess &&
            ctx->apnic_erx_legacy && *ctx->apnic_erx_legacy) {
            if (ctx->apnic_erx_root && !*ctx->apnic_erx_root) {
                *ctx->apnic_erx_root = 1;
            }
        }

        if (ctx->apnic_erx_root && *ctx->apnic_erx_root &&
            ctx->apnic_redirect_reason && *ctx->apnic_redirect_reason == 1 &&
            ctx->apnic_erx_target_rir && ctx->apnic_erx_target_rir[0] &&
            wc_lookup_exec_is_effective_current_rir(ctx, ctx->apnic_erx_target_rir) &&
            strcasecmp(ctx->apnic_erx_target_rir, "apnic") != 0 &&
            !(strcasecmp(ctx->apnic_erx_target_rir, "ripe") == 0 && st->io.ripe_non_managed)) {
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

        if (!apnic_transfer_to_apnic && wc_lookup_body_contains_full_ipv4_space(st->io.body)) {
            st->io.need_redir_eval = 1;
            if (ctx->force_rir_cycle) {
                *ctx->force_rir_cycle = 1;
            }
        }
        if (apnic_transfer_to_apnic) {
            st->io.need_redir_eval = 0;
        }

        if (st->io.need_redir_eval && st->io.auth && !st->io.ref &&
            wc_lookup_exec_is_effective_current_rir(ctx, "apnic")) {
            if (!(header_state.erx_marker_this_hop &&
                  !(ctx->erx_fast_authoritative && *ctx->erx_fast_authoritative)) &&
                (ctx->erx_fast_authoritative && *ctx->erx_fast_authoritative)) {
                st->io.need_redir_eval = 0;
            }
        }
    }

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
