// SPDX-License-Identifier: MIT
// lookup_exec_finalize.c - Finalization helpers for lookup exec
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_dns.h"
#include "wc/wc_server.h"
#include "wc/wc_util.h"
#include "lookup_internal.h"
#include "lookup_exec_finalize.h"

void wc_lookup_exec_finalize(struct wc_lookup_exec_finalize_ctx* ctx) {
    if (!ctx || !ctx->out || !ctx->q) return;
    struct wc_result* out = ctx->out;
    const struct wc_query* q = ctx->q;
    const struct wc_lookup_opts* zopts = ctx->zopts;
    const Config* cfg = ctx->cfg;
    char* combined = ctx->combined;

    if (combined && out->meta.authoritative_host[0] == '\0' && !ctx->redirect_cap_hit) {
        if (ctx->last_hop_authoritative && !ctx->last_hop_need_redirect && !ctx->last_hop_has_ref) {
            const char* fallback_host = ctx->current_host && ctx->current_host[0]
                ? ctx->current_host
                : ctx->start_host;
            const char* auth_host = wc_dns_canonical_alias(fallback_host);
            snprintf(out->meta.authoritative_host,
                     sizeof(out->meta.authoritative_host),
                     "%s",
                     auth_host ? auth_host : fallback_host);
        } else {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
        }
    }
    if (ctx->redirect_cap_hit && out->meta.authoritative_host[0] == '\0') {
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
    }
    if (ctx->redirect_cap_hit && out->meta.authoritative_ip[0] == '\0') {
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
    }
    if (out->meta.authoritative_host[0] &&
        strcasecmp(out->meta.authoritative_host, "unknown") == 0) {
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
    }
    if (ctx->apnic_erx_root && ctx->apnic_erx_seen_arin && combined) {
        const char* final_rir = (out->meta.authoritative_host[0]
            ? wc_guess_rir(out->meta.authoritative_host)
            : NULL);
        (void)final_rir;
    }

    if (ctx->erx_marker_seen && !ctx->redirect_cap_hit && ctx->rir_cycle_exhausted &&
        ctx->saw_rate_limit_or_denied && ctx->erx_marker_host && ctx->erx_marker_host[0] &&
        (!out->meta.authoritative_host[0] ||
         strcasecmp(out->meta.authoritative_host, "unknown") == 0 ||
         strcasecmp(out->meta.authoritative_host, "error") == 0) &&
        !wc_lookup_erx_baseline_recheck_guard_get()) {
        const char* base_query = (ctx->query_is_cidr_effective && ctx->cidr_base_query)
            ? ctx->cidr_base_query
            : q->raw;
        if (base_query && *base_query) {
            struct wc_lookup_opts recheck_opts = *zopts;
            struct wc_result recheck_res;
            struct wc_query recheck_q = {
                .raw = base_query,
                .start_server = ctx->erx_marker_host,
                .port = (q->port > 0 ? q->port : 43)
            };
            recheck_opts.no_redirect = 1;
            recheck_opts.max_hops = 1;
            recheck_opts.net_ctx = ctx->net_ctx;
            recheck_opts.config = cfg;
            wc_lookup_erx_baseline_recheck_guard_set(1);
            ctx->erx_baseline_recheck_attempted = 1;
            if (cfg && cfg->debug) {
                fprintf(stderr,
                    "[DEBUG] ERX baseline recheck: query=%s host=%s\n",
                    base_query,
                    ctx->erx_marker_host);
            }
            int recheck_rc = wc_lookup_execute(&recheck_q, &recheck_opts, &recheck_res);
            wc_lookup_erx_baseline_recheck_guard_set(0);
            if (recheck_rc == 0 && recheck_res.body && recheck_res.body[0]) {
                int recheck_erx = wc_lookup_body_contains_erx_iana_marker(recheck_res.body);
                int recheck_non_auth = wc_lookup_body_has_strong_redirect_hint(recheck_res.body);
                if (cfg && cfg->debug) {
                    fprintf(stderr,
                        "[DEBUG] ERX baseline recheck result: erx=%d non_auth=%d\n",
                        recheck_erx,
                        recheck_non_auth);
                }
                if (!recheck_erx && !recheck_non_auth) {
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host),
                        "%s", ctx->erx_marker_host);
                    if (recheck_res.meta.authoritative_ip[0] &&
                        strcasecmp(recheck_res.meta.authoritative_ip, "unknown") != 0) {
                        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                            "%s", recheck_res.meta.authoritative_ip);
                    } else if (recheck_res.meta.last_ip[0]) {
                        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                            "%s", recheck_res.meta.last_ip);
                    } else {
                        const char* known_ip = wc_dns_get_known_ip(ctx->erx_marker_host);
                        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                            "%s", (known_ip && known_ip[0]) ? known_ip : "unknown");
                    }
                }
            } else if (cfg && cfg->debug) {
                fprintf(stderr,
                    "[DEBUG] ERX baseline recheck failed: rc=%d\n",
                    recheck_rc);
            }
            wc_lookup_result_free(&recheck_res);
        }
    }
    if (ctx->erx_marker_seen && !ctx->redirect_cap_hit && ctx->rir_cycle_exhausted && ctx->erx_marker_host && ctx->erx_marker_host[0] &&
        (!out->meta.authoritative_host[0] ||
         strcasecmp(out->meta.authoritative_host, "unknown") == 0 ||
         strcasecmp(out->meta.authoritative_host, "error") == 0)) {
        const char* canon_host = wc_dns_canonical_alias(ctx->erx_marker_host);
        const char* final_host = canon_host ? canon_host : ctx->erx_marker_host;
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", final_host);
        if (ctx->erx_marker_ip && ctx->erx_marker_ip[0]) {
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ctx->erx_marker_ip);
        } else {
            const char* known_ip = wc_dns_get_known_ip(final_host);
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                "%s", (known_ip && known_ip[0]) ? known_ip : "unknown");
        }
    }
    if (ctx->apnic_erx_root && !ctx->redirect_cap_hit) {
        const char* apnic_host = (ctx->apnic_erx_root_host && ctx->apnic_erx_root_host[0])
            ? ctx->apnic_erx_root_host
            : "whois.apnic.net";
        if (wc_dns_is_ip_literal(apnic_host)) {
            const char* mapped = wc_lookup_known_ip_host_from_literal(apnic_host);
            apnic_host = mapped ? mapped : "whois.apnic.net";
        }
        const char* final_rir = (out->meta.authoritative_host[0]
            ? wc_guess_rir(out->meta.authoritative_host)
            : NULL);
        int non_apnic_authority = (final_rir &&
            (strcasecmp(final_rir, "arin") == 0 ||
             strcasecmp(final_rir, "ripe") == 0 ||
             strcasecmp(final_rir, "afrinic") == 0 ||
             strcasecmp(final_rir, "lacnic") == 0));
        int authoritative_apnic = (out->meta.authoritative_host[0] && strcasecmp(out->meta.authoritative_host, apnic_host) == 0);
        int apnic_ip_mismatch = (authoritative_apnic && out->meta.authoritative_ip[0] &&
            !wc_lookup_ip_matches_host(out->meta.authoritative_ip, apnic_host));
        int should_collapse = ctx->redirect_cap_hit || ctx->rir_cycle_exhausted || apnic_ip_mismatch ||
            (authoritative_apnic && (out->meta.authoritative_ip[0] == '\0' || strcasecmp(out->meta.authoritative_ip, "unknown") == 0));
        if (ctx->erx_baseline_recheck_attempted &&
            (!out->meta.authoritative_host[0] ||
             strcasecmp(out->meta.authoritative_host, "unknown") == 0 ||
             strcasecmp(out->meta.authoritative_host, "error") == 0)) {
            should_collapse = 0;
        }
        if (out->meta.authoritative_host[0] &&
            strcasecmp(out->meta.authoritative_host, "unknown") != 0 &&
            final_rir && strcasecmp(final_rir, "apnic") != 0) {
            should_collapse = 0;
        } else if (ctx->apnic_redirect_is_erx && non_apnic_authority) {
            should_collapse = 0;
        }
        if (should_collapse) {
            int visited_arin = wc_lookup_visited_has(ctx->visited, ctx->visited_count, "whois.arin.net");
            int visited_ripe = wc_lookup_visited_has(ctx->visited, ctx->visited_count, "whois.ripe.net");
            int visited_afrinic = wc_lookup_visited_has(ctx->visited, ctx->visited_count, "whois.afrinic.net");
            int visited_lacnic = wc_lookup_visited_has(ctx->visited, ctx->visited_count, "whois.lacnic.net");
            int insert_all = (out->meta.fallback_flags & 0x10) || ctx->rir_cycle_exhausted || non_apnic_authority ? 1 : 0;
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_host);
            if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip[0] && wc_lookup_ip_matches_host(ctx->apnic_erx_root_ip, apnic_host)) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ctx->apnic_erx_root_ip);
            } else if (ctx->apnic_erx_root_ip && ctx->apnic_erx_root_ip[0] && wc_guess_rir(apnic_host) &&
                       strcasecmp(wc_guess_rir(apnic_host), "apnic") == 0) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ctx->apnic_erx_root_ip);
            } else if (ctx->apnic_last_ip && ctx->apnic_last_ip[0] && wc_lookup_ip_matches_host(ctx->apnic_last_ip, apnic_host)) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ctx->apnic_last_ip);
            } else if (out->meta.via_host[0] && strcasecmp(out->meta.via_host, apnic_host) == 0 && out->meta.via_ip[0]) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", out->meta.via_ip);
            } else {
                const char* known_apnic_ip = wc_dns_get_known_ip(apnic_host);
                if (known_apnic_ip && known_apnic_ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", known_apnic_ip);
                } else {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            }
            if (combined) {
                if ((insert_all || visited_arin) && !wc_lookup_has_hop_header(combined, "whois.arin.net") &&
                    !wc_lookup_host_tokens_equal(ctx->start_label, "whois.arin.net")) {
                    combined = wc_lookup_insert_header_before_authoritative(combined, "whois.arin.net");
                }
                if ((insert_all || visited_ripe) && !wc_lookup_has_hop_header(combined, "whois.ripe.net") &&
                    !wc_lookup_host_tokens_equal(ctx->start_label, "whois.ripe.net")) {
                    combined = wc_lookup_insert_header_before_authoritative(combined, "whois.ripe.net");
                }
                if ((insert_all || visited_afrinic) && !wc_lookup_has_hop_header(combined, "whois.afrinic.net") &&
                    !wc_lookup_host_tokens_equal(ctx->start_label, "whois.afrinic.net")) {
                    combined = wc_lookup_insert_header_before_authoritative(combined, "whois.afrinic.net");
                }
                if ((insert_all || visited_lacnic) && !wc_lookup_has_hop_header(combined, "whois.lacnic.net") &&
                    !wc_lookup_host_tokens_equal(ctx->start_label, "whois.lacnic.net")) {
                    combined = wc_lookup_insert_header_before_authoritative(combined, "whois.lacnic.net");
                }
                wc_lookup_compact_hop_headers(combined);
            }
        }
    }
    if (ctx->erx_marker_seen && !ctx->redirect_cap_hit && ctx->erx_marker_host && ctx->erx_marker_host[0]) {
        if (!out->meta.authoritative_host[0] ||
            (strcasecmp(out->meta.authoritative_host, "unknown") == 0 &&
             !ctx->erx_baseline_recheck_attempted)) {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", ctx->erx_marker_host);
            if (ctx->erx_marker_ip && ctx->erx_marker_ip[0]) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ctx->erx_marker_ip);
            } else {
                const char* known_ip = wc_dns_get_known_ip(ctx->erx_marker_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s",
                    (known_ip && known_ip[0]) ? known_ip : "unknown");
            }
        }
    }
    if (out->meta.authoritative_host[0] &&
        strcasecmp(out->meta.authoritative_host, "unknown") != 0 &&
        strcasecmp(out->meta.authoritative_host, "error") != 0) {
        const char* canon = wc_dns_canonical_alias(out->meta.authoritative_host);
        if (canon && strcasecmp(canon, out->meta.authoritative_host) != 0) {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", canon);
        }
    }

    if (ctx->saw_rate_limit_or_denied && out->meta.authoritative_host[0] &&
        strcasecmp(out->meta.authoritative_host, "unknown") == 0) {
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "error");
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "error");
        if (!ctx->failure_emitted && out->meta.last_connect_errno == 0) {
            char ts[32];
            wc_lookup_format_time(ts, sizeof(ts));
            if (!ctx->last_failure_host[0]) {
                const char* fallback_host = out->meta.last_host[0] ? out->meta.last_host : ctx->current_host;
                if (fallback_host && *fallback_host) {
                    snprintf(ctx->last_failure_host, ctx->last_failure_host_len, "%s", fallback_host);
                } else if (ctx->start_host && *ctx->start_host) {
                    snprintf(ctx->last_failure_host, ctx->last_failure_host_len, "%s", ctx->start_host);
                }
            }
            if (!ctx->last_failure_ip[0] && out->meta.last_ip[0]) {
                snprintf(ctx->last_failure_ip, ctx->last_failure_ip_len, "%s", out->meta.last_ip);
            }
            const char* err_host = ctx->last_failure_host[0] ? ctx->last_failure_host : "unknown";
            const char* err_ip = ctx->last_failure_ip[0] ? ctx->last_failure_ip : "unknown";
            fprintf(stderr,
                "Error: Query failed for %s (status=%s, desc=%s, rir=%s, host=%s, ip=%s, time=%s)\n",
                q->raw,
                ctx->last_failure_status,
                ctx->last_failure_desc,
                ctx->last_failure_rir[0] ? ctx->last_failure_rir : "unknown",
                err_host,
                err_ip,
                ts);
            ctx->failure_emitted = 1;
        }
    }

    if (combined) {
        int show_non_auth = cfg && cfg->show_non_auth_body;
        int show_post_marker = cfg && cfg->show_post_marker_body;
        if (!show_non_auth && !show_post_marker) {
            wc_lookup_strip_bodies_before_authoritative_hop(combined, ctx->start_host, out->meta.authoritative_host);
            wc_lookup_strip_bodies_after_authoritative_hop(combined, ctx->start_host, out->meta.authoritative_host);
        } else if (show_non_auth && !show_post_marker) {
            wc_lookup_strip_bodies_after_authoritative_hop(combined, ctx->start_host, out->meta.authoritative_host);
        } else if (!show_non_auth && show_post_marker) {
            wc_lookup_strip_bodies_before_authoritative_hop(combined, ctx->start_host, out->meta.authoritative_host);
        }
        wc_lookup_compact_hop_headers(combined);
    }
    ctx->combined = combined;
    out->body = combined;
    out->body_len = (combined ? strlen(combined) : 0);
    out->meta.failure_emitted = ctx->failure_emitted;
}
