// SPDX-License-Identifier: MIT
// lookup_exec_connect.c - Dial + DNS candidate handling for lookup exec
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "wc/wc_dns.h"
#include "wc/wc_ip_pref.h"
#include "wc/wc_known_ips.h"
#include "wc/wc_net.h"
#include "wc/wc_selftest.h"
#include "wc/wc_server.h"
#include "wc/wc_util.h"
#include "lookup_internal.h"
#include "lookup_exec_connect.h"

int wc_lookup_exec_connect(struct wc_lookup_exec_connect_ctx* ctx) {
    if (!ctx || !ctx->out || !ctx->zopts || !ctx->cfg || !ctx->current_host || !ctx->ni ||
        !ctx->cfg_for_dns || !ctx->cfg_override || !ctx->hop_prefers_v4 || !ctx->arin_host ||
        !ctx->connected_ok || !ctx->first_conn_rc || !ctx->attempt_cap_hit ||
        !ctx->canonical_host || !ctx->pref_label) {
        return -1;
    }

    struct wc_result* out = ctx->out;
    const struct wc_lookup_opts* zopts = ctx->zopts;
    const Config* cfg = ctx->cfg;
    wc_net_context_t* net_ctx = ctx->net_ctx;
    const char* current_host = ctx->current_host;

    *ctx->connected_ok = 0;
    *ctx->first_conn_rc = 0;
    *ctx->attempt_cap_hit = 0;

    const char* rir = wc_guess_rir(current_host);
    int base_prefers_v4 = wc_ip_pref_prefers_ipv4_first(cfg->ip_pref_mode, ctx->hops);
    int hop_prefers_v4 = base_prefers_v4;
    int rir_pref = WC_RIR_IP_PREF_UNSET;
    if (rir) {
        if (strcasecmp(rir, "iana") == 0) rir_pref = cfg->rir_pref_iana;
        else if (strcasecmp(rir, "arin") == 0) rir_pref = cfg->rir_pref_arin;
        else if (strcasecmp(rir, "ripe") == 0) rir_pref = cfg->rir_pref_ripe;
        else if (strcasecmp(rir, "apnic") == 0) rir_pref = cfg->rir_pref_apnic;
        else if (strcasecmp(rir, "lacnic") == 0) rir_pref = cfg->rir_pref_lacnic;
        else if (strcasecmp(rir, "afrinic") == 0) rir_pref = cfg->rir_pref_afrinic;
        else if (strcasecmp(rir, "verisign") == 0) rir_pref = cfg->rir_pref_verisign;
    }
    int use_rir_pref = (rir_pref != WC_RIR_IP_PREF_UNSET && !cfg->ipv4_only && !cfg->ipv6_only);
    if (use_rir_pref) {
        hop_prefers_v4 = (rir_pref == WC_RIR_IP_PREF_V4) ? 1 : 0;
    }
    int arin_host = (rir && strcasecmp(rir, "arin") == 0);
    int arin_ipv4_query = (arin_host && ctx->query_is_ipv4_literal_effective);
    int arin_ipv4_override = (arin_ipv4_query && !cfg->ipv6_only);

    *ctx->hop_prefers_v4 = hop_prefers_v4;
    *ctx->arin_host = arin_host;

    wc_ip_pref_format_label(cfg->ip_pref_mode, ctx->hops, ctx->pref_label, ctx->pref_label_len);

    struct wc_net_info ni;
    ni.connected = 0;
    ni.fd = -1;
    ni.ip[0] = '\0';

    ctx->canonical_host[0] = '\0';
    wc_lookup_compute_canonical_host(current_host, rir, ctx->canonical_host, ctx->canonical_host_len);

    wc_dns_candidate_list_t candidates = {0};
    const Config* cfg_for_dns = cfg;
    if (use_rir_pref) {
        *ctx->cfg_override = *cfg;
        ctx->cfg_override->dns_family_mode = (rir_pref == WC_RIR_IP_PREF_V4)
            ? WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK
            : WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
        ctx->cfg_override->dns_family_mode_set = 1;
        ctx->cfg_override->dns_family_mode_first = ctx->cfg_override->dns_family_mode;
        ctx->cfg_override->dns_family_mode_next = ctx->cfg_override->dns_family_mode;
        ctx->cfg_override->dns_family_mode_first_set = 1;
        ctx->cfg_override->dns_family_mode_next_set = 1;
        cfg_for_dns = ctx->cfg_override;
        snprintf(ctx->pref_label, ctx->pref_label_len, "rir-%s",
                 (rir_pref == WC_RIR_IP_PREF_V4) ? "v4" : "v6");
    }
    *ctx->cfg_for_dns = cfg_for_dns;

    int dns_build_rc = wc_dns_build_candidates(cfg_for_dns, current_host, rir, hop_prefers_v4,
        ctx->hops, &candidates, net_ctx ? net_ctx->injection : NULL);
    if (candidates.last_error != 0) {
        wc_lookup_log_dns_error(current_host,
            ctx->canonical_host[0] ? ctx->canonical_host : current_host,
            candidates.last_error,
            candidates.negative_cache_hit,
            net_ctx,
            cfg);
    }
    wc_lookup_log_dns_health(ctx->canonical_host[0] ? ctx->canonical_host : current_host, AF_INET, net_ctx, cfg);
    wc_lookup_log_dns_health(ctx->canonical_host[0] ? ctx->canonical_host : current_host, AF_INET6, net_ctx, cfg);
    if (dns_build_rc != 0) {
        out->err = -1;
        wc_dns_candidate_list_free(&candidates);
        return -1;
    }
    wc_lookup_log_candidates(ctx->hops + 1, current_host, rir, &candidates,
        ctx->canonical_host, ctx->pref_label, net_ctx, cfg);

    int arin_forced_index = -1;
    int* arin_candidate_order = NULL;
    if (arin_ipv4_override && arin_forced_index >= 0 && candidates.count > 1) {
        arin_candidate_order = (int*)malloc(sizeof(int) * candidates.count);
        if (arin_candidate_order) {
            int pos = 0;
            arin_candidate_order[pos++] = arin_forced_index;
            for (int i = 0; i < candidates.count; ++i) {
                if (i == arin_forced_index) continue;
                arin_candidate_order[pos++] = i;
            }
        }
    }

    int primary_attempts = 0;
    int penalized_skipped = 0;
    char penalized_first_target[128]; penalized_first_target[0] = '\0';
    int penalized_first_family = AF_UNSPEC;
    wc_dns_health_snapshot_t penalized_first_snap; memset(&penalized_first_snap, 0, sizeof(penalized_first_snap));
    char penalized_second_target[128]; penalized_second_target[0] = '\0';
    int penalized_second_family = AF_UNSPEC;
    wc_dns_health_snapshot_t penalized_second_snap; memset(&penalized_second_snap, 0, sizeof(penalized_second_snap));

    int host_attempt_cap = (cfg->max_host_addrs > 0 ? cfg->max_host_addrs : 0);
    int host_attempts = 0;
    int connected_ok = 0;
    int first_conn_rc = 0;

    for (int order_idx = 0; order_idx < candidates.count; ++order_idx) {
        if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
            break;
        }
        int i = arin_candidate_order ? arin_candidate_order[order_idx] : order_idx;
        const char* target = candidates.items[i];
        if (!target) continue;
        if (i > 0 && strcasecmp(target, current_host) == 0) continue;
        int candidate_family = wc_lookup_family_to_af(
            (candidates.families && i < candidates.count) ?
                candidates.families[i] : (unsigned char)WC_DNS_FAMILY_UNKNOWN,
            target);
        int is_last_candidate = (order_idx == candidates.count - 1);
        wc_dns_health_snapshot_t backoff_snap;
        int penalized = wc_dns_should_skip_logged(cfg, current_host, target,
            candidate_family,
            is_last_candidate ? "force-last" : "skip",
            &backoff_snap, net_ctx);
        if (penalized && !is_last_candidate) {
            penalized_skipped++;
            if (!penalized_first_target[0]) {
                snprintf(penalized_first_target, sizeof(penalized_first_target), "%s", target);
                penalized_first_family = candidate_family;
                penalized_first_snap = backoff_snap;
            } else if (!penalized_second_target[0] && candidate_family != penalized_first_family) {
                snprintf(penalized_second_target, sizeof(penalized_second_target), "%s", target);
                penalized_second_family = candidate_family;
                penalized_second_snap = backoff_snap;
            }
            continue;
        }
        if (penalized && is_last_candidate) {
            /* Already logged via wc_dns_should_skip_logged */
        }
        int dial_timeout_ms = zopts->timeout_sec * 1000;
        int dial_retries = zopts->retries;
        if (dial_timeout_ms <= 0) dial_timeout_ms = 1000;
        primary_attempts++;
        int rc = wc_dial_43(net_ctx, target, (uint16_t)ctx->current_port,
            dial_timeout_ms, dial_retries, &ni);
        host_attempts++;
        int attempt_success = (rc == 0 && ni.connected);
        wc_lookup_record_backoff_result(cfg, target, candidate_family, attempt_success);
        if (wc_lookup_should_trace_dns(net_ctx, cfg) && i > 0) {
            wc_lookup_log_fallback(ctx->hops + 1, "connect-fail", "candidate", current_host,
                                   target, attempt_success ? "success" : "fail",
                                   out->meta.fallback_flags,
                                   attempt_success ? 0 : ni.last_errno,
                                   -1,
                                   ctx->pref_label,
                                   net_ctx,
                                   cfg);
        }
        if (attempt_success) {
            connected_ok = 1;
            break;
        } else {
            if (order_idx == 0) first_conn_rc = rc;
        }
    }

    if (arin_candidate_order) {
        free(arin_candidate_order);
        arin_candidate_order = NULL;
    }

    if (!connected_ok && primary_attempts == 0 && penalized_skipped > 0 && penalized_first_target[0]) {
        const char* override_targets[2] = { penalized_first_target, penalized_second_target[0] ? penalized_second_target : NULL };
        const int override_families[2] = { penalized_first_family, penalized_second_target[0] ? penalized_second_family : AF_UNSPEC };
        const wc_dns_health_snapshot_t* override_snaps[2] = { &penalized_first_snap, penalized_second_target[0] ? &penalized_second_snap : NULL };
        for (int oi = 0; oi < 2; ++oi) {
            if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                break;
            }
            if (!override_targets[oi]) continue;
            int dial_timeout_ms = zopts->timeout_sec * 1000;
            int dial_retries = zopts->retries;
            if (dial_timeout_ms <= 0) dial_timeout_ms = 1000;
            primary_attempts++;
            wc_dns_health_snapshot_t log_snap;
            wc_dns_health_snapshot_t* log_snap_ptr = NULL;
            if (override_snaps[oi]) {
                log_snap = *override_snaps[oi];
                log_snap_ptr = &log_snap;
            }
            (void)wc_dns_should_skip_logged(cfg, current_host, override_targets[oi],
                override_families[oi], "force-override",
                log_snap_ptr, net_ctx);
            int rc = wc_dial_43(net_ctx, override_targets[oi], (uint16_t)ctx->current_port,
                dial_timeout_ms, dial_retries, &ni);
            host_attempts++;
            int attempt_success = (rc == 0 && ni.connected);
            wc_lookup_record_backoff_result(cfg, override_targets[oi], override_families[oi], attempt_success);
            if (wc_lookup_should_trace_dns(net_ctx, cfg)) {
                wc_lookup_log_fallback(ctx->hops + 1, "connect-fail", "candidate", current_host,
                                       override_targets[oi], attempt_success ? "success" : "fail",
                                       out->meta.fallback_flags,
                                       attempt_success ? 0 : ni.last_errno,
                                       -1,
                                       ctx->pref_label,
                                       net_ctx,
                                       cfg);
            }
            if (attempt_success) {
                connected_ok = 1;
                break;
            } else if (first_conn_rc == 0) {
                first_conn_rc = rc;
            }
        }
    }

    if (!connected_ok) {
        if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
            *ctx->attempt_cap_hit = 1;
        }
        // Phase-in step 1: try forcing IPv4 for the same domain (if domain is not an IP literal)
        const char* domain_for_ipv4 = NULL;
        if (!wc_dns_is_ip_literal(current_host)) {
            domain_for_ipv4 = current_host;
        } else {
            const char* ch = wc_dns_canonical_host_for_rir(rir);
            domain_for_ipv4 = ch ? ch : NULL;
        }
        const char* domain_for_known = NULL;
        if (!wc_dns_is_ip_literal(current_host)) {
            domain_for_known = current_host;
        } else {
            const char* ch = wc_dns_canonical_host_for_rir(rir);
            domain_for_known = ch ? ch : NULL;
        }
        const char* known_ip_literal_cached = NULL;
        int known_ip_available_for_attempt = 0;
        if (domain_for_known && !cfg->no_dns_known_fallback && !cfg->dns_no_fallback) {
            known_ip_literal_cached = wc_dns_get_known_ip(domain_for_known);
            if (known_ip_literal_cached && known_ip_literal_cached[0]) {
                known_ip_available_for_attempt = 1;
            }
        }
        int forced_ipv4_attempted = 0;
        int forced_ipv4_success = 0;
        int forced_ipv4_errno = 0;
        char forced_ipv4_target[64]; forced_ipv4_target[0] = '\0';
        if (domain_for_ipv4 && !cfg->no_dns_force_ipv4_fallback && !cfg->ipv6_only) {
            if (cfg->dns_no_fallback) {
                wc_lookup_log_fallback(ctx->hops + 1, "connect-fail", "no-op",
                                       domain_for_ipv4 ? domain_for_ipv4 : current_host,
                                       "(none)",
                                       "skipped",
                                       out->meta.fallback_flags,
                                       0,
                                       -1,
                                       ctx->pref_label,
                                       net_ctx,
                                       cfg);
            } else {
                int skip_forced_ipv4 = wc_lookup_should_skip_fallback(
                    current_host,
                    domain_for_ipv4,
                    AF_INET,
                    known_ip_available_for_attempt,
                    net_ctx,
                    cfg);
                if (!skip_forced_ipv4) {
                    wc_selftest_record_forced_ipv4_attempt();
                    struct addrinfo hints, *res = NULL;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;
                    int gai = 0, tries = 0;
                    int maxtries = (cfg->dns_retry > 0 ? cfg->dns_retry : 1);
                    do {
                        gai = getaddrinfo(domain_for_ipv4, NULL, &hints, &res);
                        if (gai == EAI_AGAIN && tries < maxtries - 1) {
                            int ms = (cfg->dns_retry_interval_ms >= 0 ? cfg->dns_retry_interval_ms : 100);
                            struct timespec ts;
                            ts.tv_sec = ms / 1000;
                            ts.tv_nsec = (long)((ms % 1000) * 1000000L);
                            nanosleep(&ts, NULL);
                        }
                        tries++;
                    } while (gai == EAI_AGAIN && tries < maxtries);
                    if (gai == 0 && res) {
                        char ipbuf[64]; ipbuf[0] = '\0';
                        for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
                            if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                                break;
                            }
                            if (p->ai_family == AF_INET) {
                                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                                if (inet_ntop(AF_INET, &(ipv4->sin_addr), ipbuf, sizeof(ipbuf))) {
                                    struct wc_net_info ni4;
                                    int rc4;
                                    ni4.connected = 0;
                                    ni4.fd = -1;
                                    ni4.ip[0] = '\0';
                                    rc4 = wc_dial_43(net_ctx, ipbuf, (uint16_t)ctx->current_port,
                                        zopts->timeout_sec * 1000, zopts->retries, &ni4);
                                    host_attempts++;
                                    forced_ipv4_attempted = 1;
                                    snprintf(forced_ipv4_target, sizeof(forced_ipv4_target), "%s", ipbuf);
                                    int backoff_success = (rc4 == 0 && ni4.connected);
                                    wc_lookup_record_backoff_result(cfg, ipbuf, AF_INET, backoff_success);
                                    if (backoff_success) {
                                        ni = ni4;
                                        connected_ok = 1;
                                        out->meta.fallback_flags |= 0x4;
                                        forced_ipv4_success = 1;
                                        forced_ipv4_errno = 0;
                                        break;
                                    } else {
                                        forced_ipv4_success = 0;
                                        forced_ipv4_errno = ni4.last_errno;
                                        if (ni4.fd >= 0) {
                                            int debug_enabled = cfg ? cfg->debug : 0;
                                            wc_safe_close(&ni4.fd, "wc_lookup_forced_ipv4_fail", debug_enabled);
                                        }
                                    }
                                }
                            }
                        }
                        freeaddrinfo(res);
                    }
                }
            }
        }
        if (forced_ipv4_attempted) {
            wc_lookup_log_fallback(ctx->hops + 1, "connect-fail", "forced-ipv4",
                                   domain_for_ipv4 ? domain_for_ipv4 : current_host,
                                   forced_ipv4_target[0] ? forced_ipv4_target : "(none)",
                                   forced_ipv4_success ? "success" : "fail",
                                   out->meta.fallback_flags,
                                   forced_ipv4_success ? 0 : forced_ipv4_errno,
                                   -1,
                                   ctx->pref_label,
                                   net_ctx,
                                   cfg);
        }

        // Phase-in step 2: try known IPv4 fallback for canonical domain (do not change current_host for metadata)
        int known_ip_attempted = 0;
        int known_ip_success = 0;
        int known_ip_errno = 0;
        const char* known_ip_target = NULL;
        if (!connected_ok && domain_for_known && !cfg->no_dns_known_fallback && !cfg->ipv6_only) {
            if (cfg->dns_no_fallback) {
                wc_lookup_log_fallback(ctx->hops + 1, "connect-fail", "no-op",
                                       domain_for_known ? domain_for_known : current_host,
                                       "(none)",
                                       "skipped",
                                       out->meta.fallback_flags,
                                       0,
                                       -1,
                                       ctx->pref_label,
                                       net_ctx,
                                       cfg);
            } else {
                const char* kip = known_ip_literal_cached;
                if (kip && kip[0]) {
                    wc_lookup_should_skip_fallback(current_host,
                                                   domain_for_known,
                                                   AF_UNSPEC,
                                                   0,
                                                   net_ctx,
                                                   cfg);
                    wc_selftest_record_known_ip_attempt();
                    struct wc_net_info ni2;
                    int rc2;
                    ni2.connected = 0;
                    ni2.fd = -1;
                    ni2.ip[0] = '\0';
                    known_ip_attempted = 1;
                    known_ip_target = kip;
                    rc2 = wc_dial_43(net_ctx, kip, (uint16_t)ctx->current_port,
                        zopts->timeout_sec * 1000, zopts->retries, &ni2);
                    int known_backoff_success = (rc2 == 0 && ni2.connected);
                    wc_lookup_record_backoff_result(cfg, kip, AF_UNSPEC, known_backoff_success);
                    if (rc2 == 0 && ni2.connected) {
                        ni = ni2;
                        connected_ok = 1;
                        out->meta.fallback_flags |= 0x1;
                        if (strchr(kip, ':') == NULL && strchr(kip, '.') != NULL) {
                            out->meta.fallback_flags |= 0x4;
                        }
                        known_ip_success = 1;
                        known_ip_errno = 0;
                    } else {
                        known_ip_success = 0;
                        known_ip_errno = ni2.last_errno;
                        if (ni2.fd >= 0) {
                            int debug_enabled = cfg ? cfg->debug : 0;
                            wc_safe_close(&ni2.fd, "wc_lookup_known_ip_fail", debug_enabled);
                        }
                    }
                }
            }
        }
        if (known_ip_attempted) {
            wc_lookup_log_fallback(ctx->hops + 1, "connect-fail", "known-ip",
                                   domain_for_known ? domain_for_known : current_host,
                                   known_ip_target ? known_ip_target : "(none)",
                                   known_ip_success ? "success" : "fail",
                                   out->meta.fallback_flags,
                                   known_ip_success ? 0 : known_ip_errno,
                                   -1,
                                   ctx->pref_label,
                                   net_ctx,
                                   cfg);
        }
    }

    wc_dns_candidate_list_free(&candidates);

    *ctx->ni = ni;
    *ctx->connected_ok = connected_ok;
    *ctx->first_conn_rc = first_conn_rc;
    *ctx->attempt_cap_hit = (host_attempt_cap > 0 && host_attempts >= host_attempt_cap);

    return 0;
}
