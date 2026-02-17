// SPDX-License-Identifier: MIT
// lookup_exec_empty.c - Empty-body handling for lookup exec
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
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
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_selftest.h"
#include "wc/wc_util.h"
#include "lookup_internal.h"
#include "lookup_exec_empty.h"

int wc_lookup_exec_handle_empty_body(struct wc_lookup_exec_empty_ctx* ctx) {
    if (!ctx || !ctx->out || !ctx->q || !ctx->body || !ctx->blen || !ctx->empty_retry) return 0;

    struct wc_result* out = ctx->out;
    const struct wc_query* q = ctx->q;
    const struct wc_lookup_opts* zopts = ctx->zopts;
    const Config* cfg = ctx->cfg;
    const Config* cfg_for_dns = ctx->cfg_for_dns ? ctx->cfg_for_dns : cfg;
    wc_net_context_t* net_ctx = ctx->net_ctx;
    const char* current_host = ctx->current_host ? ctx->current_host : "";
    const char* canonical_host = ctx->canonical_host ? ctx->canonical_host : "";
    const char* pref_label = ctx->pref_label ? ctx->pref_label : "";
    struct wc_net_info* ni = ctx->ni;

    char* body = *ctx->body;
    size_t blen = *ctx->blen;

    int arin_banner_only = 0;
    int persistent_empty_local = 0;

    if (blen > 0) {
        const char* rir_empty = wc_guess_rir(current_host);
        if (rir_empty && strcasecmp(rir_empty, "arin") == 0 &&
            wc_lookup_body_is_arin_banner_only(body)) {
            arin_banner_only = 1;
            blen = 0;
        }
    }
    if (blen > 0 && body && wc_lookup_body_is_semantically_empty(body)) {
        blen = 0;
    }

    if (blen == 0 || arin_banner_only) {
        const char* rir_empty = wc_guess_rir(current_host);
        int handled_empty = 0;
        int arin_mode = (rir_empty && strcasecmp(rir_empty, "arin") == 0);
        int retry_budget = arin_mode ? 2 : 1; // ARIN allows more tolerance; others once
        int allow_empty_retry = (*ctx->empty_retry < retry_budget);

        if (allow_empty_retry) {
            // Rebuild candidates and pick a different one than current_host and last connected ip
            wc_dns_candidate_list_t cands2 = {0};
            int cands2_rc = wc_dns_build_candidates(cfg_for_dns, current_host, rir_empty,
                ctx->hop_prefers_v4, ctx->hops, &cands2, net_ctx ? net_ctx->injection : NULL);
            if (cands2.last_error != 0) {
                wc_lookup_log_dns_error(current_host, canonical_host, cands2.last_error,
                    cands2.negative_cache_hit, net_ctx, cfg);
            }
            const char* pick = NULL;
            if (cands2_rc == 0) {
                for (int i = 0; i < cands2.count; i++) {
                    const char* t = cands2.items[i];
                    if (strcasecmp(t, current_host) == 0) continue;
                    // Prefer IP literal that differs from last connected ip
                    // Update last errno (0 if connected ok)
                    out->meta.last_connect_errno = ni && ni->connected ? 0 : (ni ? ni->last_errno : 0);
                    if (wc_dns_is_ip_literal(t) && ni && ni->ip[0] && strcmp(t, ni->ip) != 0) {
                        pick = t;
                        break;
                    }
                    if (!pick) pick = t;
                }
            }
            if (pick) {
                fprintf(stderr,
                    "[EMPTY-RESP] action=retry hop=%d mode=fallback-host host=%s target=%s query=%s rir=%s\n",
                    ctx->hops,
                    current_host,
                    pick,
                    q && q->raw ? q->raw : "",
                    rir_empty ? rir_empty : "unknown");
                handled_empty = 1;
                (*ctx->empty_retry)++;
                wc_lookup_log_fallback(ctx->hops + 1, "empty-body", "candidate",
                                       current_host, pick, "success",
                                       out->meta.fallback_flags, 0, *ctx->empty_retry,
                                       pref_label, net_ctx, cfg);
            }
            wc_dns_candidate_list_free(&cands2);
        }

        // Unified fallback extension: if still not handled, attempt IPv4-only re-dial of same logical domain
        if (!handled_empty && allow_empty_retry && !cfg->no_dns_force_ipv4_fallback && !cfg->ipv6_only) {
            const char* domain_for_ipv4 = NULL;
            if (!wc_dns_is_ip_literal(current_host)) domain_for_ipv4 = current_host; else {
                const char* ch = wc_dns_canonical_host_for_rir(rir_empty);
                if (ch) domain_for_ipv4 = ch;
            }
            if (domain_for_ipv4) {
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
                    char ipbuf[64];
                    ipbuf[0] = '\0';
                    int empty_ipv4_attempted = 0;
                    int empty_ipv4_success = 0;
                    int empty_ipv4_errno = 0;
                    int empty_ipv4_retry_metric = -1;
                    for (struct addrinfo* p = res; p; p = p->ai_next) {
                        if (p->ai_family != AF_INET) continue;
                        struct sockaddr_in* a = (struct sockaddr_in*)p->ai_addr;
                        if (inet_ntop(AF_INET, &(a->sin_addr), ipbuf, sizeof(ipbuf))) {
                            struct wc_net_info ni4;
                            int rc4;
                            ni4.connected = 0;
                            ni4.fd = -1;
                            ni4.ip[0] = '\0';
                            rc4 = wc_dial_43(net_ctx, ipbuf, (uint16_t)ctx->current_port,
                                zopts->timeout_sec * 1000, zopts->retries, &ni4);
                            empty_ipv4_attempted = 1;
                            int empty_backoff_success = (rc4 == 0 && ni4.connected);
                            wc_lookup_record_backoff_result(cfg, ipbuf, AF_INET, empty_backoff_success);
                            if (empty_backoff_success) {
                                fprintf(stderr,
                                    "[EMPTY-RESP] action=retry hop=%d mode=forced-ipv4 host=%s target=%s query=%s rir=%s\n",
                                    ctx->hops,
                                    current_host,
                                    ipbuf,
                                    q && q->raw ? q->raw : "",
                                    rir_empty ? rir_empty : "unknown");
                                if (ni) {
                                    *ni = ni4;
                                }
                                handled_empty = 1;
                                (*ctx->empty_retry)++;
                                out->meta.fallback_flags |= 0x4;
                                empty_ipv4_success = 1;
                                empty_ipv4_errno = 0;
                                empty_ipv4_retry_metric = *ctx->empty_retry;
                                break;
                            } else {
                                if (ni4.fd >= 0) {
                                    int debug_enabled = cfg ? cfg->debug : 0;
                                    wc_safe_close(&ni4.fd, "wc_lookup_empty_ipv4_fail", debug_enabled);
                                }
                            }
                            if (!empty_ipv4_success) {
                                empty_ipv4_errno = ni4.last_errno;
                            }
                        }
                    }
                    if (empty_ipv4_attempted) {
                        wc_lookup_log_fallback(ctx->hops + 1, "empty-body", "forced-ipv4",
                                               domain_for_ipv4, ipbuf[0] ? ipbuf : "(none)",
                                               empty_ipv4_success ? "success" : "fail",
                                               out->meta.fallback_flags,
                                               empty_ipv4_success ? 0 : empty_ipv4_errno,
                                               empty_ipv4_success ? empty_ipv4_retry_metric : -1,
                                               pref_label, net_ctx, cfg);
                    }
                    freeaddrinfo(res);
                }
            }
        }

        // Unified fallback extension: try known IPv4 mapping if still unhandled
        if (!handled_empty && allow_empty_retry && !cfg->no_dns_known_fallback && !cfg->ipv6_only) {
            const char* domain_for_known = NULL;
            if (!wc_dns_is_ip_literal(current_host)) domain_for_known = current_host; else {
                const char* ch = wc_dns_canonical_host_for_rir(rir_empty);
                if (ch) domain_for_known = ch;
            }
            if (domain_for_known) {
                wc_selftest_record_known_ip_attempt();
                const char* kip = wc_dns_get_known_ip(domain_for_known);
                if (kip && kip[0]) {
                    struct wc_net_info ni2;
                    int rc2;
                    ni2.connected = 0;
                    ni2.fd = -1;
                    ni2.ip[0] = '\0';
                    rc2 = wc_dial_43(net_ctx, kip, (uint16_t)ctx->current_port,
                        zopts->timeout_sec * 1000, zopts->retries, &ni2);
                    int empty_known_success = (rc2 == 0 && ni2.connected);
                    wc_lookup_record_backoff_result(cfg, kip, AF_UNSPEC, empty_known_success);
                    if (empty_known_success) {
                        fprintf(stderr,
                            "[EMPTY-RESP] action=retry hop=%d mode=known-ip host=%s target=%s query=%s rir=%s\n",
                            ctx->hops,
                            current_host,
                            kip,
                            q && q->raw ? q->raw : "",
                            rir_empty ? rir_empty : "unknown");
                        if (ni) {
                            *ni = ni2;
                        }
                        handled_empty = 1;
                        (*ctx->empty_retry)++;
                        out->meta.fallback_flags |= 0x1;
                        if (strchr(kip, ':') == NULL && strchr(kip, '.') != NULL) {
                            out->meta.fallback_flags |= 0x4;
                        }
                        wc_lookup_log_fallback(ctx->hops + 1, "empty-body", "known-ip",
                                               domain_for_known, kip, "success",
                                               out->meta.fallback_flags, 0, *ctx->empty_retry,
                                               pref_label, net_ctx, cfg);
                    } else {
                        wc_lookup_log_fallback(ctx->hops + 1, "empty-body", "known-ip",
                                               domain_for_known, kip, "fail",
                                               out->meta.fallback_flags, ni2.last_errno, -1,
                                               pref_label, net_ctx, cfg);
                        if (ni2.fd >= 0) {
                            int debug_enabled = cfg ? cfg->debug : 0;
                            wc_safe_close(&ni2.fd, "wc_lookup_empty_known_fail", debug_enabled);
                        }
                    }
                }
            }
        }

        if (!handled_empty && allow_empty_retry && *ctx->empty_retry == 0) {
            // last resort: once per host
            fprintf(stderr,
                "[EMPTY-RESP] action=retry hop=%d mode=same-host host=%s target=%s query=%s rir=%s\n",
                ctx->hops,
                current_host,
                current_host,
                q && q->raw ? q->raw : "",
                rir_empty ? rir_empty : "unknown");
            handled_empty = 1;
            (*ctx->empty_retry)++;
            wc_lookup_log_fallback(ctx->hops + 1, "empty-body", "candidate",
                                   current_host, current_host, "success",
                                   out->meta.fallback_flags, 0, *ctx->empty_retry,
                                   pref_label, net_ctx, cfg);
        }

        if (handled_empty) {
            out->meta.fallback_flags |= 0x2; // empty_retry
            if (body) free(body);
            body = NULL;
            blen = 0;
            if (cfg && cfg->dns_retry_interval_ms != 0) {
                int backoff_ms = (cfg->dns_retry_interval_ms >= 0) ? cfg->dns_retry_interval_ms : 50;
                if (backoff_ms > 0) {
                    struct timespec ts;
                    ts.tv_sec = backoff_ms / 1000;
                    ts.tv_nsec = (long)((backoff_ms % 1000) * 1000000L);
                    nanosleep(&ts, NULL);
                }
            }
            *ctx->body = body;
            *ctx->blen = blen;
            return 1;
        } else if (blen == 0) {
            // Give up – annotate and proceed (will be treated as non-authoritative and may pivot)
            fprintf(stderr,
                "[EMPTY-RESP] action=give-up hop=%d host=%s query=%s rir=%s\n",
                ctx->hops,
                current_host,
                q && q->raw ? q->raw : "",
                rir_empty ? rir_empty : "unknown");
            persistent_empty_local = 1;
        }
    }

    *ctx->body = body;
    *ctx->blen = blen;
    if (ctx->persistent_empty) {
        *ctx->persistent_empty = persistent_empty_local;
    }
    return 0;
}
