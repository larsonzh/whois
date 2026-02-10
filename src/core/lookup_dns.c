// SPDX-License-Identifier: MIT
// lookup_dns.c - DNS candidate and logging helpers for lookup
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>

#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "wc/wc_config.h"
#include "wc/wc_dns.h"
#include "wc/wc_net.h"
#include "lookup_internal.h"

int wc_lookup_should_trace_dns(const wc_net_context_t* net_ctx, const Config* cfg) {
    if (cfg && cfg->debug) return 1;
    return wc_net_context_retry_metrics_enabled(net_ctx);
}

static const char* wc_lookup_origin_label(wc_dns_origin_t origin) {
    switch (origin) {
        case WC_DNS_ORIGIN_INPUT: return "input";
        case WC_DNS_ORIGIN_SELFTEST: return "selftest";
        case WC_DNS_ORIGIN_CACHE: return "cache";
        case WC_DNS_ORIGIN_RESOLVER: return "resolver";
        case WC_DNS_ORIGIN_KNOWN: return "known";
        default: break;
    }
    return "unknown";
}

static const char* wc_lookup_family_label(unsigned char fam, const char* token) {
    switch (fam) {
        case WC_DNS_FAMILY_IPV4: return "ipv4";
        case WC_DNS_FAMILY_IPV6: return "ipv6";
        case WC_DNS_FAMILY_HOST: return "host";
        default:
            if (token && wc_dns_is_ip_literal(token)) {
                return (strchr(token, ':') != NULL) ? "ipv6" : "ipv4";
            }
            return "host";
    }
}

int wc_lookup_family_to_af(unsigned char fam, const char* token) {
    switch (fam) {
        case WC_DNS_FAMILY_IPV4: return AF_INET;
        case WC_DNS_FAMILY_IPV6: return AF_INET6;
        default:
            break;
    }
    if (token && wc_dns_is_ip_literal(token)) {
        return (strchr(token, ':') != NULL) ? AF_INET6 : AF_INET;
    }
    return AF_UNSPEC;
}

int wc_lookup_effective_family(int family_hint, const char* token) {
    if (family_hint == AF_INET || family_hint == AF_INET6) {
        return family_hint;
    }
    if (token && wc_dns_is_ip_literal(token)) {
        return (strchr(token, ':') != NULL) ? AF_INET6 : AF_INET;
    }
    return AF_UNSPEC;
}

void wc_lookup_record_backoff_result(const Config* cfg,
                                     const char* token,
                                     int family_hint,
                                     int success) {
    if (!token || !*token) {
        return;
    }
    int effective_family = wc_lookup_effective_family(family_hint, token);
    if (success) {
        wc_dns_note_success(cfg, token, effective_family);
    } else {
        wc_dns_note_failure(cfg, token, effective_family);
    }
}

void wc_lookup_compute_canonical_host(const char* current_host,
                                      const char* rir,
                                      char* out,
                                      size_t out_len) {
    if (!out || out_len == 0) return;
    const char* fallback = "whois.iana.org";
    if (current_host && !wc_dns_is_ip_literal(current_host)) {
        snprintf(out, out_len, "%s", current_host);
        return;
    }
    const char* canon = wc_dns_canonical_host_for_rir(rir);
    if (canon) {
        snprintf(out, out_len, "%s", canon);
    } else if (current_host && *current_host) {
        snprintf(out, out_len, "%s", current_host);
    } else {
        snprintf(out, out_len, "%s", fallback);
    }
}

static void wc_lookup_format_fallback_flags(unsigned int flags, char* buf, size_t len) {
    if (!buf || len == 0) return;
    buf[0] = '\0';
    const char* names[5];
    int idx = 0;
    if (flags & 0x1) names[idx++] = "known-ip";
    if (flags & 0x2) names[idx++] = "empty-retry";
    if (flags & 0x4) names[idx++] = "forced-ipv4";
    if (flags & 0x8) names[idx++] = "iana-pivot";
    if (flags & 0x10) names[idx++] = "redirect-cap";
    if (idx == 0) {
        snprintf(buf, len, "%s", "none");
        return;
    }
    size_t used = 0;
    for (int i = 0; i < idx; ++i) {
        int written = snprintf(buf + used, (used < len ? len - used : 0), "%s%s", (i == 0 ? "" : "|"), names[i]);
        if (written < 0) break;
        used += (size_t)written;
        if (used >= len) break;
    }
}

void wc_lookup_log_candidates(int hop,
                              const char* server,
                              const char* rir,
                              const wc_dns_candidate_list_t* cands,
                              const char* canonical_host,
                              const char* pref_label,
                              const wc_net_context_t* net_ctx,
                              const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg) || !cands) return;
    (void)canonical_host;
    const char* rir_label = (rir && *rir) ? rir : "unknown";
    const char* server_label = (server && *server) ? server : "unknown";
    int limit_hit = (cfg && cfg->dns_max_candidates > 0 && cands->limit_hit);
    if (cands->count == 0) {
        fprintf(stderr,
            "[DNS-CAND] hop=%d server=%s rir=%s idx=-1 target=NONE type=none origin=none",
            hop, server_label, rir_label);
        if (pref_label && *pref_label) fprintf(stderr, " pref=%s", pref_label);
        if (limit_hit) fprintf(stderr, " limit=%d", cfg->dns_max_candidates);
        fputc('\n', stderr);
        return;
    }
    for (int i = 0; i < cands->count; ++i) {
        const char* target = (cands->items && cands->items[i]) ? cands->items[i] : "UNKNOWN";
        unsigned char fam = (cands->families && i < cands->count) ? cands->families[i] : (unsigned char)WC_DNS_FAMILY_UNKNOWN;
        unsigned char origin_code = (cands->origins && i < cands->count) ? cands->origins[i] : (unsigned char)WC_DNS_ORIGIN_RESOLVER;
        const char* type = wc_lookup_family_label(fam, target);
        const char* origin = wc_lookup_origin_label(origin_code);
        fprintf(stderr,
            "[DNS-CAND] hop=%d server=%s rir=%s idx=%d target=%s type=%s origin=%s",
            hop, server_label, rir_label, i, target, type, origin);
        if (pref_label && *pref_label) fprintf(stderr, " pref=%s", pref_label);
        if (limit_hit) fprintf(stderr, " limit=%d", cfg->dns_max_candidates);
        fputc('\n', stderr);
    }

    wc_dns_cache_stats_t stats;
    if (wc_dns_get_cache_stats(&stats) == 0) {
        fprintf(stderr,
                "[DNS-CACHE] hits=%ld neg_hits=%ld misses=%ld\n",
                stats.hits, stats.negative_hits, stats.misses);
    }
}

void wc_lookup_log_fallback(int hop,
                            const char* cause,
                            const char* action,
                            const char* domain,
                            const char* target,
                            const char* status,
                            unsigned int flags,
                            int err_no,
                            int empty_retry_count,
                            const char* pref_label,
                            const wc_net_context_t* net_ctx,
                            const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg)) return;
    char flagbuf[64];
    wc_lookup_format_fallback_flags(flags, flagbuf, sizeof(flagbuf));
    fprintf(stderr,
                "[DNS-FALLBACK] hop=%d cause=%s action=%s domain=%s target=%s status=%s flags=%s",
            hop,
            (cause && *cause) ? cause : "unknown",
            (action && *action) ? action : "unknown",
            (domain && *domain) ? domain : "unknown",
            (target && *target) ? target : "unknown",
            (status && *status) ? status : "unknown",
            flagbuf[0] ? flagbuf : "none");
    if (pref_label && *pref_label) fprintf(stderr, " pref=%s", pref_label);
    if (err_no > 0) fprintf(stderr, " errno=%d", err_no);
    if (empty_retry_count >= 0) fprintf(stderr, " empty_retry=%d", empty_retry_count);
    fputc('\n', stderr);
}

void wc_lookup_log_dns_error(const char* host,
                             const char* canonical_host,
                             int gai_error,
                             int negative_cache,
                             const wc_net_context_t* net_ctx,
                             const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg) || gai_error == 0) return;
    const char* source = negative_cache ? "negative-cache" : "resolver";
    const char* detail = gai_strerror(gai_error);
    fprintf(stderr,
        "[DNS-ERROR] host=%s canonical=%s source=%s gai_err=%d message=%s\n",
        (host && *host) ? host : "unknown",
        (canonical_host && *canonical_host) ? canonical_host : "unknown",
        source,
        gai_error,
        detail ? detail : "n/a");
}

int wc_lookup_should_skip_fallback(const char* server,
                                  const char* candidate,
                                  int family,
                                  int allow_skip,
                                  const wc_net_context_t* net_ctx,
                                  const Config* cfg) {
    if (!candidate || !*candidate) {
        return 0;
    }
    wc_dns_health_snapshot_t snap;
    int penalized = wc_dns_should_skip_logged(cfg, server, candidate, family,
        allow_skip ? "skip" : "force-last", &snap, net_ctx);
    return allow_skip ? penalized : 0;
}

void wc_lookup_log_dns_health(const char* host,
                              int family,
                              const wc_net_context_t* net_ctx,
                              const Config* cfg) {
    if (!wc_lookup_should_trace_dns(net_ctx, cfg)) return;
    wc_dns_health_snapshot_t snap;
    wc_dns_health_state_t st = wc_dns_health_get_state(cfg, host, family, &snap);
    const char* fam_label = (family == AF_INET) ? "ipv4" :
                (family == AF_INET6) ? "ipv6" : "unknown";
    const char* state_label = (st == WC_DNS_HEALTH_PENALIZED) ? "penalized" : "ok";
    fprintf(stderr,
        "[DNS-HEALTH] host=%s family=%s state=%s consec_fail=%d penalty_ms_left=%ld\n",
        (host && *host) ? host : "unknown",
        fam_label,
        state_label,
        snap.consecutive_failures,
        snap.penalty_ms_left);
}
