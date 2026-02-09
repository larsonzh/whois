// SPDX-License-Identifier: MIT
// lookup.c - Phase B skeleton implementation
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "wc/wc_config.h"
#include "wc/wc_runtime.h"
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"
#include "wc/wc_selftest.h"
#include "wc/wc_dns.h"
#include "wc/wc_ip_pref.h"
#include "wc/wc_known_ips.h"
#include "wc/wc_util.h"
#include "wc/wc_signal.h"
#include "lookup_internal.h"

#define APNIC_REDIRECT_NONE 0
#define APNIC_REDIRECT_ERX 1
#define APNIC_REDIRECT_IANA 2

static const Config* wc_lookup_resolve_config(const struct wc_lookup_opts* opts)
{
    if (!opts)
        return NULL;
    return opts->config;
}

static int wc_lookup_should_trace_dns(const wc_net_context_t* net_ctx, const Config* cfg) {
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

static int wc_lookup_family_to_af(unsigned char fam, const char* token) {
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

static int wc_lookup_effective_family(int family_hint, const char* token) {
    if (family_hint == AF_INET || family_hint == AF_INET6) {
        return family_hint;
    }
    if (token && wc_dns_is_ip_literal(token)) {
        return (strchr(token, ':') != NULL) ? AF_INET6 : AF_INET;
    }
    return AF_UNSPEC;
}

static void wc_lookup_record_backoff_result(const Config* cfg,
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

static void wc_lookup_compute_canonical_host(const char* current_host,
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

static int wc_lookup_erx_baseline_recheck_guard = 0;

static int wc_lookup_rir_cycle_next(const char* current_rir,
                                    char** visited,
                                    int visited_count,
                                    char* out,
                                    size_t outlen) {
    (void)current_rir;
    static const char* k_rir_cycle[] = {
        "apnic", "arin", "ripe", "afrinic", "lacnic", NULL
    };
    if (!out || outlen == 0) return 0;
    int count = 0;
    for (; k_rir_cycle[count]; ++count) { /* count */ }
    if (count == 0) return 0;

    int start_idx = 0; // always start from APNIC

    for (int i = 0; i < count; ++i) {
        int idx = (start_idx + i) % count;
        const char* rir = k_rir_cycle[idx];
        const char* host = wc_dns_canonical_host_for_rir(rir);
        if (!host || !*host) continue;
        int seen = 0;
        for (int v = 0; v < visited_count; ++v) {
            if (visited[v] && wc_lookup_hosts_match(visited[v], host)) {
                seen = 1;
                break;
            }
        }
        if (seen) continue;
        snprintf(out, outlen, "%s", host);
        return 1;
    }
    return 0;
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

static void wc_lookup_log_candidates(int hop,
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

static void wc_lookup_log_fallback(int hop,
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

static void wc_lookup_log_dns_error(const char* host,
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

static int wc_lookup_should_skip_fallback(const char* server,
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

static void wc_lookup_log_dns_health(const char* host,
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

static void wc_result_init(struct wc_result* r){
    if(!r) return;
    memset(r,0,sizeof(*r));
    r->err = 0;
    r->meta.via_host[0] = 0;
    r->meta.via_ip[0] = 0;
    r->meta.last_host[0] = 0;
    r->meta.last_ip[0] = 0;
    r->meta.authoritative_host[0] = 0;
    r->meta.authoritative_ip[0] = 0;
    r->meta.fallback_flags = 0; // initialize phased-in fallback bitset
        r->meta.last_connect_errno = 0; // initialize last connection errno
}

void wc_lookup_result_free(struct wc_result* r){ if(!r) return; if(r->body){ free(r->body); r->body=NULL; } r->body_len=0; }

// helper to append text to a growing buffer; frees base and returns new buffer
static char* append_and_free(char* base, const char* extra) {
    size_t la = base ? strlen(base) : 0;
    size_t lb = extra ? strlen(extra) : 0;
    char* n = (char*)malloc(la + lb + 1);
    if (!n) return base; // OOM: keep old to avoid leak
    if (base) memcpy(n, base, la);
    if (extra) memcpy(n + la, extra, lb);
    n[la + lb] = '\0';
    if (base) free(base);
    return n;
}

// local strdup to avoid feature-macro dependency differences across toolchains
static char* xstrdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

// Simple IP literal check (IPv4 dotted-decimal or presence of ':')
// Known-IP fallback mapping (defined in whois_client.c); phase-in with minimal coupling
// DNS fallback helper for well-known WHOIS servers.
extern const char* wc_dns_get_known_ip(const char* domain);

int wc_lookup_execute(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out) {
    if(!q || !q->raw || !out) return -1;
    struct wc_lookup_opts zopts = { .max_hops=5, .no_redirect=0, .timeout_sec=5, .retries=2, .net_ctx=NULL, .config=NULL };
    if(opts) zopts = *opts;
    const Config* cfg = wc_lookup_resolve_config(&zopts);
    wc_result_init(out);
    if (!cfg) {
        out->err = EINVAL;
        return -1;
    }
    wc_net_context_t* net_ctx = zopts.net_ctx ? zopts.net_ctx : wc_net_context_get_active();
    if (!net_ctx) {
        out->err = EINVAL;
        return -1;
    }
    if (wc_signal_should_terminate()) {
        out->err = WC_ERR_IO;
        out->meta.last_connect_errno = EINTR;
        return -1;
    }
    const wc_selftest_injection_t* injection = net_ctx ? net_ctx->injection : NULL;
    const wc_selftest_fault_profile_t* fault_profile = injection ? &injection->fault : NULL;
    int query_is_ipv4_literal = wc_lookup_query_is_ipv4_literal(q->raw);
    int query_is_ip_literal = wc_lookup_query_is_ip_literal(q->raw);
    int query_is_cidr = wc_lookup_query_is_cidr(q->raw);
    int query_is_asn = wc_lookup_query_is_asn(q->raw);
    int query_is_nethandle = wc_lookup_query_is_arin_nethandle(q->raw);
    int query_has_arin_prefix = wc_lookup_query_has_arin_prefix(q->raw);
    char* cidr_base_query = NULL;
    if (query_is_cidr) {
        cidr_base_query = wc_lookup_extract_cidr_base(q->raw);
    }
    int query_is_cidr_effective = query_is_cidr;
    int query_is_ip_literal_effective = query_is_ip_literal || (cidr_base_query != NULL);
    int query_is_ipv4_literal_effective = query_is_ipv4_literal ||
        (cidr_base_query && strchr(cidr_base_query, ':') == NULL);

    // Pick starting server: explicit -> canonical; else default to IANA
    // Keep a stable label to display in header: prefer the user-provided token verbatim when present
    char start_host[128];
    char start_label[128];
    if (q->start_server && q->start_server[0]) {
        // Prefer canonical RIR hostname for display even when the user passed
        // an IP literal (e.g., RIR numeric). This keeps headers stable:
        // "via whois.arin.net @ <ip>" instead of "via <ip> @ <ip>".
        const char* rir_guess = wc_guess_rir(q->start_server);
        const char* canon_label = NULL;
        if (rir_guess && strcmp(rir_guess, "unknown") != 0) {
            canon_label = wc_dns_canonical_host_for_rir(rir_guess);
        }
        if (!canon_label) {
            // fallback: allow direct alias mapping (arin/apnic/ripe/etc.).
            canon_label = wc_dns_canonical_host_for_rir(q->start_server);
        }
        char* mapped = NULL;
        if (!canon_label && wc_dns_is_ip_literal(q->start_server)) {
            mapped = wc_dns_rir_fallback_from_ip(cfg, q->start_server);
            if (mapped) {
                canon_label = mapped;
            }
        }

        if (canon_label) {
            snprintf(start_label, sizeof(start_label), "%s", canon_label);
        } else {
            snprintf(start_label, sizeof(start_label), "%s", q->start_server);
        }

        if (mapped) {
            free(mapped);
        }
    } else {
        snprintf(start_label, sizeof(start_label), "%s", "whois.iana.org");
    }
    if (q->start_server && q->start_server[0]) {
        if (wc_normalize_whois_host(q->start_server, start_host, sizeof(start_host)) != 0)
            snprintf(start_host, sizeof(start_host), "%s", q->start_server);
    } else {
        snprintf(start_host, sizeof(start_host), "%s", "whois.iana.org");
    }

    // Redirect loop with simple visited guard
    char* visited[16] = {0};
    int visited_count = 0;
    char current_host[128]; snprintf(current_host, sizeof(current_host), "%s", start_host);
    int current_port = (q->port > 0 ? q->port : 43);
    int hops = 0;
    int additional_emitted = 0; // first referral uses "Additional"
    int redirect_cap_hit = 0; // set when redirect limit stops the chain early
    char* combined = NULL;
    out->meta.hops = 0;
    int emit_redirect_headers = 1;

    int empty_retry = 0; // retry budget for empty-body anomalies within a hop (fallback hosts)
    char* arin_cidr_retry_query = NULL;
    int apnic_force_ip = 0;
    int apnic_revisit_used = 0;
    int apnic_ambiguous_revisit_used = 0;
    int stop_with_apnic_authority = 0;
    int stop_with_header_authority = 0;
    char header_authority_host[128];
    header_authority_host[0] = '\0';
    int apnic_redirect_reason = APNIC_REDIRECT_NONE;
    int force_original_query = 0;
    int pending_referral = 0;
    int last_hop_authoritative = 0;
    int last_hop_need_redirect = 0;
    int last_hop_has_ref = 0;
    Config cfg_override;
    const Config* cfg_for_dns = NULL;
    int apnic_erx_root = 0;
    char apnic_erx_ref_host[128];
    apnic_erx_ref_host[0] = '\0';
    char apnic_erx_target_rir[16];
    apnic_erx_target_rir[0] = '\0';
    int apnic_erx_stop = 0;
    char apnic_erx_stop_host[128];
    apnic_erx_stop_host[0] = '\0';
    int apnic_erx_stop_unknown = 0;
    int apnic_erx_ripe_non_managed = 0;
    char apnic_erx_root_host[128];
    apnic_erx_root_host[0] = '\0';
    char apnic_erx_root_ip[64];
    apnic_erx_root_ip[0] = '\0';
    int failure_emitted = 0;
    char last_failure_host[128];
    char last_failure_ip[64];
    char last_failure_rir[32];
    const char* last_failure_status = "unknown";
    const char* last_failure_desc = "unknown";
    last_failure_host[0] = '\0';
    last_failure_ip[0] = '\0';
    snprintf(last_failure_rir, sizeof(last_failure_rir), "%s", "unknown");
    char apnic_last_ip[64];
    apnic_last_ip[0] = '\0';
    int apnic_erx_seen_arin = 0;
    int rir_cycle_exhausted = 0;
    int apnic_erx_arin_before_apnic = 0;
    int apnic_erx_authoritative_stop = 0;
    int force_rir_cycle = 0;
    int seen_arin_no_match_cidr = 0;
    int seen_apnic_iana_netblock = 0;
    int seen_ripe_non_managed = 0;
    int seen_afrinic_iana_blk = 0;
    int seen_lacnic_unallocated = 0;
    int seen_real_authoritative = 0;
    int erx_marker_seen = 0;
    int saw_rate_limit_or_denied = 0;
    int erx_baseline_recheck_attempted = 0;
    char erx_marker_host[128];
    erx_marker_host[0] = '\0';
    char erx_marker_ip[64];
    erx_marker_ip[0] = '\0';
    int erx_fast_recheck_done = 0;
    int erx_fast_authoritative = 0;
    char erx_fast_authoritative_host[128];
    char erx_fast_authoritative_ip[64];
    erx_fast_authoritative_host[0] = '\0';
    erx_fast_authoritative_ip[0] = '\0';
    while (hops < zopts.max_hops) {
        if (wc_signal_should_terminate()) {
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            break;
        }
        apnic_erx_authoritative_stop = 0;
        force_rir_cycle = 0;
        // default last-hop markers for this iteration (helps error reporting on early failures)
        snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
        snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s", "unknown");
        // mark visited
        int already = 0;
        for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], current_host)==0) { already=1; break; } }
        if (!already && visited_count < 16) visited[visited_count++] = xstrdup(current_host);
        if (wc_dns_is_ip_literal(current_host)) {
            const char* mapped_host = wc_lookup_known_ip_host_from_literal(current_host);
            if (mapped_host && *mapped_host &&
                !wc_lookup_visited_has(visited, visited_count, mapped_host) && visited_count < 16) {
                visited[visited_count++] = xstrdup(mapped_host);
            }
        }
        const char* canon_visit = wc_dns_canonical_alias(current_host);
        if (canon_visit && canon_visit[0] && strcasecmp(canon_visit, current_host) != 0) {
            if (!wc_lookup_visited_has(visited, visited_count, canon_visit) && visited_count < 16) {
                visited[visited_count++] = xstrdup(canon_visit);
            }
        }

        // connect (dynamic DNS-derived candidate list; IPv6 preferred unless overridden)
        const char* rir = wc_guess_rir(current_host);
        int base_prefers_v4 = wc_ip_pref_prefers_ipv4_first(cfg->ip_pref_mode, hops);
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
        int arin_ipv4_query = (arin_host && query_is_ipv4_literal_effective);
        int arin_ipv4_override = (arin_ipv4_query && !cfg->ipv6_only);
        int arin_retry_active = 0;
        char pref_label[32];
        wc_ip_pref_format_label(cfg->ip_pref_mode, hops, pref_label, sizeof(pref_label));
        struct wc_net_info ni; int rc; ni.connected=0; ni.fd=-1; ni.ip[0]='\0';
        char canonical_host[128]; canonical_host[0]='\0';
        wc_lookup_compute_canonical_host(current_host, rir, canonical_host, sizeof(canonical_host));
        wc_dns_candidate_list_t candidates = {0};
        cfg_for_dns = cfg;
        if (use_rir_pref) {
            cfg_override = *cfg;
            cfg_override.dns_family_mode = (rir_pref == WC_RIR_IP_PREF_V4)
                ? WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK
                : WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
            cfg_override.dns_family_mode_set = 1;
            cfg_override.dns_family_mode_first = cfg_override.dns_family_mode;
            cfg_override.dns_family_mode_next = cfg_override.dns_family_mode;
            cfg_override.dns_family_mode_first_set = 1;
            cfg_override.dns_family_mode_next_set = 1;
            cfg_for_dns = &cfg_override;
            snprintf(pref_label, sizeof(pref_label), "rir-%s", (rir_pref == WC_RIR_IP_PREF_V4) ? "v4" : "v6");
        }
        int dns_build_rc = wc_dns_build_candidates(cfg_for_dns, current_host, rir, hop_prefers_v4, hops, &candidates, injection);
        if (candidates.last_error != 0) {
            wc_lookup_log_dns_error(current_host, canonical_host, candidates.last_error, candidates.negative_cache_hit, net_ctx, cfg);
        }
        // Log current DNS health for both IPv4 and IPv6 families. This is
        // observability-only in Phase 3 step 2 and does not influence
        // candidate ordering or fallback decisions.
        wc_lookup_log_dns_health(canonical_host[0] ? canonical_host : current_host, AF_INET, net_ctx, cfg);
        wc_lookup_log_dns_health(canonical_host[0] ? canonical_host : current_host, AF_INET6, net_ctx, cfg);
        if (dns_build_rc != 0) {
            out->err = -1;
            wc_dns_candidate_list_free(&candidates);
            break;
        }
        wc_lookup_log_candidates(hops+1, current_host, rir, &candidates, canonical_host, pref_label, net_ctx, cfg);
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
        int connected_ok = 0; int first_conn_rc = 0;
        for (int order_idx=0; order_idx<candidates.count; ++order_idx){
                if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                    break;
                }
            int i = arin_candidate_order ? arin_candidate_order[order_idx] : order_idx;
            const char* target = candidates.items[i];
            if (!target) continue;
            // avoid duplicate immediate retry of identical token
            if (i>0 && strcasecmp(target, current_host)==0) continue;
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
            int dial_timeout_ms = zopts.timeout_sec * 1000;
            int dial_retries = zopts.retries;
            if (dial_timeout_ms <= 0) dial_timeout_ms = 1000;
            primary_attempts++;
            rc = wc_dial_43(net_ctx, target, (uint16_t)current_port, dial_timeout_ms, dial_retries, &ni);
            host_attempts++;
            int attempt_success = (rc==0 && ni.connected);
            wc_lookup_record_backoff_result(cfg, target, candidate_family, attempt_success);
            if (wc_lookup_should_trace_dns(net_ctx, cfg) && i>0) {
                wc_lookup_log_fallback(hops+1, "connect-fail", "candidate", current_host,
                                       target, attempt_success?"success":"fail",
                                       out->meta.fallback_flags,
                                       attempt_success?0:ni.last_errno,
                                       -1,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            }
            if (attempt_success){
                // Do not mutate logical current_host with numeric dial targets; keep it as the logical server label.
                connected_ok = 1; break;
            } else {
                if (order_idx==0) first_conn_rc = rc;
            }
        }
        if (arin_candidate_order) {
            free(arin_candidate_order);
            arin_candidate_order = NULL;
        }
        if (!connected_ok && primary_attempts == 0 && penalized_skipped > 0 && penalized_first_target[0]) {
            const char* override_targets[2] = { penalized_first_target, penalized_second_target[0]?penalized_second_target:NULL };
            const int override_families[2] = { penalized_first_family, penalized_second_target[0]?penalized_second_family:AF_UNSPEC };
            const wc_dns_health_snapshot_t* override_snaps[2] = { &penalized_first_snap, penalized_second_target[0]?&penalized_second_snap:NULL };
            for (int oi = 0; oi < 2; ++oi) {
                if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                    break;
                }
                if (!override_targets[oi]) continue;
                int dial_timeout_ms = zopts.timeout_sec * 1000;
                int dial_retries = zopts.retries;
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
                rc = wc_dial_43(net_ctx, override_targets[oi], (uint16_t)current_port, dial_timeout_ms, dial_retries, &ni);
                host_attempts++;
                int attempt_success = (rc==0 && ni.connected);
                wc_lookup_record_backoff_result(cfg, override_targets[oi], override_families[oi], attempt_success);
                if (wc_lookup_should_trace_dns(net_ctx, cfg)) {
                    wc_lookup_log_fallback(hops+1, "connect-fail", "candidate", current_host,
                                           override_targets[oi], attempt_success?"success":"fail",
                                           out->meta.fallback_flags,
                                           attempt_success?0:ni.last_errno,
                                           -1,
                                           pref_label,
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
        if(!connected_ok){
            if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                break;
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
            char forced_ipv4_target[64]; forced_ipv4_target[0]='\0';
            if (domain_for_ipv4 && !cfg->no_dns_force_ipv4_fallback && !cfg->ipv6_only) {
                if (cfg->dns_no_fallback) {
                    // In dns-no-fallback mode, log a skipped forced-IPv4 fallback and do not actually retry.
                    wc_lookup_log_fallback(hops+1, "connect-fail", "no-op",
                                           domain_for_ipv4 ? domain_for_ipv4 : current_host,
                                           "(none)",
                                           "skipped",
                                           out->meta.fallback_flags,
                                           0,
                                           -1,
                                           pref_label,
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
                        hints.ai_family = AF_INET; // IPv4 only
                        hints.ai_socktype = SOCK_STREAM;
                        int gai = 0, tries=0; int maxtries = (cfg->dns_retry>0?cfg->dns_retry:1);
                        do {
                            gai = getaddrinfo(domain_for_ipv4, NULL, &hints, &res);
                            if(gai==EAI_AGAIN && tries<maxtries-1){ int ms=(cfg->dns_retry_interval_ms>=0?cfg->dns_retry_interval_ms:100); struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)((ms%1000)*1000000L); nanosleep(&ts,NULL); }
                            tries++;
                        } while(gai==EAI_AGAIN && tries<maxtries);
                        if (gai == 0 && res) {
                            char ipbuf[64]; ipbuf[0]='\0';
                            for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
                                if (host_attempt_cap > 0 && host_attempts >= host_attempt_cap) {
                                    break;
                                }
                                if (p->ai_family == AF_INET) {
                                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                                    if (inet_ntop(AF_INET, &(ipv4->sin_addr), ipbuf, sizeof(ipbuf))) {
                                        struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                        rc4 = wc_dial_43(net_ctx, ipbuf, (uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries, &ni4);
                                        host_attempts++;
                                        forced_ipv4_attempted = 1;
                                        snprintf(forced_ipv4_target, sizeof(forced_ipv4_target), "%s", ipbuf);
                                        int backoff_success = (rc4==0 && ni4.connected);
                                        wc_lookup_record_backoff_result(cfg, ipbuf, AF_INET, backoff_success);
                                        if (backoff_success) {
                                            ni = ni4;
                                            connected_ok = 1;
                                            out->meta.fallback_flags |= 0x4; // forced_ipv4
                                            forced_ipv4_success = 1;
                                            forced_ipv4_errno = 0;
                                            break;
                                        } else {
                                            forced_ipv4_success = 0;
                                            forced_ipv4_errno = ni4.last_errno;
                                            if (ni4.fd>=0) {
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
                wc_lookup_log_fallback(hops+1, "connect-fail", "forced-ipv4",
                                       domain_for_ipv4 ? domain_for_ipv4 : current_host,
                                       forced_ipv4_target[0]?forced_ipv4_target:"(none)",
                                       forced_ipv4_success?"success":"fail",
                                       out->meta.fallback_flags,
                                       forced_ipv4_success?0:forced_ipv4_errno,
                                       -1,
                                       pref_label,
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
                    // In dns-no-fallback mode, log a skipped known-IP fallback and do not actually retry.
                    wc_lookup_log_fallback(hops+1, "connect-fail", "no-op",
                                           domain_for_known ? domain_for_known : current_host,
                                           "(none)",
                                           "skipped",
                                           out->meta.fallback_flags,
                                           0,
                                           -1,
                                           pref_label,
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
                        struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
                        known_ip_attempted = 1;
                        known_ip_target = kip;
                        rc2 = wc_dial_43(net_ctx, kip, (uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries, &ni2);
                        int known_backoff_success = (rc2==0 && ni2.connected);
                        wc_lookup_record_backoff_result(cfg, kip, AF_UNSPEC, known_backoff_success);
                        if (rc2==0 && ni2.connected) {
                            // connected via known IP; keep current_host unchanged (still canonical host)
                            ni = ni2;
                            connected_ok = 1;
                            out->meta.fallback_flags |= 0x1; // used_known_ip
                            // also mark forced IPv4 if the known IP is IPv4 literal
                            if (strchr(kip, ':')==NULL && strchr(kip, '.')!=NULL) {
                                out->meta.fallback_flags |= 0x4; // forced_ipv4
                            }
                            known_ip_success = 1;
                            known_ip_errno = 0;
                        } else {
                            known_ip_success = 0;
                            known_ip_errno = ni2.last_errno;
                            // ensure fd closed in failure path
                            if (ni2.fd>=0) {
                                int debug_enabled = cfg ? cfg->debug : 0;
                                wc_safe_close(&ni2.fd, "wc_lookup_known_ip_fail", debug_enabled);
                            }
                        }
                    }
                }
            }
            if (known_ip_attempted) {
                wc_lookup_log_fallback(hops+1, "connect-fail", "known-ip",
                                       domain_for_known ? domain_for_known : current_host,
                                       known_ip_target ? known_ip_target : "(none)",
                                       known_ip_success?"success":"fail",
                                       out->meta.fallback_flags,
                                       known_ip_success?0:known_ip_errno,
                                       -1,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            }
        }
        wc_dns_candidate_list_free(&candidates);
        if(!connected_ok){
            out->err = first_conn_rc?first_conn_rc:-1;
            out->meta.last_connect_errno = ni.last_errno; // propagate failure errno
            snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
            snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s",
                     ni.ip[0] ? ni.ip : "unknown");
            if (hops == 0) {
                if (out->meta.via_host[0] == 0) {
                    snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_label);
                }
                if (out->meta.via_ip[0] == 0) {
                    snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s",
                             ni.ip[0] ? ni.ip : "unknown");
                }
            }
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        if (wc_signal_should_terminate()) {
            int debug_enabled = cfg ? cfg->debug : 0;
            wc_safe_close(&ni.fd, "wc_lookup_signal_abort", debug_enabled);
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
            snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s",
                     ni.ip[0] ? ni.ip : "unknown");
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        // record last successful hop details
        snprintf(out->meta.last_host, sizeof(out->meta.last_host), "%s", current_host);
        snprintf(out->meta.last_ip, sizeof(out->meta.last_ip), "%s", ni.ip[0]?ni.ip:"unknown");
        if (hops == 0) {
            // record first hop meta: show the user-supplied starting server token when available
            snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_label);
            snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s", ni.ip[0]?ni.ip:"unknown");
        }

        // send query (auto prepend "n " for ARIN IPv4 literals when needed)
        arin_retry_active = (arin_cidr_retry_query != NULL);
        int use_original_query = force_original_query;
        force_original_query = 0;
        int query_is_cidr_hop = query_is_cidr_effective || use_original_query;
        int query_is_ip_literal_hop = query_is_ip_literal_effective;
        if (use_original_query) {
            query_is_ip_literal_hop = query_is_ip_literal;
        }
        const char* outbound_query = arin_cidr_retry_query ? arin_cidr_retry_query : q->raw;
        if (!arin_cidr_retry_query && cfg && cfg->cidr_strip_query && cidr_base_query && !use_original_query) {
            outbound_query = cidr_base_query;
        }
        char* stripped_query = NULL;
        int query_has_arin_prefix_effective = query_has_arin_prefix || arin_retry_active;
        if (!arin_retry_active && !arin_host && query_has_arin_prefix_effective) {
            stripped_query = wc_lookup_strip_query_prefix(q->raw);
            if (stripped_query)
                outbound_query = stripped_query;
        }
        if (stripped_query && wc_lookup_should_trace_dns(net_ctx, cfg)) {
            fprintf(stderr,
                "[DNS-ARIN] action=strip-prefix host=%s query=%s stripped=%s\n",
                current_host, q->raw, stripped_query);
        }
        char* arin_prefixed_query = wc_lookup_arin_build_query(outbound_query,
            arin_host,
            query_is_ip_literal_hop,
            query_is_cidr_hop,
            query_is_asn,
            query_is_nethandle,
            query_has_arin_prefix_effective);
        if (arin_prefixed_query) {
            outbound_query = arin_prefixed_query;
        }
        size_t qlen = strlen(outbound_query);
        char* line = (char*)malloc(qlen+3);
        if(!line){
            if (arin_prefixed_query) free(arin_prefixed_query);
            out->err=-1; { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_malloc_fail", debug_enabled); }
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        memcpy(line, outbound_query, qlen); line[qlen]='\r'; line[qlen+1]='\n'; line[qlen+2]='\0';
        if (wc_signal_should_terminate()) {
            free(line);
            if (arin_prefixed_query) free(arin_prefixed_query);
            if (stripped_query) free(stripped_query);
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_signal_abort", debug_enabled); }
            break;
        }
        if (wc_send_all(ni.fd, line, qlen+2, zopts.timeout_sec*1000) < 0){
            free(line);
            if (arin_prefixed_query) free(arin_prefixed_query);
            out->err=-1; { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_send_fail", debug_enabled); }
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }
        free(line);
        if (arin_prefixed_query) {
            free(arin_prefixed_query);
        }
        if (arin_cidr_retry_query) {
            free(arin_cidr_retry_query);
            arin_cidr_retry_query = NULL;
        }
        if (stripped_query) {
            free(stripped_query);
        }

        // receive
        char* body=NULL; size_t blen=0;
        if (wc_signal_should_terminate()) {
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_signal_abort", debug_enabled); }
            break;
        }
        int max_bytes = 65536;
        if (cfg && cfg->buffer_size > 0) {
            if (cfg->buffer_size > (size_t)INT_MAX) {
                max_bytes = INT_MAX;
            } else {
                max_bytes = (int)cfg->buffer_size;
            }
        }
        if (wc_recv_until_idle(ni.fd, &body, &blen, zopts.timeout_sec*1000, max_bytes) < 0){ out->err=-1; { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_recv_fail", debug_enabled); } if (pending_referral) { snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown"); } break; }
        { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni.fd, "wc_lookup_recv_done", debug_enabled); }

        if (wc_signal_should_terminate()) {
            if (body) free(body);
            out->err = WC_ERR_IO;
            out->meta.last_connect_errno = EINTR;
            if (pending_referral) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            }
            break;
        }

    // Selftest injection hook (one-shot): simulate empty-body anomaly for retry/fallback validation
    // Controlled via wc_selftest_set_inject_empty() (no environment dependency in release).
        {
            static int injected_once = 0;
            int inject_empty = (injection && injection->inject_empty) ? 1 : 0;
            if (inject_empty && !injected_once) {
                if (body) { free(body); body = NULL; }
                blen = 0; // force empty
                injected_once = 1;
            }
        }

        // Defensive: occasionally a connection succeeds but body is empty.
        // Treat an empty (or all-whitespace) body as transient and try a fallback
        // host (DNS-derived candidates; ARIN more tolerant, others single) to avoid
        // showing an "authoritative" tail with no data section.
        int arin_banner_only = 0;
        int persistent_empty = 0;
        if (blen > 0) {
            const char* rir_empty = wc_guess_rir(current_host);
            if (rir_empty && strcasecmp(rir_empty, "arin") == 0 &&
                wc_lookup_body_is_arin_banner_only(body)) {
                arin_banner_only = 1;
                blen = 0;
            }
        }
        if (blen > 0 && body && wc_lookup_body_is_comment_only(body)) {
            blen = 0;
        }
        if (blen > 0 && strspn(body, " \r\n\t") == blen) {
            blen = 0;
        }
        if (blen == 0 || arin_banner_only) {
            const char* rir_empty = wc_guess_rir(current_host);
            int handled_empty = 0;
            int arin_mode = (rir_empty && strcasecmp(rir_empty, "arin")==0);
            int retry_budget = arin_mode ? 2 : 1; // ARIN allows more tolerance; others once
            int allow_empty_retry = (empty_retry < retry_budget);
            if (allow_empty_retry) {
                // Rebuild candidates and pick a different one than current_host and last connected ip
                wc_dns_candidate_list_t cands2 = {0};
                int cands2_rc = wc_dns_build_candidates(cfg_for_dns ? cfg_for_dns : cfg, current_host, rir_empty, hop_prefers_v4, hops, &cands2, injection);
                if (cands2.last_error != 0) {
                    wc_lookup_log_dns_error(current_host, canonical_host, cands2.last_error, cands2.negative_cache_hit, net_ctx, cfg);
                }
                const char* pick=NULL;
                if (cands2_rc == 0) {
                    for(int i=0;i<cands2.count;i++){
                        const char* t = cands2.items[i];
                        if (strcasecmp(t, current_host)==0) continue;
                        // Prefer IP literal that differs from last connected ip
                        // Update last errno (0 if connected ok)
                        out->meta.last_connect_errno = ni.connected ? 0 : ni.last_errno;
                        if (wc_dns_is_ip_literal(t) && ni.ip[0] && strcmp(t, ni.ip)!=0) { pick=t; break; }
                        // else keep a non-literal as a fallback if nothing better
                        if (!pick) pick=t;
                    }
                }
                if (pick){
                    fprintf(stderr,
                        "[EMPTY-RESP] action=retry hop=%d mode=fallback-host host=%s target=%s query=%s rir=%s\n",
                        hops,
                        current_host,
                        pick,
                        q && q->raw ? q->raw : "",
                        rir_empty ? rir_empty : "unknown");
                    /* keep logical current_host unchanged; only change dial target */
                    handled_empty = 1; empty_retry++;
                    wc_lookup_log_fallback(hops+1, "empty-body", "candidate",
                                           current_host, pick, "success",
                                           out->meta.fallback_flags, 0, empty_retry,
                                           pref_label,
                                           net_ctx,
                                           cfg);
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
                    struct addrinfo hints,*res=NULL; memset(&hints,0,sizeof(hints)); hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
                    int gai=0, tries=0, maxtries=(cfg->dns_retry>0?cfg->dns_retry:1);
                    do { gai=getaddrinfo(domain_for_ipv4, NULL, &hints, &res); if(gai==EAI_AGAIN && tries<maxtries-1){ int ms=(cfg->dns_retry_interval_ms>=0?cfg->dns_retry_interval_ms:100); struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)((ms%1000)*1000000L); nanosleep(&ts,NULL);} tries++; } while(gai==EAI_AGAIN && tries<maxtries);
                    if (gai==0 && res){
                        char ipbuf[64]; ipbuf[0]='\0';
                        int empty_ipv4_attempted = 0;
                        int empty_ipv4_success = 0;
                        int empty_ipv4_errno = 0;
                        int empty_ipv4_retry_metric = -1;
                        for(struct addrinfo* p=res; p; p=p->ai_next){ if(p->ai_family!=AF_INET) continue; struct sockaddr_in* a=(struct sockaddr_in*)p->ai_addr; if(inet_ntop(AF_INET,&(a->sin_addr),ipbuf,sizeof(ipbuf))){
                                struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                rc4 = wc_dial_43(net_ctx, ipbuf,(uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries,&ni4);
                                empty_ipv4_attempted = 1;
                                int empty_backoff_success = (rc4==0 && ni4.connected);
                                wc_lookup_record_backoff_result(cfg, ipbuf, AF_INET, empty_backoff_success);
                                if(empty_backoff_success){
                                    fprintf(stderr,
                                        "[EMPTY-RESP] action=retry hop=%d mode=forced-ipv4 host=%s target=%s query=%s rir=%s\n",
                                        hops,
                                        current_host,
                                        ipbuf,
                                        q && q->raw ? q->raw : "",
                                        rir_empty ? rir_empty : "unknown");
                                    // reuse current_host (logical) but replace ni context
                                    ni = ni4; handled_empty = 1; empty_retry++; out->meta.fallback_flags |= 0x4;
                                    empty_ipv4_success = 1;
                                    empty_ipv4_errno = 0;
                                    empty_ipv4_retry_metric = empty_retry;
                                    break; }
                                else { if(ni4.fd>=0) { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni4.fd, "wc_lookup_empty_ipv4_fail", debug_enabled); } }
                                if (!empty_ipv4_success) {
                                    empty_ipv4_errno = ni4.last_errno;
                                }
                            }}
                        if (empty_ipv4_attempted) {
                            wc_lookup_log_fallback(hops+1, "empty-body", "forced-ipv4",
                                                   domain_for_ipv4, ipbuf[0]?ipbuf:"(none)",
                                                   empty_ipv4_success?"success":"fail",
                                                   out->meta.fallback_flags,
                                                   empty_ipv4_success?0:empty_ipv4_errno,
                                                   empty_ipv4_success?empty_ipv4_retry_metric:-1,
                                                   pref_label,
                                                   net_ctx,
                                                   cfg);
                        }
                        freeaddrinfo(res);
                    }
                }
            }

            // Unified fallback extension: try known IPv4 mapping if still unhandled
            if (!handled_empty && allow_empty_retry && !cfg->no_dns_known_fallback && !cfg->ipv6_only) {
                const char* domain_for_known=NULL;
                if (!wc_dns_is_ip_literal(current_host)) domain_for_known=current_host; else {
                    const char* ch = wc_dns_canonical_host_for_rir(rir_empty); if (ch) domain_for_known=ch; }
                if (domain_for_known){
                    wc_selftest_record_known_ip_attempt();
                    const char* kip = wc_dns_get_known_ip(domain_for_known);
                    if (kip && kip[0]){
                        struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
                        rc2 = wc_dial_43(net_ctx, kip,(uint16_t)current_port, zopts.timeout_sec*1000, zopts.retries,&ni2);
                        int empty_known_success = (rc2==0 && ni2.connected);
                        wc_lookup_record_backoff_result(cfg, kip, AF_UNSPEC, empty_known_success);
                        if (empty_known_success){
                            fprintf(stderr,
                                "[EMPTY-RESP] action=retry hop=%d mode=known-ip host=%s target=%s query=%s rir=%s\n",
                                hops,
                                current_host,
                                kip,
                                q && q->raw ? q->raw : "",
                                rir_empty ? rir_empty : "unknown");
                            ni = ni2; handled_empty=1; empty_retry++; out->meta.fallback_flags |= 0x1; if(strchr(kip,':')==NULL && strchr(kip,'.')!=NULL) out->meta.fallback_flags |= 0x4;
                            wc_lookup_log_fallback(hops+1, "empty-body", "known-ip",
                                                   domain_for_known, kip, "success",
                                                   out->meta.fallback_flags, 0, empty_retry,
                                                   pref_label,
                                                   net_ctx,
                                                   cfg);
                        }
                        else {
                            wc_lookup_log_fallback(hops+1, "empty-body", "known-ip",
                                                   domain_for_known, kip, "fail",
                                                   out->meta.fallback_flags, ni2.last_errno, -1,
                                                   pref_label,
                                                   net_ctx,
                                                   cfg);
                            if(ni2.fd>=0) { int debug_enabled = cfg ? cfg->debug : 0; wc_safe_close(&ni2.fd, "wc_lookup_empty_known_fail", debug_enabled); } }
                    }
                }

            }
            if (!handled_empty && allow_empty_retry && empty_retry == 0) {
                // last resort: once per host
                fprintf(stderr,
                    "[EMPTY-RESP] action=retry hop=%d mode=same-host host=%s target=%s query=%s rir=%s\n",
                    hops,
                    current_host,
                    current_host,
                    q && q->raw ? q->raw : "",
                    rir_empty ? rir_empty : "unknown");
                handled_empty = 1; empty_retry++;
                wc_lookup_log_fallback(hops+1, "empty-body", "candidate",
                                       current_host, current_host, "success",
                                       out->meta.fallback_flags, 0, empty_retry,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            }

            if (handled_empty) {
                // mark fallback: empty-body driven retry
                out->meta.fallback_flags |= 0x2; // empty_retry
                if (body) free(body);
                body = NULL; blen = 0;
                if (cfg && cfg->dns_retry_interval_ms != 0) {
                    int backoff_ms = (cfg->dns_retry_interval_ms >= 0) ? cfg->dns_retry_interval_ms : 50;
                    if (backoff_ms > 0) {
                        struct timespec ts;
                        ts.tv_sec = backoff_ms / 1000;
                        ts.tv_nsec = (long)((backoff_ms % 1000) * 1000000L);
                        nanosleep(&ts, NULL);
                    }
                }
                // continue loop WITHOUT incrementing hops to reattempt this logical hop
                continue;
            } else if (blen == 0) {
                // Give up – annotate and proceed (will be treated as non-authoritative and may pivot)
                fprintf(stderr,
                    "[EMPTY-RESP] action=give-up hop=%d host=%s query=%s rir=%s\n",
                    hops,
                    current_host,
                    q && q->raw ? q->raw : "",
                    rir_empty ? rir_empty : "unknown");
                persistent_empty = 1;
            }
        } else {
            // successful non-empty body resets empty retry budget for next hop
            empty_retry = 0;
        }

        // ARIN CIDR no-match: do not retry with ARIN prefixes; follow normal RIR cycle.

        // Decide next action based on only the latest hop body (not the combined history)
        int auth = is_authoritative_response(body);
        int apnic_iana_netblock_cidr = 0;
        int apnic_erx_legacy = 0;
        /*
         * gTLD registry responses (e.g., whois.verisign-grs.com) often carry a
         * "Registrar WHOIS Server:" line that would trip the generic redirect
         * heuristics. Treat those registry hops as authoritative and suppress
         * redirects/referrals to avoid an unnecessary IANA pivot, even when the
         * hop was initiated via a literal IP (guarded by wc_guess_rir).
         */
        const char* current_rir_guess = wc_guess_rir(current_host);
        if (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 && !apnic_erx_root) {
            apnic_erx_arin_before_apnic = 1;
        }
        int is_gtld_registry = (strcasecmp(current_host, "whois.verisign-grs.com") == 0 ||
                                strcasecmp(current_host, "whois.crsnic.net") == 0 ||
                                (current_rir_guess && strcasecmp(current_rir_guess, "verisign") == 0));
        int need_redir_eval = (!is_gtld_registry) ? needs_redirect(body) : 0; // evaluate even when redirects disabled for logging
        int erx_marker_this_hop = wc_lookup_body_contains_erx_iana_marker(body);
        int ripe_non_managed = wc_lookup_body_contains_ripe_non_managed(body);
        int access_denied = wc_lookup_body_contains_access_denied(body);
        int rate_limited = wc_lookup_body_contains_rate_limit(body);
        char* ref = NULL;
        int ref_port = 0;
        char ref_host[128];
        ref_host[0] = '\0';
        if (!is_gtld_registry) {
            // Extract referral even when redirects are disabled, so we can surface
            // the pending hop in output ("=== Additional query to ... ===").
            ref = extract_refer_server(body);
            if (!ref) {
                ref = wc_lookup_extract_referral_fallback(body);
            }
        }
        if (ref) {
            int ref_parse_rc = wc_lookup_parse_referral_target(ref, ref_host, sizeof(ref_host), &ref_port);
            if (ref_parse_rc != 0 || ref_host[0] == '\0') {
                char ref_fallback[192];
                const char* raw = ref;
                size_t raw_len = strlen(raw);
                if (raw_len >= sizeof(ref_fallback)) raw_len = sizeof(ref_fallback) - 1;
                memcpy(ref_fallback, raw, raw_len);
                ref_fallback[raw_len] = '\0';
                // Trim leading whitespace
                char* start = ref_fallback;
                while (*start && isspace((unsigned char)*start)) start++;
                if (start != ref_fallback) {
                    memmove(ref_fallback, start, strlen(start) + 1);
                }
                // Strip schemes
                if (strncmp(ref_fallback, "whois://", 8) == 0) {
                    memmove(ref_fallback, ref_fallback + 8, strlen(ref_fallback + 8) + 1);
                } else if (strncmp(ref_fallback, "rwhois://", 9) == 0) {
                    memmove(ref_fallback, ref_fallback + 9, strlen(ref_fallback + 9) + 1);
                } else if (strncmp(ref_fallback, "http://", 7) == 0) {
                    memmove(ref_fallback, ref_fallback + 7, strlen(ref_fallback + 7) + 1);
                } else if (strncmp(ref_fallback, "https://", 8) == 0) {
                    memmove(ref_fallback, ref_fallback + 8, strlen(ref_fallback + 8) + 1);
                }
                // Trim after path
                char* slash = strchr(ref_fallback, '/');
                if (slash) *slash = '\0';
                // Trim trailing whitespace/punctuation
                size_t fb_len = strlen(ref_fallback);
                while (fb_len > 0) {
                    char c = ref_fallback[fb_len - 1];
                    if (isspace((unsigned char)c) || c == '.' || c == ',' || c == ';') {
                        ref_fallback[fb_len - 1] = '\0';
                        fb_len--;
                    } else {
                        break;
                    }
                }
                // Strip :port if present (single colon and all digits after it)
                char* colon = strchr(ref_fallback, ':');
                if (colon && strchr(colon + 1, ':') == NULL) {
                    int port_ok = 1;
                    for (const char* c = colon + 1; *c; ++c) {
                        if (!isdigit((unsigned char)*c)) { port_ok = 0; break; }
                    }
                    if (port_ok) *colon = '\0';
                }
                fb_len = strlen(ref_fallback);
                if (fb_len > 0 && fb_len + 1 <= sizeof(ref_host) &&
                    strchr(ref_fallback, '.') != NULL) {
                    int valid = 1;
                    for (size_t i = 0; i < fb_len; ++i) {
                        unsigned char c = (unsigned char)ref_fallback[i];
                        if (!(isalnum(c) || c == '-' || c == '.')) { valid = 0; break; }
                    }
                    if (valid) {
                        memcpy(ref_host, ref_fallback, fb_len + 1);
                        ref_port = 0;
                        ref_parse_rc = 0;
                    }
                }
            }
            if (ref_parse_rc != 0 || ref_host[0] == '\0') {
                free(ref);
                ref = NULL;
            }
        }
        if (ref) {
            char ref_norm[128];
            const char* cur_host = wc_dns_canonical_alias(current_host);
            if (!cur_host) {
                cur_host = current_host;
            }
            if (wc_normalize_whois_host(ref_host, ref_norm, sizeof(ref_norm)) != 0) {
                snprintf(ref_norm, sizeof(ref_norm), "%s", ref_host);
            }
            if (strchr(ref_norm, '.') == NULL || strlen(ref_norm) < 4) {
                free(ref);
                ref = NULL;
            } else if (cur_host && strcasecmp(ref_norm, cur_host) == 0) {
                free(ref);
                ref = NULL;
            }
        }
        int ref_explicit = (ref != NULL) ? wc_lookup_referral_is_explicit(body, ref_host) : 0;
        if (ref && !ref_explicit) {
            const char* ref_rir_explicit = wc_guess_rir(ref_host);
            if (current_rir_guess && ref_rir_explicit &&
                strcasecmp(ref_rir_explicit, "unknown") != 0 &&
                strcasecmp(ref_rir_explicit, current_rir_guess) != 0) {
                ref_explicit = 1;
            }
        }
        int apnic_erx_keep_ref = 0;
        if (ref && !ref_explicit) {
            char ref_norm_keep[128];
            if (wc_normalize_whois_host(ref_host, ref_norm_keep, sizeof(ref_norm_keep)) != 0) {
                snprintf(ref_norm_keep, sizeof(ref_norm_keep), "%s", ref_host);
            }
            const char* ref_rir_keep = wc_guess_rir(ref_norm_keep);
            if (ref_rir_keep &&
                (strcasecmp(ref_rir_keep, "afrinic") == 0 ||
                 strcasecmp(ref_rir_keep, "lacnic") == 0)) {
                apnic_erx_keep_ref = 1;
            }
        }
        if (ref && !ref_explicit && ripe_non_managed) {
            free(ref);
            ref = NULL;
        }
        if (apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX &&
            ref && !ref_explicit && !apnic_erx_keep_ref) {
            free(ref);
            ref = NULL;
        }
        if (ref && current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0 && apnic_erx_legacy && !ref_explicit && !apnic_erx_keep_ref) {
            free(ref);
            ref = NULL;
        }
        if (ref && apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX &&
            current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0 && apnic_erx_ripe_non_managed && !ref_explicit) {
            free(ref);
            ref = NULL;
        }
        if (apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX && apnic_erx_arin_before_apnic) {
        }
        if (apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX &&
            ref && ref_host[0] && current_rir_guess &&
            strcasecmp(current_rir_guess, "arin") == 0) {
            char ref_norm3[128];
            if (wc_normalize_whois_host(ref_host, ref_norm3, sizeof(ref_norm3)) != 0) {
                snprintf(ref_norm3, sizeof(ref_norm3), "%s", ref_host);
            }
            if (!apnic_erx_ref_host[0]) {
                snprintf(apnic_erx_ref_host, sizeof(apnic_erx_ref_host), "%s", ref_norm3);
            }
            const char* ref_rir = wc_guess_rir(ref_norm3);
            int ref_visited = 0;
            for (int i = 0; i < visited_count; ++i) {
                if (strcasecmp(visited[i], ref_norm3) == 0) { ref_visited = 1; break; }
            }
            if (!apnic_erx_stop && ref_rir && strcasecmp(ref_rir, "apnic") == 0 && ref_visited) {
                apnic_erx_stop = 1;
                snprintf(apnic_erx_stop_host, sizeof(apnic_erx_stop_host), "%s", ref_norm3);
            }
        }
        if (apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX &&
            current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0) {
            apnic_erx_seen_arin = 1;
            if (!apnic_erx_target_rir[0]) {
                if (wc_lookup_find_case_insensitive(body, "transferred to ripe") ||
                    wc_lookup_find_case_insensitive(body, "ripe network coordination centre") ||
                    (wc_lookup_find_case_insensitive(body, "netname:") &&
                     wc_lookup_find_case_insensitive(body, "ripe"))) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "ripe");
                } else if (wc_lookup_find_case_insensitive(body, "transferred to apnic") ||
                    wc_lookup_find_case_insensitive(body, "asia pacific network information centre") ||
                    (wc_lookup_find_case_insensitive(body, "netname:") &&
                     wc_lookup_find_case_insensitive(body, "apnic"))) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "apnic");
                } else if (wc_lookup_find_case_insensitive(body, "transferred to afrinic") ||
                    wc_lookup_find_case_insensitive(body, "afrinic")) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "afrinic");
                } else if (wc_lookup_find_case_insensitive(body, "transferred to lacnic") ||
                    wc_lookup_find_case_insensitive(body, "lacnic")) {
                    snprintf(apnic_erx_target_rir, sizeof(apnic_erx_target_rir), "%s", "lacnic");
                }
            }
            if (apnic_erx_target_rir[0] && strcasecmp(apnic_erx_target_rir, "apnic") == 0) {
            }
        }
        int banner_only = (!auth && body && *body && wc_lookup_body_is_comment_only(body));
        const char* header_host = wc_lookup_detect_rir_header_host(body);
        int header_is_iana = (header_host && strcasecmp(header_host, "whois.iana.org") == 0);
        int header_matches_current = 0;
        if (header_host && !header_is_iana) {
            char header_normh[128];
            char current_normh[128];
            const char* header_normp = wc_dns_canonical_alias(header_host);
            const char* current_normp = wc_dns_canonical_alias(current_host);
            if (!header_normp) header_normp = header_host;
            if (!current_normp) current_normp = current_host;
            if (wc_normalize_whois_host(header_normp, header_normh, sizeof(header_normh)) != 0) {
                snprintf(header_normh, sizeof(header_normh), "%s", header_normp);
            }
            if (wc_normalize_whois_host(current_normp, current_normh, sizeof(current_normh)) != 0) {
                snprintf(current_normh, sizeof(current_normh), "%s", current_normp);
            }
            if (strcasecmp(header_normh, current_normh) == 0) {
                header_matches_current = 1;
            }
        }
        if (header_matches_current && !auth && !banner_only) {
            if (!(current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0)) {
                auth = 1;
            }
        }
        char header_hint_host[128];
        header_hint_host[0] = '\0';
        int header_hint_valid = 0;
        if (current_rir_guess && strcasecmp(current_rir_guess, "lacnic") == 0) {
            int header_erx_hint = 0;
            if (wc_lookup_body_contains_erx_legacy(body) ||
                wc_lookup_body_contains_erx_netname(body) ||
                wc_lookup_body_contains_apnic_erx_hint(body)) {
                header_erx_hint = 1;
            }
            const char* implicit_host = NULL;
            if (header_host && !header_is_iana && !header_matches_current) {
                implicit_host = header_host;
            } else {
                implicit_host = "whois.apnic.net";
            }
            if (header_erx_hint && implicit_host && strcasecmp(implicit_host, "whois.apnic.net") == 0) {
                if (ref && !ref_explicit) {
                    free(ref);
                    ref = NULL;
                }
                if (!ref) {
                    if (!wc_lookup_visited_has(visited, visited_count, "whois.apnic.net") && visited_count < 16) {
                        visited[visited_count++] = xstrdup("whois.apnic.net");
                    }
                    apnic_erx_legacy = 1;
                    if (!apnic_erx_root) {
                        apnic_erx_root = 1;
                        if (apnic_redirect_reason == APNIC_REDIRECT_NONE) {
                            apnic_redirect_reason = APNIC_REDIRECT_ERX;
                        }
                        if (!apnic_erx_root_host[0]) {
                            snprintf(apnic_erx_root_host, sizeof(apnic_erx_root_host), "%s", "whois.apnic.net");
                        }
                    }
                    need_redir_eval = 1;
                }
            }
            if (header_host && !header_is_iana && !header_matches_current) {
                const char* header_rir = wc_guess_rir(header_host);
                if (header_rir && strcasecmp(header_rir, "unknown") != 0) {
                    if (wc_normalize_whois_host(header_host, header_hint_host, sizeof(header_hint_host)) != 0) {
                        snprintf(header_hint_host, sizeof(header_hint_host), "%s", header_host);
                    }
                    header_hint_valid = (header_hint_host[0] != '\0');
                    need_redir_eval = 1;
                    if (header_rir &&
                        (strcasecmp(header_rir, "apnic") == 0 ||
                         strcasecmp(header_rir, "ripe") == 0 ||
                         strcasecmp(header_rir, "afrinic") == 0)) {
                        int non_auth_internal = 0;
                        if (strcasecmp(header_rir, "apnic") == 0) {
                            if (wc_lookup_body_contains_apnic_iana_netblock(body) ||
                                wc_lookup_body_contains_erx_legacy(body)) {
                                non_auth_internal = 1;
                            }
                        } else if (strcasecmp(header_rir, "ripe") == 0) {
                            if (wc_lookup_body_contains_ripe_non_managed(body)) {
                                non_auth_internal = 1;
                                seen_ripe_non_managed = 1;
                            }
                        } else if (strcasecmp(header_rir, "afrinic") == 0) {
                            if (wc_lookup_body_contains_full_ipv4_space(body)) {
                                non_auth_internal = 1;
                                seen_afrinic_iana_blk = 1;
                            }
                        }
                        if (access_denied && hops == 0) {
                            non_auth_internal = 1;
                            header_hint_valid = 0;
                            force_rir_cycle = 1;
                        }
                        if (!non_auth_internal && auth && !wc_lookup_body_has_strong_redirect_hint(body)) {
                            stop_with_header_authority = 1;
                            snprintf(header_authority_host, sizeof(header_authority_host), "%s", header_hint_host);
                        } else if (non_auth_internal) {
                            header_hint_valid = 0;
                            force_rir_cycle = 1;
                        }
                        if (!access_denied &&
                            !wc_lookup_visited_has(visited, visited_count, header_hint_host) && visited_count < 16) {
                            visited[visited_count++] = xstrdup(header_hint_host);
                        }
                    }
                }
            }
        }
        int header_non_authoritative = 0;
        int first_hop_persistent_empty = (persistent_empty && hops == 0);
        int access_denied_current = (access_denied && (!header_host || header_matches_current));
        int access_denied_internal = (access_denied && header_host && !header_matches_current);
        int rate_limit_current = (rate_limited && (!header_host || header_matches_current));
        if ((access_denied_current || access_denied_internal || rate_limit_current) && cfg && cfg->debug) {
            const char* dbg_host = access_denied_internal ? header_host : current_host;
            const char* dbg_rir = dbg_host ? wc_guess_rir(dbg_host) : NULL;
            const char* dbg_ip = "unknown";
            if (access_denied_internal) {
                const char* known_ip = dbg_host ? wc_dns_get_known_ip(dbg_host) : NULL;
                if (known_ip && known_ip[0]) {
                    dbg_ip = known_ip;
                }
            } else if (ni.ip[0]) {
                dbg_ip = ni.ip;
            }
            fprintf(stderr,
                "[RIR-RESP] action=%s scope=%s host=%s rir=%s ip=%s\n",
                (access_denied_current || access_denied_internal) ? "denied" : "rate-limit",
                access_denied_internal ? "internal" : "current",
                (dbg_host && *dbg_host) ? dbg_host : "unknown",
                (dbg_rir && *dbg_rir) ? dbg_rir : "unknown",
                dbg_ip);
        }
        if (access_denied_current || access_denied_internal || rate_limit_current) {
            const char* err_host = access_denied_internal ? header_host : current_host;
            if (err_host && *err_host) {
                snprintf(last_failure_host, sizeof(last_failure_host), "%s", err_host);
            }
            const char* err_rir = wc_guess_rir(err_host);
            if (err_rir && *err_rir) {
                snprintf(last_failure_rir, sizeof(last_failure_rir), "%s", err_rir);
            }
            if (access_denied_current || access_denied_internal) {
                last_failure_status = "denied";
                last_failure_desc = "access-denied";
            } else {
                last_failure_status = "rate-limit";
                last_failure_desc = "rate-limit-exceeded";
            }
            if (last_failure_ip[0] == '\0') {
                const char* ip = NULL;
                if (!access_denied_internal && ni.ip[0]) {
                    ip = ni.ip;
                } else if (err_host) {
                    const char* known_ip = wc_dns_get_known_ip(err_host);
                    if (known_ip && known_ip[0]) {
                        ip = known_ip;
                    }
                }
                if (ip && *ip) {
                    snprintf(last_failure_ip, sizeof(last_failure_ip), "%s", ip);
                }
            }
        }
        int hide_failure_body = (cfg && cfg->hide_failure_body);
        if (hide_failure_body && (access_denied_current || access_denied_internal) && body && *body) {
            char* filtered_body = wc_lookup_strip_access_denied_lines(body);
            if (filtered_body) {
                free(body);
                body = filtered_body;
            }
        }
        if (hide_failure_body && rate_limit_current && body && *body) {
            char* filtered_body = wc_lookup_strip_rate_limit_lines(body);
            if (filtered_body) {
                free(body);
                body = filtered_body;
            }
        }
        if (access_denied_current || access_denied_internal || rate_limit_current) {
            saw_rate_limit_or_denied = 1;
        }
        if (persistent_empty && current_rir_guess) {
            header_non_authoritative = 1;
            need_redir_eval = 1;
            if (first_hop_persistent_empty) {
                if (strcasecmp(current_rir_guess, "arin") == 0) {
                    force_rir_cycle = 1;
                }
                wc_lookup_visited_remove(visited, &visited_count, current_host);
                if (wc_dns_is_ip_literal(current_host)) {
                    const char* mapped_host = wc_lookup_known_ip_host_from_literal(current_host);
                    if (mapped_host && *mapped_host) {
                        wc_lookup_visited_remove(visited, &visited_count, mapped_host);
                    }
                }
                const char* canon_visit = wc_dns_canonical_alias(current_host);
                if (canon_visit && *canon_visit) {
                    wc_lookup_visited_remove(visited, &visited_count, canon_visit);
                }
            } else {
                force_rir_cycle = 1;
            }
        }
        if (ripe_non_managed) {
            header_non_authoritative = 1;
            need_redir_eval = 1;
            force_rir_cycle = 1;
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0) {
            if (wc_lookup_body_contains_ipv6_root(body)) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
            } else if (wc_lookup_body_contains_erx_legacy(body)) {
                header_non_authoritative = 1;
            }
            if (wc_lookup_body_contains_apnic_iana_netblock(body)) {
                seen_apnic_iana_netblock = 1;
                if (!apnic_erx_root) {
                    apnic_erx_root = 1;
                    if (!apnic_erx_root_host[0]) {
                        const char* apnic_root = wc_dns_canonical_alias(current_host);
                        if (!apnic_root) apnic_root = current_host;
                        snprintf(apnic_erx_root_host, sizeof(apnic_erx_root_host), "%s", apnic_root);
                    }
                    if (!apnic_erx_root_ip[0] && ni.ip[0]) {
                        snprintf(apnic_erx_root_ip, sizeof(apnic_erx_root_ip), "%s", ni.ip);
                    }
                }
                if (apnic_redirect_reason == APNIC_REDIRECT_NONE) {
                    apnic_redirect_reason = APNIC_REDIRECT_IANA;
                }
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0) {
            if (wc_lookup_body_contains_ipv6_root(body) || wc_lookup_body_contains_ripe_access_denied(body)) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
                force_rir_cycle = 1;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "afrinic") == 0) {
            if (wc_lookup_body_contains_ipv6_root(body)) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
                force_rir_cycle = 1;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0) {
            if (wc_lookup_body_contains_no_match(body) || !auth) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
            }
        }
        if (current_rir_guess && hops == 0 && (access_denied_current || rate_limit_current)) {
            header_non_authoritative = 1;
            need_redir_eval = 1;
            force_rir_cycle = 1;
            wc_lookup_visited_remove(visited, &visited_count, current_host);
        }
        if (query_is_cidr_effective && current_rir_guess) {
            if (strcasecmp(current_rir_guess, "arin") == 0 && wc_lookup_body_contains_no_match(body)) {
                seen_arin_no_match_cidr = 1;
            } else if (strcasecmp(current_rir_guess, "ripe") == 0 && ripe_non_managed) {
                seen_ripe_non_managed = 1;
            } else if (strcasecmp(current_rir_guess, "afrinic") == 0 &&
                       wc_lookup_body_contains_full_ipv4_space(body)) {
                seen_afrinic_iana_blk = 1;
            } else if (strcasecmp(current_rir_guess, "lacnic") == 0 &&
                       wc_lookup_body_contains_lacnic_unallocated(body)) {
                seen_lacnic_unallocated = 1;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "lacnic") == 0) {
            if (wc_lookup_body_contains_lacnic_unallocated(body)) {
                header_non_authoritative = 1;
                if (!ref) {
                    need_redir_eval = 1;
                }
            }
            if (wc_lookup_body_contains_lacnic_rate_limit(body)) {
                header_non_authoritative = 1;
                need_redir_eval = 1;
                force_rir_cycle = 1;
                if (hops == 0) {
                    wc_lookup_visited_remove(visited, &visited_count, current_host);
                }
            }
        }
        if (wc_lookup_body_contains_full_ipv4_space(body)) {
            header_non_authoritative = 1;
        }
        const char* erx_marker_host_local = current_host;
        if (header_host && !header_is_iana && !header_matches_current) {
            if (header_hint_host[0])
                erx_marker_host_local = header_hint_host;
            else
                erx_marker_host_local = header_host;
        }
        if (erx_marker_this_hop) {
            header_non_authoritative = 1;
            need_redir_eval = 1;
            if (!erx_marker_seen) {
                erx_marker_seen = 1;
                snprintf(erx_marker_host, sizeof(erx_marker_host), "%s", erx_marker_host_local);
                if (erx_marker_host_local && strcasecmp(erx_marker_host_local, current_host) == 0 && ni.ip[0]) {
                    snprintf(erx_marker_ip, sizeof(erx_marker_ip), "%s", ni.ip);
                } else {
                    const char* known_ip = wc_dns_get_known_ip(erx_marker_host_local);
                    if (known_ip && known_ip[0]) {
                        snprintf(erx_marker_ip, sizeof(erx_marker_ip), "%s", known_ip);
                    }
                }
            }
        }
        if (erx_marker_this_hop && query_is_cidr && cidr_base_query &&
            !erx_fast_recheck_done && !wc_lookup_erx_baseline_recheck_guard &&
            (!cfg || cfg->cidr_erx_recheck)) {
            if (cfg && cfg->batch_interval_ms > 0) {
                int delay_ms = cfg->batch_interval_ms;
                struct timespec ts;
                ts.tv_sec = (time_t)(delay_ms / 1000);
                ts.tv_nsec = (long)((delay_ms % 1000) * 1000000L);
                nanosleep(&ts, NULL);
            }
            struct wc_lookup_opts recheck_opts = zopts;
            struct wc_result recheck_res;
            struct wc_query recheck_q = {
                .raw = cidr_base_query,
                .start_server = erx_marker_host_local,
                .port = current_port
            };
            recheck_opts.no_redirect = 1;
            recheck_opts.max_hops = 1;
            recheck_opts.net_ctx = net_ctx;
            recheck_opts.config = cfg;
            wc_lookup_erx_baseline_recheck_guard = 1;
            erx_baseline_recheck_attempted = 1;
            erx_fast_recheck_done = 1;
            if (cfg && cfg->debug) {
                fprintf(stderr,
                    "[DEBUG] ERX fast recheck: query=%s host=%s\n",
                    cidr_base_query,
                    erx_marker_host_local);
            }
            int recheck_rc = wc_lookup_execute(&recheck_q, &recheck_opts, &recheck_res);
            wc_lookup_erx_baseline_recheck_guard = 0;
            if (recheck_rc == 0 && recheck_res.body && recheck_res.body[0]) {
                int recheck_erx = wc_lookup_body_contains_erx_iana_marker(recheck_res.body);
                int recheck_non_auth = wc_lookup_body_has_strong_redirect_hint(recheck_res.body);
                if (cfg && cfg->debug) {
                    fprintf(stderr,
                        "[DEBUG] ERX fast recheck result: erx=%d non_auth=%d\n",
                        recheck_erx,
                        recheck_non_auth);
                }
                if (!recheck_erx && !recheck_non_auth) {
                    const char* canon_host = wc_dns_canonical_alias(erx_marker_host_local);
                    snprintf(erx_fast_authoritative_host,
                        sizeof(erx_fast_authoritative_host),
                        "%s", canon_host ? canon_host : erx_marker_host_local);
                    if (recheck_res.meta.authoritative_ip[0] &&
                        strcasecmp(recheck_res.meta.authoritative_ip, "unknown") != 0) {
                        snprintf(erx_fast_authoritative_ip,
                            sizeof(erx_fast_authoritative_ip),
                            "%s", recheck_res.meta.authoritative_ip);
                    } else if (recheck_res.meta.last_ip[0]) {
                        snprintf(erx_fast_authoritative_ip,
                            sizeof(erx_fast_authoritative_ip),
                            "%s", recheck_res.meta.last_ip);
                    } else {
                        const char* known_ip = wc_dns_get_known_ip(erx_marker_host_local);
                        snprintf(erx_fast_authoritative_ip,
                            sizeof(erx_fast_authoritative_ip),
                            "%s", (known_ip && known_ip[0]) ? known_ip : "unknown");
                    }
                    erx_fast_authoritative = 1;
                    header_non_authoritative = 0;
                    need_redir_eval = 0;
                    if (ref) {
                        free(ref);
                        ref = NULL;
                    }
                    auth = 1;
                }
            } else if (cfg && cfg->debug) {
                fprintf(stderr,
                    "[DEBUG] ERX fast recheck failed: rc=%d\n",
                    recheck_rc);
            }
            wc_lookup_result_free(&recheck_res);
        } else if (erx_marker_this_hop && query_is_cidr && cidr_base_query &&
            !erx_fast_recheck_done && cfg && !cfg->cidr_erx_recheck && cfg->debug) {
            fprintf(stderr,
                "[ERX-RECHECK] action=skip reason=disabled query=%s host=%s\n",
                cidr_base_query,
                erx_marker_host_local);
        }
        if (header_non_authoritative) {
            auth = 0;
        }
        if (auth && !header_non_authoritative &&
            !(current_rir_guess && strcasecmp(current_rir_guess, "iana") == 0)) {
            seen_real_authoritative = 1;
        }
        int header_authoritative_stop = (header_matches_current && auth && !header_non_authoritative) ? 1 : 0;
        if (header_host && strcasecmp(header_host, "whois.apnic.net") == 0 && ni.ip[0]) {
            snprintf(apnic_last_ip, sizeof(apnic_last_ip), "%s", ni.ip);
        }
        if (ref && header_host && !header_is_iana) {
            char ref_norm2[128];
            const char* header_norm = wc_dns_canonical_alias(header_host);
            if (!header_norm)
                header_norm = header_host;
            if (wc_normalize_whois_host(ref_host, ref_norm2, sizeof(ref_norm2)) != 0) {
                snprintf(ref_norm2, sizeof(ref_norm2), "%s", ref_host);
            }
            if (strcasecmp(ref_norm2, header_norm) == 0) {
                if (!ref_explicit) {
                    free(ref);
                    ref = NULL;
                    need_redir_eval = 0;
                }
            }
        }
        if (header_authoritative_stop && ref && !ref_explicit && !apnic_erx_keep_ref) {
            const char* ref_rir = wc_guess_rir(ref_host);
            int cross_rir_ref = (ref_rir && current_rir_guess &&
                strcasecmp(ref_rir, current_rir_guess) != 0);
            if (cross_rir_ref) {
                ref_explicit = 1;
            } else {
                free(ref);
                ref = NULL;
            }
        }
        // Do not suppress redirect evaluation when strong redirect hints exist.
        if (apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX && header_authoritative_stop) {
            apnic_erx_authoritative_stop = 1;
            need_redir_eval = 0;
            if (ref && !ref_explicit && !apnic_erx_keep_ref) {
                free(ref);
                ref = NULL;
            }
        }
        int apnic_transfer_to_apnic = 0;
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0) {
            apnic_transfer_to_apnic = wc_lookup_body_contains_apnic_transfer_to_apnic(body);
            if (apnic_transfer_to_apnic) {
                need_redir_eval = 0;
                if (ref) {
                    free(ref);
                    ref = NULL;
                }
            }
        }
        int erx_netname = wc_lookup_body_contains_erx_netname(body);
        if (auth && erx_netname && header_host && !header_is_iana) {
            if (!(ref && ref_explicit)) {
                need_redir_eval = 0;
                if (ref) {
                    free(ref);
                    ref = NULL;
                }
            }
        }
        if (auth && header_host && !header_is_iana && !ref && !need_redir_eval) {
            need_redir_eval = 0;
        }
        if (need_redir_eval && auth && !ref && current_rir_guess &&
            strcasecmp(current_rir_guess, "apnic") == 0) {
            // Suppress pivot only for APNIC ERX/transfer notes, not generic
            // "allocated by another RIR" messages.
            if (wc_lookup_body_contains_apnic_erx_hint(body)) {
                if (wc_lookup_body_contains_apnic_erx_hint_strict(body))
                    need_redir_eval = 0;
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0) {
            if (!apnic_transfer_to_apnic) {
                apnic_erx_legacy = wc_lookup_body_contains_erx_legacy(body);
                if (apnic_erx_legacy && !apnic_iana_netblock_cidr) {
                    need_redir_eval = 1;
                }
            }
        }
        if (need_redir_eval && auth && header_host && !header_is_iana && !ref &&
            (!current_rir_guess || strcasecmp(current_rir_guess, "apnic") != 0)) {
            char header_norm3[128];
            char current_norm3[128];
            const char* header_normp = wc_dns_canonical_alias(header_host);
            const char* current_normp = wc_dns_canonical_alias(current_host);
            if (!header_normp) header_normp = header_host;
            if (!current_normp) current_normp = current_host;
            if (wc_normalize_whois_host(header_normp, header_norm3, sizeof(header_norm3)) != 0) {
                snprintf(header_norm3, sizeof(header_norm3), "%s", header_normp);
            }
            if (wc_normalize_whois_host(current_normp, current_norm3, sizeof(current_norm3)) != 0) {
                snprintf(current_norm3, sizeof(current_norm3), "%s", current_normp);
            }
            if (strcasecmp(header_norm3, current_norm3) == 0) {
                if (!header_non_authoritative &&
                    !wc_lookup_body_has_strong_redirect_hint(body)) {
                    need_redir_eval = 0;
                }
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0 && apnic_erx_legacy) {
            if (!apnic_erx_root) {
                apnic_erx_root = 1;
                if (apnic_redirect_reason == APNIC_REDIRECT_NONE) {
                    apnic_redirect_reason = APNIC_REDIRECT_ERX;
                }
            }
            if (!apnic_erx_root_host[0]) {
                const char* apnic_root = wc_dns_canonical_alias(current_host);
                if (!apnic_root) apnic_root = current_host;
                snprintf(apnic_erx_root_host, sizeof(apnic_erx_root_host), "%s", apnic_root);
            }
            if (!apnic_erx_root_ip[0] && ni.ip[0]) {
                snprintf(apnic_erx_root_ip, sizeof(apnic_erx_root_ip), "%s", ni.ip);
            }
        }
        if (current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0 && ni.ip[0]) {
            snprintf(apnic_last_ip, sizeof(apnic_last_ip), "%s", ni.ip);
        }
        if (apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX &&
            apnic_erx_target_rir[0] && current_rir_guess &&
            strcasecmp(apnic_erx_target_rir, current_rir_guess) == 0 &&
            strcasecmp(apnic_erx_target_rir, "apnic") != 0 &&
            !(strcasecmp(apnic_erx_target_rir, "ripe") == 0 && ripe_non_managed)) {
            apnic_erx_stop = 1;
            apnic_erx_stop_unknown = 0;
            snprintf(apnic_erx_stop_host, sizeof(apnic_erx_stop_host), "%s", current_host);
        }
        if (!apnic_transfer_to_apnic && wc_lookup_body_contains_full_ipv4_space(body)) {
            need_redir_eval = 1;
            force_rir_cycle = 1;
        }
        if (apnic_transfer_to_apnic) {
            need_redir_eval = 0;
        }
        int allow_cycle_on_loop = (need_redir_eval || apnic_erx_legacy) ? 1 : 0;
        if (apnic_erx_authoritative_stop) {
            allow_cycle_on_loop = 0;
        }
        if (hops < 1) {
            allow_cycle_on_loop = 0;
        } else if (apnic_iana_netblock_cidr && !seen_arin_no_match_cidr) {
            allow_cycle_on_loop = 0;
        }
        int need_redir = (!zopts.no_redirect) ? need_redir_eval : 0;

        int apnic_erx_suppress_current = 0;
        int force_stop_authoritative = erx_fast_authoritative ? 1 : 0;
        if (auth && !header_non_authoritative && !need_redir_eval && !ref &&
            !(current_rir_guess && strcasecmp(current_rir_guess, "iana") == 0)) {
            if (!erx_marker_this_hop) {
                force_stop_authoritative = 1;
            }
        }

        if (seen_apnic_iana_netblock && apnic_ambiguous_revisit_used &&
            current_rir_guess && strcasecmp(current_rir_guess, "apnic") == 0 &&
            hops > 0 && wc_lookup_body_contains_apnic_iana_netblock(body)) {
            apnic_erx_suppress_current = 1;
        }

        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0) {
            if (wc_lookup_body_contains_ripe_non_managed(body)) {
                apnic_erx_ripe_non_managed = 1;
            }
        }
        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0) {
            apnic_erx_suppress_current = 0;
        }
        if (apnic_erx_root && current_rir_guess && strcasecmp(current_rir_guess, "ripe") == 0 && apnic_erx_ripe_non_managed) {
            apnic_erx_suppress_current = 0;
        }

        if (!force_rir_cycle && apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX &&
            !ref && need_redir_eval) {
            const char* stop_rir = NULL;
            if (apnic_erx_target_rir[0]) {
                stop_rir = apnic_erx_target_rir;
            } else if (apnic_erx_ref_host[0]) {
                stop_rir = wc_guess_rir(apnic_erx_ref_host);
            }
            if (stop_rir && current_rir_guess && strcasecmp(stop_rir, current_rir_guess) == 0) {
                apnic_erx_stop = 1;
                if (apnic_erx_ref_host[0]) {
                    snprintf(apnic_erx_stop_host, sizeof(apnic_erx_stop_host), "%s", apnic_erx_ref_host);
                } else {
                    const char* canon = wc_dns_canonical_host_for_rir(stop_rir);
                    snprintf(apnic_erx_stop_host, sizeof(apnic_erx_stop_host), "%s", canon ? canon : current_host);
                }
            }
        }

        last_hop_authoritative = auth ? 1 : 0;
        last_hop_need_redirect = need_redir_eval ? 1 : 0;
        last_hop_has_ref = ref ? 1 : 0;

        char next_host[128];
        next_host[0] = '\0';
        int have_next = 0;
        int next_port = current_port;
        int allow_apnic_ambiguous_revisit = 0;
        int ref_explicit_allow_visited = 0;
        
        if (!force_stop_authoritative && !ref) {
            int current_is_arin = (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0);
            int arin_no_match = (current_is_arin && wc_lookup_body_contains_no_match(body));
            int arin_no_match_erx = (arin_no_match && apnic_erx_root);
            if (!have_next && header_hint_valid) {
                if (strcasecmp(header_hint_host, current_host) != 0 &&
                    !wc_lookup_visited_has(visited, visited_count, header_hint_host)) {
                    snprintf(next_host, sizeof(next_host), "%s", header_hint_host);
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "header-hint",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
            }
            if (!have_next && wc_lookup_find_case_insensitive(body, "query terms are ambiguous")) {
                if (!apnic_ambiguous_revisit_used &&
                    wc_lookup_visited_has(visited, visited_count, "whois.apnic.net") &&
                    strcasecmp(current_host, "whois.apnic.net") != 0) {
                    apnic_ambiguous_revisit_used = 1;
                    stop_with_apnic_authority = 1;
                    wc_lookup_log_fallback(hops, "manual", "ambiguous-stop-apnic",
                                           current_host, "whois.apnic.net", "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
            }
            if (!have_next && arin_no_match && !apnic_erx_root) {
                if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                        next_host, sizeof(next_host))) {
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "no-match", "rir-cycle",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
            }
            int allow_cycle = allow_cycle_on_loop;
            if (apnic_erx_root && current_rir_guess &&
                (strcasecmp(current_rir_guess, "ripe") == 0 ||
                 strcasecmp(current_rir_guess, "afrinic") == 0 ||
                 strcasecmp(current_rir_guess, "lacnic") == 0)) {
                allow_cycle = 1;
            }
            if (apnic_erx_authoritative_stop) {
                allow_cycle = 0;
            }
            if (arin_no_match_erx) {
                allow_cycle = 1;
            }
            if (apnic_erx_root && auth && !need_redir_eval && current_rir_guess &&
                (strcasecmp(current_rir_guess, "ripe") == 0 ||
                 strcasecmp(current_rir_guess, "afrinic") == 0 ||
                 strcasecmp(current_rir_guess, "lacnic") == 0)) {
                allow_cycle = 0;
            }
            if (!have_next && hops == 0 && (need_redir_eval || apnic_erx_legacy)) {
                int visited_arin = 0;
                for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], "whois.arin.net")==0) { visited_arin=1; break; } }
                if (!visited_arin && (!current_rir_guess || strcasecmp(current_rir_guess, "arin") != 0)) {
                    snprintf(next_host, sizeof(next_host), "%s", "whois.arin.net");
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "rir-direct",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                }
            }
            if (!have_next && force_rir_cycle) {
                if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                        next_host, sizeof(next_host))) {
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                } else if (apnic_erx_root) {
                    rir_cycle_exhausted = 1;
                }
            }
            if (!have_next && allow_cycle) {
                if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                        next_host, sizeof(next_host))) {
                    have_next = 1;
                    wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                           current_host, next_host, "success",
                                           out->meta.fallback_flags, 0, -1,
                                           pref_label,
                                           net_ctx,
                                           cfg);
                } else if (apnic_erx_root) {
                    rir_cycle_exhausted = 1;
                }
            }

            if (!have_next && hops == 0 && need_redir_eval && !allow_cycle) {
                // Restrict IANA pivot: only from non-ARIN RIRs. Avoid ARIN->IANA and stop at ARIN.
                const char* cur_rir = wc_guess_rir(current_host);
                int is_arin = (cur_rir && strcasecmp(cur_rir, "arin") == 0);
                int is_known = (cur_rir &&
                    (strcasecmp(cur_rir, "apnic") == 0 || strcasecmp(cur_rir, "arin") == 0 ||
                     strcasecmp(cur_rir, "ripe") == 0 || strcasecmp(cur_rir, "afrinic") == 0 ||
                     strcasecmp(cur_rir, "lacnic") == 0 || strcasecmp(cur_rir, "iana") == 0));
                if (!is_arin && !is_known && !cfg->no_iana_pivot) {
                    int visited_iana = 0;
                    for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], "whois.iana.org")==0) { visited_iana=1; break; } }
                    if (strcasecmp(current_host, "whois.iana.org") != 0 && !visited_iana) {
                        snprintf(next_host, sizeof(next_host), "%s", "whois.iana.org");
                        have_next = 1;
                        // mark fallback: iana pivot used
                        out->meta.fallback_flags |= 0x8; // iana_pivot
                        wc_lookup_log_fallback(hops, "manual", "iana-pivot",
                                               current_host, "whois.iana.org", "success",
                                               out->meta.fallback_flags, 0, -1,
                                               pref_label,
                                               net_ctx,
                                               cfg);
                    }
                }
            }
        } else if (!force_stop_authoritative) {
            // Selftest: optionally force IANA pivot even if explicit referral exists.
            // Updated semantics: pivot at most once so that a 3-hop flow
            // (e.g., apnic -> iana -> arin) can be simulated. If IANA has
            // already been visited, follow the normal referral instead of
            // forcing IANA again, otherwise a loop guard would terminate at IANA.
            if (fault_profile && fault_profile->force_iana_pivot) {
                int visited_iana = 0;
                for (int i=0; i<visited_count; i++) {
                    if (strcasecmp(visited[i], "whois.iana.org") == 0) { visited_iana = 1; break; }
                }
                if (!visited_iana && strcasecmp(current_host, "whois.iana.org") != 0) {
                    snprintf(next_host, sizeof(next_host), "%s", "whois.iana.org");
                    have_next = 1;
                    out->meta.fallback_flags |= 0x8; // iana_pivot
                } else {
                    // Normal referral path after the one-time pivot
                    if (wc_normalize_whois_host(ref_host, next_host, sizeof(next_host)) != 0) {
                        snprintf(next_host, sizeof(next_host), "%s", ref_host);
                    }
                    have_next = 1;
                    if (ref_port > 0) next_port = ref_port;
                }
            } else {
                if (wc_normalize_whois_host(ref_host, next_host, sizeof(next_host)) != 0) {
                    snprintf(next_host, sizeof(next_host), "%s", ref_host);
                }
                if (hops == 0) {
                    have_next = 1;
                    if (ref_port > 0) next_port = ref_port;
                } else {
                    int visited_ref = 0;
                    for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], next_host)==0) { visited_ref=1; break; } }
                    if (!visited_ref) {
                        have_next = 1;
                        if (ref_port > 0) next_port = ref_port;
                    } else {
                        int allow_ref_retry = 0;
                        if (ref_explicit && combined &&
                            !wc_lookup_has_hop_header(combined, next_host) &&
                            strcasecmp(next_host, current_host) != 0) {
                            allow_ref_retry = 1;
                        }
                        if (allow_ref_retry) {
                            have_next = 1;
                            ref_explicit_allow_visited = 1;
                            if (ref_port > 0) next_port = ref_port;
                        } else {
                            if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                                    next_host, sizeof(next_host))) {
                                have_next = 1;

                                wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                                       current_host, next_host, "success",
                                                       out->meta.fallback_flags, 0, -1,
                                                       pref_label,
                                                       net_ctx,
                                                       cfg);
                            } else if (apnic_erx_root) {
                                rir_cycle_exhausted = 1;
                            }
                        }
                    }
                }
            }
        }

        if (apnic_erx_root && apnic_redirect_reason == APNIC_REDIRECT_ERX &&
            current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 && have_next) {
            snprintf(apnic_erx_ref_host, sizeof(apnic_erx_ref_host), "%s", next_host);
        }

    // Append current body to combined output (ownership may transfer below); body can be empty string
    if (!apnic_erx_suppress_current) {
        if (!combined) { combined = body; body = NULL; }
        else { combined = append_and_free(combined, body); free(body); }
    } else if (body) {
        free(body);
        body = NULL;
    }
        hops++; out->meta.hops = hops;

        if (stop_with_header_authority && header_authority_host[0]) {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", header_authority_host);
            const char* known_ip = wc_dns_get_known_ip(header_authority_host);
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s",
                (known_ip && known_ip[0]) ? known_ip : "unknown");
            if (ref) { free(ref); ref = NULL; }
            break;
        }

        if (stop_with_apnic_authority) {
            const char* apnic_host = "whois.apnic.net";
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_host);
            if (apnic_last_ip[0] && wc_lookup_ip_matches_host(apnic_last_ip, apnic_host)) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_last_ip);
            } else {
                const char* known_apnic_ip = wc_dns_get_known_ip(apnic_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s",
                    (known_apnic_ip && known_apnic_ip[0]) ? known_apnic_ip : "unknown");
            }
            if (ref) { free(ref); ref = NULL; }
            break;
        }

        if (apnic_erx_stop && apnic_erx_stop_host[0]) {
            if (apnic_erx_stop_unknown) {
                const char* apnic_host = apnic_erx_root_host[0] ? apnic_erx_root_host : "whois.apnic.net";
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_host);
                if (apnic_erx_root_ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_erx_root_ip);
                } else {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            } else {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_erx_stop_host);
                if (strcasecmp(current_host, apnic_erx_stop_host) == 0 && ni.ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip);
                } else if (out->meta.via_host[0] && strcasecmp(out->meta.via_host, apnic_erx_stop_host) == 0 && out->meta.via_ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", out->meta.via_ip);
                } else {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            }
            if (ref) { free(ref); ref = NULL; }
            break;
        }

        if (zopts.no_redirect) {
            // Treat no-redirect as an explicit cap: identical to -R 1 semantics.
            out->meta.fallback_flags |= 0x10; // redirect-cap
            if (have_next) {
                redirect_cap_hit = 1;
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            } else {
                if (auth) {
                    // No further hop; treat current as authoritative
                    const char* header_canon = (!header_is_iana && header_host)
                        ? wc_dns_canonical_alias(header_host)
                        : NULL;
                    const char* auth_host = header_canon
                        ? header_canon
                        : wc_dns_canonical_alias(current_host);
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
                } else {
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                }
            }
            if (ref) free(ref);
            break;
        }

        if (auth && !need_redir && !ref && !have_next) {
            if (erx_fast_authoritative) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host),
                    "%s", erx_fast_authoritative_host[0] ? erx_fast_authoritative_host : current_host);
                if (erx_fast_authoritative_ip[0]) {
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                        "%s", erx_fast_authoritative_ip);
                } else {
                    const char* known_ip = wc_dns_get_known_ip(current_host);
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                        "%s", (known_ip && known_ip[0]) ? known_ip : "unknown");
                }
                if (ref) free(ref);
                break;
            }
            int apnic_erx_continue = 0;
            if (apnic_erx_root && current_rir_guess) {
                if (strcasecmp(current_rir_guess, "ripe") == 0 && apnic_erx_ripe_non_managed) {
                    apnic_erx_continue = 1;
                } else if (strcasecmp(current_rir_guess, "apnic") == 0 && apnic_erx_legacy) {
                    apnic_erx_continue = 1;
                }
            }
            if (!apnic_erx_continue) {
                int non_auth_count = (seen_apnic_iana_netblock ? 1 : 0) + (seen_ripe_non_managed ? 1 : 0) +
                                     (seen_afrinic_iana_blk ? 1 : 0) + (seen_lacnic_unallocated ? 1 : 0);
                int cidr_global_unknown = (query_is_cidr_effective && !seen_real_authoritative && non_auth_count > 0 &&
                    (seen_arin_no_match_cidr || non_auth_count >= 2));
                if (cidr_global_unknown) {
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                    if (ref) free(ref);
                    break;
                }
                // Current server appears authoritative; stop following to avoid redundant self-redirects
                const char* header_canon = (!header_is_iana && header_host)
                    ? wc_dns_canonical_alias(header_host)
                    : NULL;
                const char* auth_host = header_canon
                    ? header_canon
                    : wc_dns_canonical_alias(current_host);
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
                if (ref) free(ref);
                break;
            }
        }

        // If no explicit referral but redirect seems needed, try via IANA as a safe hub
        if (ref) { free(ref); ref = NULL; }

        if (!have_next && apnic_erx_root && current_rir_guess &&
            (strcasecmp(current_rir_guess, "ripe") == 0 ||
             strcasecmp(current_rir_guess, "afrinic") == 0 ||
             strcasecmp(current_rir_guess, "lacnic") == 0)) {
            if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                    next_host, sizeof(next_host))) {
                have_next = 1;
                wc_lookup_log_fallback(hops, "manual", "rir-cycle",
                                       current_host, next_host, "success",
                                       out->meta.fallback_flags, 0, -1,
                                       pref_label,
                                       net_ctx,
                                       cfg);
            } else if (apnic_erx_root) {
                rir_cycle_exhausted = 1;
            }
        }

        if (!have_next) {
            if (apnic_erx_root && current_rir_guess &&
                (strcasecmp(current_rir_guess, "ripe") == 0 ||
                 strcasecmp(current_rir_guess, "afrinic") == 0 ||
                 strcasecmp(current_rir_guess, "lacnic") == 0)) {
                rir_cycle_exhausted = 1;
                break;
            }
            {
                int non_auth_count = (seen_apnic_iana_netblock ? 1 : 0) + (seen_ripe_non_managed ? 1 : 0) +
                                     (seen_afrinic_iana_blk ? 1 : 0) + (seen_lacnic_unallocated ? 1 : 0);
                int cidr_global_unknown = (query_is_cidr_effective && !seen_real_authoritative && non_auth_count > 0 &&
                    (seen_arin_no_match_cidr || non_auth_count >= 2));
                if (cidr_global_unknown) {
                    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                    snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                    break;
                }
            }
            if (auth) {
                // No referral and no need to redirect -> treat current as authoritative
                const char* header_canon = (!header_is_iana && header_host)
                    ? wc_dns_canonical_alias(header_host)
                    : NULL;
                const char* auth_host = header_canon
                    ? header_canon
                    : wc_dns_canonical_alias(current_host);
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            } else {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            }
            break;
        }

        if (have_next && auth) {
            pending_referral = 1;
        }

        if (have_next && hops >= zopts.max_hops) {
            // Redirect chain would exceed the configured hop budget; stop immediately.
            redirect_cap_hit = 1;
            out->meta.fallback_flags |= 0x10; // redirect-cap
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            break;
        }

        int force_original_next = (arin_retry_active && have_next && query_is_cidr);
        if (have_next && query_is_cidr_effective && !force_original_next) {
            const char* next_rir = wc_guess_rir(next_host);
            if (next_rir && strcasecmp(next_rir, "apnic") == 0) {
                apnic_force_ip = 1;
            }
        }

        // loop guard
        int loop = 0;
        for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], next_host)==0) { loop=1; break; } }
        if (loop && ref_explicit_allow_visited) {
            loop = 0;
        }
        if (loop && allow_apnic_ambiguous_revisit &&
            strcasecmp(next_host, "whois.apnic.net") == 0) {
            loop = 0;
        }
        if (loop && !apnic_revisit_used && apnic_force_ip &&
            strcasecmp(next_host, start_host) == 0) {
            loop = 0;
            apnic_revisit_used = 1;
        }
        if (loop && allow_cycle_on_loop) {
            char cycle_host[128]; cycle_host[0] = '\0';
            if (wc_lookup_rir_cycle_next(current_rir_guess, visited, visited_count,
                    cycle_host, sizeof(cycle_host))) {
                if (strcasecmp(cycle_host, next_host) != 0) {
                    snprintf(next_host, sizeof(next_host), "%s", cycle_host);
                    loop = 0;
                }
            }
        }
        if (loop || strcasecmp(next_host, current_host)==0) {
            int non_auth_count = (seen_apnic_iana_netblock ? 1 : 0) + (seen_ripe_non_managed ? 1 : 0) +
                                 (seen_afrinic_iana_blk ? 1 : 0) + (seen_lacnic_unallocated ? 1 : 0);
            int cidr_global_unknown = (query_is_cidr_effective && !seen_real_authoritative && non_auth_count > 0 &&
                (seen_arin_no_match_cidr || non_auth_count >= 2));
            if (apnic_erx_root) {
                rir_cycle_exhausted = 1;
            }
            if (cidr_global_unknown) {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
                break;
            }
            if (auth) {
                const char* auth_host = (!header_is_iana && header_host)
                    ? header_host
                    : wc_dns_canonical_alias(current_host);
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : current_host);
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            } else {
                snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
            }
            break;
        }

        // insert heading for the upcoming hop
        if (emit_redirect_headers) {
            char hdr[256];
            if (!additional_emitted) {
                snprintf(hdr, sizeof(hdr), "\n=== Additional query to %s ===\n", next_host);
                additional_emitted = 1;
            } else {
                snprintf(hdr, sizeof(hdr), "\n=== Redirected query to %s ===\n", next_host);
            }
            combined = append_and_free(combined, hdr);
        }

        // advance to next
        snprintf(current_host, sizeof(current_host), "%s", next_host);
        current_port = next_port;
        force_original_query = force_original_next;
        // continue loop for next hop
    }
    // finalize result
    if (combined && out->meta.authoritative_host[0] == '\0' && !redirect_cap_hit) {
        // best-effort only when the last hop looks authoritative and no redirect was indicated
        if (last_hop_authoritative && !last_hop_need_redirect && !last_hop_has_ref) {
            const char* fallback_host = current_host[0]?current_host:start_host;
            const char* auth_host = wc_dns_canonical_alias(fallback_host);
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", auth_host ? auth_host : fallback_host);
        } else {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
        }
    }
    if (redirect_cap_hit && out->meta.authoritative_host[0] == '\0') {
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "unknown");
    }
    if (redirect_cap_hit && out->meta.authoritative_ip[0] == '\0') {
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
    }
    if (out->meta.authoritative_host[0] &&
        strcasecmp(out->meta.authoritative_host, "unknown") == 0) {
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "unknown");
    }
    if (apnic_erx_root && apnic_erx_seen_arin && combined) {
        const char* final_rir = (out->meta.authoritative_host[0]
            ? wc_guess_rir(out->meta.authoritative_host)
            : NULL);
        (void)final_rir;
    }

    if (erx_marker_seen && !redirect_cap_hit && rir_cycle_exhausted &&
        saw_rate_limit_or_denied && erx_marker_host[0] &&
        (!out->meta.authoritative_host[0] ||
         strcasecmp(out->meta.authoritative_host, "unknown") == 0 ||
         strcasecmp(out->meta.authoritative_host, "error") == 0) &&
        !wc_lookup_erx_baseline_recheck_guard) {
        const char* base_query = (query_is_cidr_effective && cidr_base_query)
            ? cidr_base_query
            : q->raw;
        if (base_query && *base_query) {
            struct wc_lookup_opts recheck_opts = zopts;
            struct wc_result recheck_res;
            struct wc_query recheck_q = {
                .raw = base_query,
                .start_server = erx_marker_host,
                .port = (q->port > 0 ? q->port : 43)
            };
            recheck_opts.no_redirect = 1;
            recheck_opts.max_hops = 1;
            recheck_opts.net_ctx = net_ctx;
            recheck_opts.config = cfg;
            wc_lookup_erx_baseline_recheck_guard = 1;
            erx_baseline_recheck_attempted = 1;
            if (cfg && cfg->debug) {
                fprintf(stderr,
                    "[DEBUG] ERX baseline recheck: query=%s host=%s\n",
                    base_query,
                    erx_marker_host);
            }
            int recheck_rc = wc_lookup_execute(&recheck_q, &recheck_opts, &recheck_res);
            wc_lookup_erx_baseline_recheck_guard = 0;
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
                        "%s", erx_marker_host);
                    if (recheck_res.meta.authoritative_ip[0] &&
                        strcasecmp(recheck_res.meta.authoritative_ip, "unknown") != 0) {
                        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                            "%s", recheck_res.meta.authoritative_ip);
                    } else if (recheck_res.meta.last_ip[0]) {
                        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                            "%s", recheck_res.meta.last_ip);
                    } else {
                        const char* known_ip = wc_dns_get_known_ip(erx_marker_host);
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
    if (erx_marker_seen && !redirect_cap_hit && rir_cycle_exhausted && erx_marker_host[0] &&
        (!out->meta.authoritative_host[0] ||
         strcasecmp(out->meta.authoritative_host, "unknown") == 0 ||
         strcasecmp(out->meta.authoritative_host, "error") == 0)) {
        const char* canon_host = wc_dns_canonical_alias(erx_marker_host);
        const char* final_host = canon_host ? canon_host : erx_marker_host;
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", final_host);
        if (erx_marker_ip[0]) {
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", erx_marker_ip);
        } else {
            const char* known_ip = wc_dns_get_known_ip(final_host);
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip),
                "%s", (known_ip && known_ip[0]) ? known_ip : "unknown");
        }
    }
    if (apnic_erx_root && !redirect_cap_hit) {
        const char* apnic_host = apnic_erx_root_host[0] ? apnic_erx_root_host : "whois.apnic.net";
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
        int should_collapse = redirect_cap_hit || rir_cycle_exhausted || apnic_ip_mismatch ||
            (authoritative_apnic && (out->meta.authoritative_ip[0] == '\0' || strcasecmp(out->meta.authoritative_ip, "unknown") == 0));
        if (erx_baseline_recheck_attempted &&
            (!out->meta.authoritative_host[0] ||
             strcasecmp(out->meta.authoritative_host, "unknown") == 0 ||
             strcasecmp(out->meta.authoritative_host, "error") == 0)) {
            should_collapse = 0;
        }
        if (out->meta.authoritative_host[0] &&
            strcasecmp(out->meta.authoritative_host, "unknown") != 0 &&
            final_rir && strcasecmp(final_rir, "apnic") != 0) {
            should_collapse = 0;
        } else if (apnic_redirect_reason == APNIC_REDIRECT_ERX && non_apnic_authority) {
            should_collapse = 0;
        }
        if (should_collapse) {
            int visited_arin = wc_lookup_visited_has(visited, visited_count, "whois.arin.net");
            int visited_ripe = wc_lookup_visited_has(visited, visited_count, "whois.ripe.net");
            int visited_afrinic = wc_lookup_visited_has(visited, visited_count, "whois.afrinic.net");
            int visited_lacnic = wc_lookup_visited_has(visited, visited_count, "whois.lacnic.net");
            int insert_all = (out->meta.fallback_flags & 0x10) || rir_cycle_exhausted || non_apnic_authority ? 1 : 0;
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", apnic_host);
            if (apnic_erx_root_ip[0] && wc_lookup_ip_matches_host(apnic_erx_root_ip, apnic_host)) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_erx_root_ip);
            } else if (apnic_erx_root_ip[0] && wc_guess_rir(apnic_host) &&
                       strcasecmp(wc_guess_rir(apnic_host), "apnic") == 0) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_erx_root_ip);
            } else if (apnic_last_ip[0] && wc_lookup_ip_matches_host(apnic_last_ip, apnic_host)) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", apnic_last_ip);
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
            if ((insert_all || visited_arin) && !wc_lookup_has_hop_header(combined, "whois.arin.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.arin.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.arin.net");
            }
            if ((insert_all || visited_ripe) && !wc_lookup_has_hop_header(combined, "whois.ripe.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.ripe.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.ripe.net");
            }
            if ((insert_all || visited_afrinic) && !wc_lookup_has_hop_header(combined, "whois.afrinic.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.afrinic.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.afrinic.net");
            }
            if ((insert_all || visited_lacnic) && !wc_lookup_has_hop_header(combined, "whois.lacnic.net") &&
                !wc_lookup_host_tokens_equal(start_label, "whois.lacnic.net")) {
                combined = wc_lookup_insert_header_before_authoritative(combined, "whois.lacnic.net");
            }
            wc_lookup_compact_hop_headers(combined);
        }
    }
    if (erx_marker_seen && !redirect_cap_hit && erx_marker_host[0]) {
        if (!out->meta.authoritative_host[0] ||
            (strcasecmp(out->meta.authoritative_host, "unknown") == 0 &&
             !erx_baseline_recheck_attempted)) {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", erx_marker_host);
            if (erx_marker_ip[0]) {
                snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", erx_marker_ip);
            } else {
                const char* known_ip = wc_dns_get_known_ip(erx_marker_host);
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

    if (saw_rate_limit_or_denied && out->meta.authoritative_host[0] &&
        strcasecmp(out->meta.authoritative_host, "unknown") == 0) {
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", "error");
        snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", "error");
        if (!failure_emitted && out->meta.last_connect_errno == 0) {
            char ts[32];
            wc_lookup_format_time(ts, sizeof(ts));
            if (!last_failure_host[0]) {
                const char* fallback_host = out->meta.last_host[0] ? out->meta.last_host : current_host;
                if (fallback_host && *fallback_host) {
                    snprintf(last_failure_host, sizeof(last_failure_host), "%s", fallback_host);
                } else if (*start_host) {
                    snprintf(last_failure_host, sizeof(last_failure_host), "%s", start_host);
                }
            }
            if (!last_failure_ip[0] && out->meta.last_ip[0]) {
                snprintf(last_failure_ip, sizeof(last_failure_ip), "%s", out->meta.last_ip);
            }
            const char* err_host = last_failure_host[0] ? last_failure_host : "unknown";
            const char* err_ip = last_failure_ip[0] ? last_failure_ip : "unknown";
            fprintf(stderr,
                "Error: Query failed for %s (status=%s, desc=%s, rir=%s, host=%s, ip=%s, time=%s)\n",
                q->raw,
                last_failure_status,
                last_failure_desc,
                last_failure_rir[0] ? last_failure_rir : "unknown",
                err_host,
                err_ip,
                ts);
            failure_emitted = 1;
        }
    }

    if (combined) {
        int show_non_auth = cfg && cfg->show_non_auth_body;
        int show_post_marker = cfg && cfg->show_post_marker_body;
        if (!show_non_auth && !show_post_marker) {
            wc_lookup_strip_bodies_before_authoritative_hop(combined, start_host, out->meta.authoritative_host);
            wc_lookup_strip_bodies_after_authoritative_hop(combined, start_host, out->meta.authoritative_host);
        } else if (show_non_auth && !show_post_marker) {
            wc_lookup_strip_bodies_after_authoritative_hop(combined, start_host, out->meta.authoritative_host);
        } else if (!show_non_auth && show_post_marker) {
            wc_lookup_strip_bodies_before_authoritative_hop(combined, start_host, out->meta.authoritative_host);
        }
        wc_lookup_compact_hop_headers(combined);
    }
    out->body = combined;
    out->body_len = (combined ? strlen(combined) : 0);
    out->meta.failure_emitted = failure_emitted;

    if (cidr_base_query) {
        free(cidr_base_query);
        cidr_base_query = NULL;
    }

    if (arin_cidr_retry_query) {
        free(arin_cidr_retry_query);
        arin_cidr_retry_query = NULL;
    }

    // free visited list
    for (int i=0;i<16;i++) { if (visited[i]) free(visited[i]); }
    // defensive: free candidates if still allocated
    // (should be NULL unless we broke early before advancing)
    // candidates is local to the loop, but in case of refactor keep this safe-guard here

    // If there is a non-zero error code (e.g., connection failure during the redirection phase), 
    // even if some output has already been accumulated, a failure should be returned to allow the frontend to print the error.
    if (out->err) return out->err;
    return (out->body ? 0 : -1);
}
