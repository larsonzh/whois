// SPDX-License-Identifier: MIT
// lookup.c - Phase B skeleton implementation
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

// Access global configuration for IP family preference flags (defined in whois_client.c)
extern struct Config {
    int whois_port; size_t buffer_size; int max_retries; int timeout_sec; int retry_interval_ms; int retry_jitter_ms; size_t dns_cache_size; size_t connection_cache_size; int cache_timeout; int debug; int max_redirects; int no_redirect; int plain_mode; int fold_output; char* fold_sep; int fold_upper; int security_logging; int fold_unique; int dns_neg_ttl; int dns_neg_cache_disable; int ipv4_only; int ipv6_only; int prefer_ipv4; int prefer_ipv6;
    int dns_addrconfig; int dns_retry; int dns_retry_interval_ms; int dns_max_candidates; int no_dns_known_fallback; int no_dns_force_ipv4_fallback; int no_iana_pivot; int dns_no_fallback; int dns_use_wc_dns;
} g_config;
#include <netdb.h>
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"
#include "wc/wc_selftest.h"
#include "wc/wc_dns.h"
#include "wc/wc_backoff.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

static int wc_lookup_should_trace_dns(void) {
    if (g_config.debug) return 1;
    return wc_net_retry_metrics_enabled();
}

static const char* wc_lookup_origin_label(unsigned char origin) {
    switch (origin) {
        case WC_DNS_ORIGIN_INPUT: return "input";
        case WC_DNS_ORIGIN_SELFTEST: return "selftest";
        case WC_DNS_ORIGIN_CACHE: return "cache";
        case WC_DNS_ORIGIN_RESOLVER: return "resolver";
        case WC_DNS_ORIGIN_CANONICAL: return "canonical";
        default: return "unknown";
    }
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

static void wc_lookup_format_fallback_flags(unsigned int flags, char* buf, size_t len) {
    if (!buf || len == 0) return;
    buf[0] = '\0';
    const char* names[4];
    int idx = 0;
    if (flags & 0x1) names[idx++] = "known-ip";
    if (flags & 0x2) names[idx++] = "empty-retry";
    if (flags & 0x4) names[idx++] = "forced-ipv4";
    if (flags & 0x8) names[idx++] = "iana-pivot";
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
                                     const char* canonical_host) {
    if (!wc_lookup_should_trace_dns() || !cands) return;
    (void)canonical_host;
    const char* rir_label = (rir && *rir) ? rir : "unknown";
    const char* server_label = (server && *server) ? server : "unknown";
    int limit_hit = (g_config.dns_max_candidates > 0 && cands->limit_hit);
    if (cands->count == 0) {
        fprintf(stderr,
                "[DNS-CAND] hop=%d server=%s rir=%s idx=-1 target=NONE type=none origin=none",
                hop, server_label, rir_label);
        if (limit_hit) fprintf(stderr, " limit=%d", g_config.dns_max_candidates);
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
        if (limit_hit) fprintf(stderr, " limit=%d", g_config.dns_max_candidates);
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
                                   int empty_retry_count) {
    if (!wc_lookup_should_trace_dns()) return;
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
    if (err_no > 0) fprintf(stderr, " errno=%d", err_no);
    if (empty_retry_count >= 0) fprintf(stderr, " empty_retry=%d", empty_retry_count);
    fputc('\n', stderr);
}

static void wc_lookup_log_dns_error(const char* host,
                    const char* canonical_host,
                    int gai_error,
                    int negative_cache) {
    if (!wc_lookup_should_trace_dns() || gai_error == 0) return;
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

static void wc_lookup_log_backoff(const char* server,
                                  const char* candidate,
                                  int family,
                                  const char* action,
                                  const wc_dns_health_snapshot_t* snap) {
    if (!wc_lookup_should_trace_dns()) return;
    const char* fam_label = (family == AF_INET6) ? "ipv6" :
                            (family == AF_INET) ? "ipv4" : "unknown";
    int consec = snap ? snap->consecutive_failures : 0;
    long penalty_left = snap ? snap->penalty_ms_left : 0;
    fprintf(stderr,
            "[DNS-BACKOFF] server=%s target=%s family=%s action=%s consec_fail=%d penalty_ms_left=%ld\n",
            (server && *server) ? server : "unknown",
            (candidate && *candidate) ? candidate : "unknown",
            fam_label,
            (action && *action) ? action : "unknown",
            consec,
            penalty_left);
}

static void wc_lookup_log_dns_health(const char* host,
                        int family) {
    if (!wc_lookup_should_trace_dns()) return;
    wc_dns_health_snapshot_t snap;
    wc_dns_health_state_t st = wc_dns_health_get_state(host, family, &snap);
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
    struct wc_lookup_opts zopts = { .max_hops=5, .no_redirect=0, .timeout_sec=5, .retries=2 };
    if(opts) zopts = *opts;
    wc_result_init(out);

    // Pick starting server: explicit -> canonical; else default to IANA
    // Keep a stable label to display in header: prefer the user-provided token verbatim when present
    char start_host[128];
    char start_label[128];
    if (q->start_server && q->start_server[0]) {
        // If the input is the acronym of an RIR (such as arin/apnic/ripe/lacnic/afrinic/iana), 
        // the title displays its canonical domain name.
        const char* canon_label = wc_dns_canonical_host_for_rir(q->start_server);
        if (canon_label) snprintf(start_label, sizeof(start_label), "%s", canon_label);
        else snprintf(start_label, sizeof(start_label), "%s", q->start_server);
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
    int hops = 0;
    int additional_emitted = 0; // first referral uses "Additional"
    char* combined = NULL;
    out->meta.hops = 0;

    int empty_retry = 0; // retry budget for empty-body anomalies within a hop (fallback hosts)
    while (hops < zopts.max_hops) {
        // mark visited
        int already = 0;
        for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], current_host)==0) { already=1; break; } }
    if (!already && visited_count < 16) visited[visited_count++] = xstrdup(current_host);

        // connect (dynamic DNS-derived candidate list; IPv6 preferred)
        struct wc_net_info ni; int rc; ni.connected=0; ni.fd=-1; ni.ip[0]='\0';
        const char* rir = wc_guess_rir(current_host);
        char canonical_host[128]; canonical_host[0]='\0';
        wc_lookup_compute_canonical_host(current_host, rir, canonical_host, sizeof(canonical_host));
        wc_dns_candidate_list_t candidates = {0};
        int dns_build_rc = wc_dns_build_candidates(current_host, rir, &candidates);
        if (candidates.last_error != 0) {
            wc_lookup_log_dns_error(current_host, canonical_host, candidates.last_error, candidates.negative_cache_hit);
        }
        // Log current DNS health for both IPv4 and IPv6 families. This is
        // observability-only in Phase 3 step 2 and does not influence
        // candidate ordering or fallback decisions.
        wc_lookup_log_dns_health(canonical_host[0] ? canonical_host : current_host, AF_INET);
        wc_lookup_log_dns_health(canonical_host[0] ? canonical_host : current_host, AF_INET6);
        if (dns_build_rc != 0) {
            out->err = -1;
            wc_dns_candidate_list_free(&candidates);
            break;
        }
        wc_lookup_log_candidates(hops+1, current_host, rir, &candidates, canonical_host);
        int connected_ok = 0; int first_conn_rc = 0;
        for (int i=0; i<candidates.count; ++i){
            const char* target = candidates.items[i];
            if (!target) continue;
            // avoid duplicate immediate retry of identical token
            if (i>0 && strcasecmp(target, current_host)==0) continue;
            int candidate_family = wc_lookup_family_to_af(
                (candidates.families && i < candidates.count) ?
                    candidates.families[i] : (unsigned char)WC_DNS_FAMILY_UNKNOWN,
                target);
            wc_dns_health_snapshot_t backoff_snap;
            int penalized = wc_backoff_should_skip(target, candidate_family, &backoff_snap);
            int is_last_candidate = (i == candidates.count - 1);
            if (penalized && !is_last_candidate) {
                wc_lookup_log_backoff(current_host, target, candidate_family, "skip", &backoff_snap);
                continue;
            }
            if (penalized && is_last_candidate) {
                wc_lookup_log_backoff(current_host, target, candidate_family, "force-last", &backoff_snap);
            }
            rc = wc_dial_43(target, (uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries, &ni);
            int attempt_success = (rc==0 && ni.connected);
            if (wc_lookup_should_trace_dns() && i>0) {
                wc_lookup_log_fallback(hops+1, "connect-fail", "candidate", current_host,
                                       target, attempt_success?"success":"fail",
                                       out->meta.fallback_flags,
                                       attempt_success?0:ni.last_errno,
                                       -1);
            }
            if (attempt_success){
                // Do not mutate logical current_host with numeric dial targets; keep it as the logical server label.
                connected_ok = 1; break;
            } else {
                if (i==0) first_conn_rc = rc;
            }
        }
        if(!connected_ok){
            // Phase-in step 1: try forcing IPv4 for the same domain (if domain is not an IP literal)
            const char* domain_for_ipv4 = NULL;
            if (!wc_dns_is_ip_literal(current_host)) {
                domain_for_ipv4 = current_host;
            } else {
                const char* ch = wc_dns_canonical_host_for_rir(rir);
                domain_for_ipv4 = ch ? ch : NULL;
            }
            int forced_ipv4_attempted = 0;
            int forced_ipv4_success = 0;
            int forced_ipv4_errno = 0;
            char forced_ipv4_target[64]; forced_ipv4_target[0]='\0';
            if (domain_for_ipv4 && !g_config.no_dns_force_ipv4_fallback) {
                if (g_config.dns_no_fallback) {
                    // In dns-no-fallback mode, log a skipped forced-IPv4 fallback and do not actually retry.
                    wc_lookup_log_fallback(hops+1, "connect-fail", "no-op",
                                           domain_for_ipv4 ? domain_for_ipv4 : current_host,
                                           "(none)",
                                           "skipped",
                                           out->meta.fallback_flags,
                                           0,
                                           -1);
                } else {
                    wc_selftest_record_forced_ipv4_attempt();
                    struct addrinfo hints, *res = NULL;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_INET; // IPv4 only
                    hints.ai_socktype = SOCK_STREAM;
                    int gai = 0, tries=0; int maxtries = (g_config.dns_retry>0?g_config.dns_retry:1);
                    do {
                        gai = getaddrinfo(domain_for_ipv4, NULL, &hints, &res);
                        if(gai==EAI_AGAIN && tries<maxtries-1){ int ms=(g_config.dns_retry_interval_ms>=0?g_config.dns_retry_interval_ms:100); struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)((ms%1000)*1000000L); nanosleep(&ts,NULL); }
                        tries++;
                    } while(gai==EAI_AGAIN && tries<maxtries);
                    if (gai == 0 && res) {
                        char ipbuf[64]; ipbuf[0]='\0';
                        for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
                            if (p->ai_family == AF_INET) {
                                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                                if (inet_ntop(AF_INET, &(ipv4->sin_addr), ipbuf, sizeof(ipbuf))) {
                                    struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                    rc4 = wc_dial_43(ipbuf, (uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries, &ni4);
                                    forced_ipv4_attempted = 1;
                                    snprintf(forced_ipv4_target, sizeof(forced_ipv4_target), "%s", ipbuf);
                                    if (rc4==0 && ni4.connected) {
                                        ni = ni4;
                                        connected_ok = 1;
                                        out->meta.fallback_flags |= 0x4; // forced_ipv4
                                        forced_ipv4_success = 1;
                                        forced_ipv4_errno = 0;
                                        break;
                                    } else {
                                        forced_ipv4_success = 0;
                                        forced_ipv4_errno = ni4.last_errno;
                                        if (ni4.fd>=0) close(ni4.fd);
                                    }
                                }
                            }
                        }
                        freeaddrinfo(res);
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
                                       -1);
            }

            // Phase-in step 2: try known IPv4 fallback for canonical domain (do not change current_host for metadata)
            const char* domain_for_known = NULL;
            if (!wc_dns_is_ip_literal(current_host)) {
                domain_for_known = current_host;
            } else {
                const char* ch = wc_dns_canonical_host_for_rir(rir);
                domain_for_known = ch ? ch : NULL;
            }
            int known_ip_attempted = 0;
            int known_ip_success = 0;
            int known_ip_errno = 0;
            const char* known_ip_target = NULL;
            if (!connected_ok && domain_for_known && !g_config.no_dns_known_fallback) {
                if (g_config.dns_no_fallback) {
                    // In dns-no-fallback mode, log a skipped known-IP fallback and do not actually retry.
                    wc_lookup_log_fallback(hops+1, "connect-fail", "no-op",
                                           domain_for_known ? domain_for_known : current_host,
                                           "(none)",
                                           "skipped",
                                           out->meta.fallback_flags,
                                           0,
                                           -1);
                } else {
                    wc_selftest_record_known_ip_attempt();
                    const char* kip = wc_dns_get_known_ip(domain_for_known);
                    if (kip && kip[0]) {
                        struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
                        known_ip_attempted = 1;
                        known_ip_target = kip;
                        rc2 = wc_dial_43(kip, (uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries, &ni2);
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
                            if (ni2.fd>=0) close(ni2.fd);
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
                                       -1);
            }
        }
        wc_dns_candidate_list_free(&candidates);
        if (!connected_ok){
            out->err = first_conn_rc?first_conn_rc:-1;
            out->meta.last_connect_errno = ni.last_errno; // propagate failure errno
            break;
        }
        if (hops == 0) {
            // record first hop meta: show the user-supplied starting server token when available
            snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_label);
            snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s", ni.ip[0]?ni.ip:"unknown");
        }

        // send query
        size_t qlen = strlen(q->raw);
        char* line = (char*)malloc(qlen+3);
        if(!line){ out->err=-1; close(ni.fd); break; }
        memcpy(line, q->raw, qlen); line[qlen]='\r'; line[qlen+1]='\n'; line[qlen+2]='\0';
        if (wc_send_all(ni.fd, line, qlen+2, zopts.timeout_sec*1000) < 0){ free(line); out->err=-1; close(ni.fd); break; }
        free(line);

        // receive
        char* body=NULL; size_t blen=0;
        if (wc_recv_until_idle(ni.fd, &body, &blen, zopts.timeout_sec*1000, 65536) < 0){ out->err=-1; close(ni.fd); break; }
        close(ni.fd);

    // Selftest injection hook (one-shot): simulate empty-body anomaly for retry/fallback validation
    // Controlled via wc_selftest_set_inject_empty() (no environment dependency in release).
        {
            static int injected_once = 0;
            extern int wc_selftest_inject_empty_enabled(void);
            if (wc_selftest_inject_empty_enabled() && !injected_once) {
                if (body) { free(body); body = NULL; }
                blen = 0; // force empty
                injected_once = 1;
            }
        }

        // Defensive: occasionally a connection succeeds but body is empty.
        // Treat an empty (or all-whitespace) body as transient and try a fallback
        // host (DNS-derived candidates; ARIN more tolerant, others single) to avoid
        // showing an "authoritative" tail with no data section.
        if (blen == 0 || (blen > 0 && strspn(body, " \r\n\t") == blen)) {
            const char* rir_empty = wc_guess_rir(current_host);
            int handled_empty = 0;
            int arin_mode = (rir_empty && strcasecmp(rir_empty, "arin")==0);
            int retry_budget = arin_mode ? 3 : 1; // ARIN allows more tolerance; others once
            if (empty_retry < retry_budget) {
                // Rebuild candidates and pick a different one than current_host and last connected ip
                wc_dns_candidate_list_t cands2 = {0};
                int cands2_rc = wc_dns_build_candidates(current_host, rir_empty, &cands2);
                if (cands2.last_error != 0) {
                    wc_lookup_log_dns_error(current_host, canonical_host, cands2.last_error, cands2.negative_cache_hit);
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
                    combined = append_and_free(combined, "\n=== Warning: empty response from ");
                    combined = append_and_free(combined, current_host);
                    combined = append_and_free(combined, ", retrying via fallback host ");
                    combined = append_and_free(combined, pick);
                    combined = append_and_free(combined, " ===\n");
                    /* keep logical current_host unchanged; only change dial target */
                    handled_empty = 1; empty_retry++;
                    wc_lookup_log_fallback(hops+1, "empty-body", "candidate",
                                           current_host, pick, "success",
                                           out->meta.fallback_flags, 0, empty_retry);
                }
                wc_dns_candidate_list_free(&cands2);
            }
            // Unified fallback extension: if still not handled, attempt IPv4-only re-dial of same logical domain
            if (!handled_empty && !g_config.no_dns_force_ipv4_fallback) {
                const char* domain_for_ipv4 = NULL;
                if (!wc_dns_is_ip_literal(current_host)) domain_for_ipv4 = current_host; else {
                    const char* ch = wc_dns_canonical_host_for_rir(rir_empty);
                    if (ch) domain_for_ipv4 = ch;
                }
                if (domain_for_ipv4) {
                    wc_selftest_record_forced_ipv4_attempt();
                    struct addrinfo hints,*res=NULL; memset(&hints,0,sizeof(hints)); hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
                    int gai=0, tries=0, maxtries=(g_config.dns_retry>0?g_config.dns_retry:1);
                    do { gai=getaddrinfo(domain_for_ipv4, NULL, &hints, &res); if(gai==EAI_AGAIN && tries<maxtries-1){ int ms=(g_config.dns_retry_interval_ms>=0?g_config.dns_retry_interval_ms:100); struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)((ms%1000)*1000000L); nanosleep(&ts,NULL);} tries++; } while(gai==EAI_AGAIN && tries<maxtries);
                    if (gai==0 && res){
                        char ipbuf[64]; ipbuf[0]='\0';
                        int empty_ipv4_attempted = 0;
                        int empty_ipv4_success = 0;
                        int empty_ipv4_errno = 0;
                        int empty_ipv4_retry_metric = -1;
                        for(struct addrinfo* p=res; p; p=p->ai_next){ if(p->ai_family!=AF_INET) continue; struct sockaddr_in* a=(struct sockaddr_in*)p->ai_addr; if(inet_ntop(AF_INET,&(a->sin_addr),ipbuf,sizeof(ipbuf))){
                                struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                rc4 = wc_dial_43(ipbuf,(uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries,&ni4);
                                empty_ipv4_attempted = 1;
                                if(rc4==0 && ni4.connected){
                                    combined = append_and_free(combined, "\n=== Warning: empty response from ");
                                    combined = append_and_free(combined, current_host);
                                    combined = append_and_free(combined, ", retrying forced IPv4 ");
                                    combined = append_and_free(combined, ipbuf);
                                    combined = append_and_free(combined, " ===\n");
                                    // reuse current_host (logical) but replace ni context
                                    ni = ni4; handled_empty = 1; empty_retry++; out->meta.fallback_flags |= 0x4;
                                    empty_ipv4_success = 1;
                                    empty_ipv4_errno = 0;
                                    empty_ipv4_retry_metric = empty_retry;
                                    break; }
                                else { if(ni4.fd>=0) close(ni4.fd); }
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
                                                   empty_ipv4_success?empty_ipv4_retry_metric:-1);
                        }
                        freeaddrinfo(res);
                    }
                }
            }
            // Unified fallback extension: try known IPv4 mapping if still unhandled
            if (!handled_empty && !g_config.no_dns_known_fallback) {
                const char* domain_for_known=NULL;
                if (!wc_dns_is_ip_literal(current_host)) domain_for_known=current_host; else {
                    const char* ch = wc_dns_canonical_host_for_rir(rir_empty); if (ch) domain_for_known=ch; }
                if (domain_for_known){
                    wc_selftest_record_known_ip_attempt();
                    const char* kip = wc_dns_get_known_ip(domain_for_known);
                    if (kip && kip[0]){
                        struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
                        rc2 = wc_dial_43(kip,(uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries,&ni2);
                        if (rc2==0 && ni2.connected){
                            combined = append_and_free(combined, "\n=== Warning: empty response from ");
                            combined = append_and_free(combined, current_host);
                            combined = append_and_free(combined, ", retrying known IP ");
                            combined = append_and_free(combined, kip);
                            combined = append_and_free(combined, " ===\n");
                            ni = ni2; handled_empty=1; empty_retry++; out->meta.fallback_flags |= 0x1; if(strchr(kip,':')==NULL && strchr(kip,'.')!=NULL) out->meta.fallback_flags |= 0x4;
                            wc_lookup_log_fallback(hops+1, "empty-body", "known-ip",
                                                   domain_for_known, kip, "success",
                                                   out->meta.fallback_flags, 0, empty_retry);
                        }
                        else {
                            wc_lookup_log_fallback(hops+1, "empty-body", "known-ip",
                                                   domain_for_known, kip, "fail",
                                                   out->meta.fallback_flags, ni2.last_errno, -1);
                            if(ni2.fd>=0) close(ni2.fd); }
                    }
                }
            }
            if (!handled_empty && empty_retry == 0) {
                // last resort: once per host
                combined = append_and_free(combined, "\n=== Warning: empty response from ");
                combined = append_and_free(combined, current_host);
                combined = append_and_free(combined, ", retrying same host ===\n");
                handled_empty = 1; empty_retry++;
                wc_lookup_log_fallback(hops+1, "empty-body", "candidate",
                                       current_host, current_host, "success",
                                       out->meta.fallback_flags, 0, empty_retry);
            }

            if (handled_empty) {
                // mark fallback: empty-body driven retry
                out->meta.fallback_flags |= 0x2; // empty_retry
                if (body) free(body);
                body = NULL; blen = 0;
                // continue loop WITHOUT incrementing hops to reattempt this logical hop
                continue;
            } else if (blen == 0) {
                // Give up – annotate and proceed (will be treated as non-authoritative and may pivot)
                combined = append_and_free(combined, "\n=== Warning: persistent empty response from ");
                combined = append_and_free(combined, current_host);
                combined = append_and_free(combined, " (giving up) ===\n");
            }
        } else {
            // successful non-empty body resets empty retry budget for next hop
            empty_retry = 0;
        }

        // Decide next action based on only the latest hop body (not the combined history)
        int auth = is_authoritative_response(body);
        int need_redir = (!zopts.no_redirect) ? needs_redirect(body) : 0;
        char* ref = NULL;
        if (!zopts.no_redirect) {
            ref = extract_refer_server(body);
        }

    // Append current body to combined output (ownership may transfer below); body can be empty string
    if (!combined) { combined = body; body = NULL; }
    else { combined = append_and_free(combined, body); free(body); }
        hops++; out->meta.hops = hops;

        if (zopts.no_redirect) {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", current_host);
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            break;
        }

        if (auth && !need_redir) {
            // Current server appears authoritative; stop following to avoid redundant self-redirects
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", current_host);
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            if (ref) free(ref);
            break;
        }

        // If no explicit referral but redirect seems needed, try via IANA as a safe hub
        char next_host[128];
        int have_next = 0;
        if (!ref) {
            if (need_redir) {
                // Restrict IANA pivot: only from non-ARIN RIRs. Avoid ARIN->IANA and stop at ARIN.
                const char* cur_rir = wc_guess_rir(current_host);
                int is_arin = (cur_rir && strcasecmp(cur_rir, "arin") == 0);
                if (!is_arin && !g_config.no_iana_pivot) {
                    int visited_iana = 0;
                    for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], "whois.iana.org")==0) { visited_iana=1; break; } }
                    if (strcasecmp(current_host, "whois.iana.org") != 0 && !visited_iana) {
                        snprintf(next_host, sizeof(next_host), "%s", "whois.iana.org");
                        have_next = 1;
                        // mark fallback: iana pivot used
                        out->meta.fallback_flags |= 0x8; // iana_pivot
                        wc_lookup_log_fallback(hops, "manual", "iana-pivot",
                                               current_host, "whois.iana.org", "success",
                                               out->meta.fallback_flags, 0, -1);
                    }
                }
            }
        } else {
            // Selftest: optionally force IANA pivot even if explicit referral exists.
            // Updated semantics: pivot at most once so that a 3-hop flow
            // (e.g., apnic -> iana -> arin) can be simulated. If IANA has
            // already been visited, follow the normal referral instead of
            // forcing IANA again, otherwise a loop guard would terminate at IANA.
            if (wc_selftest_force_iana_pivot_enabled()) {
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
                    if (wc_normalize_whois_host(ref, next_host, sizeof(next_host)) != 0) {
                        snprintf(next_host, sizeof(next_host), "%s", ref);
                    }
                    have_next = 1;
                }
            } else {
                if (wc_normalize_whois_host(ref, next_host, sizeof(next_host)) != 0) {
                    snprintf(next_host, sizeof(next_host), "%s", ref);
                }
                have_next = 1;
            }
        }
        if (ref) { free(ref); ref = NULL; }

        if (!have_next) {
            // No referral and no need to redirect -> treat current as authoritative
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", current_host);
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            break;
        }

        // loop guard
        int loop = 0;
        for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], next_host)==0) { loop=1; break; } }
        if (loop || strcasecmp(next_host, current_host)==0) {
            snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", current_host);
            snprintf(out->meta.authoritative_ip, sizeof(out->meta.authoritative_ip), "%s", ni.ip[0]?ni.ip:"unknown");
            break;
        }

        // insert heading for the upcoming hop
        {
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
        // continue loop for next hop
    }

    // finalize result
    if (combined && out->meta.authoritative_host[0] == '\0') {
        // best-effort if we exited without setting authoritative
        snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", current_host[0]?current_host:start_host);
    }
    out->body = combined;
    out->body_len = (combined ? strlen(combined) : 0);

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
