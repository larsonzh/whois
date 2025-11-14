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

// Access global configuration for IP family preference flags (defined in whois_client.c)
extern struct Config {
    int whois_port; size_t buffer_size; int max_retries; int timeout_sec; int retry_interval_ms; int retry_jitter_ms; size_t dns_cache_size; size_t connection_cache_size; int cache_timeout; int debug; int max_redirects; int no_redirect; int plain_mode; int fold_output; char* fold_sep; int fold_upper; int security_logging; int fold_unique; int dns_neg_ttl; int dns_neg_cache_disable; int ipv4_only; int ipv6_only; int prefer_ipv4; int prefer_ipv6;
} g_config;
#include <netdb.h>
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

static void wc_result_init(struct wc_result* r){
    if(!r) return;
    memset(r,0,sizeof(*r));
    r->err = 0;
    r->meta.via_host[0] = 0;
    r->meta.via_ip[0] = 0;
    r->meta.authoritative_host[0] = 0;
    r->meta.authoritative_ip[0] = 0;
    r->meta.fallback_flags = 0; // initialize phased-in fallback bitset
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
static int is_ip_literal_str(const char* s){
    if(!s || !*s) return 0;
    int has_colon=0, has_dot=0;
    for(const char* p=s; *p; ++p){
        if(*p==':') has_colon=1;
        else if(*p=='.') has_dot=1;
    }
    if(has_colon) return 1; // IPv6 heuristic
    if(!has_dot) return 0;
    // Rough IPv4: digits and dots only
    for(const char* p=s; *p; ++p){
        if(!((*p>='0' && *p<='9') || *p=='.')) return 0;
    }
    return 1;
}

static const char* canonical_host_for_rir(const char* rir){
    if(!rir) return NULL;
    if(strcasecmp(rir,"arin")==0) return "whois.arin.net";
    if(strcasecmp(rir,"ripe")==0) return "whois.ripe.net";
    if(strcasecmp(rir,"apnic")==0) return "whois.apnic.net";
    if(strcasecmp(rir,"lacnic")==0) return "whois.lacnic.net";
    if(strcasecmp(rir,"afrinic")==0) return "whois.afrinic.net";
    if(strcasecmp(rir,"iana")==0) return "whois.iana.org";
    return NULL;
}

// Known-IP fallback mapping (defined in whois_client.c); phase-in with minimal coupling
extern const char* get_known_ip(const char* domain);

// Build dynamic candidate targets for a given host/RIR, prioritizing IPv6 literals from DNS.
// Returns heap-allocated array of char* in *out_list with *out_count entries. Caller must free each string and the array.
static void build_dynamic_candidates(const char* current_host, const char* rir, char*** out_list, int* out_count){
    *out_list = NULL; *out_count = 0;
    // Determine canonical hostname to resolve (avoid IP literal as resolver input)
    char canon[128]; canon[0]='\0';
    if(current_host && !is_ip_literal_str(current_host)){
        if (wc_normalize_whois_host(current_host, canon, sizeof(canon)) != 0) snprintf(canon,sizeof(canon),"%s", current_host);
    } else {
        const char* ch = canonical_host_for_rir(rir);
        if (ch) snprintf(canon,sizeof(canon),"%s", ch);
        else snprintf(canon,sizeof(canon),"%s", current_host?current_host:"whois.iana.org");
    }

    // Start with canonical hostname itself
    int cap = 12; int cnt = 0; char** list = (char**)malloc(sizeof(char*)*cap); if(!list) return;
    list[cnt++] = xstrdup(canon);

    // Resolve canon and collect numeric addresses (prefer IPv6, then IPv4), unique
    struct addrinfo hints; memset(&hints,0,sizeof(hints)); hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_UNSPEC;
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif
    struct addrinfo* res=NULL; {
        int gai_rc=0, tries=0; do { gai_rc = getaddrinfo(canon, "43", &hints, &res); if(gai_rc==EAI_AGAIN && tries<2){ usleep(100*1000); } tries++; } while(gai_rc==EAI_AGAIN && tries<3);
    }
    if(res){
        // Determine pass ordering based on preference flags
        int passes[2]; int pass_count = 0;
        if (g_config.ipv4_only) { passes[0] = AF_INET; pass_count = 1; }
        else if (g_config.ipv6_only) { passes[0] = AF_INET6; pass_count = 1; }
        else if (g_config.prefer_ipv4) { passes[0] = AF_INET; passes[1] = AF_INET6; pass_count = 2; }
        else { /* default prefer IPv6 */ passes[0] = AF_INET6; passes[1] = AF_INET; pass_count = 2; }
        for(int pi=0; pi<pass_count; ++pi){
            int fam = passes[pi];
            int pass = (fam==AF_INET6?0:1); // legacy variable kept for minimal diff
            for(struct addrinfo* rp=res; rp; rp=rp->ai_next){
                if(rp->ai_family != fam) continue;
                char ipbuf[64]; // NI_MAXHOST may be undefined on some minimal libc; 64 is enough for IPv6 literal
                if(getnameinfo(rp->ai_addr, rp->ai_addrlen, ipbuf, sizeof(ipbuf), NULL, 0, NI_NUMERICHOST)==0){
                    // dedup
                    int dup=0; for(int i=0;i<cnt;i++){ if(list[i] && strcmp(list[i], ipbuf)==0){ dup=1; break; } }
                    if(!dup){ if(cnt>=cap){ cap*=2; char** nl=(char**)realloc(list,sizeof(char*)*cap); if(!nl) {continue;} list=nl; }
                        list[cnt++] = xstrdup(ipbuf);
                    }
                }
            }
        }
        freeaddrinfo(res);
    }
    *out_list = list; *out_count = cnt;
}

int wc_lookup_execute(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out) {
    if(!q || !q->raw || !out) return -1;
    struct wc_lookup_opts zopts = { .max_hops=5, .no_redirect=0, .timeout_sec=5, .retries=2 };
    if(opts) zopts = *opts;
    wc_result_init(out);

    // Pick starting server: explicit -> canonical; else default to IANA
    char start_host[128];
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
        char** candidates = NULL; int cand_count = 0;
        build_dynamic_candidates(current_host, rir, &candidates, &cand_count);
        int connected_ok = 0; int first_conn_rc = 0;
        for (int i=0; i<cand_count; ++i){
            const char* target = candidates[i];
            // avoid duplicate immediate retry of identical token
            if (i>0 && strcasecmp(target, current_host)==0) continue;
            rc = wc_dial_43(target, (uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries, &ni);
            if (rc==0 && ni.connected){
                if (strcasecmp(target, current_host) != 0) snprintf(current_host, sizeof(current_host), "%s", target);
                connected_ok = 1; break;
            } else {
                if (i==0) first_conn_rc = rc;
            }
        }
        if(!connected_ok){
            // Phase-in step 1: try forcing IPv4 for the same domain (if domain is not an IP literal)
            const char* domain_for_ipv4 = NULL;
            if (!is_ip_literal_str(current_host)) {
                domain_for_ipv4 = current_host;
            } else {
                const char* ch = canonical_host_for_rir(rir);
                domain_for_ipv4 = ch ? ch : NULL;
            }
            if (domain_for_ipv4) {
                struct addrinfo hints, *res = NULL;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET; // IPv4 only
                hints.ai_socktype = SOCK_STREAM;
                int gai = 0, tries=0; do { gai = getaddrinfo(domain_for_ipv4, NULL, &hints, &res); if(gai==EAI_AGAIN && tries<2){ usleep(100*1000); } tries++; } while(gai==EAI_AGAIN && tries<3);
                if (gai == 0 && res) {
                    char ipbuf[64]; ipbuf[0]='\0';
                    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
                        if (p->ai_family == AF_INET) {
                            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                            if (inet_ntop(AF_INET, &(ipv4->sin_addr), ipbuf, sizeof(ipbuf))) {
                                struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                rc4 = wc_dial_43(ipbuf, (uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries, &ni4);
                                if (rc4==0 && ni4.connected) {
                                    ni = ni4;
                                    connected_ok = 1;
                                    out->meta.fallback_flags |= 0x4; // forced_ipv4
                                    break;
                                } else {
                                    if (ni4.fd>=0) close(ni4.fd);
                                }
                            }
                        }
                    }
                    freeaddrinfo(res);
                }
            }

            // Phase-in step 2: try known IPv4 fallback for canonical domain (do not change current_host for metadata)
            const char* domain_for_known = NULL;
            if (!is_ip_literal_str(current_host)) {
                domain_for_known = current_host;
            } else {
                const char* ch = canonical_host_for_rir(rir);
                domain_for_known = ch ? ch : NULL;
            }
            if (!connected_ok && domain_for_known) {
                const char* kip = get_known_ip(domain_for_known);
                if (kip && kip[0]) {
                    struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
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
                    } else {
                        // ensure fd closed in failure path
                        if (ni2.fd>=0) close(ni2.fd);
                    }
                }
            }
            if (!connected_ok){
                if (candidates){ for(int i=0;i<cand_count;i++){ if(candidates[i]) free(candidates[i]); } free(candidates); candidates=NULL; }
                out->err = first_conn_rc?first_conn_rc:-1; break;
            }
        }
        if (hops == 0) {
            // record first hop meta
            snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", current_host);
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

    // Selftest injection hook (only once): allow simulated empty-body anomaly for retry/fallback logic validation
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

        // Defensive: occasional observed case (user report) where connection succeeds but body is empty.
        // Treat an empty (or all-whitespace) body as a transient transport anomaly and attempt
        // a fallback host (DNS-derived candidate; ARIN allows up to 3, others single) before proceeding, to avoid
        // presenting a misleading "authoritative" tail with no data section.
        if (blen == 0 || (blen > 0 && strspn(body, " \r\n\t") == blen)) {
            const char* rir_empty = wc_guess_rir(current_host);
            int handled_empty = 0;
            int arin_mode = (rir_empty && strcasecmp(rir_empty, "arin")==0);
            int retry_budget = arin_mode ? 3 : 1; // ARIN更高容错，其它 RIR 一次
            if (empty_retry < retry_budget) {
                // Rebuild candidates and pick a different one than current_host and last connected ip
                char** cands2=NULL; int cc2=0; build_dynamic_candidates(current_host, rir_empty, &cands2, &cc2);
                const char* pick=NULL;
                for(int i=0;i<cc2;i++){
                    const char* t = cands2[i];
                    if (strcasecmp(t, current_host)==0) continue;
                    // Prefer IP literal that differs from last connected ip
                    if (is_ip_literal_str(t) && ni.ip[0] && strcmp(t, ni.ip)!=0) { pick=t; break; }
                    // else keep a non-literal as a fallback if nothing better
                    if (!pick) pick=t;
                }
                if (pick){
                    combined = append_and_free(combined, "\n=== Warning: empty response from ");
                    combined = append_and_free(combined, current_host);
                    combined = append_and_free(combined, ", retrying via fallback host ");
                    combined = append_and_free(combined, pick);
                    combined = append_and_free(combined, " ===\n");
                    snprintf(current_host, sizeof(current_host), "%s", pick);
                    handled_empty = 1; empty_retry++;
                }
                if (cands2){ for(int i=0;i<cc2;i++){ if(cands2[i]) free(cands2[i]); } free(cands2); }
            }
            // Unified fallback extension: if still not handled, attempt IPv4-only re-dial of same logical domain
            if (!handled_empty) {
                const char* domain_for_ipv4 = NULL;
                if (!is_ip_literal_str(current_host)) domain_for_ipv4 = current_host; else {
                    const char* ch = canonical_host_for_rir(rir_empty);
                    if (ch) domain_for_ipv4 = ch;
                }
                if (domain_for_ipv4) {
                    struct addrinfo hints,*res=NULL; memset(&hints,0,sizeof(hints)); hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
                    if (getaddrinfo(domain_for_ipv4, NULL, &hints, &res)==0 && res){
                        char ipbuf[64]; ipbuf[0]='\0';
                        for(struct addrinfo* p=res; p; p=p->ai_next){ if(p->ai_family!=AF_INET) continue; struct sockaddr_in* a=(struct sockaddr_in*)p->ai_addr; if(inet_ntop(AF_INET,&(a->sin_addr),ipbuf,sizeof(ipbuf))){
                                struct wc_net_info ni4; int rc4; ni4.connected=0; ni4.fd=-1; ni4.ip[0]='\0';
                                rc4 = wc_dial_43(ipbuf,(uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries,&ni4);
                                if(rc4==0 && ni4.connected){
                                    combined = append_and_free(combined, "\n=== Warning: empty response from ");
                                    combined = append_and_free(combined, current_host);
                                    combined = append_and_free(combined, ", retrying forced IPv4 ");
                                    combined = append_and_free(combined, ipbuf);
                                    combined = append_and_free(combined, " ===\n");
                                    // reuse current_host (logical) but replace ni context
                                    ni = ni4; handled_empty = 1; empty_retry++; out->meta.fallback_flags |= 0x4; break; }
                                else { if(ni4.fd>=0) close(ni4.fd); }
                            }}
                        freeaddrinfo(res);
                    }
                }
            }
            // Unified fallback extension: try known IPv4 mapping if still unhandled
            if (!handled_empty) {
                const char* domain_for_known=NULL;
                if (!is_ip_literal_str(current_host)) domain_for_known=current_host; else {
                    const char* ch = canonical_host_for_rir(rir_empty); if (ch) domain_for_known=ch; }
                if (domain_for_known){
                    const char* kip = get_known_ip(domain_for_known);
                    if (kip && kip[0]){
                        struct wc_net_info ni2; int rc2; ni2.connected=0; ni2.fd=-1; ni2.ip[0]='\0';
                        rc2 = wc_dial_43(kip,(uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries,&ni2);
                        if (rc2==0 && ni2.connected){
                            combined = append_and_free(combined, "\n=== Warning: empty response from ");
                            combined = append_and_free(combined, current_host);
                            combined = append_and_free(combined, ", retrying known IP ");
                            combined = append_and_free(combined, kip);
                            combined = append_and_free(combined, " ===\n");
                            ni = ni2; handled_empty=1; empty_retry++; out->meta.fallback_flags |= 0x1; if(strchr(kip,':')==NULL && strchr(kip,'.')!=NULL) out->meta.fallback_flags |= 0x4; }
                        else { if(ni2.fd>=0) close(ni2.fd); }
                    }
                }
            }
            if (!handled_empty && empty_retry == 0) {
                // last resort: once per host
                combined = append_and_free(combined, "\n=== Warning: empty response from ");
                combined = append_and_free(combined, current_host);
                combined = append_and_free(combined, ", retrying same host ===\n");
                handled_empty = 1; empty_retry++;
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
                if (!is_arin) {
                    int visited_iana = 0;
                    for (int i=0;i<visited_count;i++) { if (strcasecmp(visited[i], "whois.iana.org")==0) { visited_iana=1; break; } }
                    if (strcasecmp(current_host, "whois.iana.org") != 0 && !visited_iana) {
                        snprintf(next_host, sizeof(next_host), "%s", "whois.iana.org");
                        have_next = 1;
                        // mark fallback: iana pivot used
                        out->meta.fallback_flags |= 0x8; // iana_pivot
                    }
                }
            }
        } else {
            if (wc_normalize_whois_host(ref, next_host, sizeof(next_host)) != 0) {
                snprintf(next_host, sizeof(next_host), "%s", ref);
            }
            have_next = 1;
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
        if (candidates){ for(int i=0;i<cand_count;i++){ if(candidates[i]) free(candidates[i]); } free(candidates); candidates=NULL; }
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

    return (out->body ? 0 : (out->err? out->err : -1));
}
