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
    int dns_addrconfig; int dns_retry; int dns_retry_interval_ms; int dns_max_candidates; int no_dns_known_fallback; int no_dns_force_ipv4_fallback; int no_iana_pivot;
} g_config;
#include <netdb.h>
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"
#include "wc/wc_selftest.h"
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

    // Start candidate list; when a single family is enforced we skip raw hostname dialing
    // because wc_dial_43 would internally resolve with system order possibly choosing the
    // undesired family. Instead we only include numeric literals of the requested family.
    // Historical note: previously the canonical hostname was tried first, which could
    // yield an IPv6 address even under --ipv4-only. We now omit the hostname in single-
    // family modes to strictly enforce the requested address family.
    int cap = 12; int cnt = 0; char** list = (char**)malloc(sizeof(char*)*cap); if(!list) return;
    // 0) If the user explicitly provided an IP literal, try it first as-is
    if (current_host && is_ip_literal_str(current_host)) {
        list[cnt++] = xstrdup(current_host);
    }
    int allow_hostname_fallback = !(g_config.ipv4_only || g_config.ipv6_only);

    // Selftest: blackhole specific hops by forcing TEST-NET target
    if (wc_selftest_blackhole_iana_enabled() && strcasecmp(canon, "whois.iana.org") == 0) {
        list[cnt++] = xstrdup("192.0.2.1"); // unroutable TEST-NET-1
        *out_list = list; *out_count = cnt; return;
    }
    if (wc_selftest_blackhole_arin_enabled() && strcasecmp(canon, "whois.arin.net") == 0) {
        list[cnt++] = xstrdup("192.0.2.1"); // unroutable TEST-NET-1
        *out_list = list; *out_count = cnt; return;
    }

    // Resolve canon and collect numeric addresses (prefer IPv6, then IPv4), unique
    struct addrinfo hints; memset(&hints,0,sizeof(hints)); hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_UNSPEC;
#ifdef AI_ADDRCONFIG
    if (g_config.dns_addrconfig) hints.ai_flags = AI_ADDRCONFIG; else hints.ai_flags = 0;
#endif
    struct addrinfo* res=NULL; {
        int gai_rc=0; int tries=0; int maxtries = (g_config.dns_retry>0?g_config.dns_retry:1);
        do {
            gai_rc = getaddrinfo(canon, "43", &hints, &res);
            if (gai_rc==EAI_AGAIN && tries < maxtries-1) {
                int ms = (g_config.dns_retry_interval_ms>=0?g_config.dns_retry_interval_ms:100);
                struct timespec ts; ts.tv_sec = (time_t)(ms/1000); ts.tv_nsec = (long)((ms%1000)*1000000L); nanosleep(&ts,NULL);
            }
            tries++;
        } while(gai_rc==EAI_AGAIN && tries<maxtries);
    }
    if(res){
        // Lightweight Happy Eyeballs: collect IPv4/IPv6 lists, then interleave.
        // In prefer-{ipv4,ipv6} modes, start from the preferred family, then alternate;
        // in single-family enforced modes keep strict semantics.
        char* v4[64]; int v4c=0; char* v6[64]; int v6c=0; // Size is sufficient; further capped by dns_max_candidates
        for(struct addrinfo* rp=res; rp; rp=rp->ai_next){
            int fam = rp->ai_family;
            if (fam!=AF_INET && fam!=AF_INET6) continue;
            char ipbuf[64];
            if(getnameinfo(rp->ai_addr, rp->ai_addrlen, ipbuf, sizeof(ipbuf), NULL, 0, NI_NUMERICHOST)!=0) continue;
            // Simple dedup: check both buckets first
            int dup=0; for(int i=0;i<v4c;i++){ if(v4[i] && strcmp(v4[i], ipbuf)==0){ dup=1; break; } }
            if(!dup) for(int i=0;i<v6c;i++){ if(v6[i] && strcmp(v6[i], ipbuf)==0){ dup=1; break; } }
            if(dup) continue;
            if (fam==AF_INET && v4c < (int)(sizeof(v4)/sizeof(v4[0]))) v4[v4c++]=xstrdup(ipbuf);
            else if (fam==AF_INET6 && v6c < (int)(sizeof(v6)/sizeof(v6[0]))) v6[v6c++]=xstrdup(ipbuf);
        }
        // Emit according to mode:
        if (g_config.ipv4_only || g_config.ipv6_only) {
            int fam = g_config.ipv4_only ? AF_INET : AF_INET6;
            char** src = (fam==AF_INET)?v4:v6; int srcc = (fam==AF_INET)?v4c:v6c;
            for(int i=0;i<srcc;i++){
                if (g_config.dns_max_candidates>0 && cnt >= g_config.dns_max_candidates) break;
                if(cnt>=cap){ cap*=2; char** nl=(char**)realloc(list,sizeof(char*)*cap); if(!nl) break; list=nl; }
                list[cnt++] = src[i]; src[i]=NULL; // 迁移所有权
            }
        } else {
            int prefer_v4_first = g_config.prefer_ipv4 ? 1 : 0; // 默认 prefer IPv6
            int i4=0,i6=0; int turn = prefer_v4_first ? 0 : 1; // 0->v4, 1->v6
            while ((i4<v4c || i6<v6c) && (g_config.dns_max_candidates==0 || cnt<g_config.dns_max_candidates)){
                if (turn==0 && i4<v4c){
                    if(cnt>=cap){ cap*=2; char** nl=(char**)realloc(list,sizeof(char*)*cap); if(!nl) break; list=nl; }
                    list[cnt++] = v4[i4++];
                } else if (turn==1 && i6<v6c){
                    if(cnt>=cap){ cap*=2; char** nl=(char**)realloc(list,sizeof(char*)*cap); if(!nl) break; list=nl; }
                    list[cnt++] = v6[i6++];
                }
                // Alternate; once one family runs out, keep using the other
                if (i4>=v4c) turn = 1; else if (i6>=v6c) turn = 0; else turn ^= 1;
            }
            // 释放未迁移的临时项
            for(;i4<v4c;i4++){ if(v4[i4]) free(v4[i4]); }
            for(;i6<v6c;i6++){ if(v6[i6]) free(v6[i6]); }
        }
        freeaddrinfo(res);
    }
    // Defer dialing by hostname: append as a fallback after numeric candidates, or
    // when resolution yielded no numeric addresses. This preserves --prefer-ipv4/--prefer-ipv6
    // ordering and avoids system default family taking precedence.
    if (allow_hostname_fallback) {
        int has_numeric = 0;
        for (int i=0;i<cnt;i++){ if (is_ip_literal_str(list[i])) { has_numeric = 1; break; } }
        if (!has_numeric || (g_config.dns_max_candidates==0 || cnt < g_config.dns_max_candidates)) {
            if(cnt>=cap){ cap*=2; char** nl=(char**)realloc(list,sizeof(char*)*cap); if(nl) list=nl; }
            if (cnt < cap) list[cnt++] = xstrdup(canon);
        }
    }
    *out_list = list; *out_count = cnt;
}

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
        const char* canon_label = canonical_host_for_rir(q->start_server);
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
        char** candidates = NULL; int cand_count = 0;
        build_dynamic_candidates(current_host, rir, &candidates, &cand_count);
        int connected_ok = 0; int first_conn_rc = 0;
        for (int i=0; i<cand_count; ++i){
            const char* target = candidates[i];
            // avoid duplicate immediate retry of identical token
            if (i>0 && strcasecmp(target, current_host)==0) continue;
            rc = wc_dial_43(target, (uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries, &ni);
            if (rc==0 && ni.connected){
                // Do not mutate logical current_host with numeric dial targets; keep it as the logical server label.
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
            if (domain_for_ipv4 && !g_config.no_dns_force_ipv4_fallback) {
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
            if (!connected_ok && domain_for_known && !g_config.no_dns_known_fallback) {
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
                out->err = first_conn_rc?first_conn_rc:-1;
                out->meta.last_connect_errno = ni.last_errno; // propagate failure errno
                break;
            }
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
                char** cands2=NULL; int cc2=0; build_dynamic_candidates(current_host, rir_empty, &cands2, &cc2);
                const char* pick=NULL;
                for(int i=0;i<cc2;i++){
                    const char* t = cands2[i];
                    if (strcasecmp(t, current_host)==0) continue;
                    // Prefer IP literal that differs from last connected ip
                    // Update last errno (0 if connected ok)
                    out->meta.last_connect_errno = ni.connected ? 0 : ni.last_errno;
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
                    /* keep logical current_host unchanged; only change dial target */
                    handled_empty = 1; empty_retry++;
                }
                if (cands2){ for(int i=0;i<cc2;i++){ if(cands2[i]) free(cands2[i]); } free(cands2); }
            }
            // Unified fallback extension: if still not handled, attempt IPv4-only re-dial of same logical domain
            if (!handled_empty && !g_config.no_dns_force_ipv4_fallback) {
                const char* domain_for_ipv4 = NULL;
                if (!is_ip_literal_str(current_host)) domain_for_ipv4 = current_host; else {
                    const char* ch = canonical_host_for_rir(rir_empty);
                    if (ch) domain_for_ipv4 = ch;
                }
                if (domain_for_ipv4) {
                    struct addrinfo hints,*res=NULL; memset(&hints,0,sizeof(hints)); hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
                    int gai=0, tries=0, maxtries=(g_config.dns_retry>0?g_config.dns_retry:1);
                    do { gai=getaddrinfo(domain_for_ipv4, NULL, &hints, &res); if(gai==EAI_AGAIN && tries<maxtries-1){ int ms=(g_config.dns_retry_interval_ms>=0?g_config.dns_retry_interval_ms:100); struct timespec ts; ts.tv_sec=ms/1000; ts.tv_nsec=(long)((ms%1000)*1000000L); nanosleep(&ts,NULL);} tries++; } while(gai==EAI_AGAIN && tries<maxtries);
                    if (gai==0 && res){
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
            if (!handled_empty && !g_config.no_dns_known_fallback) {
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
                if (!is_arin && !g_config.no_iana_pivot) {
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

    // If there is a non-zero error code (e.g., connection failure during the redirection phase), 
    // even if some output has already been accumulated, a failure should be returned to allow the frontend to print the error.
    if (out->err) return out->err;
    return (out->body ? 0 : -1);
}
