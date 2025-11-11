// SPDX-License-Identifier: MIT
// lookup.c - Phase B skeleton implementation
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "wc/wc_lookup.h"
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_redirect.h"

static void wc_result_init(struct wc_result* r){ if(r){ memset(r,0,sizeof(*r)); r->err = 0; r->meta.via_host[0]=0; r->meta.via_ip[0]=0; r->meta.authoritative_host[0]=0; r->meta.authoritative_ip[0]=0; }}

void wc_lookup_result_free(struct wc_result* r){ if(!r) return; if(r->body){ free(r->body); r->body=NULL; } r->body_len=0; }

int wc_lookup_execute(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out) {
    if(!q || !q->raw || !out) return -1;
    struct wc_lookup_opts zopts = { .max_hops=5, .no_redirect=0, .timeout_sec=5, .retries=2 };
    if(opts) zopts = *opts;
    wc_result_init(out);

    // Pick starting server: explicit -> canonical; else guess by input type (simplified: default to whois.iana.org then referral)
    char start_host[128];
    if (q->start_server && q->start_server[0]) {
        if (wc_normalize_whois_host(q->start_server, start_host, sizeof(start_host)) != 0)
            snprintf(start_host, sizeof(start_host), "%s", q->start_server);
    } else {
        // IANA first hop strategy for cross-RIR stability
        snprintf(start_host, sizeof(start_host), "%s", "whois.iana.org");
    }

    // Connect first hop
    struct wc_net_info ni; int rc;
    rc = wc_dial_43(start_host, (uint16_t)(q->port>0?q->port:43), zopts.timeout_sec*1000, zopts.retries, &ni);
    if(rc!=0 || !ni.connected){ out->err = rc?rc:-1; return out->err; }
    snprintf(out->meta.via_host, sizeof(out->meta.via_host), "%s", start_host);
    snprintf(out->meta.via_ip, sizeof(out->meta.via_ip), "%s", ni.ip[0]?ni.ip:"unknown");

    // Send query (append \r\n per whois convention)
    size_t qlen = strlen(q->raw);
    char* line = (char*)malloc(qlen+3);
    if(!line){ out->err=-1; return out->err; }
    memcpy(line, q->raw, qlen); line[qlen]='\r'; line[qlen+1]='\n'; line[qlen+2]='\0';
    if (wc_send_all(ni.fd, line, qlen+2, zopts.timeout_sec*1000) < 0){ free(line); out->err=-1; return out->err; }
    free(line);

    // Read response (single shot in skeleton)
    char* body=NULL; size_t blen=0;
    if (wc_recv_until_idle(ni.fd, &body, &blen, zopts.timeout_sec*1000, 65536) < 0){ out->err=-1; return out->err; }

    // Decide referral vs authoritative (skeleton: use existing helpers)
    out->body = body; out->body_len = blen; out->meta.hops = 1;
    const char* final_host = start_host;
    if (!zopts.no_redirect) {
        char* ref = extract_refer_server(body);
        if (ref) {
            // Normalize and record as authoritative in skeleton; full redirect chain will be implemented later in Phase B+
            char canon[128];
            if (wc_normalize_whois_host(ref, canon, sizeof(canon))==0) final_host = strdup(canon); else final_host = ref;
            // Note: not following further for skeleton; just mark meta
        }
    }

    snprintf(out->meta.authoritative_host, sizeof(out->meta.authoritative_host), "%s", final_host);
    // authoritative_ip left unknown in skeleton (first hop IP already captured)
    return 0;
}
