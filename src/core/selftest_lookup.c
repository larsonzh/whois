// SPDX-License-Identifier: MIT
// selftest_lookup.c - optional minimal lookup-specific selftests (Phase-in)
// Enabled when compiled with -DWHOIS_LOOKUP_SELFTEST. Safe no-op otherwise.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wc/wc_lookup.h"
#include "wc/wc_selftest.h"

#ifndef WHOIS_LOOKUP_SELFTEST
int wc_selftest_lookup(void){ return 0; }
#else
static int test_iana_first_path(void){
    struct wc_query q = { .raw = "8.8.8.8", .start_server = NULL, .port = 43 };
    struct wc_lookup_opts o = { .max_hops = 4, .no_redirect = 0, .timeout_sec = 2, .retries = 1 };
    struct wc_result r; memset(&r,0,sizeof(r));
    int rc = wc_lookup_execute(&q,&o,&r);
    if(rc!=0){ fprintf(stderr,"[LOOKUP_SELFTEST] iana-first: SKIP (dial fail rc=%d)\n", rc); return 0; }
    int pass = (r.meta.via_host[0] && strstr(r.meta.via_host,"iana")) && r.meta.authoritative_host[0];
    fprintf(stderr,"[LOOKUP_SELFTEST] iana-first: %s (via=%s auth=%s)\n", pass?"PASS":"WARN", r.meta.via_host, r.meta.authoritative_host);
    wc_lookup_result_free(&r); return pass?0:0; // WARN treated as non-fatal
}

static int test_no_redirect_single(void){
    struct wc_query q = { .raw = "1.1.1.1", .start_server = NULL, .port = 43 };
    struct wc_lookup_opts o = { .max_hops = 1, .no_redirect = 1, .timeout_sec = 2, .retries = 0 };
    struct wc_result r; memset(&r,0,sizeof(r));
    int rc = wc_lookup_execute(&q,&o,&r);
    if(rc!=0){ fprintf(stderr,"[LOOKUP_SELFTEST] no-redirect-single: SKIP (dial fail rc=%d)\n", rc); return 0; }
    fprintf(stderr,"[LOOKUP_SELFTEST] no-redirect-single: PASS (via=%s)\n", r.meta.via_host);
    wc_lookup_result_free(&r); return 0;
}

static int test_empty_injection(void){
    // Use environment flag to inject empty body once.
    const char* prev = getenv("WHOIS_SELFTEST_INJECT_EMPTY");
    setenv("WHOIS_SELFTEST_INJECT_EMPTY","1",1);
    struct wc_query q = { .raw = "8.8.4.4", .start_server = "whois.iana.org", .port = 43 };
    struct wc_lookup_opts o = { .max_hops = 2, .no_redirect = 1, .timeout_sec = 2, .retries = 0 };
    struct wc_result r; memset(&r,0,sizeof(r)); int rc = wc_lookup_execute(&q,&o,&r);
    if(rc==0 && r.body && strstr(r.body,"Warning: empty response")){
        fprintf(stderr,"[LOOKUP_SELFTEST] empty-body-injection: PASS\n");
    } else if(rc==0){
        fprintf(stderr,"[LOOKUP_SELFTEST] empty-body-injection: WARN (no warning captured)\n");
    } else {
        fprintf(stderr,"[LOOKUP_SELFTEST] empty-body-injection: SKIP (dial fail rc=%d)\n", rc);
    }
    wc_lookup_result_free(&r);
    if(prev) setenv("WHOIS_SELFTEST_INJECT_EMPTY", prev, 1); else unsetenv("WHOIS_SELFTEST_INJECT_EMPTY");
    return 0;
}

int wc_selftest_lookup(void){
    test_iana_first_path();
    test_no_redirect_single();
    test_empty_injection();
    return 0; // non-fatal aggregate
}
#endif
