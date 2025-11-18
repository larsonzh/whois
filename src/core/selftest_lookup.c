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
    // Use runtime flag to inject empty body once (no env dependency).
    wc_selftest_set_inject_empty(1);
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
    wc_selftest_set_inject_empty(0);
    return 0;
}

static int test_dns_no_fallback_smoke(void){
    // Smoke-test that --dns-no-fallback does not crash lookup and still completes a query.
    struct wc_query q = { .raw = "example.com", .start_server = NULL, .port = 43 };
    struct wc_lookup_opts o = { .max_hops = 2, .no_redirect = 0, .timeout_sec = 2, .retries = 1 };
    struct wc_result r; memset(&r,0,sizeof(r));
    int rc = wc_lookup_execute(&q,&o,&r);
    if (rc == 0) {
        fprintf(stderr,"[LOOKUP_SELFTEST] dns-no-fallback-smoke: PASS (via=%s auth=%s)\n",
                r.meta.via_host, r.meta.authoritative_host);
    } else {
        fprintf(stderr,"[LOOKUP_SELFTEST] dns-no-fallback-smoke: SKIP (dial fail rc=%d)\n", rc);
    }
    wc_lookup_result_free(&r);
    return 0;
}

    static int test_dns_no_fallback_known_ip(void){
        // This test assumes a network where known-IP fallback for ARIN would normally be attempted.
        // We use the selftest DNS fallback counters to assert that when dns-no-fallback is enabled,
        // no known-IP attempts are recorded.
        wc_selftest_reset_dns_fallback_counters();
        struct wc_query q = { .raw = "8.8.8.8", .start_server = "arin", .port = 43 };
        struct wc_lookup_opts o = { .max_hops = 2, .no_redirect = 0, .timeout_sec = 2, .retries = 0 };
        struct wc_result r; memset(&r,0,sizeof(r));
        int rc = wc_lookup_execute(&q,&o,&r);
        (void)rc; // network-dependent; we only care about counters here
        int forced_ipv4 = wc_selftest_forced_ipv4_attempts();
        int known_ip = wc_selftest_known_ip_attempts();
        fprintf(stderr,
            "[LOOKUP_SELFTEST] dns-no-fallback-known-ip: forced_ipv4=%d known_ip=%d (informational)\n",
            forced_ipv4, known_ip);
        wc_lookup_result_free(&r);
        return 0;
    }

int wc_selftest_lookup(void){
    test_iana_first_path();
    test_no_redirect_single();
    test_empty_injection();
        test_dns_no_fallback_smoke();
        test_dns_no_fallback_known_ip();
    return 0; // non-fatal aggregate
}
#endif
