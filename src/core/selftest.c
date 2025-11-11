// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // free
#include "wc/wc_selftest.h"
#include "wc/wc_fold.h"
#include "wc/wc_redirect.h"
#include "wc/wc_server.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
// Optional lookup-specific selftests (non-fatal, guarded by WHOIS_LOOKUP_SELFTEST)
int wc_selftest_lookup(void);

// Local portable helpers (avoid feature-macro prototypes)
static char* xstrdup(const char* s){ if(!s) return NULL; size_t n=strlen(s)+1; char* p=(char*)malloc(n); if(!p) return NULL; memcpy(p,s,n); return p; }
extern int putenv(char*);

// Lightweight harness network scenario validation without performing real external connects.
// We simulate authoritative / redirect decisions using crafted bodies and minimal wc_lookup_execute
// invocation when possible. For full end-to-end validation a remote smoke test is still required.

static int scenario_chain_tests(void) {
    int failed = 0;
    // We focus on redirect decision heuristics using is_authoritative_response / needs_redirect.
    // Scenario 1: ARIN direct should be authoritative (no IANA pivot) for typical ARIN body.
    const char* arin_body = "NetRange: 8.8.8.0 - 8.8.8.255\nOrgName: Google LLC\n";
    if (!is_authoritative_response(arin_body)) { fprintf(stderr, "[SELFTEST] scenario1-arin-authoritative: FAIL\n"); failed=1; }
    else fprintf(stderr, "[SELFTEST] scenario1-arin-authoritative: PASS\n");

    // Scenario 2: Simulate ARIN IPv4 blocked fallback via needs_redirect phrase (treated as redirect) then authoritative.
    // We cannot force network failure here; instead we validate redirect trigger phrase exists and authoritative phrase afterwards.
    const char* arin_block_phrase = "No match found for 199.91.0.46"; // sample placeholder
    if (!needs_redirect(arin_block_phrase)) { fprintf(stderr, "[SELFTEST] scenario2-arin-fallback-trigger: FAIL\n"); failed=1; }
    else fprintf(stderr, "[SELFTEST] scenario2-arin-fallback-trigger: PASS\n");

    // Scenario 3: IANA referral to ARIN: body shows Refer: whois.arin.net and is not itself authoritative for 8.8.8.8
    const char* iana_body = "refer: whois.arin.net\nwhois: data\n"; // lowercase refer acceptable
    if (!needs_redirect(iana_body)) { fprintf(stderr, "[SELFTEST] scenario3-iana-to-arin-redirect: FAIL\n"); failed=1; }
    else fprintf(stderr, "[SELFTEST] scenario3-iana-to-arin-redirect: PASS\n");

    // Scenario 4: IANA referral to APNIC (simulate 1.1.1.1 path)
    const char* iana_to_apnic = "Refer: whois.apnic.net\n";
    if (!needs_redirect(iana_to_apnic)) { fprintf(stderr, "[SELFTEST] scenario4-iana-to-apnic-redirect: FAIL\n"); failed=1; }
    else fprintf(stderr, "[SELFTEST] scenario4-iana-to-apnic-redirect: PASS\n");

    // Scenario 5: Empty-body fallback simulation – inject environment flag and ensure warning path reachable.
    // We trigger the code path by calling wc_lookup_execute on a query with WHOIS_SELFTEST_INJECT_EMPTY=1.
    // Since real network I/O is out of scope here (wc_dial_43 would attempt a connect), we guard with fast skip if dial fails.
    const char* prev = getenv("WHOIS_SELFTEST_INJECT_EMPTY");
    // Use putenv for portability (no feature macros needed). Caller must keep the string alive.
    char* inj_kv = xstrdup("WHOIS_SELFTEST_INJECT_EMPTY=1");
    if (inj_kv) putenv(inj_kv); // leaked intentionally until process exit to satisfy putenv contract
    struct wc_query q = { .raw = "8.8.8.8", .start_server = "whois.iana.org", .port = 43};
    struct wc_lookup_opts o = { .max_hops=2, .no_redirect=1, .timeout_sec=1, .retries=0 };
    struct wc_result r; memset(&r,0,sizeof(r));
    int lrc = wc_lookup_execute(&q, &o, &r);
    if (lrc == 0 && r.body && strstr(r.body, "Warning: empty response") ) {
        fprintf(stderr, "[SELFTEST] scenario5-empty-body-injection: PASS\n");
    } else {
        // If network unavailable (failure) we treat as inconclusive rather than FAIL to avoid false negatives in offline builds.
        if (lrc == 0) { fprintf(stderr, "[SELFTEST] scenario5-empty-body-injection: FAIL (no warning)\n"); failed=1; }
        else fprintf(stderr, "[SELFTEST] scenario5-empty-body-injection: SKIP (dial failure)\n");
    }
    wc_lookup_result_free(&r);
    // Scenario 6: LACNIC empty-body injection (single retry budget). We only check that if warning appears it is PASS.
    // Host whois.lacnic.net
    char* inj_kv2 = xstrdup("WHOIS_SELFTEST_INJECT_EMPTY=1"); if(inj_kv2) putenv(inj_kv2);
    struct wc_query q2 = { .raw = "2800:1:200::", .start_server = "whois.lacnic.net", .port = 43};
    struct wc_lookup_opts o2 = { .max_hops=1, .no_redirect=1, .timeout_sec=1, .retries=0 };
    struct wc_result r2; memset(&r2,0,sizeof(r2));
    int lrc2 = wc_lookup_execute(&q2, &o2, &r2);
    if (lrc2 == 0 && r2.body && strstr(r2.body, "Warning: empty response") ) {
        fprintf(stderr, "[SELFTEST] scenario6-lacnic-empty-body-injection: PASS\n");
    } else {
        if (lrc2 == 0) { fprintf(stderr, "[SELFTEST] scenario6-lacnic-empty-body-injection: FAIL (no warning)\n"); failed=1; }
        else fprintf(stderr, "[SELFTEST] scenario6-lacnic-empty-body-injection: SKIP (dial failure)\n");
    }
    wc_lookup_result_free(&r2);
    // restore unset (best-effort)
    char* unset_kv2 = xstrdup("WHOIS_SELFTEST_INJECT_EMPTY="); if(unset_kv2) putenv(unset_kv2);

    if (prev) {
        size_t n = strlen(prev) + strlen("WHOIS_SELFTEST_INJECT_EMPTY=") + 1;
        char* restore = (char*)malloc(n);
        if (restore) {
            snprintf(restore, n, "WHOIS_SELFTEST_INJECT_EMPTY=%s", prev);
            putenv(restore); // likewise intentionally leaked
        }
    } else {
        char* unset_kv = xstrdup("WHOIS_SELFTEST_INJECT_EMPTY=");
        if (unset_kv) putenv(unset_kv);
    }
    return failed ? 1 : 0;
}

int wc_selftest_run(void) {
    int failed = 0;

    // Network chain scenario checks (redirect heuristics + empty-body fallback injection)
    int sc = scenario_chain_tests();
    if (sc != 0) failed = 1;

    // Fold basic test
    const char* body = "netname: Google\n descr: Alpha\n descr: Alpha\n    Mountain View\n";
    char* s1 = wc_fold_build_line(body, "8.8.8.8", "whois.arin.net", " ", 1);
    if (!s1 || strstr(s1, "GOOGLE") == NULL) { fprintf(stderr, "[SELFTEST] fold-basic: FAIL\n"); failed = 1; }
    else fprintf(stderr, "[SELFTEST] fold-basic: PASS\n");
    if (s1) free(s1);

    // Fold unique test
    wc_fold_set_unique(1);
    char* s2 = wc_fold_build_line(body, "8.8.8.8", "whois.arin.net", ",", 1);
    if (!s2) { fprintf(stderr, "[SELFTEST] fold-unique: FAIL (null)\n"); failed = 1; }
    else {
        int has_dup = strstr(s2, ",ALPHA,ALPHA,") != NULL;
        if (has_dup) { fprintf(stderr, "[SELFTEST] fold-unique: FAIL (dup) -> %s\n", s2); failed = 1; }
        else fprintf(stderr, "[SELFTEST] fold-unique: PASS\n");
    }
    if (s2) free(s2);
    wc_fold_set_unique(0);

    // Redirect: needs_redirect basic phrases
    const char* redir_samples[] = {
        "No match found for 1.2.3.4",            // no match
        "This block is UNALLOCATED",             // unallocated
        "not registered in LACNIC",              // not registered
        "Refer: whois.ripe.net",                 // refer:
        NULL
    };
    for (int i = 0; redir_samples[i]; i++) {
        if (!needs_redirect(redir_samples[i])) { fprintf(stderr, "[SELFTEST] redirect-detect-%d: FAIL\n", i); failed = 1; } 
        else fprintf(stderr, "[SELFTEST] redirect-detect-%d: PASS\n", i);
    }

    // Redirect: is_authoritative_response indicators
    const char* auth_sample = "inetnum: 8.8.8.0 - 8.8.8.255\nnetname: GOOGLE\ncountry: US\n";
    if (!is_authoritative_response(auth_sample)) { fprintf(stderr, "[SELFTEST] auth-indicators: FAIL\n"); failed = 1; }
    else fprintf(stderr, "[SELFTEST] auth-indicators: PASS\n");

    // Redirect: extract_refer_server basic
    const char* ex1 = "ReferralServer: whois://whois.ripe.net\n";
    char* rs = extract_refer_server(ex1);
    if (!rs || strcmp(rs, "whois.ripe.net") != 0) { fprintf(stderr, "[SELFTEST] extract-refer: FAIL (%s)\n", rs ? rs : "null"); failed = 1; }
    else fprintf(stderr, "[SELFTEST] extract-refer: PASS\n");
    if (rs) free(rs);

    // Server normalize + RIR guess (light sanity)
    char hostbuf[64];
    if (wc_normalize_whois_host("ripe", hostbuf, sizeof(hostbuf)) != 0 || strcmp(hostbuf, "whois.ripe.net") != 0) {
        fprintf(stderr, "[SELFTEST] server-normalize: FAIL (%s)\n", hostbuf);
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] server-normalize: PASS\n");
    }
    const char* rir = wc_guess_rir("whois.arin.net");
    if (!rir || strcmp(rir, "arin") != 0) { fprintf(stderr, "[SELFTEST] rir-guess: FAIL (%s)\n", rir ? rir : "null"); failed = 1; }
    else fprintf(stderr, "[SELFTEST] rir-guess: PASS\n");

#ifdef WHOIS_GREP_TEST
    fprintf(stderr, "[SELFTEST] grep: BUILT-IN TESTS ENABLED (run at startup if env set)\n");
#else
    fprintf(stderr, "[SELFTEST] grep: not built (compile with -DWHOIS_GREP_TEST to enable)\n");
#endif

#ifdef WHOIS_SECLOG_TEST
    fprintf(stderr, "[SELFTEST] seclog: BUILT-IN TESTS ENABLED (run at startup if env set)\n");
#else
    fprintf(stderr, "[SELFTEST] seclog: not built (compile with -DWHOIS_SECLOG_TEST to enable)\n");
#endif

    // Lookup suite (weak)
    wc_selftest_lookup();

    return failed ? 1 : 0;
}

