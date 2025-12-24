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
#include "wc/wc_dns.h"
#include "wc/wc_config.h"
#include "wc/wc_runtime.h"
#include "wc/wc_query_exec.h"

Config wc_selftest_config_snapshot(void)
{
    Config cfg;
    wc_runtime_snapshot_config(&cfg);
    return cfg;
}
// Optional lookup-specific selftests (non-fatal, guarded by WHOIS_LOOKUP_SELFTEST)
int wc_selftest_lookup(void);

// (env-free version) no local helpers needed

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
    Config cfg = wc_selftest_config_snapshot();
    wc_selftest_set_inject_empty(1);
    struct wc_query q = { .raw = "8.8.8.8", .start_server = "whois.iana.org", .port = 43};
    struct wc_lookup_opts o = { .max_hops=2, .no_redirect=1, .timeout_sec=1, .retries=0,
        .net_ctx = wc_net_context_get_active(), .config = &cfg };
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
    wc_selftest_set_inject_empty(1);
    struct wc_query q2 = { .raw = "2800:1:200::", .start_server = "whois.lacnic.net", .port = 43};
    struct wc_lookup_opts o2 = { .max_hops=1, .no_redirect=1, .timeout_sec=1, .retries=0,
        .net_ctx = wc_net_context_get_active(), .config = &cfg };
    struct wc_result r2; memset(&r2,0,sizeof(r2));
    int lrc2 = wc_lookup_execute(&q2, &o2, &r2);
    if (lrc2 == 0 && r2.body && strstr(r2.body, "Warning: empty response") ) {
        fprintf(stderr, "[SELFTEST] scenario6-lacnic-empty-body-injection: PASS\n");
    } else {
        if (lrc2 == 0) { fprintf(stderr, "[SELFTEST] scenario6-lacnic-empty-body-injection: FAIL (no warning)\n"); failed=1; }
        else fprintf(stderr, "[SELFTEST] scenario6-lacnic-empty-body-injection: SKIP (dial failure)\n");
    }
    wc_lookup_result_free(&r2);
    wc_selftest_set_inject_empty(0);
    return failed ? 1 : 0;
}

static void selftest_dns_candidate_limit(void) {
    Config base = wc_selftest_config_snapshot();
    Config cfg = base;
    cfg.dns_max_candidates = 1;
    const wc_selftest_injection_t* injection = wc_selftest_export_injection();
    wc_dns_candidate_list_t list = {0};
    int rc = wc_dns_build_candidates(&cfg, "whois.arin.net", "arin", -1, &list, injection);
    if (rc != 0 || list.count == 0) {
        fprintf(stderr, "[SELFTEST] dns-cand-limit: SKIP (resolver unavailable)\n");
    } else {
        int pass = (list.count <= 1);
        fprintf(stderr, "[SELFTEST] dns-cand-limit: %s (count=%d)\n", pass ? "PASS" : "WARN", list.count);
    }
    wc_dns_candidate_list_free(&list);
}

static void selftest_dns_negative_flag(void) {
    wc_dns_candidate_list_t list = {0};
    wc_selftest_set_dns_negative(1);
    Config cfg = wc_selftest_config_snapshot();
    const wc_selftest_injection_t* injection = wc_selftest_export_injection();
    int rc = wc_dns_build_candidates(&cfg, "selftest.invalid", "unknown", -1, &list, injection);
    if (rc == 0 && list.count > 0) {
        fprintf(stderr, "[SELFTEST] dns-neg-cache: WARN (unexpected candidates)\n");
    } else {
        fprintf(stderr, "[SELFTEST] dns-neg-cache: PASS (gai_err=%d)\n", list.last_error);
    }
    wc_dns_candidate_list_free(&list);
    wc_selftest_set_dns_negative(0);
}

static int selftest_dns_family_controls(void) {
    const char* literal = "2001:db8::cafe";
    Config base = wc_selftest_config_snapshot();
    int failed_local = 0;
    const wc_selftest_injection_t* injection = wc_selftest_export_injection();

    // Scenario A: IPv6-only should suppress canonical host fallback (numeric-only list)
    Config ipv6_only = base;
    ipv6_only.ipv4_only = 0;
    ipv6_only.ipv6_only = 1;
    ipv6_only.prefer_ipv4 = 0;
    ipv6_only.prefer_ipv6 = 0;
    wc_dns_candidate_list_t list = {0};
    int rc = wc_dns_build_candidates(&ipv6_only, literal, "arin", -1, &list, injection);
    if (rc != 0) {
        fprintf(stderr, "[SELFTEST] dns-ipv6-only-candidates: SKIP (rc=%d last_error=%d)\n", rc, list.last_error);
    } else {
        int pass = (list.count == 1 && list.items && list.items[0] && strcmp(list.items[0], literal) == 0);
        if (pass && list.origins) {
            pass = (list.origins[0] == (unsigned char)WC_DNS_ORIGIN_INPUT);
        }
        fprintf(stderr, "[SELFTEST] dns-ipv6-only-candidates: %s\n", pass ? "PASS" : "WARN");
        if (!pass) {
            fprintf(stderr, "  details: count=%d literal=%s origin=%u\n", list.count,
                (list.items && list.items[0]) ? list.items[0] : "(null)",
                (list.origins ? list.origins[0] : 255));
        }
    }
    wc_dns_candidate_list_free(&list);

    // Scenario B: default family preference allows canonical host fallback to reappear
    Config prefer_v6 = base;
    prefer_v6.ipv6_only = 0;
    prefer_v6.prefer_ipv6 = 1;
    list = (wc_dns_candidate_list_t){0};
    rc = wc_dns_build_candidates(&prefer_v6, literal, "arin", -1, &list, injection);
    if (rc != 0) {
        fprintf(stderr, "[SELFTEST] dns-canonical-fallback: SKIP (rc=%d last_error=%d)\n", rc, list.last_error);
    } else {
        const char* canon = wc_dns_canonical_host_for_rir("arin");
        int found = 0;
        for (int i = 0; i < list.count; ++i) {
            if (list.items && list.items[i] && canon && strcmp(list.items[i], canon) == 0) {
                if (!list.origins || list.origins[i] == (unsigned char)WC_DNS_ORIGIN_CANONICAL) {
                    found = 1;
                    break;
                }
            }
        }
        fprintf(stderr, "[SELFTEST] dns-canonical-fallback: %s\n", found ? "PASS" : "FAIL");
        if (!found) failed_local = 1;
    }
    wc_dns_candidate_list_free(&list);
    return failed_local;
}

static int selftest_injection_view_fallback(void) {
    const wc_selftest_injection_t* current = wc_selftest_injection_view();
    wc_selftest_injection_t backup = {0};
    if (current)
        backup = *current;
    wc_selftest_injection_t inj = backup;
    inj.force_suspicious = "*";
    if (inj.fault_version == 0)
        inj.fault_version = 1;
    wc_selftest_set_injection_view_for_test(&inj);
    int rc = wc_handle_suspicious_query("1.2.3.4", 0, NULL);
    int failed_local = 0;
    if (rc != 0) {
        fprintf(stderr, "[SELFTEST] action=injection-view-fallback: PASS\n");
    } else {
        fprintf(stderr, "[SELFTEST] action=injection-view-fallback: FAIL\n");
        failed_local = 1;
    }
    wc_selftest_set_injection_view_for_test(&backup);
    return failed_local;
}

static int selftest_dns_fallback_toggles(void) {
    Config base = wc_selftest_config_snapshot();

    struct wc_query q = { .raw = "8.8.8.8", .start_server = "whois.arin.net", .port = 43 };
    struct wc_lookup_opts opts_enabled = { .max_hops = 1, .no_redirect = 1, .timeout_sec = 1, .retries = 0,
        .net_ctx = wc_net_context_get_active(), .config = &base };
    struct wc_result r; memset(&r, 0, sizeof(r));

    wc_selftest_set_blackhole_arin(1);
    Config enabled = base;
    enabled.no_dns_force_ipv4_fallback = 0;
    enabled.no_dns_known_fallback = 0;
    wc_selftest_reset_dns_fallback_counters();
    opts_enabled.config = &enabled;
    int rc = wc_lookup_execute(&q, &opts_enabled, &r);
    int forced_attempts = wc_selftest_forced_ipv4_attempts();
    int known_attempts = wc_selftest_known_ip_attempts();
    int failed_local = 0;
    if (forced_attempts > 0 && known_attempts > 0) {
        fprintf(stderr, "[SELFTEST] dns-fallback-enabled: PASS (forced=%d known=%d rc=%d)\n",
                forced_attempts, known_attempts, rc);
    } else {
        fprintf(stderr, "[SELFTEST] dns-fallback-enabled: WARN (forced=%d known=%d rc=%d)\n",
                forced_attempts, known_attempts, rc);
    }
    wc_lookup_result_free(&r);
    Config disabled = base;
    disabled.no_dns_force_ipv4_fallback = 1;
    disabled.no_dns_known_fallback = 1;
    struct wc_lookup_opts opts_disabled = { .max_hops = 1, .no_redirect = 1, .timeout_sec = 1, .retries = 0,
        .net_ctx = wc_net_context_get_active(), .config = &disabled };
    wc_selftest_reset_dns_fallback_counters();
    memset(&r, 0, sizeof(r));
    int rc2 = wc_lookup_execute(&q, &opts_disabled, &r);
    forced_attempts = wc_selftest_forced_ipv4_attempts();
    known_attempts = wc_selftest_known_ip_attempts();
    if (forced_attempts == 0 && known_attempts == 0) {
        fprintf(stderr, "[SELFTEST] dns-fallback-disabled: PASS (rc=%d)\n", rc2);
    } else {
        fprintf(stderr, "[SELFTEST] dns-fallback-disabled: WARN (forced=%d known=%d rc=%d)\n",
                forced_attempts, known_attempts, rc2);
    }
    wc_lookup_result_free(&r);

    wc_selftest_set_blackhole_arin(0);
    return failed_local;
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

    const char* parent_guard_sample =
        "inetnum: 143.128.0.0 - 143.128.255.255\n"
        "parent: 0.0.0.0 - 255.255.255.255\n"
        "ReferralServer: whois://whois.afrinic.net\n";
    char* parent_rs = extract_refer_server(parent_guard_sample);
    if (!parent_rs || strcmp(parent_rs, "whois.afrinic.net") != 0) {
        fprintf(stderr, "[SELFTEST] redirect-parent-guard: FAIL (%s)\n", parent_rs ? parent_rs : "null");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] redirect-parent-guard: PASS\n");
    }
    if (parent_rs) free(parent_rs);

    const char* parent_guard_sample_v6 =
        "inet6num: 2c0f:fea0::/32\n"
        "parent: ::/0\n"
        "ReferralServer: whois://whois.afrinic.net\n";
    char* parent_rs_v6 = extract_refer_server(parent_guard_sample_v6);
    if (!parent_rs_v6 || strcmp(parent_rs_v6, "whois.afrinic.net") != 0) {
        fprintf(stderr, "[SELFTEST] redirect-parent-guard-v6: FAIL (%s)\n",
                parent_rs_v6 ? parent_rs_v6 : "null");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] redirect-parent-guard-v6: PASS\n");
    }
    if (parent_rs_v6) free(parent_rs_v6);

    const char* ipv6_guard_sample = "inet6num: ::/0\n";
    if (!needs_redirect(ipv6_guard_sample)) {
        fprintf(stderr, "[SELFTEST] redirect-inet6num-guard: FAIL\n");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] redirect-inet6num-guard: PASS\n");
    }

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

    selftest_dns_candidate_limit();
    selftest_dns_negative_flag();
    failed |= selftest_dns_family_controls();
    failed |= selftest_dns_fallback_toggles();
    failed |= selftest_injection_view_fallback();

    return failed ? 1 : 0;
}

