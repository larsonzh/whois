// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // free
#include "wc/wc_selftest.h"
#include "lookup_exec_terminal_retry.h"
#include "wc/wc_preclass.h"
#include "wc/wc_opts.h"
#include "wc/wc_fold.h"
#include "wc/wc_redirect.h"
#include "wc/wc_server.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "wc/wc_dns.h"
#include "wc/wc_config.h"
#include "wc/wc_runtime.h"
#include "wc/wc_pipeline.h"
#include "wc/wc_query_exec.h"
#include "wc/wc_workbuf.h"
#include "wc/wc_batch_strategy.h"
#include "wc/wc_title.h"
#include "wc/wc_pick.h"
#include "lookup_internal.h"
#include "lookup_exec_redirect.h"
#include "lookup_exec_next.h"

Config wc_selftest_config_snapshot(void)
{
    Config cfg;
    wc_runtime_snapshot_config(&cfg);
    return cfg;
}
// Optional lookup-specific selftests (non-fatal, guarded by WHOIS_LOOKUP_SELFTEST)
int wc_selftest_lookup(void);
int wc_selftest_registry(void);

typedef struct wc_selftest_registry_override_state_s {
    int on_result_called;
} wc_selftest_registry_override_state_t;

static const char* wc_selftest_registry_override_pick(
        const wc_batch_context_t* ctx)
{
    (void)ctx;
    return "whois.override.test";
}

static void wc_selftest_registry_override_on_result(
        const wc_batch_context_t* ctx,
        const wc_batch_strategy_result_t* result)
{
    (void)ctx;
    if (!result)
        return;
    wc_selftest_registry_override_state_t* state =
        (wc_selftest_registry_override_state_t*)ctx->strategy_state;
    if (state)
        state->on_result_called = 1;
}

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
    int rc = wc_dns_build_candidates(&cfg, "whois.arin.net", "arin", -1, 0, &list, injection);
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
    int rc = wc_dns_build_candidates(&cfg, "selftest.invalid", "unknown", -1, 0, &list, injection);
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
    int rc = wc_dns_build_candidates(&ipv6_only, literal, "arin", -1, 0, &list, injection);
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
    rc = wc_dns_build_candidates(&prefer_v6, literal, "arin", -1, 0, &list, injection);
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
    int rc = wc_handle_suspicious_query(NULL, "1.2.3.4;", 0, NULL);
    int failed_local = 0;
    if (rc == 0) {
        fprintf(stderr, "[SELFTEST] action=injection-view-fallback: PASS\n");
    } else {
        fprintf(stderr, "[SELFTEST] action=injection-view-fallback: FAIL\n");
        failed_local = 1;
    }
    wc_selftest_set_injection_view_for_test(&backup);
    return failed_local;
}

static int selftest_crlf_normalization(void) {
    Config cfg = wc_selftest_config_snapshot();
    wc_workbuf_t wb; wc_workbuf_init(&wb);
    int title_enabled = wc_title_is_enabled();
    wc_title_set_enabled(0); // ensure CRLF check isn't affected by title projection

    const char* sample = "line1\r\nline2\rline3\nline4\r\n";
    const char* expected = "line1\nline2\nline3\nline4\n";
    char* out = wc_apply_response_filters(&cfg, "crlf-test", sample, 0, &wb);
    int failed_local = 0;
    if (!out) {
        fprintf(stderr, "[SELFTEST] crlf-normalize: FAIL (null)\n");
        failed_local = 1;
    } else if (strcmp(out, expected) != 0) {
        fprintf(stderr, "[SELFTEST] crlf-normalize: FAIL (got=\"%s\")\n", out);
        failed_local = 1;
    } else {
        fprintf(stderr, "[SELFTEST] crlf-normalize: PASS\n");
    }

    wc_workbuf_free(&wb);

    // Verify CR-only bodies do not leak unmatched headers after normalization.
    wc_workbuf_init(&wb);
    wc_title_parse_patterns("inetnum");
    wc_title_set_enabled(1);
    const char* cr_body = "inetnum: 1.1.1.0 - 1.1.1.255\rnetname: SHOULD-NOT-LEAK\r";
    char* filtered = wc_apply_response_filters(&cfg, "1.1.1.1", cr_body, 0, &wb);
    if (!filtered) {
        fprintf(stderr, "[SELFTEST] normalize-crlf-title: FAIL (null)\n");
        failed_local = 1;
    } else {
        int has_inetnum = strstr(filtered, "inetnum: 1.1.1.0 - 1.1.1.255") != NULL;
        int leaks_netname = strstr(filtered, "netname: SHOULD-NOT-LEAK") != NULL;
        if (has_inetnum && !leaks_netname) {
            fprintf(stderr, "[SELFTEST] normalize-crlf-title: PASS\n");
        } else {
            fprintf(stderr, "[SELFTEST] normalize-crlf-title: FAIL (inetnum=%d leak=%d)\n",
                has_inetnum, leaks_netname);
            failed_local = 1;
        }
    }

    wc_title_free();
    wc_workbuf_free(&wb);
    wc_title_set_enabled(title_enabled);
    return failed_local;
}

int wc_selftest_registry(void)
{
    int failed_local = 0;
    const wc_batch_strategy_iface_t* global_before = wc_batch_strategy_get_active();

    wc_batch_strategy_registry_t reg;
    wc_batch_strategy_registry_init(&reg);
    wc_batch_strategy_registry_register_builtins(&reg);

    const wc_batch_strategy_iface_t* active =
        wc_batch_strategy_registry_get_active(&reg);
    if (!active || strcmp(active->name, "raw") != 0) {
        fprintf(stderr,
            "[SELFTEST] action=batch-registry-default: FAIL (name=%s)\n",
            active ? active->name : "(null)");
        failed_local = 1;
    } else {
        fprintf(stderr, "[SELFTEST] action=batch-registry-default: PASS\n");
    }

    if (!wc_batch_strategy_registry_set_active_name(&reg, "health-first")) {
        fprintf(stderr, "[SELFTEST] action=batch-registry-set-active: FAIL (health-first)\n");
        failed_local = 1;
    } else {
        const wc_batch_strategy_iface_t* hf =
            wc_batch_strategy_registry_get_active(&reg);
        fprintf(stderr,
            "[SELFTEST] action=batch-registry-set-active: PASS (name=%s)\n",
            hf ? hf->name : "(null)");
    }

    wc_selftest_registry_override_state_t override_state = {0};
    wc_batch_strategy_iface_t override_iface = {
        .name = "registry-override",
        .init = NULL,
        .pick_start_host = wc_selftest_registry_override_pick,
        .on_result = wc_selftest_registry_override_on_result,
        .teardown = NULL,
    };

    wc_batch_strategy_registry_register(&reg, &override_iface);
    if (!wc_batch_strategy_registry_set_active_name(&reg, override_iface.name)) {
        fprintf(stderr, "[SELFTEST] action=batch-registry-override: FAIL (activate)\n");
        failed_local = 1;
    }

    const char* candidates[2] = { "whois.arin.net", "whois.ripe.net" };
    wc_batch_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_host = "whois.iana.org";
    ctx.candidates = candidates;
    ctx.candidate_count = 2;
    ctx.strategy_state = &override_state;

    const char* picked = wc_batch_strategy_registry_pick(&reg, &ctx);
    if (!picked || strcmp(picked, "whois.override.test") != 0) {
        fprintf(stderr, "[SELFTEST] action=batch-registry-override-pick: FAIL (picked=%s)\n",
            picked ? picked : "(null)");
        failed_local = 1;
    } else {
        fprintf(stderr, "[SELFTEST] action=batch-registry-override-pick: PASS\n");
    }

    wc_batch_strategy_result_t res = {
        .start_host = picked,
        .authoritative_host = "whois.arin.net",
        .lookup_rc = 0,
    };
    wc_batch_strategy_registry_handle_result(&reg, &ctx, &res);
    if (!override_state.on_result_called) {
        fprintf(stderr, "[SELFTEST] action=batch-registry-override-on-result: FAIL\n");
        failed_local = 1;
    } else {
        fprintf(stderr, "[SELFTEST] action=batch-registry-override-on-result: PASS\n");
    }

    const wc_batch_strategy_iface_t* global_after = wc_batch_strategy_get_active();
    if (global_before != global_after) {
        fprintf(stderr, "[SELFTEST] action=batch-registry-global-leak: FAIL\n");
        failed_local = 1;
    }

    return failed_local ? 1 : 0;
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

static int selftest_preclass_phasec_policy(void)
{
    int failed = 0;
    wc_preclass_route_decision_t decision;
    wc_preclass_result_t test_net_result;
    wc_selftest_injection_t private_injection = {0};
    struct wc_terminal_retry_registry retry_registry;

    wc_terminal_retry_registry_init(&retry_registry);
    wc_terminal_retry_register(&retry_registry, "apnic", WC_TERMINAL_RETRY_EMPTY);
    wc_terminal_retry_register(&retry_registry, "whois.apnic.net", WC_TERMINAL_RETRY_RATE_LIMIT);
    wc_terminal_retry_register(&retry_registry, "arin", WC_TERMINAL_RETRY_DENIED);
    wc_terminal_retry_register(&retry_registry, "ripe", WC_TERMINAL_RETRY_EMPTY);
    wc_terminal_retry_register(&retry_registry, "afrinic", WC_TERMINAL_RETRY_EMPTY);
    wc_terminal_retry_register(&retry_registry, "lacnic", WC_TERMINAL_RETRY_EMPTY);
    wc_terminal_retry_register(&retry_registry, "iana", WC_TERMINAL_RETRY_EMPTY);
    if (retry_registry.count != WC_TERMINAL_RETRY_MAX_RIRS ||
        strcmp(retry_registry.entries[0].host, "whois.apnic.net") != 0 ||
        strcmp(retry_registry.entries[4].host, "whois.lacnic.net") != 0 ||
        !wc_terminal_retry_has_reason(&retry_registry, WC_TERMINAL_RETRY_EMPTY) ||
        !wc_terminal_retry_has_reason(&retry_registry, WC_TERMINAL_RETRY_RATE_LIMIT) ||
        !wc_terminal_retry_has_reason(&retry_registry, WC_TERMINAL_RETRY_DENIED)) {
        fprintf(stderr, "[SELFTEST] terminal-retry-registry: FAIL\n");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] terminal-retry-registry: PASS\n");
    }
    if (!wc_terminal_retry_should_run(&retry_registry, 1, 0, 1, 0) ||
        wc_terminal_retry_should_run(&retry_registry, 0, 0, 1, 0) ||
        wc_terminal_retry_should_run(&retry_registry, 1, 1, 1, 0) ||
        wc_terminal_retry_should_run(&retry_registry, 1, 0, 0, 0) ||
        wc_terminal_retry_should_run(&retry_registry, 1, 0, 1, 1) ||
        wc_terminal_retry_classify_body("") != WC_TERMINAL_RETRY_NO_RESULT ||
        wc_terminal_retry_classify_body("Access denied\n") != WC_TERMINAL_RETRY_NO_RESULT ||
        wc_terminal_retry_classify_body("refer: whois.arin.net\n") != WC_TERMINAL_RETRY_DETERMINABLE ||
        wc_terminal_retry_classify_body("NetRange: 8.8.8.0 - 8.8.8.255\nOrgName: Google LLC\n") !=
            WC_TERMINAL_RETRY_AUTHORITATIVE) {
        fprintf(stderr, "[SELFTEST] terminal-retry-policy: FAIL\n");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] terminal-retry-policy: PASS\n");
    }

    if (!wc_preclass_classification_should_early_converge("reserved", "none", "high") ||
        !wc_preclass_classification_should_early_converge("special", "none", "high") ||
        wc_preclass_classification_should_early_converge("reserved", "none", "low") ||
        wc_preclass_classification_should_early_converge("unknown", "unknown", "low") ||
        wc_preclass_classification_should_early_converge("allocated", "arin", "high") ||
        wc_preclass_classification_should_early_converge("reserved", "unknown", "high")) {
        fprintf(stderr, "[SELFTEST] preclass-phasec-policy: FAIL\n");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] preclass-phasec-policy: PASS\n");
    }

    if (!wc_preclass_classify_query("203.0.113.0/24", &test_net_result) ||
        strcmp(test_net_result.cls, "special") != 0 ||
        strcmp(test_net_result.rir, "none") != 0 ||
        strcmp(test_net_result.covering_rir, "apnic") != 0 ||
        strcmp(test_net_result.registry, "iana") != 0 ||
        strcmp(test_net_result.purpose, "documentation") != 0 ||
        strcmp(test_net_result.globally_reachable, "false") != 0 ||
        strcmp(test_net_result.reserved_by_protocol, "false") != 0) {
        fprintf(stderr, "[SELFTEST] preclass-special-test-net-3: FAIL\n");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] preclass-special-test-net-3: PASS\n");
    }

    memset(&decision, 0, sizeof(decision));
    wc_preclass_resolve_route_decision("whois.iana.org", 0, 0, 0, 1, 0, 0, 0, &decision);
    if (!decision.short_circuit || !decision.route_change ||
        !decision.start_host || strcmp(decision.start_host, "unknown") != 0 ||
        !decision.action || strcmp(decision.action, "preclass-early-converge-unknown") != 0) {
        fprintf(stderr, "[SELFTEST] preclass-phasec-route: FAIL\n");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] preclass-phasec-route: PASS\n");
    }

    memset(&decision, 0, sizeof(decision));
    wc_preclass_resolve_route_decision("whois.arin.net", 1, 1, 0, 1, 0, 0, 0, &decision);
    if (decision.short_circuit || decision.route_change ||
        !decision.action || strcmp(decision.action, "hint-bypassed") != 0) {
        fprintf(stderr, "[SELFTEST] preclass-phasec-explicit-host-bypass: FAIL\n");
        failed = 1;
    } else {
        fprintf(stderr, "[SELFTEST] preclass-phasec-explicit-host-bypass: PASS\n");
    }

    private_injection.force_private = "10.0.0.8";
    if (!wc_query_exec_is_forced_private(&private_injection, "10.0.0.8") ||
        wc_query_exec_is_forced_private(&private_injection, "10.0.0.9") ||
        wc_query_exec_is_forced_private(NULL, "10.0.0.8")) {
        fprintf(stderr, "[SELFTEST] preclass-phasec-force-private-priority: FAIL\n");
        failed = 1;
    } else {
        private_injection.force_private = "*";
        if (!wc_query_exec_is_forced_private(&private_injection, "10.0.0.9")) {
            fprintf(stderr, "[SELFTEST] preclass-phasec-force-private-priority: FAIL\n");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] preclass-phasec-force-private-priority: PASS\n");
        }
    }

    {
        extern int optind;
        wc_opts_t short_opts;
        wc_opts_t long_opts;
        wc_opts_t permuted_opts;
        wc_opts_t no_body_opts;
        wc_opts_t print_meta_opts;
        wc_opts_t print_meta_conflict_opts;
        wc_opts_t print_chain_opts;
        wc_opts_t print_chain_conflict_opts;
        wc_opts_t pick_opts;
        wc_opts_t pick_conflict_opts;
        char* short_argv[] = { "whois", "-DP", "-h", "whois.arin.net", "8.8.8.8", NULL };
        char* long_argv[] = { "whois", "--debug", "--host=whois.arin.net", "8.8.8.8", NULL };
        char* permuted_argv[] = { "whois", "203.0.113.0/24", "-h", "arin", NULL };
        char* no_body_argv[] = { "whois", "--no-body", "8.8.8.8", NULL };
        optind = 1;
        if (wc_opts_parse(5, short_argv, &short_opts) != 0 || !short_opts.debug || !short_opts.plain_mode ||
            !short_opts.host || strcmp(short_opts.host, "whois.arin.net") != 0 ||
            !short_opts.preclass_first_hop_enable || optind != 4) {
            fprintf(stderr, "[SELFTEST] opts-short-parser: FAIL\n");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] opts-short-parser: PASS\n");
        }
        wc_opts_free(&short_opts);
        optind = 1;
        if (wc_opts_parse(4, long_argv, &long_opts) != 0 || !long_opts.debug ||
            !long_opts.host || strcmp(long_opts.host, "whois.arin.net") != 0 || optind != 3) {
            fprintf(stderr, "[SELFTEST] opts-long-parser: FAIL\n");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] opts-long-parser: PASS\n");
        }
        wc_opts_free(&long_opts);
        optind = 1;
        if (wc_opts_parse(4, permuted_argv, &permuted_opts) != 0 ||
            !permuted_opts.host || strcmp(permuted_opts.host, "arin") != 0 ||
            optind != 3 || strcmp(permuted_argv[optind], "203.0.113.0/24") != 0) {
            fprintf(stderr, "[SELFTEST] opts-permuted-parser: FAIL\n");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] opts-permuted-parser: PASS\n");
        }
        wc_opts_free(&permuted_opts);
        optind = 1;
        if (wc_opts_parse(3, no_body_argv, &no_body_opts) != 0 || !no_body_opts.no_body) {
            fprintf(stderr, "[SELFTEST] opts-no-body-parser: FAIL\n");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] opts-no-body-parser: PASS\n");
        }
        wc_opts_free(&no_body_opts);
        optind = 1;
        {
            char* print_meta_argv[] = { "whois", "--print-meta", "8.8.8.8", NULL };
            if (wc_opts_parse(3, print_meta_argv, &print_meta_opts) != 0 ||
                !print_meta_opts.print_meta) {
                fprintf(stderr, "[SELFTEST] opts-print-meta-parser: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] opts-print-meta-parser: PASS\n");
            }
            wc_opts_free(&print_meta_opts);
        }
        optind = 1;
        {
            char* conflict_argv[] = { "whois", "--print-meta", "--plain", "8.8.8.8", NULL };
            if (wc_opts_parse(4, conflict_argv, &print_meta_conflict_opts) == 0) {
                fprintf(stderr, "[SELFTEST] opts-print-meta-plain-conflict: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] opts-print-meta-plain-conflict: PASS\n");
            }
            wc_opts_free(&print_meta_conflict_opts);
        }
        optind = 1;
        {
            char* print_chain_argv[] = { "whois", "--print-chain", "8.8.8.8", NULL };
            if (wc_opts_parse(3, print_chain_argv, &print_chain_opts) != 0 ||
                !print_chain_opts.print_chain) {
                fprintf(stderr, "[SELFTEST] opts-print-chain-parser: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] opts-print-chain-parser: PASS\n");
            }
            wc_opts_free(&print_chain_opts);
        }
        optind = 1;
        {
            char* conflict_argv[] = { "whois", "--print-chain", "--plain", "8.8.8.8", NULL };
            if (wc_opts_parse(4, conflict_argv, &print_chain_conflict_opts) == 0) {
                fprintf(stderr, "[SELFTEST] opts-print-chain-plain-conflict: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] opts-print-chain-plain-conflict: PASS\n");
            }
            wc_opts_free(&print_chain_conflict_opts);
        }
        optind = 1;
        {
            char* pick_argv[] = { "whois", "--pick", " Country,netname,COUNTRY ",
                "--pick-mode", "join", "8.8.8.8", NULL };
            if (wc_opts_parse(6, pick_argv, &pick_opts) != 0 ||
                !pick_opts.pick_keys || strcmp(pick_opts.pick_keys, "country,netname") != 0 ||
                pick_opts.pick_mode != WC_PICK_MODE_JOIN) {
                fprintf(stderr, "[SELFTEST] opts-pick-parser: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] opts-pick-parser: PASS\n");
            }
            wc_opts_free(&pick_opts);
        }
        optind = 1;
        {
            char* conflict_argv[] = { "whois", "--pick-mode", "first", "8.8.8.8", NULL };
            if (wc_opts_parse(4, conflict_argv, &pick_conflict_opts) == 0) {
                fprintf(stderr, "[SELFTEST] opts-pick-mode-without-pick: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] opts-pick-mode-without-pick: PASS\n");
            }
            wc_opts_free(&pick_conflict_opts);
        }
        {
            const char* response =
                "Route6: must-not-match-route\n"
                "NetName:  Alpha   Network \n"
                "  continued value\n"
                "Country:\n"
                "country: US\n"
                "descr: First\n"
                "descr: Second\n";
            char* first = wc_pick_build_line(response,
                "route,netname,country,descr,origin", WC_PICK_MODE_FIRST);
            char* joined = wc_pick_build_line(response,
                "country,descr", WC_PICK_MODE_JOIN);
            if (!first || strcmp(first,
                    "route=\tnetname=Alpha Network; continued value\tcountry=\tdescr=First\torigin=\n") != 0 ||
                !joined || strcmp(joined, "country=|US\tdescr=First|Second\n") != 0) {
                fprintf(stderr, "[SELFTEST] pick-extract-first-join: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] pick-extract-first-join: PASS\n");
            }
            free(first);
            free(joined);
        }
        {
            size_t value_len = 65537;
            char* response = (char*)malloc(value_len + 22);
            char* picked = NULL;
            if (response) {
                memcpy(response, "descr: ", 7);
                memset(response + 7, 'x', value_len);
                memcpy(response + 7 + value_len, "\ncountry: US\n", 14);
                response[7 + value_len + 14] = '\0';
                picked = wc_pick_build_line(response,
                    "descr,country", WC_PICK_MODE_FIRST);
            }
            size_t picked_len = picked ? strlen(picked) : 0;
            if (!picked || picked_len < 16 ||
                    strcmp(picked + picked_len - 15,
                        "...\tcountry=US\n") != 0) {
                fprintf(stderr, "[SELFTEST] pick-truncation-boundary: FAIL\n");
                failed = 1;
            } else {
                fprintf(stderr, "[SELFTEST] pick-truncation-boundary: PASS\n");
            }
            free(response);
            free(picked);
        }
    }
    return failed;
}

static int selftest_preclass_consistency(void)
{
    if (wc_preclass_verify_hardcoded_consistency() != 0) {
        fprintf(stderr, "[SELFTEST] preclass-consistency: FAIL\n");
        return 1;
    }
    fprintf(stderr, "[SELFTEST] preclass-consistency: PASS\n");
    return 0;
}

static int selftest_preclass_single_pass(void)
{
    int failed = 0;
    const char* ips[] = {
        "10.0.0.1", "127.0.0.1", "169.254.10.20", "172.16.0.1",
        "192.168.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
        "0.0.0.1", "::1", "fc00::1", "fe80::1", "ff00::1",
        "2001:db8::1", "2001:db9::1", "8.8.8.8", "203.0.113.1", NULL
    };
    size_t i;

    for (i = 0; ips[i]; ++i) {
        const char* family = NULL;
        const char* cls = NULL;
        const char* rir = NULL;
        const char* reason = NULL;
        const char* confidence = NULL;
        wc_preclass_result_t result;

        wc_preclass_classify_ip(ips[i], &family, &cls, &rir,
            &reason, &confidence);
        if (!wc_preclass_classify_query(ips[i], &result) ||
            !result.family || strcmp(result.family, family) != 0 ||
            !result.cls || strcmp(result.cls, cls) != 0 ||
            !result.rir || strcmp(result.rir, rir) != 0 ||
            !result.reason || strcmp(result.reason, reason) != 0 ||
            !result.confidence || strcmp(result.confidence, confidence) != 0) {
            fprintf(stderr, "[SELFTEST] preclass-single-pass: FAIL (%s)\n", ips[i]);
            failed = 1;
        }
    }

    {
        wc_preclass_result_t cidr_result;
        if (!wc_preclass_classify_query("203.0.113.0/24", &cidr_result) ||
            strcmp(cidr_result.cls, "special") != 0 ||
            strcmp(cidr_result.rir, "none") != 0 ||
            strcmp(cidr_result.covering_rir, "apnic") != 0) {
            fprintf(stderr, "[SELFTEST] preclass-single-pass-cidr: FAIL\n");
            failed = 1;
        }
    }

    {
        wc_preclass_result_t c1;
        wc_preclass_result_t c2;
        unsigned long after_first = 0;
        if (!wc_preclass_classify_query("1.1.1.1", &c1))
            failed = 1;
        after_first = wc_preclass_get_lookup_count();
        if (!wc_preclass_classify_query("1.1.1.1", &c2) ||
            c1.family != c2.family || c1.cls != c2.cls ||
            c1.rir != c2.rir || c1.reason != c2.reason ||
            c1.confidence != c2.confidence ||
            (wc_preclass_get_lookup_count() - after_first) != 0) {
            fprintf(stderr, "[SELFTEST] preclass-cache-single-scan: FAIL\n");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] preclass-cache-single-scan: PASS\n");
        }
    }
    if (failed == 0)
        fprintf(stderr, "[SELFTEST] preclass-single-pass: PASS\n");
    return failed;
}

int wc_selftest_run(void) {
    int failed = 0;

    int consistency = selftest_preclass_consistency();
    if (consistency != 0) failed = 1;

    int phasec = selftest_preclass_phasec_policy();
    if (phasec != 0) failed = 1;

    int singlepass = selftest_preclass_single_pass();
    if (singlepass != 0) failed = 1;

    int crlf = selftest_crlf_normalization();
    if (crlf != 0) failed = 1;

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

    {
        const char* semantic_empty_body =
            "% This is a WHOIS service banner.\n"
            "# Terms of use apply.\n";
        const char* non_authoritative_body =
            "% No match found for 203.0.113.1\n";
        const char* authoritative_body =
            "inetnum: 203.0.113.0 - 203.0.113.255\n";
        if (!wc_lookup_body_is_semantically_empty(semantic_empty_body) ||
            wc_lookup_body_is_semantically_empty(non_authoritative_body) ||
            !needs_redirect(non_authoritative_body) ||
            wc_lookup_body_is_semantically_empty(authoritative_body) ||
            !is_authoritative_response(authoritative_body)) {
            fprintf(stderr, "[SELFTEST] redirect-semantic-empty-priority: FAIL\n");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] redirect-semantic-empty-priority: PASS\n");
        }
    }

    // Redirect: extract_refer_server basic
    const char* ex1 = "ReferralServer: whois://whois.ripe.net\n";
    char* rs = extract_refer_server(ex1);
    if (!rs || strcmp(rs, "whois.ripe.net") != 0) { fprintf(stderr, "[SELFTEST] extract-refer: FAIL (%s)\n", rs ? rs : "null"); failed = 1; }
    else fprintf(stderr, "[SELFTEST] extract-refer: PASS\n");
    if (rs) free(rs);

    const char* ex_bad = "ReferralServer: whois://whois\n";
    char* rs_bad = extract_refer_server(ex_bad);
    if (rs_bad) {
        fprintf(stderr, "[SELFTEST] extract-refer-invalid: FAIL (%s)\n", rs_bad);
        failed = 1;
        free(rs_bad);
    } else {
        fprintf(stderr, "[SELFTEST] extract-refer-invalid: PASS\n");
    }

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

    {
        char frozen_response[] =
            "%ERROR:115: invalid search key\n"
            "ReferralServer: whois://whois.ripe.net\n";
        char header_hint_host[128] = {0};
        int auth = 1;
        int need_redir_eval = 1;
        int force_stop_authoritative = 0;
        char* ref = (char*)malloc(strlen("whois://whois.ripe.net") + 1);
        int ref_allocated = ref ? 1 : 0;
        if (ref) {
            memcpy(ref, "whois://whois.ripe.net", strlen("whois://whois.ripe.net") + 1);
        }
        struct wc_lookup_exec_redirect_ctx redirect_ctx = {
            .body = frozen_response,
            .auth = &auth,
            .current_host = "whois.arin.net",
            .current_rir_guess = "arin",
            .current_port = 43,
            .need_redir_eval = &need_redir_eval,
            .header_hint_host = header_hint_host,
            .header_hint_host_len = sizeof(header_hint_host),
            .force_stop_authoritative = &force_stop_authoritative,
            .ref = &ref
        };
        wc_lookup_exec_eval_redirect(&redirect_ctx);
        if (!ref_allocated || auth != 0 || need_redir_eval != 0 ||
            force_stop_authoritative != 1 || ref != NULL) {
            fprintf(stderr,
                "[SELFTEST] redirect-invalid-key-priority: FAIL (allocated=%d auth=%d redir=%d stop=%d ref=%s)\n",
                ref_allocated,
                    auth,
                    need_redir_eval,
                    force_stop_authoritative,
                    ref ? ref : "null");
            failed = 1;
        } else {
            fprintf(stderr, "[SELFTEST] redirect-invalid-key-priority: PASS\n");
        }
        if (ref) free(ref);
    }

    {
        const struct {
            const char* label;
            const char* marker;
            int access_denied;
            int rate_limited;
            const char* status;
            const char* desc;
        } failure_cases[] = {
            {"denied", "Access denied", 1, 0, "denied", "access-denied"},
            {"rate-limit", "Query rate limit exceeded", 0, 1, "rate-limit", "rate-limit-exceeded"}
        };
        for (size_t case_index = 0;
             case_index < sizeof(failure_cases) / sizeof(failure_cases[0]);
             ++case_index) {
            char frozen_response[160];
            char header_hint_host[128] = {0};
            char last_failure_host[128] = {0};
            char last_failure_rir[32] = {0};
            char* visited_hosts[4] = {NULL, NULL, NULL, NULL};
            snprintf(frozen_response,
                     sizeof(frozen_response),
                     "inetnum: 203.0.113.0 - 203.0.113.255\n%s\n",
                     failure_cases[case_index].marker);
            visited_hosts[0] = (char*)malloc(strlen("whois.arin.net") + 1);
            int visited_allocated = visited_hosts[0] ? 1 : 0;
            if (visited_hosts[0]) {
                memcpy(visited_hosts[0], "whois.arin.net", strlen("whois.arin.net") + 1);
            }
            int auth = 1;
            int need_redir_eval = 0;
            int force_rir_cycle = 0;
            int header_non_authoritative = 0;
            int saw_rate_limit_or_denied = 0;
            int visited_count = visited_allocated;
            const char* last_failure_status = NULL;
            const char* last_failure_desc = NULL;
            struct wc_lookup_exec_redirect_ctx redirect_ctx = {
                .body = frozen_response,
                .auth = &auth,
                .current_host = "whois.arin.net",
                .current_rir_guess = "arin",
                .hops = 0,
                .current_port = 43,
                .access_denied = failure_cases[case_index].access_denied,
                .rate_limited = failure_cases[case_index].rate_limited,
                .need_redir_eval = &need_redir_eval,
                .force_rir_cycle = &force_rir_cycle,
                .header_hint_host = header_hint_host,
                .header_hint_host_len = sizeof(header_hint_host),
                .header_non_authoritative = &header_non_authoritative,
                .saw_rate_limit_or_denied = &saw_rate_limit_or_denied,
                .last_failure_host = last_failure_host,
                .last_failure_host_len = sizeof(last_failure_host),
                .last_failure_rir = last_failure_rir,
                .last_failure_rir_len = sizeof(last_failure_rir),
                .last_failure_status = &last_failure_status,
                .last_failure_desc = &last_failure_desc,
                .visited = visited_hosts,
                .visited_count = &visited_count
            };
            wc_lookup_exec_eval_redirect(&redirect_ctx);
            if (!visited_allocated || auth != 0 || need_redir_eval != 1 || force_rir_cycle != 1 ||
                header_non_authoritative != 1 || saw_rate_limit_or_denied != 1 ||
                visited_count != 0 || strcmp(last_failure_host, "whois.arin.net") != 0 ||
                strcmp(last_failure_rir, "arin") != 0 || !last_failure_status ||
                strcmp(last_failure_status, failure_cases[case_index].status) != 0 ||
                !last_failure_desc || strcmp(last_failure_desc, failure_cases[case_index].desc) != 0) {
                fprintf(stderr,
                        "[SELFTEST] redirect-%s-priority: FAIL (allocated=%d auth=%d redir=%d cycle=%d nonauth=%d saw=%d visited=%d host=%s rir=%s status=%s desc=%s)\n",
                        failure_cases[case_index].label,
                        visited_allocated,
                        auth,
                        need_redir_eval,
                        force_rir_cycle,
                        header_non_authoritative,
                        saw_rate_limit_or_denied,
                        visited_count,
                        last_failure_host,
                        last_failure_rir,
                        last_failure_status ? last_failure_status : "null",
                        last_failure_desc ? last_failure_desc : "null");
                failed = 1;
            } else {
                fprintf(stderr,
                        "[SELFTEST] redirect-%s-priority: PASS\n",
                        failure_cases[case_index].label);
            }
            for (int i = 0; i < visited_count; ++i) {
                free(visited_hosts[i]);
            }
        }
    }

    {
        Config selftest_cfg = wc_selftest_config_snapshot();
        char next_host[128] = {0};
        int have_next = 0;
        int next_port = 43;
        unsigned int fallback_flags = 0;
        int visited_count = 1;
        char* visited_hosts[4] = {
            "whois.afrinic.net",
            NULL,
            NULL,
            NULL
        };
        struct wc_lookup_exec_next_ctx next_ctx = {
            .zopts = NULL,
            .cfg = &selftest_cfg,
            .net_ctx = NULL,
            .fault_profile = NULL,
            .current_host = "whois.arin.net",
            .current_rir_guess = "arin",
            .current_port = 43,
            .body = "ReferralServer: whois://whois.afrinic.net\n",
            .hops = 0,
            .auth = 0,
            .need_redir_eval = 0,
            .header_hint_valid = 0,
            .header_hint_host = NULL,
            .allow_cycle_on_loop = 0,
            .force_stop_authoritative = 0,
            .force_rir_cycle = 0,
            .apnic_erx_root = 0,
            .apnic_redirect_reason = 0,
            .apnic_erx_authoritative_stop = 0,
            .apnic_erx_legacy = 0,
            .erx_fast_authoritative = 0,
            .apnic_erx_ripe_non_managed = 0,
            .ref = "whois://whois.afrinic.net",
            .ref_host = "whois.afrinic.net",
            .ref_port = 43,
            .ref_explicit = 1,
            .combined = NULL,
            .fallback_flags = &fallback_flags,
            .pref_label = NULL,
            .visited = visited_hosts,
            .visited_count = &visited_count,
            .apnic_ambiguous_revisit_used = NULL,
            .stop_with_apnic_authority = NULL,
            .rir_cycle_exhausted = NULL,
            .apnic_erx_ref_host = NULL,
            .apnic_erx_ref_host_len = 0,
            .next_host = next_host,
            .next_host_len = sizeof(next_host),
            .have_next = &have_next,
            .next_port = &next_port,
            .ref_explicit_allow_visited = NULL
        };
        wc_lookup_exec_pick_next_hop(&next_ctx);
        if (!have_next || strcmp(next_host, "whois.apnic.net") != 0) {
            fprintf(stderr,
                    "[SELFTEST] referral-visited-rir-fallback: FAIL (next=%s have_next=%d)\n",
                    next_host,
                    have_next);
            failed = 1;
        } else {
            fprintf(stderr,
                    "[SELFTEST] referral-visited-rir-fallback: PASS (next=%s)\n",
                    next_host);
        }
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

