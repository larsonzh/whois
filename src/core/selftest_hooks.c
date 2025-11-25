// SPDX-License-Identifier: MIT
// Auxiliary self-test demos originally hosted in whois_client.c.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wc/wc_config.h"
#include "wc/wc_grep.h"
#include "wc/wc_seclog.h"
#include "wc/wc_selftest.h"

extern Config g_config;

void wc_selftest_maybe_run_seclog_demo(void)
{
#ifdef WHOIS_SECLOG_TEST
    if (!wc_selftest_seclog_test_enabled())
        return;

    int prev = g_config.security_logging;
    wc_seclog_set_enabled(1);

    for (int i = 0; i < 200; ++i) {
        log_security_event(SEC_EVENT_CONNECTION_ATTACK,
            "SECTEST event #%d", i);
    }
    for (int i = 0; i < 10; ++i) {
        log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
            "SECTEST extra #%d", i);
    }

    wc_seclog_set_enabled(prev);
#else
    (void)0;
#endif
}

#ifdef WHOIS_GREP_TEST
static void print_greptest_output(const char* title, const char* s)
{
    if (!title || !s)
        return;
    fprintf(stderr, "[GREPTEST] %s\n", title);
    const char* p = s;
    const char* q = s;
    while (*q) {
        while (*q && *q != '\n')
            ++q;
        if (q > p)
            fprintf(stderr, "[GREPTEST-OUT] %.*s\n", (int)(q - p), p);
        if (*q == '\n') {
            ++q;
            p = q;
        }
    }
}
#endif

void wc_selftest_maybe_run_grep_demo(void)
{
#ifdef WHOIS_GREP_TEST
    if (!wc_selftest_grep_test_enabled())
        return;

    const char* sample =
        "OrgName: Google LLC\n"
        " Address: Mountain View\n"
        "\n"
        "Abuse-Contact: abuse@google.com\n"
        " Foo: bar\n";

    wc_grep_set_enabled(1);
    if (wc_grep_compile("orgname|abuse-contact", 0) > 0) {
        wc_grep_set_line_mode(0);
        wc_grep_set_keep_continuation(0);
        char* out = wc_grep_filter(sample);
        if (out) {
            int ok = 1;
            if (!strstr(out, "OrgName:")) ok = 0;
            if (!strstr(out, " Address:")) ok = 0;
            if (!strstr(out, "Abuse-Contact:")) ok = 0;
            if (strstr(out, " Foo:")) ok = 0;
            fprintf(stderr, ok ? "[GREPTEST] block mode: PASS\n"
                                : "[GREPTEST] block mode: FAIL\n");
            if (!ok)
                print_greptest_output("block mode output", out);
            free(out);
        }
    }

    wc_grep_set_line_mode(1);
    wc_grep_set_keep_continuation(0);
    {
        char* out = wc_grep_filter(sample);
        if (out) {
            int ok = 1;
            if (!strstr(out, "OrgName:")) ok = 0;
            if (strstr(out, " Address:")) ok = 0;
            if (!strstr(out, "Abuse-Contact:")) ok = 0;
            fprintf(stderr,
                ok ? "[GREPTEST] line mode (no-cont): PASS\n"
                   : "[GREPTEST] line mode (no-cont): FAIL\n");
            if (!ok)
                print_greptest_output("line mode (no-cont) output", out);
            free(out);
        }
    }

    wc_grep_set_keep_continuation(1);
    {
        char* out = wc_grep_filter(sample);
        if (out) {
            int ok = 1;
            if (!strstr(out, "OrgName:")) ok = 0;
            if (!strstr(out, " Address:")) ok = 0;
            if (!strstr(out, "Abuse-Contact:")) ok = 0;
            fprintf(stderr,
                ok ? "[GREPTEST] line mode (keep-cont): PASS\n"
                   : "[GREPTEST] line mode (keep-cont): FAIL\n");
            if (!ok)
                print_greptest_output("line mode (keep-cont) output", out);
            free(out);
        }
    }

    wc_grep_free();
#else
    (void)0;
#endif
}

void wc_selftest_run_startup_demos(void)
{
    // These helpers already contain their own compile-time guards, so call
    // them unconditionally to keep whois_client.c free of #ifdef clutter.
    wc_selftest_maybe_run_seclog_demo();
    wc_selftest_maybe_run_grep_demo();
}
