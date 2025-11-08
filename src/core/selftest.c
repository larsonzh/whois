// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // free
#include "wc/wc_selftest.h"
#include "wc/wc_fold.h"

int wc_selftest_run(void) {
    int failed = 0;

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

    return failed ? 1 : 0;
}
