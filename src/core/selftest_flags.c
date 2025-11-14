// SPDX-License-Identifier: MIT
#include "wc/wc_selftest.h"

static int g_inject_empty = 0;
static int g_grep_test = 0;
static int g_seclog_test = 0;

void wc_selftest_set_inject_empty(int enabled){ g_inject_empty = enabled ? 1 : 0; }
int wc_selftest_inject_empty_enabled(void){ return g_inject_empty; }

void wc_selftest_set_grep_test(int enabled){ g_grep_test = enabled ? 1 : 0; }
int wc_selftest_grep_test_enabled(void){ return g_grep_test; }

void wc_selftest_set_seclog_test(int enabled){ g_seclog_test = enabled ? 1 : 0; }
int wc_selftest_seclog_test_enabled(void){ return g_seclog_test; }
