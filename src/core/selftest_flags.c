// SPDX-License-Identifier: MIT
#include "wc/wc_selftest.h"

static int g_inject_empty = 0;
static int g_grep_test = 0;
static int g_seclog_test = 0;
static int g_dns_negative = 0;
static int g_blackhole_iana = 0;
static int g_blackhole_arin = 0;
static int g_force_iana_pivot = 0;
static int g_forced_ipv4_attempts = 0;
static int g_known_ip_attempts = 0;

void wc_selftest_set_inject_empty(int enabled){ g_inject_empty = enabled ? 1 : 0; }
int wc_selftest_inject_empty_enabled(void){ return g_inject_empty; }

void wc_selftest_set_grep_test(int enabled){ g_grep_test = enabled ? 1 : 0; }
int wc_selftest_grep_test_enabled(void){ return g_grep_test; }

void wc_selftest_set_seclog_test(int enabled){ g_seclog_test = enabled ? 1 : 0; }
int wc_selftest_seclog_test_enabled(void){ return g_seclog_test; }

void wc_selftest_set_dns_negative(int enabled){ g_dns_negative = enabled ? 1 : 0; }
int wc_selftest_dns_negative_enabled(void){ return g_dns_negative; }

void wc_selftest_set_blackhole_iana(int enabled){ g_blackhole_iana = enabled ? 1 : 0; }
int wc_selftest_blackhole_iana_enabled(void){ return g_blackhole_iana; }

void wc_selftest_set_blackhole_arin(int enabled){ g_blackhole_arin = enabled ? 1 : 0; }
int wc_selftest_blackhole_arin_enabled(void){ return g_blackhole_arin; }

void wc_selftest_set_force_iana_pivot(int enabled){ g_force_iana_pivot = enabled ? 1 : 0; }
int wc_selftest_force_iana_pivot_enabled(void){ return g_force_iana_pivot; }

void wc_selftest_reset_dns_fallback_counters(void){ g_forced_ipv4_attempts = 0; g_known_ip_attempts = 0; }
void wc_selftest_record_forced_ipv4_attempt(void){ g_forced_ipv4_attempts++; }
void wc_selftest_record_known_ip_attempt(void){ g_known_ip_attempts++; }
int wc_selftest_forced_ipv4_attempts(void){ return g_forced_ipv4_attempts; }
int wc_selftest_known_ip_attempts(void){ return g_known_ip_attempts; }
