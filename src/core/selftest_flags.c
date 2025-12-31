// SPDX-License-Identifier: MIT
#include <string.h>

#include "wc/wc_selftest.h"
#include "wc/wc_opts.h"

static int g_inject_empty = 0;
static int g_grep_test = 0;
static int g_seclog_test = 0;
static int g_workbuf_test = 0;
static wc_selftest_fault_profile_t g_fault_profile = {0};
static unsigned g_fault_profile_version = 1;
static int g_forced_ipv4_attempts = 0;
static int g_known_ip_attempts = 0;
static wc_selftest_injection_t g_injection_baseline = {0};

static void wc_selftest_touch_fault_profile(void)
{
	unsigned new_version = g_fault_profile_version + 1;
	if (new_version == 0)
		new_version = 1; // avoid zero to simplify consumer logic
	g_fault_profile_version = new_version;
}

static void wc_selftest_update_fault_flag(int* slot, int enabled)
{
	int value = enabled ? 1 : 0;
	if (*slot == value)
		return;
	*slot = value;
	wc_selftest_touch_fault_profile();
}

void wc_selftest_set_inject_empty(int enabled){ g_inject_empty = enabled ? 1 : 0; }
int wc_selftest_inject_empty_enabled(void){ return g_inject_empty; }

void wc_selftest_set_grep_test(int enabled){ g_grep_test = enabled ? 1 : 0; }
int wc_selftest_grep_test_enabled(void){ return g_grep_test; }

void wc_selftest_set_seclog_test(int enabled){ g_seclog_test = enabled ? 1 : 0; }
int wc_selftest_seclog_test_enabled(void){ return g_seclog_test; }

void wc_selftest_set_workbuf_test(int enabled){ g_workbuf_test = enabled ? 1 : 0; }
int wc_selftest_workbuf_test_enabled(void){ return g_workbuf_test; }

void wc_selftest_set_dns_negative(int enabled){ wc_selftest_update_fault_flag(&g_fault_profile.dns_negative, enabled); }
int wc_selftest_dns_negative_enabled(void){ return g_fault_profile.dns_negative; }

void wc_selftest_set_blackhole_iana(int enabled){ wc_selftest_update_fault_flag(&g_fault_profile.blackhole_iana, enabled); }
int wc_selftest_blackhole_iana_enabled(void){ return g_fault_profile.blackhole_iana; }

void wc_selftest_set_blackhole_arin(int enabled){ wc_selftest_update_fault_flag(&g_fault_profile.blackhole_arin, enabled); }
int wc_selftest_blackhole_arin_enabled(void){ return g_fault_profile.blackhole_arin; }

void wc_selftest_set_force_iana_pivot(int enabled){ wc_selftest_update_fault_flag(&g_fault_profile.force_iana_pivot, enabled); }
int wc_selftest_force_iana_pivot_enabled(void){ return g_fault_profile.force_iana_pivot; }

void wc_selftest_set_fail_first_attempt(int enabled){ wc_selftest_update_fault_flag(&g_fault_profile.net_fail_first_once, enabled); }

const wc_selftest_fault_profile_t* wc_selftest_fault_profile(void)
{
	return &g_fault_profile;
}

unsigned wc_selftest_fault_profile_version(void)
{
	return g_fault_profile_version;
}

const wc_selftest_injection_t* wc_selftest_export_injection(void)
{
	return wc_selftest_injection_view();
}

const wc_selftest_injection_t* wc_selftest_injection_view(void)
{
	return &g_injection_baseline;
}

void wc_selftest_set_injection_view_for_test(const wc_selftest_injection_t* injection)
{
	if (!injection)
		return;
	g_injection_baseline = *injection;
}

void wc_selftest_set_force_suspicious_query(const char* query)
{
    (void)query;
}

void wc_selftest_reset_dns_fallback_counters(void){ g_forced_ipv4_attempts = 0; g_known_ip_attempts = 0; }
void wc_selftest_record_forced_ipv4_attempt(void){ g_forced_ipv4_attempts++; }
void wc_selftest_record_known_ip_attempt(void){ g_known_ip_attempts++; }
int wc_selftest_forced_ipv4_attempts(void){ return g_forced_ipv4_attempts; }
int wc_selftest_known_ip_attempts(void){ return g_known_ip_attempts; }

void wc_selftest_reset_all(void)
{
	g_inject_empty = 0;
	g_grep_test = 0;
	g_seclog_test = 0;
	g_workbuf_test = 0;
	memset(&g_fault_profile, 0, sizeof(g_fault_profile));
	g_fault_profile_version = 1;
	g_forced_ipv4_attempts = 0;
	g_known_ip_attempts = 0;
}

static void wc_selftest_apply_injection_baseline_locked(void)
{
	g_inject_empty = g_injection_baseline.inject_empty;
	g_grep_test = g_injection_baseline.grep_test;
	g_seclog_test = g_injection_baseline.seclog_test;
		g_workbuf_test = g_injection_baseline.workbuf_test;
	g_fault_profile = g_injection_baseline.fault;
	g_fault_profile_version = g_injection_baseline.fault_version ? g_injection_baseline.fault_version : 1;
}

void wc_selftest_apply_injection_baseline(void)
{
	wc_selftest_apply_injection_baseline_locked();
}

void wc_selftest_set_injection_from_opts(const wc_opts_t* opts)
{
	wc_selftest_reset_all();
	if (!opts)
		return;
	g_injection_baseline.inject_empty = opts->selftest_inject_empty ? 1 : 0;
	g_injection_baseline.grep_test = opts->selftest_grep ? 1 : 0;
	g_injection_baseline.seclog_test = opts->selftest_seclog ? 1 : 0;
		g_injection_baseline.workbuf_test = opts->selftest_workbuf ? 1 : 0;
	g_injection_baseline.fault.dns_negative = opts->selftest_dns_negative ? 1 : 0;
	g_injection_baseline.fault.blackhole_iana = opts->selftest_blackhole_iana ? 1 : 0;
	g_injection_baseline.fault.blackhole_arin = opts->selftest_blackhole_arin ? 1 : 0;
	g_injection_baseline.fault.force_iana_pivot = opts->selftest_force_iana_pivot ? 1 : 0;
	g_injection_baseline.fault.net_fail_first_once = opts->selftest_fail_first ? 1 : 0;
	g_injection_baseline.fault_version = g_fault_profile_version + 1;
	if (g_injection_baseline.fault_version == 0)
		g_injection_baseline.fault_version = 1;
	g_fault_profile_version = g_injection_baseline.fault_version;
	g_injection_baseline.force_suspicious = opts->selftest_force_suspicious;
	g_injection_baseline.force_private = opts->selftest_force_private;
	wc_selftest_apply_injection_baseline_locked();
}

void wc_selftest_apply_cli_flags(const wc_opts_t* opts)
{
	wc_selftest_set_injection_from_opts(opts);
}
