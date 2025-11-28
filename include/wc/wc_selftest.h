// wc_selftest.h - internal self-test harness + runtime knobs (no env in release)
#ifndef WC_SELFTEST_H_
#define WC_SELFTEST_H_

int wc_selftest_run(void); // returns 0 on success, non-zero on any failure

struct wc_opts_s; // forward declaration to avoid heavy includes

typedef struct wc_selftest_fault_profile_s {
	int dns_negative;         // simulate resolver failures (EAI_FAIL)
	int blackhole_iana;       // force IANA candidate to 192.0.2.1
	int blackhole_arin;       // force ARIN candidate to 192.0.2.1
	int force_iana_pivot;     // redirect referrals through IANA once
	int net_fail_first_once;  // drop the first dial attempt globally
} wc_selftest_fault_profile_t;

const wc_selftest_fault_profile_t* wc_selftest_fault_profile(void);
unsigned wc_selftest_fault_profile_version(void);

// Runtime knobs (always available; tests guarded by compile-time macros inside modules)
void wc_selftest_set_inject_empty(int enabled);
int wc_selftest_inject_empty_enabled(void);

void wc_selftest_set_grep_test(int enabled);
int wc_selftest_grep_test_enabled(void);

void wc_selftest_set_seclog_test(int enabled);
int wc_selftest_seclog_test_enabled(void);

// New: simulate negative DNS cache scenario for testing
void wc_selftest_set_dns_negative(int enabled);
int wc_selftest_dns_negative_enabled(void);

// Test-only knobs to simulate connect failures on specific hops
void wc_selftest_set_blackhole_iana(int enabled);
int wc_selftest_blackhole_iana_enabled(void);

void wc_selftest_set_blackhole_arin(int enabled);
int wc_selftest_blackhole_arin_enabled(void);

// Test-only knob to force using IANA as a pivot hop even when an explicit
// referral exists; helps create a predictable 3-hop chain for testing.
void wc_selftest_set_force_iana_pivot(int enabled);
int wc_selftest_force_iana_pivot_enabled(void);

void wc_selftest_set_fail_first_attempt(int enabled);

void wc_selftest_set_force_suspicious_query(const char* query);
int wc_selftest_should_force_suspicious(const char* query);

void wc_selftest_set_force_private_query(const char* query);
int wc_selftest_should_force_private(const char* query);

// DNS fallback instrumentation (always compiled, used by selftests)
void wc_selftest_reset_dns_fallback_counters(void);
void wc_selftest_record_forced_ipv4_attempt(void);
void wc_selftest_record_known_ip_attempt(void);
int wc_selftest_forced_ipv4_attempts(void);
int wc_selftest_known_ip_attempts(void);

// Optional demo helpers (no-op unless compiled with the corresponding flags)
void wc_selftest_maybe_run_seclog_demo(void);
void wc_selftest_maybe_run_grep_demo(void);

// Entry-point helper to run any compile-time gated demos without cluttering
// whois_client.c with multiple #ifdef blocks.
void wc_selftest_run_startup_demos(void);

// Optional lookup selftests (built when compiled with -DWHOIS_LOOKUP_SELFTEST)
int wc_selftest_lookup(void);

// Selftest controller helpers used by CLI/runtime glue.
void wc_selftest_apply_cli_flags(const struct wc_opts_s* opts);
void wc_selftest_reset_all(void);

// Unified runtime entry to invoke requested selftests once per process.
void wc_selftest_run_if_enabled(const struct wc_opts_s* opts);

#endif // WC_SELFTEST_H_
