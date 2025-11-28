// wc_selftest.h - internal self-test harness + runtime knobs (no env in release)
#ifndef WC_SELFTEST_H_
#define WC_SELFTEST_H_

int wc_selftest_run(void); // returns 0 on success, non-zero on any failure

struct wc_opts_s; // forward declaration to avoid heavy includes

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

// Selftest controller helpers used by CLI/runtime glue.
void wc_selftest_apply_cli_flags(const struct wc_opts_s* opts);
void wc_selftest_reset_all(void);

#endif // WC_SELFTEST_H_
