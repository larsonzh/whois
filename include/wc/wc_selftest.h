// wc_selftest.h - internal self-test harness + runtime knobs (no env in release)
#ifndef WC_SELFTEST_H_
#define WC_SELFTEST_H_

int wc_selftest_run(void); // returns 0 on success, non-zero on any failure

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

#endif // WC_SELFTEST_H_
