// SPDX-License-Identifier: GPL-3.0-or-later
// Unified server backoff helpers built on wc_dns_health memory.

#include <stddef.h>
#include <sys/socket.h>

#include "wc/wc_backoff.h"
#include "wc/wc_dns.h"

static int wc_backoff_check_family(const char* host,
                                   int family,
                                   wc_dns_health_snapshot_t* snap) {
	if (family != AF_INET && family != AF_INET6) {
		return 0;
	}
	wc_dns_health_snapshot_t local;
	wc_dns_health_snapshot_t* target = snap ? snap : &local;
	wc_dns_health_state_t st = wc_dns_health_get_state(host, family, target);
	return st == WC_DNS_HEALTH_PENALIZED;
}

void wc_backoff_note_result(const char* host, int family, int success) {
	if (!host || !*host) {
		return;
	}
	if (family == AF_UNSPEC) {
		wc_dns_health_note_result(host, AF_INET, success);
		wc_dns_health_note_result(host, AF_INET6, success);
		return;
	}
	wc_dns_health_note_result(host, family, success);
}

void wc_backoff_note_success(const char* host, int family) {
	wc_backoff_note_result(host, family, 1);
}

void wc_backoff_note_failure(const char* host, int family) {
	wc_backoff_note_result(host, family, 0);
}

int wc_backoff_should_skip(const char* host,
                           int family,
                           wc_dns_health_snapshot_t* snap) {
	if (!host || !*host) {
		return 0;
	}
	if (family == AF_UNSPEC) {
		if (wc_backoff_check_family(host, AF_INET, snap)) {
			return 1;
		}
		if (wc_backoff_check_family(host, AF_INET6, snap)) {
			return 1;
		}
		return 0;
	}
	return wc_backoff_check_family(host, family, snap);
}

void wc_backoff_set_penalty_window_seconds(int seconds) {
	long ms = (seconds <= 0) ? 0 : (long)seconds * 1000L;
	wc_dns_health_set_penalty_window_ms(ms);
}

long wc_backoff_get_penalty_window_ms(void) {
	return wc_dns_health_get_penalty_window_ms();
}
