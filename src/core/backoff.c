// SPDX-License-Identifier: GPL-3.0-or-later
// Unified server backoff helpers built on wc_dns_health memory.

#include <stddef.h>
#include <strings.h>
#include <sys/socket.h>
#include <string.h>

#include "wc/wc_backoff.h"
#include "wc/wc_dns.h"

static int wc_backoff_check_family(const Config* config,
								   const char* host,
                                   int family,
                                   wc_dns_health_snapshot_t* snap) {
	if (family != AF_INET && family != AF_INET6) {
		return 0;
	}
	wc_dns_health_snapshot_t local;
	wc_dns_health_snapshot_t* target = snap ? snap : &local;
    wc_dns_health_state_t st = wc_dns_health_get_state(config, host, family, target);
	return st == WC_DNS_HEALTH_PENALIZED;
}

void wc_backoff_note_result(const Config* config, const char* host, int family, int success) {
	if (!host || !*host) {
		return;
	}
	if (family == AF_UNSPEC) {
		wc_dns_health_note_result(config, host, AF_INET, success);
		wc_dns_health_note_result(config, host, AF_INET6, success);
		return;
	}
	wc_dns_health_note_result(config, host, family, success);
}

void wc_backoff_note_success(const Config* config, const char* host, int family) {
	wc_backoff_note_result(config, host, family, 1);
}

void wc_backoff_note_failure(const Config* config, const char* host, int family) {
	wc_backoff_note_result(config, host, family, 0);
}

int wc_backoff_should_skip(const Config* config,
                           const char* host,
                           int family,
                           wc_dns_health_snapshot_t* snap) {
	if (!host || !*host) {
		return 0;
	}
	if (family == AF_UNSPEC) {
		if (wc_backoff_check_family(config, host, AF_INET, snap)) {
			return 1;
		}
		if (wc_backoff_check_family(config, host, AF_INET6, snap)) {
			return 1;
		}
		return 0;
	}
	return wc_backoff_check_family(config, host, family, snap);
}

void wc_backoff_set_penalty_window_seconds(int seconds) {
	long ms = (seconds <= 0) ? 0 : (long)seconds * 1000L;
	wc_dns_health_set_penalty_window_ms(ms);
}

long wc_backoff_get_penalty_window_ms(void) {
	return wc_dns_health_get_penalty_window_ms();
}

void wc_backoff_get_host_health(const Config* config,
		const char* host,
		wc_backoff_host_health_t* out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!host || !*host)
		return;
	out->host = host;
	out->ipv4_state = wc_dns_health_get_state(config, host, AF_INET, &out->ipv4);
	out->ipv6_state = wc_dns_health_get_state(config, host, AF_INET6, &out->ipv6);
}

size_t wc_backoff_collect_host_health(const Config* config,
		const char* const* hosts,
		size_t host_count,
		wc_backoff_host_health_t* out,
		size_t out_capacity)
{
	if (!hosts || !out || out_capacity == 0)
		return 0;
	size_t written = 0;
	for (size_t i = 0; i < host_count && written < out_capacity; ++i) {
		const char* host = hosts[i];
		if (!host || !*host)
			continue;
		int duplicate = 0;
		for (size_t j = 0; j < written; ++j) {
			if (out[j].host && strcasecmp(out[j].host, host) == 0) {
				duplicate = 1;
				break;
			}
		}
		if (duplicate)
			continue;
		wc_backoff_get_host_health(config, host, &out[written]);
		if (!out[written].host)
			continue;
		written++;
	}
	return written;
}
