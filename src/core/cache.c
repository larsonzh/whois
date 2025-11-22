// SPDX-License-Identifier: GPL-3.0-or-later
// Cache-related helpers for whois client (server backoff, etc.).

#include <pthread.h>
#include <string.h>
#include <time.h>

#include "wc/wc_cache.h"
#include "wc/wc_debug.h"
#include "wc/wc_util.h"
#include "wc/wc_output.h" // for log_message declaration

// Server status tracking structure for fast failure mechanism
typedef struct {
	char* host;
	time_t last_failure;
	int failure_count;
} ServerStatus;

#define MAX_SERVER_STATUS 20
#define SERVER_BACKOFF_TIME 300 // 5 minutes in seconds

static ServerStatus server_status[MAX_SERVER_STATUS] = {0};
static pthread_mutex_t server_status_mutex = PTHREAD_MUTEX_INITIALIZER;

int wc_cache_is_server_backed_off(const char* host)
{
	if (!host || !*host) return 0;

	pthread_mutex_lock(&server_status_mutex);

	time_t now = time(NULL);
	int backed_off = 0;

	for (int i = 0; i < MAX_SERVER_STATUS; i++) {
		if (server_status[i].host && strcmp(server_status[i].host, host) == 0) {
			// Check if server has too many recent failures
			if (server_status[i].failure_count >= 3 &&
			    (now - server_status[i].last_failure) < SERVER_BACKOFF_TIME) {
				backed_off = 1;
				if (wc_is_debug_enabled()) {
					log_message("DEBUG",
					           "Server %s is backed off (failures: %d, last: %lds ago)",
					           host,
					           server_status[i].failure_count,
					           (long)(now - server_status[i].last_failure));
				}
			}
			break;
		}
	}

	pthread_mutex_unlock(&server_status_mutex);
	return backed_off;
}

void wc_cache_mark_server_failure(const char* host)
{
	if (!host || !*host) return;

	pthread_mutex_lock(&server_status_mutex);

	time_t now = time(NULL);
	int found = 0;
	int empty_slot = -1;

	// Find existing entry or empty slot
	for (int i = 0; i < MAX_SERVER_STATUS; i++) {
		if (server_status[i].host && strcmp(server_status[i].host, host) == 0) {
			server_status[i].failure_count++;
			server_status[i].last_failure = now;
			found = 1;
			if (wc_is_debug_enabled()) {
				log_message("DEBUG",
				           "Marked server %s failure (count: %d)",
				           host,
				           server_status[i].failure_count);
			}
			break;
		} else if (!server_status[i].host && empty_slot == -1) {
			empty_slot = i;
		}
	}

	// Create new entry if not found
	if (!found && empty_slot != -1) {
		server_status[empty_slot].host = wc_safe_strdup(host, "wc_cache_mark_server_failure");
		server_status[empty_slot].failure_count = 1;
		server_status[empty_slot].last_failure = now;
		if (wc_is_debug_enabled()) {
			log_message("DEBUG",
			           "Created failure record for server %s",
			           host);
		}
	}

	pthread_mutex_unlock(&server_status_mutex);
}

void wc_cache_mark_server_success(const char* host)
{
	if (!host || !*host) return;

	pthread_mutex_lock(&server_status_mutex);

	for (int i = 0; i < MAX_SERVER_STATUS; i++) {
		if (server_status[i].host && strcmp(server_status[i].host, host) == 0) {
			// Reset failure count on success
			if (server_status[i].failure_count > 0) {
				if (wc_is_debug_enabled()) {
					log_message("DEBUG",
					           "Reset failure count for server %s (was: %d)",
					           host,
					           server_status[i].failure_count);
				}
				server_status[i].failure_count = 0;
			}
			break;
		}
	}

	pthread_mutex_unlock(&server_status_mutex);
}
