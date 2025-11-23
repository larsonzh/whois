// SPDX-License-Identifier: GPL-3.0-or-later
// Cache-related helpers for whois client (server backoff, DNS cache, etc.).

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "wc/wc_cache.h"
#include "wc/wc_client_util.h"
#include "wc/wc_config.h"
#include "wc/wc_debug.h"
#include "wc/wc_defaults.h"
#include "wc/wc_output.h"
#include "wc/wc_util.h"

extern Config g_config;
void safe_close(int* fd, const char* function_name);

// DNS cache structure - stores domain to IP mapping
typedef struct {
	char* domain;
	char* ip;
	time_t timestamp;
	int negative;
} DNSCacheEntry;

// Connection cache structure - stores connections to servers
typedef struct {
	char* host;
	int port;
	int sockfd;
	time_t last_used;
} ConnectionCacheEntry;

static DNSCacheEntry* dns_cache = NULL;
static ConnectionCacheEntry* connection_cache = NULL;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t allocated_dns_cache_size = 0;
static size_t allocated_connection_cache_size = 0;
int g_dns_neg_cache_hits = 0;
int g_dns_neg_cache_sets = 0;

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

void wc_cache_cleanup(void)
{
	pthread_mutex_lock(&cache_mutex);

	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
			free(dns_cache[i].domain);
			dns_cache[i].domain = NULL;
			free(dns_cache[i].ip);
			dns_cache[i].ip = NULL;
		}
		free(dns_cache);
		dns_cache = NULL;
		allocated_dns_cache_size = 0;
	}

	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
			free(connection_cache[i].host);
			connection_cache[i].host = NULL;
			if (connection_cache[i].sockfd != -1) {
				safe_close(&connection_cache[i].sockfd, "wc_cache_cleanup");
			}
		}
		free(connection_cache);
		connection_cache = NULL;
		allocated_connection_cache_size = 0;
	}

	pthread_mutex_unlock(&cache_mutex);
}

void wc_cache_init(void)
{
	pthread_mutex_lock(&cache_mutex);

	if (g_config.dns_cache_size == 0 || g_config.dns_cache_size > 100) {
		wc_output_log_message("WARN",
		           "DNS cache size %zu is unreasonable, using default",
		           g_config.dns_cache_size);
		g_config.dns_cache_size = WC_DEFAULT_DNS_CACHE_SIZE;
	}

	if (g_config.connection_cache_size == 0 || g_config.connection_cache_size > 50) {
		wc_output_log_message("WARN",
		           "Connection cache size %zu is unreasonable, using default",
		           g_config.connection_cache_size);
		g_config.connection_cache_size = WC_DEFAULT_CONNECTION_CACHE_SIZE;
	}

	dns_cache = wc_safe_malloc(g_config.dns_cache_size * sizeof(DNSCacheEntry), "wc_cache_init");
	memset(dns_cache, 0, g_config.dns_cache_size * sizeof(DNSCacheEntry));
	allocated_dns_cache_size = g_config.dns_cache_size;
	if (g_config.debug) {
		printf("[DEBUG] DNS cache allocated for %zu entries\n",
		       g_config.dns_cache_size);
	}

	connection_cache = wc_safe_malloc(g_config.connection_cache_size * sizeof(ConnectionCacheEntry), "wc_cache_init");
	memset(connection_cache, 0,
	       g_config.connection_cache_size * sizeof(ConnectionCacheEntry));
	for (size_t i = 0; i < g_config.connection_cache_size; i++) {
		connection_cache[i].sockfd = -1;
	}
	allocated_connection_cache_size = g_config.connection_cache_size;
	if (g_config.debug) {
		printf("[DEBUG] Connection cache allocated for %zu entries\n",
		       g_config.connection_cache_size);
	}

	pthread_mutex_unlock(&cache_mutex);
	wc_cache_log_statistics();
}

int wc_cache_validate_sizes(void)
{
	size_t free_mem = wc_client_get_free_memory();
	if (free_mem == 0) {
		return 1;
	}

	size_t required_mem =
		(g_config.dns_cache_size * sizeof(DNSCacheEntry)) +
		(g_config.connection_cache_size * sizeof(ConnectionCacheEntry));
	required_mem = required_mem * 110 / 100;

	if (required_mem > free_mem * 1024) {
		fprintf(stderr,
		        "Warning: Requested cache size (%zu bytes) exceeds available "
		        "memory (%zu KB)\n",
		        required_mem,
		        free_mem);
		return 0;
	}

	return 1;
}

void wc_cache_cleanup_expired_entries(void)
{
	if (g_config.debug) {
		wc_output_log_message("DEBUG", "Starting cache cleanup");
	}

	pthread_mutex_lock(&cache_mutex);

	time_t now = time(NULL);
	int dns_cleaned = 0;
	int conn_cleaned = 0;

	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
			if (dns_cache[i].domain && dns_cache[i].ip) {
				if (now - dns_cache[i].timestamp >= g_config.cache_timeout) {
					if (g_config.debug) {
						wc_output_log_message("DEBUG",
						           "Removing expired DNS cache: %s -> %s",
						           dns_cache[i].domain,
						           dns_cache[i].ip);
					}
					free(dns_cache[i].domain);
					free(dns_cache[i].ip);
					dns_cache[i].domain = NULL;
					dns_cache[i].ip = NULL;
					dns_cleaned++;
				}
			}
		}
	}

	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
			if (connection_cache[i].host) {
				if ((now - connection_cache[i].last_used >= g_config.cache_timeout) ||
				    !wc_cache_is_connection_alive(connection_cache[i].sockfd)) {
					if (g_config.debug) {
						wc_output_log_message("DEBUG",
						           "Removing expired/dead connection: %s:%d",
						           connection_cache[i].host,
						           connection_cache[i].port);
					}
					safe_close(&connection_cache[i].sockfd, "wc_cache_cleanup_expired_entries");
					free(connection_cache[i].host);
					connection_cache[i].host = NULL;
					connection_cache[i].sockfd = -1;
					conn_cleaned++;
				}
			}
		}
	}

	pthread_mutex_unlock(&cache_mutex);

	if (g_config.debug && (dns_cleaned > 0 || conn_cleaned > 0)) {
		wc_output_log_message("DEBUG",
		           "Cache cleanup completed: %d DNS, %d connection entries removed",
		           dns_cleaned,
		           conn_cleaned);
	}
}

char* wc_cache_get_dns(const char* domain)
{
	if (!wc_client_is_valid_domain_name(domain)) {
		wc_output_log_message("WARN",
		           "Invalid domain name for DNS cache lookup: %s",
		           domain);
		return NULL;
	}

	pthread_mutex_lock(&cache_mutex);

	if (!dns_cache) {
		pthread_mutex_unlock(&cache_mutex);
		return NULL;
	}

	time_t now = time(NULL);
	for (size_t i = 0; i < allocated_dns_cache_size; i++) {
		if (dns_cache[i].domain && strcmp(dns_cache[i].domain, domain) == 0) {
			if (dns_cache[i].negative) {
				if (now - dns_cache[i].timestamp < g_config.dns_neg_ttl) {
					pthread_mutex_unlock(&cache_mutex);
					return NULL;
				}
				free(dns_cache[i].domain);
				free(dns_cache[i].ip);
				dns_cache[i].domain = NULL;
				dns_cache[i].ip = NULL;
				continue;
			}
			if (now - dns_cache[i].timestamp < g_config.cache_timeout) {
				if (!wc_client_validate_dns_response(dns_cache[i].ip)) {
					wc_output_log_message("WARN",
					           "Invalid cached IP found for %s: %s",
					           domain,
					           dns_cache[i].ip);
					free(dns_cache[i].domain);
					free(dns_cache[i].ip);
					dns_cache[i].domain = NULL;
					dns_cache[i].ip = NULL;
					pthread_mutex_unlock(&cache_mutex);
					return NULL;
				}
				char* result = wc_safe_strdup(dns_cache[i].ip, "wc_cache_get_dns");
				pthread_mutex_unlock(&cache_mutex);
				return result;
			}
			free(dns_cache[i].domain);
			free(dns_cache[i].ip);
			dns_cache[i].domain = NULL;
			dns_cache[i].ip = NULL;
		}
	}

	pthread_mutex_unlock(&cache_mutex);
	return NULL;
}

void wc_cache_set_dns(const char* domain, const char* ip)
{
	if (!wc_client_is_valid_domain_name(domain)) {
		wc_output_log_message("WARN",
		           "Attempted to cache invalid domain: %s",
		           domain);
		return;
	}

	if (!wc_client_validate_dns_response(ip)) {
		wc_output_log_message("WARN",
		           "Attempted to cache invalid IP: %s for domain %s",
		           ip,
		           domain);
		return;
	}

	pthread_mutex_lock(&cache_mutex);

	if (!dns_cache) {
		pthread_mutex_unlock(&cache_mutex);
		return;
	}

	int oldest_index = 0;
	time_t oldest_time = time(NULL);

	for (size_t i = 0; i < allocated_dns_cache_size; i++) {
		if (dns_cache[i].domain && strcmp(dns_cache[i].domain, domain) == 0) {
			dns_cache[i].negative = 0;
			free(dns_cache[i].ip);
			dns_cache[i].ip = wc_safe_strdup(ip, "wc_cache_set_dns");
			dns_cache[i].timestamp = time(NULL);
			pthread_mutex_unlock(&cache_mutex);
			return;
		}

		if (dns_cache[i].timestamp < oldest_time) {
			oldest_time = dns_cache[i].timestamp;
			oldest_index = (int)i;
		}
	}

	free(dns_cache[oldest_index].domain);
	free(dns_cache[oldest_index].ip);
	dns_cache[oldest_index].domain = wc_safe_strdup(domain, "wc_cache_set_dns");
	dns_cache[oldest_index].ip = wc_safe_strdup(ip, "wc_cache_set_dns");
	dns_cache[oldest_index].timestamp = time(NULL);
	dns_cache[oldest_index].negative = 0;

	pthread_mutex_unlock(&cache_mutex);
	if (g_config.debug) {
		wc_output_log_message("DEBUG", "Cached DNS: %s -> %s", domain, ip);
	}
}

int wc_cache_is_negative_dns_cached(const char* domain)
{
	if (g_config.dns_neg_cache_disable || !domain) {
		return 0;
	}
	pthread_mutex_lock(&cache_mutex);
	if (!dns_cache) {
		pthread_mutex_unlock(&cache_mutex);
		return 0;
	}
	time_t now = time(NULL);
	for (size_t i = 0; i < allocated_dns_cache_size; i++) {
		if (dns_cache[i].domain && dns_cache[i].negative &&
		    strcmp(dns_cache[i].domain, domain) == 0) {
			if (now - dns_cache[i].timestamp < g_config.dns_neg_ttl) {
				pthread_mutex_unlock(&cache_mutex);
				g_dns_neg_cache_hits++;
				return 1;
			}
			free(dns_cache[i].domain);
			free(dns_cache[i].ip);
			dns_cache[i].domain = NULL;
			dns_cache[i].ip = NULL;
			dns_cache[i].negative = 0;
		}
	}
	pthread_mutex_unlock(&cache_mutex);
	return 0;
}

void wc_cache_set_negative_dns(const char* domain)
{
	if (g_config.dns_neg_cache_disable || !domain) {
		return;
	}
	pthread_mutex_lock(&cache_mutex);
	if (!dns_cache) {
		pthread_mutex_unlock(&cache_mutex);
		return;
	}
	int oldest_index = 0;
	time_t oldest_time = time(NULL);
	for (size_t i = 0; i < allocated_dns_cache_size; i++) {
		if (dns_cache[i].domain && strcmp(dns_cache[i].domain, domain) == 0) {
			free(dns_cache[i].ip);
			dns_cache[i].ip = NULL;
			dns_cache[i].timestamp = time(NULL);
			dns_cache[i].negative = 1;
			pthread_mutex_unlock(&cache_mutex);
			return;
		}
		if (dns_cache[i].timestamp < oldest_time) {
			oldest_time = dns_cache[i].timestamp;
			oldest_index = (int)i;
		}
	}
	free(dns_cache[oldest_index].domain);
	free(dns_cache[oldest_index].ip);
	dns_cache[oldest_index].domain = wc_safe_strdup(domain, "wc_cache_set_negative_dns");
	dns_cache[oldest_index].ip = NULL;
	dns_cache[oldest_index].timestamp = time(NULL);
	dns_cache[oldest_index].negative = 1;
	pthread_mutex_unlock(&cache_mutex);
	g_dns_neg_cache_sets++;
}

int wc_cache_get_connection(const char* host, int port)
{
	pthread_mutex_lock(&cache_mutex);

	if (!connection_cache) {
		pthread_mutex_unlock(&cache_mutex);
		return -1;
	}

	time_t now = time(NULL);
	for (size_t i = 0; i < allocated_connection_cache_size; i++) {
		if (connection_cache[i].host &&
		    strcmp(connection_cache[i].host, host) == 0 &&
		    connection_cache[i].port == port) {
			if (now - connection_cache[i].last_used < g_config.cache_timeout) {
				if (wc_cache_is_connection_alive(connection_cache[i].sockfd)) {
					connection_cache[i].last_used = now;
					int sockfd = connection_cache[i].sockfd;
					pthread_mutex_unlock(&cache_mutex);
					return sockfd;
				}
				safe_close(&connection_cache[i].sockfd, "wc_cache_get_connection");
				free(connection_cache[i].host);
				connection_cache[i].host = NULL;
			} else {
				safe_close(&connection_cache[i].sockfd, "wc_cache_get_connection");
				free(connection_cache[i].host);
				connection_cache[i].host = NULL;
			}
		}
	}

	pthread_mutex_unlock(&cache_mutex);
	return -1;
}

void wc_cache_set_connection(const char* host, int port, int sockfd)
{
	if (!host || !*host) {
		wc_output_log_message("WARN",
		           "Attempted to cache connection with invalid host");
		return;
	}

	if (port <= 0 || port > 65535) {
		wc_output_log_message("WARN",
		           "Attempted to cache connection with invalid port: %d",
		           port);
		return;
	}

	if (sockfd < 0) {
		wc_output_log_message("WARN",
		           "Attempted to cache invalid socket descriptor: %d",
		           sockfd);
		return;
	}

	if (!wc_cache_is_connection_alive(sockfd)) {
		wc_output_log_message("WARN",
		           "Attempted to cache dead connection to %s:%d",
		           host,
		           port);
		safe_close(&sockfd, "wc_cache_set_connection");
		return;
	}

	pthread_mutex_lock(&cache_mutex);

	if (!connection_cache) {
		pthread_mutex_unlock(&cache_mutex);
		return;
	}

	int oldest_index = 0;
	time_t oldest_time = time(NULL);

	for (size_t i = 0; i < allocated_connection_cache_size; i++) {
		if (!connection_cache[i].host) {
			connection_cache[i].host = wc_safe_strdup(host, "wc_cache_set_connection");
			connection_cache[i].port = port;
			connection_cache[i].sockfd = sockfd;
			connection_cache[i].last_used = time(NULL);
			if (g_config.debug) {
				wc_output_log_message("DEBUG",
				           "Cached connection to %s:%d (slot %d)",
				           host,
				           port,
				           (int)i);
			}
			pthread_mutex_unlock(&cache_mutex);
			return;
		}

		if (connection_cache[i].last_used < oldest_time) {
			oldest_time = connection_cache[i].last_used;
			oldest_index = (int)i;
		}
	}

	if (g_config.debug) {
		wc_output_log_message("DEBUG",
		           "Replacing oldest connection (slot %d) with %s:%d",
		           oldest_index,
		           host,
		           port);
	}

	safe_close(&connection_cache[oldest_index].sockfd, "wc_cache_set_connection");
	free(connection_cache[oldest_index].host);
	connection_cache[oldest_index].host = wc_safe_strdup(host, "wc_cache_set_connection");
	connection_cache[oldest_index].port = port;
	connection_cache[oldest_index].sockfd = sockfd;
	connection_cache[oldest_index].last_used = time(NULL);

	pthread_mutex_unlock(&cache_mutex);
}

void wc_cache_validate_integrity(void)
{
	if (!g_config.debug) {
		return;
	}

	pthread_mutex_lock(&cache_mutex);

	int dns_valid = 0;
	int dns_invalid = 0;
	int conn_valid = 0;
	int conn_invalid = 0;

	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
			if (dns_cache[i].domain && dns_cache[i].ip) {
				if (wc_client_is_valid_domain_name(dns_cache[i].domain) &&
				    wc_client_validate_dns_response(dns_cache[i].ip)) {
					dns_valid++;
				} else {
					dns_invalid++;
					wc_output_log_message("WARN",
					           "Invalid DNS cache entry: %s -> %s",
					           dns_cache[i].domain,
					           dns_cache[i].ip);
				}
			}
		}
	}

	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
			if (connection_cache[i].host) {
				if (wc_client_is_valid_domain_name(connection_cache[i].host) &&
				    connection_cache[i].port > 0 &&
				    connection_cache[i].port <= 65535 &&
				    connection_cache[i].sockfd >= 0 &&
				    wc_cache_is_connection_alive(connection_cache[i].sockfd)) {
					conn_valid++;
				} else {
					conn_invalid++;
					wc_output_log_message("WARN",
					           "Invalid connection cache entry: %s:%d (fd: %d)",
					           connection_cache[i].host,
					           connection_cache[i].port,
					           connection_cache[i].sockfd);
				}
			}
		}
	}

	pthread_mutex_unlock(&cache_mutex);

	if (dns_invalid > 0 || conn_invalid > 0) {
		wc_output_log_message("INFO",
		           "Cache integrity check: %d/%d DNS valid, %d/%d connections valid",
		           dns_valid,
		           dns_valid + dns_invalid,
		           conn_valid,
		           conn_valid + conn_invalid);
	}
}

void wc_cache_log_statistics(void)
{
	if (!g_config.debug) {
		return;
	}

	pthread_mutex_lock(&cache_mutex);

	int dns_entries = 0;
	int conn_entries = 0;

	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
			if (dns_cache[i].domain && dns_cache[i].ip) {
				dns_entries++;
			}
		}
	}

	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
			if (connection_cache[i].host) {
				conn_entries++;
			}
		}
	}

	pthread_mutex_unlock(&cache_mutex);

	wc_output_log_message("DEBUG",
	           "Cache statistics: %d/%zu DNS entries, %d/%zu connection entries",
	           dns_entries,
	           g_config.dns_cache_size,
	           conn_entries,
	           g_config.connection_cache_size);
}

int wc_cache_is_server_backed_off(const char* host)
{
	if (!host || !*host) return 0;

	pthread_mutex_lock(&server_status_mutex);

	time_t now = time(NULL);
	int backed_off = 0;

	for (int i = 0; i < MAX_SERVER_STATUS; i++) {
		if (server_status[i].host && strcmp(server_status[i].host, host) == 0) {
			if (server_status[i].failure_count >= 3 &&
			    (now - server_status[i].last_failure) < SERVER_BACKOFF_TIME) {
				backed_off = 1;
				if (wc_is_debug_enabled()) {
					wc_output_log_message("DEBUG",
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

	for (int i = 0; i < MAX_SERVER_STATUS; i++) {
		if (server_status[i].host && strcmp(server_status[i].host, host) == 0) {
			server_status[i].failure_count++;
			server_status[i].last_failure = now;
			found = 1;
			if (wc_is_debug_enabled()) {
				wc_output_log_message("DEBUG",
				           "Marked server %s failure (count: %d)",
				           host,
				           server_status[i].failure_count);
			}
			break;
		} else if (!server_status[i].host && empty_slot == -1) {
			empty_slot = i;
		}
	}

	if (!found && empty_slot != -1) {
		server_status[empty_slot].host = wc_safe_strdup(host, "wc_cache_mark_server_failure");
		server_status[empty_slot].failure_count = 1;
		server_status[empty_slot].last_failure = now;
		if (wc_is_debug_enabled()) {
			wc_output_log_message("DEBUG",
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
			if (server_status[i].failure_count > 0) {
				if (wc_is_debug_enabled()) {
					wc_output_log_message("DEBUG",
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

int wc_cache_is_connection_alive(int sockfd)
{
	if (sockfd == -1) return 0;

	int error = 0;
	socklen_t len = sizeof(error);

	if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
		return error == 0;
	}

	return 0;
}
