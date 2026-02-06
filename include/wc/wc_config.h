// SPDX-License-Identifier: MIT
#ifndef WC_CONFIG_H
#define WC_CONFIG_H

#include <stddef.h>

#include "wc/wc_ip_pref.h"
#include "wc/wc_dns_family_mode.h"

// Forward declaration and full definition of Config shared
// between whois_client.c and core helpers.
typedef struct Config Config;

struct Config {
	int whois_port;                // WHOIS server port
	size_t buffer_size;            // Response buffer size
	int max_retries;               // Maximum retry count
	int timeout_sec;               // Timeout in seconds
	int retry_interval_ms;         // Base sleep between retries in milliseconds
	int retry_jitter_ms;           // Additional random jitter in milliseconds
	int retry_all_addrs;           // Apply retry budget to every resolved address when non-zero
	int retry_metrics;             // Emit retry metrics when enabled
	int pacing_disable;            // Disable connect-level pacing when set (>0)
	int pacing_interval_ms;        // Override pacing interval (ms)
	int pacing_jitter_ms;          // Override pacing jitter (ms)
	int pacing_backoff_factor;     // Override pacing backoff multiplier
	int pacing_max_ms;             // Override pacing maximum sleep (ms)
	size_t dns_cache_size;         // DNS cache entries count
	size_t connection_cache_size;  // Connection cache entries count
	int cache_timeout;             // Cache timeout in seconds
	int cache_counter_sampling;    // Emit cache counter samples even without debug
	int debug;                     // Debug mode flag
	int max_redirects;             // Maximum redirect/follow count
	int no_redirect;               // Disable following redirects when set
	int plain_mode;                // Suppress header line when set
	int show_non_auth_body;        // Show non-authoritative bodies when enabled
	int show_post_marker_body;     // Show bodies after ERX/IANA marker when enabled
	int show_failure_body;         // Keep rate-limit/denied body lines when enabled
	int cidr_strip_query;          // Strip CIDR prefix length when sending queries
	int cidr_fast_v4;              // IPv4 CIDR fast-path (two-phase lookup)
	int fold_output;               // Fold selected lines into one line per query
	char* fold_sep;                // Separator string for folded output (default: " ")
	int fold_upper;                // Uppercase values/RIR in folded output (default: 1)
	int security_logging;          // Enable security event logging (default: 0)
	int fold_unique;               // Deduplicate folded output segments when enabled
	int dns_neg_ttl;               // Negative DNS cache TTL (seconds)
	int dns_neg_cache_disable;     // Disable negative DNS caching
	int ipv4_only;                 // Force IPv4 only resolution
	int ipv6_only;                 // Force IPv6 only resolution
	int prefer_ipv4;               // Prefer IPv4 first then IPv6 (default)
	int prefer_ipv6;               // Prefer IPv6 first then IPv4
	wc_ip_pref_mode_t ip_pref_mode; // Hop-aware IPv4/IPv6 preference mode
	wc_rir_ip_pref_t rir_pref_iana;     // RIR-specific IPv4/IPv6 preference override
	wc_rir_ip_pref_t rir_pref_arin;
	wc_rir_ip_pref_t rir_pref_ripe;
	wc_rir_ip_pref_t rir_pref_apnic;
	wc_rir_ip_pref_t rir_pref_lacnic;
	wc_rir_ip_pref_t rir_pref_afrinic;
	wc_rir_ip_pref_t rir_pref_verisign;
	wc_dns_family_mode_t dns_family_mode; // DNS candidate ordering mode (global default)
	wc_dns_family_mode_t dns_family_mode_first; // First hop override (if set)
	wc_dns_family_mode_t dns_family_mode_next;  // Second+ hop override (if set)
	int dns_family_mode_first_set; // Non-zero when first-hop mode explicitly selected
	int dns_family_mode_next_set;  // Non-zero when second+ hop mode explicitly selected
	int dns_family_mode_set;       // Non-zero when global family mode explicitly selected
	// DNS resolver controls (Phase 1)
	int dns_addrconfig;            // enable AI_ADDRCONFIG in getaddrinfo
	int dns_retry;                 // retry attempts for getaddrinfo EAI_AGAIN
	int dns_retry_interval_ms;     // sleep between getaddrinfo retries
	int dns_max_candidates;        // cap number of resolved IPs to try
	int max_host_addrs;            // cap number of per-host resolved addresses to attempt (0 = unbounded)
	int dns_backoff_window_ms;     // DNS backoff failure window in ms (0 = disable window)
	int dns_append_known_ips;      // append known IPs to DNS candidates when enabled
	// Fallback toggles
	int no_dns_known_fallback;     // disable known IPv4 fallback
	int no_dns_force_ipv4_fallback;// disable forced IPv4 fallback
	int no_iana_pivot;             // disable IANA pivot
	int dns_no_fallback;           // disable forced fallback layers entirely
	int batch_interval_ms;         // sleep between batch queries in ms (0 = disable)
	int batch_jitter_ms;           // add random 0..J ms to batch interval
	const char* batch_strategy;    // batch accelerator/strategy selection
};

// Validates mandatory bounds in the configuration structure.
// Returns non-zero when the configuration is sane, 0 otherwise.
int wc_config_validate(const Config* config);

// Normalize cache-related settings and ensure they stay within allowed bounds
// before runtime modules consume them. Returns non-zero on success.
int wc_config_prepare_cache_settings(Config* config);

#endif // WC_CONFIG_H
