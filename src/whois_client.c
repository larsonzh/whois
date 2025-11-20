// whois client (version 3.2.9) - migrated from lzispro
// License: GPL-3.0-or-later

// ============================================================================
// 1. Header includes
// ============================================================================

// Enable POSIX interfaces (e.g., strdup) in strict C modes on newer GCC
// (GCC 14 treats implicit function declarations as errors for C11+).
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <strings.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include "wc/wc_output.h"
#include "wc/wc_seclog.h"
#include "wc/wc_fold.h"
#include "wc/wc_title.h"
#include "wc/wc_grep.h"
#include "wc/wc_opts.h"
#include "wc/wc_meta.h"
#include "wc/wc_lookup.h"
#include "wc/wc_dns.h"
#include <unistd.h>
#include <signal.h>

// ============================================================================
// 2. Macro definitions and constants
// ============================================================================

// Provide a portable replacement for strdup for strict C11 builds on CI.
// We alias strdup to our local static function to avoid missing prototype
// issues across different libcs while keeping call sites unchanged.
static char* safe_strdup(const char* s) {
	if (!s) return NULL;
	size_t len = strlen(s) + 1;  // include NUL
	char* p = (char*)malloc(len);
	if (!p) return NULL;
	memcpy(p, s, len);
	return p;
}
#undef strdup
#define strdup safe_strdup

// Default configuration values
#define DEFAULT_WHOIS_PORT 43
#define BUFFER_SIZE 524288
#define MAX_RETRIES 2
#define TIMEOUT_SEC 5
#define DNS_CACHE_SIZE 10
#define CONNECTION_CACHE_SIZE 5
#define CACHE_TIMEOUT 300
#define DEBUG 0
#define MAX_REDIRECTS 5

// Response processing constants
#define RESPONSE_SEPARATOR "\n=== %s query to %s ===\n"
#define FINAL_QUERY_TEXT "Final"
#define REDIRECTED_QUERY_TEXT "Redirected"
#define ADDITIONAL_QUERY_TEXT "Additional"

// Server status tracking constants for fast failure mechanism
#define MAX_SERVER_STATUS 20
#define SERVER_BACKOFF_TIME 300 // 5 minutes in seconds

// Security event type definitions
#define SEC_EVENT_INVALID_INPUT      1
#define SEC_EVENT_SUSPICIOUS_QUERY   2
#define SEC_EVENT_CONNECTION_ATTACK  3
#define SEC_EVENT_RESPONSE_TAMPERING 4
#define SEC_EVENT_RATE_LIMIT_HIT     5

// Protocol-level security definitions
#define MAX_PROTOCOL_LINE_LENGTH 1024
#define MAX_RESPONSE_SIZE (10 * 1024 * 1024) // 10MB max response
#define PROTOCOL_TIMEOUT_EXTENDED 30 // Extended timeout for large responses
#define MIN_VALID_RESPONSE_SIZE 10 // Minimum valid response size

// ============================================================================
// 3. Data structures & global variables (minimal declarations before use)
// ============================================================================

// Shared configuration structure
#include "wc/wc_config.h"

extern Config g_config;

// Global configuration, initialized with macro definitions
Config g_config = {.whois_port = DEFAULT_WHOIS_PORT,
			   .buffer_size = BUFFER_SIZE,
			   .max_retries = MAX_RETRIES,
			   .timeout_sec = TIMEOUT_SEC,
			   .retry_interval_ms = 300,
			   .retry_jitter_ms = 300,
			   .dns_cache_size = DNS_CACHE_SIZE,
			   .connection_cache_size = CONNECTION_CACHE_SIZE,
			   .cache_timeout = CACHE_TIMEOUT,
			   .debug = DEBUG,
			   .max_redirects = MAX_REDIRECTS,
			   .no_redirect = 0,
			   .plain_mode = 0,
			   .fold_output = 0,
			   .fold_sep = NULL,
			   .fold_upper = 1,
			   .security_logging = 0,
			   .fold_unique = 0};

// DNS cache structure - stores domain to IP mapping
typedef struct {
	char* domain;      // Domain name
	char* ip;          // IP address
	time_t timestamp;  // Cache timestamp
	int negative;      // 1 if this is a negative cache entry (resolution failure)
} DNSCacheEntry;

// Connection cache structure - stores connections to servers
typedef struct {
	char* host;        // Hostname or IP
	int port;          // Port number
	int sockfd;        // Socket descriptor
	time_t last_used;  // Last used time
} ConnectionCacheEntry;

// WHOIS server structure - stores WHOIS server information
typedef struct {
	const char* name;         // Server short name
	const char* domain;       // Server domain
	const char* description;  // Server description
} WhoisServer;

// WHOIS server list - all supported WHOIS servers
static WhoisServer servers[] = {
	{"arin", "whois.arin.net", "American Registry for Internet Numbers"},
	{"apnic", "whois.apnic.net", "Asia-Pacific Network Information Centre"},
	{"ripe", "whois.ripe.net", "RIPE Network Coordination Centre"},
	{"lacnic", "whois.lacnic.net",
	 "Latin America and Caribbean Network Information Centre"},
	{"afrinic", "whois.afrinic.net", "African Network Information Centre"},
	{"iana", "whois.iana.org", "Internet Assigned Numbers Authority"},
	{NULL, NULL, NULL}  // End of list marker
};

// Server status tracking structure for fast failure mechanism
typedef struct {
	char* host;
	time_t last_failure;
	int failure_count;
} ServerStatus;

// Global cache variables
static DNSCacheEntry* dns_cache = NULL;
static ConnectionCacheEntry* connection_cache = NULL;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t allocated_dns_cache_size = 0;
static size_t allocated_connection_cache_size = 0;
static ServerStatus server_status[MAX_SERVER_STATUS] = {0};
static pthread_mutex_t server_status_mutex = PTHREAD_MUTEX_INITIALIZER;
// DNS negative cache counters (diagnostics)
static int g_dns_neg_cache_hits = 0;
static int g_dns_neg_cache_sets = 0;

// Signal handling context
static volatile sig_atomic_t g_shutdown_requested = 0;
static pthread_mutex_t signal_mutex = PTHREAD_MUTEX_INITIALIZER;

// Active connection tracking for signal cleanup
typedef struct {
	char* host;
	int port;
	int sockfd;
	time_t start_time;
} ActiveConnection;

static ActiveConnection g_active_conn = {NULL, 0, -1, 0};
static pthread_mutex_t active_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

// Define wc_debug shim now that g_config is defined
int wc_is_debug_enabled(void) { return g_config.debug; }

// ============================================================================
// 5. Function declarations
// ============================================================================

//  Utility functions
size_t parse_size_with_unit(const char* str);
void print_servers();
int is_private_ip(const char* ip);
int validate_global_config();   // Ensure that returning 0 indicates failure and 1
								// indicates success
void init_caches();
void cleanup_caches();
size_t get_free_memory();  // Changed to size_t for consistency
void report_memory_error(const char* function, size_t size);
void log_message(const char* level, const char* format, ...);
// Forward declarations for signal & active connection management used before definitions
static void setup_signal_handlers(void);
static void cleanup_on_signal(void);
static void signal_handler(int sig);
static void register_active_connection(const char* host, int port, int sockfd);
static void unregister_active_connection(void);
static int should_terminate(void);
// Use shared utility allocator from wc_util for fatal-on-OOM behavior.
void* wc_safe_malloc(size_t size, const char* function_name);

// DNS and connection cache functions
char* get_cached_dns(const char* domain);
void set_cached_dns(const char* domain, const char* ip);
int is_negative_dns_cached(const char* domain);
void set_negative_dns(const char* domain);
int is_connection_alive(int sockfd);
int get_cached_connection(const char* host, int port);
void set_cached_connection(const char* host, int port, int sockfd);
const char* get_known_ip(const char* domain);

// Network connection functions
char* resolve_domain(const char* domain);
int connect_to_server(const char* host, int port, int* sockfd);
int connect_with_fallback(const char* domain, int port, int* sockfd);
int send_query(int sockfd, const char* query);
char* receive_response(int sockfd);

// WHOIS protocol processing functions
#include "wc/wc_redirect.h"
// Debug shim for modules
#include "wc/wc_debug.h"
// Selftest toggles
#include "wc/wc_selftest.h"
#include "wc/wc_query_exec.h"
// Expose debug flag via wc_debug shim for new modules (defined after g_config below)
int wc_is_debug_enabled(void);
char* perform_whois_query(const char* target, int port, const char* query, char** authoritative_server_out, char** first_server_host_out, char** first_server_ip_out);
char* get_server_target(const char* server_input);
// Forward prototypes to avoid implicit declarations before definitions
static int is_safe_protocol_character(unsigned char c);
static int is_valid_domain_name(const char* domain);
static int is_valid_ip_address(const char* ip);
static void safe_close(int* fd, const char* function_name);

// Fallback resolution helpers for IP literal servers
static int is_ip_literal(const char* s);
static char* reverse_lookup_domain(const char* ip_literal);
static const char* map_domain_to_rir(const char* domain);
static char* attempt_rir_fallback_from_ip(const char* ip_literal);

// ============================================================================
// 6. Static function implementations
// ============================================================================

// Protocol-level security functions
static int validate_whois_protocol_response(const char* response, size_t len) {
    if (!response || len == 0) {
        log_message("WARN", "Empty or NULL WHOIS protocol response");
        return 0;
    }
    
    // Check for minimum valid response size
    if (len < MIN_VALID_RESPONSE_SIZE) {
        log_message("WARN", "WHOIS response too short: %zu bytes", len);
        return 0;
    }
    
    // Check for maximum response size
    if (len > MAX_RESPONSE_SIZE) {
        log_message("WARN", "WHOIS response too large: %zu bytes", len);
        return 0;
    }
    
    // Validate response structure
    int has_valid_content = 0;
    int line_count = 0;
    int max_lines = 10000; // Reasonable limit for WHOIS responses
    
    const char* ptr = response;
    while (*ptr && line_count < max_lines) {
        const char* line_start = ptr;
        size_t line_len = 0;
        
        // Find end of line
        while (*ptr && *ptr != '\n' && *ptr != '\r') {
            if (!is_safe_protocol_character((unsigned char)*ptr)) {
                log_message("WARN", "Unsafe character in WHOIS response: 0x%02x", (unsigned char)*ptr);
                return 0;
            }
            ptr++;
            line_len++;
        }
        
        // Check line length
        if (line_len > MAX_PROTOCOL_LINE_LENGTH) {
            log_message("WARN", "WHOIS response line too long: %zu characters", line_len);
            return 0;
        }
        
        // Check for valid WHOIS content
        if (line_len > 0) {
            // Skip comment lines starting with %
            if (line_start[0] != '%' && line_start[0] != '#') {
                // Check for common WHOIS field patterns
                for (size_t i = 0; i < line_len; i++) {
                    if (line_start[i] == ':') {
                        has_valid_content = 1;
                        break;
                    }
                }
            }
        }
        
        line_count++;
        
        // Skip line endings
        while (*ptr == '\n' || *ptr == '\r') {
            ptr++;
        }
    }
    
	if (!has_valid_content) {
		int has_printable = 0;
		for (const char* p = response; *p; p++) {
			unsigned char c = (unsigned char)*p;
			if (c > ' ' && c < 0x7f) {
				has_printable = 1;
				break;
			}
		}
		if (!has_printable) {
			log_message("WARN", "WHOIS response lacks valid content structure");
			return 0;
		}
		log_message("INFO", "WHOIS response lacks key/value pairs, continuing for redirect compatibility");
	}
    
    return 1;
}

static int detect_protocol_anomalies(const char* response) {
    if (!response) return 0;
    
    int anomalies = 0;
    
    // Check for suspicious patterns
    const char* suspicious_patterns[] = {
        "<script>",
        "javascript:",
        "vbscript:",
        "onload=",
        "onerror=",
        "eval(",
        "document.cookie",
        "window.location",
        "base64,",
        "data:text/html",
        NULL
    };
    
    for (int i = 0; suspicious_patterns[i] != NULL; i++) {
        if (strstr(response, suspicious_patterns[i])) {
            log_security_event(SEC_EVENT_RESPONSE_TAMPERING, 
                              "Detected suspicious pattern in WHOIS response: %s", 
                              suspicious_patterns[i]);
            anomalies++;
        }
    }
    
    // Check for excessive redirect attempts
    int redirect_count = 0;
    const char* ptr = response;
    while ((ptr = strstr(ptr, "refer:")) != NULL) {
        redirect_count++;
        ptr += 6; // Move past "refer:"
        
        if (redirect_count > 5) {
            log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
                              "Excessive redirect references in response: %d", 
                              redirect_count);
            anomalies++;
            break;
        }
    }
    
    // Check for binary data or control characters
    for (const char* p = response; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
            if (c != 0) { // Allow null terminator
                log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
                                  "Binary/control character in WHOIS response: 0x%02x", c);
                anomalies++;
                break;
            }
        }
    }
    
    return anomalies;
}

static int is_safe_protocol_character(unsigned char c) {
    // Allow printable ASCII characters and common whitespace
    if (c >= 32 && c <= 126) {
        return 1;
    }
    
    // Allow common whitespace characters
    if (c == '\t' || c == '\n' || c == '\r') {
        return 1;
    }
    
    return 0;
}

static int check_response_integrity(const char* response, size_t len) {
    if (!response || len == 0) {
        return 0;
    }
    
    // Check for null bytes in the middle of response
    for (size_t i = 0; i < len; i++) {
        if (response[i] == 0 && i < len - 1) {
            log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
                              "Null byte detected in WHOIS response at position %zu", i);
            return 0;
        }
    }
    
    // Check for consistent line endings (should be \r\n or \n)
    int has_crlf = 0;
    int has_lf = 0;
    
    for (size_t i = 0; i < len - 1; i++) {
        if (response[i] == '\r' && response[i+1] == '\n') {
            has_crlf = 1;
        } else if (response[i] == '\n' && (i == 0 || response[i-1] != '\r')) {
            has_lf = 1;
        }
    }
    
    // Mixed line endings might indicate tampering
    if (has_crlf && has_lf) {
        log_message("WARN", "Mixed line endings in WHOIS response (possible tampering)");
        return 0;
    }
    
    return 1;
}

static int detect_protocol_injection(const char* query, const char* response) {
    if (!query || !response) {
        return 0;
    }
    
    int injection_detected = 0;
    
    // Check if query appears in response in unexpected ways
    // This could indicate response injection or query reflection attacks
    if (strstr(response, query)) {
        // It's normal for the query to appear in some responses,
        // but we should check for suspicious patterns
        
        // Look for query in comment sections or error messages
        const char* suspicious_contexts[] = {
            "Error:",
            "Warning:",
            "Invalid",
            "Unknown",
            "not found",
            "no match",
            NULL
        };
        
        for (int i = 0; suspicious_contexts[i] != NULL; i++) {
            char pattern[256];
            snprintf(pattern, sizeof(pattern), "%s.*%s", suspicious_contexts[i], query);
            
            // Simple substring check (for demonstration)
            const char* ctx_pos = strstr(response, suspicious_contexts[i]);
            const char* query_pos = strstr(response, query);
            
            if (ctx_pos && query_pos && query_pos > ctx_pos && 
                (query_pos - ctx_pos) < 100) {
                log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
                                  "Possible query injection detected: %s in %s context", 
                                  query, suspicious_contexts[i]);
                injection_detected = 1;
                break;
            }
        }
    }
    
    return injection_detected;
}

// Signal handling functions
static void setup_signal_handlers(void) {
	struct sigaction sa;

	// Default template
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = signal_handler;

	// For termination-like signals, do not use SA_RESTART so select/connect
	// and other syscalls get interrupted by EINTR.
	sa.sa_flags = 0; // no SA_RESTART for SIGINT/SIGTERM/SIGHUP
	sigaction(SIGINT, &sa, NULL);  // Ctrl+C
	sigaction(SIGTERM, &sa, NULL); // Termination signal
	sigaction(SIGHUP, &sa, NULL);  // Hangup

	// Use SA_RESTART for SIGPIPE and let the network layer handle it
	sa.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &sa, NULL); // Broken pipe (network connection closed)

	// Ignore some signals
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	if (g_config.debug) {
		log_message("DEBUG", "Signal handlers installed");
	}
}

static void signal_handler(int sig) {
    const char* sig_name = "UNKNOWN";
    
    switch(sig) {
        case SIGINT:  sig_name = "SIGINT"; break;
        case SIGTERM: sig_name = "SIGTERM"; break;
        case SIGHUP:  sig_name = "SIGHUP"; break;
        case SIGPIPE: sig_name = "SIGPIPE"; break;
    }
    
	log_message("INFO", "Received signal: %s (%d)", sig_name, sig);
    
    pthread_mutex_lock(&signal_mutex);
    
    if (sig == SIGPIPE) {
        // For SIGPIPE, log but don't terminate, let network layer handle the error
        log_message("WARN", "Broken pipe detected, connection may be closed");
	} else {
		// For termination signals, set shutdown flag
		g_shutdown_requested = 1;

		// Immediately clean up active connection
		pthread_mutex_lock(&active_conn_mutex);
		if (g_active_conn.sockfd != -1) {
			log_message("DEBUG", "Closing active connection due to signal");
			safe_close(&g_active_conn.sockfd, "signal_handler");
		}
		pthread_mutex_unlock(&active_conn_mutex);

		// Inform the user and exit quickly (allow atexit to flush retry metrics).
		const char msg[] = "\n[INFO] Terminated by user (Ctrl-C). Exiting...\n";
		/*
		 * Best-effort write in async-signal context: ignore return value
		 * to avoid side effects in the handler and silence warn_unused_result.
		 */
		(void)write(STDERR_FILENO, msg, sizeof(msg)-1);

		// Security event logging
		if (g_config.security_logging) {
			log_security_event(SEC_EVENT_CONNECTION_ATTACK, 
							  "Process termination requested by signal: %s", sig_name);
		}

		// Exit gracefully (triggering atexit, thereby flushing [RETRY-METRICS]).
		exit(130);
	}
    
    pthread_mutex_unlock(&signal_mutex);
}

static void cleanup_on_signal(void) {
    if (g_config.debug) {
        log_message("DEBUG", "Performing signal cleanup");
    }
    
    // Clean up active connection
    unregister_active_connection();
    
    // Clean up caches (already registered with atexit)
    // Additional cleanup can be added here if needed
	if (g_config.debug >= 2) {
		fprintf(stderr, "[DNS] negative cache: hits=%d, sets=%d, ttl=%d, disabled=%d\n",
			g_dns_neg_cache_hits, g_dns_neg_cache_sets, g_config.dns_neg_ttl, g_config.dns_neg_cache_disable);
	}
}

static void register_active_connection(const char* host, int port, int sockfd) {
    pthread_mutex_lock(&active_conn_mutex);
    
    // Clean up old connection record
    if (g_active_conn.host) {
        free(g_active_conn.host);
    }
    
    // Register new connection
    g_active_conn.host = host ? strdup(host) : NULL;
    g_active_conn.port = port;
    g_active_conn.sockfd = sockfd;
    g_active_conn.start_time = time(NULL);
    
    pthread_mutex_unlock(&active_conn_mutex);
}

static void unregister_active_connection(void) {
    pthread_mutex_lock(&active_conn_mutex);
    
    if (g_active_conn.host) {
        free(g_active_conn.host);
        g_active_conn.host = NULL;
    }
    if (g_active_conn.sockfd != -1) {
        safe_close(&g_active_conn.sockfd, "unregister_active_connection");
    }
    g_active_conn.port = 0;
    g_active_conn.start_time = 0;
    
    pthread_mutex_unlock(&active_conn_mutex);
}

static int should_terminate(void) {
    return g_shutdown_requested;
}

// Cache security functions
static int is_valid_domain_name(const char* domain) {
    if (!domain || *domain == '\0') return 0;
    
    size_t len = strlen(domain);
    if (len < 1 || len > 253) return 0;
    
    // Check for valid characters: alphanumeric, hyphen, dot
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)domain[i];
        if (!(isalnum(c) || c == '-' || c == '.')) {
            return 0;
        }
    }
    
    // Check for consecutive dots or leading/trailing dots
    if (domain[0] == '.' || domain[len-1] == '.' || strstr(domain, "..")) {
        return 0;
    }
    
    // Check each label length (between dots)
    const char* start = domain;
    const char* end = domain;
    while (*end) {
        if (*end == '.') {
            size_t label_len = end - start;
            if (label_len < 1 || label_len > 63) return 0;
            start = end + 1;
        }
        end++;
    }
    
    // Check last label
    size_t last_label_len = end - start;
    if (last_label_len < 1 || last_label_len > 63) return 0;
    
    return 1;
}

static int is_valid_ip_address(const char* ip) {
    if (!ip || *ip == '\0') return 0;
    
    struct in_addr addr4;
    struct in6_addr addr6;
    
    // Check IPv4
    if (inet_pton(AF_INET, ip, &addr4) == 1) {
        return 1;
    }
    
    // Check IPv6
    if (inet_pton(AF_INET6, ip, &addr6) == 1) {
        return 1;
    }
    
    return 0;
}

static int validate_dns_response(const char* ip) {
    if (!ip || *ip == '\0') return 0;
    
    // Check if it's a valid IP address
    if (!is_valid_ip_address(ip)) {
        return 0;
    }
    
    // Additional validation: check for private/reserved IPs
    if (is_private_ip(ip)) {
        log_message("WARN", "DNS response contains private IP: %s", ip);
        // Allow private IPs but log them
    }
    
    return 1;
}

static void cleanup_expired_cache_entries(void) {
    if (g_config.debug) {
        log_message("DEBUG", "Starting cache cleanup");
    }
    
    pthread_mutex_lock(&cache_mutex);
    
    time_t now = time(NULL);
    int dns_cleaned = 0;
    int conn_cleaned = 0;
    
    // Clean up expired DNS cache entries
	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
            if (dns_cache[i].domain && dns_cache[i].ip) {
                // Check if entry is expired
                if (now - dns_cache[i].timestamp >= g_config.cache_timeout) {
                    if (g_config.debug) {
                        log_message("DEBUG", "Removing expired DNS cache: %s -> %s", 
                                   dns_cache[i].domain, dns_cache[i].ip);
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
    
    // Clean up expired and dead connection cache entries
	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
            if (connection_cache[i].host) {
                // Check if entry is expired or connection is dead
                if (now - connection_cache[i].last_used >= g_config.cache_timeout || 
                    !is_connection_alive(connection_cache[i].sockfd)) {
                    if (g_config.debug) {
                        log_message("DEBUG", "Removing expired/dead connection: %s:%d", 
                                   connection_cache[i].host, connection_cache[i].port);
                    }
                    safe_close(&connection_cache[i].sockfd, "cleanup_expired_cache_entries");
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
        log_message("DEBUG", "Cache cleanup completed: %d DNS, %d connection entries removed", 
                   dns_cleaned, conn_cleaned);
    }
}

static void validate_cache_integrity(void) {
    if (!g_config.debug) {
        return; // Only run integrity checks in debug mode
    }
    
    pthread_mutex_lock(&cache_mutex);
    
    int dns_valid = 0;
    int dns_invalid = 0;
    int conn_valid = 0;
    int conn_invalid = 0;
    
    // Validate DNS cache integrity
	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
            if (dns_cache[i].domain && dns_cache[i].ip) {
                if (is_valid_domain_name(dns_cache[i].domain) && 
                    validate_dns_response(dns_cache[i].ip)) {
                    dns_valid++;
                } else {
                    dns_invalid++;
                    log_message("WARN", "Invalid DNS cache entry: %s -> %s", 
                               dns_cache[i].domain, dns_cache[i].ip);
                }
            }
        }
    }
    
    // Validate connection cache integrity
	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
            if (connection_cache[i].host) {
                if (is_valid_domain_name(connection_cache[i].host) && 
                    connection_cache[i].port > 0 && connection_cache[i].port <= 65535 &&
                    connection_cache[i].sockfd >= 0 && 
                    is_connection_alive(connection_cache[i].sockfd)) {
                    conn_valid++;
                } else {
                    conn_invalid++;
                    log_message("WARN", "Invalid connection cache entry: %s:%d (fd: %d)", 
                               connection_cache[i].host, connection_cache[i].port, 
                               connection_cache[i].sockfd);
                }
            }
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
    
    if (dns_invalid > 0 || conn_invalid > 0) {
        log_message("INFO", "Cache integrity check: %d/%d DNS valid, %d/%d connections valid", 
                   dns_valid, dns_valid + dns_invalid, conn_valid, conn_valid + conn_invalid);
    }
}

// Cache statistics and monitoring
static void log_cache_statistics(void) {
    if (!g_config.debug) {
        return;
    }
    
    pthread_mutex_lock(&cache_mutex);
    
    int dns_entries = 0;
    int conn_entries = 0;
    
    // Count DNS cache entries
	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
            if (dns_cache[i].domain && dns_cache[i].ip) {
                dns_entries++;
            }
        }
    }
    
    // Count connection cache entries
	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
            if (connection_cache[i].host) {
                conn_entries++;
            }
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
    
    log_message("DEBUG", "Cache statistics: %d/%zu DNS entries, %d/%zu connection entries", 
               dns_entries, g_config.dns_cache_size, 
               conn_entries, g_config.connection_cache_size);
}

// Enhanced cache initialization with security checks
void init_caches() {
    pthread_mutex_lock(&cache_mutex);

    // Validate cache sizes before allocation
    if (g_config.dns_cache_size == 0 || g_config.dns_cache_size > 100) {
        log_message("WARN", "DNS cache size %zu is unreasonable, using default", 
                   g_config.dns_cache_size);
        g_config.dns_cache_size = DNS_CACHE_SIZE;
    }
    
    if (g_config.connection_cache_size == 0 || g_config.connection_cache_size > 50) {
        log_message("WARN", "Connection cache size %zu is unreasonable, using default", 
                   g_config.connection_cache_size);
        g_config.connection_cache_size = CONNECTION_CACHE_SIZE;
    }

    // Allocate DNS cache
	dns_cache = wc_safe_malloc(g_config.dns_cache_size * sizeof(DNSCacheEntry), "init_caches");
    memset(dns_cache, 0, g_config.dns_cache_size * sizeof(DNSCacheEntry));
    allocated_dns_cache_size = g_config.dns_cache_size;
    if (g_config.debug)
        printf("[DEBUG] DNS cache allocated for %zu entries\n",
               g_config.dns_cache_size);

    // Allocate connection cache
	connection_cache = wc_safe_malloc(g_config.connection_cache_size * sizeof(ConnectionCacheEntry), "init_caches");
    memset(connection_cache, 0,
           g_config.connection_cache_size * sizeof(ConnectionCacheEntry));
	for (size_t i = 0; i < g_config.connection_cache_size; i++) {
        connection_cache[i].sockfd = -1;
    }
    allocated_connection_cache_size = g_config.connection_cache_size;
    if (g_config.debug)
        printf("[DEBUG] Connection cache allocated for %zu entries\n",
               g_config.connection_cache_size);

    pthread_mutex_unlock(&cache_mutex);
    
    // Log initial cache statistics
    log_cache_statistics();
}

static void free_fold_resources() {
	if (g_config.fold_sep) { free(g_config.fold_sep); g_config.fold_sep = NULL; }
}

// Enhanced file descriptor safety functions
static void safe_close(int* fd, const char* function_name) {
    if (fd && *fd != -1) {
        if (close(*fd) == -1) {
            // Don't warn about EBADF (bad file descriptor) as it's already closed
            if (errno != EBADF) {
                if (g_config.debug) {
                    log_message("WARN", "%s: Failed to close fd %d: %s", 
                               function_name, *fd, strerror(errno));
                }
            }
        } else {
            if (g_config.debug) {
                log_message("DEBUG", "%s: Closed fd %d", function_name, *fd);
            }
        }
        *fd = -1;
    }
}

static int is_socket_alive(int sockfd) {
    if (sockfd == -1) return 0;
    
    int error = 0;
    socklen_t len = sizeof(error);
    
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        return error == 0;
    }
    
    // If we can't get socket option, assume it's not alive
    return 0;
}

// Server status tracking functions
static int is_server_backed_off(const char* host) {
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
                if (g_config.debug) {
                    log_message("DEBUG", "Server %s is backed off (failures: %d, last: %lds ago)", 
                               host, server_status[i].failure_count, now - server_status[i].last_failure);
                }
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&server_status_mutex);
    return backed_off;
}

static void mark_server_failure(const char* host) {
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
            if (g_config.debug) {
                log_message("DEBUG", "Marked server %s failure (count: %d)", 
                           host, server_status[i].failure_count);
            }
            break;
        } else if (!server_status[i].host && empty_slot == -1) {
            empty_slot = i;
        }
    }
    
    // Create new entry if not found
    if (!found && empty_slot != -1) {
        server_status[empty_slot].host = strdup(host);
        server_status[empty_slot].failure_count = 1;
        server_status[empty_slot].last_failure = now;
        if (g_config.debug) {
            log_message("DEBUG", "Created failure record for server %s", host);
        }
    }
    
    pthread_mutex_unlock(&server_status_mutex);
}

static void mark_server_success(const char* host) {
    if (!host || !*host) return;
    
    pthread_mutex_lock(&server_status_mutex);
    
    for (int i = 0; i < MAX_SERVER_STATUS; i++) {
        if (server_status[i].host && strcmp(server_status[i].host, host) == 0) {
            // Reset failure count on success
            if (server_status[i].failure_count > 0) {
                if (g_config.debug) {
                    log_message("DEBUG", "Reset failure count for server %s (was: %d)", 
                               host, server_status[i].failure_count);
                }
                server_status[i].failure_count = 0;
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&server_status_mutex);
}

// Response data validation functions
static int validate_response_data(const char* data, size_t len) {
    if (!data || len == 0) {
        log_message("WARN", "Response data is NULL or empty");
        return 0;
    }
    
    // Check for null bytes and binary data
    int line_length = 0;
    int max_line_length = 1024; // Reasonable limit for WHOIS responses
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        
        // Check for null byte
        if (c == 0) {
            log_message("WARN", "Response contains null byte at position %zu", i);
            return 0;
        }
        
        // Check for invalid control characters (allow \n, \r, \t)
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
            log_message("WARN", "Response contains invalid control character 0x%02x at position %zu", c, i);
            return 0;
        }
        
        // Check line length to prevent terminal issues
        if (c == '\n') {
            line_length = 0;
        } else {
            line_length++;
            if (line_length > max_line_length) {
                log_message("WARN", "Response line too long (%d characters), possible data corruption", line_length);
                return 0;
            }
        }
    }
    
    return 1;
}

// Security logging functions

// monitor_connection_security is implemented in src/out/seclog.c

#ifdef WHOIS_SECLOG_TEST
// Optional self-test hook for security log rate limiting
// Activation: build with -DWHOIS_SECLOG_TEST; enable via wc_selftest_set_seclog_test(1)
static void maybe_run_seclog_self_test(void) {
	if (!wc_selftest_seclog_test_enabled()) return;
	int prev = g_config.security_logging;
	wc_seclog_set_enabled(1); // ensure logging is on for the test

	// Emit a burst to trigger limiter; 200 events should exceed any sane cap
	for (int i = 0; i < 200; i++) {
		log_security_event(SEC_EVENT_CONNECTION_ATTACK, "SECTEST event #%d", i);
	}
	// Optionally add another small burst to cross window boundary if execution spans seconds
	for (int i = 0; i < 10; i++) {
		log_security_event(SEC_EVENT_RESPONSE_TAMPERING, "SECTEST extra #%d", i);
	}

	wc_seclog_set_enabled(prev);
}
#endif

// ============================================================================
// 7. Utility function implementations
// ============================================================================

#ifdef WHOIS_GREP_TEST
static void print_greptest_output(const char* title, const char* s);
// Optional self-test for wc_grep filtering behaviors
// Activation: compile with -DWHOIS_GREP_TEST; enable via wc_selftest_set_grep_test(1)
static void maybe_run_grep_self_test(void) {
	if (!wc_selftest_grep_test_enabled()) return;


	const char* sample =
		"OrgName: Google LLC\n"
		" Address: Mountain View\n"
		"\n"
		"Abuse-Contact: abuse@google.com\n"
		" Foo: bar\n";

	// Case-insensitive, block mode: expect header+continuation for OrgName, and Abuse-Contact block
	wc_grep_set_enabled(1);
	if (wc_grep_compile("orgname|abuse-contact", 0) > 0) {
		wc_grep_set_line_mode(0);
		wc_grep_set_keep_continuation(0);
		char* out = wc_grep_filter(sample);
		if (out) {
			int ok = 1;
			if (strstr(out, "OrgName:") == NULL) ok = 0;
			if (strstr(out, " Address:") == NULL) ok = 0; // continuation kept in block mode
			if (strstr(out, "Abuse-Contact:") == NULL) ok = 0;
			if (strstr(out, " Foo:") != NULL) ok = 0; // unrelated line must be filtered
			fprintf(stderr, ok ? "[GREPTEST] block mode: PASS\n" : "[GREPTEST] block mode: FAIL\n");
			if (!ok) {
				print_greptest_output("block mode output", out);
			}
			free(out);
		}
	}

	// Line mode without keep-continuation: only header lines, no continuation
	wc_grep_set_line_mode(1);
	wc_grep_set_keep_continuation(0);
	{
		char* out = wc_grep_filter(sample);
		if (out) {
			int ok = 1;
			if (strstr(out, "OrgName:") == NULL) ok = 0;
			if (strstr(out, " Address:") != NULL) ok = 0; // no continuation
			if (strstr(out, "Abuse-Contact:") == NULL) ok = 0;
			fprintf(stderr, ok ? "[GREPTEST] line mode (no-cont): PASS\n" : "[GREPTEST] line mode (no-cont): FAIL\n");
			if (!ok) {
				print_greptest_output("line mode (no-cont) output", out);
			}
			free(out);
		}
	}

	// Line mode with keep-continuation: include header + continuation as a block
	wc_grep_set_keep_continuation(1);
	{
		char* out = wc_grep_filter(sample);
		if (out) {
			int ok = 1;
			if (strstr(out, "OrgName:") == NULL) ok = 0;
			if (strstr(out, " Address:") == NULL) ok = 0; // continuation included
			if (strstr(out, "Abuse-Contact:") == NULL) ok = 0;
			fprintf(stderr, ok ? "[GREPTEST] line mode (keep-cont): PASS\n" : "[GREPTEST] line mode (keep-cont): FAIL\n");
			if (!ok) {
				print_greptest_output("line mode (keep-cont) output", out);
			}
			free(out);
		}
	}

	wc_grep_free();
}
static void print_greptest_output(const char* title, const char* s) {
	if (!s) return;
	fprintf(stderr, "[GREPTEST] %s\n", title);
	const char* p = s; const char* q = s;
	while (*q) {
		while (*q && *q != '\n') q++;
		if (q > p) fprintf(stderr, "[GREPTEST-OUT] %.*s\n", (int)(q - p), p);
		if (*q == '\n') { q++; p = q; }
	}
}
#endif

size_t parse_size_with_unit(const char* str) {
	if (str == NULL || *str == '\0') {
		return 0;
	}

	// Skip leading whitespace
	while (isspace(*str)) str++;

	if (*str == '\0') {
		return 0;
	}

	char* end;
	errno = 0;
	unsigned long long size = strtoull(str, &end, 10);
	// Check for conversion errors
	if (errno == ERANGE) {
		return SIZE_MAX;
	}

	if (end == str) {
		return 0;  // Invalid number
	}

	// Skip whitespace after number
	while (isspace(*end)) end++;

	// Process units
	if (*end) {
		char unit = toupper(*end);
		switch (unit) {
			case 'K':
				if (size > SIZE_MAX / 1024) return SIZE_MAX;
				size *= 1024;
				end++;
				break;
			case 'M':
				if (size > SIZE_MAX / (1024 * 1024)) return SIZE_MAX;
				size *= 1024 * 1024;
				end++;
				break;
			case 'G':
				if (size > SIZE_MAX / (1024 * 1024 * 1024)) return SIZE_MAX;
				size *= 1024 * 1024 * 1024;
				end++;
				break;
			default:
				// Invalid unit, but may just be a number
				if (g_config.debug) {
					printf(
						"[DEBUG] Unknown unit '%c' in size specification, "
						"ignoring\n",
						unit);
				}
				break;
		}

		// Check for extra characters (like "B" in "10MB")
		if (*end && !isspace(*end)) {
			if (g_config.debug) {
				printf("[DEBUG] Extra characters after unit: '%s'\n", end);
			}
		}
	}

	// Check if it exceeds size_t maximum value
	if (size > SIZE_MAX) {
		return SIZE_MAX;
	}

	if (g_config.debug) {
		printf("[DEBUG] Parsed size: '%s' -> %llu bytes\n", str, size);
	}

	return (size_t)size;
}

/* help/version 已迁移到 wc_meta 模块 */

void print_servers() {
	printf("Available whois servers:\n\n");
	for (int i = 0; servers[i].name != NULL; i++) {
		printf("  %-12s - %s\n", servers[i].name, servers[i].description);
		printf("            Domain: %s\n\n", servers[i].domain);
	}
}

int validate_global_config() {
	if (g_config.whois_port <= 0 || g_config.whois_port > 65535) {
		fprintf(stderr, "Error: Invalid port number in config\n");
		return 0;
	}
	if (g_config.buffer_size ==
		0) {  // Changed to check 0, as size_t is unsigned
		fprintf(stderr, "Error: Invalid buffer size in config\n");
		return 0;
	}
	if (g_config.max_retries < 0) {
		fprintf(stderr, "Error: Invalid retry count in config\n");
		return 0;
	}
	if (g_config.timeout_sec <= 0) {
		fprintf(stderr, "Error: Invalid timeout value in config\n");
		return 0;
	}
	if (g_config.dns_cache_size == 0) {  // Changed to check 0
		fprintf(stderr, "Error: Invalid DNS cache size in config\n");
		return 0;
	}
	if (g_config.connection_cache_size == 0) {  // Changed to check 0
		fprintf(stderr, "Error: Invalid connection cache size in config\n");
		return 0;
	}
	if (g_config.cache_timeout <= 0) {
		fprintf(stderr, "Error: Invalid cache timeout in config\n");
		return 0;
	}
	if (g_config.max_redirects < 0) {
		fprintf(stderr, "Error: Invalid max redirects in config\n");
		return 0;
	}
	if (g_config.retry_interval_ms < 0) {
		fprintf(stderr, "Error: Invalid retry interval in config\n");
		return 0;
	}
	if (g_config.retry_jitter_ms < 0) {
		fprintf(stderr, "Error: Invalid retry jitter in config\n");
		return 0;
	}
	return 1;
}

int is_private_ip(const char* ip) {
	struct in_addr addr4;
	struct in6_addr addr6;

	// Check IPv4 private addresses
	if (inet_pton(AF_INET, ip, &addr4) == 1) {
		unsigned long ip_addr = ntohl(addr4.s_addr);
		return ((ip_addr >= 0x0A000000 && ip_addr <= 0x0AFFFFFF) ||  // 10.0.0.0/8
				(ip_addr >= 0xAC100000 && ip_addr <= 0xAC1FFFFF) ||  // 172.16.0.0/12
				(ip_addr >= 0xC0A80000 && ip_addr <= 0xC0A8FFFF));  // 192.168.0.0/16
	}

	// Check IPv6 private addresses
	if (inet_pton(AF_INET6, ip, &addr6) == 1) {
		// Unique Local Address (ULA): fc00::/7
		if ((addr6.s6_addr[0] & 0xFE) == 0xFC) {
			return 1;
		}
		// Link-local address: fe80::/10
		if (addr6.s6_addr[0] == 0xFE && (addr6.s6_addr[1] & 0xC0) == 0x80) {
			return 1;
		}
		// Documentation addresses (2001:db8::/32)
		if (strncmp(ip, "2001:db8:", 9) == 0) {
			return 1;
		}
		// Loopback address (::1)
		if (strcmp(ip, "::1") == 0) {
			return 1;
		}
	}

	return 0;
}

void cleanup_caches() {
	pthread_mutex_lock(&cache_mutex);

	// Clean up DNS cache
	if (dns_cache) {
		for (size_t i = 0; i < allocated_dns_cache_size; i++) {
			if (dns_cache[i].domain) {
				free(dns_cache[i].domain);
				dns_cache[i].domain = NULL;
			}
			if (dns_cache[i].ip) {
				free(dns_cache[i].ip);
				dns_cache[i].ip = NULL;
			}
		}
		free(dns_cache);
		dns_cache = NULL;
		allocated_dns_cache_size = 0;
	}

	// Clean up connection cache
	if (connection_cache) {
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
			if (connection_cache[i].host) {
				free(connection_cache[i].host);
				connection_cache[i].host = NULL;
			}
			if (connection_cache[i].sockfd != -1) {
				safe_close(&connection_cache[i].sockfd, "cleanup_caches");
			}
		}
		free(connection_cache);
		connection_cache = NULL;
		allocated_connection_cache_size = 0;
	}

	pthread_mutex_unlock(&cache_mutex);
	
	// Clean up server status cache
	pthread_mutex_lock(&server_status_mutex);
	for (int i = 0; i < MAX_SERVER_STATUS; i++) {
		if (server_status[i].host) {
			free(server_status[i].host);
			server_status[i].host = NULL;
			server_status[i].failure_count = 0;
			server_status[i].last_failure = 0;
		}
	}
	pthread_mutex_unlock(&server_status_mutex);
}

size_t get_free_memory() {  // Changed to return size_t
	FILE* meminfo = fopen("/proc/meminfo", "r");
	if (!meminfo) return 0;

	char line[256];
	size_t free_mem = 0;

	while (fgets(line, sizeof(line), meminfo)) {
		if (strncmp(line, "MemFree:", 8) == 0) {
			sscanf(line + 8, "%zu", &free_mem);
			break;
		}
	}

	fclose(meminfo);
	return free_mem;
}

void report_memory_error(const char* function, size_t size) {
	fprintf(stderr, "Error: Memory allocation failed in %s for %zu bytes\n",
			function, size);
	fprintf(stderr, "       Reason: %s\n", strerror(errno));

	// If in debug mode, provide more information
	if (g_config.debug) {
		fprintf(stderr,
				"       Available memory might be limited on this system\n");
	}
}

void log_message(const char* level, const char* format, ...) {
	// Always show ERROR/WARN level regardless of debug switch,
	// otherwise only print when debug is enabled.
	int always = 0;
	if (level) {
		if (strcmp(level, "ERROR") == 0 || strcmp(level, "WARN") == 0 ||
			strcmp(level, "WARNING") == 0) {
			always = 1;
		}
	}

	if (!g_config.debug && !always) return;

	va_list args;
	va_start(args, format);

	// Add full timestamp with year-month-day to the log
	time_t now = time(NULL);
	struct tm* t = localtime(&now);
	fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ", 
			t ? t->tm_year + 1900 : 0, t ? t->tm_mon + 1 : 0, t ? t->tm_mday : 0,
			t ? t->tm_hour : 0, t ? t->tm_min : 0, t ? t->tm_sec : 0, level ? level : "LOG");

	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
}

int validate_cache_sizes() {
	size_t free_mem = get_free_memory();
	if (free_mem == 0) {
		return 1;  // Unable to get memory info, assume valid
	}

	// Calculate required memory, add 10% safety margin
	size_t required_mem =
		(g_config.dns_cache_size * sizeof(DNSCacheEntry)) +
		(g_config.connection_cache_size * sizeof(ConnectionCacheEntry));
	required_mem = required_mem * 110 / 100;  // Add 10% safety margin

	if (required_mem > free_mem * 1024) {  // free_mem is in KB
		fprintf(stderr,
				"Warning: Requested cache size (%zu bytes) exceeds available "
				"memory (%zu KB)\n",
				required_mem, free_mem);
		return 0;
	}

	return 1;
}

// ============================================================================
// 8. Cache management function implementations
// ============================================================================

const char* get_known_ip(const char* domain) {
	// Enhanced input validation
	if (!domain) {
		log_message("ERROR", "get_known_ip: Domain parameter is NULL");
		return NULL;
	}
	
	if (strlen(domain) == 0) {
		log_message("ERROR", "get_known_ip: Domain parameter is empty");
		return NULL;
	}

	// Detailed domain format validation
	int valid_chars = 1;
	int dot_count = 0;
	size_t len = strlen(domain);
	
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)domain[i];
		if (!(isalnum(c) || c == '.' || c == '-')) {
			valid_chars = 0;
			log_message("WARN", "get_known_ip: Domain '%s' contains invalid character '%c' at position %zu", 
					   domain, c, i);
			break;
		}
		if (c == '.') dot_count++;
	}

	// Domain structure validation
	if (!valid_chars) {
		log_message("ERROR", "get_known_ip: Domain '%s' contains illegal characters", domain);
		return NULL;
	}

	if (domain[0] == '.' || domain[0] == '-') {
		log_message("ERROR", "get_known_ip: Domain '%s' starts with illegal character", domain);
		return NULL;
	}

	if (domain[len - 1] == '.' || domain[len - 1] == '-') {
		log_message("ERROR", "get_known_ip: Domain '%s' ends with illegal character", domain);
		return NULL;
	}

	if (strstr(domain, "..")) {
		log_message("ERROR", "get_known_ip: Domain '%s' contains consecutive dots", domain);
		return NULL;
	}

	if (dot_count == 0) {
		log_message("WARN", "get_known_ip: Domain '%s' has no dots, may not be a fully qualified domain", domain);
	}

	// Updated IP address mapping (as final fallback)
	const char* known_ip = NULL;
	if (strcmp(domain, "whois.apnic.net") == 0) {
		known_ip = "203.119.102.14";  // Updated APNIC IP
	} else if (strcmp(domain, "whois.ripe.net") == 0) {
		known_ip = "193.0.6.135";     // RIPE unchanged
	} else if (strcmp(domain, "whois.arin.net") == 0) {
		known_ip = "199.71.0.46";     // Updated ARIN IP
	} else if (strcmp(domain, "whois.lacnic.net") == 0) {
		known_ip = "200.3.14.10";     // LACNIC unchanged
	} else if (strcmp(domain, "whois.afrinic.net") == 0) {
		known_ip = "196.216.2.6";     // AFRINIC unchanged
	} else if (strcmp(domain, "whois.iana.org") == 0) {
		known_ip = "192.0.43.8";      // Updated IANA IP
	}

	if (known_ip) {
		if (g_config.debug) {
			log_message("DEBUG", "get_known_ip: Found known IP %s for domain %s (fallback mode)", 
					   known_ip, domain);
		}
		return known_ip;
	} else {
		log_message("WARN", "get_known_ip: No known IP mapping for domain '%s'", domain);
		return NULL;
	}
}

char* get_cached_dns(const char* domain) {
	// Enhanced input validation
	if (!is_valid_domain_name(domain)) {
		log_message("WARN", "Invalid domain name for DNS cache lookup: %s", domain);
		return NULL;
	}

	pthread_mutex_lock(&cache_mutex);

	if (dns_cache == NULL) {
		pthread_mutex_unlock(&cache_mutex);
		return NULL;
	}

	time_t now = time(NULL);
	for (size_t i = 0; i < allocated_dns_cache_size; i++) {
		if (dns_cache[i].domain && strcmp(dns_cache[i].domain, domain) == 0) {
			if (dns_cache[i].negative) {
				// Negative entry: use shorter TTL
				if (now - dns_cache[i].timestamp < g_config.dns_neg_ttl) {
					pthread_mutex_unlock(&cache_mutex);
					return NULL; // negative cached (fast-fail)
				} else {
					// expire negative entry
					free(dns_cache[i].domain);
					free(dns_cache[i].ip);
					dns_cache[i].domain = NULL;
					dns_cache[i].ip = NULL;
					continue;
				}
			}
			if (now - dns_cache[i].timestamp < g_config.cache_timeout) {
				// Validate cached IP before returning
				if (!validate_dns_response(dns_cache[i].ip)) {
					log_message("WARN", "Invalid cached IP found for %s: %s", domain, dns_cache[i].ip);
					// Remove invalid cache entry
					free(dns_cache[i].domain);
					free(dns_cache[i].ip);
					dns_cache[i].domain = NULL;
					dns_cache[i].ip = NULL;
					pthread_mutex_unlock(&cache_mutex);
					return NULL;
				}
				
				char* result = strdup(dns_cache[i].ip);
				pthread_mutex_unlock(&cache_mutex);
				return result;
			} else {
				// Cache entry expired, clean it up
				free(dns_cache[i].domain);
				free(dns_cache[i].ip);
				dns_cache[i].domain = NULL;
				dns_cache[i].ip = NULL;
			}
		}
	}

	pthread_mutex_unlock(&cache_mutex);
	return NULL;
}

void set_cached_dns(const char* domain, const char* ip) {
	// Enhanced input validation
	if (!is_valid_domain_name(domain)) {
		log_message("WARN", "Attempted to cache invalid domain: %s", domain);
		return;
	}
	
	if (!validate_dns_response(ip)) {
		log_message("WARN", "Attempted to cache invalid IP: %s for domain %s", ip, domain);
		return;
	}

	pthread_mutex_lock(&cache_mutex);

	if (dns_cache == NULL) {
		pthread_mutex_unlock(&cache_mutex);
		return;
	}

	// Look for an existing entry or the oldest cache item
	int oldest_index = 0;
	time_t oldest_time = time(NULL);

	for (size_t i = 0; i < allocated_dns_cache_size; i++) {
		if (dns_cache[i].domain && strcmp(dns_cache[i].domain, domain) == 0) {
			// Update existing entry (reset negative flag if previously negative)
			dns_cache[i].negative = 0;
			free(dns_cache[i].ip);  // Free the old IP address
			dns_cache[i].ip = strdup(ip);
			dns_cache[i].timestamp = time(NULL);
			pthread_mutex_unlock(&cache_mutex);
			return;
		}

		// Track the oldest entry for replacement if needed
		if (dns_cache[i].timestamp < oldest_time) {
			oldest_time = dns_cache[i].timestamp;
			oldest_index = i;
		}
	}

	// If no existing entry, replace the oldest entry
	free(dns_cache[oldest_index].domain);
	free(dns_cache[oldest_index].ip);
	dns_cache[oldest_index].domain = strdup(domain);
	dns_cache[oldest_index].ip = strdup(ip);
	dns_cache[oldest_index].timestamp = time(NULL);
	dns_cache[oldest_index].negative = 0;

	// done
	pthread_mutex_unlock(&cache_mutex);
	if (g_config.debug) {
		log_message("DEBUG", "Cached DNS: %s -> %s", domain, ip);
	}
}

int is_negative_dns_cached(const char* domain) {
	if (g_config.dns_neg_cache_disable) return 0;
	if (!domain) return 0;
	pthread_mutex_lock(&cache_mutex);
	if (!dns_cache) { pthread_mutex_unlock(&cache_mutex); return 0; }
	time_t now = time(NULL);
	for (size_t i=0;i<allocated_dns_cache_size;i++) {
		if (dns_cache[i].domain && dns_cache[i].negative && strcmp(dns_cache[i].domain, domain)==0) {
			if (now - dns_cache[i].timestamp < g_config.dns_neg_ttl) {
				pthread_mutex_unlock(&cache_mutex);
				g_dns_neg_cache_hits++;
				return 1; // negative cached hit
			} else {
				// expire
				free(dns_cache[i].domain); free(dns_cache[i].ip);
				dns_cache[i].domain=NULL; dns_cache[i].ip=NULL; dns_cache[i].negative=0;
			}
		}
	}
	pthread_mutex_unlock(&cache_mutex);
	return 0;
}

void set_negative_dns(const char* domain) {
	if (g_config.dns_neg_cache_disable) return;
	if (!domain) return;
	pthread_mutex_lock(&cache_mutex);
	if (!dns_cache) { pthread_mutex_unlock(&cache_mutex); return; }
	int oldest_index = 0; time_t oldest_time = time(NULL);
	for (size_t i=0;i<allocated_dns_cache_size;i++) {
		if (dns_cache[i].domain && strcmp(dns_cache[i].domain, domain)==0) {
			// replace existing entry with negative marker
			free(dns_cache[i].ip); dns_cache[i].ip=NULL; dns_cache[i].timestamp=time(NULL); dns_cache[i].negative=1;
			pthread_mutex_unlock(&cache_mutex); return;
		}
		if (dns_cache[i].timestamp < oldest_time) { oldest_time = dns_cache[i].timestamp; oldest_index = i; }
	}
	free(dns_cache[oldest_index].domain); free(dns_cache[oldest_index].ip);
	dns_cache[oldest_index].domain = strdup(domain); dns_cache[oldest_index].ip=NULL; dns_cache[oldest_index].timestamp=time(NULL); dns_cache[oldest_index].negative=1;
	pthread_mutex_unlock(&cache_mutex);
	g_dns_neg_cache_sets++;
}

int is_connection_alive(int sockfd) {
	return is_socket_alive(sockfd);
}

int get_cached_connection(const char* host, int port) {
	pthread_mutex_lock(&cache_mutex);

	if (connection_cache == NULL) {
		pthread_mutex_unlock(&cache_mutex);
		return -1;
	}

	time_t now = time(NULL);
	for (size_t i = 0; i < allocated_connection_cache_size; i++) {
		if (connection_cache[i].host &&
			strcmp(connection_cache[i].host, host) == 0 &&
			connection_cache[i].port == port) {
			if (now - connection_cache[i].last_used < g_config.cache_timeout) {
				// Check if connection is still valid
				if (is_connection_alive(connection_cache[i].sockfd)) {
					connection_cache[i].last_used = now;
					int sockfd = connection_cache[i].sockfd;
					pthread_mutex_unlock(&cache_mutex);
					return sockfd;
				} else {
					// Connection is invalid, close and clean up
					safe_close(&connection_cache[i].sockfd, "get_cached_connection");
					free(connection_cache[i].host);
					connection_cache[i].host = NULL;
				}
			} else {
				// Connection expired, close and clean up
				safe_close(&connection_cache[i].sockfd, "get_cached_connection");
				free(connection_cache[i].host);
				connection_cache[i].host = NULL;
			}
		}
	}

	pthread_mutex_unlock(&cache_mutex);
	return -1;
}

void set_cached_connection(const char* host, int port, int sockfd) {
	// Enhanced input validation
	if (!host || !*host) {
		log_message("WARN", "Attempted to cache connection with invalid host");
		return;
	}
	
	if (port <= 0 || port > 65535) {
		log_message("WARN", "Attempted to cache connection with invalid port: %d", port);
		return;
	}
	
	if (sockfd < 0) {
		log_message("WARN", "Attempted to cache invalid socket descriptor: %d", sockfd);
		return;
	}
	
	// Validate that the socket is still alive before caching
	if (!is_connection_alive(sockfd)) {
		log_message("WARN", "Attempted to cache dead connection to %s:%d", host, port);
		safe_close(&sockfd, "set_cached_connection");
		return;
	}

	pthread_mutex_lock(&cache_mutex);

	// Find empty slot or oldest connection
	int oldest_index = 0;
	time_t oldest_time = time(NULL);

	for (size_t i = 0; i < allocated_connection_cache_size; i++) {
		if (connection_cache[i].host == NULL) {
			// Found empty slot
			connection_cache[i].host = strdup(host);
			connection_cache[i].port = port;
			connection_cache[i].sockfd = sockfd;
			connection_cache[i].last_used = time(NULL);
			
			if (g_config.debug) {
				log_message("DEBUG", "Cached connection to %s:%d (slot %d)", host, port, (int)i);
			}
			
			pthread_mutex_unlock(&cache_mutex);
			return;
		}

		if (connection_cache[i].last_used < oldest_time) {
			oldest_time = connection_cache[i].last_used;
			oldest_index = i;
		}
	}

	// Replace the oldest connection
	if (g_config.debug) {
		log_message("DEBUG", "Replacing oldest connection (slot %d) with %s:%d", 
			   oldest_index, host, port);
	}
	
	safe_close(&connection_cache[oldest_index].sockfd, "set_cached_connection");
	free(connection_cache[oldest_index].host);
	connection_cache[oldest_index].host = strdup(host);
	connection_cache[oldest_index].port = port;
	connection_cache[oldest_index].sockfd = sockfd;
	connection_cache[oldest_index].last_used = time(NULL);

	pthread_mutex_unlock(&cache_mutex);
}

// ============================================================================
// 9. Find an empty slot
// ============================================================================

char* resolve_domain(const char* domain) {
	if (g_config.debug) printf("[DEBUG] Resolving domain: %s\n", domain);

	// First check positive cache then negative cache
	char* cached_ip = get_cached_dns(domain);
	if (cached_ip) {
		if (g_config.debug)
			printf("[DEBUG] Using cached DNS: %s -> %s\n", domain, cached_ip);
		return cached_ip;
	}
	if (is_negative_dns_cached(domain)) {
		if (g_config.debug) printf("[DEBUG] Negative DNS cache hit for %s (fast-fail)\n", domain);
		return NULL;
	}

	// Selftest: special domain triggers negative cache set once to simulate scenario
	{
		static int injected_once = 0;
		if (wc_selftest_dns_negative_enabled() && !injected_once) {
			if (domain && strcmp(domain, "selftest.invalid") == 0) {
				// Only early-return when negative cache is enabled; otherwise continue normal resolution
				if (!g_config.dns_neg_cache_disable) {
					set_negative_dns(domain);
					injected_once = 1;
					return NULL;
				}
			}
		}
	}

	struct addrinfo hints, *res = NULL, *p;
	int status;
	char* ip = NULL;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;  // Support both IPv4 and IPv6
	hints.ai_socktype = SOCK_STREAM;

	status = getaddrinfo(domain, NULL, &hints, &res);
	if (status != 0) {
		log_message("ERROR", "Failed to resolve domain %s: %s", domain, gai_strerror(status));
		if (status == EAI_NONAME || status == EAI_FAIL) set_negative_dns(domain);
		return NULL;
	}

	// Try all addresses and pick the first one
	for (p = res; p != NULL; p = p->ai_next) {
		void* addr;
		char ipstr[INET6_ADDRSTRLEN];

		if (p->ai_family == AF_INET) {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
			addr = &(ipv4->sin_addr);
		} else if (p->ai_family == AF_INET6) {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
			addr = &(ipv6->sin6_addr);
		} else {
			continue;  // Skip unsupported address families
		}

		inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
		ip = strdup(ipstr);  // Keep raw literal; do NOT wrap IPv6 with []

		if (ip == NULL) {
			log_message("ERROR", "Memory allocation failed for IP address");
			continue;
		}
		// We only resolve and return the textual address here;
		// connectivity will be handled by connect_to_server().
		break;
	}

	freeaddrinfo(res);

	// Store result in cache
	if (ip) {
		set_cached_dns(domain, ip);
		if (g_config.debug)
			printf("[DEBUG] Resolved %s to %s (cached)\n", domain, ip);
	} else {
		set_negative_dns(domain); // store negative result
	}

	return ip;
}

int connect_to_server(const char* host, int port, int* sockfd) {
	// Check if we should terminate due to signal
	if (should_terminate()) {
		return -1;
	}

	log_message("DEBUG", "Attempting to connect to %s:%d", host, port);

	// Security: monitor connection attempts (don't log start, only result)
	// We'll log the result after we know if it succeeded or failed

	// First check connection cache
	int cached_sockfd = get_cached_connection(host, port);
	if (cached_sockfd != -1) {
		// Check if connection is still valid using SO_ERROR
		if (is_connection_alive(cached_sockfd)) {
			*sockfd = cached_sockfd;
			log_message("DEBUG", "Using cached connection to %s:%d", host, port);
			// Security: log successful cached connection
			monitor_connection_security(host, port, 0);
			return 0;
		}
		// Connection is invalid, remove from cache
		// Note: cached_sockfd is a copy, not a reference to the cache entry
		safe_close(&cached_sockfd, "connect_to_server"); // Use safe_close for local copy
		pthread_mutex_lock(&cache_mutex);
		for (size_t i = 0; i < allocated_connection_cache_size; i++) {
			if (connection_cache[i].sockfd == cached_sockfd) {
				free(connection_cache[i].host);
				connection_cache[i].host = NULL;
				connection_cache[i].sockfd = -1;
				break;
			}
		}
		pthread_mutex_unlock(&cache_mutex);
	}

	// Cache miss or connection invalid, create new connection
	struct addrinfo hints, *res, *p;
	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%d", port);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int status = getaddrinfo(host, port_str, &hints, &res);
	if (status != 0) {
		log_message("ERROR", "getaddrinfo failed for %s:%s - %s", host, port_str, gai_strerror(status));
		return -1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		*sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (*sockfd == -1) {
			if (g_config.debug) log_message("ERROR", "Socket creation failed: %s", strerror(errno));
			continue;
		}

		// Set non-blocking for connect timeout handling
		int flags = fcntl(*sockfd, F_GETFL, 0);
		if (flags < 0) flags = 0;
		if (fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK) == -1) { 
			safe_close(sockfd, "connect_to_server"); 
			continue; 
		}

		int ret = connect(*sockfd, p->ai_addr, p->ai_addrlen);
		if (ret == 0) {
			// Connected immediately
			fcntl(*sockfd, F_SETFL, flags);
			struct timeval timeout_io = {g_config.timeout_sec, 0};
			setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout_io, sizeof(timeout_io));
			setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout_io, sizeof(timeout_io));
			log_message("DEBUG", "Successfully connected to %s:%d", host, port);
			// Security: log successful connection
			monitor_connection_security(host, port, 0);
			set_cached_connection(host, port, *sockfd);
			freeaddrinfo(res);
			return 0;
		} else if (ret < 0 && errno == EINPROGRESS) {
			// Wait for writability within timeout
			fd_set wfds; FD_ZERO(&wfds); FD_SET(*sockfd, &wfds);
			struct timeval tv; tv.tv_sec = g_config.timeout_sec; tv.tv_usec = 0;
			int sel = select(*sockfd + 1, NULL, &wfds, NULL, &tv);
			if (sel > 0) {
				int soerr = 0; socklen_t slen = sizeof(soerr);
				if (getsockopt(*sockfd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0) {
					fcntl(*sockfd, F_SETFL, flags);
					struct timeval timeout_io = {g_config.timeout_sec, 0};
					setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout_io, sizeof(timeout_io));
					setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout_io, sizeof(timeout_io));
					log_message("DEBUG", "Successfully connected (non-blocking) to %s:%d", host, port);
					set_cached_connection(host, port, *sockfd);
					freeaddrinfo(res);
					return 0;
				} else {
					log_message("ERROR", "Connect error after select to %s:%d - %s", host, port, strerror(soerr));
				}
			} else if (sel == 0) {
				log_message("ERROR", "Connect timeout to %s:%d after %d sec", host, port, g_config.timeout_sec);
			} else {
				if (g_config.debug) log_message("ERROR", "Select error during connect to %s:%d - %s", host, port, strerror(errno));
			}
		} else {
			if (g_config.debug) log_message("ERROR", "Connection failed to %s:%d - %s", host, port, strerror(errno));
		}

		safe_close(sockfd, "connect_to_server");
	}

	freeaddrinfo(res);
	return -1;
}

int connect_with_fallback(const char* domain, int port, int* sockfd) {
	// First try direct connection to domain
	if (connect_to_server(domain, port, sockfd) == 0) {
		return 0;
	}

	// If domain connection fails, try resolving domain and use IP
	char* ip = resolve_domain(domain);
	if (ip) {
		if (connect_to_server(ip, port, sockfd) == 0) {
			free(ip);
			return 0;
		}
		free(ip);
	}

	// If resolution fails, try using known backup IP
	const char* known_ip = get_known_ip(domain);
	if (known_ip) {
		if (g_config.debug) {
			log_message("DEBUG", "connect_with_fallback: DNS resolution failed, trying known IP %s for %s", 
					   known_ip, domain);
		}
		if (connect_to_server(known_ip, port, sockfd) == 0) {
			log_message("INFO", "connect_with_fallback: Successfully connected using known IP fallback for %s", domain);
			return 0;
		} else {
			log_message("WARN", "connect_with_fallback: Known IP fallback also failed for %s", domain);
		}
	} else {
		if (g_config.debug) {
			log_message("DEBUG", "connect_with_fallback: No known IP fallback available for %s", domain);
		}
	}

	log_message("ERROR", "connect_with_fallback: All connection attempts failed for %s:%d", domain, port);
	return -1;
}

int send_query(int sockfd, const char* query) {
	char query_msg[256];
	snprintf(query_msg, sizeof(query_msg), "%s\r\n", query);
	int sent = send(sockfd, query_msg, strlen(query_msg), 0);
	if (g_config.debug)
		printf("[DEBUG] Sending query: %s (%d bytes)\n", query, sent);
	return sent;
}

char* receive_response(int sockfd) {
	if (g_config.debug) {
		printf(
			"[DEBUG] Attempting to allocate response buffer of size %zu "
			"bytes\n",
			g_config.buffer_size);
	}

	// Check if buffer size exceeds reasonable limits
	if (g_config.buffer_size > 100 * 1024 * 1024) {
		if (g_config.debug) {
			printf("[WARNING] Requested buffer size is very large (%zu MB)\n",
				   g_config.buffer_size / (1024 * 1024));
		}
	}

	char* buffer = wc_safe_malloc(g_config.buffer_size, "receive_response");
	// Note: safe_malloc already handles allocation failures by exiting

	ssize_t total_bytes = 0;
	fd_set read_fds;
	struct timeval timeout;

	// Important improvement: keep reading until timeout, don't rely on double
	// newline to exit early
	while ((size_t)total_bytes < g_config.buffer_size - 1) {
		// Check for termination signal
		if (should_terminate()) {
			log_message("INFO", "Receive interrupted by signal");
			break;
		}
		FD_ZERO(&read_fds);
		FD_SET(sockfd, &read_fds);
		timeout.tv_sec = g_config.timeout_sec;
		timeout.tv_usec = 0;

		int ready = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
		if (ready < 0) {
			if (g_config.debug)
				printf("[DEBUG] Select error after %zd bytes: %s\n", total_bytes, strerror(errno));
			break;
		} else if (ready == 0) {
			if (g_config.debug)
				printf("[DEBUG] Select timeout after %zd bytes\n", total_bytes);
			break;
		}

		ssize_t n = recv(sockfd, buffer + total_bytes,
						 g_config.buffer_size - total_bytes - 1, 0);
		if (n < 0) {
			if (g_config.debug)
				printf("[DEBUG] Read error after %zd bytes: %s\n", total_bytes, strerror(errno));
			break;
		} else if (n == 0) {
			if (g_config.debug)
				printf("[DEBUG] Connection closed by peer after %zd bytes\n",
					   total_bytes);
			break;
		}

		total_bytes += n;
		if (g_config.debug)
			printf("[DEBUG] Received %zd bytes, total %zd bytes\n", n,
				   total_bytes);

		// Important improvement: don't exit early, ensure complete response is
		// received Only check the basic termination conditions, but continue
		// reading until timeout
		if (total_bytes > 1000) {
			// Check if a complete WHOIS response has already been received
			if (strstr(buffer, "source:") || strstr(buffer, "person:") ||
				strstr(buffer, "inetnum:") || strstr(buffer, "NetRange:")) {
				// If contains key fields, can be considered complete response
				if (g_config.debug)
					printf("[DEBUG] Detected complete WHOIS response\n");
				// Even if complete response is detected, continue reading until
				// timeout to ensure all data is received
			}
		}
	}

	if (total_bytes > 0) {
		buffer[total_bytes] = '\0';

		// Validate response data
		if (!validate_response_data(buffer, total_bytes)) {
			log_message("ERROR", "Response data validation failed");
			free(buffer);
			return NULL;
		}

		// Enhanced protocol-level security validation
		if (!validate_whois_protocol_response(buffer, total_bytes)) {
			log_message("ERROR", "WHOIS protocol response validation failed");
			free(buffer);
			return NULL;
		}

		if (!check_response_integrity(buffer, total_bytes)) {
			log_message("ERROR", "WHOIS response integrity check failed");
			free(buffer);
			return NULL;
		}

		// Detect protocol anomalies
		if (detect_protocol_anomalies(buffer)) {
			log_message("WARN", "Protocol anomalies detected in WHOIS response");
			// Continue processing but log the warning
		}

		if (g_config.debug) {
			printf("[DEBUG] Response received successfully (%zd bytes)\n",
				   total_bytes);
			printf("[DEBUG] ===== RESPONSE PREVIEW =====\n");
			printf("%.500s\n", buffer);
			if (total_bytes > 500) printf("... (truncated)\n");
			printf("[DEBUG] ===== END PREVIEW =====\n");
		}

		return buffer;
	}

	free(buffer);
	if (g_config.debug) printf("[DEBUG] No response received\n");
	return NULL;
}

// ============================================================================
// 10. Implementation of the WHOIS protocol processing function
// ============================================================================

char* perform_whois_query(const char* target, int port, const char* query, char** authoritative_server_out, char** first_server_host_out, char** first_server_ip_out) {
	if (authoritative_server_out) *authoritative_server_out = NULL;
	if (first_server_host_out) *first_server_host_out = NULL;
	if (first_server_ip_out) *first_server_ip_out = NULL;
	int redirect_count = 0;
	char* current_target = strdup(target);
	int current_port = port;
	char* current_query = strdup(query);
	char* combined_result = NULL;
	const char* redirect_server = NULL;
	// Track visited redirect targets to avoid loops
	char* visited[16] = {0};
	char* final_authoritative = NULL;
	int literal_retry_performed = 0;
	char* first_server_host = NULL;
	char* first_server_ip = NULL;
	int first_connection_recorded = 0;

	if (!current_target || !current_query) {
		log_message("ERROR", "Memory allocation failed for query parameters");
		free(current_target);
		free(current_query);
		return NULL;
	}

	log_message("DEBUG", "Starting WHOIS query to %s:%d for %s", current_target, current_port, current_query);

	while (redirect_count <= g_config.max_redirects) {
		log_message("DEBUG", "===== QUERY ATTEMPT %d =====", redirect_count + 1);
		log_message("DEBUG", "Current target: %s, Query: %s", current_target, current_query);

		// Execute query
		int sockfd = -1;
		int retry_count = 0;
		char* result = NULL;

		// Retry mechanism with exponential backoff and fast failure
		while (retry_count < g_config.max_retries) {
			log_message("DEBUG", "Query attempt %d/%d to %s", retry_count + 1, g_config.max_retries, current_target);

			// Check if server is backed off before attempting connection
			if (is_server_backed_off(current_target)) {
				log_message("DEBUG", "Skipping backed off server: %s", current_target);
				break;
			}

			if (connect_with_fallback(current_target, current_port, &sockfd) == 0) {
				if (!first_connection_recorded) {
					first_server_host = current_target ? strdup(current_target) : NULL;
					struct sockaddr_storage peer_addr;
					socklen_t peer_len = sizeof(peer_addr);
					if (getpeername(sockfd, (struct sockaddr*)&peer_addr, &peer_len) == 0) {
						char ipbuf[NI_MAXHOST];
						if (getnameinfo((struct sockaddr*)&peer_addr, peer_len, ipbuf, sizeof(ipbuf), NULL, 0, NI_NUMERICHOST) == 0) {
							first_server_ip = strdup(ipbuf);
						}
					}
					first_connection_recorded = 1;
				}
				// Register active connection for signal handling
				register_active_connection(current_target, current_port, sockfd);
				if (send_query(sockfd, current_query) > 0) {
					result = receive_response(sockfd);
					// Unregister and close connection
					unregister_active_connection();
					close(sockfd);
					sockfd = -1;
					// Mark success on successful query
					mark_server_success(current_target);
					break;
				}
				close(sockfd);
				sockfd = -1;
			} else if (!literal_retry_performed && redirect_count == 0 && is_ip_literal(current_target)) {
				literal_retry_performed = 1;
				char* canonical = attempt_rir_fallback_from_ip(current_target);
				if (!canonical) {
					fprintf(stderr, "Error: Specified RIR server IP '%s' does not belong to any known RIR (PTR lookup failed).\n", current_target);
					if (first_server_host) free(first_server_host);
					if (first_server_ip) free(first_server_ip);
					free(current_target);
					free(current_query);
					if (combined_result) free(combined_result);
					return NULL;
				}
				if (g_config.debug) {
					log_message("DEBUG", "IP literal %s mapped to RIR hostname %s", current_target, canonical);
				}
				fprintf(stderr, "Notice: Falling back to RIR hostname %s derived from %s\n", canonical, current_target);
				free(current_target);
				current_target = canonical;
				current_port = port;
				retry_count = 0;
				continue;
			}

			// Mark failure and calculate exponential backoff delay
			mark_server_failure(current_target);
			retry_count++;
			
			// Exponential backoff with jitter
			int base_delay = g_config.retry_interval_ms;
			int max_delay = 10000; // 10 seconds maximum delay
			int delay_ms = base_delay * (1 << retry_count); // Exponential backoff: base * 2^retry_count
			
			// Cap the delay at maximum
			if (delay_ms > max_delay) delay_ms = max_delay;
			
			// Add random jitter
			if (g_config.retry_jitter_ms > 0) {
				int j = rand() % (g_config.retry_jitter_ms + 1);
				delay_ms += j;
			}
			
			if (g_config.debug) {
				log_message("DEBUG", "Retry %d/%d: waiting %d ms before next attempt", 
					   retry_count, g_config.max_retries, delay_ms);
			}
			
			if (delay_ms > 0) {
				struct timespec ts; ts.tv_sec = (time_t)(delay_ms/1000); ts.tv_nsec = (long)((delay_ms%1000)*1000000L);
				nanosleep(&ts, NULL);
			}
		}

		if (result == NULL) {
			// Check if failure was due to signal interruption
			if (should_terminate()) {
				log_message("INFO", "Query interrupted by user signal");
				if (first_server_host) free(first_server_host);
				if (first_server_ip) free(first_server_ip);
				free(current_target);
				free(current_query);
				if (combined_result) free(combined_result);
				return NULL;
			}
			
			log_message("DEBUG", "Query failed to %s after %d attempts", current_target, g_config.max_retries);

			// If this is the first query, return error
			if (redirect_count == 0) {
				if (first_server_host) free(first_server_host);
				if (first_server_ip) free(first_server_ip);
				free(current_target);
				free(current_query);
				if (combined_result) free(combined_result);
				return NULL;
			}

			// If not the first, return collected results
			if (!final_authoritative && current_target) {
				// best-effort authoritative guess
				final_authoritative = strdup(current_target);
			}
			break;
		}

		// Protocol injection detection
		if (detect_protocol_injection(current_query, result)) {
			log_security_event(SEC_EVENT_RESPONSE_TAMPERING, 
						  "Protocol injection detected for query: %s", current_query);
			// Continue processing but log the security event
		}

		// Check if redirect is needed
		if (!g_config.no_redirect && needs_redirect(result)) {
            log_message("DEBUG", "==== REDIRECT REQUIRED ====");
			int force_iana = 0;
			if (current_target && strcasecmp(current_target, "whois.iana.org") != 0) {
				int visited_iana = 0;
				for (int vi = 0; vi < 16 && visited[vi]; vi++) {
					if (strcasecmp(visited[vi], "whois.iana.org") == 0) {
						visited_iana = 1;
						break;
					}
				}
				if (!visited_iana) {
					force_iana = 1;
				}
			}
			if (force_iana) {
				redirect_server = strdup("whois.iana.org");
				if (redirect_server == NULL) {
					log_message("ERROR", "Failed to allocate redirect server string");
				}
				log_message("DEBUG", "Forcing redirect via IANA for %s", current_target);
			} else {
				redirect_server = extract_refer_server(result);
			}

			if (redirect_server) {
				log_message("DEBUG", "Redirecting to: %s", redirect_server);

				// Check if redirecting to same server
				if (strcmp(redirect_server, current_target) == 0) {
					log_message("DEBUG", "Redirect server same as current target, stopping redirect");
					free((void*)redirect_server);
					redirect_server = NULL;

					// Add current result to final result
					if (combined_result == NULL) {
						combined_result = result;
					} else {
						size_t new_len = strlen(combined_result) + strlen(result) + 100;
						char* new_combined = malloc(new_len);
						if (new_combined) {
							snprintf(new_combined, new_len,
									 "%s\n=== Additional query to %s ===\n%s",
									 combined_result, current_target, result);
							free(combined_result);
							free(result);
							combined_result = new_combined;
						} else {
							free(result);
						}
					}
					if (!final_authoritative && current_target)
						final_authoritative = strdup(current_target);
					break;
				}

				// Save current result
				if (combined_result == NULL) {
					combined_result = result;
				} else {
					size_t new_len = strlen(combined_result) + strlen(result) + 100;
					char* new_combined = malloc(new_len);
					if (new_combined) {
						snprintf(new_combined, new_len,
								 "%s\n=== Redirected query to %s ===\n%s",
								 combined_result, current_target, result);
						free(combined_result);
						free(result);
						combined_result = new_combined;
					} else {
						free(result);  // Ensure memory is freed
					}
				}

				// Prepare for next query with loop guard
				free(current_target);
				int loop = 0;
				// simple visited check to avoid A<->B loops
				// note: visited list declared at function top
				for (int i = 0; i < 16 && visited[i]; i++) {
					if (strcmp(visited[i], redirect_server) == 0) { loop = 1; break; }
				}
				// record visited if room
				if (!loop) {
					for (int i = 0; i < 16; i++) {
						if (!visited[i]) { visited[i] = strdup(redirect_server); break; }
					}
				}
				current_target = strdup(redirect_server);
				free((void*)redirect_server);
				redirect_server = NULL;

				if (!current_target) {
					log_message("DEBUG", "Memory allocation failed for redirect target");
					break;
				}
				if (loop) {
					log_message("WARN", "Detected redirect loop, stop following redirects");
					if (!final_authoritative && current_target)
						final_authoritative = strdup(current_target);
					break;
				}

				redirect_count++;
				continue;
			} else {
				log_message("DEBUG", "No redirect server found, stopping redirect");
				if (combined_result == NULL) {
					combined_result = result;
				} else {
					size_t new_len = strlen(combined_result) + strlen(result) + 100;
					char* new_combined = malloc(new_len);
					if (new_combined) {
						snprintf(new_combined, new_len,
								 "%s\n=== Final query to %s ===\n%s",
								 combined_result, current_target, result);
						free(combined_result);
						free(result);
						combined_result = new_combined;
					} else {
						free(result);
					}
				}
				break;
			}
		} else {
			log_message("DEBUG", "No redirect needed, returning result");
			if (combined_result == NULL) {
				combined_result = result;
			} else {
				size_t new_len = strlen(combined_result) + strlen(result) + 100;
				char* new_combined = malloc(new_len);
				if (new_combined) {
					snprintf(new_combined, new_len,
							 "%s\n=== Final query to %s ===\n%s",
							 combined_result, current_target, result);
					free(combined_result);
					free(result);
					combined_result = new_combined;
				} else {
					free(result);
				}
			}
			if (!final_authoritative && current_target)
				final_authoritative = strdup(current_target);
			break;
		}
	}

	if (redirect_count > g_config.max_redirects) {
		log_message("DEBUG", "Maximum redirects reached (%d)", g_config.max_redirects);

		// Add warning message
		if (combined_result) {
			size_t new_len = strlen(combined_result) + 200;
			char* new_result = malloc(new_len);
			if (new_result) {
				snprintf(new_result, new_len,
						 "Warning: Maximum redirects reached (%d).\n"
						 "You may need to manually query the final server for "
						 "complete information.\n\n%s",
						 g_config.max_redirects, combined_result);
				free(combined_result);
				combined_result = new_result;
			}
		}
	}

	// Cleanup resources
	if (redirect_server) free((void*)redirect_server);
	// free visited records
	for (int i = 0; i < 16; i++) { if (visited[i]) free(visited[i]); }
	// Preserve authoritative if not set
	if (!final_authoritative && current_target)
		final_authoritative = strdup(current_target);
	free(current_target);
	free(current_query);
	if (first_server_host_out && first_server_host) {
		*first_server_host_out = first_server_host;
		first_server_host = NULL;
	}
	if (first_server_ip_out && first_server_ip) {
		*first_server_ip_out = first_server_ip;
		first_server_ip = NULL;
	}
	if (!first_server_host_out && first_server_host) free(first_server_host);
	if (!first_server_ip_out && first_server_ip) free(first_server_ip);
	
	// Perform cache maintenance after query completion
	cleanup_expired_cache_entries();
	if (g_config.debug) {
		validate_cache_integrity();
	}
	
	if (authoritative_server_out) *authoritative_server_out = final_authoritative;
	else if (final_authoritative) free(final_authoritative);
	return combined_result;
}

char* get_server_target(const char* server_input) {
	struct in_addr addr4;
	struct in6_addr addr6;

	// Check if it's an IP address
	if (inet_pton(AF_INET, server_input, &addr4) == 1) {
		return strdup(server_input);
	}
	if (inet_pton(AF_INET6, server_input, &addr6) == 1) {
		return strdup(server_input);
	}

	// Check if it's a known server name
	for (int i = 0; servers[i].name != NULL; i++) {
		if (strcmp(server_input, servers[i].name) == 0) {
			return strdup(servers[i].domain);
		}
	}

	// Check if it's domain format
	if (strchr(server_input, '.') != NULL ||
		strchr(server_input, ':') != NULL) {
		return strdup(server_input);
	}

	return NULL;
}

// ============================================================================
// 10.1 Fallback resolution for IP literal RIR hosts
// ============================================================================
// New feature: When user supplies an IPv4/IPv6 literal via --host and initial
// connection fails, attempt reverse DNS (PTR) lookup. If the resolved domain
// maps to a known RIR, retry with that canonical RIR hostname; otherwise
// report that the literal does not belong to any known RIR.

static int is_ip_literal(const char* s) {
	if (!s || !*s) return 0;
	struct in_addr a4; struct in6_addr a6;
	if (inet_pton(AF_INET, s, &a4) == 1) return 1;
	if (inet_pton(AF_INET6, s, &a6) == 1) return 1;
	return 0;
}

static char* reverse_lookup_domain(const char* ip_literal) {
	if (!ip_literal) return NULL;
	struct in_addr a4; struct in6_addr a6;
	char hostbuf[NI_MAXHOST];
	int rc = -1;
	if (inet_pton(AF_INET, ip_literal, &a4) == 1) {
		struct sockaddr_in sa4; memset(&sa4,0,sizeof(sa4));
		sa4.sin_family = AF_INET; sa4.sin_addr = a4; sa4.sin_port = htons(g_config.whois_port);
		rc = getnameinfo((struct sockaddr*)&sa4, sizeof(sa4), hostbuf, sizeof(hostbuf), NULL, 0, NI_NAMEREQD);
	} else if (inet_pton(AF_INET6, ip_literal, &a6) == 1) {
		struct sockaddr_in6 sa6; memset(&sa6,0,sizeof(sa6));
		sa6.sin6_family = AF_INET6; sa6.sin6_addr = a6; sa6.sin6_port = htons(g_config.whois_port);
		rc = getnameinfo((struct sockaddr*)&sa6, sizeof(sa6), hostbuf, sizeof(hostbuf), NULL, 0, NI_NAMEREQD);
	} else {
		return NULL;
	}
	if (rc != 0) {
		if (g_config.debug) log_message("DEBUG", "reverse PTR failed for %s: %s", ip_literal, gai_strerror(rc));
		return NULL;
	}
	if (!is_valid_domain_name(hostbuf)) return NULL;
	return strdup(hostbuf);
}

static const char* map_domain_to_rir(const char* domain) {
	if (!domain) return NULL;
	// Accept direct match or suffix match on known domains.
	const struct { const char* suffix; const char* canonical; } map[] = {
		{"whois.arin.net", "whois.arin.net"},
		{"arin.net", "whois.arin.net"},
		{"whois.apnic.net", "whois.apnic.net"},
		{"apnic.net", "whois.apnic.net"},
		{"whois.ripe.net", "whois.ripe.net"},
		{"ripe.net", "whois.ripe.net"},
		{"whois.lacnic.net", "whois.lacnic.net"},
		{"lacnic.net", "whois.lacnic.net"},
		{"whois.afrinic.net", "whois.afrinic.net"},
		{"afrinic.net", "whois.afrinic.net"},
		{"whois.iana.org", "whois.iana.org"},
		{"iana.org", "whois.iana.org"},
		{NULL,NULL}
	};
	for (int i=0; map[i].suffix; i++) {
		const char* s = map[i].suffix;
		size_t dl = strlen(domain), sl = strlen(s);
		if ((dl == sl && strcasecmp(domain, s)==0) || (dl>sl && strcasecmp(domain+dl-sl, s)==0)) {
			return map[i].canonical;
		}
	}
	return NULL;
}

static char* attempt_rir_fallback_from_ip(const char* ip_literal) {
	char* ptr_domain = reverse_lookup_domain(ip_literal);
	if (!ptr_domain) return NULL;
	const char* canonical = map_domain_to_rir(ptr_domain);
	if (g_config.debug) {
		if (canonical) log_message("DEBUG", "PTR %s -> %s (mapped RIR canonical)", ptr_domain, canonical);
		else log_message("DEBUG", "PTR %s did not map to known RIR", ptr_domain);
	}
	free(ptr_domain);
	if (!canonical) return NULL;
	return strdup(canonical);
}

// ============================================================================
// 11. Implementation of the main entry function
// ============================================================================

static int g_dns_cache_stats_enabled = 0;

static void wc_print_dns_cache_summary_at_exit(void) {
	if (!g_dns_cache_stats_enabled) return;
	wc_dns_cache_stats_t stats;
	if (wc_dns_get_cache_stats(&stats) == 0) {
		fprintf(stderr,
			"[DNS-CACHE-SUM] hits=%ld neg_hits=%ld misses=%ld\n",
			stats.hits, stats.negative_hits, stats.misses);
	}
}

// Helpers for lookup/response handling are implemented in src/core/whois_query_exec.c

// Helper: handle meta/display options (help/version/about/examples/servers/selftest)
// Returns:
//   0  -> no meta option consumed, continue normal flow
//   >0 -> meta handled successfully, caller should exit(0)
//   <0 -> meta handled but indicates failure (e.g. selftest failed)
static int wc_handle_meta_requests(const wc_opts_t* opts, const char* progname) {
	if (!opts) return 0;
	if (opts->show_help) {
		wc_meta_print_usage(progname,
			DEFAULT_WHOIS_PORT,
			BUFFER_SIZE,
			MAX_RETRIES,
			TIMEOUT_SEC,
			g_config.retry_interval_ms,
			g_config.retry_jitter_ms,
			MAX_REDIRECTS,
			DNS_CACHE_SIZE,
			CONNECTION_CACHE_SIZE,
			CACHE_TIMEOUT,
			DEBUG);
		return 1;
	}
	if (opts->show_version) {
		wc_meta_print_version();
		return 1;
	}
	if (opts->show_about) {
		wc_meta_print_about();
		return 1;
	}
	if (opts->show_examples) {
		wc_meta_print_examples(progname);
		return 1;
	}
	if (opts->show_servers) {
		print_servers();
		return 1;
	}
	if (opts->show_selftest) {
		extern int wc_selftest_run(void);
		int rc = wc_selftest_run();
		return (rc == 0) ? 1 : -1;
	}
	return 0;
}

// Helper: detect batch vs single-query mode and extract positional query
// Returns 0 on success, non-zero on error (after printing usage message).
static int wc_detect_mode_and_query(const wc_opts_t* opts,
		int argc, char* argv[], int* out_batch_mode,
		const char** out_single_query) {
	if (!out_batch_mode || !out_single_query)
		return -1;
	*out_batch_mode = 0;
	*out_single_query = NULL;

	int explicit_batch = opts ? opts->explicit_batch : 0;
	if (explicit_batch) {
		*out_batch_mode = 1;
		if (optind < argc) {
			fprintf(stderr,
				"Error: --batch/-B does not accept a positional query. Provide input via stdin.\n");
			wc_meta_print_usage(argv[0],
				DEFAULT_WHOIS_PORT,
				BUFFER_SIZE,
				MAX_RETRIES,
				TIMEOUT_SEC,
				g_config.retry_interval_ms,
				g_config.retry_jitter_ms,
				MAX_REDIRECTS,
				DNS_CACHE_SIZE,
				CONNECTION_CACHE_SIZE,
				CACHE_TIMEOUT,
				DEBUG);
			return -1;
		}
		return 0;
	}

	if (optind >= argc) {
		if (!isatty(STDIN_FILENO)) {
			*out_batch_mode = 1;  // auto batch when no positional arg and stdin is piped
			return 0;
		}
		fprintf(stderr, "Error: Missing query argument\n");
		wc_meta_print_usage(argv[0],
			DEFAULT_WHOIS_PORT,
			BUFFER_SIZE,
			MAX_RETRIES,
			TIMEOUT_SEC,
			g_config.retry_interval_ms,
			g_config.retry_jitter_ms,
			MAX_REDIRECTS,
			DNS_CACHE_SIZE,
			CONNECTION_CACHE_SIZE,
			CACHE_TIMEOUT,
			DEBUG);
		return -1;
	}

	*out_single_query = argv[optind];
	return 0;
}

// Helper: execute a single query (non-batch mode) end-to-end
static int wc_run_single_query(const char* query,
		const char* server_host, int port) {
	// Security: detect suspicious queries
	if (wc_handle_suspicious_query(query, 0))
		return 1;

	// Check if it's a private IP address
	if (is_private_ip(query)) {
		return wc_handle_private_ip(query, NULL, 0);
	}

	// Phase B: use new lookup state machine (single-hop skeleton)
	struct wc_result res;
	int lrc = wc_execute_lookup(query, server_host, port, &res);

	if (g_config.debug)
		printf("[DEBUG] ===== MAIN QUERY START (lookup) =====\n");
	if (!lrc && res.body) {
		char* result = res.body; // adopt ownership; MUST null out res.body to avoid double free later
		res.body = NULL;
		if (wc_is_debug_enabled())
			fprintf(stderr,
				"[TRACE] after header; body_ptr=%p len=%zu (stage=initial)\n",
				(void*)result, res.body_len);
		/* Header using metadata from lookup */
		if (!g_config.fold_output && !g_config.plain_mode) {
			const char* via_host = res.meta.via_host[0]
				? res.meta.via_host
				: (server_host ? server_host : "whois.iana.org");
			const char* via_ip = res.meta.via_ip[0] ? res.meta.via_ip : NULL;
			if (via_ip)
				wc_output_header_via_ip(query, via_host, via_ip);
			else
				wc_output_header_via_unknown(query, via_host);
		}
		// Apply title/grep/sanitize pipeline
			char* filtered = wc_apply_response_filters(query, result, 0);
			free(result);
			result = filtered;

		char* authoritative_display_owned = NULL;
		const char* authoritative_display =
			(res.meta.authoritative_host[0]
				? res.meta.authoritative_host
				: NULL);
		if (authoritative_display && is_ip_literal(authoritative_display)) {
			char* mapped = attempt_rir_fallback_from_ip(authoritative_display);
			if (mapped) {
				authoritative_display_owned = mapped;
				authoritative_display = mapped;
			}
		}

		if (g_config.fold_output) {
			const char* rirv =
				(authoritative_display && *authoritative_display)
					? authoritative_display
					: "unknown";
			char* folded = wc_fold_build_line(
				result, query, rirv,
				g_config.fold_sep ? g_config.fold_sep : " ",
				g_config.fold_upper);
			printf("%s", folded);
			free(folded);
		} else {
			printf("%s", result);
			if (!g_config.plain_mode) {
				/* Tail line using wc_lookup meta (now includes authoritative IP when available) */
				if (authoritative_display && *authoritative_display) {
					const char* auth_ip =
						(res.meta.authoritative_ip[0]
							? res.meta.authoritative_ip
							: "unknown");
					wc_output_tail_authoritative_ip(authoritative_display,
						auth_ip);
				} else {
					wc_output_tail_unknown_unknown();
				}
			}
		}
		if (authoritative_display_owned)
			free(authoritative_display_owned);
		free(result);
		wc_lookup_result_free(&res);
		return 0;
	}

	// failure path
	if (should_terminate()) {
		fprintf(stderr, "Query interrupted by user\n");
	} else {
		wc_report_query_failure(query, server_host, res.meta.last_connect_errno);
	}
	// Free any partial result state from lookup
	wc_lookup_result_free(&res);
	cleanup_caches();
	return 1;
}

static int wc_run_batch_stdin(const char* server_host, int port) {
    if (g_config.debug)
        printf("[DEBUG] ===== BATCH STDIN MODE START =====\n");

    char linebuf[512];
    while (fgets(linebuf, sizeof(linebuf), stdin)) {
        if (should_terminate()) {
            log_message("INFO", "Batch processing interrupted by user");
            break;
        }
        char* p = linebuf;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        char* start = p;
        size_t len = strlen(start);
        while (len > 0 && (start[len-1] == '\n' || start[len-1] == '\r' ||
                start[len-1] == ' ' || start[len-1] == '\t')) {
            start[--len] = '\0';
        }

        if (len == 0) continue;
		if (start[0] == '#') continue;

		if (wc_handle_suspicious_query(start, 1))
			continue;

        const char* query = start;
		if (is_private_ip(query)) {
			wc_handle_private_ip(query, NULL, 1);
			continue;
		}

		struct wc_result res;
		int lrc = wc_execute_lookup(query, server_host, port, &res);

        if (!lrc && res.body) {
            char* result = res.body;
            res.body = NULL;
            if (wc_is_debug_enabled())
                fprintf(stderr, "[TRACE][batch] after header; body_ptr=%p len=%zu (stage=initial)\n",
                    (void*)result, res.body_len);
            if (!g_config.fold_output && !g_config.plain_mode) {
                const char* via_host = res.meta.via_host[0] ? res.meta.via_host : (server_host ? server_host : "whois.iana.org");
                const char* via_ip = res.meta.via_ip[0] ? res.meta.via_ip : NULL;
                if (via_ip) wc_output_header_via_ip(query, via_host, via_ip);
                else wc_output_header_via_unknown(query, via_host);
            }
			// Apply title/grep/sanitize pipeline
			char* filtered = wc_apply_response_filters(query, result, 1);
			free(result);
			result = filtered;

            char* authoritative_display_owned = NULL;
            const char* authoritative_display = (res.meta.authoritative_host[0] ? res.meta.authoritative_host : NULL);
            if (authoritative_display && is_ip_literal(authoritative_display)) {
                char* mapped = attempt_rir_fallback_from_ip(authoritative_display);
                if (mapped) {
                    authoritative_display_owned = mapped;
                    authoritative_display = mapped;
                }
            }

            if (g_config.fold_output) {
                const char* rirv = (authoritative_display && *authoritative_display) ? authoritative_display : "unknown";
                char* folded = wc_fold_build_line(
                    result, query, rirv,
                    g_config.fold_sep ? g_config.fold_sep : " ",
                    g_config.fold_upper);
                printf("%s", folded);
                free(folded);
            } else {
                printf("%s", result);
                if (!g_config.plain_mode) {
                    if (authoritative_display && *authoritative_display) {
                        const char* auth_ip = (res.meta.authoritative_ip[0] ? res.meta.authoritative_ip : "unknown");
                        wc_output_tail_authoritative_ip(authoritative_display, auth_ip);
                    } else {
                        wc_output_tail_unknown_unknown();
                    }
                }
            }
            if (authoritative_display_owned) free(authoritative_display_owned);
            free(result);
            wc_lookup_result_free(&res);
		} else {
			if (should_terminate()) {
				fprintf(stderr, "Query interrupted by user\n");
				break;
			} else {
				wc_report_query_failure(query, server_host, res.meta.last_connect_errno);
			}
			wc_lookup_result_free(&res);
		}
    }
    return 0;
}

// Helper: map parsed wc_opts_t back to global g_config
static void wc_apply_opts_to_config(const wc_opts_t* opts) {
	if (!opts) return;
	// Map parsed options back to legacy global config (incremental migration)
	g_config.whois_port = opts->port;
	g_config.timeout_sec = opts->timeout_sec;
	g_config.max_retries = opts->retries;
	g_config.retry_interval_ms = opts->retry_interval_ms;
	g_config.retry_jitter_ms = opts->retry_jitter_ms;
	g_config.max_redirects = opts->max_hops;
	g_config.no_redirect = opts->no_redirect;
	g_config.plain_mode = opts->plain_mode;
	g_config.debug = opts->debug;
	if (opts->debug_verbose)
		g_config.debug = (g_config.debug < 2 ? 2 : g_config.debug);
	// Note: WHOIS_DEBUG env is deprecated; CLI flags control debug.
	g_config.buffer_size = opts->buffer_size;
	g_config.dns_cache_size = opts->dns_cache_size;
	g_config.connection_cache_size = opts->connection_cache_size;
	g_config.cache_timeout = opts->cache_timeout;
	g_config.ipv4_only = opts->ipv4_only;
	g_config.ipv6_only = opts->ipv6_only;
	g_config.prefer_ipv4 = opts->prefer_ipv4;
	g_config.prefer_ipv6 = opts->prefer_ipv6;
	g_config.dns_neg_ttl = opts->dns_neg_ttl;
	g_config.dns_neg_cache_disable = opts->dns_neg_cache_disable;
	// DNS resolver controls and fallbacks
	g_config.dns_addrconfig = opts->dns_addrconfig;
	g_config.dns_retry = opts->dns_retry;
	g_config.dns_retry_interval_ms = opts->dns_retry_interval_ms;
	g_config.dns_max_candidates = opts->dns_max_candidates;
	g_config.no_dns_known_fallback = opts->no_dns_known_fallback;
	g_config.no_dns_force_ipv4_fallback = opts->no_dns_force_ipv4_fallback;
	g_config.no_iana_pivot = opts->no_iana_pivot;
	g_config.fold_output = opts->fold;
	g_config.fold_upper = opts->fold_upper;
	g_config.fold_unique = opts->fold_unique;
	if (opts->fold_sep) {
		if (g_config.fold_sep)
			free(g_config.fold_sep);
		g_config.fold_sep = strdup(opts->fold_sep);
	}
	g_config.security_logging = opts->security_log;
}

int main(int argc, char* argv[]) {
	// Seed RNG for retry jitter if used
	srand((unsigned)time(NULL));

	// Set up signal handlers for graceful shutdown
	setup_signal_handlers();
	atexit(cleanup_on_signal);

	// Parse options via wc_opts module
	wc_opts_t opts;
	if (wc_opts_parse(argc, argv, &opts) != 0) {
		wc_meta_print_usage(argv[0],
			DEFAULT_WHOIS_PORT,
			BUFFER_SIZE,
			MAX_RETRIES,
			TIMEOUT_SEC,
			g_config.retry_interval_ms,
			g_config.retry_jitter_ms,
			MAX_REDIRECTS,
			DNS_CACHE_SIZE,
			CONNECTION_CACHE_SIZE,
			CACHE_TIMEOUT,
			DEBUG);
		return 1;
	}

	// Map parsed options back to legacy global config (incremental migration)
	wc_apply_opts_to_config(&opts);

	// Apply fold unique behavior
	extern void wc_fold_set_unique(int on);
	wc_fold_set_unique(g_config.fold_unique);

	const char* server_host = opts.host;
	int port = opts.port;

	/* Process-level DNS cache summary flag; printed once at exit */
	g_dns_cache_stats_enabled = opts.dns_cache_stats;
	if (g_dns_cache_stats_enabled) {
		atexit(wc_print_dns_cache_summary_at_exit);
	}

    // opts currently only owns fold_sep; will free after meta handling

	// Ensure fold separator default if still unset
	if (!g_config.fold_sep) g_config.fold_sep = strdup(" ");

	// Configure security logging module according to parsed options (already set in parse)
	wc_seclog_set_enabled(g_config.security_logging);

	// Language option removed; always use English outputs

	// Validate configuration
	if (!validate_global_config()) return 1;

#ifdef WHOIS_SECLOG_TEST
	// Run optional security log self-test if enabled via environment
	maybe_run_seclog_self_test();
#endif

#ifdef WHOIS_GREP_TEST
	// Optional grep self-test driven by env var
	maybe_run_grep_self_test();
#endif

	// Check if cache sizes are reasonable
	if (!validate_cache_sizes()) {
		fprintf(stderr, "Error: Invalid cache sizes, using defaults\n");
		g_config.dns_cache_size = DNS_CACHE_SIZE;
		g_config.connection_cache_size = CONNECTION_CACHE_SIZE;
	}

	if (g_config.debug) printf("[DEBUG] Parsed command line arguments\n");
	if (g_config.debug) {
		printf("[DEBUG] Final configuration:\n");
		printf("        Buffer size: %zu bytes\n", g_config.buffer_size);
		printf("        DNS cache size: %zu entries\n",
			   g_config.dns_cache_size);
		printf("        Connection cache size: %zu entries\n",
			   g_config.connection_cache_size);
		printf("        Timeout: %d seconds\n", g_config.timeout_sec);
		printf("        Max retries: %d\n", g_config.max_retries);
		printf("        Retry interval: %d ms\n", g_config.retry_interval_ms);
		printf("        Retry jitter: %d ms\n", g_config.retry_jitter_ms);
		printf("        DNS retry: %d (interval %d ms, addrconfig %s, max candidates %d)\n",
			g_config.dns_retry, g_config.dns_retry_interval_ms, g_config.dns_addrconfig?"on":"off", g_config.dns_max_candidates);
	}

	// 2. Handle display options (help, version, server list, about, examples, selftest)
	int meta_rc = wc_handle_meta_requests(&opts, argv[0]);
	if (meta_rc != 0) {
		int exit_code = (meta_rc > 0) ? 0 : 1;
		wc_opts_free(&opts);
		return exit_code;
	}

	// 3. Validate arguments / detect stdin batch mode (restored semantics via helper)
	int batch_mode = 0;
	const char* single_query = NULL;
	if (wc_detect_mode_and_query(&opts, argc, argv, &batch_mode,
			&single_query) != 0) {
		wc_opts_free(&opts);
		return 1;
	}

    // 4. Initialize caches now (using final configuration values)
	if (g_config.debug)
		printf("[DEBUG] Initializing caches with final configuration...\n");
	init_caches();
	atexit(cleanup_caches);
	atexit(wc_title_free);
	atexit(wc_grep_free);
	atexit(free_fold_resources);

	if (g_config.debug) printf("[DEBUG] Caches initialized successfully\n");

	// 5. Continue with main logic...
	if (!batch_mode) {
		// Single query mode
		return wc_run_single_query(single_query, server_host, port);
	}

	// Batch stdin mode
	return wc_run_batch_stdin(server_host, port);
}

