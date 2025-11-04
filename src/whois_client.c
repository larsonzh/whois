// whois client (version 3.2.2) - migrated from lzispro
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

// Redirect related constants
#define REDIRECT_WARNING                                                  \
	"Warning: Maximum redirects reached (%d).\nYou may need to manually " \
	"query the final server for complete information.\n\n"

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
// 3. Data structures & global variables
// ============================================================================

// Protocol validation flags
typedef enum {
    PROTO_VALID_WHOIS_FORMAT = 1,
    PROTO_VALID_RESPONSE_STRUCTURE = 2,
    PROTO_VALID_CONTENT_TYPE = 4,
    PROTO_VALID_ENCODING = 8
} ProtocolValidationFlags;

// Configuration structure - stores all configurable parameters
typedef struct {
	int whois_port;                // WHOIS server port
	size_t buffer_size;            // Response buffer size
	int max_retries;               // Maximum retry count
	int timeout_sec;               // Timeout in seconds
	int retry_interval_ms;         // Base sleep between retries in milliseconds
	int retry_jitter_ms;           // Additional random jitter in milliseconds
	size_t dns_cache_size;         // DNS cache entries count
	size_t connection_cache_size;  // Connection cache entries count
	int cache_timeout;             // Cache timeout in seconds
	int debug;                     // Debug mode flag
	int max_redirects;             // Maximum redirect/follow count
	int no_redirect;               // Disable following redirects when set
	int plain_mode;                // Suppress header line when set
    int fold_output;      	       // Fold selected lines into one line per query
	char* fold_sep;               // Separator string for folded output (default: " ")
	int fold_upper;               // Uppercase values/RIR in folded output (default: 1)
	int security_logging;          // Enable security event logging (default: 0)
	int rdap_fallback;            // Enable RDAP fallback via external curl (default: 0)
	int rdap_prefer;              // Prefer RDAP first; on success, skip WHOIS (default: 0)
	int rdap_only;                // RDAP only, do not perform WHOIS (default: 0)
	int rdap_fast_fallback;       // Tighten WHOIS timeout/retries to reach RDAP quicker (default: 0)
} Config;

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
			   .rdap_fallback = 0,
			   .rdap_prefer = 0,
			   .rdap_only = 0,
			   .rdap_fast_fallback = 0};

// Title grep configuration (Phase 2.5 Step 1 - minimal)
typedef struct {
	int enabled;                 // whether -g was provided
	char* raw;                   // original pattern string (for debug)
	char** patterns;             // parsed patterns (lowercased)
	int count;                   // number of patterns
} TitleGrepConfig;

static TitleGrepConfig g_title_grep = {0, NULL, NULL, 0};

// Regex filter configuration (block-level filter on business entries)
typedef struct {
	int enabled;            // whether regex filtering is enabled
	int case_sensitive;     // 0: ignore case; 1: case-sensitive
	char* raw;              // original regex string
	regex_t re;             // compiled regex
	int compiled;           // 1 if compiled
	int mode_line;          // 1: line mode; 0: block mode (default)
	int line_keep_cont;     // in line mode: include continuation lines of the matched block
} RegexFilterConfig;

static RegexFilterConfig g_regex = {0, 0, NULL, {0}, 0, 0, 0};

// DNS cache structure - stores domain to IP mapping
typedef struct {
	char* domain;      // Domain name
	char* ip;          // IP address
	time_t timestamp;  // Cache timestamp
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
WhoisServer servers[] = {
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

// ============================================================================
// 4. Static function declarations
// ============================================================================

// Cache security functions
static int is_valid_domain_name(const char* domain);
static int is_valid_ip_address(const char* ip);
static int validate_dns_response(const char* ip);
static void cleanup_expired_cache_entries(void);
static void validate_cache_integrity(void);

// Signal handling functions
static void setup_signal_handlers(void);
static void signal_handler(int sig);
static void cleanup_on_signal(void);
static void register_active_connection(const char* host, int port, int sockfd);
static void unregister_active_connection(void);
static int should_terminate(void);

// Enhanced memory safety functions
static void* safe_malloc(size_t size, const char* function_name);
static void* safe_realloc(void* ptr, size_t size, const char* function_name);

// Title grep functions
static void free_title_grep();
static char* str_tolower_dup(const char* s);
static int parse_title_patterns(const char* arg);
static int ci_prefix_match_n(const char* name, size_t name_len, const char* pat);
static int is_header_line_and_name(const char* line, size_t len, const char** name_ptr, size_t* name_len_ptr, int* leading_ws_ptr);
static char* filter_response_by_title(const char* input);

// Regex filter functions
static void free_regex_filter();
static int compile_regex_filter(const char* pattern, int case_sensitive);
static char* filter_response_by_regex(const char* input);
static char* filter_response_by_regex_line(const char* input);

// Fold output functions
static void free_fold_resources();
static void append_upper_token(char** out, size_t* cap, size_t* len, const char* s, size_t n);
static int is_likely_regex(const char* s);
static const char* extract_query_from_body(const char* body, char* buf, size_t bufsz);
static char* build_folded_line(const char* body, const char* query, const char* rir);

// File descriptor safety functions
static void safe_close(int* fd, const char* function_name);
static int is_socket_alive(int sockfd);

// Server status tracking functions
static int is_server_backed_off(const char* host);
static void mark_server_failure(const char* host);
static void mark_server_success(const char* host);

// Response data validation functions
static int validate_response_data(const char* data, size_t len);
static char* sanitize_response_for_output(const char* input);

// Protocol-level security functions
static int validate_whois_protocol_response(const char* response, size_t len);
static int detect_protocol_anomalies(const char* response);
static int validate_redirect_target(const char* redirect_server);
static int is_safe_protocol_character(unsigned char c);
static int check_response_integrity(const char* response, size_t len);
static int is_valid_ipv4_literal(const char* s);
static int is_valid_ipv6_literal(const char* s);
static char* rdap_fetch_via_shell(const char* ip);
static char* rdap_fetch_via_shell_with_base(const char* base, const char* ip);
static const char* rdap_base_for_whois(const char* host);
static char* rdap_fetch_url_via_curl(const char* url);
static char* rdap_extract_follow_url(const char* json);
static int detect_protocol_injection(const char* query, const char* response);
static int strcasestr_simple(const char* haystack, const char* needle);
static int looks_like_iana_body(const char* body);
static int body_matches_authoritative_rir(const char* body, const char* authoritative);

// Security logging functions
static void log_security_event(int event_type, const char* format, ...);
static int detect_suspicious_query(const char* query);
static void monitor_connection_security(const char* host, int port, int result);
#ifdef WHOIS_SECLOG_TEST
static void maybe_run_seclog_self_test(void);
#endif

// ============================================================================
// 5. Function declarations
// ============================================================================

//  Utility functions
size_t parse_size_with_unit(const char* str);
void print_usage(const char* program_name);
void print_version();
void print_servers();
int is_private_ip(const char* ip);
int validate_global_config();   // Ensure that returning 0 indicates failure and 1
								// indicates success
void init_caches();
void cleanup_caches();
size_t get_free_memory();  // Changed to size_t for consistency
void report_memory_error(const char* function, size_t size);
void log_message(const char* level, const char* format, ...);

// DNS and connection cache functions
char* get_cached_dns(const char* domain);
void set_cached_dns(const char* domain, const char* ip);
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
char* extract_refer_server(const char* response);
int is_authoritative_response(const char* response);
int needs_redirect(const char* response);
char* perform_whois_query(const char* target, int port, const char* query, char** authoritative_server_out);
char* get_server_target(const char* server_input);

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
        log_message("WARN", "WHOIS response lacks valid content structure");
        return 0;
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

static int validate_redirect_target(const char* redirect_server) {
    if (!redirect_server || !*redirect_server) {
        log_message("WARN", "Empty redirect target");
        return 0;
    }
    
    // Check for valid domain or IP format
    if (!is_valid_domain_name(redirect_server) && !is_valid_ip_address(redirect_server)) {
        log_message("WARN", "Invalid redirect target format: %s", redirect_server);
        return 0;
    }
    
    // Check for localhost or private network redirects
    const char* suspicious_redirects[] = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "192.168.",
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        NULL
    };
    
    for (int i = 0; suspicious_redirects[i] != NULL; i++) {
        if (strstr(redirect_server, suspicious_redirects[i])) {
            log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
                              "Suspicious redirect target: %s -> %s", 
                              redirect_server, suspicious_redirects[i]);
            return 0;
        }
    }
    
    // Check for protocol prefix stripping
    if (strncmp(redirect_server, "whois://", 8) == 0) {
        // Already handled in extract_refer_server, but log it
        log_message("DEBUG", "Redirect target with whois:// prefix: %s", redirect_server);
    }
    
    return 1;
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

// Basic IPv4 literal validation (simple, not exhaustive CIDR)
static int is_valid_ipv4_literal(const char* s) {
	if (!s || !*s) return 0;
	int dots = 0; int num = 0; int len = 0;
	for (const char* p = s; ; ++p) {
		char c = *p;
		if (c >= '0' && c <= '9') {
			num = num*10 + (c - '0');
			if (num > 255) return 0;
			len++;
			if (len > 3) return 0;
		} else if (c == '.' || c == '\0') {
			if (len == 0) return 0;
			dots += (c == '.') ? 1 : 0;
			if (c == '\0') break;
			num = 0; len = 0;
		} else {
			return 0;
		}
	}
	return dots == 3;
}

// Minimal IPv6 literal check: allow hex, colon, and at most one '::'
static int is_valid_ipv6_literal(const char* s) {
	if (!s || !*s) return 0;
	int dc = 0; // '::' count
	for (const char* p = s; *p; ++p) {
		char c = *p;
		if (!( (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' )) {
			return 0;
		}
		if (c == ':' && p[1] == ':') {
			dc++;
			if (dc > 1) return 0;
		}
	}
	// not strict, but sufficient for avoiding shell injection in URL path
	return 1;
}

// RDAP via external curl (optional). Requires WHOIS_RDAP_ALLOW_SHELL=1 in environment.
// Returns malloc'd string (JSON/plain) or NULL on failure.
static char* rdap_fetch_via_shell(const char* ip) {
	if (!(is_valid_ipv4_literal(ip) || is_valid_ipv6_literal(ip))) {
		fprintf(stderr, "[RDAP] Skipped: '%s' is not a valid IP literal.\n", ip ? ip : "(null)");
		return NULL;
	}
	// Check if curl is available
	FILE* cv = popen("curl --version", "r");
	if (!cv) { fprintf(stderr, "[RDAP] 'curl' not available; skipping RDAP fallback.\n"); return NULL; }
	char tmpbuf[64]; size_t got = fread(tmpbuf, 1, sizeof(tmpbuf), cv);
	pclose(cv);
	if (got == 0) { fprintf(stderr, "[RDAP] 'curl' not available; skipping RDAP fallback.\n"); return NULL; }
	// Use IANA RDAP bootstrap to avoid hardcoding RIR endpoints
	char cmd[512];
	// Note: keep it simple; IPv6 literal is acceptable in path per IANA RDAP
	snprintf(cmd, sizeof(cmd), "curl -sL --max-time 8 https://rdap.iana.org/ip/%s", ip);

	FILE* fp = popen(cmd, "r");
	if (!fp) {
		fprintf(stderr, "[RDAP] popen failed: %s\n", strerror(errno));
		return NULL;
	}

	size_t cap = 65536; // cap to 64KB
	char* buf = (char*)malloc(cap + 1);
	if (!buf) { pclose(fp); return NULL; }
	size_t n = fread(buf, 1, cap, fp);
	buf[n] = '\0';
	pclose(fp);
	if (n == 0) { free(buf); return NULL; }

	// Try to follow IANA bootstrap to concrete RIR RDAP if a URL is present
	char* follow = rdap_extract_follow_url(buf);
	if (follow) {
		char* data = rdap_fetch_url_via_curl(follow);
		free(follow);
		if (data) { free(buf); return data; }
	}
	return buf;
}

// RDAP via specified base (e.g., https://rdap.arin.net/registry/ip/)
static char* rdap_fetch_via_shell_with_base(const char* base, const char* ip) {
	if (!base || !*base) return NULL;
	if (!(is_valid_ipv4_literal(ip) || is_valid_ipv6_literal(ip))) return NULL;
	FILE* cv = popen("curl --version", "r");
	if (!cv) return NULL;
	char tmpbuf[32]; fread(tmpbuf,1,sizeof(tmpbuf),cv); pclose(cv);
	char cmd[768];
	snprintf(cmd, sizeof(cmd), "curl -sL --max-time 8 %s%s", base, ip);
	FILE* fp = popen(cmd, "r");
	if (!fp) return NULL;
	size_t cap = 131072; // 128KB upper
	char* buf = (char*)malloc(cap+1);
	if (!buf) { pclose(fp); return NULL; }
	size_t n = fread(buf,1,cap,fp); buf[n]='\0'; pclose(fp);
	if (n==0) { free(buf); return NULL; }
	return buf;
}

static const char* rdap_base_for_whois(const char* host) {
	if (!host) return NULL;
	if (strcasestr_simple(host, "arin")) return "https://rdap.arin.net/registry/ip/";
	if (strcasestr_simple(host, "ripe")) return "https://rdap.db.ripe.net/ip/";
	if (strcasestr_simple(host, "apnic")) return "https://rdap.apnic.net/ip/";
	if (strcasestr_simple(host, "lacnic")) return "https://rdap.lacnic.net/rdap/ip/";
	if (strcasestr_simple(host, "afrinic")) return "https://rdap.afrinic.net/rdap/ip/";
	if (strcasestr_simple(host, "iana")) return "https://rdap.iana.org/ip/"; // not RIR, but keep for completeness
	return NULL;
}

// Fetch arbitrary URL via curl
static char* rdap_fetch_url_via_curl(const char* url) {
	if (!url || !*url) return NULL;
	FILE* fp = NULL;
	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "curl -sL --max-time 8 '%s'", url);
	fp = popen(cmd, "r");
	if (!fp) return NULL;
	size_t cap = 131072; // 128KB
	char* buf = (char*)malloc(cap+1);
	if (!buf) { pclose(fp); return NULL; }
	size_t n = fread(buf,1,cap,fp); buf[n]='\0'; pclose(fp);
	if (n==0) { free(buf); return NULL; }
	return buf;
}

// Extract first RDAP URL from IANA JSON (very lightweight parser)
static char* rdap_extract_follow_url(const char* json) {
	if (!json) return NULL;
	const char* p = json;
	// look for https://rdap.*" and capture till next quote
	while ((p = strstr(p, "https://rdap.")) != NULL) {
		const char* start = p;
		const char* q = start;
		while (*q && *q != '"' && *q != '\n' && *q != '\r') q++;
		size_t len = (size_t)(q - start);
		if (len > 0 && len < 1000) {
			// Heuristic: must contain /ip/
			if (memmem(start, len, "/ip/", 4) || memmem(start, len, "/rdap/ip/", 9)) {
				char* out = (char*)malloc(len+1);
				if (!out) return NULL;
				memcpy(out, start, len); out[len] = '\0';
				return out;
			}
		}
		p = q;
	}
	return NULL;
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

// Minimal case-insensitive substring search
static int strcasestr_simple(const char* haystack, const char* needle) {
	if (!haystack || !needle || !*needle) return 0;
	size_t nlen = strlen(needle);
	for (const char* p = haystack; *p; ++p) {
		size_t i = 0;
		while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
		if (i == nlen) return 1;
	}
	return 0;
}

// Heuristic: IANA body usually contains these markers
static int looks_like_iana_body(const char* body) {
	if (!body) return 0;
	if (strcasestr_simple(body, "IANA WHOIS server")) return 1;
	if (strcasestr_simple(body, "source: IANA")) return 1;
	if (strcasestr_simple(body, "For more information on IANA")) return 1;
	return 0;
}

// Check whether body appears to come from authoritative RIR text
static int body_matches_authoritative_rir(const char* body, const char* authoritative) {
	if (!body || !authoritative || !*authoritative) return 0;
	// If authoritative contains a known host, check it's mentioned
	if (strcasestr_simple(authoritative, "arin")) {
		if (strcasestr_simple(body, "ARIN")) return 1;
	} else if (strcasestr_simple(authoritative, "ripe")) {
		if (strcasestr_simple(body, "RIPE")) return 1;
	} else if (strcasestr_simple(authoritative, "apnic")) {
		if (strcasestr_simple(body, "APNIC")) return 1;
	} else if (strcasestr_simple(authoritative, "lacnic")) {
		if (strcasestr_simple(body, "LACNIC")) return 1;
	} else if (strcasestr_simple(authoritative, "afrinic")) {
		if (strcasestr_simple(body, "AFRINIC")) return 1;
	} else if (strcasestr_simple(authoritative, "iana")) {
		if (looks_like_iana_body(body)) return 1;
	}
	return 0;
}

// Signal handling functions
static void setup_signal_handlers(void) {
    struct sigaction sa;
    
    // Set up signal handler
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart system calls after signal handling
    
    // Register signals to handle
    sigaction(SIGINT, &sa, NULL);  // Ctrl+C
    sigaction(SIGTERM, &sa, NULL); // Termination signal
    sigaction(SIGHUP, &sa, NULL);  // Hangup
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
        
        // Security event logging
        if (g_config.security_logging) {
            log_security_event(SEC_EVENT_CONNECTION_ATTACK, 
                              "Process termination requested by signal: %s", sig_name);
        }
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
    dns_cache = safe_malloc(g_config.dns_cache_size * sizeof(DNSCacheEntry), "init_caches");
    memset(dns_cache, 0, g_config.dns_cache_size * sizeof(DNSCacheEntry));
    allocated_dns_cache_size = g_config.dns_cache_size;
    if (g_config.debug)
        printf("[DEBUG] DNS cache allocated for %zu entries\n",
               g_config.dns_cache_size);

    // Allocate connection cache
    connection_cache = safe_malloc(g_config.connection_cache_size * sizeof(ConnectionCacheEntry), "init_caches");
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

// Enhanced memory safety functions
static void* safe_malloc(size_t size, const char* function_name) {
	if (size == 0) return NULL;
	void* ptr = malloc(size);
	if (!ptr) {
		fprintf(stderr, "Error: Memory allocation failed in %s for %zu bytes\n", 
				function_name, size);
		exit(EXIT_FAILURE);
	}
	return ptr;
}

static void* safe_realloc(void* ptr, size_t size, const char* function_name) {
	if (size == 0) {
		free(ptr);
		return NULL;
	}
	void* new_ptr = realloc(ptr, size);
	if (!new_ptr) {
		fprintf(stderr, "Error: Memory reallocation failed in %s for %zu bytes\n", 
				function_name, size);
		exit(EXIT_FAILURE);
	}
	return new_ptr;
}

static void free_title_grep() {
	if (g_title_grep.patterns) {
		for (int i = 0; i < g_title_grep.count; i++) {
			if (g_title_grep.patterns[i]) free(g_title_grep.patterns[i]);
		}
		free(g_title_grep.patterns);
	}
	if (g_title_grep.raw) free(g_title_grep.raw);
	g_title_grep.enabled = 0;
	g_title_grep.raw = NULL;
	g_title_grep.patterns = NULL;
	g_title_grep.count = 0;
}

static char* str_tolower_dup(const char* s) {
	if (!s) return NULL;
	size_t n = strlen(s);
	char* r = (char*)safe_malloc(n + 1, "str_tolower_dup");
	for (size_t i = 0; i < n; i++) r[i] = (char)tolower((unsigned char)s[i]);
	r[n] = '\0';
	return r;
}

static void free_regex_filter() {
	if (g_regex.compiled) {
		regfree(&g_regex.re);
		g_regex.compiled = 0;
	}
	if (g_regex.raw) { free(g_regex.raw); g_regex.raw = NULL; }
	g_regex.enabled = 0;
	g_regex.case_sensitive = 0;
	g_regex.mode_line = 0;
	g_regex.line_keep_cont = 0;
}

static int compile_regex_filter(const char* pattern, int case_sensitive) {
	if (!pattern || !*pattern) return 0;
	if (strlen(pattern) > 4096) {
		fprintf(stderr, "Error: --grep pattern too long (max 4096)\n");
		return -1;
	}
	// Preserve mode toggles across re-compilation
	int prev_mode_line = g_regex.mode_line;
	int prev_keep_cont = g_regex.line_keep_cont;
	free_regex_filter();
	g_regex.enabled = 1;
	g_regex.case_sensitive = case_sensitive ? 1 : 0;
	g_regex.raw = strdup(pattern);
	if (!g_regex.raw) { fprintf(stderr, "Error: OOM parsing --grep\n"); return -1; }
	int flags = REG_EXTENDED | REG_NOSUB;
	if (!g_regex.case_sensitive) flags |= REG_ICASE;
	int rc = regcomp(&g_regex.re, pattern, flags);
	if (rc != 0) {
		char buf[256];
		regerror(rc, &g_regex.re, buf, sizeof(buf));
		fprintf(stderr, "Error: invalid regex: %s\n", buf);
		free_regex_filter();
		return -1;
	}
	g_regex.compiled = 1;
	// Restore mode toggles
	g_regex.mode_line = prev_mode_line;
	g_regex.line_keep_cont = prev_keep_cont;
	return 1;
}

static int parse_title_patterns(const char* arg) {
	// split by '|', trim spaces, lower-case each, enforce limits
	if (!arg || !*arg) return 0;
	if (strlen(arg) > 4096) {
		fprintf(stderr, "Error: -g pattern string too long (max 4096)\n");
		return -1;
	}
	// allocate temporary copy to tokenize
	char* tmp = strdup(arg);
	if (!tmp) return -1;
	int capacity = 16;
	char** pats = (char**)safe_malloc(sizeof(char*) * capacity, "parse_title_patterns");
	int count = 0;
	char* p = tmp;
	while (p) {
		char* token = p;
		char* bar = strchr(p, '|');
		if (bar) { *bar = '\0'; p = bar + 1; } else { p = NULL; }
		// trim leading/trailing spaces on token
		while (*token == ' ' || *token == '\t') token++;
		char* end = token + strlen(token);
		while (end > token && (end[-1] == ' ' || end[-1] == '\t')) { *--end = '\0'; }
		if (*token == '\0') continue; // skip empty
		if ((int)strlen(token) > 128) {
			fprintf(stderr, "Error: -g pattern too long (max 128): %s\n", token);
			free(pats); free(tmp);
			return -1;
		}
		if (count >= 64) {
			fprintf(stderr, "Error: -g patterns exceed max count 64\n");
			free(pats); free(tmp);
			return -1;
		}
		char* lower = str_tolower_dup(token);
		if (!lower) { free(pats); free(tmp); return -1; }
		if (count >= capacity) {
			capacity *= 2;
			char** np = (char**)safe_realloc(pats, sizeof(char*) * capacity, "parse_title_patterns");
			pats = np;
		}
		pats[count++] = lower;
	}
	free(tmp);
	g_title_grep.patterns = pats;
	g_title_grep.count = count;
	return count;
}

static int ci_prefix_match_n(const char* name, size_t name_len, const char* pat) {
	if (!name || !pat) return 0;
	size_t plen = strlen(pat);
	if (plen == 0 || plen > name_len) return 0;
	for (size_t i = 0; i < plen; i++) {
		unsigned char a = (unsigned char)name[i];
		unsigned char b = (unsigned char)pat[i];
		if (tolower(a) != tolower(b)) return 0;
	}
	return 1;
}

static int is_header_line_and_name(const char* line, size_t len, const char** name_ptr, size_t* name_len_ptr, int* leading_ws_ptr) {
	// Identify first non-space/tab token; if it ends with ':', treat as header; return header name (without ':')
	const char* s = line;
	const char* end = line + len;
	int leading_ws = 0;
	// detect if line starts with whitespace (for continuation)
	if (s < end && (*s == ' ' || *s == '\t')) leading_ws = 1;
	// skip leading whitespace for header token detection
	while (s < end && (*s == ' ' || *s == '\t')) s++;
	const char* tok_start = s;
	while (s < end && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n') {
		if (*s == ':') break;
		s++;
	}
	if (s < end && *s == ':') {
		// header token ends right before ':'
		const char* name_start = tok_start;
		size_t nlen = (size_t)(s - name_start);
		if (nlen == 0) return 0;
		if (name_ptr) *name_ptr = name_start;
		if (name_len_ptr) *name_len_ptr = nlen;
		if (leading_ws_ptr) *leading_ws_ptr = leading_ws;
		return 1;
	}
	if (leading_ws_ptr) *leading_ws_ptr = leading_ws;
	return 0;
}

static char* filter_response_by_title(const char* input) {
	if (!g_title_grep.enabled || g_title_grep.count <= 0 || !input) {
		return input ? strdup(input) : strdup("");
	}
	size_t in_len = strlen(input);
	char* out = (char*)safe_malloc(in_len + 1, "filter_response_by_title");
	size_t opos = 0;
	const char* p = input;
	int print_cont = 0;
	while (*p) {
		// find end of line
		const char* line_start = p;
		const char* q = p;
		while (*q && *q != '\n') q++;
		size_t line_len = (size_t)(q - line_start);
		// strip trailing \r for detection
		size_t det_len = line_len;
		if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;
		const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
		int is_header = is_header_line_and_name(line_start, det_len, &hname, &hlen, &leading_ws);
		int should_print = 0;
		if (is_header) {
			// match against patterns by prefix (case-insensitive)
			for (int i = 0; i < g_title_grep.count; i++) {
				if (ci_prefix_match_n(hname, hlen, g_title_grep.patterns[i])) { should_print = 1; break; }
			}
			print_cont = should_print; // continuation follows only if header matched
		} else {
			// non-header: print only if continuation and line starts with whitespace
			if (print_cont && leading_ws) should_print = 1; else should_print = 0;
		}
		if (should_print) {
			memcpy(out + opos, line_start, line_len);
			opos += line_len;
			if (*q == '\n') { out[opos++] = '\n'; }
		}
		p = (*q == '\n') ? (q + 1) : q;
	}
	out[opos] = '\0';
	return out;
}

// Block-level regex filter: treat a business entry as a block starting from a header
// line (token ending with ':') followed by continuation lines (leading space/tab).
// If any line in the block matches the regex, the entire block is printed.
static char* filter_response_by_regex(const char* input) {
	if (!g_regex.enabled || !g_regex.compiled || !input) {
		return input ? strdup(input) : strdup("");
	}
	size_t in_len = strlen(input);
	// Output buffer (same size upper bound)
	char* out = (char*)safe_malloc(in_len + 1, "filter_response_by_regex");
	size_t opos = 0;

	// Current block buffer
	char* blk = (char*)safe_malloc(in_len + 1, "filter_response_by_regex");
	size_t bpos = 0;
	int in_block = 0;     // whether inside a header block
	int blk_matched = 0;   // whether current block has any match

	// Reusable temporary line buffer for portable per-line regex match
	char* tmp = NULL; size_t tmp_cap = 0;

	const char* p = input;
	while (*p) {
		const char* line_start = p;
		const char* q = p;
		while (*q && *q != '\n') q++;
		size_t line_len = (size_t)(q - line_start);
		size_t det_len = line_len;
		if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;

		const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
		int is_header = is_header_line_and_name(line_start, det_len, &hname, &hlen, &leading_ws);

		// Boundary line: neither header nor continuation -> finalize current block
		int is_cont = (!is_header && leading_ws);
		int is_boundary = (!is_header && !is_cont);

		if (is_header && in_block) {
			// New header begins -> flush previous block first
			if (blk_matched && bpos > 0) {
				memcpy(out + opos, blk, bpos);
				opos += bpos;
			}
			bpos = 0; blk_matched = 0; in_block = 0;
		}

		if (is_header) {
			in_block = 1;
			// append line to block
			memcpy(blk + bpos, line_start, line_len);
			bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
			// test regex on this line
			if (!blk_matched && g_regex.compiled) {
				if (det_len > tmp_cap) {
					size_t nc = det_len + 1; char* np = (char*)realloc(tmp, nc);
					if (!np) { /* OOM: fallback to skip match */ }
					else { tmp = np; tmp_cap = nc - 1; }
				}
				if (tmp_cap >= det_len) {
					memcpy(tmp, line_start, det_len); tmp[det_len] = '\0';
					int rc = regexec(&g_regex.re, tmp, 0, NULL, 0);
					if (rc == 0) blk_matched = 1;
				}
			}
		} else if (is_cont && in_block) {
			// continuation inside a block
			memcpy(blk + bpos, line_start, line_len);
			bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
			if (!blk_matched && g_regex.compiled) {
				if (det_len > tmp_cap) {
					size_t nc = det_len + 1; char* np = (char*)realloc(tmp, nc);
					if (!np) { /* OOM: fallback to skip match */ }
					else { tmp = np; tmp_cap = nc - 1; }
				}
				if (tmp_cap >= det_len) {
					memcpy(tmp, line_start, det_len); tmp[det_len] = '\0';
					int rc = regexec(&g_regex.re, tmp, 0, NULL, 0);
					if (rc == 0) blk_matched = 1;
				}
			}
		} else if (is_boundary) {
			// separator/blank/comments -> finalize any open block
			if (in_block) {
				if (blk_matched && bpos > 0) {
					memcpy(out + opos, blk, bpos);
					opos += bpos;
				}
				bpos = 0; blk_matched = 0; in_block = 0;
			}
			// do not copy boundary lines
		}

		p = (*q == '\n') ? (q + 1) : q;
	}

	// flush last block
	if (in_block) {
		if (blk_matched && bpos > 0) {
			memcpy(out + opos, blk, bpos);
			opos += bpos;
		}
	}

	free(blk);
	if (tmp) free(tmp);
	out[opos] = '\0';
	return out;
}

// Line-level regex filter: match per-line. Header/tail markers (=== ...) are preserved.
// If g_regex.line_keep_cont is set and a match occurs inside a field block, output the
// entire block (title + continuation) once; otherwise only output matching lines.
static char* filter_response_by_regex_line(const char* input) {
	if (!g_regex.enabled || !g_regex.compiled || !input) {
		return input ? strdup(input) : strdup("");
	}
	size_t in_len = strlen(input);
	char* out = (char*)safe_malloc(in_len + 1, "filter_response_by_regex_line");
	size_t opos = 0;

	// Reuse block aggregation to support keep-cont behavior
	char* blk = (char*)safe_malloc(in_len + 1, "filter_response_by_regex_line");
	size_t bpos = 0;
	int in_block = 0;
	int blk_matched = 0; // any line in current block matched

	// Reusable temporary line buffer for portable per-line regex match
	char* tmp = NULL; size_t tmp_cap = 0;

	const char* p = input;
	while (*p) {
		const char* line_start = p;
		const char* q = p;
		while (*q && *q != '\n') q++;
		size_t line_len = (size_t)(q - line_start);
		size_t det_len = line_len;
		if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;

		// Determine header/cont/boundary
		const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
		int is_header = is_header_line_and_name(line_start, det_len, &hname, &hlen, &leading_ws);
		int is_cont = (!is_header && leading_ws);
		int is_boundary = (!is_header && !is_cont);

		// If a new header begins, finalize previous block first
		if (is_header && in_block) {
			if (g_regex.line_keep_cont) {
				if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; }
			} // else: already emitted matching lines inline
			bpos = 0; blk_matched = 0; in_block = 0;
		}

		if (is_header) {
			in_block = 1;
			// Append to block aggregation
			memcpy(blk + bpos, line_start, line_len);
			bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
			// Test regex
			if (det_len > tmp_cap) {
				size_t nc = det_len + 1; char* np = (char*)realloc(tmp, nc);
				if (!np) { /* OOM: fallback to skip match */ }
				else { tmp = np; tmp_cap = nc - 1; }
			}
			int rc = 1;
			if (tmp_cap >= det_len) {
				memcpy(tmp, line_start, det_len); tmp[det_len] = '\0';
				rc = regexec(&g_regex.re, tmp, 0, NULL, 0);
			}
			if (rc == 0) {
				blk_matched = 1;
				if (!g_regex.line_keep_cont) {
					// Emit this matched line only
					memcpy(out + opos, line_start, line_len);
					opos += line_len; if (*q == '\n') out[opos++] = '\n';
				}
			}
		} else if (is_cont && in_block) {
			// Continuation line in block
			memcpy(blk + bpos, line_start, line_len);
			bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
			if (det_len > tmp_cap) {
				size_t nc = det_len + 1; char* np = (char*)realloc(tmp, nc);
				if (!np) { /* OOM: fallback to skip match */ }
				else { tmp = np; tmp_cap = nc - 1; }
			}
			int rc = 1;
			if (tmp_cap >= det_len) {
				memcpy(tmp, line_start, det_len); tmp[det_len] = '\0';
				rc = regexec(&g_regex.re, tmp, 0, NULL, 0);
			}
			if (rc == 0) {
				blk_matched = 1;
				if (!g_regex.line_keep_cont) {
					memcpy(out + opos, line_start, line_len);
					opos += line_len; if (*q == '\n') out[opos++] = '\n';
				}
			}
		} else if (is_boundary) {
			// Finalize any open block first
			if (in_block) {
				if (g_regex.line_keep_cont) {
					if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; }
				}
				bpos = 0; blk_matched = 0; in_block = 0;
			}
			// Preserve header/tail markers (=== ...)
			if (det_len >= 3 && line_start[0] == '=' && line_start[1] == '=' && line_start[2] == '=') {
				memcpy(out + opos, line_start, line_len);
				opos += line_len; if (*q == '\n') out[opos++] = '\n';
				p = (*q == '\n') ? (q + 1) : q; continue;
			}
			// For other boundary lines, match per-line in line mode
			if (det_len > tmp_cap) {
				size_t nc = det_len + 1; char* np = (char*)realloc(tmp, nc);
				if (!np) { /* OOM: fallback to skip match */ }
				else { tmp = np; tmp_cap = nc - 1; }
			}
			int rc = 1;
			if (tmp_cap >= det_len) {
				memcpy(tmp, line_start, det_len); tmp[det_len] = '\0';
				rc = regexec(&g_regex.re, tmp, 0, NULL, 0);
			}
			if (rc == 0) {
				memcpy(out + opos, line_start, line_len);
				opos += line_len; if (*q == '\n') out[opos++] = '\n';
			}
		}

		p = (*q == '\n') ? (q + 1) : q;
	}

	// Flush last block if needed
	if (in_block) {
		if (g_regex.line_keep_cont) {
			if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; }
		}
	}

	free(blk);
	if (tmp) free(tmp);
	out[opos] = '\0';
	return out;
}

static void free_fold_resources() {
	if (g_config.fold_sep) { free(g_config.fold_sep); g_config.fold_sep = NULL; }
}

// Build a folded one-line summary: "<query> [VALUES...] <RIR>\n"
// - Input 'body' is the filtered server response (after title/regex filters)
// - Extract values from header/continuation lines:
//   header line: take content after ':' and leading spaces
//   continuation line: trim leading spaces and take the entire line
// - Convert values and RIR to uppercase; collapse internal whitespace to single spaces
static void append_upper_token(char** out, size_t* cap, size_t* len, const char* s, size_t n) {
	// ensure separator if needed
	const char* sep = g_config.fold_sep ? g_config.fold_sep : " ";
	size_t seplen = strlen(sep);
	if (*len > 0) {
		if (*len + seplen >= *cap) {
			while (*len + seplen >= *cap) { *cap = (*cap ? *cap*2 : 128); }
			*out = (char*)realloc(*out, *cap);
		}
		memcpy((*out)+(*len), sep, seplen);
		*len += seplen;
	}
	// append token with whitespace collapsing; case conversion conditional
	int in_space = 0;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '\r' || c == '\n') break;
		if (c == ' ' || c == '\t') { in_space = 1; continue; }
		if (in_space) {
			if (*len + 1 >= *cap) { *cap = (*cap ? *cap*2 : 128); *out = (char*)realloc(*out, *cap); }
			(*out)[(*len)++] = ' ';
			in_space = 0;
		}
		char ch = (g_config.fold_upper ? (char)toupper(c) : (char)c);
		if (*len + 1 >= *cap) { *cap = (*cap ? *cap*2 : 128); *out = (char*)realloc(*out, *cap); }
		(*out)[(*len)++] = ch;
	}
}

// Heuristic: detect if a string looks like a regex (not a concrete query)
static int is_likely_regex(const char* s) {
	if (!s || !*s) return 0;
	// If contains typical regex meta and also spaces/pipes, treat as regex-ish
	int has_meta = 0, has_sep = 0;
	for (const char* p = s; *p; ++p) {
		char c = *p;
		if (c=='^' || c=='$' || c=='[' || c==']' || c=='(' || c==')' || c=='|' || c=='?' || c=='+' || c=='*' || c=='{' || c=='}') has_meta = 1;
		if (c==' ' || c=='\t' || c=='|') has_sep = 1;
		if (has_meta && has_sep) return 1;
	}
	return 0;
}

// Try to extract original query from header marker lines inside body: "=== Query: <q> ==="
static const char* extract_query_from_body(const char* body, char* buf, size_t bufsz) {
	if (!body || !buf || bufsz==0) return NULL;
	const char* p = body;
	const char* marker = "=== Query:";
	size_t mlen = strlen(marker);
	while (*p) {
		const char* line = p;
		const char* q = p;
		while (*q && *q!='\n') q++;
		size_t len = (size_t)(q - line);
		const char* end = line + len;
		if (len >= mlen && memcmp(line, marker, mlen)==0) {
			// Trim prefix and trailing '===' if present
			const char* s = line + mlen;
			while (s<end && (*s==' ' || *s=='\t')) s++;
			// strip trailing spaces and '=' signs
			while (end>s && (end[-1]==' ' || end[-1]=='\t')) end--;
			while (end>s && end[-1]=='=') end--;
			while (end>s && (end[-1]==' ' || end[-1]=='\t')) end--;
			size_t qlen = (size_t)(end - s);
			if (qlen > 0) {
				if (qlen >= bufsz) qlen = bufsz - 1;
				memcpy(buf, s, qlen); buf[qlen] = '\0';
				return buf;
			}
		}
		p = (*q=='\n') ? (q+1) : q;
	}
	return NULL;
}

static char* build_folded_line(const char* body, const char* query, const char* rir) {
	size_t cap = 256; size_t len = 0;
	char* out = (char*)malloc(cap);
	if (!out) return strdup("");
	// start with query (prefer original query; if missing or looks like a regex, try extract from body markers)
	char qbuf[256];
	const char* qsrc = query;
	if (!qsrc || !*qsrc || is_likely_regex(qsrc)) {
		const char* from_body = extract_query_from_body(body, qbuf, sizeof(qbuf));
		if (from_body && *from_body) qsrc = from_body;
	}
	if (!qsrc) qsrc = "";
	size_t qlen = strlen(qsrc);
	if (len + qlen + 1 >= cap) { while (len + qlen + 1 >= cap) cap *= 2; out = (char*)realloc(out, cap); }
	memcpy(out + len, qsrc, qlen); len += qlen;

	// scan body lines and extract values
	if (body) {
		const char* p = body;
		while (*p) {
			const char* line_start = p;
			const char* q = p;
			while (*q && *q != '\n') q++;
			size_t line_len = (size_t)(q - line_start);
			size_t det_len = line_len; if (det_len>0 && line_start[det_len-1]=='\r') det_len--;

			const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
			int is_header = is_header_line_and_name(line_start, det_len, &hname, &hlen, &leading_ws);
			if (is_header) {
				// find ':' position
				const char* colon = memchr(line_start, ':', det_len);
				if (colon) {
					const char* val = colon + 1;
					// trim leading spaces/tabs
					while (val < line_start + det_len && (*val==' ' || *val=='\t')) val++;
					append_upper_token(&out, &cap, &len, val, (size_t)((line_start + det_len) - val));
				}
			} else if (leading_ws) {
				// continuation line: trim leading ws and take the rest
				const char* s = line_start;
				while (s < line_start + det_len && (*s==' ' || *s=='\t')) s++;
				if (s < line_start + det_len) {
					append_upper_token(&out, &cap, &len, s, (size_t)((line_start + det_len) - s));
				}
			}
			p = (*q == '\n') ? (q + 1) : q;
		}
	}

	// append RIR at tail
	const char* rirv = (rir && *rir) ? rir : "unknown";
	append_upper_token(&out, &cap, &len, rirv, strlen(rirv));

	// newline terminate
	if (len + 2 >= cap) { cap += 2; out = (char*)realloc(out, cap); }
	out[len++] = '\n'; out[len] = '\0';
	return out;
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

static char* sanitize_response_for_output(const char* input) {
    if (!input) return strdup("");
    
    size_t len = strlen(input);
    char* output = safe_malloc(len + 1, "sanitize_response_for_output");
    if (!output) return strdup("");
    
    size_t out_pos = 0;
    int in_escape = 0;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = input[i];
        
        // Replace problematic characters with safe alternatives
        if (c == 0) {
            // Skip null bytes
            continue;
        } else if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
            // Replace other control characters with space
            output[out_pos++] = ' ';
        } else if (c == '\033') { // ESC character
            // Skip ANSI escape sequences to prevent terminal issues
            in_escape = 1;
            continue;
        } else if (in_escape) {
            // Skip characters in escape sequence until command character
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                in_escape = 0;
            }
            continue;
        } else {
            // Safe character, copy as-is
            output[out_pos++] = c;
        }
    }
    
    output[out_pos] = '\0';
    
    // If we made changes, log it in debug mode
    if (out_pos != len && g_config.debug) {
        log_message("DEBUG", "Sanitized response: removed %zu problematic characters", len - out_pos);
    }
    
    return output;
}

// Security logging functions
static void log_security_event(int event_type, const char* format, ...) {
	if (!g_config.security_logging) return;

	// Simple rate limiter to avoid stderr flood during attacks
	// Windowed tokens: allow up to 20 events per second
	enum { SECLOG_CAPACITY_PER_SEC = 20 };
	static pthread_mutex_t sec_log_mutex = PTHREAD_MUTEX_INITIALIZER;
	static time_t window_start = 0;
	static int tokens = SECLOG_CAPACITY_PER_SEC;
	static unsigned int suppressed = 0;
	static time_t last_summary = 0; // last time we printed a suppression summary

	time_t now = time(NULL);

	pthread_mutex_lock(&sec_log_mutex);
	if (window_start == 0 || now - window_start >= 1) {
		// New one-second window; if any were suppressed in previous window, summarize once
		if (suppressed > 0) {
			struct tm* ts = localtime(&now);
			fprintf(stderr,
					"[%04d-%02d-%02d %02d:%02d:%02d] [SECURITY] [RATE_LIMIT] suppressed %u event(s) in the last 1s\n",
					ts ? ts->tm_year + 1900 : 0, ts ? ts->tm_mon + 1 : 0, ts ? ts->tm_mday : 0,
					ts ? ts->tm_hour : 0, ts ? ts->tm_min : 0, ts ? ts->tm_sec : 0,
					suppressed);
		}
		window_start = now;
		tokens = SECLOG_CAPACITY_PER_SEC;
		suppressed = 0;
	}

	if (tokens <= 0) {
		suppressed++;
		// Additionally, print a summary at most once every 5 seconds to give feedback in long floods
		if (now - last_summary >= 5) {
			struct tm* ts = localtime(&now);
			fprintf(stderr,
					"[%04d-%02d-%02d %02d:%02d:%02d] [SECURITY] [RATE_LIMIT] further events are being suppressed...\n",
					ts ? ts->tm_year + 1900 : 0, ts ? ts->tm_mon + 1 : 0, ts ? ts->tm_mday : 0,
					ts ? ts->tm_hour : 0, ts ? ts->tm_min : 0, ts ? ts->tm_sec : 0);
			last_summary = now;
		}
		pthread_mutex_unlock(&sec_log_mutex);
		return;
	}

	// Consume a token and proceed to log
	tokens--;

	const char* event_names[] = {
		"",
		"INVALID_INPUT",
		"SUSPICIOUS_QUERY",
		"CONNECTION_ATTACK",
		"RESPONSE_TAMPERING",
		"RATE_LIMIT_HIT"
	};

	const char* event_name = (event_type >= 1 && event_type <= 5) ? event_names[event_type] : "UNKNOWN";

	va_list args;
	va_start(args, format);

	struct tm* t = localtime(&now);
	fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] [SECURITY] [%s] ",
			t ? t->tm_year + 1900 : 0, t ? t->tm_mon + 1 : 0, t ? t->tm_mday : 0,
			t ? t->tm_hour : 0, t ? t->tm_min : 0, t ? t->tm_sec : 0, event_name);

	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
	pthread_mutex_unlock(&sec_log_mutex);
}

static int detect_suspicious_query(const char* query) {
    if (!query || !*query) return 0;
    
    // Check for potential injection patterns
    const char* suspicious_patterns[] = {
        "..",         // Directory traversal
        ";",          // Command injection
        "|",          // Pipe injection
        "&&",         // Command chaining
        "||",         // Command chaining
        "`",          // Command substitution
        "$",          // Variable substitution
        "(",          // Command grouping
        ")",          // Command grouping
        "\\n",        // Newline injection
        "\\r",        // Carriage return injection
        "\\0",        // Null byte injection
        "--",         // SQL/command comment
        "/*",         // SQL comment start
        "*/",         // SQL comment end
        "<",          // Input redirection
        ">",          // Output redirection
        NULL
    };
    
    for (int i = 0; suspicious_patterns[i] != NULL; i++) {
        if (strstr(query, suspicious_patterns[i])) {
            log_security_event(SEC_EVENT_SUSPICIOUS_QUERY, 
                              "Detected suspicious pattern '%s' in query: %s", 
                              suspicious_patterns[i], query);
            return 1;
        }
    }
    
    // Check for overly long queries (reasonable limit for WHOIS queries)
    // IPv6 addresses can be up to 45 chars, domains up to 253 chars, so 1024 is safe
    // Note: This only applies to actual WHOIS queries, not regex patterns or other options
    if (strlen(query) > 1024) {
        log_security_event(SEC_EVENT_SUSPICIOUS_QUERY, 
                          "Overly long query detected (%zu chars): %.100s...", 
                          strlen(query), query);
        return 1;
    }
    
    // Check for binary data in query
    for (const char* p = query; *p; p++) {
        if ((unsigned char)*p < 32 && *p != '\n' && *p != '\r' && *p != '\t') {
            log_security_event(SEC_EVENT_SUSPICIOUS_QUERY, 
                              "Binary data detected in query at position %ld: 0x%02x", 
                              p - query, (unsigned char)*p);
            return 1;
        }
    }
    
    return 0;
}

static void monitor_connection_security(const char* host, int port, int result) {
    if (!g_config.security_logging) return;
    
    static time_t last_connection_time = 0;
    static int connection_count = 0;
    time_t now = time(NULL);
    
    // Reset counter if more than 10 seconds have passed
    if (now - last_connection_time > 10) {
        connection_count = 0;
    }
    
    connection_count++;
    last_connection_time = now;
    
    // Log connection attempts for security analysis
    if (result == 0) {
        log_security_event(SEC_EVENT_CONNECTION_ATTACK, 
                          "Connection attempt to %s:%d (success) - total connections in last 10s: %d", 
                          host, port, connection_count);
    } else if (result == -1) {
        log_security_event(SEC_EVENT_CONNECTION_ATTACK, 
                          "Connection attempt to %s:%d (failed) - total connections in last 10s: %d", 
                          host, port, connection_count);
    }
    // Note: result == -2 indicates connection attempt started, don't log
    
    // Detect potential connection flooding
    if (connection_count > 10) {
        log_security_event(SEC_EVENT_RATE_LIMIT_HIT, 
                          "High connection rate detected: %d connections in last 10 seconds", 
                          connection_count);
    }
}

#ifdef WHOIS_SECLOG_TEST
// Optional self-test hook for security log rate limiting
// Activation: build with -DWHOIS_SECLOG_TEST and set env WHOIS_SECLOG_TEST=1
static void maybe_run_seclog_self_test(void) {
	const char* e = getenv("WHOIS_SECLOG_TEST");
	if (!e || *e == '\0' || *e == '0') return;
	int prev = g_config.security_logging;
	g_config.security_logging = 1; // ensure logging is on for the test

	// Emit a burst to trigger limiter; 200 events should exceed any sane cap
	for (int i = 0; i < 200; i++) {
		log_security_event(SEC_EVENT_CONNECTION_ATTACK, "SECTEST event #%d", i);
	}
	// Optionally add another small burst to cross window boundary if execution spans seconds
	for (int i = 0; i < 10; i++) {
		log_security_event(SEC_EVENT_RESPONSE_TAMPERING, "SECTEST extra #%d", i);
	}

	g_config.security_logging = prev;
}
#endif

// ============================================================================
// 7. Utility function implementations
// ============================================================================

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

void print_usage(const char* program_name) {
	printf("Usage: %s [OPTIONS] <IP or domain>\n", program_name);
	printf("Options:\n");
	printf(
		"  -h, --host HOST          Specify whois server (name or domain)\n");
	printf("  -p, --port PORT          Specify port number (default: %d)\n",
		   DEFAULT_WHOIS_PORT);
	printf("  -g, --title PATTERNS     Title grep: case-insensitive prefix match on key names; use '|' to separate multiple patterns (e.g., inet|netname)\n");
	printf("      --grep REGEX         Regex filter (POSIX ERE, case-insensitive). Default mode: block\n");
	printf("      --grep-cs REGEX      Regex filter (POSIX ERE, case-sensitive)\n");
	printf("      --grep-line          Select by line instead of block; header/tail markers are preserved\n");
	printf("      --grep-block         Select by block (default); use after --grep-line to switch back\n");
	printf("      --keep-continuation-lines  With --grep-line: when a match occurs inside a field block, print the whole block (title + continuation)\n");
	printf("      --no-keep-continuation-lines  Disable the above continuation expansion\n");
	printf("  -b, --buffer-size SIZE   Set buffer size (default: %d)\n",
		   BUFFER_SIZE);
	printf("  -r, --retries COUNT      Set maximum retry count (default: %d)\n",
		   MAX_RETRIES);
	printf("  -t, --timeout SECONDS    Set timeout in seconds (default: %d)\n",
		   TIMEOUT_SEC);
	printf("  -i, --retry-interval-ms MS  Base wait between retries in ms (default: %d)\n",
		g_config.retry_interval_ms);
	printf("  -J, --retry-jitter-ms MS    Add up to MS random jitter to retry wait (default: %d)\n",
		g_config.retry_jitter_ms);
	printf("  -R, --max-redirects N    Set max referral redirects (default: %d)\n",
		MAX_REDIRECTS);
	printf("  -Q, --no-redirect        Do not follow referral redirects\n");
	printf("  -B, --batch              Read queries from stdin (batch mode)\n");
	printf("  -P, --plain              Suppress header/tail markers (no '=== Query: ... ===')\n");
	printf("      --fold               Fold selected body into a single line: '<query> [VALUES...] <RIR>' (values uppercased)\n");
	printf("      --fold-sep SEP       Separator between folded tokens (default: space). Supports \\t, \\n, \\r, \\s\n");
	printf("      --no-fold-upper      Preserve original case in folded output (default: uppercase)\n");
	printf("  -d, --dns-cache SIZE     Set DNS cache size (default: %d)\n",
		   DNS_CACHE_SIZE);
	printf(
		"  -c, --conn-cache SIZE    Set connection cache size (default: %d)\n",
		CONNECTION_CACHE_SIZE);
	printf(
		"  -T, --cache-timeout SEC  Set cache timeout in seconds (default: "
		"%d)\n",
		CACHE_TIMEOUT);
	printf("  -D, --debug              Enable debug mode (default: %s)\n",
		   DEBUG ? "on" : "off");
	printf("      --security-log       Enable security event logging (default: off)\n");
	printf("      --rdap-fallback=allow-shell  If port 43 path fails, try RDAP via HTTPS using system 'curl' (if available)\n");
	printf("      --rdap-prefer        Prefer RDAP first; on success, skip WHOIS (implies --rdap-fallback=allow-shell)\n");
	printf("      --rdap-only          RDAP only; do not attempt WHOIS (implies --rdap-fallback=allow-shell)\n");
	printf("      --rdap-fast-fallback Tighten WHOIS timeout/retries so fallback triggers faster (clamp timeout<=2s, retries<=1)\n");
	printf("  -l, --list               List available whois servers\n");
	printf("  -v, --version            Show version information\n");
	printf("  -H, --help               Show this help message\n\n");
	printf("Examples:\n");
	printf("  %s 8.8.8.8\n", program_name);
	printf("  %s --host apnic 103.89.208.0\n", program_name);
	printf("  %s --timeout 10 --retries 3 8.8.8.8\n", program_name);
	printf("  %s -Q 8.8.8.8  (no redirect)\n", program_name);
	printf("  %s -B --host apnic < ip_list.txt  (batch from stdin)\n", program_name);
	printf("  %s -P 8.8.8.8  (no header line)\n", program_name);
	printf("  %s --debug --buffer-size 1048576 8.8.8.8\n", program_name);
}

void print_version() {
	printf("whois client 3.2.2 (Batch mode, headers+RIR tail, non-blocking connect, timeouts, smart redirects, conditional output engine)\n");
	printf("High-performance whois query tool for BusyBox pipelines: batch stdin, plain mode, authoritative RIR tail, non-blocking connect, robust smart redirects, and powerful conditional output. Default retry pacing: interval=300ms, jitter=300ms.\n");
	printf("Phase 2.5 Step1: optional title projection via -g PATTERNS (case-insensitive prefix on header keys; NOT a regex).\n");
	printf("Phase 2.5 Step1.5: regex filtering via --grep/--grep-cs (POSIX ERE), block/line selection; --grep-line for line mode; --keep-continuation-lines expands to whole field block in line mode.\n");
	printf("Phase 2.5 Step2: optional --fold for single-line summary per query: '<query> [VALUES...] <RIR>' (values uppercased; --fold-sep, --no-fold-upper supported).\n");
	printf("3.2.2: Security hardening (nine areas); add --security-log (off by default) with built-in rate limiting (~20 events/sec, with suppression summaries); safer memory helpers; improved signal handling; stricter input/redirect validation; response sanitization/validation. RDAP features: --rdap-fallback=allow-shell (uses system curl), --rdap-prefer, --rdap-only, --rdap-fast-fallback.\n");
}

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
	size_t oldest_index = 0;
	time_t oldest_time = time(NULL);

	for (size_t i = 0; i < allocated_dns_cache_size; i++) {
		if (dns_cache[i].domain && strcmp(dns_cache[i].domain, domain) == 0) {
			// Update existing entry
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

	if (g_config.debug) {
		log_message("DEBUG", "Cached DNS: %s -> %s", domain, ip);
	}

	pthread_mutex_unlock(&cache_mutex);
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
	size_t oldest_index = 0;
	time_t oldest_time = time(NULL);

	for (size_t i = 0; i < allocated_connection_cache_size; i++) {
		if (connection_cache[i].host == NULL) {
			// Found empty slot
			connection_cache[i].host = strdup(host);
			connection_cache[i].port = port;
			connection_cache[i].sockfd = sockfd;
			connection_cache[i].last_used = time(NULL);
			
			if (g_config.debug) {
				log_message("DEBUG", "Cached connection to %s:%d (slot %zu)", host, port, i);
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
		log_message("DEBUG", "Replacing oldest connection (slot %zu) with %s:%d", 
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

	// First check cache
	char* cached_ip = get_cached_dns(domain);
	if (cached_ip) {
		if (g_config.debug)
			printf("[DEBUG] Using cached DNS: %s -> %s\n", domain, cached_ip);
		return cached_ip;
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

	char* buffer = safe_malloc(g_config.buffer_size, "receive_response");
	// Note: safe_malloc already handles allocation failures by exiting

	size_t total_bytes = 0;
	fd_set read_fds;
	struct timeval timeout;

	// Important improvement: keep reading until timeout, don't rely on double
	// newline to exit early
	while (total_bytes < g_config.buffer_size - 1) {
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
				printf("[DEBUG] Select error after %zu bytes: %s\n", total_bytes, strerror(errno));
			break;
		} else if (ready == 0) {
			if (g_config.debug)
				printf("[DEBUG] Select timeout after %zu bytes\n", total_bytes);
			break;
		}

		ssize_t n = recv(sockfd, buffer + total_bytes,
						 g_config.buffer_size - total_bytes - 1, 0);
		if (n < 0) {
			if (g_config.debug)
				printf("[DEBUG] Read error after %zu bytes: %s\n", total_bytes, strerror(errno));
			break;
		} else if (n == 0) {
			if (g_config.debug)
				printf("[DEBUG] Connection closed by peer after %zu bytes\n",
					   total_bytes);
			break;
		}

		total_bytes += (size_t)n;
		if (g_config.debug)
			printf("[DEBUG] Received %zd bytes, total %zu bytes\n", n,
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
			printf("[DEBUG] Response received successfully (%zu bytes)\n",
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

char* extract_refer_server(const char* response) {
	if (g_config.debug) printf("[DEBUG] ===== EXTRACTING REFER SERVER =====\n");

	// Check for invalid IPv4 response
	if (strstr(response, "0.0.0.0 - 255.255.255.255") != NULL) {
		if (g_config.debug)
			printf(
				"[DEBUG] Invalid IPv4 response detected, redirecting to "
				"IANA\n");
		return strdup("whois.iana.org");
	}

	if (strstr(response, "0.0.0.0/0") != NULL) {
		if (g_config.debug)
			printf(
				"[DEBUG] Invalid IPv4 response detected, redirecting to "
				"IANA\n");
		return strdup("whois.iana.org");
	}

	// New: check for invalid IPv6 response
	if (strstr(response, "::/0") != NULL) {
		if (g_config.debug)
			printf(
				"[DEBUG] Invalid IPv6 response detected (::/0), redirecting to "
				"IANA\n");
		return strdup("whois.iana.org");
	}

	// Detection for IPv6 full range addresses
	if (strstr(response, "0:0:0:0:0:0:0:0") != NULL &&
		(strstr(response, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") != NULL ||
		 strstr(response, "::") != NULL)) {
		if (g_config.debug)
			printf(
				"[DEBUG] Invalid IPv6 response detected (full range), "
				"redirecting to IANA\n");
		return strdup("whois.iana.org");
	}

	// Check IANA default block
	if (strstr(response, "IANA-BLK") != NULL &&
		strstr(response, "whole IPv4 address space") != NULL) {
		if (g_config.debug)
			printf("[DEBUG] Invalid response detected, redirecting to IANA\n");
		return strdup("whois.iana.org");
	}

	// Handle APNIC responses specifically
	if (strstr(response, "APNIC")) {
		const char* apnic_not_managed_patterns[] = {
			"not allocated to",
			"not registered in",
			"not managed by",
			"does not belong to",
			"is not assigned to",
			"This network range is not allocated to",
			"allocated by another Regional Internet Registry",
			"IP address block not managed by",
			NULL};

		int not_managed_by_apnic = 0;
		for (int i = 0; apnic_not_managed_patterns[i] != NULL; i++) {
			if (strstr(response, apnic_not_managed_patterns[i])) {
				not_managed_by_apnic = 1;
				if (g_config.debug)
					printf(
						"[DEBUG] APNIC indicates IP is not managed by them: "
						"%s\n",
						apnic_not_managed_patterns[i]);
				break;
			}
		}

		if (not_managed_by_apnic) {
			// Try to extract suggested RIR
			const char* suggested_rirs[] = {
				"ARIN",   "whois.arin.net",   "RIPE",    "whois.ripe.net",
				"LACNIC", "whois.lacnic.net", "AFRINIC", "whois.afrinic.net",
				NULL};

			for (int i = 0; suggested_rirs[i] != NULL; i += 2) {
				if (strstr(response, suggested_rirs[i])) {
					if (g_config.debug)
						printf("[DEBUG] APNIC suggests querying %s (%s)\n",
							   suggested_rirs[i + 1], suggested_rirs[i]);
					return strdup(suggested_rirs[i + 1]);
				}
			}

			// If no specific RIR suggested, redirect to IANA by default
			if (g_config.debug)
				printf(
					"[DEBUG] No specific RIR suggested by APNIC, redirecting "
					"to IANA\n");
			return strdup("whois.iana.org");
		}
	}

	// The original parsing logic remains unchanged
	char* response_copy = strdup(response);
	if (!response_copy) {
		if (g_config.debug)
			printf("[DEBUG] Memory allocation failed for response copy\n");
		return NULL;
	}

	char* line = strtok(response_copy, "\n");
	char* whois_server = NULL;
	char* web_link = NULL;

	while (line != NULL) {
		// Skip empty lines and comment lines
		if (strlen(line) > 0 && line[0] != '#') {
			if (g_config.debug) printf("[DEBUG] Analyzing line: %s\n", line);

			// Find ReferralServer line (WHOIS protocol)
			char* pos = strstr(line, "ReferralServer:");
			if (pos) {
				pos += strlen("ReferralServer:");
				while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;

				if (strlen(pos) > 0) {
					char* end = pos;
					while (*end && *end != ' ' && *end != '\t' &&
						   *end != '\r' && *end != '\n')
						end++;

					size_t len = end - pos;
					whois_server = malloc(len + 1);
					strncpy(whois_server, pos, len);
					whois_server[len] = '\0';

					// Clean up server name
					char* p = whois_server + strlen(whois_server) - 1;
					while (p >= whois_server &&
						   (*p == ' ' || *p == '\t' || *p == '\r' ||
							*p == '.' || *p == ',')) {
						*p-- = '\0';
					}

					// Handle whois:// prefix
					if (strncmp(whois_server, "whois://", 8) == 0) {
						memmove(whois_server, whois_server + 8,
								strlen(whois_server) - 7);
					}

					if (g_config.debug)
						printf("[DEBUG] Found ReferralServer: %s\n",
							   whois_server);
				}
			}

			// Find other WHOIS server indicators
			if (!whois_server) {
				pos = strstr(line, "whois:");
				if (pos) {
					pos += strlen("whois:");
					while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;

					if (strlen(pos) > 0) {
						char* end = pos;
						while (*end && *end != ' ' && *end != '\t' &&
							   *end != '\r' && *end != '\n')
							end++;

						size_t len = end - pos;
						whois_server = malloc(len + 1);
						strncpy(whois_server, pos, len);
						whois_server[len] = '\0';

						if (g_config.debug)
							printf("[DEBUG] Found whois: directive: %s\n",
								   whois_server);
					}
				}
			}
		}
		line = strtok(NULL, "\n");
	}

	free(response_copy);

	// Return WHOIS server with priority
	if (whois_server && strchr(whois_server, '.') != NULL &&
		strlen(whois_server) > 3) {
		// Validate redirect target for security
		if (!validate_redirect_target(whois_server)) {
			log_message("WARN", "Invalid redirect target: %s", whois_server);
			free(whois_server);
			whois_server = NULL;
		} else {
			if (g_config.debug)
				printf("[DEBUG] Extracted refer server: %s\n", whois_server);
		}
		if (web_link) free(web_link);
		return whois_server;
	}

	// If no explicit server found but invalid response detected, redirect to
	// IANA
	if (web_link) {
		free(web_link);
	}

	// Avoid leaking a partially parsed whois_server token
	if (whois_server) {
		free(whois_server);
		whois_server = NULL;
	}

	// If no explicit server found, infer from response content
	if (g_config.debug)
		printf(
			"[DEBUG] No explicit refer server found, trying to infer from "
			"content\n");

	if (strstr(response, "APNIC") || strstr(response, "Asia Pacific") ||
		strstr(response, "whois.apnic.net")) {
		if (g_config.debug)
			printf("[DEBUG] Inferred server: whois.apnic.net (APNIC)\n");
		return strdup("whois.apnic.net");
	} else if (strstr(response, "RIPE") || strstr(response, "Europe") ||
			   strstr(response, "Middle East") ||
			   strstr(response, "whois.ripe.net")) {
		if (g_config.debug)
			printf("[DEBUG] Inferred server: whois.ripe.net (RIPE)\n");
		return strdup("whois.ripe.net");
	} else if (strstr(response, "LAC") || strstr(response, "Latin America") ||
			   strstr(response, "Caribbean") ||
			   strstr(response, "whois.lacnic.net")) {
		if (g_config.debug)
			printf("[DEBUG] Inferred server: whois.lacnic.net (LACNIC)\n");
		return strdup("whois.lacnic.net");
	} else if (strstr(response, "AFRINIC") || strstr(response, "Africa") ||
			   strstr(response, "whois.afrinic.net")) {
		if (g_config.debug)
			printf("[DEBUG] Inferred server: whois.afrinic.net (AFRINIC)\n");
		return strdup("whois.afrinic.net");
	} else if (strstr(response, "ARIN") || strstr(response, "North America") ||
			   strstr(response, "whois.arin.net")) {
		if (g_config.debug)
			printf("[DEBUG] Inferred server: whois.arin.net (ARIN)\n");
		return strdup("whois.arin.net");
	}

	if (g_config.debug) printf("[DEBUG] No refer server found in response\n");
	return NULL;
}

int is_authoritative_response(const char* response) {
	if (g_config.debug)
		printf("[DEBUG] ===== CHECKING AUTHORITATIVE RESPONSE =====\n");

	const char* authoritative_indicators[] = {
		"inetnum:",   "inet6num:",      "netname:",   "descr:",
		"country:",   "status:",        "person:",    "role:",
		"irt:",       "admin-c:",       "tech-c:",    "abuse-c:",
		"mnt-by:",    "mnt-irt:",       "mnt-lower:", "mnt-routes:",
		"source:",    "last-modified:", "NetRange:",  "CIDR:",
		"NetName:",   "NetHandle:",     "NetType:",   "Organization:",
		"OrgName:",   "OrgId:",         "Address:",   "City:",
		"StateProv:", "PostalCode:",    "Country:",   "RegDate:",
		"Updated:",   "Comment:",       "Ref:",       NULL};

	for (int i = 0; authoritative_indicators[i] != NULL; i++) {
		if (strstr(response, authoritative_indicators[i])) {
			if (g_config.debug)
				printf("[DEBUG] Authoritative indicator found: %s\n",
					   authoritative_indicators[i]);
			return 1;
		}
	}

	if (g_config.debug) printf("[DEBUG] No authoritative indicators found\n");
	return 0;
}

int needs_redirect(const char* response) {
	if (g_config.debug) printf("[DEBUG] ===== CHECKING REDIRECT NEED =====\n");

	// Check for invalid IPv4 response
	if (strstr(response, "0.0.0.0 - 255.255.255.255") != NULL) {
		if (g_config.debug)
			printf(
				"[DEBUG] Redirect flag found: Whole IPv4 address space "
				"returned\n");
		return 1;
	}

	if (strstr(response, "0.0.0.0/0") != NULL) {
		if (g_config.debug)
			printf(
				"[DEBUG] Redirect flag found: Invalid IPv4 range 0.0.0.0/0\n");
		return 1;
	}

	// Check for invalid IPv6 response
	if (strstr(response, "::/0") != NULL) {
		if (g_config.debug)
			printf("[DEBUG] Redirect flag found: Invalid IPv6 range ::/0\n");
		return 1;
	}

	if (strstr(response, "0:0:0:0:0:0:0:0") != NULL &&
		(strstr(response, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") != NULL ||
		 strstr(response, "::") != NULL)) {
		if (g_config.debug)
			printf(
				"[DEBUG] Redirect flag found: Whole IPv6 address space "
				"returned\n");
		return 1;
	}

	// Check IANA default block
	if (strstr(response, "IANA-BLK") != NULL &&
		strstr(response, "whole IPv4 address space") != NULL) {
		if (g_config.debug)
			printf(
				"[DEBUG] Redirect flag found: IANA default block returned\n");
		return 1;
	}

	// Check APNIC specific response patterns
	const char* apnic_redirect_flags[] = {
		"not registered in the APNIC database",
		"This IP address range is not registered",
		"not allocated to APNIC",
		"allocated by another Regional Internet Registry",
		"This network range is not allocated to",
		"IP address block not managed by APNIC",
		NULL};

	for (int i = 0; apnic_redirect_flags[i] != NULL; i++) {
		if (strstr(response, apnic_redirect_flags[i])) {
			if (g_config.debug)
				printf("[DEBUG] APNIC redirect flag found: %s\n",
					   apnic_redirect_flags[i]);
			return 1;
		}
	}

	// Check other common redirect flags
	const char* redirect_flags[] = {"not in database",
									"No match",
									"not found",
									"refer:",
									"ReferralServer:",
									"whois:",
									"Whois Server:",
									"This IP address range is not registered",
									"NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK",
									"IP address block not managed by",
									"Allocated to",
									"not registered in the",
									"Maintained by",
									"For more information, see",
									"For details, refer to",
									"See also",
									"Please query",
									"Query terms are ambiguous",
									NULL};

	for (int i = 0; redirect_flags[i] != NULL; i++) {
		if (strstr(response, redirect_flags[i])) {
			if (g_config.debug &&
				i < 10) {  // Only output first 10 matching flags
				printf("[DEBUG] Redirect flag found: %s\n", redirect_flags[i]);
			}
			return 1;
		}
	}

	// Finally check if it's an authoritative response
	if (!is_authoritative_response(response)) {
		if (g_config.debug)
			printf("[DEBUG] Response is not authoritative, needs redirect\n");
		return 1;
	}

	if (g_config.debug) printf("[DEBUG] No redirect needed\n");
	return 0;
}

char* perform_whois_query(const char* target, int port, const char* query, char** authoritative_server_out) {
	if (authoritative_server_out) *authoritative_server_out = NULL;
	int redirect_count = 0;
	char* current_target = strdup(target);
	int current_port = port;
	char* current_query = strdup(query);
	char* combined_result = NULL;
	const char* redirect_server = NULL;
	// Track visited redirect targets to avoid loops
	char* visited[16] = {0};
	char* final_authoritative = NULL;

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
				usleep((useconds_t)delay_ms * 1000);
			}
		}

		if (result == NULL) {
			// Check if failure was due to signal interruption
			if (should_terminate()) {
				log_message("INFO", "Query interrupted by user signal");
				free(current_target);
				free(current_query);
				if (combined_result) free(combined_result);
				return NULL;
			}
			
			log_message("DEBUG", "Query failed to %s after %d attempts", current_target, g_config.max_retries);

			// Per-RIR RDAP fast path: if WHOIS to this target failed and RDAP is allowed,
			// try the target's RDAP endpoint for IP queries.
			if (g_config.rdap_fallback && (is_valid_ipv4_literal(current_query) || is_valid_ipv6_literal(current_query))) {
				const char* base = rdap_base_for_whois(current_target);
				// Skip IANA for RDAP unless explicitly mapped
				if (base && !strcasestr_simple(current_target, "iana")) {
					char* rdj = rdap_fetch_via_shell_with_base(base, current_query);
					if (rdj) {
						// Compose result purely from RDAP to give user something useful
						size_t need = strlen(rdj) + 256;
						char* block = (char*)malloc(need);
						if (block) {
							int n = 0;
							if (!g_config.plain_mode)
								n = snprintf(block, need, "=== RDAP Fallback (%s): %s ===\n%s\n=== End RDAP Fallback ===\n", current_target, current_query, rdj);
							else
								n = snprintf(block, need, "%s\n", rdj);
							(void)n;
							if (combined_result == NULL) {
								combined_result = block;
							} else {
								size_t new_len = strlen(combined_result) + strlen(block) + 1;
								char* nb = (char*)malloc(new_len);
								if (nb) { strcpy(nb, combined_result); strcat(nb, block); free(combined_result); free(block); combined_result = nb; }
								else { free(block); }
							}
						}
						free(rdj);
						if (!final_authoritative && current_target)
							final_authoritative = strdup(current_target);
						break; // stop redirect chain; we provided RDAP
					}
				}
			}

			// If this is the first query and we couldn't RDAP, return error
			if (redirect_count == 0) {
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
			redirect_server = extract_refer_server(result);

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
	
	// Perform cache maintenance after query completion
	cleanup_expired_cache_entries();
	if (g_config.debug) {
		validate_cache_integrity();
	}
	
	if (authoritative_server_out) *authoritative_server_out = final_authoritative; else if (final_authoritative) free(final_authoritative);
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
// 11. Implementation of the main entry function
// ============================================================================

int main(int argc, char* argv[]) {
	// 1. Parse command line arguments
	const char* server_host = NULL;
	int port = g_config.whois_port;
	int show_help = 0, show_version = 0, show_servers = 0;
	// Seed RNG for retry jitter if used
	srand((unsigned)time(NULL));
	// Initialize default fold separator if not set
	if (!g_config.fold_sep) g_config.fold_sep = strdup(" ");

	// Set up signal handlers for graceful shutdown
	setup_signal_handlers();
	atexit(cleanup_on_signal);

	// Extended command line options
	static struct option long_options[] = {
		{"host", required_argument, 0, 'h'},
		{"port", required_argument, 0, 'p'},
		{"title", required_argument, 0, 'g'},
		{"grep", required_argument, 0, 1000},
		{"grep-cs", required_argument, 0, 1001},
		{"grep-line", no_argument, 0, 1002},
		{"keep-continuation-lines", no_argument, 0, 1003},
		{"grep-block", no_argument, 0, 1004},
		{"no-keep-continuation-lines", no_argument, 0, 1005},
        {"fold", no_argument, 0, 1006},
		{"fold-sep", required_argument, 0, 1007},
		{"no-fold-upper", no_argument, 0, 1008},
		{"security-log", no_argument, 0, 1009},
		{"rdap-fallback", required_argument, 0, 1010},
		{"rdap-prefer", no_argument, 0, 1011},
		{"rdap-only", no_argument, 0, 1012},
		{"rdap-fast-fallback", no_argument, 0, 1013},
		{"buffer-size", required_argument, 0, 'b'},
		{"retries", required_argument, 0, 'r'},
		{"timeout", required_argument, 0, 't'},
		{"retry-interval-ms", required_argument, 0, 'i'},
		{"retry-jitter-ms", required_argument, 0, 'J'},
		{"dns-cache", required_argument, 0, 'd'},
		{"conn-cache", required_argument, 0, 'c'},
		{"cache-timeout", required_argument, 0, 'T'},
		{"max-redirects", required_argument, 0, 'R'},
		{"no-redirect", no_argument, 0, 'Q'},
		{"batch", no_argument, 0, 'B'},
		{"plain", no_argument, 0, 'P'},
		{"debug", no_argument, 0, 'D'},
		{"list", no_argument, 0, 'l'},
		{"version", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'H'},
		{0, 0, 0, 0}};

	int opt;
	int option_index = 0;
	int explicit_batch = 0;

	// Parse command line arguments
	while ((opt = getopt_long(argc, argv, "h:p:g:b:r:t:i:J:d:c:T:R:QBPDlvH", long_options,
							  &option_index)) != -1) {
		switch (opt) {
			case 'g':
				// Reset previous title-grep config, then set new patterns
				free_title_grep();
				g_title_grep.enabled = 1;
				g_title_grep.raw = strdup(optarg);
				if (!g_title_grep.raw) { fprintf(stderr, "Error: OOM parsing -g\n"); return 1; }
				if (parse_title_patterns(optarg) < 0) { free_title_grep(); return 1; }
				break;
			case 1000: /* --grep (case-insensitive) */
				if (compile_regex_filter(optarg, 0) < 0) return 1;
				break;
			case 1001: /* --grep-cs (case-sensitive) */
				if (compile_regex_filter(optarg, 1) < 0) return 1;
				break;
			case 1002: /* --grep-line */
				g_regex.mode_line = 1;
				break;
			case 1003: /* --keep-continuation-lines */
				g_regex.line_keep_cont = 1;
				break;
			case 1004: /* --grep-block */
				g_regex.mode_line = 0;
				break;
			case 1005: /* --no-keep-continuation-lines */
				g_regex.line_keep_cont = 0;
				break;
            case 1006: /* --fold */
                g_config.fold_output = 1;
                break;
			case 1007: /* --fold-sep */
				if (g_config.fold_sep) { free(g_config.fold_sep); g_config.fold_sep = NULL; }
				if (optarg && strcmp(optarg, "\\t") == 0) g_config.fold_sep = strdup("\t");
				else if (optarg && strcmp(optarg, "\\n") == 0) g_config.fold_sep = strdup("\n");
				else if (optarg && strcmp(optarg, "\\r") == 0) g_config.fold_sep = strdup("\r");
				else if (optarg && (strcmp(optarg, "\\s") == 0 || strcmp(optarg, "space") == 0)) g_config.fold_sep = strdup(" ");
				else g_config.fold_sep = strdup(optarg ? optarg : " ");
				if (!g_config.fold_sep) { fprintf(stderr, "Error: OOM parsing --fold-sep\n"); return 1; }
				break;
			case 1008: /* --no-fold-upper */
				g_config.fold_upper = 0;
				break;
			case 1009: /* --security-log */
				g_config.security_logging = 1;
				break;
			case 1010: /* --rdap-fallback */
				if (optarg && strcmp(optarg, "allow-shell") == 0) {
					g_config.rdap_fallback = 1; // allow shell-based RDAP via curl
				} else {
					fprintf(stderr, "Error: --rdap-fallback expects 'allow-shell' (e.g., --rdap-fallback=allow-shell)\n");
					return 1;
				}
				break;
			case 1011: /* --rdap-prefer */
				g_config.rdap_fallback = 1; // imply fallback capability
				g_config.rdap_prefer = 1;
				break;
			case 1012: /* --rdap-only */
				g_config.rdap_fallback = 1; // imply fallback capability
				g_config.rdap_only = 1;
				break;
			case 1013: /* --rdap-fast-fallback */
				g_config.rdap_fast_fallback = 1;
				break;
			case 'B':
				// Explicitly enable batch mode from stdin
				explicit_batch = 1;
				break;
			case 'h':
				server_host = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				if (port <= 0 || port > 65535) {
					fprintf(stderr, "Error: Invalid port number\n");
					return 1;
				}
				break;
			case 'b': {
				size_t new_size = parse_size_with_unit(optarg);
				if (new_size == 0) {
					fprintf(stderr, "Error: Invalid buffer size '%s'\n",
							optarg);
					fprintf(stderr, "       Valid formats: 1024, 1K, 1M, 1G\n");
					return 1;
				}

				// Set reasonable upper limit (e.g. 1GB)
				if (new_size > 1024 * 1024 * 1024) {
					fprintf(stderr, "Warning: Buffer size capped at 1GB\n");
					new_size = 1024 * 1024 * 1024;
				}

				// Check minimum value
				if (new_size < 1024) {
					fprintf(
						stderr,
						"Warning: Buffer size increased to minimum of 1KB\n");
					new_size = 1024;
				}

				g_config.buffer_size = new_size;
				if (g_config.debug)
					printf("[DEBUG] Set buffer size to %zu bytes\n",
						   g_config.buffer_size);
			} break;
			case 'r':
				g_config.max_retries = atoi(optarg);
				if (g_config.max_retries < 0) {
					fprintf(stderr, "Error: Invalid retry count\n");
					return 1;
				}
				break;
			case 't':
				g_config.timeout_sec = atoi(optarg);
				if (g_config.timeout_sec <= 0) {
					fprintf(stderr, "Error: Invalid timeout value\n");
					return 1;
				}
				break;
			case 'i':
				g_config.retry_interval_ms = atoi(optarg);
				if (g_config.retry_interval_ms < 0) {
					fprintf(stderr, "Error: Invalid retry interval\n");
					return 1;
				}
				break;
			case 'J':
				g_config.retry_jitter_ms = atoi(optarg);
				if (g_config.retry_jitter_ms < 0) {
					fprintf(stderr, "Error: Invalid retry jitter\n");
					return 1;
				}
				break;
			case 'd':
				g_config.dns_cache_size = atoi(optarg);
				if (g_config.dns_cache_size <= 0) {
					fprintf(stderr, "Error: Invalid DNS cache size\n");
					return 1;
				}
				if (g_config.dns_cache_size > 20) {
					fprintf(stderr, "Warning: DNS cache size capped at 20\n");
					g_config.dns_cache_size = 20;
				}
				break;
			case 'c':
				g_config.connection_cache_size = atoi(optarg);
				if (g_config.connection_cache_size <= 0) {
					fprintf(stderr, "Error: Invalid connection cache size\n");
					return 1;
				}
				if (g_config.connection_cache_size > 10) {
					fprintf(stderr,
							"Warning: Connection cache size capped at 10\n");
					g_config.connection_cache_size = 10;
				}
				break;
			case 'T':
				g_config.cache_timeout = atoi(optarg);
				if (g_config.cache_timeout <= 0) {
					fprintf(stderr, "Error: Invalid cache timeout\n");
					return 1;
				}
				break;
			case 'R':
				g_config.max_redirects = atoi(optarg);
				if (g_config.max_redirects < 0) {
					fprintf(stderr, "Error: Invalid max redirects\n");
					return 1;
				}
				break;
			case 'Q':
				g_config.no_redirect = 1;
				break;
			case 'P':
				g_config.plain_mode = 1;
				break;
			case 'D':
				g_config.debug = 1;
				break;
			case 'l':
				show_servers = 1;
				break;
			case 'v':
				show_version = 1;
				break;
			case 'H':
				show_help = 1;
				break;
			default:
				print_usage(argv[0]);
				return 1;
		}
	}

	// Validate configuration
	if (!validate_global_config()) return 1;

	// Optional operator banner for security logging: print early so it precedes any self-test output
	if (g_config.security_logging) {
		fprintf(stderr, "[SECURITY] Security logging enabled (rate-limited to ~20 events/sec; suppression summaries enabled)\n");
	}

#ifdef WHOIS_SECLOG_TEST
	// Run optional security log self-test if enabled via environment
	maybe_run_seclog_self_test();
#endif

	// Check if cache sizes are reasonable
	if (!validate_cache_sizes()) {
		fprintf(stderr, "Error: Invalid cache sizes, using defaults\n");
		g_config.dns_cache_size = DNS_CACHE_SIZE;
		g_config.connection_cache_size = CONNECTION_CACHE_SIZE;
	}

	// If user asked for fast RDAP fallback, clamp WHOIS timings to fail fast,
	// but don't override more aggressive values users explicitly set.
	if (g_config.rdap_fast_fallback) {
		if (g_config.timeout_sec > 2) g_config.timeout_sec = 2;
		if (g_config.max_retries > 1) g_config.max_retries = 1;
		if (g_config.retry_interval_ms > 100) g_config.retry_interval_ms = 100;
		if (g_config.retry_jitter_ms > 100) g_config.retry_jitter_ms = 100;
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
	}

	// 2. Handle display options (help, version, server list)
	if (show_help) {
		print_usage(argv[0]);
		return 0;
	}
	if (show_version) {
		print_version();
		return 0;
	}
	if (show_servers) {
		print_servers();
		return 0;
	}

	// 3. Validate arguments / detect stdin batch mode
	int batch_mode = 0;
	const char* single_query = NULL;
	if (explicit_batch) {
		batch_mode = 1;
		if (optind < argc) {
			fprintf(stderr, "Error: --batch/-B does not accept a positional query. Provide input via stdin.\n");
			print_usage(argv[0]);
			return 1;
		}
	} else {
		if (optind >= argc) {
			if (!isatty(STDIN_FILENO)) {
				batch_mode = 1;  // No positional query, but data is coming from stdin
			} else {
				fprintf(stderr, "Error: Missing query argument\n");
				print_usage(argv[0]);
				return 1;
			}
		} else {
			single_query = argv[optind];
		}
	}

    // 4. Initialize caches now (using final configuration values)
	if (g_config.debug)
		printf("[DEBUG] Initializing caches with final configuration...\n");
	init_caches();
	atexit(cleanup_caches);
	atexit(free_title_grep);
	atexit(free_regex_filter);
	atexit(free_fold_resources);

	if (g_config.debug) printf("[DEBUG] Caches initialized successfully\n");

	// 5. Continue with main logic...
	if (!batch_mode) {
		// Single query mode
		const char* query = single_query;

		// Security: detect suspicious queries
		if (detect_suspicious_query(query)) {
			log_security_event(SEC_EVENT_SUSPICIOUS_QUERY, "Blocked suspicious query: %s", query);
			fprintf(stderr, "Error: Suspicious query detected\n");
			cleanup_caches();
			return 1;
		}

		// Check if it's a private IP address
		if (is_private_ip(query)) {
			if (g_config.fold_output) {
				char* folded = build_folded_line("", query, "unknown");
				printf("%s", folded);
				free(folded);
			} else {
				if (!g_config.plain_mode) {
					printf("=== Query: %s ===\n", query);
				}
				printf("%s is a private IP address\n", query);
				if (!g_config.plain_mode) {
					printf("=== Authoritative RIR: unknown ===\n");
				}
			}
			return 0;
		}

		// RDAP preferred/only path
		if (g_config.rdap_fallback && (g_config.rdap_prefer || g_config.rdap_only)) {
			char* rd = rdap_fetch_via_shell(query);
			if (rd) {
				if (!g_config.plain_mode) printf("=== RDAP Fallback: %s ===\n", query);
				printf("%s\n", rd);
				if (!g_config.plain_mode) printf("=== End RDAP Fallback ===\n");
				free(rd);
				return 0; // prefer/only: RDAP success ends here
			}
			if (g_config.rdap_only) {
				fprintf(stderr, "Error: RDAP request failed\n");
				return 1;
			}
			// rdap_prefer but failed -> continue WHOIS
		}

		char* target = NULL;
		if (server_host) {
			// Get specified server target
			target = get_server_target(server_host);
			if (!target) {
				fprintf(stderr, "Error: Unknown server '%s'\n", server_host);
				cleanup_caches();
				return 1;
			}
		} else {
			// Use IANA as default starting query point
			target = strdup("whois.iana.org");
			if (!target) {
				fprintf(stderr,
						"Error: Memory allocation failed for default target\n");
				cleanup_caches();
				return 1;
			}
		}

		if (g_config.debug) printf("[DEBUG] ===== MAIN QUERY START =====\n");
		if (g_config.debug)
			printf("[DEBUG] Final target: %s, Query: %s\n", target, query);

		char* authoritative = NULL;
		char* result = perform_whois_query(target, port, query, &authoritative);
		free(target);

		if (result) {
			if (!g_config.fold_output && !g_config.plain_mode) {
				printf("=== Query: %s ===\n", query);
			}
			if (g_title_grep.enabled) {
				char* filtered = filter_response_by_title(result);
				free(result);
				result = filtered;
			}
			if (g_regex.enabled) {
				char* f2 = g_regex.mode_line ? filter_response_by_regex_line(result) : filter_response_by_regex(result);
				free(result);
				result = f2;
			}
			
			// Sanitize response data before output
			char* sanitized_result = sanitize_response_for_output(result);
			free(result);
			result = sanitized_result;

			// If RDAP fallback is allowed and the output is likely from IANA or
			// doesn't match the declared authoritative RIR (e.g., ARIN blocked),
			// append RDAP as a helpful supplement.
			if (g_config.rdap_fallback) {
				int need_rdap = 0;
				if (looks_like_iana_body(result)) need_rdap = 1;
				else if (authoritative && !body_matches_authoritative_rir(result, authoritative)) need_rdap = 1;
				else if (!is_authoritative_response(result)) need_rdap = 1;
				if (need_rdap) {
					char* rdap = rdap_fetch_via_shell(query);
					if (rdap) {
						if (!g_config.plain_mode) printf("=== RDAP Fallback: %s ===\n", query);
						printf("%s\n", rdap);
						if (!g_config.plain_mode) printf("=== End RDAP Fallback ===\n");
						free(rdap);
					}
				}
			}
			
			if (g_config.fold_output) {
				const char* rirv = (authoritative && *authoritative) ? authoritative : "unknown";
				char* folded = build_folded_line(result, query, rirv);
				printf("%s", folded);
				free(folded);
			} else {
				printf("%s", result);
				if (!g_config.plain_mode) {
					if (authoritative && strlen(authoritative) > 0)
						printf("=== Authoritative RIR: %s ===\n", authoritative);
					else
						printf("=== Authoritative RIR: unknown ===\n");
				}
			}
			free(result);
			if (authoritative) free(authoritative);
			return 0;
		} else {
			// Check if failure was due to signal interruption
			if (should_terminate()) {
				fprintf(stderr, "Query interrupted by user\n");
			} else {
				fprintf(stderr, "Error: Query failed for %s\n", query);
				// Optional RDAP fallback via shell 'curl' if enabled
				if (g_config.rdap_fallback) {
					char* rdap = rdap_fetch_via_shell(query);
					if (rdap) {
						if (!g_config.plain_mode) printf("=== RDAP Fallback: %s ===\n", query);
						printf("%s\n", rdap);
						if (!g_config.plain_mode) printf("=== End RDAP Fallback ===\n");
						free(rdap);
						cleanup_caches();
						return 0; // treat as success
					}
				}
			}
			cleanup_caches();
			return 1;
		}
	} else {
		// Batch stdin mode: read queries line-by-line from stdin and process sequentially
		if (g_config.debug)
			printf("[DEBUG] ===== BATCH STDIN MODE START =====\n");

		char linebuf[512];
		while (fgets(linebuf, sizeof(linebuf), stdin)) {
			// Check for termination signal
			if (should_terminate()) {
				log_message("INFO", "Batch processing interrupted by user");
				break;
			}
			// Trim whitespace and newline\r\n
			char* p = linebuf;
			while (*p && (*p == ' ' || *p == '\t')) p++;
			char* start = p;
			size_t len = strlen(start);
			while (len > 0 && (start[len-1] == '\n' || start[len-1] == '\r' || start[len-1] == ' ' || start[len-1] == '\t')) {
				start[--len] = '\0';
			}

			if (len == 0) continue;              // skip empty lines
			if (start[0] == '#') continue;       // skip comments

			// Security: detect suspicious queries in batch mode
			if (detect_suspicious_query(start)) {
				log_security_event(SEC_EVENT_SUSPICIOUS_QUERY, "Blocked suspicious query in batch mode: %s", start);
				fprintf(stderr, "Error: Suspicious query detected in batch mode: %s\n", start);
				continue; // Skip this query but continue processing others
			}

			// Determine target server for batch if needed
			const char* query = start;
			if (is_private_ip(query)) {
				if (g_config.fold_output) {
					char* folded = build_folded_line("", query, "unknown");
					printf("%s", folded);
					free(folded);
				} else {
					if (!g_config.plain_mode) {
						printf("=== Query: %s ===\n", query);
					}
					printf("%s is a private IP address\n", query);
					if (!g_config.plain_mode) {
						printf("=== Authoritative RIR: unknown ===\n");
					}
				}
				continue;
			}

			char* target = NULL;
			if (server_host) {
				target = get_server_target(server_host);
				if (!target) {
					fprintf(stderr, "Error: Unknown server '%s'\n", server_host);
					cleanup_caches();
					return 1;
				}
			} else {
				target = strdup("whois.iana.org");
				if (!target) {
					fprintf(stderr, "Error: Memory allocation failed for default target\n");
					cleanup_caches();
					return 1;
				}
			}

			char* authoritative = NULL;
			char* result = perform_whois_query(target, port, query, &authoritative);
			free(target);

			if (result) {
				if (!g_config.fold_output && !g_config.plain_mode) {
					printf("=== Query: %s ===\n", query);
				}
				if (g_title_grep.enabled) {
					char* filtered = filter_response_by_title(result);
					free(result);
					result = filtered;
				}
				if (g_regex.enabled) {
					char* f2 = g_regex.mode_line ? filter_response_by_regex_line(result) : filter_response_by_regex(result);
					free(result);
					result = f2;
				}
				
				// Sanitize response data before output
				char* sanitized_result = sanitize_response_for_output(result);
				free(result);
				result = sanitized_result;
				
				if (g_config.fold_output) {
					const char* rirv = (authoritative && *authoritative) ? authoritative : "unknown";
					char* folded = build_folded_line(result, query, rirv);
					printf("%s", folded);
					free(folded);
				} else {
					printf("%s", result);
					if (!g_config.plain_mode) {
						if (authoritative && strlen(authoritative) > 0)
							printf("=== Authoritative RIR: %s ===\n", authoritative);
						else
							printf("=== Authoritative RIR: unknown ===\n");
					}
				}
				free(result);
				if (authoritative) free(authoritative);
			} else {
				// Check if failure was due to signal interruption
				if (should_terminate()) {
					fprintf(stderr, "Query interrupted by user\n");
					break; // Exit the batch processing loop
				} else {
					fprintf(stderr, "Error: Query failed for %s\n", query);
				}
				if (authoritative) free(authoritative);
			}
		}

		// Treat as success even if no lines were processed (empty stdin)
		return 0;
	}
}

