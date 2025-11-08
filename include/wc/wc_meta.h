// wc_meta.h - Help/Version/Usage metadata utilities for whois client
#ifndef WC_META_H_
#define WC_META_H_

#include <stdio.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Print usage/help to stdout. Caller provides program name and default values
// so the text stays accurate even when defaults are tuned by build flags.
void wc_meta_print_usage(
    const char* program_name,
    int default_port,
    size_t default_buffer,
    int default_retries,
    int default_timeout_sec,
    int default_retry_interval_ms,
    int default_retry_jitter_ms,
    int default_max_redirects,
    int default_dns_cache_size,
    int default_connection_cache_size,
    int default_cache_timeout,
    int default_debug);

// Print version information to stdout.
void wc_meta_print_version(void);

// Return version string (e.g., "3.2.5"). String is static; do not free.
const char* wc_meta_version_string(void);

// Print extended about text (detailed architecture / modules overview)
void wc_meta_print_about(void);

// Print extended examples (advanced usage scenarios)
void wc_meta_print_examples(const char* program_name);

// Set language for meta outputs ("en" or "zh"). Defaults to "en".
void wc_meta_set_lang(const char* lang);

#ifdef __cplusplus
}
#endif

#endif // WC_META_H_
