// wc_server.h - Whois server normalization and RIR guess utilities (phase A skeleton)
#ifndef WC_SERVER_H_
#define WC_SERVER_H_

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

// Normalize common aliases to canonical whois host (e.g., whois.arin.net). Returns 0 on success.
int wc_normalize_whois_host(const char* in, char* out, size_t cap);

// Guess RIR name from host or IP literal: "arin", "ripe", "apnic", "lacnic", "afrinic", "iana", or "unknown".
const char* wc_guess_rir(const char* host_or_ip);

// Default batch host list (ordered). Returns the canonical IANA host.
const char* wc_server_default_batch_host(void);

// Retrieve the default batch host list. Returns the number of entries and
// sets *out to a static array; do not free the returned pointer.
size_t wc_server_get_default_batch_hosts(const char* const** out);

#ifdef __cplusplus
}
#endif

#endif // WC_SERVER_H_
