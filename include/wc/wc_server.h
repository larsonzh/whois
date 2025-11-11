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

#ifdef __cplusplus
}
#endif

#endif // WC_SERVER_H_
