// SPDX-License-Identifier: MIT
#ifndef WC_REDIRECT_H
#define WC_REDIRECT_H

#ifdef __cplusplus
extern "C" {
#endif

// Extract referral WHOIS server from a WHOIS response text.
// Returns a newly allocated string that the caller must free, or NULL if not found.
char* extract_refer_server(const char* response);

// Check whether the WHOIS response appears authoritative (contains definitive fields).
// Returns 1 if authoritative, 0 otherwise.
int is_authoritative_response(const char* response);

// Determine if the response indicates a redirect is needed (invalid ranges, hints, or not authoritative).
// Returns 1 if redirect is suggested, 0 otherwise.
int needs_redirect(const char* response);

#ifdef __cplusplus
}
#endif

#endif // WC_REDIRECT_H
