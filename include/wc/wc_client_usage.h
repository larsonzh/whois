#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wc_client_server_entry_s {
    const char* alias;
    const char* domain;
    const char* description;
} wc_client_server_entry_t;

// Print the known whois servers table to stdout.
void wc_client_print_server_catalog(void);

// Expose the static catalog for callers that need to iterate.
const wc_client_server_entry_t* wc_client_server_catalog(void);

// Resolve a known server alias to its canonical domain. Returns NULL if unknown.
const char* wc_client_find_server_domain(const char* alias);

#ifdef __cplusplus
}
#endif
