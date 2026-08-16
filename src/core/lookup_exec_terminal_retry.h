// SPDX-License-Identifier: MIT
#ifndef WC_LOOKUP_EXEC_TERMINAL_RETRY_H_
#define WC_LOOKUP_EXEC_TERMINAL_RETRY_H_

#include "wc/wc_lookup.h"

#define WC_TERMINAL_RETRY_MAX_RIRS 5

enum wc_terminal_retry_reason {
    WC_TERMINAL_RETRY_NONE = 0,
    WC_TERMINAL_RETRY_DENIED = 1u << 0,
    WC_TERMINAL_RETRY_RATE_LIMIT = 1u << 1,
    WC_TERMINAL_RETRY_EMPTY = 1u << 2
};

enum wc_terminal_retry_result {
    WC_TERMINAL_RETRY_NO_RESULT = 0,
    WC_TERMINAL_RETRY_DETERMINABLE = 1,
    WC_TERMINAL_RETRY_AUTHORITATIVE = 2
};

struct wc_terminal_retry_entry {
    char host[128];
    unsigned int reasons;
};

struct wc_terminal_retry_registry {
    struct wc_terminal_retry_entry entries[WC_TERMINAL_RETRY_MAX_RIRS];
    int count;
};

void wc_terminal_retry_registry_init(struct wc_terminal_retry_registry* registry);
void wc_terminal_retry_register(struct wc_terminal_retry_registry* registry,
                                const char* host,
                                unsigned int reason);
int wc_terminal_retry_has_reason(const struct wc_terminal_retry_registry* registry,
                                 unsigned int reason_mask);
int wc_terminal_retry_should_run(const struct wc_terminal_retry_registry* registry,
                                 int rir_cycle_exhausted,
                                 int redirect_cap_hit,
                                 int authority_unresolved,
                                 int recheck_guard_active);
enum wc_terminal_retry_result wc_terminal_retry_classify_body(const char* body);
enum wc_terminal_retry_result wc_terminal_retry_attempt(
    const struct wc_terminal_retry_entry* entry,
    const struct wc_query* query,
    const struct wc_lookup_opts* options,
    struct wc_result* retry_result);

#endif