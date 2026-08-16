// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#if defined(_MSC_VER)
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

#include "wc/wc_dns.h"
#include "wc/wc_redirect.h"
#include "wc/wc_server.h"
#include "lookup_exec_terminal_retry.h"
#include "lookup_internal.h"

void wc_terminal_retry_registry_init(struct wc_terminal_retry_registry* registry)
{
    if (registry)
        memset(registry, 0, sizeof(*registry));
}

void wc_terminal_retry_register(struct wc_terminal_retry_registry* registry,
                                const char* host,
                                unsigned int reason)
{
    if (!registry || !host || !*host || reason == WC_TERMINAL_RETRY_NONE)
        return;

    const char* rir = wc_guess_rir(host);
    const char* canonical = rir ? wc_dns_canonical_host_for_rir(rir) : NULL;
    if (!rir || strcasecmp(rir, "unknown") == 0 || strcasecmp(rir, "iana") == 0 ||
        !canonical || !*canonical)
        return;

    for (int i = 0; i < registry->count; ++i) {
        if (strcasecmp(registry->entries[i].host, canonical) == 0) {
            registry->entries[i].reasons |= reason;
            return;
        }
    }

    if (registry->count >= WC_TERMINAL_RETRY_MAX_RIRS)
        return;

    struct wc_terminal_retry_entry* entry = &registry->entries[registry->count++];
    snprintf(entry->host, sizeof(entry->host), "%s", canonical);
    entry->reasons = reason;
}

int wc_terminal_retry_has_reason(const struct wc_terminal_retry_registry* registry,
                                 unsigned int reason_mask)
{
    if (!registry || reason_mask == WC_TERMINAL_RETRY_NONE)
        return 0;
    for (int i = 0; i < registry->count; ++i) {
        if (registry->entries[i].reasons & reason_mask)
            return 1;
    }
    return 0;
}

int wc_terminal_retry_should_run(const struct wc_terminal_retry_registry* registry,
                                 int rir_cycle_exhausted,
                                 int redirect_cap_hit,
                                 int authority_unresolved,
                                 int recheck_guard_active)
{
    return registry && registry->count > 0 && rir_cycle_exhausted &&
        !redirect_cap_hit && authority_unresolved && !recheck_guard_active;
}

enum wc_terminal_retry_result wc_terminal_retry_classify_body(const char* body)
{
    if (!body || !body[0] || wc_lookup_body_is_semantically_empty(body) ||
        wc_lookup_body_contains_access_denied(body) ||
        wc_lookup_body_contains_rate_limit(body) ||
        wc_lookup_body_contains_temporary_denied(body) ||
        wc_lookup_body_contains_permanent_denied(body)) {
        return WC_TERMINAL_RETRY_NO_RESULT;
    }

    if (is_authoritative_response(body) &&
        !wc_lookup_body_has_strong_redirect_hint(body) &&
        !wc_lookup_body_contains_erx_iana_marker(body)) {
        return WC_TERMINAL_RETRY_AUTHORITATIVE;
    }

    return WC_TERMINAL_RETRY_DETERMINABLE;
}

enum wc_terminal_retry_result wc_terminal_retry_attempt(
    const struct wc_terminal_retry_entry* entry,
    const struct wc_query* query,
    const struct wc_lookup_opts* options,
    struct wc_result* retry_result)
{
    if (!entry || !entry->host[0] || !query || !query->raw || !options || !retry_result)
        return WC_TERMINAL_RETRY_NO_RESULT;

    struct wc_lookup_opts retry_options = *options;
    struct wc_query retry_query = {
        .raw = query->raw,
        .start_server = entry->host,
        .port = query->port > 0 ? query->port : 43
    };

    memset(retry_result, 0, sizeof(*retry_result));
    retry_options.no_redirect = 1;
    retry_options.max_hops = 1;

    int previous_recheck_guard = wc_lookup_erx_baseline_recheck_guard_get();
    wc_lookup_erx_baseline_recheck_guard_set(1);
    int retry_rc = wc_lookup_execute(&retry_query, &retry_options, retry_result);
    wc_lookup_erx_baseline_recheck_guard_set(previous_recheck_guard);

    if (retry_rc != 0) {
        return WC_TERMINAL_RETRY_NO_RESULT;
    }
    return wc_terminal_retry_classify_body(retry_result->body);
}