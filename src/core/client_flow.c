#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_client_flow.h"
#include "wc/wc_backoff.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"
#include "wc/wc_fold.h"
#include "wc/wc_lookup.h"
#include "wc/wc_output.h"
#include "wc/wc_query_exec.h"
#include "wc/wc_runtime.h"

extern Config g_config;

static const char* const k_wc_batch_default_hosts[] = {
    "whois.iana.org",
    "whois.arin.net",
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.lacnic.net",
    "whois.afrinic.net"
};

static const char* wc_client_normalize_batch_host(const char* host)
{
    if (!host || !*host)
        return k_wc_batch_default_hosts[0];
    if (!wc_dns_is_ip_literal(host)) {
        const char* canon = wc_dns_canonical_host_for_rir(host);
        if (canon)
            return canon;
    }
    return host;
}

static int wc_client_batch_host_list_contains(const char* const* hosts,
        size_t count,
        const char* candidate)
{
    if (!candidate)
        return 1;
    for (size_t i = 0; i < count; ++i) {
        if (!hosts[i])
            continue;
        if (strcasecmp(hosts[i], candidate) == 0)
            return 1;
    }
    return 0;
}

static size_t wc_client_build_batch_health_hosts(const char* server_host,
        const char* out[],
        size_t capacity)
{
    size_t count = 0;
    if (!out || capacity == 0)
        return 0;
    const char* primary = wc_client_normalize_batch_host(server_host);
    if (primary && *primary)
        out[count++] = primary;
    for (size_t i = 0; i < sizeof(k_wc_batch_default_hosts) / sizeof(k_wc_batch_default_hosts[0]); ++i) {
        if (count >= capacity)
            break;
        const char* candidate = k_wc_batch_default_hosts[i];
        if (!candidate)
            continue;
        if (wc_client_batch_host_list_contains(out, count, candidate))
            continue;
        out[count++] = candidate;
    }
    return count;
}

static void wc_client_log_batch_snapshot_entry(const char* host,
        const char* family_label,
        wc_dns_health_state_t state,
        const wc_dns_health_snapshot_t* snap)
{
    if (!host || !family_label || !snap)
        return;
    if (state == WC_DNS_HEALTH_OK && snap->consecutive_failures == 0)
        return;
    fprintf(stderr,
        "[DNS-BATCH] host=%s family=%s state=%s consec_fail=%d penalty_ms_left=%ld\n",
        host,
        family_label,
        (state == WC_DNS_HEALTH_PENALIZED) ? "penalized" : "ok",
        snap->consecutive_failures,
        (long)snap->penalty_ms_left);
}

static void wc_client_log_batch_host_health(const char* server_host)
{
    if (!wc_is_debug_enabled())
        return;
    const char* hosts[16];
    wc_backoff_host_health_t health[16];
    size_t host_count = wc_client_build_batch_health_hosts(server_host, hosts, 16);
    size_t produced = wc_backoff_collect_host_health(hosts, host_count, health, 16);
    for (size_t i = 0; i < produced; ++i) {
        const wc_backoff_host_health_t* entry = &health[i];
        wc_client_log_batch_snapshot_entry(entry->host, "ipv4",
            entry->ipv4_state, &entry->ipv4);
        wc_client_log_batch_snapshot_entry(entry->host, "ipv6",
            entry->ipv6_state, &entry->ipv6);
    }
}

int wc_client_run_batch_stdin(const char* server_host, int port) {
    if (g_config.debug)
        printf("[DEBUG] ===== BATCH STDIN MODE START =====\n");

    char linebuf[512];
    while (fgets(linebuf, sizeof(linebuf), stdin)) {
        char* p = linebuf;
        while (*p && (*p == ' ' || *p == '\t'))
            p++;
        char* start = p;
        size_t len = strlen(start);
        while (len > 0 && (start[len - 1] == '\n' ||
                start[len - 1] == '\r' || start[len - 1] == ' ' ||
                start[len - 1] == '\t')) {
            start[--len] = '\0';
        }

        if (len == 0)
            continue;
        if (start[0] == '#')
            continue;

        wc_client_log_batch_host_health(server_host);

        if (wc_handle_suspicious_query(start, 1))
            continue;

        const char* query = start;
        struct wc_result res;
        int lrc = wc_execute_lookup(query, server_host, port, &res);

        if (!lrc && res.body) {
            char* result = res.body;
            res.body = NULL;
            if (wc_is_debug_enabled())
                fprintf(stderr,
                    "[TRACE][batch] after header; body_ptr=%p len=%zu (stage=initial)\n",
                    (void*)result, res.body_len);
            if (!g_config.fold_output && !g_config.plain_mode) {
                const char* via_host = res.meta.via_host[0]
                    ? res.meta.via_host
                    : (server_host ? server_host : "whois.iana.org");
                const char* via_ip = res.meta.via_ip[0]
                    ? res.meta.via_ip
                    : NULL;
                if (via_ip)
                    wc_output_header_via_ip(query, via_host, via_ip);
                else
                    wc_output_header_via_unknown(query, via_host);
            }
            char* filtered = wc_apply_response_filters(query, result, 1);
            free(result);
            result = filtered;

            char* authoritative_display_owned = NULL;
            const char* authoritative_display =
                (res.meta.authoritative_host[0]
                    ? res.meta.authoritative_host
                    : NULL);
            if (authoritative_display &&
                    wc_dns_is_ip_literal(authoritative_display)) {
                char* mapped =
                    wc_dns_rir_fallback_from_ip(authoritative_display);
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
                    if (authoritative_display && *authoritative_display) {
                        const char* auth_ip =
                            (res.meta.authoritative_ip[0]
                                ? res.meta.authoritative_ip
                                : "unknown");
                        wc_output_tail_authoritative_ip(
                            authoritative_display, auth_ip);
                    } else {
                        wc_output_tail_unknown_unknown();
                    }
                }
            }
            if (authoritative_display_owned)
                free(authoritative_display_owned);
            free(result);
        } else {
            wc_report_query_failure(query, server_host,
                res.meta.last_connect_errno);
        }
        wc_lookup_result_free(&res);
        wc_runtime_housekeeping_tick();
    }
    return 0;
}

int wc_client_run_with_mode(const wc_opts_t* opts,
        int argc,
        char* const* argv,
        Config* config) {
    int batch_mode = 0;
    const char* single_query = NULL;

    int meta_rc = wc_client_handle_meta_requests(opts, argv[0], config);
    if (meta_rc != 0) {
        return (meta_rc > 0) ? WC_EXIT_SUCCESS : WC_EXIT_FAILURE;
    }

    if (wc_client_detect_mode_and_query(opts, argc, (char**)argv,
            &batch_mode, &single_query, config) != 0) {
        return wc_client_handle_usage_error(argv[0], config);
    }

    wc_runtime_init_resources();

    const char* server_host = opts->host;
    int port = opts->port;
    if (!batch_mode) {
        return wc_client_run_single_query(single_query, server_host, port);
    }
    return wc_client_run_batch_stdin(server_host, port);
}

int wc_client_handle_usage_error(const char* progname, const Config* cfg)
{
	return wc_client_exit_usage_error(progname, cfg);
}
