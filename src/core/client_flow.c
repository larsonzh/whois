#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wc/wc_client_flow.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"
#include "wc/wc_fold.h"
#include "wc/wc_lookup.h"
#include "wc/wc_output.h"
#include "wc/wc_query_exec.h"
#include "wc/wc_runtime.h"

extern Config g_config;

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
            wc_lookup_result_free(&res);
        } else {
            wc_report_query_failure(query, server_host,
                res.meta.last_connect_errno);
            wc_lookup_result_free(&res);
        }
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
        return WC_EXIT_FAILURE;
    }

    wc_runtime_init_resources();

    const char* server_host = opts->host;
    int port = opts->port;
    if (!batch_mode) {
        return wc_client_run_single_query(single_query, server_host, port);
    }
    return wc_client_run_batch_stdin(server_host, port);
}
