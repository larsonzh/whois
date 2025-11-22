#ifndef WC_QUERY_EXEC_H
#define WC_QUERY_EXEC_H

#include "wc_types.h"
#include "wc_lookup.h"
#include "wc_title.h"
#include "wc_grep.h"
#include "wc_config.h"
#include "wc_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

int wc_execute_lookup(const char* query,
                      const char* server_host,
                      int port,
                      struct wc_result* out_res);

int wc_handle_suspicious_query(const char* query, int in_batch);
int wc_handle_private_ip(const char* query, const char* ip, int in_batch);
void wc_report_query_failure(const char* query,
                             const char* server_host,
                             int err);
char* wc_apply_response_filters(const char* query,
                                const char* raw_response,
                                int in_batch);

// Execute a single query end-to-end in non-batch mode. This wraps
// suspicious checks, lookup execution, response filtering,
// header/tail printing and cache cleanup.
int wc_client_run_single_query(const char* query,
        const char* server_host,
        int port);

// Execute batch queries from stdin, line by line. This mirrors
// the legacy wc_run_batch_stdin behavior used in batch mode.
int wc_client_run_batch_stdin(const char* server_host, int port);

// High-level orchestrator that mirrors the legacy main-loop logic
// in whois_client.c for determining batch vs single mode and
// dispatching queries accordingly. This is part of the B-plan
// refactor to gradually thin the CLI entry.
int wc_client_run_with_mode(const wc_opts_t* opts,
                int argc,
                char* const* argv,
                Config* config);

#ifdef __cplusplus
}
#endif

#endif /* WC_QUERY_EXEC_H */
