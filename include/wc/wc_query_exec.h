#ifndef WC_QUERY_EXEC_H
#define WC_QUERY_EXEC_H

#include "wc_types.h"
#include "wc_lookup.h"
#include "wc_title.h"
#include "wc_grep.h"
#include "wc_config.h"
#include "wc_opts.h"
#include "wc_net.h"

#ifdef __cplusplus
extern "C" {
#endif

int wc_execute_lookup(const Config* config,
                      const char* query,
                      const char* server_host,
                      int port,
                      wc_net_context_t* net_ctx,
                      struct wc_result* out_res);

int wc_handle_suspicious_query(const char* query, int in_batch);
int wc_handle_private_ip(const Config* config,
                         const char* query,
                         const char* ip,
                         int in_batch);
void wc_report_query_failure(const Config* config,
                             const char* query,
                             const char* server_host,
                             int err);
char* wc_apply_response_filters(const Config* config,
                                const char* query,
                                const char* raw_response,
                                int in_batch);

// Execute a single query end-to-end in non-batch mode. This wraps
// suspicious checks, lookup execution, response filtering,
// header/tail printing and cache cleanup.
int wc_client_run_single_query(const Config* config,
        const char* query,
        const char* server_host,
        int port,
        wc_net_context_t* net_ctx);

#ifdef __cplusplus
}
#endif

#endif /* WC_QUERY_EXEC_H */
