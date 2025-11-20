#ifndef WC_QUERY_EXEC_H
#define WC_QUERY_EXEC_H

#include "wc_types.h"
#include "wc_lookup.h"
#include "wc_title.h"
#include "wc_grep.h"

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

#ifdef __cplusplus
}
#endif

#endif /* WC_QUERY_EXEC_H */
