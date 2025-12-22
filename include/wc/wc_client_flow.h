#ifndef WC_CLIENT_FLOW_H
#define WC_CLIENT_FLOW_H

#include "wc_config.h"
#include "wc_opts.h"
#include "wc_net.h"
#include "wc_client_runner.h"

#ifdef __cplusplus
extern "C" {
#endif

int wc_client_run_batch_stdin(const Config* config,
                              const char* server_host,
                              int port,
                              wc_net_context_t* net_ctx);

int wc_client_run_with_mode(const wc_opts_t* opts,
                            int argc,
                            char* const* argv,
                            const Config* config);

int wc_client_handle_usage_error(const char* progname, const Config* cfg);

#ifdef __cplusplus
}
#endif

#endif /* WC_CLIENT_FLOW_H */
