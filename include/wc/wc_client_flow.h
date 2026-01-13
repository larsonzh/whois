#ifndef WC_CLIENT_FLOW_H
#define WC_CLIENT_FLOW_H

#include "wc_config.h"
#include "wc_opts.h"
#include "wc_net.h"
#include "wc_client_runner.h"
#include "wc_lookup.h"

typedef struct wc_client_render_opts {
    int debug;
    int fold_output;
    int plain_mode;
    const char* fold_sep;
    int fold_upper;
} wc_client_render_opts_t;

static inline wc_client_render_opts_t wc_client_render_opts_init(
    const Config* cfg)
{
    wc_client_render_opts_t opts;
    opts.debug = cfg && cfg->debug;
    opts.fold_output = cfg && cfg->fold_output;
    opts.plain_mode = cfg && cfg->plain_mode;
    opts.fold_sep = (cfg && cfg->fold_sep) ? cfg->fold_sep : " ";
    opts.fold_upper = cfg ? cfg->fold_upper : 0;
    return opts;
}

#ifdef __cplusplus
extern "C" {
#endif

int wc_client_run_batch_stdin(const Config* config,
                              const wc_client_render_opts_t* render_opts,
                              const char* server_host,
                              int port,
                              wc_net_context_t* net_ctx);

// Shared render glue used by pipeline facade
void wc_client_render_response(const Config* cfg,
                               const wc_client_render_opts_t* render_opts,
                               const char* query,
                               const char* via_host_default,
                               struct wc_result* res,
                               int in_batch);

int wc_client_run_with_mode(const wc_opts_t* opts,
                            int argc,
                            char* const* argv,
                            const Config* config);

int wc_client_handle_usage_error(const char* progname, const Config* cfg);

#ifdef __cplusplus
}
#endif

#endif /* WC_CLIENT_FLOW_H */
