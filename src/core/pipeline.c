#include <stdio.h>
#include "wc/wc_pipeline.h"
#include "wc/wc_client_flow.h"

// Temporary thin wrapper around existing client_flow dispatch. This allows
// main() to delegate to a single pipeline entry while we migrate batch
// runner/pipeline logic without changing behavior.
int wc_pipeline_run(const wc_opts_t* opts, int argc, char* const* argv, const Config* config)
{
    return wc_client_run_with_mode(opts, argc, argv, config);
}

// Thin facade to keep render/filters wiring centralized for future pipeline moves.
void wc_pipeline_render(const Config* cfg,
                        const wc_client_render_opts_t* render_opts,
                        const char* query,
                        const char* via_host_default,
                        struct wc_result* res,
                        int in_batch)
{
    wc_client_render_response(cfg, render_opts, query, via_host_default, res, in_batch);
}
