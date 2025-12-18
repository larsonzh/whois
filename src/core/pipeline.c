#include <stdio.h>
#include "wc/wc_pipeline.h"
#include "wc/wc_client_flow.h"

// Temporary thin wrapper around existing client_flow dispatch. This allows
// main() to delegate to a single pipeline entry while we migrate batch
// runner/pipeline logic without changing behavior.
int wc_pipeline_run(const wc_opts_t* opts, int argc, char* const* argv, Config* config)
{
    return wc_client_run_with_mode(opts, argc, argv, config);
}
