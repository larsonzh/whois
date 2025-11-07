#include <stdio.h>
#include "wc/wc_pipeline.h"

// Initial scaffolding: no behavior change yet. CLI still uses legacy path.
int wc_pipeline_run(const wc_opts_t* opts, FILE* in, FILE* out, FILE* err) {
    (void)opts;
    (void)in;
    (void)out;
    (void)err;
    // Placeholder returning success; real implementation will wire modules.
    return 0;
}
