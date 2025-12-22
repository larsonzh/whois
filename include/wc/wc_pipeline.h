// High-level pipeline facade; single entrypoint for a full query run
#ifndef WC_PIPELINE_H_
#define WC_PIPELINE_H_

#include <stdio.h>
#include "wc_opts.h"
#include "wc_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Run pipeline with given options and config; returns 0 on success
int wc_pipeline_run(const wc_opts_t* opts, int argc, char* const* argv, const Config* config);

#ifdef __cplusplus
}
#endif

#endif // WC_PIPELINE_H_
