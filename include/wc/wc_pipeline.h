// High-level pipeline facade; single entrypoint for a full query run
#ifndef WC_PIPELINE_H_
#define WC_PIPELINE_H_

#include <stdio.h>
#include "wc_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

// Run pipeline with given options; returns 0 on success
int wc_pipeline_run(const wc_opts_t* opts, FILE* in, FILE* out, FILE* err);

#ifdef __cplusplus
}
#endif

#endif // WC_PIPELINE_H_
