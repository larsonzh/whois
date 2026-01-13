// High-level pipeline facade; single entrypoint for a full query run
#ifndef WC_PIPELINE_H_
#define WC_PIPELINE_H_

#include <stdio.h>
#include "wc_opts.h"
#include "wc_config.h"
#include "wc_client_flow.h"
#include "wc_lookup.h"

#ifdef __cplusplus
extern "C" {
#endif

// Run pipeline with given options and config; returns 0 on success
int wc_pipeline_run(const wc_opts_t* opts, int argc, char* const* argv, const Config* config);

// Render WHOIS response via the pipeline glue (title/grep/fold/sanitize/tail)
void wc_pipeline_render(const Config* cfg,
						const wc_client_render_opts_t* render_opts,
						const char* query,
						const char* via_host_default,
						struct wc_result* res,
						int in_batch);

#ifdef __cplusplus
}
#endif

#endif // WC_PIPELINE_H_
