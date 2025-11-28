#pragma once

#include "wc_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Print usage text and return WC_EXIT_FAILURE (used for CLI errors).
int wc_client_exit_usage_error(const char* progname, const Config* cfg);

#ifdef __cplusplus
}
#endif
