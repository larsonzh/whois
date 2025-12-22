// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef WC_CLIENT_FRONTEND_H
#define WC_CLIENT_FRONTEND_H

#include "wc_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

// Front-end entry adapter: wraps runner bootstrap + pipeline dispatch.
// Returns WC_EXIT_* codes (see wc_types.h).
int wc_client_frontend_run(int argc, char* argv[], const wc_opts_t* opts);

#ifdef __cplusplus
}
#endif

#endif // WC_CLIENT_FRONTEND_H