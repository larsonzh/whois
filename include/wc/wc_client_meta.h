#pragma once

#include "wc_opts.h"
#include "wc_config.h"

// Apply parsed CLI options back to a Config instance.
// This keeps whois_client.c thin and allows other modules
// to reuse the same mapping logic if needed.
void wc_client_apply_opts_to_config(const wc_opts_t* opts, Config* cfg);
