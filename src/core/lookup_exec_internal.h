// SPDX-License-Identifier: MIT
// lookup_exec_internal.h - Internal entry for lookup execution
#ifndef WC_LOOKUP_EXEC_INTERNAL_H_
#define WC_LOOKUP_EXEC_INTERNAL_H_

#include "wc/wc_lookup.h"

int wc_lookup_exec_run(const struct wc_query* q,
                       const struct wc_lookup_opts* opts,
                       struct wc_result* out);

#endif // WC_LOOKUP_EXEC_INTERNAL_H_
