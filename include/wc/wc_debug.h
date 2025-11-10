// SPDX-License-Identifier: MIT
#ifndef WC_DEBUG_H
#define WC_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

// Query global debug flag without exposing internal config structure.
int wc_is_debug_enabled(void);

#ifdef __cplusplus
}
#endif

#endif // WC_DEBUG_H
