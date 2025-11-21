// Basic types and error/exit codes for whois client modularization
#ifndef WC_TYPES_H_
#define WC_TYPES_H_

#include <stddef.h>
#include <stdint.h>

typedef enum wc_err_e {
    WC_OK = 0,
    WC_ERR_INVALID = 1,
    WC_ERR_IO = 2,
    WC_ERR_TIMEOUT = 3,
    WC_ERR_INTERNAL = 4
} wc_err_t;

// Process exit codes (C plan phase 1: naming only, values keep
// compatibility with historical behavior and existing scripts).
//  - WC_EXIT_SUCCESS: successful completion.
//  - WC_EXIT_FAILURE: generic error (parse/validation/runtime failure).
//
// NOTE: Ctrl-C / SIGINT is handled in signal.c via exit(130) and
// stays as-is; do not reuse 130 here for non-signal exits.
typedef enum wc_exit_code_e {
    WC_EXIT_SUCCESS = 0,
    WC_EXIT_FAILURE = 1
} wc_exit_code_t;

#endif // WC_TYPES_H_
