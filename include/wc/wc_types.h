// Basic types and error codes for whois client modularization
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

#endif // WC_TYPES_H_
