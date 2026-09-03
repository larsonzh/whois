#ifndef WC_TLS_COMPANION_H
#define WC_TLS_COMPANION_H

#include "wc_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

int wc_tls_companion_maybe_exec(int argc, char* argv[], const wc_opts_t* opts);

#ifdef __cplusplus
}
#endif

#endif // WC_TLS_COMPANION_H