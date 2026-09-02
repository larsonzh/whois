#ifndef WC_TLS_H
#define WC_TLS_H

#include <stdint.h>

#include "wc_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wc_tls_result {
    WC_TLS_RESULT_SUCCEEDED = 0,
    WC_TLS_RESULT_UNSUPPORTED,
    WC_TLS_RESULT_CA_CONFIG_FAILURE,
    WC_TLS_RESULT_PEER_VERIFY_FAILURE,
    WC_TLS_RESULT_HANDSHAKE_FAILURE,
    WC_TLS_RESULT_TIMEOUT,
    WC_TLS_RESULT_IO_FAILURE,
    WC_TLS_RESULT_PROTOCOL_FAILURE
} wc_tls_result_t;

wc_tls_result_t wc_tls_wrap_client(int fd,
                                   const char* peer_name,
                                   uint64_t deadline_ms,
                                   wc_transport_t** out_transport);
const char* wc_tls_result_name(wc_tls_result_t result);
int wc_tls_selftest(void);

#ifdef __cplusplus
}
#endif

#endif // WC_TLS_H
