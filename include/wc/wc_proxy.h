#ifndef WC_PROXY_H
#define WC_PROXY_H

#include <stdint.h>

#include "wc_config.h"
#include "wc_net.h"
#include "wc_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wc_proxy_result {
    WC_PROXY_RESULT_SUCCEEDED = 0,
    WC_PROXY_RESULT_TCP_FAILURE,
    WC_PROXY_RESULT_TIMEOUT,
    WC_PROXY_RESULT_AUTH_REQUIRED,
    WC_PROXY_RESULT_REJECTED,
    WC_PROXY_RESULT_UPSTREAM_FAILURE,
    WC_PROXY_RESULT_PROTOCOL_FAILURE,
    WC_PROXY_RESULT_UNSUPPORTED
} wc_proxy_result_t;

int wc_proxy_should_proxy(const Config* config,
                          const char* target_host,
                          const char* target_address,
                          int target_port);
int wc_proxy_http_connect_transport(wc_transport_t* transport,
                                    const wc_proxy_config_t* proxy,
                                    const char* target_address,
                                    uint16_t target_port,
                                    uint64_t deadline_ms,
                                    int* status_code);
int wc_proxy_dial_hop(const Config* config,
                      wc_net_context_t* net_ctx,
                      const char* target_host,
                      const char* target_address,
                      uint16_t target_port,
                      int timeout_ms,
                      int retries,
                      struct wc_net_info* out,
                      int* used_proxy,
                      wc_proxy_result_t* proxy_result);
const char* wc_proxy_result_name(wc_proxy_result_t result);
int wc_proxy_selftest(void);

#ifdef __cplusplus
}
#endif

#endif // WC_PROXY_H
