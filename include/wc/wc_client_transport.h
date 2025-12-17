// SPDX-License-Identifier: GPL-3.0-or-later
// Socket send/receive helpers preserved for legacy WHOIS execution paths.

#ifndef WC_CLIENT_TRANSPORT_H
#define WC_CLIENT_TRANSPORT_H

#include "wc_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Send a WHOIS query terminated with CRLF. Returns bytes sent or <0 on error.
int wc_client_send_query(const Config* config, int sockfd, const char* query);

// Receive a WHOIS response using configurable buffer/timeouts.
// Returns a newly allocated buffer (caller owns) or NULL on failure.
char* wc_client_receive_response(const Config* config, int sockfd);

#ifdef __cplusplus
}
#endif

#endif // WC_CLIENT_TRANSPORT_H
