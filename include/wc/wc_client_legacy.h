// SPDX-License-Identifier: GPL-3.0-or-later
// Legacy WHOIS query orchestration helpers kept for compatibility.

#ifndef WC_CLIENT_LEGACY_H
#define WC_CLIENT_LEGACY_H

#include "wc_config.h"

#ifdef __cplusplus
extern "C" {
#endif

char* wc_client_perform_legacy_query(const Config* config,
                                     const char* target,
                                     int port,
                                     const char* query,
                                     char** authoritative_server_out,
                                     char** first_server_host_out,
                                     char** first_server_ip_out);

#ifdef __cplusplus
}
#endif

#endif // WC_CLIENT_LEGACY_H
