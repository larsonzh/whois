// SPDX-License-Identifier: MIT
// lookup_exec_append.h - Output append helpers for lookup exec
#ifndef WC_LOOKUP_EXEC_APPEND_H_
#define WC_LOOKUP_EXEC_APPEND_H_

char* wc_lookup_exec_append_and_free(char* base, const char* extra);

char* wc_lookup_exec_append_body(char* combined, char** body, int suppress_current);

int wc_lookup_exec_append_redirect_header(char** combined,
                                          const char* next_host,
                                          const char* next_ip,
                                          int* additional_emitted,
                                          int emit_redirect_headers);

int wc_lookup_exec_update_redirect_header_ip(char** combined,
                                             const char* host,
                                             const char* ip);

#endif // WC_LOOKUP_EXEC_APPEND_H_
