// SPDX-License-Identifier: MIT
#ifndef WC_SECLOG_H
#define WC_SECLOG_H

#include <stdarg.h>

// Configure security logging on/off (thread-safe)
void wc_seclog_set_enabled(int enabled);

// Event logging API (same signatures as legacy to avoid churn)
void log_security_event(int event_type, const char* format, ...);
void monitor_connection_security(const char* host, int port, int result);

#endif // WC_SECLOG_H
