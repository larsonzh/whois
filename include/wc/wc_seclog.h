// SPDX-License-Identifier: MIT
#ifndef WC_SECLOG_H
#define WC_SECLOG_H

#include <stdarg.h>

// Configure security logging on/off (thread-safe)
void wc_seclog_set_enabled(int enabled);

// Security event type definitions (shared across modules)
#define SEC_EVENT_INVALID_INPUT      1
#define SEC_EVENT_SUSPICIOUS_QUERY   2
#define SEC_EVENT_CONNECTION_ATTACK  3
#define SEC_EVENT_RESPONSE_TAMPERING 4
#define SEC_EVENT_RATE_LIMIT_HIT     5

// Event logging API (same signatures as legacy to avoid churn)
void log_security_event(int event_type, const char* format, ...);
void monitor_connection_security(const char* host, int port, int result);

#endif // WC_SECLOG_H
