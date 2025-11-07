// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <stdarg.h>

#include "wc/wc_seclog.h"

// Internal enable flag (atomic via mutex guarding)
static int g_enabled = 0;
static pthread_mutex_t g_enabled_mutex = PTHREAD_MUTEX_INITIALIZER;

void wc_seclog_set_enabled(int enabled) {
    pthread_mutex_lock(&g_enabled_mutex);
    g_enabled = (enabled != 0);
    pthread_mutex_unlock(&g_enabled_mutex);
}

// Simple rate limiter to avoid stderr flood during attacks
// Windowed tokens: allow up to 20 events per second
enum { SECLOG_CAPACITY_PER_SEC = 20 };
static pthread_mutex_t sec_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t window_start = 0;
static int tokens = SECLOG_CAPACITY_PER_SEC;
static unsigned int suppressed = 0;
static time_t last_summary = 0; // last time we printed a suppression summary

static int wc_seclog_is_enabled_nolock(void) {
    return g_enabled;
}

void log_security_event(int event_type, const char* format, ...) {
    // fast path check
    pthread_mutex_lock(&g_enabled_mutex);
    int enabled = wc_seclog_is_enabled_nolock();
    pthread_mutex_unlock(&g_enabled_mutex);
    if (!enabled) return;

    time_t now = time(NULL);

    pthread_mutex_lock(&sec_log_mutex);
    if (window_start == 0 || now - window_start >= 1) {
        // New one-second window; if any were suppressed in previous window, summarize once
        if (suppressed > 0) {
            struct tm* ts = localtime(&now);
            fprintf(stderr,
                    "[%04d-%02d-%02d %02d:%02d:%02d] [SECURITY] [RATE_LIMIT] suppressed %u event(s) in the last 1s\n",
                    ts ? ts->tm_year + 1900 : 0, ts ? ts->tm_mon + 1 : 0, ts ? ts->tm_mday : 0,
                    ts ? ts->tm_hour : 0, ts ? ts->tm_min : 0, ts ? ts->tm_sec : 0,
                    suppressed);
        }
        window_start = now;
        tokens = SECLOG_CAPACITY_PER_SEC;
        suppressed = 0;
    }

    if (tokens <= 0) {
        suppressed++;
        // Additionally, print a summary at most once every 5 seconds to give feedback in long floods
        if (now - last_summary >= 5) {
            struct tm* ts = localtime(&now);
            fprintf(stderr,
                    "[%04d-%02d-%02d %02d:%02d:%02d] [SECURITY] [RATE_LIMIT] further events are being suppressed...\n",
                    ts ? ts->tm_year + 1900 : 0, ts ? ts->tm_mon + 1 : 0, ts ? ts->tm_mday : 0,
                    ts ? ts->tm_hour : 0, ts ? ts->tm_min : 0, ts ? ts->tm_sec : 0);
            last_summary = now;
        }
        pthread_mutex_unlock(&sec_log_mutex);
        return;
    }

    // Consume a token and proceed to log
    tokens--;

    const char* event_names[] = {
        "",
        "INVALID_INPUT",
        "SUSPICIOUS_QUERY",
        "CONNECTION_ATTACK",
        "RESPONSE_TAMPERING",
        "RATE_LIMIT_HIT"
    };

    const char* event_name = (event_type >= 1 && event_type <= 5) ? event_names[event_type] : "UNKNOWN";

    va_list args;
    va_start(args, format);

    struct tm* t = localtime(&now);
    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] [SECURITY] [%s] ",
            t ? t->tm_year + 1900 : 0, t ? t->tm_mon + 1 : 0, t ? t->tm_mday : 0,
            t ? t->tm_hour : 0, t ? t->tm_min : 0, t ? t->tm_sec : 0, event_name);

    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
    pthread_mutex_unlock(&sec_log_mutex);
}

void monitor_connection_security(const char* host, int port, int result) {
    // fast path check
    pthread_mutex_lock(&g_enabled_mutex);
    int enabled = wc_seclog_is_enabled_nolock();
    pthread_mutex_unlock(&g_enabled_mutex);
    if (!enabled) return;

    static time_t last_connection_time = 0;
    static int connection_count = 0;
    time_t now = time(NULL);

    // Reset counter if more than 10 seconds have passed
    if (now - last_connection_time > 10) {
        connection_count = 0;
    }

    connection_count++;
    last_connection_time = now;

    // Log connection attempts for security analysis
    if (result == 0) {
        log_security_event(3 /*CONNECTION_ATTACK*/, 
                          "Connection attempt to %s:%d (success) - total connections in last 10s: %d", 
                          host, port, connection_count);
    } else if (result == -1) {
        log_security_event(3 /*CONNECTION_ATTACK*/, 
                          "Connection attempt to %s:%d (failed) - total connections in last 10s: %d", 
                          host, port, connection_count);
    }
    // Note: result == -2 indicates connection attempt started, don't log

    // Detect potential connection flooding
    if (connection_count > 10) {
        log_security_event(5 /*RATE_LIMIT_HIT*/, 
                          "High connection rate detected: %d connections in last 10 seconds", 
                          connection_count);
    }
}
