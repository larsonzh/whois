#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "wc/wc_signal.h"
#include "wc/wc_types.h"
#include "wc/wc_config.h"
#include "wc/wc_seclog.h"
#include "wc/wc_debug.h"
#include "wc/wc_output.h"
#include "wc/wc_util.h"
#include "wc/wc_cache.h"

extern Config g_config;

static volatile sig_atomic_t g_shutdown_requested = 0;
static pthread_mutex_t signal_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char* host;
    int port;
    int sockfd;
    time_t start_time;
} ActiveConnection;

static ActiveConnection g_active_conn = {NULL, 0, -1, 0};
static pthread_mutex_t active_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int sig);

void wc_signal_setup_handlers(void) {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = signal_handler;

    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_flags = SA_RESTART;
    sigaction(SIGPIPE, &sa, NULL);

    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);

    if (g_config.debug) {
        wc_output_log_message("DEBUG", "Signal handlers installed");
    }
}

static void wc_signal_register_active_connection_internal(const char* host, int port, int sockfd) {
    pthread_mutex_lock(&active_conn_mutex);
    if (g_active_conn.host) {
        free(g_active_conn.host);
    }
    g_active_conn.host = host ? strdup(host) : NULL;
    g_active_conn.port = port;
    g_active_conn.sockfd = sockfd;
    g_active_conn.start_time = time(NULL);
    pthread_mutex_unlock(&active_conn_mutex);
}

static void wc_signal_unregister_active_connection_internal(void) {
    pthread_mutex_lock(&active_conn_mutex);
    if (g_active_conn.host) {
        free(g_active_conn.host);
        g_active_conn.host = NULL;
    }
    if (g_active_conn.sockfd != -1) {
        wc_safe_close(&g_active_conn.sockfd, "unregister_active_connection");
    }
    g_active_conn.port = 0;
    g_active_conn.start_time = 0;
    pthread_mutex_unlock(&active_conn_mutex);
}

static void signal_handler(int sig) {
    const char* sig_name = "UNKNOWN";
    switch(sig) {
        case SIGINT:  sig_name = "SIGINT"; break;
        case SIGTERM: sig_name = "SIGTERM"; break;
        case SIGHUP:  sig_name = "SIGHUP"; break;
        case SIGPIPE: sig_name = "SIGPIPE"; break;
    }

    wc_output_log_message("INFO", "Received signal: %s (%d)", sig_name, sig);

    pthread_mutex_lock(&signal_mutex);

    if (sig == SIGPIPE) {
        wc_output_log_message("WARN", "Broken pipe detected, connection may be closed");
    } else {
        g_shutdown_requested = 1;

        pthread_mutex_lock(&active_conn_mutex);
        if (g_active_conn.sockfd != -1) {
            wc_output_log_message("DEBUG", "Closing active connection due to signal");
            wc_safe_close(&g_active_conn.sockfd, "signal_handler");
        }
        pthread_mutex_unlock(&active_conn_mutex);

        const char msg[] = "\n[INFO] Terminated by user (Ctrl-C). Exiting...\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg)-1);

        if (g_config.security_logging) {
            log_security_event(SEC_EVENT_CONNECTION_ATTACK,
                               "Process termination requested by signal: %s", sig_name);
        }

        exit(WC_EXIT_SIGINT);
    }

    pthread_mutex_unlock(&signal_mutex);
}

void wc_signal_atexit_cleanup(void) {
    if (g_config.debug) {
        wc_output_log_message("DEBUG", "Performing signal cleanup");
    }
    wc_signal_unregister_active_connection_internal();
    if (g_config.debug >= 2) {
        wc_cache_neg_stats_t stats = {0, 0};
        wc_cache_get_negative_stats(&stats);
        fprintf(stderr,
            "[DNS] negative cache: hits=%d, sets=%d, ttl=%d, disabled=%d\n",
            stats.hits,
            stats.sets,
            g_config.dns_neg_ttl,
            g_config.dns_neg_cache_disable);
    }
}

void wc_signal_register_active_connection(const char* host, int port, int sockfd) {
    wc_signal_register_active_connection_internal(host, port, sockfd);
}

void wc_signal_unregister_active_connection(void) {
    wc_signal_unregister_active_connection_internal();
}

int wc_signal_should_terminate(void) {
    return g_shutdown_requested;
}
