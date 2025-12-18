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
#include "wc/wc_runtime.h"

static const Config* g_signal_config = NULL;

static const Config* wc_signal_config(void)
{
    return g_signal_config;
}

static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile sig_atomic_t g_shutdown_announced = 0;
static volatile sig_atomic_t g_shutdown_handled = 0;

typedef struct {
    char* host;
    int port;
    int sockfd;
    time_t start_time;
} ActiveConnection;

static ActiveConnection g_active_conn = {NULL, 0, -1, 0};
static volatile sig_atomic_t g_active_fd = -1;
static pthread_mutex_t active_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int sig);

void wc_signal_setup_handlers(void) {
    const Config* cfg = wc_signal_config();
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

    if (cfg && cfg->debug) {
        wc_output_log_message("DEBUG", "Signal handlers installed");
    }
}

void wc_signal_set_config(const Config* config)
{
    g_signal_config = config;
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
    g_active_fd = sockfd;
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
    g_active_fd = -1;
    g_active_conn.port = 0;
    g_active_conn.start_time = 0;
    pthread_mutex_unlock(&active_conn_mutex);
}

static void signal_handler(int sig) {
    if (sig == SIGPIPE) {
        return;
    }

    g_shutdown_requested = 1;

    if (!g_shutdown_announced) {
        g_shutdown_announced = 1;
        const char msg[] = "\n[INFO] Termination requested (signal).\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    }

    if (g_active_fd >= 0) {
        int fd = g_active_fd;
        g_active_fd = -1;
        g_active_conn.sockfd = -1;
        (void)close(fd);
    }
}

void wc_signal_atexit_cleanup(void) {
    const Config* cfg = wc_signal_config();

    if (cfg && cfg->debug) {
        wc_output_log_message("DEBUG", "Performing signal cleanup");
    }
    wc_signal_unregister_active_connection_internal();
    if (cfg && cfg->debug >= 2) {
        wc_cache_neg_stats_t stats = {0};
        wc_cache_get_negative_stats(&stats);
        fprintf(stderr,
            "[DNS] negative cache: hits=%d, sets=%d, shim_hits=%d, ttl=%d, disabled=%d\n",
            stats.hits,
            stats.sets,
            stats.shim_hits,
            cfg->dns_neg_ttl,
            cfg->dns_neg_cache_disable);
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

int wc_signal_handle_pending_shutdown(void) {
    const Config* cfg = wc_signal_config();

    if (!g_shutdown_requested)
        return 0;
    if (g_shutdown_handled)
        return 1;
    g_shutdown_handled = 1;
    wc_signal_unregister_active_connection_internal();
    if (cfg && cfg->security_logging) {
        log_security_event(SEC_EVENT_CONNECTION_ATTACK,
            "Process termination requested by signal");
    }
    wc_runtime_emit_dns_cache_summary();
    return 1;
}
