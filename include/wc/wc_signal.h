#ifndef WC_SIGNAL_H
#define WC_SIGNAL_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

struct Config;

void wc_signal_setup_handlers(void);
void wc_signal_atexit_cleanup(void);
// Inject process configuration for signal-time diagnostics/logging. Optional;
// when unset remains zeroed; callers should inject explicitly.
void wc_signal_set_config(const struct Config* config);
void wc_signal_register_active_connection(const char* host, int port, int sockfd);
void wc_signal_unregister_active_connection(void);
int wc_signal_should_terminate(void);
int wc_signal_handle_pending_shutdown(void);
int wc_signal_check_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif // WC_SIGNAL_H
