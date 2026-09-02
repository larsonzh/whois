// SPDX-License-Identifier: MIT
// tls.c - optional OpenSSL client transport for HTTPS proxy endpoints

#if defined(__has_include)
#if __has_include("wc/wc_tls.h")
#include "wc/wc_tls.h"
#define WC_TLS_PUBLIC_HEADER 1
#endif
#endif
#ifndef WC_TLS_PUBLIC_HEADER
#include <stdint.h>
#include "wc/wc_transport.h"
typedef enum wc_tls_result {
    WC_TLS_RESULT_SUCCEEDED = 0,
    WC_TLS_RESULT_UNSUPPORTED,
    WC_TLS_RESULT_CA_CONFIG_FAILURE,
    WC_TLS_RESULT_PEER_VERIFY_FAILURE,
    WC_TLS_RESULT_HANDSHAKE_FAILURE,
    WC_TLS_RESULT_TIMEOUT,
    WC_TLS_RESULT_IO_FAILURE,
    WC_TLS_RESULT_PROTOCOL_FAILURE
} wc_tls_result_t;
#endif

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#ifdef WHOIS_TLS
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include "wc/wc_ca_bundle.h"
#include "wc/wc_util.h"

typedef struct wc_tls_context {
    SSL_CTX* ssl_context;
    SSL* ssl;
    int fd;
    uint64_t io_deadline_ms;
} wc_tls_context_t;

static int wc_tls_wait_fd(wc_tls_context_t* context, int events, uint64_t deadline_ms)
{
    wc_transport_t bare_transport;
    if (!context || context->fd < 0) return -1;
    wc_transport_init(&bare_transport, &context->fd);
    return wc_transport_wait_until(&bare_transport, events, deadline_ms);
}

static int wc_tls_wait_for_ssl(wc_tls_context_t* context, int ssl_error)
{
    int events = ssl_error == SSL_ERROR_WANT_READ ? WC_TRANSPORT_WAIT_READ : WC_TRANSPORT_WAIT_WRITE;
    int ready = wc_tls_wait_fd(context, events, context->io_deadline_ms);
    if (ready == 0) errno = ETIMEDOUT;
    return ready;
}

static int wc_tls_read(void* value, char* buffer, size_t length)
{
    wc_tls_context_t* context = (wc_tls_context_t*)value;
    if (!context || !context->ssl || length > (size_t)INT_MAX) return -1;
    for (;;) {
        int result = SSL_read(context->ssl, buffer, (int)length);
        int error;
        if (result > 0) return result;
        error = SSL_get_error(context->ssl, result);
        if (error == SSL_ERROR_ZERO_RETURN) return 0;
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return -1;
        if (wc_tls_wait_for_ssl(context, error) <= 0) return -1;
    }
}

static int wc_tls_write(void* value, const char* data, size_t length)
{
    wc_tls_context_t* context = (wc_tls_context_t*)value;
    if (!context || !context->ssl || length > (size_t)INT_MAX) return -1;
    for (;;) {
        int result = SSL_write(context->ssl, data, (int)length);
        int error;
        if (result > 0) return result;
        error = SSL_get_error(context->ssl, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return -1;
        if (wc_tls_wait_for_ssl(context, error) <= 0) return -1;
    }
}

static int wc_tls_wait(void* value, int events, uint64_t deadline_ms)
{
    wc_tls_context_t* context = (wc_tls_context_t*)value;
    if (!context || !context->ssl) return -1;
    context->io_deadline_ms = deadline_ms;
    if ((events & WC_TRANSPORT_WAIT_READ) != 0 && SSL_pending(context->ssl) > 0) return 1;
    return wc_tls_wait_fd(context, events, deadline_ms);
}

static void wc_tls_close(void* value, const char* reason, int debug_enabled)
{
    wc_tls_context_t* context = (wc_tls_context_t*)value;
    if (!context) return;
    if (context->ssl) {
        (void)SSL_shutdown(context->ssl);
        SSL_free(context->ssl);
    }
    if (context->ssl_context) SSL_CTX_free(context->ssl_context);
    wc_safe_close(&context->fd, reason, debug_enabled);
    free(context);
}

static const wc_transport_ops_t g_wc_tls_transport_ops = {
    wc_tls_read, wc_tls_write, wc_tls_wait, wc_tls_close
};

static int wc_tls_load_embedded_ca(SSL_CTX* context)
{
    BIO* input;
    X509_STORE* store;
    X509* certificate;
    int loaded = 0;
    if (!context || wc_ca_bundle_pem_len == 0 || wc_ca_bundle_pem_len > (size_t)INT_MAX) return 0;
    input = BIO_new_mem_buf(wc_ca_bundle_pem, (int)wc_ca_bundle_pem_len);
    store = SSL_CTX_get_cert_store(context);
    if (!input || !store) { BIO_free(input); return 0; }
    while ((certificate = PEM_read_bio_X509(input, NULL, NULL, NULL)) != NULL) {
        if (X509_STORE_add_cert(store, certificate) == 1) loaded++;
        else ERR_clear_error();
        X509_free(certificate);
    }
    ERR_clear_error();
    BIO_free(input);
    return loaded > 0;
}

static int wc_tls_configure_trust(SSL_CTX* context, int allow_environment_override)
{
    const char* override_path = allow_environment_override ? getenv("SSL_CERT_FILE") : NULL;
    if (override_path && *override_path)
        return SSL_CTX_load_verify_locations(context, override_path, NULL) == 1;
    return wc_tls_load_embedded_ca(context);
}

static int wc_tls_configure_peer(SSL* ssl, const char* peer_name)
{
    X509_VERIFY_PARAM* parameters;
    if (!ssl || !peer_name || !*peer_name) return 0;
    parameters = SSL_get0_param(ssl);
    if (!parameters) return 0;
    if (X509_VERIFY_PARAM_set1_ip_asc(parameters, peer_name) == 1) return 1;
    ERR_clear_error();
    return SSL_set_tlsext_host_name(ssl, peer_name) == 1 &&
        X509_VERIFY_PARAM_set1_host(parameters, peer_name, 0) == 1;
}

wc_tls_result_t wc_tls_wrap_client(int fd,
                                   const char* peer_name,
                                   uint64_t deadline_ms,
                                   wc_transport_t** out_transport)
{
    wc_tls_context_t* context = NULL;
    wc_transport_t* transport = NULL;
    wc_tls_result_t result = WC_TLS_RESULT_PROTOCOL_FAILURE;
    if (out_transport) *out_transport = NULL;
    if (fd < 0 || !peer_name || !*peer_name || !out_transport) return result;
    context = (wc_tls_context_t*)calloc(1, sizeof(*context));
    if (!context) return WC_TLS_RESULT_IO_FAILURE;
    context->fd = fd;
    context->io_deadline_ms = deadline_ms;
    context->ssl_context = SSL_CTX_new(TLS_client_method());
    if (!context->ssl_context) goto cleanup;
    if (SSL_CTX_set_min_proto_version(context->ssl_context, TLS1_2_VERSION) != 1) goto cleanup;
    SSL_CTX_set_verify(context->ssl_context, SSL_VERIFY_PEER, NULL);
    if (!wc_tls_configure_trust(context->ssl_context, 1)) { result = WC_TLS_RESULT_CA_CONFIG_FAILURE; goto cleanup; }
    context->ssl = SSL_new(context->ssl_context);
    if (!context->ssl || SSL_set_fd(context->ssl, fd) != 1 || !wc_tls_configure_peer(context->ssl, peer_name)) goto cleanup;
    for (;;) {
        int handshake = SSL_connect(context->ssl);
        int error;
        int ready;
        if (handshake == 1) break;
        error = SSL_get_error(context->ssl, handshake);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            if (SSL_get_verify_result(context->ssl) != X509_V_OK)
                result = WC_TLS_RESULT_PEER_VERIFY_FAILURE;
            else
                result = error == SSL_ERROR_SSL ? WC_TLS_RESULT_HANDSHAKE_FAILURE : WC_TLS_RESULT_IO_FAILURE;
            goto cleanup;
        }
        ready = wc_tls_wait_for_ssl(context, error);
        if (ready <= 0) { result = ready == 0 ? WC_TLS_RESULT_TIMEOUT : WC_TLS_RESULT_IO_FAILURE; goto cleanup; }
    }
    if (SSL_get_verify_result(context->ssl) != X509_V_OK) { result = WC_TLS_RESULT_PEER_VERIFY_FAILURE; goto cleanup; }
    transport = (wc_transport_t*)malloc(sizeof(*transport));
    if (!transport) { result = WC_TLS_RESULT_IO_FAILURE; goto cleanup; }
    wc_transport_init_with_ops(transport, &g_wc_tls_transport_ops, context);
    *out_transport = transport;
    return WC_TLS_RESULT_SUCCEEDED;
cleanup:
    free(transport);
    if (context) {
        if (context->ssl) SSL_free(context->ssl);
        if (context->ssl_context) SSL_CTX_free(context->ssl_context);
        free(context);
    }
    return result;
}

int wc_tls_selftest(void)
{
    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    SSL* dns_ssl = NULL;
    SSL* ip_ssl = NULL;
    X509_STORE* store;
    int dns_configured = 0;
    int ip_configured = 0;
    int passed = context != NULL;
    if (passed) passed = SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) == 1;
    if (passed) { SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL); passed = wc_tls_configure_trust(context, 0); }
    store = context ? SSL_CTX_get_cert_store(context) : NULL;
    if (passed) passed = store && X509_STORE_get0_objects(store) && sk_X509_OBJECT_num(X509_STORE_get0_objects(store)) > 0;
    if (passed) {
        dns_ssl = SSL_new(context);
        ip_ssl = SSL_new(context);
        if (dns_ssl) dns_configured = wc_tls_configure_peer(dns_ssl, "proxy.example");
        if (ip_ssl) ip_configured = wc_tls_configure_peer(ip_ssl, "192.0.2.1");
        passed = dns_ssl && ip_ssl && dns_configured == 1 && ip_configured == 1;
    }
    SSL_free(ip_ssl);
    SSL_free(dns_ssl);
    SSL_CTX_free(context);
    return passed ? 0 : 1;
}
#else
wc_tls_result_t wc_tls_wrap_client(int fd,
                                   const char* peer_name,
                                   uint64_t deadline_ms,
                                   wc_transport_t** out_transport)
{
    (void)fd; (void)peer_name; (void)deadline_ms;
    if (out_transport) *out_transport = NULL;
    return WC_TLS_RESULT_UNSUPPORTED;
}
int wc_tls_selftest(void)
{
    wc_transport_t* transport = (wc_transport_t*)1;
    return wc_tls_wrap_client(-1, "proxy.example", 0, &transport) == WC_TLS_RESULT_UNSUPPORTED && transport == NULL ? 0 : 1;
}
#endif

const char* wc_tls_result_name(wc_tls_result_t result)
{
    switch (result) {
        case WC_TLS_RESULT_SUCCEEDED: return "succeeded";
        case WC_TLS_RESULT_UNSUPPORTED: return "unsupported";
        case WC_TLS_RESULT_CA_CONFIG_FAILURE: return "ca-config-failure";
        case WC_TLS_RESULT_PEER_VERIFY_FAILURE: return "peer-verify-failure";
        case WC_TLS_RESULT_HANDSHAKE_FAILURE: return "handshake-failure";
        case WC_TLS_RESULT_TIMEOUT: return "timeout";
        case WC_TLS_RESULT_IO_FAILURE: return "io-failure";
        default: return "protocol-failure";
    }
}
