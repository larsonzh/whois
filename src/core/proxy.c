// SPDX-License-Identifier: MIT
// proxy.c - HTTP CONNECT and per-hop NO_PROXY routing

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "wc/wc_proxy.h"
#if defined(__has_include)
#if __has_include("wc/wc_tls.h")
#include "wc/wc_tls.h"
#define WC_PROXY_TLS_HEADER 1
#endif
#endif
#ifndef WC_PROXY_TLS_HEADER
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
wc_tls_result_t wc_tls_wrap_client(int fd, const char* peer_name, uint64_t deadline_ms, wc_transport_t** out_transport);
const char* wc_tls_result_name(wc_tls_result_t result);
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "wc/wc_dns.h"
#include "wc/wc_strings.h"
#include "wc/wc_util.h"

#define WC_PROXY_RESPONSE_LIMIT 8192

static void wc_proxy_secure_clear(void* value, size_t length)
{
    volatile unsigned char* cursor = (volatile unsigned char*)value;
    while (cursor && length-- > 0) *cursor++ = 0;
}

static int wc_proxy_parse_port(const char* text, int* port)
{
    long value = 0;
    const unsigned char* cursor = (const unsigned char*)text;
    if (!cursor || !*cursor || !port) return 0;
    while (*cursor) {
        if (!isdigit(*cursor)) return 0;
        value = value * 10 + (*cursor++ - '0');
        if (value > 65535) return 0;
    }
    if (value < 1) return 0;
    *port = (int)value;
    return 1;
}

static int wc_proxy_host_equal(const char* left, const char* right)
{
    return left && right && strcasecmp(left, right) == 0;
}

static int wc_proxy_suffix_match(const char* host, const char* suffix)
{
    size_t host_length;
    size_t suffix_length;
    if (!host || !suffix || suffix[0] != '.') return 0;
    host_length = strlen(host);
    suffix_length = strlen(suffix);
    if (host_length + 1 == suffix_length) return strcasecmp(host, suffix + 1) == 0;
    return host_length >= suffix_length &&
        strcasecmp(host + host_length - suffix_length, suffix) == 0;
}

static int wc_proxy_token_matches(const char* begin, size_t length,
                                  const char* target, int target_port,
                                  int allow_domain_suffix)
{
    char token[320];
    char* host = token;
    char* end;
    char* port_text = NULL;
    int token_port = 0;
    size_t colon_count = 0;
    if (!target || !*target || length == 0 || length >= sizeof(token)) return 0;
    memcpy(token, begin, length);
    token[length] = '\0';
    while (*host && isspace((unsigned char)*host)) ++host;
    end = host + strlen(host);
    while (end > host && isspace((unsigned char)end[-1])) *--end = '\0';
    if (!*host || strchr(host, '/') || (strchr(host, '*') && strcmp(host, "*") != 0)) return 0;
    if (strcmp(host, "*") == 0) return 1;
    if (*host == '[') {
        char* close = strchr(host + 1, ']');
        if (!close) return 0;
        *close = '\0';
        host++;
        if (close[1] == ':') port_text = close + 2;
        else if (close[1] != '\0') return 0;
    } else {
        char* cursor;
        for (cursor = host; *cursor; ++cursor) if (*cursor == ':') colon_count++;
        if (colon_count > 1) return 0;
        if (colon_count == 1) {
            port_text = strrchr(host, ':');
            *port_text++ = '\0';
        }
    }
    if (port_text && (!wc_proxy_parse_port(port_text, &token_port) || token_port != target_port)) return 0;
    if (host[0] == '.') return allow_domain_suffix && wc_proxy_suffix_match(target, host);
    return wc_proxy_host_equal(target, host);
}

static int wc_proxy_list_matches(const char* list, const char* target, int target_port,
                                 int allow_domain_suffix)
{
    const char* cursor = list;
    if (!cursor || !*cursor) return 0;
    while (*cursor) {
        const char* comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        if (wc_proxy_token_matches(cursor, length, target, target_port, allow_domain_suffix)) return 1;
        if (!comma) break;
        cursor = comma + 1;
    }
    return 0;
}

int wc_proxy_should_proxy(const Config* config,
                          const char* target_host,
                          const char* target_address,
                          int target_port)
{
    if (!config || !config->proxy.configured || !config->proxy.routing_enabled) return 0;
    if (wc_proxy_list_matches(config->proxy.no_proxy, target_host, target_port, 1)) return 0;
    if (target_address && (!target_host || strcasecmp(target_address, target_host) != 0) &&
        wc_proxy_list_matches(config->proxy.no_proxy, target_address, target_port, 0)) return 0;
    return 1;
}

int wc_proxy_target_supported(const Config* config,
                              const char* target_host,
                              const char* target_address,
                              int target_port)
{
    struct in_addr address;
    if (!config || !target_address || !*target_address) return 0;
    if (!wc_proxy_should_proxy(config, target_host, target_address, target_port)) return 1;
    if (config->proxy.scheme != WC_PROXY_SCHEME_SOCKS4) return 1;
    return inet_pton(AF_INET, target_address, &address) == 1;
}

int wc_proxy_uses_remote_dns(const Config* config,
                             const char* target_host,
                             int target_port)
{
    return config &&
        (config->proxy.scheme == WC_PROXY_SCHEME_SOCKS4A ||
         config->proxy.scheme == WC_PROXY_SCHEME_SOCKS5H) &&
        target_host && !wc_dns_is_ip_literal(target_host) &&
        wc_proxy_should_proxy(config, target_host, target_host, target_port);
}

static size_t wc_proxy_base64(char* output, size_t capacity, const unsigned char* input, size_t length)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t in_index = 0;
    size_t out_index = 0;
    if (!output || !input || capacity < ((length + 2) / 3) * 4 + 1) return 0;
    while (in_index < length) {
        unsigned int value = (unsigned int)input[in_index++] << 16;
        int remaining = (int)(length - in_index);
        if (remaining >= 0 && in_index < length) value |= (unsigned int)input[in_index++] << 8;
        if (in_index < length) value |= input[in_index++];
        output[out_index++] = alphabet[(value >> 18) & 63];
        output[out_index++] = alphabet[(value >> 12) & 63];
        output[out_index++] = remaining > 0 ? alphabet[(value >> 6) & 63] : '=';
        output[out_index++] = remaining > 1 ? alphabet[value & 63] : '=';
    }
    output[out_index] = '\0';
    return out_index;
}

static wc_proxy_result_t wc_proxy_http_classify(int status)
{
    if (status >= 200 && status <= 299) return WC_PROXY_RESULT_SUCCEEDED;
    if (status == 407) return WC_PROXY_RESULT_AUTH_REQUIRED;
    if (status >= 400 && status <= 499) return WC_PROXY_RESULT_REJECTED;
    if (status >= 500 && status <= 599) return WC_PROXY_RESULT_UPSTREAM_FAILURE;
    return WC_PROXY_RESULT_PROTOCOL_FAILURE;
}

static int wc_proxy_recv_exact_until(wc_transport_t* transport, unsigned char* buffer,
                                     size_t length, uint64_t deadline_ms)
{
    size_t received_total = 0;
    while (received_total < length) {
        int ready = wc_transport_wait_until(transport, WC_TRANSPORT_WAIT_READ, deadline_ms);
        int received;
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (ready == 0) return 0;
        received = wc_transport_read(transport, (char*)buffer + received_total, length - received_total);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return -1;
        received_total += (size_t)received;
    }
    return 1;
}

static wc_proxy_result_t wc_proxy_socks4_classify(unsigned char reply)
{
    switch (reply) {
        case 0x5a: return WC_PROXY_RESULT_SUCCEEDED;
        case 0x5b: return WC_PROXY_RESULT_REJECTED;
        case 0x5c:
        case 0x5d: return WC_PROXY_RESULT_AUTH_REQUIRED;
        default: return WC_PROXY_RESULT_UNKNOWN_REPLY;
    }
}

int wc_proxy_socks4_connect_transport(wc_transport_t* transport,
                                      const wc_proxy_config_t* proxy,
                                      const char* target,
                                      uint16_t target_port,
                                      int remote_dns,
                                      uint64_t deadline_ms,
                                      int* reply_code)
{
    unsigned char request[512];
    unsigned char response[8];
    size_t username_length;
    size_t target_length = 0;
    size_t request_length;
    int receive_result;
    wc_proxy_result_t result = WC_PROXY_RESULT_PROTOCOL_FAILURE;
    if (reply_code) *reply_code = 0;
    if (!transport || !proxy || !target || !*target || target_port == 0) return result;
    username_length = proxy->has_credentials ? strlen(proxy->username) : 0;
    if (username_length > 255) return result;
    request[0] = 0x04;
    request[1] = 0x01;
    request[2] = (unsigned char)(target_port >> 8);
    request[3] = (unsigned char)(target_port & 0xff);
    if (remote_dns) {
        target_length = strlen(target);
        if (target_length == 0 || target_length > 255) return result;
        request[4] = 0x00;
        request[5] = 0x00;
        request[6] = 0x00;
        request[7] = 0x01;
    } else if (inet_pton(AF_INET, target, request + 4) != 1) {
        return WC_PROXY_RESULT_ADDRESS_TYPE_UNSUPPORTED;
    }
    if (username_length > 0) memcpy(request + 8, proxy->username, username_length);
    request[8 + username_length] = 0x00;
    request_length = 9 + username_length;
    if (remote_dns) {
        memcpy(request + request_length, target, target_length);
        request_length += target_length;
        request[request_length++] = 0x00;
    }
    if (wc_transport_send_all_until(transport, (const char*)request, request_length, deadline_ms) < 0) {
        result = WC_PROXY_RESULT_TIMEOUT;
        goto cleanup;
    }
    receive_result = wc_proxy_recv_exact_until(transport, response, sizeof(response), deadline_ms);
    if (receive_result <= 0) {
        result = receive_result == 0 ? WC_PROXY_RESULT_TIMEOUT : WC_PROXY_RESULT_PROTOCOL_FAILURE;
        goto cleanup;
    }
    if (response[0] != 0x00) goto cleanup;
    if (reply_code) *reply_code = response[1];
    result = wc_proxy_socks4_classify(response[1]);
cleanup:
    wc_proxy_secure_clear(request, sizeof(request));
    wc_proxy_secure_clear(response, sizeof(response));
    return result;
}

static wc_proxy_result_t wc_proxy_socks5_classify(unsigned char reply)
{
    switch (reply) {
        case 0x00: return WC_PROXY_RESULT_SUCCEEDED;
        case 0x01: return WC_PROXY_RESULT_GENERAL_FAILURE;
        case 0x02: return WC_PROXY_RESULT_RULESET_DENIED;
        case 0x03: return WC_PROXY_RESULT_NETWORK_UNREACHABLE;
        case 0x04: return WC_PROXY_RESULT_HOST_UNREACHABLE;
        case 0x05: return WC_PROXY_RESULT_CONNECTION_REFUSED;
        case 0x06: return WC_PROXY_RESULT_TTL_EXPIRED;
        case 0x07: return WC_PROXY_RESULT_COMMAND_UNSUPPORTED;
        case 0x08: return WC_PROXY_RESULT_ADDRESS_TYPE_UNSUPPORTED;
        default: return WC_PROXY_RESULT_UNKNOWN_REPLY;
    }
}

int wc_proxy_socks5_connect_transport(wc_transport_t* transport,
                                      const wc_proxy_config_t* proxy,
                                      const char* target,
                                      uint16_t target_port,
                                      int remote_dns,
                                      uint64_t deadline_ms,
                                      int* reply_code)
{
    unsigned char request[300];
    unsigned char response[260];
    size_t request_length;
    size_t address_length;
    int address_family = 0;
    int receive_result;
    wc_proxy_result_t result = WC_PROXY_RESULT_PROTOCOL_FAILURE;
    if (reply_code) *reply_code = 0;
    if (!transport || !proxy || !target || !*target || target_port == 0) return result;

    request[0] = 0x05;
    request[1] = proxy->has_credentials ? 0x02 : 0x01;
    request[2] = 0x00;
    if (proxy->has_credentials) request[3] = 0x02;
    request_length = proxy->has_credentials ? 4U : 3U;
    if (wc_transport_send_all_until(transport, (const char*)request, request_length, deadline_ms) < 0)
        return WC_PROXY_RESULT_TIMEOUT;
    receive_result = wc_proxy_recv_exact_until(transport, response, 2, deadline_ms);
    if (receive_result <= 0)
        return receive_result == 0 ? WC_PROXY_RESULT_TIMEOUT : WC_PROXY_RESULT_PROTOCOL_FAILURE;
    if (response[0] != 0x05) return result;
    if (response[1] == 0xff) return WC_PROXY_RESULT_AUTH_REQUIRED;
    if (response[1] == 0x02) {
        size_t username_length;
        size_t password_length;
        if (!proxy->has_credentials) return WC_PROXY_RESULT_AUTH_REQUIRED;
        username_length = strlen(proxy->username);
        password_length = strlen(proxy->password);
        if (username_length == 0 || username_length > 255 || password_length == 0 || password_length > 255)
            return result;
        request[0] = 0x01;
        request[1] = (unsigned char)username_length;
        memcpy(request + 2, proxy->username, username_length);
        request[2 + username_length] = (unsigned char)password_length;
        memcpy(request + 3 + username_length, proxy->password, password_length);
        request_length = 3 + username_length + password_length;
        if (wc_transport_send_all_until(transport, (const char*)request, request_length, deadline_ms) < 0) {
            wc_proxy_secure_clear(request, request_length);
            return WC_PROXY_RESULT_TIMEOUT;
        }
        receive_result = wc_proxy_recv_exact_until(transport, response, 2, deadline_ms);
        wc_proxy_secure_clear(request, request_length);
        if (receive_result <= 0)
            return receive_result == 0 ? WC_PROXY_RESULT_TIMEOUT : WC_PROXY_RESULT_PROTOCOL_FAILURE;
        if (response[0] != 0x01) return result;
        if (response[1] != 0x00) return WC_PROXY_RESULT_AUTH_REQUIRED;
    } else if (response[1] != 0x00) {
        return result;
    }

    request[0] = 0x05;
    request[1] = 0x01;
    request[2] = 0x00;
    if (remote_dns) {
        address_length = strlen(target);
        if (address_length == 0 || address_length > 255) return result;
        request[3] = 0x03;
        request[4] = (unsigned char)address_length;
        memcpy(request + 5, target, address_length);
        request_length = 5 + address_length;
    } else if (inet_pton(AF_INET, target, request + 4) == 1) {
        request[3] = 0x01;
        request_length = 8;
    } else if (inet_pton(AF_INET6, target, request + 4) == 1) {
        request[3] = 0x04;
        request_length = 20;
    } else {
        return WC_PROXY_RESULT_ADDRESS_TYPE_UNSUPPORTED;
    }
    request[request_length++] = (unsigned char)(target_port >> 8);
    request[request_length++] = (unsigned char)(target_port & 0xff);
    if (wc_transport_send_all_until(transport, (const char*)request, request_length, deadline_ms) < 0)
        return WC_PROXY_RESULT_TIMEOUT;
    receive_result = wc_proxy_recv_exact_until(transport, response, 4, deadline_ms);
    if (receive_result <= 0)
        return receive_result == 0 ? WC_PROXY_RESULT_TIMEOUT : WC_PROXY_RESULT_PROTOCOL_FAILURE;
    if (response[0] != 0x05 || response[2] != 0x00) return result;
    if (reply_code) *reply_code = response[1];
    result = wc_proxy_socks5_classify(response[1]);
    address_family = response[3];
    if (address_family == 0x01) address_length = 4;
    else if (address_family == 0x04) address_length = 16;
    else if (address_family == 0x03) {
        receive_result = wc_proxy_recv_exact_until(transport, response, 1, deadline_ms);
        if (receive_result <= 0)
            return receive_result == 0 ? WC_PROXY_RESULT_TIMEOUT : WC_PROXY_RESULT_PROTOCOL_FAILURE;
        address_length = response[0];
        if (address_length == 0) return WC_PROXY_RESULT_PROTOCOL_FAILURE;
    } else {
        return WC_PROXY_RESULT_PROTOCOL_FAILURE;
    }
    receive_result = wc_proxy_recv_exact_until(transport, response, address_length + 2, deadline_ms);
    if (receive_result <= 0)
        return receive_result == 0 ? WC_PROXY_RESULT_TIMEOUT : WC_PROXY_RESULT_PROTOCOL_FAILURE;
    return result;
}

int wc_proxy_http_connect_transport(wc_transport_t* transport,
                                    const wc_proxy_config_t* proxy,
                                    const char* target_address,
                                    uint16_t target_port,
                                    uint64_t deadline_ms,
                                    int* status_code)
{
    char authority[320];
    char credential[260];
    char encoded[352];
    char request[1024];
    char response[WC_PROXY_RESPONSE_LIMIT + 1];
    size_t response_used = 0;
    int request_length;
    int status = 0;
    int result = WC_PROXY_RESULT_PROTOCOL_FAILURE;
    if (status_code) *status_code = 0;
    if (!transport || !proxy || !target_address || !*target_address || target_port == 0) return WC_PROXY_RESULT_PROTOCOL_FAILURE;
    if (strchr(target_address, ':')) request_length = snprintf(authority, sizeof(authority), "[%s]:%u", target_address, (unsigned)target_port);
    else request_length = snprintf(authority, sizeof(authority), "%s:%u", target_address, (unsigned)target_port);
    if (request_length < 0 || (size_t)request_length >= sizeof(authority)) return WC_PROXY_RESULT_PROTOCOL_FAILURE;
    encoded[0] = '\0';
    credential[0] = '\0';
    if (proxy->has_credentials) {
        request_length = snprintf(credential, sizeof(credential), "%s:%s", proxy->username, proxy->password);
        if (request_length < 0 || (size_t)request_length >= sizeof(credential) ||
            wc_proxy_base64(encoded, sizeof(encoded), (const unsigned char*)credential, (size_t)request_length) == 0) goto cleanup;
        request_length = snprintf(request, sizeof(request),
            "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic %s\r\n\r\n",
            authority, authority, encoded);
    } else {
        request_length = snprintf(request, sizeof(request),
            "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", authority, authority);
    }
    if (request_length < 0 || (size_t)request_length >= sizeof(request)) goto cleanup;
    if (wc_transport_send_all_until(transport, request, (size_t)request_length, deadline_ms) < 0) {
        result = WC_PROXY_RESULT_TIMEOUT;
        goto cleanup;
    }
    wc_proxy_secure_clear(credential, sizeof(credential));
    wc_proxy_secure_clear(encoded, sizeof(encoded));
    wc_proxy_secure_clear(request, sizeof(request));
    while (response_used < WC_PROXY_RESPONSE_LIMIT) {
        int ready = wc_transport_wait_until(transport, WC_TRANSPORT_WAIT_READ, deadline_ms);
        int received;
        if (ready <= 0) { result = WC_PROXY_RESULT_TIMEOUT; goto cleanup; }
        received = wc_transport_read(transport, response + response_used, WC_PROXY_RESPONSE_LIMIT - response_used);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) goto cleanup;
        response_used += (size_t)received;
        response[response_used] = '\0';
        if (strstr(response, "\r\n\r\n")) break;
    }
    if (response_used == WC_PROXY_RESPONSE_LIMIT ||
        (strncmp(response, "HTTP/1.0 ", 9) != 0 && strncmp(response, "HTTP/1.1 ", 9) != 0) ||
        !isdigit((unsigned char)response[9]) || !isdigit((unsigned char)response[10]) ||
        !isdigit((unsigned char)response[11]) || (response[12] != ' ' && response[12] != '\r')) goto cleanup;
    status = (response[9] - '0') * 100 + (response[10] - '0') * 10 + (response[11] - '0');
    if (status_code) *status_code = status;
    result = wc_proxy_http_classify(status);
cleanup:
    wc_proxy_secure_clear(credential, sizeof(credential));
    wc_proxy_secure_clear(encoded, sizeof(encoded));
    wc_proxy_secure_clear(request, sizeof(request));
    wc_proxy_secure_clear(response, sizeof(response));
    return result;
}

const char* wc_proxy_result_name(wc_proxy_result_t result)
{
    switch (result) {
        case WC_PROXY_RESULT_SUCCEEDED: return "succeeded";
        case WC_PROXY_RESULT_TCP_FAILURE: return "proxy-tcp-failure";
        case WC_PROXY_RESULT_TLS_FAILURE: return "proxy-tls-failure";
        case WC_PROXY_RESULT_TIMEOUT: return "proxy-timeout";
        case WC_PROXY_RESULT_AUTH_REQUIRED: return "proxy-auth-required";
        case WC_PROXY_RESULT_REJECTED: return "proxy-rejected";
        case WC_PROXY_RESULT_UPSTREAM_FAILURE: return "proxy-upstream-failure";
        case WC_PROXY_RESULT_UNSUPPORTED: return "proxy-unsupported";
        case WC_PROXY_RESULT_NETWORK_UNREACHABLE: return "network-unreachable";
        case WC_PROXY_RESULT_HOST_UNREACHABLE: return "host-unreachable";
        case WC_PROXY_RESULT_CONNECTION_REFUSED: return "connection-refused";
        case WC_PROXY_RESULT_TTL_EXPIRED: return "ttl-expired";
        case WC_PROXY_RESULT_ADDRESS_TYPE_UNSUPPORTED: return "address-type-unsupported";
        case WC_PROXY_RESULT_UNKNOWN_REPLY: return "unknown-reply";
        case WC_PROXY_RESULT_GENERAL_FAILURE: return "general-failure";
        case WC_PROXY_RESULT_RULESET_DENIED: return "ruleset-denied";
        case WC_PROXY_RESULT_COMMAND_UNSUPPORTED: return "command-unsupported";
        default: return "proxy-protocol-failure";
    }
}

int wc_proxy_result_is_terminal(wc_proxy_result_t result)
{
    return result == WC_PROXY_RESULT_AUTH_REQUIRED ||
        result == WC_PROXY_RESULT_REJECTED ||
        result == WC_PROXY_RESULT_PROTOCOL_FAILURE ||
        result == WC_PROXY_RESULT_UNSUPPORTED ||
        result == WC_PROXY_RESULT_GENERAL_FAILURE ||
        result == WC_PROXY_RESULT_RULESET_DENIED ||
        result == WC_PROXY_RESULT_COMMAND_UNSUPPORTED ||
        result == WC_PROXY_RESULT_ADDRESS_TYPE_UNSUPPORTED ||
        result == WC_PROXY_RESULT_UNKNOWN_REPLY;
}

int wc_proxy_dial_hop(const Config* config,
                      wc_net_context_t* net_ctx,
                      const char* target_host,
                      const char* target_address,
                      uint16_t target_port,
                      int timeout_ms,
                      int retries,
                      struct wc_net_info* out,
                      int* used_proxy,
                      wc_proxy_result_t* proxy_result)
{
    wc_net_dial_policy_t policy;
    struct wc_net_info endpoint;
    wc_transport_t bare_transport;
    wc_transport_t* transport;
    wc_transport_t* tls_transport = NULL;
    uint64_t deadline_ms;
    int status = 0;
    const char* phase = "connect";
    wc_proxy_result_t result;
    if (used_proxy) *used_proxy = 0;
    if (proxy_result) *proxy_result = WC_PROXY_RESULT_SUCCEEDED;
    if (!config || !target_address || !out) return WC_ERR_INVALID;
    if (!wc_proxy_should_proxy(config, target_host, target_address, (int)target_port))
        return wc_dial_43(net_ctx, target_address, target_port, timeout_ms, retries, out);
    if (used_proxy) *used_proxy = 1;
    if (config->proxy.scheme != WC_PROXY_SCHEME_HTTP &&
        config->proxy.scheme != (wc_proxy_scheme_t)6 &&
        config->proxy.scheme != WC_PROXY_SCHEME_SOCKS5 &&
        config->proxy.scheme != WC_PROXY_SCHEME_SOCKS5H &&
        config->proxy.scheme != WC_PROXY_SCHEME_SOCKS4 &&
        config->proxy.scheme != WC_PROXY_SCHEME_SOCKS4A) {
        if (proxy_result) *proxy_result = WC_PROXY_RESULT_UNSUPPORTED;
        return WC_ERR_INVALID;
    }
    deadline_ms = wc_net_deadline_after(timeout_ms);
    wc_net_dial_policy_init(&policy);
    if (config->proxy.family == WC_PROXY_FAMILY_V4) policy.family = WC_NET_ENDPOINT_FAMILY_IPV4;
    else if (config->proxy.family == WC_PROXY_FAMILY_V6) policy.family = WC_NET_ENDPOINT_FAMILY_IPV6;
    policy.record_dns_health = 0;
    wc_net_info_init(&endpoint);
    if (wc_net_dial_endpoint_until(net_ctx, config->proxy.endpoint_host,
            (uint16_t)config->proxy.endpoint_port, deadline_ms, retries, &policy, &endpoint) != WC_OK ||
        !endpoint.connected || endpoint.fd < 0) {
        wc_net_info_move(out, &endpoint);
        if (proxy_result) *proxy_result = WC_PROXY_RESULT_TCP_FAILURE;
        return WC_ERR_IO;
    }
    if (config->proxy.scheme == (wc_proxy_scheme_t)6) {
        wc_tls_result_t tls_result;
        phase = "tls";
        tls_result = wc_tls_wrap_client(endpoint.fd, config->proxy.endpoint_host, deadline_ms, &tls_transport);
        if (tls_result != WC_TLS_RESULT_SUCCEEDED || !tls_transport) {
            if (config->debug || config->retry_metrics)
                fprintf(stderr, "[PROXY] scheme=https phase=tls port=%u result=proxy-tls-failure tls=%s status=0\n",
                    (unsigned)config->proxy.endpoint_port, wc_tls_result_name(tls_result));
            wc_net_info_close(&endpoint, "wc_proxy_tls_fail", config->debug);
            result = WC_PROXY_RESULT_TLS_FAILURE;
            endpoint.err = WC_ERR_IO;
            endpoint.last_errno = tls_result == WC_TLS_RESULT_TIMEOUT ? ETIMEDOUT : EPROTO;
            wc_net_info_move(out, &endpoint);
            if (proxy_result) *proxy_result = result;
            return WC_ERR_IO;
        }
        endpoint.fd = -1;
        wc_net_info_adopt(&endpoint, tls_transport);
        phase = "connect";
    }
    transport = wc_net_info_get(&endpoint, &bare_transport);
    if (!transport) {
        wc_net_info_close(&endpoint, "wc_proxy_transport_missing", config->debug);
        result = WC_PROXY_RESULT_TCP_FAILURE;
    } else if (config->proxy.scheme == WC_PROXY_SCHEME_HTTP ||
               config->proxy.scheme == (wc_proxy_scheme_t)6) {
        result = (wc_proxy_result_t)wc_proxy_http_connect_transport(transport, &config->proxy,
            target_address, target_port, deadline_ms, &status);
    } else if (config->proxy.scheme == WC_PROXY_SCHEME_SOCKS4 ||
               config->proxy.scheme == WC_PROXY_SCHEME_SOCKS4A) {
        const int remote_dns = config->proxy.scheme == WC_PROXY_SCHEME_SOCKS4A;
        const char* socks_target = remote_dns ? target_host : target_address;
        result = (wc_proxy_result_t)wc_proxy_socks4_connect_transport(transport, &config->proxy,
            socks_target, target_port, remote_dns, deadline_ms, &status);
    } else {
        const char* socks_target = config->proxy.scheme == WC_PROXY_SCHEME_SOCKS5H ? target_host : target_address;
        result = (wc_proxy_result_t)wc_proxy_socks5_connect_transport(transport, &config->proxy,
            socks_target, target_port, config->proxy.scheme == WC_PROXY_SCHEME_SOCKS5H,
            deadline_ms, &status);
    }
    if (result != WC_PROXY_RESULT_SUCCEEDED) {
        wc_net_info_close(&endpoint, "wc_proxy_connect_fail", config->debug);
        endpoint.err = WC_ERR_IO;
        endpoint.last_errno = (result == WC_PROXY_RESULT_TIMEOUT) ? ETIMEDOUT : EPROTO;
    } else if (config->proxy.scheme == WC_PROXY_SCHEME_SOCKS4A ||
               config->proxy.scheme == WC_PROXY_SCHEME_SOCKS5H) {
        endpoint.ip[0] = '\0';
    } else {
        snprintf(endpoint.ip, sizeof(endpoint.ip), "%s", target_address);
    }
    if ((config->debug || config->retry_metrics) && result != WC_PROXY_RESULT_SUCCEEDED)
        fprintf(stderr, "[PROXY] scheme=%s phase=%s port=%u result=%s status=%d\n",
            config->proxy.scheme == (wc_proxy_scheme_t)6 ? "https" :
            (config->proxy.scheme == WC_PROXY_SCHEME_HTTP ? "http" :
                (config->proxy.scheme == WC_PROXY_SCHEME_SOCKS5H ? "socks5h" :
                (config->proxy.scheme == WC_PROXY_SCHEME_SOCKS5 ? "socks5" :
                (config->proxy.scheme == WC_PROXY_SCHEME_SOCKS4A ? "socks4a" : "socks4")))),
            phase, (unsigned)config->proxy.endpoint_port, wc_proxy_result_name(result), status);
    wc_net_info_move(out, &endpoint);
    if (proxy_result) *proxy_result = result;
    return result == WC_PROXY_RESULT_SUCCEEDED ? WC_OK : WC_ERR_IO;
}

typedef struct wc_proxy_fake {
    const char* response;
    size_t response_length;
    size_t response_offset;
    char request[1024];
    size_t request_used;
} wc_proxy_fake_t;

static int wc_proxy_fake_read(void* context, char* buffer, size_t length)
{
    wc_proxy_fake_t* fake = (wc_proxy_fake_t*)context;
    size_t total = fake->response_length ? fake->response_length : strlen(fake->response);
    size_t remaining = total - fake->response_offset;
    if (remaining == 0) return 0;
    if (length > remaining) length = remaining;
    memcpy(buffer, fake->response + fake->response_offset, length);
    fake->response_offset += length;
    return (int)length;
}

static int wc_proxy_fake_write(void* context, const char* data, size_t length)
{
    wc_proxy_fake_t* fake = (wc_proxy_fake_t*)context;
    if (fake->request_used + length >= sizeof(fake->request)) return -1;
    memcpy(fake->request + fake->request_used, data, length);
    fake->request_used += length;
    fake->request[fake->request_used] = '\0';
    return (int)length;
}

static int wc_proxy_fake_wait(void* context, int events, uint64_t deadline_ms)
{
    (void)context; (void)events; (void)deadline_ms;
    return 1;
}

static void wc_proxy_fake_close(void* context, const char* reason, int debug_enabled)
{
    (void)context; (void)reason; (void)debug_enabled;
}

static int wc_proxy_test_report(const char* name, int pass)
{
    fprintf(stderr, "[SELFTEST] proxy-routing-%s: %s\n", name, pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}

int wc_proxy_selftest(void)
{
    static const wc_transport_ops_t operations = { wc_proxy_fake_read, wc_proxy_fake_write, wc_proxy_fake_wait, wc_proxy_fake_close };
    static const unsigned char socks5_ipv4_response[] = {
        0x05, 0x00,
        0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38
    };
    static const unsigned char socks5_auth_domain_response[] = {
        0x05, 0x02,
        0x01, 0x00,
        0x05, 0x00, 0x00, 0x03, 0x03, 'f', 'o', 'o', 0x04, 0x38
    };
    static const unsigned char socks5_refused_response[] = {
        0x05, 0x00,
        0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0
    };
    static const unsigned char socks5_ipv6_response[] = {
        0x05, 0x00,
        0x05, 0x00, 0x00, 0x04,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x04, 0x38
    };
    static const unsigned char socks5_auth_rejected_response[] = {
        0x05, 0x02,
        0x01, 0x01
    };
    static const unsigned char socks4_success_response[] = {
        0x00, 0x5a, 0x00, 0x2b, 192, 0, 2, 70
    };
    static const unsigned char socks4_rejected_response[] = {
        0x00, 0x5b, 0x00, 0x2b, 0, 0, 0, 0
    };
    const uint64_t no_deadline = ~(uint64_t)0;
    Config config;
    wc_proxy_fake_t fake;
    wc_transport_t transport;
    int failed = 0;
    int status = 0;
    memset(&config, 0, sizeof(config));
    config.proxy.configured = 1;
    config.proxy.routing_enabled = 1;
    config.proxy.scheme = WC_PROXY_SCHEME_HTTP;
    snprintf(config.proxy.no_proxy, sizeof(config.proxy.no_proxy), "localhost,.example.net,192.0.2.7:43,[2001:db8::7]:4343");
    failed |= wc_proxy_test_report("no-proxy-exact", !wc_proxy_should_proxy(&config, "localhost", "127.0.0.1", 43));
    failed |= wc_proxy_test_report("no-proxy-suffix", !wc_proxy_should_proxy(&config, "whois.example.net", "192.0.2.8", 43));
    snprintf(config.proxy.no_proxy, sizeof(config.proxy.no_proxy), ".7");
    failed |= wc_proxy_test_report("no-proxy-suffix-not-address",
        wc_proxy_should_proxy(&config, "other.test", "192.0.2.7", 43));
    snprintf(config.proxy.no_proxy, sizeof(config.proxy.no_proxy), "localhost,.example.net,192.0.2.7:43,[2001:db8::7]:4343");
    failed |= wc_proxy_test_report("no-proxy-port", wc_proxy_should_proxy(&config, "other.test", "192.0.2.7", 4343));
    failed |= wc_proxy_test_report("no-proxy-ipv6", !wc_proxy_should_proxy(&config, "other.test", "2001:db8::7", 4343));
    snprintf(config.proxy.no_proxy, sizeof(config.proxy.no_proxy), "2001:db8::7");
    failed |= wc_proxy_test_report("no-proxy-unbracketed-ipv6-rejected",
        wc_proxy_should_proxy(&config, "other.test", "2001:db8::7", 43));
    snprintf(config.proxy.no_proxy, sizeof(config.proxy.no_proxy), "localhost,.example.net,192.0.2.7:43,[2001:db8::7]:4343");
    failed |= wc_proxy_test_report("proxy-required", wc_proxy_should_proxy(&config, "whois.example.org", "192.0.2.9", 43));
    config.proxy.scheme = WC_PROXY_SCHEME_SOCKS4;
    failed |= wc_proxy_test_report("socks4-ipv4-supported",
        wc_proxy_target_supported(&config, "whois.example.org", "192.0.2.9", 43));
    failed |= wc_proxy_test_report("socks4-ipv6-rejected",
        !wc_proxy_target_supported(&config, "whois.example.org", "2001:db8::9", 43));
    snprintf(config.proxy.no_proxy, sizeof(config.proxy.no_proxy), "[2001:db8::9]");
    failed |= wc_proxy_test_report("socks4-no-proxy-ipv6",
        wc_proxy_target_supported(&config, "whois.example.org", "2001:db8::9", 43));
    snprintf(config.proxy.no_proxy, sizeof(config.proxy.no_proxy), "localhost,.example.net,192.0.2.7:43,[2001:db8::7]:4343");
    config.proxy.scheme = WC_PROXY_SCHEME_SOCKS5H;
    failed |= wc_proxy_test_report("socks5h-remote-dns",
        wc_proxy_uses_remote_dns(&config, "whois.example.org", 43));
    failed |= wc_proxy_test_report("socks5h-no-proxy-local-dns",
        !wc_proxy_uses_remote_dns(&config, "whois.example.net", 43));
    failed |= wc_proxy_test_report("socks5h-ip-literal",
        !wc_proxy_uses_remote_dns(&config, "192.0.2.9", 43));
    config.proxy.scheme = WC_PROXY_SCHEME_HTTP;
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 204 No Content\r\nX-Test: yes\r\n\r\n";
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-2xx",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "2001:db8::9", 4343, no_deadline, &status) == WC_PROXY_RESULT_SUCCEEDED &&
        status == 204 && strstr(fake.request, "CONNECT [2001:db8::9]:4343 HTTP/1.1\r\nHost: [2001:db8::9]:4343\r\n") != NULL);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
    config.proxy.has_credentials = 1;
    snprintf(config.proxy.username, sizeof(config.proxy.username), "user");
    snprintf(config.proxy.password, sizeof(config.proxy.password), "pass");
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-basic-407",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.10", 43, no_deadline, &status) == WC_PROXY_RESULT_AUTH_REQUIRED &&
        status == 407 && strstr(fake.request, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != NULL);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    snprintf(config.proxy.username, sizeof(config.proxy.username), "u");
    snprintf(config.proxy.password, sizeof(config.proxy.password), "pp");
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-basic-padding",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.11", 43, no_deadline, &status) == WC_PROXY_RESULT_SUCCEEDED &&
        strstr(fake.request, "Proxy-Authorization: Basic dTpwcA==\r\n") != NULL);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1\r\nX-Test: 200\r\n\r\n";
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-malformed-missing-status",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.12", 43, no_deadline, &status) == WC_PROXY_RESULT_PROTOCOL_FAILURE);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 200X Invalid\r\n\r\n";
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-malformed-status-delimiter",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.13", 43, no_deadline, &status) == WC_PROXY_RESULT_PROTOCOL_FAILURE);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks5_ipv4_response;
    fake.response_length = sizeof(socks5_ipv4_response);
    config.proxy.has_credentials = 0;
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks5-ipv4",
        wc_proxy_socks5_connect_transport(&transport, &config.proxy, "192.0.2.20", 43, 0,
            no_deadline, &status) == WC_PROXY_RESULT_SUCCEEDED && status == 0 &&
        fake.request_used == 13 &&
        memcmp(fake.request, "\x05\x01\x00\x05\x01\x00\x01\xc0\x00\x02\x14\x00\x2b", 13) == 0);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks5_auth_domain_response;
    fake.response_length = sizeof(socks5_auth_domain_response);
    config.proxy.has_credentials = 1;
    snprintf(config.proxy.username, sizeof(config.proxy.username), "user");
    snprintf(config.proxy.password, sizeof(config.proxy.password), "pass");
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks5h-auth-domain",
        wc_proxy_socks5_connect_transport(&transport, &config.proxy, "whois.example", 43, 1,
            no_deadline, &status) == WC_PROXY_RESULT_SUCCEEDED && status == 0 &&
        fake.request_used == 35 &&
        memcmp(fake.request, "\x05\x02\x00\x02\x01\x04user\x04pass\x05\x01\x00\x03\x0dwhois.example\x00\x2b", 35) == 0);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks5_refused_response;
    fake.response_length = sizeof(socks5_refused_response);
    config.proxy.has_credentials = 0;
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks5-reply-refused",
        wc_proxy_socks5_connect_transport(&transport, &config.proxy, "2001:db8::20", 43, 0,
            no_deadline, &status) == WC_PROXY_RESULT_CONNECTION_REFUSED && status == 5);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks5_ipv6_response;
    fake.response_length = sizeof(socks5_ipv6_response);
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks5-ipv6",
        wc_proxy_socks5_connect_transport(&transport, &config.proxy, "2001:db8::20", 43, 0,
            no_deadline, &status) == WC_PROXY_RESULT_SUCCEEDED && status == 0 &&
        fake.request_used == 25 && (unsigned char)fake.request[6] == 0x04 &&
        (unsigned char)fake.request[23] == 0x00 && (unsigned char)fake.request[24] == 0x2b);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks5_auth_rejected_response;
    fake.response_length = sizeof(socks5_auth_rejected_response);
    config.proxy.has_credentials = 1;
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks5-auth-rejected",
        wc_proxy_socks5_connect_transport(&transport, &config.proxy, "192.0.2.21", 43, 0,
            no_deadline, &status) == WC_PROXY_RESULT_AUTH_REQUIRED);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks4_success_response;
    fake.response_length = sizeof(socks4_success_response);
    config.proxy.has_credentials = 0;
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks4-ipv4",
        wc_proxy_socks4_connect_transport(&transport, &config.proxy, "192.0.2.70", 43, 0,
            no_deadline, &status) == WC_PROXY_RESULT_SUCCEEDED && status == 0x5a &&
        fake.request_used == 9 &&
        memcmp(fake.request, "\x04\x01\x00\x2b\xc0\x00\x02\x46\x00", 9) == 0);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks4_success_response;
    fake.response_length = sizeof(socks4_success_response);
    config.proxy.has_credentials = 1;
    snprintf(config.proxy.username, sizeof(config.proxy.username), "user");
    snprintf(config.proxy.password, sizeof(config.proxy.password), "not-sent");
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks4a-userid-domain",
        wc_proxy_socks4_connect_transport(&transport, &config.proxy, "whois.example", 4343, 1,
            no_deadline, &status) == WC_PROXY_RESULT_SUCCEEDED && status == 0x5a &&
        fake.request_used == 27 &&
        memcmp(fake.request + 8, "user\0whois.example\0", 19) == 0 &&
        strstr(fake.request, "not-sent") == NULL);
    memset(&fake, 0, sizeof(fake));
    fake.response = (const char*)socks4_rejected_response;
    fake.response_length = sizeof(socks4_rejected_response);
    config.proxy.has_credentials = 0;
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("socks4-rejected",
        wc_proxy_socks4_connect_transport(&transport, &config.proxy, "192.0.2.71", 43, 0,
            no_deadline, &status) == WC_PROXY_RESULT_REJECTED && status == 0x5b);
    failed |= wc_proxy_test_report("socks4-reply-classes",
        wc_proxy_socks4_classify(0x5a) == WC_PROXY_RESULT_SUCCEEDED &&
        wc_proxy_socks4_classify(0x5b) == WC_PROXY_RESULT_REJECTED &&
        wc_proxy_socks4_classify(0x5c) == WC_PROXY_RESULT_AUTH_REQUIRED &&
        wc_proxy_socks4_classify(0x5d) == WC_PROXY_RESULT_AUTH_REQUIRED &&
        wc_proxy_socks4_classify(0x01) == WC_PROXY_RESULT_UNKNOWN_REPLY);
    failed |= wc_proxy_test_report("socks5-reply-classes",
        wc_proxy_socks5_classify(0x00) == WC_PROXY_RESULT_SUCCEEDED &&
        wc_proxy_socks5_classify(0x01) == WC_PROXY_RESULT_GENERAL_FAILURE &&
        wc_proxy_socks5_classify(0x02) == WC_PROXY_RESULT_RULESET_DENIED &&
        wc_proxy_socks5_classify(0x03) == WC_PROXY_RESULT_NETWORK_UNREACHABLE &&
        wc_proxy_socks5_classify(0x04) == WC_PROXY_RESULT_HOST_UNREACHABLE &&
        wc_proxy_socks5_classify(0x05) == WC_PROXY_RESULT_CONNECTION_REFUSED &&
        wc_proxy_socks5_classify(0x06) == WC_PROXY_RESULT_TTL_EXPIRED &&
        wc_proxy_socks5_classify(0x07) == WC_PROXY_RESULT_COMMAND_UNSUPPORTED &&
        wc_proxy_socks5_classify(0x08) == WC_PROXY_RESULT_ADDRESS_TYPE_UNSUPPORTED &&
        wc_proxy_socks5_classify(0x09) == WC_PROXY_RESULT_UNKNOWN_REPLY &&
        wc_proxy_result_is_terminal(WC_PROXY_RESULT_RULESET_DENIED) &&
        !wc_proxy_result_is_terminal(WC_PROXY_RESULT_CONNECTION_REFUSED));
    wc_proxy_secure_clear(&fake, sizeof(fake));
    wc_proxy_secure_clear(&config.proxy, sizeof(config.proxy));
    return failed;
}
