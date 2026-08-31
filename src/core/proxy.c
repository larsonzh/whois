// SPDX-License-Identifier: MIT
// proxy.c - HTTP CONNECT and per-hop NO_PROXY routing

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "wc/wc_proxy.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        case WC_PROXY_RESULT_TIMEOUT: return "proxy-timeout";
        case WC_PROXY_RESULT_AUTH_REQUIRED: return "proxy-auth-required";
        case WC_PROXY_RESULT_REJECTED: return "proxy-rejected";
        case WC_PROXY_RESULT_UPSTREAM_FAILURE: return "proxy-upstream-failure";
        case WC_PROXY_RESULT_UNSUPPORTED: return "proxy-unsupported";
        default: return "proxy-protocol-failure";
    }
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
    wc_transport_t transport;
    uint64_t deadline_ms;
    int status = 0;
    wc_proxy_result_t result;
    if (used_proxy) *used_proxy = 0;
    if (proxy_result) *proxy_result = WC_PROXY_RESULT_SUCCEEDED;
    if (!config || !target_address || !out) return WC_ERR_INVALID;
    if (!wc_proxy_should_proxy(config, target_host, target_address, (int)target_port))
        return wc_dial_43(net_ctx, target_address, target_port, timeout_ms, retries, out);
    if (used_proxy) *used_proxy = 1;
    if (config->proxy.scheme != WC_PROXY_SCHEME_HTTP) {
        if (proxy_result) *proxy_result = WC_PROXY_RESULT_UNSUPPORTED;
        return WC_ERR_INVALID;
    }
    deadline_ms = wc_net_deadline_after(timeout_ms);
    wc_net_dial_policy_init(&policy);
    if (config->proxy.family == WC_PROXY_FAMILY_V4) policy.family = WC_NET_ENDPOINT_FAMILY_IPV4;
    else if (config->proxy.family == WC_PROXY_FAMILY_V6) policy.family = WC_NET_ENDPOINT_FAMILY_IPV6;
    policy.record_dns_health = 0;
    if (wc_net_dial_endpoint_until(net_ctx, config->proxy.endpoint_host,
            (uint16_t)config->proxy.endpoint_port, deadline_ms, retries, &policy, &endpoint) != WC_OK ||
        !endpoint.connected || endpoint.fd < 0) {
        if (out) *out = endpoint;
        if (proxy_result) *proxy_result = WC_PROXY_RESULT_TCP_FAILURE;
        return WC_ERR_IO;
    }
    wc_transport_init(&transport, &endpoint.fd);
    result = (wc_proxy_result_t)wc_proxy_http_connect_transport(&transport, &config->proxy,
        target_address, target_port, deadline_ms, &status);
    if (result != WC_PROXY_RESULT_SUCCEEDED) {
        wc_transport_close(&transport, "wc_proxy_connect_fail", config->debug);
        endpoint.connected = 0;
        endpoint.err = WC_ERR_IO;
        endpoint.last_errno = (result == WC_PROXY_RESULT_TIMEOUT) ? ETIMEDOUT : EPROTO;
    } else {
        snprintf(endpoint.ip, sizeof(endpoint.ip), "%s", target_address);
    }
    if ((config->debug || config->retry_metrics) && result != WC_PROXY_RESULT_SUCCEEDED)
        fprintf(stderr, "[PROXY] scheme=http phase=connect port=%u result=%s status=%d\n",
            (unsigned)config->proxy.endpoint_port, wc_proxy_result_name(result), status);
    *out = endpoint;
    if (proxy_result) *proxy_result = result;
    return result == WC_PROXY_RESULT_SUCCEEDED ? WC_OK : WC_ERR_IO;
}

typedef struct wc_proxy_fake {
    const char* response;
    size_t response_offset;
    char request[1024];
    size_t request_used;
} wc_proxy_fake_t;

static int wc_proxy_fake_read(void* context, char* buffer, size_t length)
{
    wc_proxy_fake_t* fake = (wc_proxy_fake_t*)context;
    size_t remaining = strlen(fake->response) - fake->response_offset;
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
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 204 No Content\r\nX-Test: yes\r\n\r\n";
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-2xx",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "2001:db8::9", 4343, UINT64_MAX, &status) == WC_PROXY_RESULT_SUCCEEDED &&
        status == 204 && strstr(fake.request, "CONNECT [2001:db8::9]:4343 HTTP/1.1\r\nHost: [2001:db8::9]:4343\r\n") != NULL);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
    config.proxy.has_credentials = 1;
    snprintf(config.proxy.username, sizeof(config.proxy.username), "user");
    snprintf(config.proxy.password, sizeof(config.proxy.password), "pass");
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-basic-407",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.10", 43, UINT64_MAX, &status) == WC_PROXY_RESULT_AUTH_REQUIRED &&
        status == 407 && strstr(fake.request, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != NULL);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    snprintf(config.proxy.username, sizeof(config.proxy.username), "u");
    snprintf(config.proxy.password, sizeof(config.proxy.password), "pp");
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-basic-padding",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.11", 43, UINT64_MAX, &status) == WC_PROXY_RESULT_SUCCEEDED &&
        strstr(fake.request, "Proxy-Authorization: Basic dTpwcA==\r\n") != NULL);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1\r\nX-Test: 200\r\n\r\n";
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-malformed-missing-status",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.12", 43, UINT64_MAX, &status) == WC_PROXY_RESULT_PROTOCOL_FAILURE);
    memset(&fake, 0, sizeof(fake));
    fake.response = "HTTP/1.1 200X Invalid\r\n\r\n";
    wc_transport_init_with_ops(&transport, &operations, &fake);
    failed |= wc_proxy_test_report("http-malformed-status-delimiter",
        wc_proxy_http_connect_transport(&transport, &config.proxy, "192.0.2.13", 43, UINT64_MAX, &status) == WC_PROXY_RESULT_PROTOCOL_FAILURE);
    wc_proxy_secure_clear(&fake, sizeof(fake));
    wc_proxy_secure_clear(&config.proxy, sizeof(config.proxy));
    return failed;
}
