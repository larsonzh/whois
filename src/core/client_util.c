// SPDX-License-Identifier: GPL-3.0-or-later
// Client-side utility helpers for whois CLI layer.

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "wc/wc_client_util.h"
#include "wc/wc_client_usage.h"
#include "wc/wc_output.h"
#include "wc/wc_util.h"

static int wc_client_debug_enabled(void)
{
    return wc_output_is_debug_enabled();
}

size_t wc_client_parse_size_with_unit(const char* str)
{
    const int debug = wc_client_debug_enabled();
    if (str == NULL || *str == '\0') {
        return 0;
    }

    // Skip leading whitespace
    while (isspace((unsigned char)*str)) str++;

    if (*str == '\0') {
        return 0;
    }

    char* end;
    errno = 0;
    unsigned long long size = strtoull(str, &end, 10);
    // Check for conversion errors
    if (errno == ERANGE) {
        return SIZE_MAX;
    }

    if (end == str) {
        return 0;  // Invalid number
    }

    // Skip whitespace after number
    while (isspace((unsigned char)*end)) end++;

    // Process units
    if (*end) {
        char unit = (char)toupper((unsigned char)*end);
        switch (unit) {
        case 'K':
            if (size > SIZE_MAX / 1024) return SIZE_MAX;
            size *= 1024;
            end++;
            break;
        case 'M':
            if (size > SIZE_MAX / (1024ULL * 1024ULL)) return SIZE_MAX;
            size *= 1024ULL * 1024ULL;
            end++;
            break;
        case 'G':
            if (size > SIZE_MAX / (1024ULL * 1024ULL * 1024ULL)) return SIZE_MAX;
            size *= 1024ULL * 1024ULL * 1024ULL;
            end++;
            break;
        default:
            // Invalid unit, but may just be a number
            if (debug) {
                printf("[DEBUG] Unknown unit '%c' in size specification, ignoring\n",
                       unit);
            }
            break;
        }

        // Check for extra characters (like "B" in "10MB")
        if (*end && !isspace((unsigned char)*end)) {
            if (debug) {
                printf("[DEBUG] Extra characters after unit: '%s'\n", end);
            }
        }
    }

    // Check if it exceeds size_t maximum value
    if (size > SIZE_MAX) {
        return SIZE_MAX;
    }

    if (debug) {
        printf("[DEBUG] Parsed size: '%s' -> %llu bytes\n", str, size);
    }

    return (size_t)size;
}

char* wc_client_get_server_target(const char* server_input)
{
    if (!server_input || !*server_input) {
        return NULL;
    }

    struct in_addr addr4;
    struct in6_addr addr6;

    // Preserve literals as-is so downstream code can reuse them directly.
    if (inet_pton(AF_INET, server_input, &addr4) == 1) {
        return wc_safe_strdup(server_input, __func__);
    }
    if (inet_pton(AF_INET6, server_input, &addr6) == 1) {
        return wc_safe_strdup(server_input, __func__);
    }

    const char* mapped = wc_client_find_server_domain(server_input);
    if (mapped) {
        return wc_safe_strdup(mapped, __func__);
    }

    if (strchr(server_input, '.') != NULL || strchr(server_input, ':') != NULL) {
        return wc_safe_strdup(server_input, __func__);
    }

    return NULL;
}

int wc_client_is_valid_domain_name(const char* domain)
{
    if (domain == NULL || *domain == '\0') {
        return 0;
    }

    size_t len = strlen(domain);
    if (len < 1 || len > 253) {
        return 0;
    }

    // Check for valid characters: alphanumeric, hyphen, dot
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)domain[i];
        if (!(isalnum(c) || c == '-' || c == '.')) {
            return 0;
        }
    }

    // Check for consecutive dots or leading/trailing dots
    if (domain[0] == '.' || domain[len - 1] == '.' || strstr(domain, "..")) {
        return 0;
    }

    // Check each label length (between dots)
    const char* start = domain;
    const char* end = domain;
    while (*end) {
        if (*end == '.') {
            size_t label_len = (size_t)(end - start);
            if (label_len < 1 || label_len > 63) {
                return 0;
            }
            start = end + 1;
        }
        end++;
    }

    // Check last label
    size_t last_label_len = (size_t)(end - start);
    if (last_label_len < 1 || last_label_len > 63) {
        return 0;
    }

    return 1;
}

int wc_client_is_valid_ip_address(const char* ip)
{
    if (!ip || !*ip) {
        return 0;
    }

    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip, &addr4) == 1) {
        return 1;
    }

    if (inet_pton(AF_INET6, ip, &addr6) == 1) {
        return 1;
    }

    return 0;
}

int wc_client_is_private_ip(const char* ip)
{
    if (!ip || !*ip) return 0;

    struct in_addr addr4;
    struct in6_addr addr6;

    // Check IPv4 private ranges
    if (inet_pton(AF_INET, ip, &addr4) == 1) {
        unsigned long ip_addr = ntohl(addr4.s_addr);
        if ((ip_addr >= 0x0A000000 && ip_addr <= 0x0AFFFFFF) ||
            (ip_addr >= 0xAC100000 && ip_addr <= 0xAC1FFFFF) ||
            (ip_addr >= 0xC0A80000 && ip_addr <= 0xC0A8FFFF)) {
            return 1;
        }
        return 0;
    }

    // Check IPv6 private ranges
    if (inet_pton(AF_INET6, ip, &addr6) == 1) {
        // Unique Local Address (fc00::/7)
        if ((addr6.s6_addr[0] & 0xFE) == 0xFC) {
            return 1;
        }
        // Link-local (fe80::/10)
        if (addr6.s6_addr[0] == 0xFE && (addr6.s6_addr[1] & 0xC0) == 0x80) {
            return 1;
        }
        // Documentation (2001:db8::/32)
        if (strncmp(ip, "2001:db8:", 9) == 0) {
            return 1;
        }
        // Loopback
        if (strcmp(ip, "::1") == 0) {
            return 1;
        }
    }

    return 0;
}

int wc_client_validate_dns_response(const char* ip)
{
    if (!ip || !*ip) {
        return 0;
    }

    if (!wc_client_is_valid_ip_address(ip)) {
        return 0;
    }

    if (wc_client_is_private_ip(ip)) {
        wc_output_log_message("WARN", "DNS response contains private IP: %s", ip);
    }

    return 1;
}

size_t wc_client_get_free_memory(void)
{
    FILE* meminfo = fopen("/proc/meminfo", "r");
    if (!meminfo) return 0;

    char line[256];
    size_t free_mem = 0;

    while (fgets(line, sizeof(line), meminfo)) {
        if (strncmp(line, "MemFree:", 8) == 0) {
            sscanf(line + 8, "%zu", &free_mem);
            break;
        }
    }

    fclose(meminfo);
    return free_mem;
}

void wc_client_report_memory_error(const char* function, size_t size)
{
    fprintf(stderr,
            "Error: Memory allocation failed in %s for %zu bytes\n",
            function,
            size);
    fprintf(stderr,
            "       Reason: %s\n",
            strerror(errno));

    if (wc_client_debug_enabled()) {
        fprintf(stderr,
                "       Available memory might be limited on this system\n");
    }
}
