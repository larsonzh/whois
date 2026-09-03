// SPDX-License-Identifier: MIT
// tls_companion.c - optional handoff from the compact client to its TLS build

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "wc/wc_tls_companion.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WHOIS_VERSION
#define WHOIS_VERSION "3.4.0"
#endif

#define WC_TLS_COMPANION_ACTIVE "WHOIS_TLS_COMPANION_ACTIVE"
#define WC_TLS_COMPANION_VERSION "WHOIS_TLS_COMPANION_EXPECT_VERSION"

#if defined(_WIN32) || defined(__MINGW32__)
#include <process.h>
#include <windows.h>
#define WC_TLS_COMPANION_PATH_CAPACITY 32768
#else
#include <unistd.h>
#define WC_TLS_COMPANION_PATH_CAPACITY 4096
#endif

static int wc_tls_companion_is_meta_request(const wc_opts_t* opts)
{
    return opts && (opts->show_help || opts->show_version || opts->show_servers ||
        opts->show_about || opts->show_examples || opts->show_selftest);
}

#ifndef WHOIS_TLS
static int wc_tls_companion_append_suffix(char* path, size_t capacity)
{
    static const char suffix[] = "-tls";
    size_t length;
    size_t extension = 0;
    if (!path || capacity == 0) return 0;
    length = strlen(path);
#if defined(_WIN32) || defined(__MINGW32__)
    if (length >= 4 && path[length - 4] == '.' &&
        (path[length - 3] == 'e' || path[length - 3] == 'E') &&
        (path[length - 2] == 'x' || path[length - 2] == 'X') &&
        (path[length - 1] == 'e' || path[length - 1] == 'E'))
        extension = 4;
#endif
    if (length + sizeof(suffix) > capacity) return 0;
    memmove(path + length - extension + sizeof(suffix) - 1,
        path + length - extension, extension + 1);
    memcpy(path + length - extension, suffix, sizeof(suffix) - 1);
    return 1;
}

static int wc_tls_companion_path(const char* argv0, char* path, size_t capacity)
{
#if defined(_WIN32) || defined(__MINGW32__)
    DWORD length = GetModuleFileNameA(NULL, path, (DWORD)capacity);
    (void)argv0;
    if (length == 0 || (size_t)length >= capacity) return 0;
    path[length] = '\0';
#else
    ssize_t length = readlink("/proc/self/exe", path, capacity - 1);
    if (length < 0) {
        if (!argv0 || (!strchr(argv0, '/') && !strchr(argv0, '\\'))) return 0;
        if (strlen(argv0) >= capacity) return 0;
        memcpy(path, argv0, strlen(argv0) + 1);
    } else {
        path[length] = '\0';
    }
#endif
    return wc_tls_companion_append_suffix(path, capacity);
}

static int wc_tls_companion_set_environment(void)
{
#if defined(_WIN32) || defined(__MINGW32__)
    return _putenv_s(WC_TLS_COMPANION_ACTIVE, "1") == 0 &&
        _putenv_s(WC_TLS_COMPANION_VERSION, WHOIS_VERSION) == 0;
#else
    return setenv(WC_TLS_COMPANION_ACTIVE, "1", 1) == 0 &&
        setenv(WC_TLS_COMPANION_VERSION, WHOIS_VERSION, 1) == 0;
#endif
}
#endif

int wc_tls_companion_maybe_exec(int argc, char* argv[], const wc_opts_t* opts)
{
    (void)argc;
    (void)argv;
    if (!opts || opts->proxy.scheme != WC_PROXY_SCHEME_HTTPS ||
        wc_tls_companion_is_meta_request(opts)) return 0;
#ifdef WHOIS_TLS
    {
        const char* expected_version = getenv(WC_TLS_COMPANION_VERSION);
        if (expected_version && strcmp(expected_version, WHOIS_VERSION) != 0) {
            fprintf(stderr, "Error: HTTPS proxy TLS companion version mismatch (expected %s, got %s)\n",
                expected_version, WHOIS_VERSION);
            return 37;
        }
    }
    return 0;
#else
    {
        char path[WC_TLS_COMPANION_PATH_CAPACITY];
        if (getenv(WC_TLS_COMPANION_ACTIVE)) {
            fprintf(stderr, "Error: HTTPS proxy TLS companion is not TLS-enabled\n");
            return 37;
        }
        if (!argv || !argv[0] || !wc_tls_companion_path(argv[0], path, sizeof(path))) {
            fprintf(stderr, "Error: Cannot determine HTTPS proxy TLS companion path\n");
            return 37;
        }
        if (!wc_tls_companion_set_environment()) {
            fprintf(stderr, "Error: Cannot prepare HTTPS proxy TLS companion environment\n");
            return 37;
        }
#if defined(_WIN32) || defined(__MINGW32__)
        _execv(path, (const char* const*)argv);
#else
        execv(path, argv);
#endif
        fprintf(stderr, "Error: HTTPS proxy requires TLS companion '%s': %s\n", path, strerror(errno));
        return 37;
    }
#endif
}