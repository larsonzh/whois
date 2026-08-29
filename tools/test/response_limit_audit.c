// SPDX-License-Identifier: MIT

#include <stdio.h>

#if !defined(__linux__)

int main(void)
{
    fputs("[RESPONSE-LIMIT-AUDIT] status=SKIP reason=native-linux-required\n", stderr);
    return 2;
}

#else

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "wc/wc_net.h"

int wc_signal_should_terminate(void)
{
    return 0;
}

static int run_case(const char* name, size_t sent_len, int max_bytes,
                    size_t expected_len, int expected_truncated)
{
    int sockets[2] = {-1, -1};
    char* payload = NULL;
    char* received = NULL;
    size_t received_len = 0;
    int result = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        fprintf(stderr, "[RESPONSE-LIMIT-AUDIT] case=%s status=FAIL step=socketpair errno=%d\n",
                name, errno);
        goto cleanup;
    }

    payload = malloc(sent_len ? sent_len : 1);
    if (!payload) {
        fprintf(stderr, "[RESPONSE-LIMIT-AUDIT] case=%s status=FAIL step=malloc\n", name);
        goto cleanup;
    }
    memset(payload, 'A', sent_len);

    size_t written = 0;
    while (written < sent_len) {
        ssize_t count = write(sockets[0], payload + written, sent_len - written);
        if (count <= 0) {
            fprintf(stderr, "[RESPONSE-LIMIT-AUDIT] case=%s status=FAIL step=write errno=%d\n",
                    name, errno);
            goto cleanup;
        }
        written += (size_t)count;
    }
    if (shutdown(sockets[0], SHUT_WR) != 0) {
        fprintf(stderr, "[RESPONSE-LIMIT-AUDIT] case=%s status=FAIL step=shutdown errno=%d\n",
                name, errno);
        goto cleanup;
    }

    ssize_t rc = wc_recv_until_idle(sockets[1], &received, &received_len, 100, max_bytes);
    int observed_truncated = sent_len > received_len;
    int pass = rc == (ssize_t)expected_len && received_len == expected_len &&
               observed_truncated == expected_truncated;
    printf("[RESPONSE-LIMIT-AUDIT] case=%s status=%s sent=%zu cap=%d returned=%zd received=%zu truncated=%d\n",
           name, pass ? "PASS" : "FAIL", sent_len, max_bytes, rc, received_len,
           observed_truncated);
    result = pass ? 0 : 1;

cleanup:
    free(received);
    free(payload);
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    return result;
}

int main(void)
{
    int failures = 0;
    failures += run_case("below-cap", 31, 64, 31, 0);
    failures += run_case("at-cap", 64, 64, 64, 0);
    failures += run_case("over-cap", 65, 64, 64, 1);

    printf("[RESPONSE-LIMIT-AUDIT] summary status=%s cases=3 failures=%d silent_truncation=%s\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 0 ? "confirmed" : "unconfirmed");
    return failures == 0 ? 0 : 1;
}

#endif