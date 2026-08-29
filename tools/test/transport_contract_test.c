#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wc/wc_transport.h"

typedef struct fake_transport_state {
    const char* input;
    size_t input_length;
    size_t input_offset;
    char output[32];
    size_t output_length;
    size_t max_write;
    uint64_t expected_deadline;
    int deadline_mismatch;
    int wait_events;
    int wait_result;
    int closed;
} fake_transport_state_t;

void wc_safe_close(int* fd, const char* reason, int debug_enabled)
{
    (void)reason;
    (void)debug_enabled;
    if (fd) *fd = -1;
}

int wc_signal_should_terminate(void)
{
    return 0;
}

static int fake_read(void* context, char* buffer, size_t length)
{
    fake_transport_state_t* state = (fake_transport_state_t*)context;
    size_t remaining = state->input_length - state->input_offset;
    size_t count = remaining < length ? remaining : length;
    if (count == 0) return 0;
    memcpy(buffer, state->input + state->input_offset, count);
    state->input_offset += count;
    return (int)count;
}

static int fake_write(void* context, const char* data, size_t length)
{
    fake_transport_state_t* state = (fake_transport_state_t*)context;
    size_t count = length < state->max_write ? length : state->max_write;
    memcpy(state->output + state->output_length, data, count);
    state->output_length += count;
    return (int)count;
}

static int fake_wait(void* context, int events, uint64_t deadline_ms)
{
    fake_transport_state_t* state = (fake_transport_state_t*)context;
    state->wait_events |= events;
    if (state->expected_deadline != 0 && deadline_ms != state->expected_deadline)
        state->deadline_mismatch = 1;
    return state->wait_result;
}

static void fake_close(void* context, const char* reason, int debug_enabled)
{
    fake_transport_state_t* state = (fake_transport_state_t*)context;
    (void)reason;
    (void)debug_enabled;
    state->closed = 1;
}

static int require(int condition, const char* label)
{
    if (condition) return 0;
    fprintf(stderr, "[TRANSPORT-CONTRACT] FAIL %s\n", label);
    return 1;
}

int main(void)
{
    static const wc_transport_ops_t fake_ops = {
        fake_read,
        fake_write,
        fake_wait,
        fake_close
    };
    fake_transport_state_t state;
    wc_transport_t transport;
    wc_transport_t invalid_transport;
    char* received = NULL;
    size_t received_length = 0;
    int failed = 0;

    memset(&state, 0, sizeof(state));
    memset(&invalid_transport, 0, sizeof(invalid_transport));
    state.input = "reply";
    state.input_length = 5;
    state.max_write = 2;
    state.expected_deadline = wc_transport_deadline_after(1000);
    state.wait_result = 1;
    wc_transport_init_with_ops(&transport, &fake_ops, &state);

    failed |= require(wc_transport_send_all_until(&transport, "query", 5, state.expected_deadline) == 5,
                      "partial-write-result");
    failed |= require(state.output_length == 5 && memcmp(state.output, "query", 5) == 0,
                      "partial-write-data");
    failed |= require((state.wait_events & WC_TRANSPORT_WAIT_WRITE) != 0 && !state.deadline_mismatch,
                      "write-deadline-dispatch");

    state.expected_deadline = 0;
    state.wait_events = 0;
    failed |= require(wc_transport_recv_until_idle(&transport, &received, &received_length, 100, 16) == 5,
                      "read-result");
    failed |= require(received && received_length == 5 && memcmp(received, "reply", 5) == 0,
                      "read-data");
    failed |= require((state.wait_events & WC_TRANSPORT_WAIT_READ) != 0, "read-wait-dispatch");
    free(received);

    wc_transport_close(&transport, "contract-test", 0);
    failed |= require(state.closed, "close-dispatch");

    state.wait_result = 0;
    failed |= require(wc_transport_send_all_until(&transport, "x", 1, UINT64_C(1)) < 0,
                      "wait-timeout");
    failed |= require(wc_transport_send_all(&invalid_transport, "x", 1, 10) < 0,
                      "invalid-transport");

    if (failed) return 1;
    puts("[TRANSPORT-CONTRACT] PASS");
    return 0;
}