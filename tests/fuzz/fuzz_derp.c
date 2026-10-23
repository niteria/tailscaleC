#include "tailscalec/derp.h"
#include "tailscalec/crypto.h"
#include "tailscalec/nacl.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static tsc_derp waiting, ready;
static int initialized;

static void drain(tsc_derp *d, unsigned selector)
{
    const uint8_t *output;
    size_t length;
    if (tsc_derp_output(d, &output, &length) == TSC_OK) {
        assert(output >= d->transmit_buffer);
        assert(length <= sizeof(d->transmit_buffer));
        assert(tsc_derp_output_consumed(d, length + 1) == TSC_ERR_ARGUMENT);
        /* Partial writes exercise cursor and queued-pong transitions. */
        size_t first = selector % (length + 1);
        assert(tsc_derp_output_consumed(d, first) == TSC_OK);
        assert(tsc_derp_output_consumed(d, length - first) == TSC_OK);
    }
}

static void feed(tsc_derp *d, const uint8_t *data, size_t size, unsigned chunk)
{
    size_t at = 0;
    for (size_t attempt = 0; attempt < size + 16; attempt++) {
        size_t count = size - at;
        if (chunk && count > chunk) count = chunk;
        size_t consumed = SIZE_MAX;
        tsc_derp_event event;
        int rc = tsc_derp_feed(d, data + at, count, &consumed, &event);
        assert(consumed <= count);
        at += consumed;
        if (event.data) {
            assert(event.data >= d->receive_buffer);
            assert(event.data <= d->receive_buffer + sizeof(d->receive_buffer));
            assert(event.length <= (size_t)(d->receive_buffer + sizeof(d->receive_buffer) - event.data));
        }
        if (rc < 0) {
            size_t ignored;
            assert(tsc_derp_feed(d, NULL, 0, &ignored, &event) == rc);
            return;
        }
        drain(d, chunk);
        if (at == size && consumed == 0) return;
    }
    assert(at == size);
}

static void header(uint8_t *frame, uint8_t type, size_t n)
{
    frame[0] = type;
    frame[1] = (uint8_t)(n >> 24); frame[2] = (uint8_t)(n >> 16);
    frame[3] = (uint8_t)(n >> 8); frame[4] = (uint8_t)n;
}

static void setup(void)
{
    uint8_t client_private[32] = {1}, server_private[32] = {2};
    uint8_t frame[128] = {0};
    assert(tsc_derp_init(&waiting, client_private) == TSC_OK);
    assert(tsc_derp_start(&waiting, NULL) == TSC_OK);
    header(frame, 1, 40);
    memcpy(frame + 5, "DERP\xf0\x9f\x94\x91", 8);
    assert(tsc_crypto_x25519_public(frame + 13, server_private) == TSC_OK);
    feed(&waiting, frame, 45, 0);
    ready = waiting;
    memset(frame, 0, sizeof(frame));
    header(frame, 3, 42);
    assert(tsc_nacl_box_afternm(frame + 29, (const uint8_t *)"{}", 2,
        frame + 5, ready.shared_key) == TSC_OK);
    feed(&ready, frame, 47, 0);
    assert(tsc_derp_is_ready(&ready));
    initialized = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 16384) return 0;
    if (!initialized) setup();
    unsigned selector = size ? data[0] : 0;
    tsc_derp d = ready;
    feed(&d, data, size, selector % 19);
    d = waiting;
    /* Authenticate arbitrary JSON so the server-info parser gets fuzzed too. */
    if (size + 40 <= TSC_DERP_MAX_FRAME_SIZE) {
        uint8_t frame[TSC_DERP_MAX_FRAME_SIZE + 5] = {0};
        header(frame, 3, size + 40);
        assert(tsc_nacl_box_afternm(frame + 29, data, size,
            frame + 5, d.shared_key) == TSC_OK);
        feed(&d, frame, size + 45, selector % 17);
    }
    uint8_t private_key[32] = {3};
    assert(tsc_derp_init(&d, private_key) == TSC_OK);
    assert(tsc_derp_start(&d, "localhost:443") == TSC_OK);
    feed(&d, data, size, selector % 23);
    tsc_derp_clear(&d);
    return 0;
}
