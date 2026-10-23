#include "tailscalec/derp.h"
#include "tailscalec/crypto.h"
#include "tailscalec/stream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if TSC_ENABLE_DERP

typedef struct {
    tsc_derp derp;
    tsc_stream stream;
    uint8_t input[61];
    size_t used, available;
} connection;

static int progress(connection *c, tsc_derp_event *event)
{
    const uint8_t *output;
    size_t n, moved;
    int status;
    memset(event, 0, sizeof(*event));
    /* Force small partial writes; output bytes must remain stable across all
     * retries. Writes drain before reads to exercise bounded backpressure. */
    while ((status = tsc_derp_output(&c->derp, &output, &n)) == TSC_OK) {
        if (n > 23) n = 23;
        status = tsc_stream_write(&c->stream, output, n, &moved, 1000);
        if (status != TSC_OK) return status;
        if (!moved) return TSC_ERR_IO;
        status = tsc_derp_output_consumed(&c->derp, moved);
        if (status != TSC_OK) return status;
    }
    if (status != TSC_AGAIN) return status;
    if (c->used == c->available) {
        status = tsc_derp_feed(&c->derp, NULL, 0, &moved, event);
        if (status < 0 || event->type != TSC_DERP_EVENT_NONE) return status;
        if (tsc_derp_output(&c->derp, &output, &n) == TSC_OK) return TSC_AGAIN;
        c->used = c->available = 0;
        status = tsc_stream_read(&c->stream, c->input, sizeof(c->input),
                                 &c->available, 1000);
        if (status != TSC_OK) return status;
        if (!c->available) return TSC_ERR_IO;
    }
    status = tsc_derp_feed(&c->derp, c->input+c->used,
                          c->available-c->used, &moved, event);
    c->used += moved;
    return status;
}

static int expect(connection *c, tsc_derp_event_type type,
                   tsc_derp_event *event)
{
    size_t attempts;
    int status;
    for (attempts = 0; attempts < 10000; ++attempts) {
        status = progress(c, event);
        if (status < 0) return status;
        if (event->type == type) return TSC_OK;
        if (event->type == TSC_DERP_EVENT_HEALTH && event->length) return TSC_ERR_PROTOCOL;
    }
    return TSC_ERR_TIMEOUT;
}

static int decode_key(uint8_t key[32], const char *s)
{
    size_t i;
    if (strlen(s) != 64) return 0;
    for (i = 0; i < 32; ++i) {
        unsigned a, b;
        char x = s[i*2], y = s[i*2+1];
        a = x >= '0' && x <= '9' ? (unsigned)(x-'0') :
            x >= 'a' && x <= 'f' ? (unsigned)(x-'a'+10) : 16;
        b = y >= '0' && y <= '9' ? (unsigned)(y-'0') :
            y >= 'a' && y <= 'f' ? (unsigned)(y-'a'+10) : 16;
        if (a > 15 || b > 15) return 0;
        key[i] = (uint8_t)((a << 4) | b);
    }
    return 1;
}

int main(int argc, char **argv)
{
    connection c = {0};
    tsc_stream_options options = {5000, 0, NULL, 0};
    tsc_derp_event event;
    uint8_t key[32], peer[32], packet[TSC_MAX_DATAGRAM_SIZE];
    uint8_t ping[8] = {1,2,3,4,5,6,7,8};
    char host[300];
    size_t i, j, n, sizes[] = {0, 1, 7, 40, 148, TSC_MAX_DATAGRAM_SIZE};
    unsigned long port;
    int status = TSC_ERR_ARGUMENT;
    if (argc != 4) return 77;
    port = strtoul(argv[2], NULL, 10);
    if (!port || port > 65535 || !decode_key(peer, argv[3])) return 1;
    snprintf(host, sizeof(host), "%s:%lu", argv[1], port);
    if ((status = tsc_crypto_random(key, sizeof(key))) != TSC_OK ||
        (status = tsc_derp_init(&c.derp, key)) != TSC_OK ||
        (status = tsc_stream_connect(&c.stream, argv[1], (uint16_t)port, &options)) != TSC_OK ||
        (status = tsc_derp_start(&c.derp, host)) != TSC_OK ||
        (status = expect(&c, TSC_DERP_EVENT_READY, &event)) != TSC_OK) goto done;
    tsc_crypto_zero(key, sizeof(key));
    if ((status = tsc_derp_note_preferred(&c.derp, 1)) != TSC_OK) goto done;
    /* A read of server-side ping response flushes the preferred-home frame. */
    {
        const uint8_t *out;
        size_t len, moved;
        while (tsc_derp_output(&c.derp, &out, &len) == TSC_OK) {
            status = tsc_stream_write(&c.stream, out, len, &moved, 1000);
            if (status != TSC_OK || !moved) goto done;
            if ((status = tsc_derp_output_consumed(&c.derp, moved)) != TSC_OK) goto done;
        }
    }
    if ((status = tsc_derp_ping(&c.derp, ping)) != TSC_OK ||
        (status = expect(&c, TSC_DERP_EVENT_PONG, &event)) != TSC_OK) goto done;
    if (event.length != 8 || memcmp(event.data, ping, 8)) { status = TSC_ERR_PROTOCOL; goto done; }
    for (i = 0; i < 240; ++i) {
        n = sizes[i % (sizeof(sizes)/sizeof(sizes[0]))];
        for (j = 0; j < n; ++j) packet[j] = (uint8_t)(i*13 + j*7);
        if ((status = tsc_derp_send(&c.derp, peer, packet, n)) != TSC_OK ||
            (status = expect(&c, TSC_DERP_EVENT_PACKET, &event)) != TSC_OK) goto done;
        if (event.length != n || memcmp(event.peer_key, peer, 32) ||
            (n && memcmp(event.data, packet, n))) { status = TSC_ERR_PROTOCOL; goto done; }
    }
    puts("DERP live: upstream Go server + Go peer, HTTP upgrade, authenticated login, ping/pong, 240 bidirectional packet relays passed");
    status = TSC_OK;
done:
    if (status != TSC_OK) fprintf(stderr, "DERP live failed: %d\n", status);
    tsc_crypto_zero(key, sizeof(key));
    tsc_derp_clear(&c.derp);
    tsc_stream_close(&c.stream);
    return status == TSC_OK ? 0 : 1;
}

#else
int main(void) { return 77; }
#endif
