#include "tailscalec/derp.h"
#include "tailscalec/crypto.h"
#include "tailscalec/nacl.h"
#include "check.h"
#include <string.h>

#if TSC_ENABLE_DERP

static const uint8_t client_private[32] = { 17, 33, 4, 88, 9 };
static const uint8_t server_private[32] = { 57, 77, 6, 13, 11 };
static uint8_t server_public[32];

static size_t frame(uint8_t *out, uint8_t type, const void *data, size_t n)
{
    out[0] = type;
    out[1] = (uint8_t)(n >> 24);
    out[2] = (uint8_t)(n >> 16);
    out[3] = (uint8_t)(n >> 8);
    out[4] = (uint8_t)n;
    if (n) memcpy(out + 5, data, n);
    return n + 5;
}

static size_t greeting(uint8_t *out)
{
    uint8_t body[48] = { 'D','E','R','P',0xf0,0x9f,0x94,0x91 };
    memcpy(body + 8, server_public, 32);
    /* A future greeting extension must not break the client. */
    memset(body + 40, 0xdd, 8);
    return frame(out, 1, body, sizeof(body));
}

static void drain(tsc_derp *d)
{
    const uint8_t *out;
    size_t length;
    while (tsc_derp_output(d, &out, &length) == TSC_OK) {
        CHECK(out != NULL && length > 0);
        CHECK(tsc_derp_output_consumed(d, length > 7 ? 7 : length) == TSC_OK);
    }
}

static tsc_derp_event feed_fragments(tsc_derp *d, const uint8_t *data,
                                    size_t length, size_t fragment)
{
    tsc_derp_event event;
    size_t offset = 0, used, n;
    int status = TSC_AGAIN;
    memset(&event, 0, sizeof(event));
    while (offset < length) {
        n = length - offset;
        if (n > fragment) n = fragment;
        status = tsc_derp_feed(d, data + offset, n, &used, &event);
        CHECK(status == TSC_OK || status == TSC_AGAIN);
        CHECK(used > 0 && used <= n);
        offset += used;
    }
    CHECK(status == TSC_OK);
    return event;
}

static void begin(tsc_derp *d, int http)
{
    const char response[] = "HTTP/1.1 101 Switching Protocols\r\n"
        "uPgRaDe: dErP\r\nConnection: keep-alive, Upgrade\r\n\r\n";
    uint8_t input[256], shared[32], plaintext[128];
    const uint8_t *output;
    size_t n, length, used;
    tsc_derp_event event;
    CHECK(tsc_derp_init(d, client_private) == TSC_OK);
    CHECK(!tsc_derp_is_ready(d));
    CHECK(tsc_derp_start(d, http ? "localhost:1234" : NULL) == TSC_OK);
    if (http) {
        CHECK(tsc_derp_output(d, &output, &length) == TSC_OK);
        CHECK(length > 70 && !memcmp(output, "GET /derp HTTP/1.1\r\n", 20));
        CHECK(tsc_derp_output_consumed(d, length + 1) == TSC_ERR_ARGUMENT);
        drain(d);
        for (n = 0; n < sizeof(response)-1; ++n) {
            CHECK(tsc_derp_feed(d, response+n, 1, &used, &event) == TSC_AGAIN);
            CHECK(used == 1);
        }
    }
    n = greeting(input);
    event = feed_fragments(d, input, n, 1);
    CHECK(event.type == TSC_DERP_EVENT_NONE);
    CHECK(tsc_derp_output(d, &output, &length) == TSC_OK);
    CHECK(output[0] == 2 && length > 77);
    CHECK(!memcmp(output+5, d->public_key, 32));
    CHECK(tsc_nacl_box_beforenm(shared, output+5, server_private) == TSC_OK);
    CHECK(length - 77 < sizeof(plaintext));
    CHECK(tsc_nacl_box_open_afternm(plaintext, output+61, length-61,
                                   output+37, shared) == TSC_OK);
    CHECK(length-77 == strlen("{\"version\":2,\"CanAckPings\":true}"));
    CHECK(!memcmp(plaintext, "{\"version\":2,\"CanAckPings\":true}", length-77));
    for (n = 0; n < 32; ++n) CHECK(d->private_key[n] == 0);
    drain(d);
    tsc_crypto_zero(shared, sizeof(shared));
}

static size_t info_frame(tsc_derp *d, uint8_t *out, const char *json)
{
    uint8_t body[1024] = {0}, shared[32];
    size_t n = strlen(json);
    CHECK(n < sizeof(body)-40);
    memset(body, 0x5a, 24);
    CHECK(tsc_nacl_box_beforenm(shared, d->public_key, server_private) == TSC_OK);
    CHECK(tsc_nacl_box_afternm(body+24, (const uint8_t *)json, n,
                              body, shared) == TSC_OK);
    tsc_crypto_zero(shared, sizeof(shared));
    return frame(out, 3, body, n+40);
}

static void ready(tsc_derp *d)
{
    uint8_t input[1024];
    size_t n;
    tsc_derp_event event;
    begin(d, 1);
    n = info_frame(d, input, "{\"version\":2,\"future\":[true,null,{\"a\":-2.3e+4}]}");
    event = feed_fragments(d, input, n, 3);
    CHECK(event.type == TSC_DERP_EVENT_READY);
    CHECK(event.length > 10 && event.data[0] == '{');
    CHECK(tsc_derp_is_ready(d));
    for (n = 0; n < 32; ++n) CHECK(d->shared_key[n] == 0);
}

static void test_frames(void)
{
    tsc_derp d;
    tsc_derp_event event;
    uint8_t input[TSC_DERP_BUFFER_SIZE + 10], payload[TSC_MAX_DATAGRAM_SIZE + 32];
    const uint8_t *out;
    size_t n, used, length;
    ready(&d);
    memset(payload, 0xa5, sizeof(payload));
    n = frame(input, 5, payload, sizeof(payload));
    event = feed_fragments(&d, input, n, 1);
    CHECK(event.type == TSC_DERP_EVENT_PACKET);
    CHECK(event.length == TSC_MAX_DATAGRAM_SIZE);
    CHECK(!memcmp(event.peer_key, payload, 32));
    CHECK(!memcmp(event.data, payload+32, event.length));
    CHECK(tsc_derp_send(&d, server_public, payload, TSC_MAX_DATAGRAM_SIZE) == TSC_OK);
    CHECK(tsc_derp_send(&d, server_public, payload, 1) == TSC_AGAIN);
    CHECK(tsc_derp_output(&d, &out, &length) == TSC_OK);
    CHECK(length == TSC_MAX_DATAGRAM_SIZE + 37 && out[0] == 4);
    CHECK(!memcmp(out+5, server_public, 32));
    CHECK(!memcmp(out+37, payload, TSC_MAX_DATAGRAM_SIZE));
    drain(&d);
    CHECK(tsc_derp_send(&d, server_public, payload, TSC_MAX_DATAGRAM_SIZE+1) == TSC_ERR_SPACE);
    CHECK(tsc_derp_send(&d, server_public, NULL, 0) == TSC_OK);
    drain(&d);
    CHECK(tsc_derp_note_preferred(&d, 1) == TSC_OK);
    CHECK(tsc_derp_output(&d, &out, &length) == TSC_OK && length == 6 && out[5] == 1);
    drain(&d);
    CHECK(tsc_derp_note_preferred(&d, 2) == TSC_ERR_ARGUMENT);
    n = frame(input, 8, payload, 32);
    event = feed_fragments(&d, input, n, 4);
    CHECK(event.type == TSC_DERP_EVENT_PEER_GONE && event.reason == 0);
    payload[32] = 1;
    n = frame(input, 8, payload, 33);
    event = feed_fragments(&d, input, n, 2);
    CHECK(event.type == TSC_DERP_EVENT_PEER_GONE && event.reason == 1);
    n = frame(input, 0x14, "duplicate", 9);
    event = feed_fragments(&d, input, n, 2);
    CHECK(event.type == TSC_DERP_EVENT_HEALTH && event.length == 9);
    memset(payload, 0, 8);
    payload[3] = 25; payload[7] = 50;
    n = frame(input, 0x15, payload, 8);
    event = feed_fragments(&d, input, n, 2);
    CHECK(event.type == TSC_DERP_EVENT_RESTARTING);
    CHECK(event.reconnect_in_ms == 25 && event.retry_for_ms == 50);
    n = frame(input, 6, NULL, 0);
    n += frame(input+n, 0x71, "future", 6);
    CHECK(tsc_derp_feed(&d, input, n, &used, &event) == TSC_OK && used == 5);
    CHECK(event.type == TSC_DERP_EVENT_NONE);
    CHECK(tsc_derp_feed(&d, input+used, n-used, &length, &event) == TSC_OK);
    CHECK(length == 11 && event.type == TSC_DERP_EVENT_NONE);
    tsc_derp_clear(&d);
    for (n = 0; n < sizeof(d); ++n) CHECK(((uint8_t *)&d)[n] == 0);
}

static void test_ping_backpressure(void)
{
    tsc_derp d;
    tsc_derp_event event;
    uint8_t input[16], ping[8] = {1,2,3,4,5,6,7,8};
    const uint8_t *out;
    size_t n, used, length;
    ready(&d);
    CHECK(tsc_derp_ping(&d, ping) == TSC_OK);
    n = frame(input, 0x12, ping, 8);
    event = feed_fragments(&d, input, n, 3);
    CHECK(event.type == TSC_DERP_EVENT_NONE);
    CHECK(tsc_derp_feed(&d, input, n, &used, &event) == TSC_AGAIN && used == n);
    CHECK(tsc_derp_feed(&d, NULL, 0, &used, &event) == TSC_AGAIN && used == 0);
    CHECK(tsc_derp_output(&d, &out, &length) == TSC_OK && out[0] == 0x12);
    CHECK(tsc_derp_output_consumed(&d, length) == TSC_OK);
    CHECK(tsc_derp_output(&d, &out, &length) == TSC_OK && out[0] == 0x13);
    CHECK(!memcmp(out+5, ping, 8));
    CHECK(tsc_derp_feed(&d, NULL, 0, &used, &event) == TSC_OK && used == 0);
    drain(&d); /* both automatic pong replies */
    n = frame(input, 0x13, ping, 8);
    event = feed_fragments(&d, input, n, 2);
    CHECK(event.type == TSC_DERP_EVENT_PONG && event.length == 8);
    CHECK(!memcmp(event.data, ping, 8));
    tsc_derp_clear(&d);
}

static void test_errors(void)
{
    static const char *bad_json[] = {
        "[]", "{}x", "{\"x\":01}", "{\"x\":1.}", "{\"x\":1e}",
        "{\"x\":true,}", "{\"x\":nul}", "{\"x\":\"\\q\"}", "{\"x\":}",
        "{\"x\":\"\\u000x\"}", "{\"x\":-}", "{\"x\":[1,]}"
    };
    tsc_derp d;
    tsc_derp_event event;
    uint8_t input[TSC_DERP_BUFFER_SIZE + 10];
    size_t n, used, i;
    const uint8_t *out;
    CHECK(tsc_derp_init(NULL, client_private) == TSC_ERR_ARGUMENT);
    CHECK(tsc_derp_init(&d, client_private) == TSC_OK);
    CHECK(tsc_derp_start(&d, "host\r\nInjected: yes") == TSC_ERR_ARGUMENT);
    CHECK(tsc_derp_start(&d, "") == TSC_ERR_ARGUMENT);
    CHECK(tsc_derp_start(&d, "localhost") == TSC_OK);
    drain(&d);
    {
        const char wrong[] = "HTTP/1.1 200 OK\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
        CHECK(tsc_derp_feed(&d, wrong, sizeof(wrong)-1, &used, &event) == TSC_ERR_PROTOCOL);
        CHECK(tsc_derp_feed(&d, wrong, sizeof(wrong)-1, &used, &event) == TSC_ERR_PROTOCOL);
        CHECK(used == 0);
    }
    CHECK(tsc_derp_init(&d, client_private) == TSC_OK);
    CHECK(tsc_derp_start(&d, NULL) == TSC_OK);
    n = greeting(input); input[5] = 'X';
    CHECK(tsc_derp_feed(&d, input, n, &used, &event) == TSC_ERR_PROTOCOL);
    CHECK(tsc_derp_output(&d, &out, &n) == TSC_ERR_PROTOCOL);
    CHECK(tsc_derp_init(&d, client_private) == TSC_OK);
    CHECK(tsc_derp_start(&d, NULL) == TSC_OK);
    n = greeting(input); memset(input+13, 0, 32);
    CHECK(tsc_derp_feed(&d, input, n, &used, &event) == TSC_ERR_PROTOCOL);
    begin(&d, 0);
    n = info_frame(&d, input, "{\"version\":2}"); input[n-1] ^= 1;
    CHECK(tsc_derp_feed(&d, input, n, &used, &event) == TSC_ERR_PROTOCOL);
    for (i = 0; i < sizeof(bad_json)/sizeof(bad_json[0]); ++i) {
        begin(&d, 0);
        n = info_frame(&d, input, bad_json[i]);
        CHECK(tsc_derp_feed(&d, input, n, &used, &event) == TSC_ERR_PROTOCOL);
    }
    ready(&d);
    input[0] = 5; memset(input+1, 0xff, 4);
    CHECK(tsc_derp_feed(&d, input, 5, &used, &event) == TSC_ERR_SPACE);
    CHECK(used == 5);
    CHECK(tsc_derp_send(&d, server_public, NULL, 0) == TSC_ERR_SPACE);
    ready(&d);
    n = frame(input, 5, "short", 5);
    CHECK(tsc_derp_feed(&d, input, n, &used, &event) == TSC_ERR_PROTOCOL);
    CHECK(tsc_derp_init(&d, client_private) == TSC_OK);
    CHECK(tsc_derp_start(&d, "host") == TSC_OK);
    drain(&d);
    memset(input, 'A', TSC_DERP_MAX_HTTP_HEADER+1);
    CHECK(tsc_derp_feed(&d, input, TSC_DERP_MAX_HTTP_HEADER+1, &used, &event) == TSC_ERR_SPACE);
    tsc_derp_clear(&d);
}

static uint32_t pseudo_random(uint32_t *state)
{
    *state = *state * 1664525u + 1013904223u;
    return *state;
}

static void test_fragment_fuzz(void)
{
    tsc_derp baseline, d;
    tsc_derp_event event;
    uint8_t input[133], body[128];
    uint32_t rng = 0x73ac9917;
    size_t run, i, n, used, offset, chunk;
    int status;
    ready(&baseline);
    for (run = 0; run < 20000; ++run) {
        d = baseline;
        n = pseudo_random(&rng) % sizeof(body);
        for (i = 0; i < n; ++i) body[i] = (uint8_t)(pseudo_random(&rng) >> 24);
        n = frame(input, (uint8_t)(pseudo_random(&rng) >> 24), body, n);
        if ((run % 7) == 0) input[1] = 0xff;
        offset = 0;
        while (offset < n) {
            chunk = (pseudo_random(&rng) % 23) + 1;
            if (chunk > n-offset) chunk = n-offset;
            status = tsc_derp_feed(&d, input+offset, chunk, &used, &event);
            CHECK(used <= chunk);
            offset += used;
            if (status < 0) {
                CHECK(tsc_derp_feed(&d, input, n, &used, &event) == status);
                CHECK(used == 0);
                break;
            }
            CHECK(used > 0);
            drain(&d);
        }
        tsc_derp_clear(&d);
    }
    tsc_derp_clear(&baseline);
}

int main(void)
{
    CHECK(tsc_crypto_x25519_public(server_public, server_private) == TSC_OK);
    test_frames();
    test_ping_backpressure();
    test_errors();
    test_fragment_fuzz();
    puts("DERP: login authentication, HTTP upgrade, fragmented frames, limits, backpressure, 20000 malformed frames passed");
    return 0;
}

#else
int main(void) { return 77; }
#endif
