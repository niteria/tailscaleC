#include "tailscalec/wireguard.h"
#include "check.h"
#include "../third_party/wireguard/crypto/refc/blake2s.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Deliberately deterministic test-only hooks. Never use this RNG in firmware. */
typedef struct {
    uint64_t random_state, now_ms, timestamp;
    int fail_random, fail_timestamp;
} test_clock;

typedef struct {
    tsc_wg a, b;
    tsc_wg_peer a_peers[3], b_peers[3];
    test_clock a_clock, b_clock;
} fixture;

enum { A_PEER = 1, B_PEER = 2, PACKET_CAPACITY = 2048 };

static int test_random(void *user, void *buffer, size_t length)
{
    test_clock *clock = user;
    uint8_t *bytes = buffer;
    size_t i;
    if (clock->fail_random) return TSC_ERR_IO;
    for (i = 0; i < length; ++i) {
        clock->random_state ^= clock->random_state << 13;
        clock->random_state ^= clock->random_state >> 7;
        clock->random_state ^= clock->random_state << 17;
        bytes[i] = (uint8_t)clock->random_state;
    }
    return TSC_OK;
}

static int test_stuck_random(void *user, void *buffer, size_t length)
{
    test_clock *clock = user;
    ++clock->random_state; /* Count calls to prove collision retries are bounded. */
    memset(buffer, clock->fail_random ? 0 : 0x55, length);
    return TSC_OK;
}

static uint64_t test_now(void *user)
{
    return ((test_clock *)user)->now_ms;
}

static int test_tai64n(void *user, uint8_t timestamp[12])
{
    test_clock *clock = user;
    uint64_t seconds = UINT64_C(0x400000006000000a);
    uint32_t nanoseconds = (uint32_t)++clock->timestamp;
    unsigned i;
    if (clock->fail_timestamp) return TSC_ERR_IO;
    for (i = 0; i < 8; ++i) timestamp[7 - i] = (uint8_t)(seconds >> (8 * i));
    for (i = 0; i < 4; ++i) timestamp[11 - i] = (uint8_t)(nanoseconds >> (8 * i));
    return TSC_OK;
}

static tsc_wg_hooks hooks_for(test_clock *clock)
{
    tsc_wg_hooks hooks = { clock, test_random, test_now, test_tai64n };
    return hooks;
}

static void fixture_init(fixture *f)
{
    uint8_t a_key[32], b_key[32];
    tsc_wg_hooks a_hooks, b_hooks;
    size_t i;
    memset(f, 0, sizeof(*f));
    f->a_clock.random_state = UINT64_C(0x123456789abcdef1);
    f->b_clock.random_state = UINT64_C(0x87654321fedcba19);
    f->a_clock.now_ms = f->b_clock.now_ms = 100000;
    a_hooks = hooks_for(&f->a_clock);
    b_hooks = hooks_for(&f->b_clock);
    for (i = 0; i < sizeof(a_key); ++i) {
        a_key[i] = (uint8_t)(i * 7 + 1);
        b_key[i] = (uint8_t)(i * 11 + 3);
    }
    CHECK(tsc_wg_init(&f->a, f->a_peers, 3, a_key, &a_hooks) == TSC_OK);
    CHECK(tsc_wg_init(&f->b, f->b_peers, 3, b_key, &b_hooks) == TSC_OK);
    CHECK(memcmp(f->a.public_key, f->b.public_key, 32) != 0);
    CHECK(tsc_wg_peer_set(&f->a, A_PEER, f->b.public_key, NULL) == TSC_OK);
    CHECK(tsc_wg_peer_set(&f->b, B_PEER, f->a.public_key, NULL) == TSC_OK);
}

static void fixture_destroy(fixture *f)
{
    uint8_t zero[32] = { 0 };
    tsc_wg_destroy(&f->a);
    tsc_wg_destroy(&f->b);
    CHECK(!f->a.valid && !f->b.valid);
    CHECK(memcmp(f->a.private_key, zero, sizeof(zero)) == 0);
    CHECK(memcmp(f->b.private_key, zero, sizeof(zero)) == 0);
    CHECK(!f->a_peers[A_PEER].valid && !f->b_peers[B_PEER].valid);
}

static void advance(fixture *f, uint64_t millis)
{
    f->a_clock.now_ms += millis;
    f->b_clock.now_ms += millis;
}

static void check_event(const tsc_wg_event *event, tsc_wg_event_kind kind,
                        size_t peer, size_t length, int established)
{
    CHECK(event->kind == kind);
    CHECK(event->authenticated);
    CHECK(event->peer_index == peer);
    CHECK(event->length == length);
    CHECK(event->established == (established != 0));
}

static int receive_rejected(tsc_wg *device, const uint8_t *packet, size_t length,
                            size_t capacity)
{
    uint8_t output[PACKET_CAPACITY];
    tsc_wg_event event;
    int rc;
    CHECK(capacity <= sizeof(output));
    memset(&event, 0xa5, sizeof(event));
    memset(output, 0xa5, sizeof(output));
    rc = tsc_wg_receive(device, packet, length, output, capacity, &event);
    CHECK(rc < 0);
    CHECK(event.kind == TSC_WG_EVENT_NONE);
    CHECK(!event.authenticated && !event.established && event.length == 0);
    return rc;
}

static void establish(fixture *f)
{
    uint8_t initiation[PACKET_CAPACITY], response[PACKET_CAPACITY];
    uint8_t confirmation[PACKET_CAPACITY], output[PACKET_CAPACITY];
    size_t length = 999;
    tsc_wg_event event;
    CHECK(tsc_wg_start(&f->a, A_PEER, initiation, sizeof(initiation), &length) == TSC_OK);
    CHECK(length == TSC_WG_INITIATION_SIZE && initiation[0] == 1);
    CHECK(tsc_wg_receive(&f->b, initiation, length, response, sizeof(response), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_TX, B_PEER, TSC_WG_RESPONSE_SIZE, 0);
    CHECK(response[0] == 2);
    CHECK(tsc_wg_peer_established(&f->b, B_PEER) == 0);
    CHECK(tsc_wg_receive(&f->a, response, event.length, confirmation,
                          sizeof(confirmation), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_TX, A_PEER, TSC_WG_OVERHEAD, 1);
    CHECK(confirmation[0] == 4);
    CHECK(tsc_wg_peer_established(&f->a, A_PEER) == 1);
    CHECK(tsc_wg_receive(&f->b, confirmation, event.length, output, sizeof(output), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_KEEPALIVE, B_PEER, 0, 1);
    CHECK(tsc_wg_peer_established(&f->b, B_PEER) == 1);
}

static void test_handshake_and_payloads(void)
{
    fixture f;
    uint8_t plaintext[1024], ciphertext[PACKET_CAPACITY], output[PACKET_CAPACITY];
    const size_t lengths[] = { 0, 1, 15, 16, 17, 20, 31, 32, 33, 255, 1024 };
    size_t i, j, written;
    tsc_wg_event event;
    fixture_init(&f);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 0);
    written = 999;
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "x", 1, ciphertext,
                          sizeof(ciphertext), &written) == TSC_AGAIN);
    CHECK(written == 0);
    establish(&f);
    for (i = 0; i < sizeof(plaintext); ++i) plaintext[i] = (uint8_t)(i ^ (i >> 5));
    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t length = lengths[i], padded = (length + 15) & ~(size_t)15;
        CHECK(tsc_wg_encrypt(&f.a, A_PEER, length ? plaintext : NULL, length,
                              ciphertext, sizeof(ciphertext), &written) == TSC_OK);
        CHECK(written == padded + TSC_WG_OVERHEAD);
        CHECK(tsc_wg_receive(&f.b, ciphertext, written, output, sizeof(output), &event) == TSC_OK);
        check_event(&event, length ? TSC_WG_EVENT_RX : TSC_WG_EVENT_KEEPALIVE,
                    B_PEER, padded, 1);
        CHECK(memcmp(output, plaintext, length) == 0);
        for (j = length; j < padded; ++j) CHECK(output[j] == 0);
        CHECK(receive_rejected(&f.b, ciphertext, written, sizeof(output)) == TSC_WG_ERR_REPLAY);

        /* The responder has an independent sending counter/key. */
        CHECK(tsc_wg_encrypt(&f.b, B_PEER, length ? plaintext : NULL, length,
                              ciphertext, sizeof(ciphertext), &written) == TSC_OK);
        CHECK(tsc_wg_receive(&f.a, ciphertext, written, output, sizeof(output), &event) == TSC_OK);
        check_event(&event, length ? TSC_WG_EVENT_RX : TSC_WG_EVENT_KEEPALIVE,
                    A_PEER, padded, 1);
        CHECK(memcmp(output, plaintext, length) == 0);
    }
    fixture_destroy(&f);
}

static void test_replay_window(void)
{
    fixture f;
    uint8_t packets[70][48], output[PACKET_CAPACITY];
    const unsigned accepted[] = { 0, 2, 1, 64, 3, 65, 69, 6 };
    size_t written, i;
    tsc_wg_event event;
    fixture_init(&f);
    establish(&f);
    for (i = 0; i < 70; ++i) {
        uint8_t payload = (uint8_t)i;
        CHECK(tsc_wg_encrypt(&f.a, A_PEER, &payload, 1, packets[i], sizeof(packets[i]), &written) == TSC_OK);
        CHECK(written == sizeof(packets[i]));
    }
    for (i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        unsigned index = accepted[i];
        CHECK(tsc_wg_receive(&f.b, packets[index], sizeof(packets[index]),
                              output, sizeof(output), &event) == TSC_OK);
        check_event(&event, TSC_WG_EVENT_RX, B_PEER, 16, 1);
        CHECK(output[0] == index);
    }
    /* 63 behind the latest counter is accepted; 64 behind is outside. */
    CHECK(receive_rejected(&f.b, packets[5], sizeof(packets[5]), sizeof(output)) == TSC_WG_ERR_REPLAY);
    CHECK(receive_rejected(&f.b, packets[6], sizeof(packets[6]), sizeof(output)) == TSC_WG_ERR_REPLAY);
    CHECK(receive_rejected(&f.b, packets[69], sizeof(packets[69]), sizeof(output)) == TSC_WG_ERR_REPLAY);
    fixture_destroy(&f);
}

static void test_large_counters(void)
{
    fixture f;
    uint8_t old[PACKET_CAPACITY], jump[PACKET_CAPACITY], packet[PACKET_CAPACITY];
    uint8_t output[PACKET_CAPACITY];
    size_t old_length, jump_length, written;
    tsc_wg_event event;
    const uint64_t high = (UINT64_C(1) << 32) + 7;
    fixture_init(&f);
    establish(&f);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "old", 3, old, sizeof(old), &old_length) == TSC_OK);
    f.a_peers[A_PEER].curr_keypair.sending_counter = high;
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "jump", 4, jump, sizeof(jump), &jump_length) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, jump, jump_length, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.authenticated && memcmp(output, "jump", 4) == 0);
    CHECK(f.b_peers[B_PEER].curr_keypair.replay_counter > UINT32_MAX);
    CHECK(receive_rejected(&f.b, old, old_length, sizeof(output)) == TSC_WG_ERR_REPLAY);
    CHECK(receive_rejected(&f.b, jump, jump_length, sizeof(output)) == TSC_WG_ERR_REPLAY);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "next", 4, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(memcmp(output, "next", 4) == 0);
    /* A nonce must never wrap, even if the caller has not ticked timers. */
    f.a_peers[A_PEER].curr_keypair.sending_counter = UINT64_MAX;
    written = 999;
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "x", 1, packet, sizeof(packet), &written) == TSC_WG_ERR_EXPIRED);
    CHECK(written == 0 && !f.a_peers[A_PEER].curr_keypair.valid);
    fixture_destroy(&f);
}

static void test_unaligned_buffers(void)
{
    fixture f;
    uint8_t packet[PACKET_CAPACITY + 1], plaintext[35], output[PACKET_CAPACITY + 1];
    size_t written;
    tsc_wg_event event;
    fixture_init(&f);
    CHECK(tsc_wg_start(&f.a, A_PEER, packet + 1, PACKET_CAPACITY, &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet + 1, written, output + 1, PACKET_CAPACITY, &event) == TSC_OK);
    CHECK(tsc_wg_receive(&f.a, output + 1, event.length, packet + 1, PACKET_CAPACITY, &event) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet + 1, event.length, output + 1, PACKET_CAPACITY, &event) == TSC_OK);
    memset(plaintext, 0x42, sizeof(plaintext));
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, plaintext + 1, 33, packet + 1, PACKET_CAPACITY, &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet + 1, written, output + 1, PACKET_CAPACITY, &event) == TSC_OK);
    CHECK(event.authenticated && event.length == 48 && memcmp(output + 1, plaintext + 1, 33) == 0);
    fixture_destroy(&f);
}

static void test_transport_tampering(void)
{
    fixture f;
    uint8_t packet[PACKET_CAPACITY], changed[PACKET_CAPACITY], output[PACKET_CAPACITY];
    uint8_t payload[33];
    size_t written, i;
    uint64_t replay_counter, replay_bitmap;
    tsc_wg_event event;
    fixture_init(&f);
    establish(&f);
    memset(payload, 0x5a, sizeof(payload));
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, payload, sizeof(payload), packet, sizeof(packet), &written) == TSC_OK);
    replay_counter = f.b_peers[B_PEER].curr_keypair.replay_counter;
    replay_bitmap = f.b_peers[B_PEER].curr_keypair.replay_bitmap;
    for (i = 0; i < written; ++i) {
        memcpy(changed, packet, written);
        changed[i] ^= 0x80;
        receive_rejected(&f.b, changed, written, sizeof(output));
        CHECK(f.b_peers[B_PEER].curr_keypair.replay_counter == replay_counter);
        CHECK(f.b_peers[B_PEER].curr_keypair.replay_bitmap == replay_bitmap);
    }
    /* An unauthenticated far-future counter must not evict real traffic. */
    memcpy(changed, packet, written);
    memset(changed + 8, 0xff, 8);
    receive_rejected(&f.b, changed, written, sizeof(output));
    CHECK(f.b_peers[B_PEER].curr_keypair.replay_counter == replay_counter);
    CHECK(f.b_peers[B_PEER].curr_keypair.replay_bitmap == replay_bitmap);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.authenticated && event.length == 48 && memcmp(output, payload, sizeof(payload)) == 0);
    fixture_destroy(&f);
}

static void test_malformed_packets(void)
{
    fixture f;
    uint8_t packet[PACKET_CAPACITY], output[PACKET_CAPACITY], changed[PACKET_CAPACITY];
    size_t written, i;
    tsc_wg_event event;
    fixture_init(&f);
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    for (i = 0; i < TSC_WG_INITIATION_SIZE; ++i)
        receive_rejected(&f.b, packet, i, sizeof(output));
    /* MAC1 binds every field before MAC2. Cookie MAC2 is optional unless the
     * responder is under load and cannot authenticate an initiation alone. */
    for (i = 0; i < TSC_WG_INITIATION_SIZE - 16; ++i) {
        memcpy(changed, packet, written);
        changed[i] ^= 0x01;
        receive_rejected(&f.b, changed, written, sizeof(output));
    }
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.kind == TSC_WG_EVENT_TX);
    receive_rejected(&f.b, packet, written, sizeof(output));
    /* Unknown sender: removing its configured key must deny a valid initiation. */
    CHECK(tsc_wg_peer_remove(&f.b, B_PEER) == TSC_OK);
    CHECK(receive_rejected(&f.b, packet, written, sizeof(output)) == TSC_WG_ERR_AUTH);
    fixture_destroy(&f);

    fixture_init(&f);
    establish(&f);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "packet", 6, packet, sizeof(packet), &written) == TSC_OK);
    for (i = 0; i < written; ++i) receive_rejected(&f.b, packet, i, sizeof(output));
    memcpy(changed, packet, written);
    memset(changed + 4, 0, 4);
    CHECK(receive_rejected(&f.b, changed, written, sizeof(output)) == TSC_WG_ERR_AUTH);
    memcpy(changed, packet, written);
    changed[written] = 0;
    receive_rejected(&f.b, changed, written + 1, sizeof(output));
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    fixture_destroy(&f);
}

static void test_response_authentication(void)
{
    fixture f;
    uint8_t initiation[PACKET_CAPACITY], response[PACKET_CAPACITY];
    uint8_t changed[PACKET_CAPACITY], output[PACKET_CAPACITY];
    size_t written, response_length, i;
    tsc_wg_event event;
    fixture_init(&f);
    CHECK(tsc_wg_start(&f.a, A_PEER, initiation, sizeof(initiation), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, initiation, written, response, sizeof(response), &event) == TSC_OK);
    response_length = event.length;
    CHECK(response_length == TSC_WG_RESPONSE_SIZE);
    CHECK(tsc_wg_tick(&f.b, B_PEER, initiation, sizeof(initiation), &written) == TSC_AGAIN);
    CHECK(written == 0); /* Pending responder waits for key confirmation. */
    for (i = 0; i < response_length; ++i)
        receive_rejected(&f.a, response, i, sizeof(output));
    for (i = 0; i < response_length - 16; ++i) {
        memcpy(changed, response, response_length);
        changed[i] ^= 0x01;
        receive_rejected(&f.a, changed, response_length, sizeof(output));
        CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 0);
    }
    /* Failed responses must preserve the pending handshake so the real one
     * can still establish the session. */
    CHECK(tsc_wg_receive(&f.a, response, response_length, output, sizeof(output), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_TX, A_PEER, TSC_WG_OVERHEAD, 1);
    CHECK(tsc_wg_receive(&f.b, output, event.length, changed, sizeof(changed), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_KEEPALIVE, B_PEER, 0, 1);
    receive_rejected(&f.a, response, response_length, sizeof(output));
    fixture_destroy(&f);
}

static void replace_mac1(tsc_wg *receiver, uint8_t *packet, size_t length)
{
    /* MAC1 uses only the receiver's public key. An active attacker can forge
     * it, so malformed Noise fields must also fail after a correct MAC1. */
    CHECK(length == TSC_WG_INITIATION_SIZE || length == TSC_WG_RESPONSE_SIZE);
    CHECK(blake2s(packet + length - 32, 16, receiver->label_mac1_key, 32,
                   packet, length - 32) == 0);
}

static void test_noise_authentication(void)
{
    fixture f;
    uint8_t initiation[PACKET_CAPACITY], response[PACKET_CAPACITY];
    uint8_t changed[PACKET_CAPACITY], output[PACKET_CAPACITY];
    size_t written, response_length, i;
    tsc_wg_event event;
    fixture_init(&f);
    CHECK(tsc_wg_start(&f.a, A_PEER, initiation, sizeof(initiation), &written) == TSC_OK);
    /* Cover every byte of ephemeral key, encrypted static and timestamp. */
    for (i = 8; i < TSC_WG_INITIATION_SIZE - 32; ++i) {
        memcpy(changed, initiation, written);
        changed[i] ^= 0x01;
        replace_mac1(&f.b, changed, written);
        CHECK(receive_rejected(&f.b, changed, written, sizeof(output)) == TSC_WG_ERR_AUTH);
        CHECK(tsc_wg_peer_established(&f.b, B_PEER) == 0);
    }
    memcpy(changed, initiation, written);
    memset(changed + 8, 0, 32); /* Low-order X25519 public point. */
    replace_mac1(&f.b, changed, written);
    CHECK(receive_rejected(&f.b, changed, written, sizeof(output)) == TSC_WG_ERR_AUTH);
    CHECK(tsc_wg_receive(&f.b, initiation, written, response, sizeof(response), &event) == TSC_OK);
    response_length = event.length;
    /* A valid MAC1 cannot make an attacker-controlled response authenticate. */
    for (i = 12; i < response_length - 32; ++i) {
        memcpy(changed, response, response_length);
        changed[i] ^= 0x01;
        replace_mac1(&f.a, changed, response_length);
        CHECK(receive_rejected(&f.a, changed, response_length, sizeof(output)) == TSC_WG_ERR_AUTH);
        CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 0);
    }
    memcpy(changed, response, response_length);
    memset(changed + 12, 0, 32);
    replace_mac1(&f.a, changed, response_length);
    CHECK(receive_rejected(&f.a, changed, response_length, sizeof(output)) == TSC_WG_ERR_AUTH);
    CHECK(tsc_wg_receive(&f.a, response, response_length, output, sizeof(output), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_TX, A_PEER, TSC_WG_OVERHEAD, 1);
    CHECK(tsc_wg_receive(&f.b, output, event.length, changed, sizeof(changed), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_KEEPALIVE, B_PEER, 0, 1);
    fixture_destroy(&f);
}

static void test_crossed_initiations(void)
{
    fixture f;
    uint8_t a_initiation[PACKET_CAPACITY], b_initiation[PACKET_CAPACITY];
    uint8_t a_response[PACKET_CAPACITY], b_response[PACKET_CAPACITY];
    uint8_t output[PACKET_CAPACITY];
    size_t a_length, b_length, a_response_length, b_response_length, written;
    tsc_wg_event event;
    fixture_init(&f);
    CHECK(tsc_wg_start(&f.a, A_PEER, a_initiation, sizeof(a_initiation), &a_length) == TSC_OK);
    CHECK(tsc_wg_start(&f.b, B_PEER, b_initiation, sizeof(b_initiation), &b_length) == TSC_OK);
    CHECK(tsc_wg_receive(&f.a, b_initiation, b_length, a_response, sizeof(a_response), &event) == TSC_OK);
    a_response_length = event.length;
    CHECK(tsc_wg_receive(&f.b, a_initiation, a_length, b_response, sizeof(b_response), &event) == TSC_OK);
    b_response_length = event.length;
    /* Each inbound initiation replaced its own pending initiator state. The
     * crossed responses cannot match, but retries must remain enabled. */
    CHECK(receive_rejected(&f.a, b_response, b_response_length, sizeof(output)) == TSC_WG_ERR_AUTH);
    CHECK(receive_rejected(&f.b, a_response, a_response_length, sizeof(output)) == TSC_WG_ERR_AUTH);
    advance(&f, f.a_peers[A_PEER].retry_interval_ms);
    CHECK(tsc_wg_tick(&f.a, A_PEER, a_initiation, sizeof(a_initiation), &written) == TSC_OK);
    CHECK(written == TSC_WG_INITIATION_SIZE);
    CHECK(tsc_wg_receive(&f.b, a_initiation, written, b_response, sizeof(b_response), &event) == TSC_OK);
    CHECK(tsc_wg_receive(&f.a, b_response, event.length, a_response, sizeof(a_response), &event) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, a_response, event.length, output, sizeof(output), &event) == TSC_OK);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 1);
    CHECK(tsc_wg_peer_established(&f.b, B_PEER) == 1);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "A", 1, a_initiation, sizeof(a_initiation), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, a_initiation, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.authenticated && output[0] == 'A');
    CHECK(tsc_wg_encrypt(&f.b, B_PEER, "B", 1, b_initiation, sizeof(b_initiation), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.a, b_initiation, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.authenticated && output[0] == 'B');
    fixture_destroy(&f);
}

static void test_buffer_bounds(void)
{
    fixture f;
    uint8_t packet[PACKET_CAPACITY], output[PACKET_CAPACITY];
    uint8_t plaintext[17] = { 0x45, 0, 0, 17 };
    size_t written, i;
    uint64_t counter;
    tsc_wg_event event;
    fixture_init(&f);
    for (i = 0; i < TSC_WG_INITIATION_SIZE; ++i) {
        written = 999;
        CHECK(tsc_wg_start(&f.a, A_PEER, output, i, &written) == TSC_ERR_SPACE);
        CHECK(written == 0);
    }
    establish(&f);
    counter = f.a_peers[A_PEER].curr_keypair.sending_counter;
    for (i = 0; i < 64; ++i) {
        written = 999;
        CHECK(tsc_wg_encrypt(&f.a, A_PEER, plaintext, sizeof(plaintext),
                              packet, i, &written) == TSC_ERR_SPACE);
        CHECK(written == 0);
        CHECK(f.a_peers[A_PEER].curr_keypair.sending_counter == counter);
    }
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, plaintext, sizeof(plaintext), packet, sizeof(packet), &written) == TSC_OK);
    for (i = 0; i < 32; ++i)
        CHECK(receive_rejected(&f.b, packet, written, i) == TSC_ERR_SPACE);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.length == 32 && memcmp(output, plaintext, sizeof(plaintext)) == 0);
    fixture_destroy(&f);
}

static void test_peer_lifecycle_and_psk(void)
{
    fixture f;
    uint8_t psk[32], packet[PACKET_CAPACITY], output[PACKET_CAPACITY];
    tsc_wg_peer before;
    tsc_wg_event event;
    size_t written;
    fixture_init(&f);
    establish(&f);
    before = f.a_peers[A_PEER];
    CHECK(tsc_wg_peer_set(&f.a, A_PEER, f.b.public_key, NULL) == TSC_OK);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 1);
    CHECK(memcmp(&before, &f.a_peers[A_PEER], sizeof(before)) == 0);
    CHECK(tsc_wg_peer_remove(&f.a, A_PEER) == TSC_OK);
    CHECK(!f.a_peers[A_PEER].valid);
    CHECK(!f.a_peers[A_PEER].curr_keypair.valid);
    CHECK(!f.a_peers[A_PEER].handshake.valid);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 0);
    CHECK(tsc_wg_peer_set(&f.a, A_PEER, f.b.public_key, NULL) == TSC_OK);
    memset(psk, 0x6b, sizeof(psk));
    CHECK(tsc_wg_peer_set(&f.a, A_PEER, f.b.public_key, psk) == TSC_OK);
    CHECK(tsc_wg_peer_set(&f.b, B_PEER, f.a.public_key, psk) == TSC_OK);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 0);
    advance(&f, 6000);
    establish(&f);
    CHECK(tsc_wg_encrypt(&f.b, B_PEER, "psk", 3, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.a, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.authenticated && memcmp(output, "psk", 3) == 0);
    fixture_destroy(&f);

    fixture_init(&f);
    CHECK(tsc_wg_peer_set(&f.a, A_PEER, f.b.public_key, psk) == TSC_OK);
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(receive_rejected(&f.a, output, event.length, sizeof(packet)) == TSC_WG_ERR_AUTH);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 0);
    CHECK(tsc_wg_peer_established(&f.b, B_PEER) == 0);
    fixture_destroy(&f);
}

static void test_rekey_and_expiry(void)
{
    fixture f;
    uint8_t old_packet[PACKET_CAPACITY], stale_packet[PACKET_CAPACITY];
    uint8_t packet[PACKET_CAPACITY], output[PACKET_CAPACITY];
    size_t old_length, stale_length, written;
    tsc_wg_event event;
    fixture_init(&f);
    establish(&f);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "old", 3, old_packet, sizeof(old_packet), &old_length) == TSC_OK);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "stale", 5, stale_packet, sizeof(stale_packet), &stale_length) == TSC_OK);
    advance(&f, 120000);
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(written == TSC_WG_INITIATION_SIZE && packet[0] == 1);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.kind == TSC_WG_EVENT_TX && event.length == TSC_WG_RESPONSE_SIZE);
    CHECK(tsc_wg_receive(&f.a, output, event.length, packet, sizeof(packet), &event) == TSC_OK);
    CHECK(event.kind == TSC_WG_EVENT_TX && event.length == TSC_WG_OVERHEAD);
    CHECK(tsc_wg_receive(&f.b, packet, event.length, output, sizeof(output), &event) == TSC_OK);
    /* A packet already in flight remains valid under the previous keypair. */
    CHECK(tsc_wg_receive(&f.b, old_packet, old_length, output, sizeof(output), &event) == TSC_OK);
    CHECK(event.authenticated && event.length == 16 && memcmp(output, "old", 3) == 0);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "new", 3, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    CHECK(memcmp(output, "new", 3) == 0);
    advance(&f, 60001);
    CHECK(receive_rejected(&f.b, stale_packet, stale_length, sizeof(output)) == TSC_WG_ERR_EXPIRED);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 1);
    advance(&f, 120000);
    CHECK(tsc_wg_peer_established(&f.a, A_PEER) == 0);
    written = 999;
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "x", 1, packet, sizeof(packet), &written) == TSC_WG_ERR_EXPIRED);
    CHECK(written == 0);
    fixture_destroy(&f);
}

static void test_timers(void)
{
    fixture f;
    uint8_t packet[PACKET_CAPACITY], output[PACKET_CAPACITY];
    size_t written;
    tsc_wg_event event;
    fixture_init(&f);
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(f.a_peers[A_PEER].retry_interval_ms >= 5000);
    CHECK(f.a_peers[A_PEER].retry_interval_ms <= 5333);
    advance(&f, f.a_peers[A_PEER].retry_interval_ms - 1u);
    written = 999;
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_AGAIN);
    CHECK(written == 0);
    advance(&f, 1);
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(written == TSC_WG_INITIATION_SIZE);
    advance(&f, 85001);
    written = 999;
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_AGAIN);
    CHECK(written == 0);
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(written == TSC_WG_INITIATION_SIZE);
    fixture_destroy(&f);

    fixture_init(&f);
    establish(&f);
    f.a_peers[A_PEER].keepalive_interval = 25;
    advance(&f, 24999);
    written = 999;
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_AGAIN);
    CHECK(written == 0);
    advance(&f, 1);
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(written == TSC_WG_OVERHEAD);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_KEEPALIVE, B_PEER, 0, 1);
    fixture_destroy(&f);
}

static void test_data_liveness_timers(void)
{
    fixture f;
    uint8_t packet[PACKET_CAPACITY], output[PACKET_CAPACITY];
    size_t written;
    tsc_wg_event event;
    fixture_init(&f);
    establish(&f);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "data", 4, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    advance(&f, 9999);
    written = 999;
    CHECK(tsc_wg_tick(&f.b, B_PEER, packet, sizeof(packet), &written) == TSC_AGAIN);
    CHECK(written == 0);
    advance(&f, 1);
    CHECK(tsc_wg_tick(&f.b, B_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(written == TSC_WG_OVERHEAD);
    CHECK(tsc_wg_receive(&f.a, packet, written, output, sizeof(output), &event) == TSC_OK);
    check_event(&event, TSC_WG_EVENT_KEEPALIVE, A_PEER, 0, 1);
    advance(&f, 5000);
    /* The reply confirms liveness, cancelling the sender's 15-second retry. */
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_AGAIN);
    CHECK(written == 0);
    fixture_destroy(&f);

    fixture_init(&f);
    establish(&f);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "dropped", 7, packet, sizeof(packet), &written) == TSC_OK);
    advance(&f, 10000);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "also dropped", 12, packet, sizeof(packet), &written) == TSC_OK);
    advance(&f, 4999);
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_AGAIN);
    CHECK(written == 0);
    advance(&f, 1);
    /* More outgoing data cannot indefinitely defer detecting a dead peer. */
    CHECK(tsc_wg_tick(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(written == TSC_WG_INITIATION_SIZE && packet[0] == 1);
    fixture_destroy(&f);

    fixture_init(&f);
    establish(&f);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, "request", 7, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.b, packet, written, output, sizeof(output), &event) == TSC_OK);
    advance(&f, 1000);
    CHECK(tsc_wg_encrypt(&f.b, B_PEER, "response", 8, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(tsc_wg_receive(&f.a, packet, written, output, sizeof(output), &event) == TSC_OK);
    advance(&f, 9000);
    /* A normal response supplies the same liveness signal as a keepalive. */
    CHECK(tsc_wg_tick(&f.b, B_PEER, packet, sizeof(packet), &written) == TSC_AGAIN);
    CHECK(written == 0);
    fixture_destroy(&f);
}

static void test_hook_failures(void)
{
    fixture f;
    tsc_wg device;
    tsc_wg_peer peers[1];
    test_clock clock = { UINT64_C(0x1122334455667788), 100000, 0, 1, 0 };
    tsc_wg_hooks hooks = hooks_for(&clock);
    uint8_t key[32] = { 1 }, packet[PACKET_CAPACITY];
    size_t written;
    memset(&device, 0, sizeof(device));
    CHECK(tsc_wg_init(&device, peers, 1, key, &hooks) == TSC_WG_ERR_RANDOM);
    CHECK(!device.valid);
    fixture_init(&f);
    f.a_clock.fail_random = 1;
    written = 999;
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_WG_ERR_RANDOM);
    CHECK(written == 0);
    CHECK(!f.a_peers[A_PEER].curr_keypair.valid);
    fixture_destroy(&f);
    fixture_init(&f);
    f.a_clock.fail_timestamp = 1;
    written = 999;
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) < 0);
    CHECK(written == 0);
    CHECK(!f.a_peers[A_PEER].curr_keypair.valid);
    fixture_destroy(&f);
}

static void test_stuck_rng_is_bounded(void)
{
    fixture f;
    uint8_t packet[PACKET_CAPACITY];
    size_t written;
    uint64_t calls;
    fixture_init(&f);
    f.a.hooks.random_bytes = test_stuck_random;
    f.a_clock.random_state = 0;
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_OK);
    CHECK(written == TSC_WG_INITIATION_SIZE);
    calls = f.a_clock.random_state;
    advance(&f, f.a_peers[A_PEER].retry_interval_ms);
    written = 999;
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_WG_ERR_RANDOM);
    CHECK(written == 0);
    CHECK(f.a_clock.random_state - calls <= 130);
    fixture_destroy(&f);
    fixture_init(&f);
    f.a.hooks.random_bytes = test_stuck_random;
    f.a_clock.fail_random = 1; /* An all-zero RNG must also fail promptly. */
    f.a_clock.random_state = 0;
    written = 999;
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), &written) == TSC_WG_ERR_RANDOM);
    CHECK(written == 0 && f.a_clock.random_state <= 130);
    fixture_destroy(&f);
}

static void test_argument_bounds(void)
{
    fixture f;
    tsc_wg device;
    tsc_wg_peer peers[1];
    test_clock clock = { UINT64_C(0x1122334455667788), 100000, 0, 0, 0 };
    tsc_wg_hooks hooks = hooks_for(&clock), invalid;
    uint8_t key[32] = { 1 }, packet[PACKET_CAPACITY], zero[32] = { 0 };
    size_t written;
    tsc_wg_event event;
    memset(&device, 0, sizeof(device));
    CHECK(tsc_wg_init(NULL, peers, 1, key, &hooks) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_init(&device, NULL, 1, key, &hooks) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_init(&device, peers, 1, NULL, &hooks) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_init(&device, peers, 1, key, NULL) == TSC_ERR_ARGUMENT);
    invalid = hooks; invalid.random_bytes = NULL;
    CHECK(tsc_wg_init(&device, peers, 1, key, &invalid) == TSC_ERR_ARGUMENT);
    invalid = hooks; invalid.monotonic_ms = NULL;
    CHECK(tsc_wg_init(&device, peers, 1, key, &invalid) == TSC_ERR_ARGUMENT);
    invalid = hooks; invalid.tai64n_now = NULL;
    CHECK(tsc_wg_init(&device, peers, 1, key, &invalid) == TSC_ERR_ARGUMENT);
    fixture_init(&f);
    CHECK(tsc_wg_peer_set(&f.a, 3, f.b.public_key, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_peer_set(&f.a, SIZE_MAX, f.b.public_key, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_peer_set(&f.a, 0, NULL, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_peer_set(&f.a, 0, zero, NULL) < 0);
    CHECK(tsc_wg_peer_remove(&f.a, 3) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_start(&f.a, 3, packet, sizeof(packet), &written) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_start(&f.a, A_PEER, NULL, sizeof(packet), &written) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_start(&f.a, A_PEER, packet, sizeof(packet), NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_encrypt(&f.a, 3, key, sizeof(key), packet, sizeof(packet), &written) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_encrypt(&f.a, A_PEER, NULL, 1, packet, sizeof(packet), &written) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_receive(&f.a, NULL, 1, packet, sizeof(packet), &event) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_receive(&f.a, packet, 1, NULL, sizeof(packet), &event) == TSC_ERR_ARGUMENT);
    CHECK(tsc_wg_receive(&f.a, packet, 1, packet, sizeof(packet), NULL) == TSC_ERR_ARGUMENT);
    fixture_destroy(&f);
    tsc_wg_destroy(NULL);
}

int main(void)
{
    test_argument_bounds();
    test_hook_failures();
    test_stuck_rng_is_bounded();
    test_handshake_and_payloads();
    test_replay_window();
    test_large_counters();
    test_unaligned_buffers();
    test_transport_tampering();
    test_malformed_packets();
    test_response_authentication();
    test_noise_authentication();
    test_crossed_initiations();
    test_buffer_bounds();
    test_peer_lifecycle_and_psk();
    test_rekey_and_expiry();
    test_timers();
    test_data_liveness_timers();
    printf("WireGuard tests passed; device = %zu bytes, peer = %zu bytes\n",
            sizeof(tsc_wg), sizeof(tsc_wg_peer));
    return 0;
}
