#define _POSIX_C_SOURCE 200809L
#include "tailscalec/socket.h"
#include "tailscalec/wireguard.h"
#include "check.h"
#include <poll.h>
#include <stdio.h>
#include <string.h>

/* Localhost-only helper for wireguard_interop/main.go. The fixed private key
 * is a public test fixture and must never be used outside these tests. */
enum { MESSAGE_COUNT = 32 };

static void from_hex(const char *hex, uint8_t key[32])
{
    size_t i;
    CHECK(strlen(hex) == 64);
    for (i = 0; i < 32; ++i) {
        unsigned byte;
        CHECK(sscanf(hex + i * 2, "%2x", &byte) == 1);
        key[i] = (uint8_t)byte;
    }
}

static uint16_t checksum(const uint8_t *packet, size_t length)
{
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < length; i += 2)
        sum += ((uint16_t)packet[i] << 8) | packet[i + 1];
    if (i < length) sum += (uint16_t)packet[i] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void store16(uint8_t *output, unsigned value)
{
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static size_t make_packet(uint8_t *output, unsigned sequence, int from_c)
{
    size_t payload_length = 29 + (sequence % 5) * 127, i;
    size_t length = 28 + payload_length;
    uint16_t sum;
    memset(output, 0, length);
    output[0] = 0x45;
    store16(output + 2, (unsigned)length);
    output[8] = 64;
    output[9] = 17;
    output[12] = output[16] = 100;
    output[13] = output[17] = 64;
    output[15] = from_c ? 1 : 2;
    output[19] = from_c ? 2 : 1;
    sum = checksum(output, 20);
    store16(output + 10, sum);
    store16(output + 20, from_c ? 10001 : 10002);
    store16(output + 22, from_c ? 10002 : 10001);
    store16(output + 24, (unsigned)(8 + payload_length));
    /* UDP checksum zero is valid for IPv4. Binary content includes NULs. */
    output[28] = from_c ? 'C' : 'G';
    output[29] = (uint8_t)sequence;
    for (i = 2; i < payload_length; ++i)
        output[28 + i] = (uint8_t)(sequence * 17 + i * 31);
    return length;
}

int main(void)
{
    tsc_socket socket = TSC_SOCKET_INITIALIZER;
    tsc_endpoint loopback, local, remote, from;
    tsc_platform platform;
    tsc_wg device;
    tsc_wg_peer peers[1];
    tsc_wg_hooks hooks;
    uint8_t private_key[32], public_key[32], psk[32];
    uint8_t packet[TSC_MAX_DATAGRAM_SIZE], output[TSC_MAX_DATAGRAM_SIZE];
    uint8_t plaintext[TSC_MAX_DATAGRAM_SIZE], expected[TSC_MAX_DATAGRAM_SIZE];
    char public_hex[65], psk_hex[65];
    unsigned port, initiate, tx_count = 0, rx_count = 0;
    unsigned char received[MESSAGE_COUNT] = { 0 };
    uint64_t deadline;
    size_t written, length, i;
    tsc_wg_event event;
    CHECK(TSC_MAX_DATAGRAM_SIZE >= 608); /* Largest test packet plus padding/tag. */
    CHECK(tsc_socket_resolve("127.0.0.1", 0, TSC_AF_IPV4, &loopback) == TSC_OK);
    CHECK(tsc_socket_open(&socket, &loopback) == TSC_OK);
    CHECK(tsc_socket_local(&socket, &local) == TSC_OK);
    platform = tsc_socket_platform(&socket);
    hooks.user = &socket;
    hooks.random_bytes = platform.random_bytes;
    hooks.monotonic_ms = platform.monotonic_ms;
    hooks.tai64n_now = tsc_socket_tai64n_now;
    for (i = 0; i < sizeof(private_key); ++i) private_key[i] = (uint8_t)(i * 7 + 41);
    CHECK(tsc_wg_init(&device, peers, 1, private_key, &hooks) == TSC_OK);
    printf("READY %u ", local.port);
    for (i = 0; i < 32; ++i) printf("%02x", device.public_key[i]);
    putchar('\n');
    fflush(stdout);
    CHECK(scanf("%u %64s %64s %u", &port, public_hex, psk_hex, &initiate) == 4);
    CHECK(port > 0 && port <= 65535 && initiate <= 1);
    from_hex(public_hex, public_key);
    from_hex(psk_hex, psk);
    CHECK(tsc_socket_resolve("127.0.0.1", (uint16_t)port, TSC_AF_IPV4, &remote) == TSC_OK);
    CHECK(tsc_wg_peer_set(&device, 0, public_key, psk) == TSC_OK);
    if (initiate) {
        CHECK(tsc_wg_start(&device, 0, packet, sizeof(packet), &written) == TSC_OK);
        CHECK(tsc_socket_send(&socket, &remote, packet, written) == TSC_OK);
    }
    deadline = platform.monotonic_ms(platform.user) + 10000;
    while (rx_count < MESSAGE_COUNT || tx_count < MESSAGE_COUNT) {
        struct pollfd descriptor = { socket.fd, POLLIN, 0 };
        int rc;
        CHECK(platform.monotonic_ms(platform.user) < deadline);
        rc = tsc_socket_receive(&socket, &from, packet, sizeof(packet), &length);
        CHECK(rc == TSC_AGAIN || rc == TSC_OK);
        if (rc == TSC_OK) {
            CHECK(tsc_endpoint_equal(&from, &remote));
            CHECK(tsc_wg_receive(&device, packet, length, output, sizeof(output), &event) == TSC_OK);
            if (event.kind == TSC_WG_EVENT_TX)
                CHECK(tsc_socket_send(&socket, &remote, output, event.length) == TSC_OK);
            if (event.kind == TSC_WG_EVENT_RX) {
                unsigned sequence;
                size_t expected_length;
                CHECK(event.authenticated && event.peer_index == 0 && event.length >= 30);
                /* The embedding application checks allowed IPs after auth. */
                CHECK(output[12] == 100 && output[13] == 64 && output[14] == 0 && output[15] == 2);
                sequence = output[29];
                CHECK(sequence < MESSAGE_COUNT && !received[sequence]);
                expected_length = make_packet(expected, sequence, 0);
                CHECK(event.length >= expected_length && event.length < expected_length + 16);
                CHECK(memcmp(output, expected, expected_length) == 0);
                received[sequence] = 1;
                ++rx_count;
            }
        }
        if (tsc_wg_peer_established(&device, 0) && tx_count < MESSAGE_COUNT) {
            length = make_packet(plaintext, tx_count, 1);
            CHECK(tsc_wg_encrypt(&device, 0, plaintext, length, output, sizeof(output), &written) == TSC_OK);
            CHECK(tsc_socket_send(&socket, &remote, output, written) == TSC_OK);
            ++tx_count;
        }
        if (rc == TSC_AGAIN) {
            rc = tsc_wg_tick(&device, 0, output, sizeof(output), &written);
            CHECK(rc == TSC_OK || rc == TSC_AGAIN);
            if (rc == TSC_OK) CHECK(tsc_socket_send(&socket, &remote, output, written) == TSC_OK);
            CHECK(poll(&descriptor, 1, 5) >= 0);
        }
    }
    tsc_wg_destroy(&device);
    tsc_socket_close(&socket);
    printf("PASS tx=%u rx=%u\n", tx_count, rx_count);
    return 0;
}
