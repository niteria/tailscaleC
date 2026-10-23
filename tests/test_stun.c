#include "tailscalec/stun.h"
#include "check.h"

#if TSC_ENABLE_STUN
#include "tailscalec/socket.h"
#include <poll.h>
#include <string.h>

/* Binding success: 203.0.113.9:3478, XOR-encoded with the STUN cookie. */
static const uint8_t response[] = {
    0x01,0x01,0x00,0x0c,0x21,0x12,0xa4,0x42,
    0,1,2,3,4,5,6,7,8,9,10,11,
    0x00,0x20,0x00,0x08,0x00,0x01,0x2c,0x84,0xea,0x12,0xd5,0x4b
};
static const uint8_t transaction[] = { 0,1,2,3,4,5,6,7,8,9,10,11 };

static void parser(void)
{
    uint8_t packet[64];
    size_t length = 123;
    tsc_endpoint mapped, sentinel;
    memset(&sentinel, 0x5a, sizeof(sentinel));
    mapped = sentinel;
    CHECK(tsc_stun_request(transaction, packet, TSC_STUN_REQUEST_SIZE - 1,
                            &length) == TSC_ERR_SPACE);
    CHECK(length == 0);
    CHECK(tsc_stun_request(transaction, packet, sizeof(packet), &length) == TSC_OK);
    CHECK(length == TSC_STUN_REQUEST_SIZE && packet[0] == 0 && packet[1] == 1);
    CHECK(memcmp(packet + 8, transaction, 12) == 0);
    CHECK(memcmp(packet + 24, "tailnode", 8) == 0);
    /* Golden IEEE CRC32 fingerprint, independently computed with Python zlib. */
    const uint8_t expected_fingerprint[] = { 0x8a,0xab,0xad,0x90 };
    CHECK(memcmp(packet + 36, expected_fingerprint, 4) == 0);
    for (size_t n = 0; n < sizeof(response); ++n) {
        CHECK(tsc_stun_response(response, n, transaction, &mapped) == TSC_ERR_PROTOCOL);
        CHECK(memcmp(&mapped, &sentinel, sizeof(mapped)) == 0);
    }
    CHECK(tsc_stun_response(response, sizeof(response), transaction, &mapped) == TSC_OK);
    CHECK(mapped.family == TSC_AF_IPV4 && mapped.port == 3478);
    CHECK(mapped.address[0] == 203 && mapped.address[1] == 0 &&
          mapped.address[2] == 113 && mapped.address[3] == 9);

    const size_t corrupt[] = { 0, 2, 4, 8, 22, 25 };
    for (size_t n = 0; n < sizeof(corrupt) / sizeof(corrupt[0]); ++n) {
        memcpy(packet, response, sizeof(response));
        packet[corrupt[n]] ^= 0xff;
        mapped = sentinel;
        CHECK(tsc_stun_response(packet, sizeof(response), transaction, &mapped) != TSC_OK);
        CHECK(memcmp(&mapped, &sentinel, sizeof(mapped)) == 0);
    }
    /* An unknown optional attribute with 3 bytes of padding precedes mapping. */
    memcpy(packet, response, 20);
    packet[3] = 20;
    const uint8_t attribute[] = { 0x80,0x22,0x00,0x01,0x78,0,0,0 };
    memcpy(packet + 20, attribute, 8);
    memcpy(packet + 28, response + 20, 12);
    CHECK(tsc_stun_response(packet, 40, transaction, &mapped) == TSC_OK);
    packet[23] = 255;
    CHECK(tsc_stun_response(packet, 40, transaction, &mapped) == TSC_ERR_PROTOCOL);

    /* IPv6 XOR key is cookie || transaction, not just the cookie repeated. */
    const uint8_t ipv6[] = { 0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0xab,0xcd };
    memcpy(packet, response, 24);
    packet[3] = 24;
    packet[23] = 20;
    packet[24] = 0;
    packet[25] = 2;
    packet[26] = 0x2c;
    packet[27] = 0x84;
    for (size_t i = 0; i < 16; ++i)
        packet[28 + i] = ipv6[i] ^ (i < 4 ? response[4 + i] : transaction[i - 4]);
#if TSC_ENABLE_IPV6
    CHECK(tsc_stun_response(packet, 44, transaction, &mapped) == TSC_OK);
    CHECK(mapped.family == TSC_AF_IPV6 && mapped.port == 3478);
    CHECK(memcmp(mapped.address, ipv6, 16) == 0);
#else
    CHECK(tsc_stun_response(packet, 44, transaction, &mapped) == TSC_ERR_UNSUPPORTED);
#endif
    const uint8_t ipv4_mapped[] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,203,0,113,9 };
    for (size_t i = 0; i < 16; ++i)
        packet[28 + i] = ipv4_mapped[i] ^ (i < 4 ? response[4 + i] : transaction[i - 4]);
    CHECK(tsc_stun_response(packet, 44, transaction, &mapped) == TSC_OK);
    CHECK(mapped.family == TSC_AF_IPV4 && mapped.port == 3478);
    CHECK(mapped.address[0] == 203 && mapped.address[2] == 113 && mapped.address[3] == 9);
}

typedef struct {
    uint64_t now;
    unsigned sends;
    int receive_status;
    int send_status;
    int random_status;
    uint8_t incoming[sizeof(response)];
    uint8_t outgoing[TSC_STUN_REQUEST_SIZE];
    tsc_endpoint from;
} fake_io;

static int fake_send(void *user, const tsc_endpoint *to, const void *data, size_t size)
{
    fake_io *io = user;
    CHECK(to->port == 3478);
    CHECK(size == sizeof(io->outgoing));
    if (io->send_status != TSC_OK)
        return io->send_status;
    ++io->sends;
    memcpy(io->outgoing, data, size);
    return TSC_OK;
}

static int fake_receive(void *user, tsc_endpoint *from,
                         void *data, size_t capacity, size_t *size)
{
    fake_io *io = user;
    int rc = io->receive_status;
    io->receive_status = TSC_AGAIN;
    if (rc == TSC_OK) {
        CHECK(capacity >= sizeof(io->incoming));
        memcpy(data, io->incoming, sizeof(io->incoming));
        *size = sizeof(io->incoming);
        *from = io->from;
    }
    return rc;
}

static uint64_t fake_clock(void *user) { return ((fake_io *)user)->now; }
static int fake_random(void *user, void *data, size_t size)
{
    CHECK(size == sizeof(transaction));
    memcpy(data, transaction, size);
    return ((fake_io *)user)->random_status;
}

static void state_machine(void)
{
    fake_io io = { .receive_status = TSC_AGAIN };
    tsc_platform platform = { &io, fake_send, fake_receive, fake_clock, fake_random };
    tsc_endpoint server = { .family = TSC_AF_IPV4, .address = {127,0,0,1}, .port = 3478 };
    tsc_stun_client client;
    uint8_t scratch[TSC_MAX_DATAGRAM_SIZE];
    CHECK(tsc_stun_start(&client, &platform, &server) == TSC_OK);
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
    CHECK(io.sends == 1 && memcmp(io.outgoing + 8, transaction, 12) == 0);
    memcpy(io.incoming, response, sizeof(response));
    io.from = server;
    ++io.from.port; /* A reply from the wrong server must be ignored. */
    io.receive_status = TSC_OK;
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
    io.from = server;
    io.incoming[8] ^= 1; /* So must a reply for another transaction. */
    io.receive_status = TSC_OK;
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
    io.incoming[8] ^= 1;
    io.receive_status = TSC_OK;
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_OK);
    CHECK(client.mapped.address[0] == 203 && client.mapped.port == 3478);
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_OK);

    CHECK(tsc_stun_start(&client, &client.platform, &client.server) == TSC_OK);
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
    CHECK(tsc_endpoint_equal(&client.server, &server));

    io.sends = 0;
    CHECK(tsc_stun_start(&client, &platform, &server) == TSC_OK);
    for (unsigned i = 0; i < TSC_STUN_MAX_ATTEMPTS; ++i) {
        io.now = client.next_attempt_ms;
        CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
        CHECK(io.sends == i + 1);
        io.now = client.next_attempt_ms - 1;
        CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
        CHECK(io.sends == i + 1);
    }
    io.now = client.next_attempt_ms;
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_ERR_TIMEOUT);
    CHECK(io.sends == TSC_STUN_MAX_ATTEMPTS);
    io.send_status = TSC_AGAIN;
    CHECK(tsc_stun_start(&client, &platform, &server) == TSC_OK);
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
    CHECK(client.attempts == 0);
    io.now = client.deadline_ms;
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_ERR_TIMEOUT);
    CHECK(tsc_stun_start(&client, &platform, &server) == TSC_OK);
    io.send_status = TSC_ERR_IO;
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_ERR_IO);
    io.random_status = TSC_ERR_IO;
    CHECK(tsc_stun_start(&client, &platform, &server) == TSC_ERR_IO);
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_ERR_IO);
}

static void socket_integration(void)
{
    tsc_socket a = TSC_SOCKET_INITIALIZER, b = TSC_SOCKET_INITIALIZER;
    tsc_endpoint loopback, server, from;
    tsc_stun_client client;
    tsc_platform platform;
    uint8_t scratch[TSC_MAX_DATAGRAM_SIZE], reply[sizeof(response)];
    size_t size;
    CHECK(tsc_socket_resolve("127.0.0.1", 0, TSC_AF_IPV4, &loopback) == TSC_OK);
    CHECK(tsc_socket_open(&a, &loopback) == TSC_OK);
    CHECK(tsc_socket_open(&b, &loopback) == TSC_OK);
    CHECK(tsc_socket_local(&b, &server) == TSC_OK);
    platform = tsc_socket_platform(&a);
    CHECK(tsc_stun_start(&client, &platform, &server) == TSC_OK);
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_AGAIN);
    struct pollfd descriptor = { .fd = b.fd, .events = POLLIN };
    CHECK(poll(&descriptor, 1, 1000) == 1);
    CHECK(tsc_socket_receive(&b, &from, scratch, sizeof(scratch), &size) == TSC_OK);
    CHECK(size == TSC_STUN_REQUEST_SIZE && scratch[1] == 1);
    memcpy(reply, response, sizeof(reply));
    memcpy(reply + 8, scratch + 8, 12);
    CHECK(tsc_socket_send(&b, &from, reply, sizeof(reply)) == TSC_OK);
    descriptor.fd = a.fd;
    CHECK(poll(&descriptor, 1, 1000) == 1);
    CHECK(tsc_stun_poll(&client, scratch, sizeof(scratch)) == TSC_OK);
    CHECK(client.mapped.port == 3478 && client.mapped.address[0] == 203);
    tsc_socket_close(&a);
    tsc_socket_close(&b);
}

int main(void)
{
    parser();
    state_machine();
    socket_integration();
    printf("STUN tests passed; client storage = %zu bytes\n", sizeof(tsc_stun_client));
    return 0;
}
#else
int main(void)
{
    puts("STUN excluded by configuration");
    return 77;
}
#endif
