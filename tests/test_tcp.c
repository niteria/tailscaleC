#define _POSIX_C_SOURCE 200809L
#include "tailscalec/tcp.h"
#include "check.h"

#if TSC_APP_TCP
#include <stdint.h>
#include <string.h>
#ifndef ESP_PLATFORM
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

/* Wire tests use independent processes because the bounded TCP engine permits
 * one stack per process. The parent is a lossy/reordering IP link, not a TCP
 * implementation. Every packet also gets independently checked here. */
enum { TEST_PORT = 48127, TRANSFER_SIZE = 32789 };

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void write16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint32_t sum_bytes(uint32_t sum, const uint8_t *p, size_t length)
{
    while (length >= 2) {
        sum += read16(p);
        p += 2;
        length -= 2;
    }
    if (length)
        sum += (uint16_t)p[0] << 8;
    return sum;
}

static uint16_t finish_sum(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 65535U) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(const uint8_t *packet, size_t length)
{
    size_t header = (packet[0] & 15U) * 4U;
    uint32_t sum = sum_bytes(0, packet + 12, 8);
    sum += 6 + (uint32_t)(length - header);
    return finish_sum(sum_bytes(sum, packet + header, length - header));
}

static size_t check_packet(const uint8_t *packet, size_t length)
{
    CHECK(length >= 40 && length <= TSC_MAX_DATAGRAM_SIZE);
    CHECK((packet[0] >> 4) == 4);
    size_t ip_header = (packet[0] & 15U) * 4U;
    CHECK(ip_header >= 20 && ip_header + 20 <= length);
    CHECK(read16(packet + 2) == length && packet[9] == 6);
    CHECK((read16(packet + 6) & 0x3fffU) == 0);
    CHECK(finish_sum(sum_bytes(0, packet, ip_header)) == 0);
    size_t tcp_header = (packet[ip_header + 12] >> 4) * 4U;
    CHECK(tcp_header >= 20 && ip_header + tcp_header <= length);
    CHECK(tcp_checksum(packet, length) == 0);
    return length - ip_header - tcp_header;
}

typedef struct {
    uint8_t packet[TSC_MAX_DATAGRAM_SIZE];
    size_t length;
    unsigned packets;
    int output_status;
    int random_status;
    uint32_t random;
    tsc_tcp *reentrant_stack;
    unsigned reentry_attempts;
} capture_io;

static int capture_packet(void *user, const void *packet, size_t length)
{
    capture_io *io = user;
    check_packet(packet, length);
    CHECK(length <= sizeof(io->packet));
    memcpy(io->packet, packet, length);
    io->length = length;
    ++io->packets;
    if (io->reentrant_stack) {
        tsc_tcp_handle handle;
        tsc_tcp_state state;
        CHECK(tsc_tcp_get_state(io->reentrant_stack, 1, &state) == TSC_ERR_ARGUMENT);
        CHECK(tsc_tcp_listen(io->reentrant_stack, TEST_PORT,
                              &handle) == TSC_ERR_ARGUMENT);
        CHECK(tsc_tcp_input(io->reentrant_stack, packet, length) == TSC_ERR_ARGUMENT);
        CHECK(tsc_tcp_poll(io->reentrant_stack, 0) == TSC_ERR_ARGUMENT);
        ++io->reentry_attempts;
    }
    return io->output_status;
}

static int random_bytes(void *user, void *output, size_t length)
{
    capture_io *io = user;
    uint8_t *bytes = output;
    if (io->random_status != TSC_OK)
        return io->random_status;
    for (size_t i = 0; i < length; ++i) {
        io->random = io->random * UINT32_C(1664525) + UINT32_C(1013904223);
        bytes[i] = (uint8_t)(io->random >> 24);
    }
    return TSC_OK;
}

static tsc_tcp_config test_config(capture_io *io)
{
    tsc_tcp_config config = {
        .local_ipv4 = {100, 64, 0, 1}, .mtu = 1280,
        .user = io, .send_ip = capture_packet, .random_bytes = random_bytes
    };
    return config;
}

static void validation_and_limits(void)
{
    tsc_tcp stack = {0}, second = {0};
    capture_io io = { .random = UINT32_C(0x43e1) };
    tsc_tcp_config config = test_config(&io);
    tsc_tcp_handle handle = 0;
    tsc_endpoint remote = {
        .family = TSC_AF_IPV4, .address = {100, 64, 0, 2}, .port = TEST_PORT
    };
    CHECK(tsc_tcp_init(NULL, &config, 0) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_init(&stack, NULL, 0) == TSC_ERR_ARGUMENT);
    config.mtu = 575;
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_ERR_ARGUMENT);
    config.mtu = 1280;
    config.send_ip = NULL;
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_ERR_ARGUMENT);
    config = test_config(&io);
    CHECK(tsc_tcp_init(&stack, &config, 100) == TSC_OK);
    CHECK(tsc_tcp_init(&second, &config, 100) == TSC_ERR_SPACE);
    CHECK(tsc_tcp_init(&stack, &config, 100) == TSC_ERR_SPACE);
    CHECK(tsc_tcp_poll(NULL, 100) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_input(NULL, "", 0) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_input(&stack, NULL, 40) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_listen(&stack, TEST_PORT, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_listen(&stack, 0, &handle) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_connect(&stack, NULL, 0, &handle) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_connect(&stack, &remote, 0, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_close(&stack, 0) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_unlisten(&stack, 0) == TSC_ERR_ARGUMENT);

    tsc_tcp_handle listeners[TSC_MAX_TCP_LISTENERS];
    for (size_t i = 0; i < TSC_MAX_TCP_LISTENERS; ++i) {
        CHECK(tsc_tcp_listen(&stack, (uint16_t)(TEST_PORT + i),
                              &listeners[i]) == TSC_OK);
        tsc_endpoint from;
        CHECK(tsc_tcp_accept(&stack, listeners[i], &handle, &from) == TSC_AGAIN);
    }
    CHECK(tsc_tcp_listen(&stack, TEST_PORT + TSC_MAX_TCP_LISTENERS,
                          &handle) == TSC_ERR_SPACE);
    for (size_t i = 0; i < TSC_MAX_TCP_LISTENERS; ++i)
        CHECK(tsc_tcp_unlisten(&stack, listeners[i]) == TSC_OK);
    CHECK(tsc_tcp_unlisten(&stack, listeners[0]) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_listen(&stack, TEST_PORT, &handle) == TSC_OK);
    CHECK(tsc_tcp_unlisten(&stack, handle) == TSC_OK);

    tsc_tcp_handle connections[TSC_MAX_TCP_CONNECTIONS];
    for (size_t i = 0; i < TSC_MAX_TCP_CONNECTIONS; ++i) {
        CHECK(tsc_tcp_connect(&stack, &remote, 0, &connections[i]) == TSC_OK);
        tsc_tcp_state state = TSC_TCP_UNUSED;
        CHECK(tsc_tcp_get_state(&stack, connections[i], &state) == TSC_OK);
        CHECK(state == TSC_TCP_CONNECTING);
    }
    CHECK(tsc_tcp_connect(&stack, &remote, 0, &handle) == TSC_ERR_SPACE);
    tsc_tcp_state state;
    uint8_t byte = 0;
    size_t length = 999;
    CHECK(tsc_tcp_get_state(&stack, 0, &state) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_get_state(&stack, connections[0], NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_send(&stack, connections[0], NULL, 1, &length) == TSC_ERR_ARGUMENT);
    CHECK(length == 0);
    CHECK(tsc_tcp_send(&stack, connections[0], &byte, 1, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_receive(&stack, connections[0], NULL, 1,
                           &length) == TSC_ERR_ARGUMENT);
    CHECK(length == 0);
    CHECK(tsc_tcp_receive(&stack, connections[0], &byte, 1, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_send(&stack, 0, &byte, 1, &length) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_receive(&stack, 0, &byte, 1, &length) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_shutdown(&stack, 0) == TSC_ERR_ARGUMENT);
    for (size_t i = 0; i < TSC_MAX_TCP_CONNECTIONS; ++i) {
        CHECK(tsc_tcp_close(&stack, connections[i]) == TSC_OK);
        CHECK(tsc_tcp_close(&stack, connections[i]) == TSC_ERR_ARGUMENT);
    }
    CHECK(tsc_tcp_connect(&stack, &remote, 0, &handle) == TSC_OK);
    CHECK(tsc_tcp_close(&stack, handle) == TSC_OK);

    /* Malformed input must not emit a response or consume application slots. */
    uint8_t malformed[40] = {0};
    unsigned before = io.packets;
    for (size_t n = 0; n < sizeof(malformed); ++n)
        CHECK(tsc_tcp_input(&stack, malformed, n) < TSC_OK);
    CHECK(io.packets == before);
    tsc_tcp_destroy(&stack);
    tsc_tcp_destroy(&stack);
    tsc_tcp_destroy(NULL);
    CHECK(tsc_tcp_poll(&stack, 101) == TSC_ERR_ARGUMENT);
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_OK);
    tsc_tcp_destroy(&stack);
    CHECK(tsc_tcp_init(&second, &config, 0) == TSC_OK);
    tsc_tcp_destroy(&second);
    puts("TCP validation, listener/connection limits and reinitialization passed");
}

static void random_failure_and_reentry(void)
{
    tsc_tcp stack = {0}, second = {0};
    capture_io io = {
        .random = UINT32_C(0x80ea), .random_status = TSC_ERR_IO
    };
    tsc_tcp_config config = test_config(&io);
    tsc_endpoint remote = {
        .family = TSC_AF_IPV4, .address = {100,64,0,2}, .port = TEST_PORT
    };
    tsc_tcp_handle connection, listener;
    uint8_t malformed[40] = {0};

    /* An unavailable secure RNG must not reserve the process-wide instance. */
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_ERR_IO);
    CHECK(io.packets == 0);
    io.random_status = TSC_OK;
    CHECK(tsc_tcp_init(&second, &config, 0) == TSC_OK);
    tsc_tcp_destroy(&second);

    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_OK);
    io.random_status = TSC_ERR_IO;
    CHECK(tsc_tcp_connect(&stack, &remote, 0, &connection) == TSC_ERR_IO);
    CHECK(io.packets == 0); /* No SYN with a predictable fallback sequence. */
    CHECK(tsc_tcp_poll(&stack, 1000) == TSC_ERR_IO);
    CHECK(tsc_tcp_input(&stack, malformed, sizeof(malformed)) == TSC_ERR_IO);
    CHECK(tsc_tcp_listen(&stack, TEST_PORT, &listener) == TSC_ERR_IO);
    CHECK(tsc_tcp_connect(&stack, &remote, 0, &connection) == TSC_ERR_IO);
    CHECK(io.packets == 0);
    tsc_tcp_destroy(&stack);

    io.random_status = TSC_OK;
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_OK);
    CHECK(tsc_tcp_connect(&stack, &remote, 0, &connection) == TSC_OK);
    CHECK(io.packets > 0);
#if TSC_MAX_TCP_CONNECTIONS > 1
    unsigned before = io.packets;
    tsc_tcp_handle other;
    size_t sent = 999;
    io.random_status = TSC_ERR_IO;
    CHECK(tsc_tcp_connect(&stack, &remote, 0, &other) == TSC_ERR_IO);
    CHECK(tsc_tcp_send(&stack, connection, "x", 1, &sent) == TSC_ERR_IO);
    CHECK(sent == 0);
    CHECK(tsc_tcp_shutdown(&stack, connection) == TSC_ERR_IO);
    CHECK(io.packets == before);
#endif
    tsc_tcp_destroy(&stack);

    io.random_status = TSC_OK;
    io.reentrant_stack = &stack;
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_OK);
    CHECK(tsc_tcp_connect(&stack, &remote, 0, &connection) == TSC_OK);
    CHECK(io.reentry_attempts > 0);
    tsc_tcp_state state;
    CHECK(tsc_tcp_get_state(&stack, connection, &state) == TSC_OK);
    CHECK(state == TSC_TCP_CONNECTING);
    CHECK(tsc_tcp_close(&stack, connection) == TSC_OK);
    tsc_tcp_destroy(&stack);
    puts("TCP RNG failure suppresses output, recovers after destroy; callback reentry rejected");
}

static void independent_wire_packet(void)
{
    tsc_tcp stack = {0};
    capture_io io = { .random = UINT32_C(0x9121) };
    tsc_tcp_config config = test_config(&io);
    uint8_t syn[40] = {
        0x45,0,0,40,0x12,0x34,0x40,0,64,6,0,0,
        100,64,0,2,100,64,0,1,
        0x98,0x76,0xbc,0x01,0x12,0x34,0x56,0x78,
        0,0,0,0,0x50,0x02,0x40,0,0,0,0,0
    };
    write16(syn + 10, finish_sum(sum_bytes(0, syn, 20)));
    write16(syn + 36, tcp_checksum(syn, sizeof(syn)));
    CHECK(check_packet(syn, sizeof(syn)) == 0);
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_OK);
    /* A standards-shaped packet from outside this library gets a valid RST. */
    CHECK(tsc_tcp_input(&stack, syn, sizeof(syn)) == TSC_OK);
    CHECK(io.packets == 1);
    size_t ip_header = (io.packet[0] & 15U) * 4U;
    CHECK((io.packet[ip_header + 13] & 0x14) == 0x14);
    CHECK(read32(io.packet + ip_header + 8) == UINT32_C(0x12345679));
    CHECK(read16(io.packet + ip_header) == 0xbc01);
    CHECK(read16(io.packet + ip_header + 2) == 0x9876);
    CHECK(memcmp(io.packet + 12, syn + 16, 4) == 0);
    CHECK(memcmp(io.packet + 16, syn + 12, 4) == 0);

    unsigned before = io.packets;
    syn[27] ^= 1; /* Corrupt TCP sequence without updating the checksum. */
    (void)tsc_tcp_input(&stack, syn, sizeof(syn));
    CHECK(io.packets == before);
    syn[27] ^= 1;
    syn[8] ^= 1; /* Likewise an invalid IP header checksum. */
    (void)tsc_tcp_input(&stack, syn, sizeof(syn));
    CHECK(io.packets == before);
    tsc_tcp_destroy(&stack);
    puts("TCP independently encoded SYN/reset and checksum rejection passed");
}

static void raw_segment(tsc_tcp *stack, uint32_t sequence, uint32_t acknowledgment,
                        uint8_t flags, const void *data, size_t length)
{
    uint8_t packet[TSC_MAX_DATAGRAM_SIZE] = {
        0x45,0,0,0,0,0,0x40,0,64,6,0,0,
        100,64,0,2,100,64,0,1
    };
    CHECK(length <= sizeof(packet) - 40);
    write16(packet + 2, (uint16_t)(40 + length));
    write16(packet + 20, 39000);
    write16(packet + 22, TEST_PORT);
    write32(packet + 24, sequence);
    write32(packet + 28, acknowledgment);
    packet[32] = 0x50;
    packet[33] = flags;
    write16(packet + 34, 4096);
    if (length)
        memcpy(packet + 40, data, length);
    write16(packet + 10, finish_sum(sum_bytes(0, packet, 20)));
    write16(packet + 36, tcp_checksum(packet, 40 + length));
    CHECK(check_packet(packet, 40 + length) == length);
    CHECK(tsc_tcp_input(stack, packet, 40 + length) == TSC_OK);
}

static void independent_wire_exchange(int active_close)
{
    tsc_tcp stack = {0};
    capture_io io = { .random = UINT32_C(0xa012) };
    tsc_tcp_config config = test_config(&io);
    tsc_tcp_handle listener, connection;
    tsc_endpoint remote;
    const uint8_t request[] = {0,1,2,0xff,0xfe,0xfd,0x80};
    const uint8_t reply[] = {0xff,0,0xaa,0x55,0,0x99,0x42,0x31};
    uint8_t received[sizeof(request)];
    size_t count;
    uint32_t peer_sequence = UINT32_C(0xfffffff9);
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_OK);
    CHECK(tsc_tcp_listen(&stack, TEST_PORT, &listener) == TSC_OK);
    raw_segment(&stack, peer_sequence, 0, 0x02, NULL, 0);
    CHECK(io.packets == 1);
    size_t header = (io.packet[0] & 15U) * 4U;
    CHECK((io.packet[header + 13] & 0x12) == 0x12);
    CHECK(read32(io.packet + header + 8) == peer_sequence + 1);
    uint32_t local_sequence = read32(io.packet + header + 4) + 1;
    ++peer_sequence;
    raw_segment(&stack, peer_sequence, local_sequence, 0x10, NULL, 0);
    CHECK(tsc_tcp_accept(&stack, listener, &connection, &remote) == TSC_OK);
    CHECK(remote.family == TSC_AF_IPV4 && remote.port == 39000);
    CHECK(remote.address[3] == 2);
    CHECK(tsc_tcp_receive(&stack, connection, received, sizeof(received),
                           &count) == TSC_AGAIN);
    CHECK(count == 0);

    /* This segment crosses UINT32_MAX, exercising actual TCP sequence wrap. */
    raw_segment(&stack, peer_sequence, local_sequence, 0x18,
                request, sizeof(request));
    peer_sequence += (uint32_t)sizeof(request);
    CHECK(tsc_tcp_receive(&stack, connection, received, 3, &count) == TSC_OK);
    CHECK(count == 3 && memcmp(received, request, 3) == 0);
    CHECK(tsc_tcp_receive(&stack, connection, received + 3,
                           sizeof(received) - 3, &count) == TSC_OK);
    CHECK(count == sizeof(request) - 3);
    CHECK(memcmp(received, request, sizeof(request)) == 0);
    CHECK(tsc_tcp_send(&stack, connection, reply, sizeof(reply), &count) == TSC_OK);
    CHECK(count == sizeof(reply));
    CHECK(check_packet(io.packet, io.length) == sizeof(reply));
    header = (io.packet[0] & 15U) * 4U;
    size_t tcp_header = (io.packet[header + 12] >> 4) * 4U;
    CHECK(read32(io.packet + header + 4) == local_sequence);
    CHECK(read32(io.packet + header + 8) == peer_sequence);
    CHECK(memcmp(io.packet + header + tcp_header, reply, sizeof(reply)) == 0);
    local_sequence += (uint32_t)sizeof(reply);
    if (active_close) {
        /* Keep the application handle alive after the engine's TIME_WAIT PCB
         * expires. A freed PCB must never be dereferenced by a later close. */
        raw_segment(&stack, peer_sequence, local_sequence, 0x10, NULL, 0);
        CHECK(tsc_tcp_shutdown(&stack, connection) == TSC_OK);
        raw_segment(&stack, peer_sequence, local_sequence + 1, 0x11, NULL, 0);
        ++peer_sequence;
        for (unsigned i = 0; i < 4; ++i)
            CHECK(tsc_tcp_poll(&stack, 180000) == TSC_OK);
    } else {
        raw_segment(&stack, peer_sequence, local_sequence, 0x11, NULL, 0);
        ++peer_sequence;
        CHECK(tsc_tcp_receive(&stack, connection, received, sizeof(received),
                               &count) == TSC_OK);
        CHECK(count == 0);
        CHECK(tsc_tcp_shutdown(&stack, connection) == TSC_OK);
        header = (io.packet[0] & 15U) * 4U;
        CHECK(io.packet[header + 13] & 1U);
        CHECK(read32(io.packet + header + 4) == local_sequence);
        CHECK(read32(io.packet + header + 8) == peer_sequence);
        raw_segment(&stack, peer_sequence, local_sequence + 1, 0x10, NULL, 0);
    }
    tsc_tcp_state state;
    CHECK(tsc_tcp_get_state(&stack, connection, &state) == TSC_OK);
    CHECK(state == TSC_TCP_EOF);
    CHECK(tsc_tcp_receive(&stack, connection, received, sizeof(received),
                           &count) == TSC_OK);
    CHECK(count == 0);
    CHECK(tsc_tcp_close(&stack, connection) == TSC_OK);
    CHECK(tsc_tcp_unlisten(&stack, listener) == TSC_OK);
    tsc_tcp_destroy(&stack);
    printf("TCP independent wire peer: handshake, binary transfer, sequence wrap, FIN%s passed\n",
           active_close ? " and deferred close after TIME_WAIT expiry" : "");
}

#ifndef ESP_PLATFORM
typedef struct {
    int descriptor;
    capture_io random;
} endpoint_io;

static int endpoint_output(void *user, const void *packet, size_t length)
{
    endpoint_io *io = user;
    check_packet(packet, length);
    ssize_t n;
    do {
        n = send(io->descriptor, packet, length, 0);
    } while (n < 0 && errno == EINTR);
    return n == (ssize_t)length ? TSC_OK : TSC_ERR_IO;
}

static int endpoint_random(void *user, void *output, size_t length)
{
    return random_bytes(&((endpoint_io *)user)->random, output, length);
}

static uint8_t payload_byte(unsigned side, size_t offset)
{
    return (uint8_t)((offset * 73U + (offset >> 7) + side * 103U) & 255U);
}

static void marker(int descriptor, char value)
{
    CHECK(send(descriptor, &value, 1, 0) == 1);
}

static void endpoint_process(int descriptor, unsigned side)
{
    alarm(15);
    tsc_tcp stack = {0};
    endpoint_io io = {
        .descriptor = descriptor,
        .random = { .random = UINT32_C(0x12340000) + side }
    };
    tsc_tcp_config config = {
        .local_ipv4 = {100,64,0,(uint8_t)(side + 1)}, .mtu = 1280,
        .user = &io, .send_ip = endpoint_output, .random_bytes = endpoint_random
    };
    tsc_endpoint remote = {
        .family = TSC_AF_IPV4, .address = {100,64,0,2}, .port = TEST_PORT
    };
    tsc_tcp_handle listener = 0, connection = 0;
    CHECK(tsc_tcp_init(&stack, &config, 0) == TSC_OK);
    if (side == 1)
        CHECK(tsc_tcp_listen(&stack, TEST_PORT, &listener) == TSC_OK);
    marker(descriptor, 'R');
    char go;
    CHECK(recv(descriptor, &go, 1, 0) == 1 && go == 'G');
    if (side == 0)
        CHECK(tsc_tcp_connect(&stack, &remote, 40123, &connection) == TSC_OK);

    uint8_t incoming[TSC_MAX_DATAGRAM_SIZE];
    uint8_t data[4096];
    size_t sent = 0, received = 0;
    unsigned blocked_writes = 0;
    int shutdown_sent = 0, received_eof = 0;
    uint64_t now = 0;
    for (unsigned round = 0; round < 100000; ++round) {
        struct pollfd pfd = { .fd = descriptor, .events = POLLIN };
        int polled = poll(&pfd, 1, 1);
        CHECK(polled >= 0 || errno == EINTR);
        if (polled > 0 && (pfd.revents & POLLIN)) {
            for (unsigned i = 0; i < 64; ++i) {
                ssize_t n = recv(descriptor, incoming, sizeof(incoming), MSG_DONTWAIT);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    break;
                if (n < 0 && errno == EINTR)
                    continue;
                CHECK(n > 0);
                if (n == 1) {
                    CHECK(incoming[0] == 'Q');
                    CHECK(sent == TRANSFER_SIZE && received == TRANSFER_SIZE);
                    CHECK(shutdown_sent && received_eof);
                    CHECK(blocked_writes > 0);
                    CHECK(tsc_tcp_close(&stack, connection) == TSC_OK);
                    if (listener)
                        CHECK(tsc_tcp_unlisten(&stack, listener) == TSC_OK);
                    tsc_tcp_destroy(&stack);
                    close(descriptor);
                    exit(0);
                }
                CHECK(tsc_tcp_input(&stack, incoming, (size_t)n) == TSC_OK);
            }
        }
        now += 10;
        CHECK(tsc_tcp_poll(&stack, now) == TSC_OK);
        if (!connection && side == 1) {
            tsc_endpoint from;
            int status = tsc_tcp_accept(&stack, listener, &connection, &from);
            CHECK(status == TSC_OK || status == TSC_AGAIN);
            if (status == TSC_OK) {
                CHECK(from.family == TSC_AF_IPV4 && from.port == 40123);
                CHECK(from.address[0] == 100 && from.address[3] == 1);
            }
        }
        if (!connection)
            continue;
        tsc_tcp_state state;
        CHECK(tsc_tcp_get_state(&stack, connection, &state) == TSC_OK);
        if (state == TSC_TCP_FAILED)
            fprintf(stderr, "TCP endpoint %u failed at %llu ms; sent=%zu, received=%zu, shutdown=%d, EOF=%d\n",
                    side, (unsigned long long)now, sent, received,
                    shutdown_sent, received_eof);
        CHECK(state != TSC_TCP_FAILED && state != TSC_TCP_UNUSED);
        if (state == TSC_TCP_CONNECTING)
            continue;

        /* Saturate the bounded send queue, rather than assuming each write is
         * accepted whole. Parent-side losses also force buffered retransmits. */
        while (sent < TRANSFER_SIZE) {
            size_t offered = TRANSFER_SIZE - sent;
            if (offered > sizeof(data))
                offered = sizeof(data);
            for (size_t i = 0; i < offered; ++i)
                data[i] = payload_byte(side, sent + i);
            size_t count = 999;
            int status = tsc_tcp_send(&stack, connection, data, offered, &count);
            CHECK(status == TSC_OK || status == TSC_AGAIN);
            CHECK(count <= offered);
            if (status == TSC_AGAIN) {
                CHECK(count == 0);
                ++blocked_writes;
                break;
            }
            CHECK(count > 0);
            sent += count;
        }

        /* Delay reads to exercise bounded receive storage and advertised-window
         * backpressure. Poll/input must continue to service ACKs meanwhile. */
        if (now >= 1000 && !received_eof) {
            for (;;) {
                size_t count = 999;
                size_t capacity = 1 + (received % sizeof(data));
                int status = tsc_tcp_receive(&stack, connection, data, capacity, &count);
                CHECK(status == TSC_OK || status == TSC_AGAIN);
                if (status == TSC_AGAIN) {
                    CHECK(count == 0);
                    break;
                }
                CHECK(count <= capacity && count <= TRANSFER_SIZE - received);
                if (!count) {
                    CHECK(received == TRANSFER_SIZE);
                    received_eof = 1;
                    break;
                }
                for (size_t i = 0; i < count; ++i)
                    CHECK(data[i] == payload_byte(1 - side, received + i));
                received += count;
            }
        }
        if (sent == TRANSFER_SIZE && !shutdown_sent) {
            int status = tsc_tcp_shutdown(&stack, connection);
            CHECK(status == TSC_OK || status == TSC_AGAIN);
            shutdown_sent = status == TSC_OK;
        }
        if (shutdown_sent && received_eof == 1) {
            marker(descriptor, 'D');
            /* The parent may still need us to acknowledge peer retransmits. */
            received_eof = 2;
        }
    }
    CHECK(!"TCP exchange exceeded bounded event-loop deadline");
}

static uint64_t milliseconds(void)
{
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void forward_packet(int descriptor, const uint8_t *packet, size_t length)
{
    CHECK(send(descriptor, packet, length, 0) == (ssize_t)length);
}

static void exchange(int impaired)
{
    int links[2][2];
    pid_t children[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, links[0]) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, links[1]) == 0);
    for (unsigned side = 0; side < 2; ++side) {
        children[side] = fork();
        CHECK(children[side] >= 0);
        if (!children[side]) {
            close(links[0][0]);
            close(links[1][0]);
            close(links[1 - side][1]);
            endpoint_process(links[side][1], side);
            exit(1);
        }
    }
    close(links[0][1]);
    close(links[1][1]);
    unsigned ready = 0, done = 0;
    int started = 0;
    unsigned dropped_syn = 0, dropped_data[2] = {0}, duplicated = 0, reordered = 0;
    uint8_t held[TSC_MAX_DATAGRAM_SIZE];
    size_t held_length = 0;
    uint64_t held_since = 0;
    uint64_t deadline = milliseconds() + 12000;
    int success = 0;
    while (milliseconds() < deadline) {
        struct pollfd descriptors[2] = {
            { .fd = links[0][0], .events = POLLIN },
            { .fd = links[1][0], .events = POLLIN }
        };
        int status = poll(descriptors, 2, 5);
        CHECK(status >= 0 || errno == EINTR);
        for (unsigned side = 0; side < 2; ++side) {
            if (!(descriptors[side].revents & POLLIN))
                continue;
            uint8_t packet[TSC_MAX_DATAGRAM_SIZE];
            ssize_t n = recv(links[side][0], packet, sizeof(packet), 0);
            CHECK(n > 0);
            if (n == 1) {
                if (packet[0] == 'R')
                    ready |= 1U << side;
                else {
                    CHECK(packet[0] == 'D');
                    done |= 1U << side;
                }
                continue;
            }
            size_t length = (size_t)n;
            size_t payload = check_packet(packet, length);
            size_t ip_header = (packet[0] & 15U) * 4U;
            uint8_t flags = packet[ip_header + 13];
            if (impaired && side == 0 && (flags & 2U) && !dropped_syn) {
                ++dropped_syn;
                continue;
            }
            if (impaired && payload && !dropped_data[side]) {
                ++dropped_data[side];
                continue;
            }
            if (impaired && side == 0 && payload && !reordered) {
                if (!held_length) {
                    memcpy(held, packet, length);
                    held_length = length;
                    held_since = milliseconds();
                    continue;
                }
                size_t held_header = (held[0] & 15U) * 4U;
                if (read32(packet + ip_header + 4) !=
                    read32(held + held_header + 4)) {
                    forward_packet(links[1][0], packet, length);
                    forward_packet(links[1][0], held, held_length);
                    held_length = 0;
                    reordered = 1;
                    continue;
                }
            }
            forward_packet(links[1 - side][0], packet, length);
            if (impaired && side == 1 && payload && !duplicated) {
                forward_packet(links[0][0], packet, length);
                ++duplicated;
            }
        }
        if (ready == 3 && !started) {
            marker(links[0][0], 'G');
            marker(links[1][0], 'G');
            started = 1;
        }
        if (held_length && milliseconds() - held_since > 20) {
            forward_packet(links[1][0], held, held_length);
            held_length = 0;
        }
        if (done == 3) {
            marker(links[0][0], 'Q');
            marker(links[1][0], 'Q');
            success = 1;
            break;
        }
    }
    for (unsigned side = 0; side < 2; ++side) {
        if (!success)
            kill(children[side], SIGKILL);
        int status;
        CHECK(waitpid(children[side], &status, 0) == children[side]);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        close(links[side][0]);
    }
    CHECK(success);
    if (impaired) {
        CHECK(dropped_syn && dropped_data[0] && dropped_data[1]);
        CHECK(duplicated && reordered);
    }
    printf("TCP full-duplex %u-byte streams, half-close, backpressure%s passed\n",
           TRANSFER_SIZE, impaired ? ", SYN/data loss, duplication and reordering" : "");
}

#endif /* !ESP_PLATFORM */

int main(void)
{
    validation_and_limits();
    random_failure_and_reentry();
    independent_wire_packet();
    independent_wire_exchange(0);
    independent_wire_exchange(1);
#ifndef ESP_PLATFORM
    fflush(NULL); /* fork must not duplicate buffered test progress output. */
    exchange(0);
    fflush(NULL);
    exchange(1);
#endif
    printf("TCP tests passed; stack storage = %zu bytes\n", sizeof(tsc_tcp));
    return 0;
}
#else
int main(void)
{
    puts("Application TCP excluded by configuration");
    return 77;
}
#endif
