#define _POSIX_C_SOURCE 200809L
#include "tailscalec/socket.h"
#include "check.h"
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>

static void readable(tsc_socket *socket)
{
    struct pollfd descriptor = { .fd = socket->fd, .events = POLLIN };
    CHECK(poll(&descriptor, 1, 1000) == 1);
    CHECK(descriptor.revents & POLLIN);
}

static void roundtrip(tsc_address_family family)
{
    tsc_socket a = TSC_SOCKET_INITIALIZER;
    tsc_socket b = TSC_SOCKET_INITIALIZER;
    tsc_endpoint loopback, a_address, b_address, from;
    uint8_t packet[TSC_MAX_DATAGRAM_SIZE];
    static const uint8_t payload[] = { 0, 1, 2, 255, 0, 42 };
    size_t length = 999;
    int rc;
    CHECK(tsc_socket_resolve(family == TSC_AF_IPV4 ? "127.0.0.1" : "::1",
                            0, family, &loopback) == TSC_OK);
    rc = tsc_socket_open(&a, &loopback);
    if (rc != TSC_OK && family == TSC_AF_IPV6) {
        puts("IPv6 loopback unavailable on this host; IPv6 socket test skipped");
        return;
    }
    CHECK(rc == TSC_OK);
    CHECK(tsc_socket_open(&b, &loopback) == TSC_OK);
    CHECK(tsc_socket_open(&a, &loopback) == TSC_ERR_ARGUMENT);
    CHECK(tsc_socket_local(&a, &a_address) == TSC_OK);
    CHECK(tsc_socket_local(&b, &b_address) == TSC_OK);
    CHECK(a_address.port != 0 && b_address.port != 0);
    CHECK(tsc_socket_receive(&b, &from, packet, sizeof(packet), &length) == TSC_AGAIN);
    CHECK(length == 0);
    CHECK(tsc_socket_send(&a, &b_address, payload, sizeof(payload)) == TSC_OK);
    readable(&b);
    CHECK(tsc_socket_receive(&b, &from, packet, sizeof(packet), &length) == TSC_OK);
    CHECK(length == sizeof(payload) && memcmp(packet, payload, length) == 0);
    CHECK(tsc_endpoint_equal(&from, &a_address));

    /* A too-small caller buffer must discard, never deliver, a partial packet. */
    CHECK(tsc_socket_send(&a, &b_address, payload, sizeof(payload)) == TSC_OK);
    readable(&b);
    memset(packet, 0xa5, sizeof(packet));
    CHECK(tsc_socket_receive(&b, &from, packet, 1, &length) == TSC_ERR_TRUNCATED);
    CHECK(length == 0 && packet[0] == 0xa5);
    CHECK(tsc_socket_receive(&b, &from, packet, sizeof(packet), &length) == TSC_AGAIN);

    /* Zero-length datagrams are valid UDP, distinct from an empty socket. */
    CHECK(tsc_socket_send(&a, &b_address, NULL, 0) == TSC_OK);
    readable(&b);
    CHECK(tsc_socket_receive(&b, &from, NULL, 0, &length) == TSC_OK);
    CHECK(length == 0);

    memset(packet, 0x5a, sizeof(packet));
    CHECK(tsc_socket_send(&a, &b_address, packet, sizeof(packet)) == TSC_OK);
    readable(&b);
    CHECK(tsc_socket_receive(&b, &from, packet, sizeof(packet), &length) == TSC_OK);
    CHECK(length == sizeof(packet) && packet[sizeof(packet) - 1] == 0x5a);
    CHECK(tsc_socket_send(&a, &b_address, packet, sizeof(packet) + 1) == TSC_ERR_SPACE);

    tsc_socket_close(&a);
    tsc_socket_close(&a);
    tsc_socket_close(&b);
    CHECK(tsc_socket_open(&a, &loopback) == TSC_OK);
    tsc_socket_close(&a);
}

static void oversized_datagram(void)
{
#if TSC_MAX_DATAGRAM_SIZE < 65507
    tsc_socket sender = TSC_SOCKET_INITIALIZER, receiver = TSC_SOCKET_INITIALIZER;
    tsc_endpoint loopback, bound, from;
    struct sockaddr_in native = { 0 };
    uint8_t oversized[TSC_MAX_DATAGRAM_SIZE + 1];
    uint8_t destination[TSC_MAX_DATAGRAM_SIZE];
    size_t length;
    CHECK(tsc_socket_resolve("127.0.0.1", 0, TSC_AF_IPV4, &loopback) == TSC_OK);
    CHECK(tsc_socket_open(&sender, &loopback) == TSC_OK);
    CHECK(tsc_socket_open(&receiver, &loopback) == TSC_OK);
    CHECK(tsc_socket_local(&receiver, &bound) == TSC_OK);
    native.sin_family = AF_INET;
    native.sin_port = htons(bound.port);
    memcpy(&native.sin_addr, bound.address, 4);
    memset(oversized, 0x33, sizeof(oversized));
    CHECK(sendto(sender.fd, oversized, sizeof(oversized), 0,
                 (struct sockaddr *)&native, sizeof(native)) == (ssize_t)sizeof(oversized));
    readable(&receiver);
    CHECK(tsc_socket_receive(&receiver, &from, destination, sizeof(destination),
                             &length) == TSC_ERR_TRUNCATED);
    CHECK(length == 0);
    tsc_socket_close(&sender);
    tsc_socket_close(&receiver);
#endif
}

int main(void)
{
    tsc_socket socket = TSC_SOCKET_INITIALIZER;
    tsc_platform platform = tsc_socket_platform(&socket);
    uint8_t random[32];
    uint64_t before = platform.monotonic_ms(platform.user);
    CHECK(platform.random_bytes(platform.user, random, sizeof(random)) == TSC_OK);
    CHECK(platform.random_bytes(platform.user, NULL, 0) == TSC_OK);
    CHECK(platform.random_bytes(platform.user, NULL, 1) == TSC_ERR_ARGUMENT);
    CHECK(platform.monotonic_ms(platform.user) >= before);
    roundtrip(TSC_AF_IPV4);
#if TSC_ENABLE_IPV6
    roundtrip(TSC_AF_IPV6);
#else
    tsc_endpoint address;
    CHECK(tsc_socket_resolve("::1", 1, TSC_AF_IPV6, &address) == TSC_ERR_UNSUPPORTED);
#endif
    oversized_datagram();
    printf("Transport tests passed; socket storage = %zu bytes\n", sizeof(socket));
    return 0;
}
