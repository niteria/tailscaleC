#define _POSIX_C_SOURCE 200809L
#include "tailscalec/disco.h"
#include "tailscalec/crypto.h"
#include "tailscalec/socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if TSC_ENABLE_DISCO

typedef struct {
    tsc_socket socket;
    tsc_platform underlying;
    tsc_endpoint own, peer;
    uint8_t peer_node[32];
    size_t observations, pongs, paths;
    int bad_endpoint;
} context;

static int send_packet(void *user, const tsc_endpoint *to, const void *data, size_t length)
{
    context *c = user;
    int status = c->underlying.udp_send(c->underlying.user, to, data, length);
    if (status == TSC_OK && length == 110) ++c->pongs;
    return status;
}

static uint64_t now_ms(void *user)
{
    context *c = user;
    return c->underlying.monotonic_ms(c->underlying.user);
}

static int random_bytes(void *user, void *data, size_t length)
{
    context *c = user;
    return c->underlying.random_bytes(c->underlying.user, data, length);
}

static void observed(void *user, const tsc_endpoint *ep)
{
    context *c = user;
    if (!tsc_endpoint_equal(ep, &c->own)) c->bad_endpoint = 1;
    ++c->observations;
}

static void path_changed(void *user, const uint8_t node[32], const tsc_endpoint *ep, uint32_t rtt)
{
    context *c = user;
    (void)rtt;
    if (!tsc_endpoint_equal(ep, &c->peer) || memcmp(node, c->peer_node, 32)) c->bad_endpoint = 1;
    ++c->paths;
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
    static const uint8_t node_private[32] = {17,33,4,88,9};
    static const uint8_t disco_private[32] = {7,93,11,27,2};
    context c = {0};
    tsc_disco d = {0};
    tsc_endpoint bind_address = {TSC_AF_IPV4,{127,0,0,1},0,0}, source, chosen;
    tsc_platform platform = {&c, send_packet, NULL, now_ms, random_bytes};
    tsc_disco_callbacks callbacks = {&c, NULL, path_changed, observed};
    uint8_t disco_key[32], node_key[32], packet[TSC_MAX_DATAGRAM_SIZE];
    unsigned long port;
    uint64_t start;
    size_t round, length;
    struct timespec pause = {0, 1000000};
    int status = TSC_ERR_ARGUMENT;
    if (argc != 5) return 77;
    c.socket.fd = -1;
    port = strtoul(argv[2], NULL, 10);
    if (!port || port > 65535 || !decode_key(disco_key, argv[3]) ||
        !decode_key(c.peer_node, argv[4])) return 1;
    if ((status = tsc_socket_resolve(argv[1], (uint16_t)port, TSC_AF_IPV4, &c.peer)) != TSC_OK ||
        (status = tsc_socket_open(&c.socket, &bind_address)) != TSC_OK ||
        (status = tsc_socket_local(&c.socket, &c.own)) != TSC_OK ||
        (status = tsc_crypto_x25519_public(node_key, node_private)) != TSC_OK) goto done;
    c.underlying = tsc_socket_platform(&c.socket);
    if ((status = tsc_disco_init(&d, &platform, &callbacks, disco_private, node_key)) != TSC_OK ||
        (status = tsc_disco_set_peer(&d, c.peer_node, disco_key, &c.peer, 1)) != TSC_OK) goto done;
    for (round = 0; round < 200; ++round) {
        if ((status = tsc_disco_probe(&d, c.peer_node, 0)) != TSC_OK) goto done;
        start = now_ms(&c);
        while (c.observations <= round || c.pongs <= round) {
            status = tsc_socket_receive(&c.socket, &source, packet, sizeof(packet), &length);
            if (status == TSC_AGAIN) {
                if (now_ms(&c)-start > 3000) { status = TSC_ERR_TIMEOUT; goto done; }
                (void)nanosleep(&pause, NULL);
                continue;
            }
            if (status != TSC_OK ||
                (status = tsc_disco_receive(&d, &source, packet, length)) != TSC_OK) goto done;
            if (length == 110 && tsc_disco_receive(&d, &source, packet, length) != TSC_AGAIN) {
                status = TSC_ERR_PROTOCOL; goto done;
            }
        }
        if (c.bad_endpoint || tsc_disco_endpoint(&d, c.peer_node, &chosen) != TSC_OK ||
            !tsc_endpoint_equal(&chosen, &c.peer)) { status = TSC_ERR_PROTOCOL; goto done; }
    }
    if (c.paths != 1 || c.observations != 200 || c.pongs != 200) {
        status = TSC_ERR_PROTOCOL; goto done;
    }
    puts("DISCO live: upstream Go parser/marshaller + Go NaCl, 200 bidirectional ping/pong exchanges, node/endpoint binding, replay rejection passed");
    status = TSC_OK;
done:
    if (status != TSC_OK) fprintf(stderr, "DISCO live failed: %d\n", status);
    tsc_disco_clear(&d);
    tsc_socket_close(&c.socket);
    return status == TSC_OK ? 0 : 1;
}

#else
int main(void) { return 77; }
#endif
