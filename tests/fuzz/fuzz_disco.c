#include "tailscalec/disco.h"
#include "tailscalec/crypto.h"
#include "tailscalec/nacl.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static uint64_t current_time = 100;
static uint64_t now(void *unused) { (void)unused; return current_time; }
static int random_bytes(void *unused, void *buffer, size_t n)
{
    (void)unused;
    for (size_t i = 0; i < n; i++) ((uint8_t *)buffer)[i] = (uint8_t)(i + 1);
    return TSC_OK;
}
static int udp_send(void *unused, const tsc_endpoint *to, const void *packet, size_t n)
{
    (void)unused; (void)to; (void)packet;
    assert(n <= TSC_MAX_DATAGRAM_SIZE);
    return TSC_OK;
}
static int relay_send(void *unused, const uint8_t node[32], const void *packet, size_t n)
{
    (void)unused; (void)node; (void)packet;
    assert(n <= TSC_MAX_DATAGRAM_SIZE);
    return TSC_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized;
    static tsc_disco base;
    static uint8_t peer_public[32];
    static const uint8_t node[32] = {4};
    static const tsc_endpoint source = {.family=TSC_AF_IPV4, .address={127,0,0,1}, .port=1234};
    if (size > TSC_MAX_DATAGRAM_SIZE) return 0;
    current_time = 100;
    if (!initialized) {
        tsc_platform platform = {.udp_send=udp_send, .monotonic_ms=now, .random_bytes=random_bytes};
        tsc_disco_callbacks callbacks = {.relay_send=relay_send};
        uint8_t own_private[32] = {1}, own_node[32] = {2}, peer_private[32] = {3};
        assert(tsc_crypto_x25519_public(peer_public, peer_private) == TSC_OK);
        assert(tsc_disco_init(&base, &platform, &callbacks, own_private, own_node) == TSC_OK);
        assert(tsc_disco_set_peer(&base, node, peer_public, &source, 1) == TSC_OK);
        assert(tsc_disco_probe(&base, node, 1) == TSC_OK);
        initialized = 1;
    }
    tsc_disco d = base;
    (void)tsc_disco_is_packet(data, size);
    (void)tsc_disco_receive(&d, &source, data, size);
    assert(!d.peers[0].has_best); /* Unauthenticated bytes cannot select paths. */
    if (size + 78 <= TSC_MAX_DATAGRAM_SIZE) {
        uint8_t packet[TSC_MAX_DATAGRAM_SIZE] = {0};
        uint8_t plain[TSC_MAX_DATAGRAM_SIZE];
        memcpy(packet, "TS\xf0\x9f\x92\xac", 6);
        memcpy(packet + 6, peer_public, 32);
        memcpy(plain, data, size);
        if (size >= 14 && (data[1] & 4))
            memcpy(plain + 2, d.probes[0].txid, 12);
        assert(tsc_nacl_box_afternm(packet + 62, plain, size, packet + 38,
            d.peers[0].shared_key) == TSC_OK);
        int via_relay = size && (data[0] & 0x80);
        int rc = via_relay ? tsc_disco_receive_relay(&d, node, packet, size + 78) :
            tsc_disco_receive(&d, &source, packet, size + 78);
        assert(d.peers[0].endpoint_count <= TSC_MAX_PEER_ENDPOINTS);
        uint64_t trust = d.peers[0].trusted_until_ms;
        if (via_relay) assert(!d.peers[0].has_best);
        if (rc == TSC_OK && size >= 32 && data[0] == 2) {
            current_time++;
            (void)tsc_disco_receive(&d, &source, packet, size + 78);
            assert(d.peers[0].trusted_until_ms == trust); /* Pong replay. */
        }
    }
    tsc_disco_clear(&d);
    return 0;
}
