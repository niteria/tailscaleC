#include "tailscalec/config.h"
#if TSC_SESSION_CACHE && TSC_MAX_SESSIONS == 2 && TSC_MAX_PEERS >= 3
#define TEST_NODES 4
#define main baseline_client_main
#include "test_client.c"
#undef main
#include "blake2s.h"

static uint8_t captured[TSC_WG_INITIATION_SIZE];
static int have_capture;

static int capture_send(void *user, const tsc_endpoint *to, const void *packet, size_t length)
{
    adapter *a = user;
    if (!have_capture && a->index == 1 && to->port == 41000 &&
        length == sizeof(captured) && ((const uint8_t *)packet)[0] == 1) {
        memcpy(captured, packet, length); have_capture = 1;
    }
    return send_packet(user, to, packet, length);
}
static int owns(size_t client, const uint8_t key[32])
{
    for (size_t i = 0; i < TSC_MAX_SESSIONS; ++i)
        if (clients[client].peers[i].active && !memcmp(clients[client].peers[i].public_key, key, 32)) return 1;
    return 0;
}
static void cache_receive(void *user, const void *packet, size_t length)
{
    size_t index = (size_t)(uintptr_t)user;
    tsc_udp_packet_view view;
    CHECK(tsc_packet_udp_decode(packet, length, &view) == TSC_OK);
    CHECK(view.length == sizeof(payload) - 1 && !memcmp(view.payload, payload, view.length));
    ++received[index];
    if (!index) {
        uint8_t reply[TSC_MTU]; size_t n;
        CHECK(tsc_packet_udp_encode(view.dst, view.src, view.dst_port, view.src_port,
            payload, sizeof(payload) - 1, 2, reply, sizeof(reply), &n) == TSC_OK);
        CHECK(tsc_client_send_ip(&clients[0], reply, n) == TSC_OK);
    }
}
static void pump_all(void)
{
    for (unsigned k = 0; k < 20; ++k) {
        for (unsigned i = 0; i < TEST_NODES; ++i) CHECK(tsc_client_poll(&clients[i]) >= 0);
        net.now += 10;
    }
}
static void echo_from(unsigned index)
{
    unsigned before = received[index];
    uint8_t packet[TSC_MTU]; size_t n;
    CHECK(tsc_packet_udp_encode(clients[index].ipv4, clients[0].ipv4,
        (uint16_t)(49000 + index), 32123, payload, sizeof(payload) - 1,
        1, packet, sizeof(packet), &n) == TSC_OK);
    for (unsigned i = 0; i < 100 && received[index] == before; ++i) {
        CHECK(tsc_client_send_ip(&clients[index], packet, n) >= 0);
        pump_all();
    }
    CHECK(received[index] > before);
}
static void unchanged_after_packet(const uint8_t *packet)
{
    uint8_t keys[TSC_MAX_SESSIONS][32], sessions[TSC_MAX_SESSIONS][32];
    for (unsigned i = 0; i < TSC_MAX_SESSIONS; ++i) {
        memcpy(keys[i], clients[0].peers[i].public_key, 32);
        memcpy(sessions[i], clients[0].wg_peers[i].curr_keypair.sending_key, 32);
    }
    CHECK(send_packet(&net.nodes[1], &net.nodes[0].outer, packet, sizeof(captured)) == TSC_OK);
    CHECK(tsc_client_poll(&clients[0]) >= 0);
    for (unsigned i = 0; i < TSC_MAX_SESSIONS; ++i) {
        CHECK(!memcmp(keys[i], clients[0].peers[i].public_key, 32));
        CHECK(!memcmp(sessions[i], clients[0].wg_peers[i].curr_keypair.sending_key, 32));
    }
    CHECK(!clients[0].peers[TSC_MAX_SESSIONS].active);
}
int main(void)
{
    memset(&net, 0, sizeof(net)); net.now = 100000;
    for (unsigned i = 0; i < TEST_NODES; ++i) CHECK(tsc_identity_generate(&identities[i]) == TSC_OK);
    for (unsigned i = 0; i < TEST_NODES; ++i) {
        adapter *a = &net.nodes[i];
        a->network = &net; a->index = i;
        a->outer.family = TSC_AF_IPV4; a->outer.address[0] = 127; a->outer.address[3] = 1;
        a->outer.port = (uint16_t)(41000 + i);
        a->map.has_ipv4 = 1; a->map.ipv4[0] = 100; a->map.ipv4[1] = 64;
        a->map.ipv4[3] = (uint8_t)(i + 1); a->map.generation = 1;
#if TSC_CONTROL_DYNAMIC_PEERS
        a->map.peers = calloc(TEST_NODES, sizeof(*a->map.peers)); CHECK(a->map.peers);
#endif
        for (unsigned j = 0; j < TEST_NODES; ++j) {
            if (j == i || (i && j)) continue;
            tsc_control_peer *p = &a->map.peers[a->map.peer_count++];
            p->id = j + 1; p->has_ipv4 = 1;
            memcpy(p->ipv4, a->map.ipv4, 4); p->ipv4[3] = (uint8_t)(j + 1);
            CHECK(tsc_crypto_x25519_public(p->public_key, identities[j].node_private) == TSC_OK);
            CHECK(tsc_crypto_x25519_public(p->disco_key, identities[j].disco_private) == TSC_OK);
            tsc_endpoint endpoint = a->outer; endpoint.port = (uint16_t)(41000 + j);
            tsc_control_endpoint_store(&p->endpoints[0], &endpoint); p->endpoint_count = 1;
        }
        if (!i) {
            const char policy[] = "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":32123,\"Last\":32123}}],\"IPProto\":[17]}]";
            CHECK(tsc_policy_parse_json(&a->map.policy, (const uint8_t *)policy, strlen(policy)) == TSC_OK);
        }
        initialize_client(i);
        clients[i].platform.udp_send = capture_send;
        CHECK(tsc_client_join(&clients[i]) == TSC_OK);
        tsc_client_set_ip_handler(&clients[i], cache_receive, (void *)(uintptr_t)i);
    }
    CHECK(clients[0].history_count == 3);
    echo_from(1); CHECK(have_capture);
    echo_from(2); echo_from(3);
    uint8_t first_key[32];
    CHECK(tsc_crypto_x25519_public(first_key, identities[1].node_private) == TSC_OK);
    CHECK(!owns(0, first_key));

    /* Replaying a valid old initiation cannot replace either cached session. */
    unchanged_after_packet(captured);
    /* Correct MAC1 and decryptable sender identity, but invalid timestamp AEAD:
     * admission must still leave both authenticated sessions untouched. */
    uint8_t forged[sizeof(captured)]; memcpy(forged, captured, sizeof(forged));
    forged[88] ^= 1;
    CHECK(blake2s(forged + 116, 16, clients[0].wireguard.label_mac1_key, 32, forged, 116) == 0);
    unchanged_after_packet(forged);
    /* Replay protection follows identity, not directory or cache slot order. */
    tsc_control_peer tmp = net.nodes[0].map.peers[0];
    net.nodes[0].map.peers[0] = net.nodes[0].map.peers[2]; net.nodes[0].map.peers[2] = tmp;
    CHECK(tsc_client_refresh_map(&clients[0]) == TSC_OK);
    unchanged_after_packet(captured);
    echo_from(1); CHECK(owns(0, first_key));
    echo_from(2); echo_from(3); echo_from(1);

    /* Removing a node from the coordinator revokes both cached and cold use. */
    uint8_t removed[32]; CHECK(tsc_crypto_x25519_public(removed, identities[3].node_private) == TSC_OK);
    size_t keep = 0;
    for (size_t i = 0; i < net.nodes[0].map.peer_count; ++i)
        if (memcmp(net.nodes[0].map.peers[i].public_key, removed, 32))
            net.nodes[0].map.peers[keep++] = net.nodes[0].map.peers[i];
    net.nodes[0].map.peer_count = keep;
    CHECK(tsc_client_refresh_map(&clients[0]) == TSC_OK);
    CHECK(!owns(0, removed) && clients[0].history_count == 2);
    net.now += 6000;
    size_t server_slot = 0, n;
    while (server_slot < TSC_MAX_SESSIONS && !clients[3].peers[server_slot].active) ++server_slot;
    CHECK(server_slot < TSC_MAX_SESSIONS);
    uint8_t init[TSC_MAX_DATAGRAM_SIZE];
    CHECK(tsc_wg_start(&clients[3].wireguard, server_slot, init, sizeof(init), &n) == TSC_OK);
    CHECK(send_packet(&net.nodes[3], &net.nodes[0].outer, init, n) == TSC_OK);
    CHECK(tsc_client_poll(&clients[0]) >= 0);
    CHECK(!owns(0, removed));
    for (unsigned i = 0; i < TEST_NODES; ++i) {
        tsc_client_close(&clients[i]);
#if TSC_CONTROL_DYNAMIC_PEERS
        free(net.nodes[i].map.peers);
#endif
    }
    puts("generic session cache: three controllers, two slots, eviction/replay/forgery/revocation PASS");
    return 0;
}
#else
int main(void) { return 77; }
#endif
