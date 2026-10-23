#include "tailscalec/client.h"
#include "tailscalec/crypto.h"
#include "tailscalec/packet.h"
#include "check.h"
#include <string.h>

#if TSC_ENABLE_CLIENT && TSC_APP_UDP && TSC_MAX_UDP_PORTS >= 2

#define QUEUE_SIZE 64

typedef struct {
    tsc_endpoint source;
    size_t length;
    uint8_t bytes[TSC_MAX_DATAGRAM_SIZE];
} queued_packet;

typedef struct network network;
typedef struct {
    network *network;
    size_t index, head, count;
    tsc_endpoint outer;
    queued_packet queue[QUEUE_SIZE];
    tsc_control_map map;
    int join_error, poll_error;
    unsigned tx_count;
    uint64_t last_map;
} adapter;

struct network { adapter nodes[2]; uint64_t now; };
static network net;
static tsc_client clients[2];
static tsc_identity identities[2];
static tsc_udp sockets[2], denied, unsolicited;
static unsigned received[2], denied_received;
static const char payload[] = "secret-tailnet-message";

/* A fake coordinator isolates packet routing and connection tracking tests.
 * WireGuard, cryptographic providers, packet parsing and policy are real. */
int tsc_control_join(tsc_control *control, const tsc_control_config *config)
{
    adapter *node = config->platform->user;
    if (node->join_error) return node->join_error;
    control->implementation = node;
    node->last_map = node->network->now;
    return TSC_OK;
}
int tsc_control_poll(tsc_control *control)
{
    adapter *node = control->implementation;
    if (!node) return TSC_ERR_ARGUMENT;
    if (node->poll_error) return node->poll_error;
    node->last_map = node->network->now;
    ++node->map.generation;
    return TSC_OK;
}
int tsc_control_expire(tsc_control *control)
{
    adapter *node = control->implementation;
    size_t i, count = 0;
    if (!node) return TSC_ERR_ARGUMENT;
    if (node->map.has_expiry && node->network->now >= node->map.expires_at_ms)
        return TSC_ERR_PROTOCOL;
    for (i = 0; i < node->map.peer_count; ++i) {
        if (node->map.peers[i].has_expiry &&
            node->network->now >= node->map.peers[i].expires_at_ms) continue;
        node->map.peers[count++] = node->map.peers[i];
    }
    if (count != node->map.peer_count) {
        node->map.peer_count = count;
        ++node->map.generation;
    }
    return TSC_OK;
}
int tsc_control_maintain(tsc_control *control, uint32_t max_age_ms)
{
    adapter *node = control->implementation;
    int rc = tsc_control_expire(control);
    if (rc != TSC_OK) return rc;
    if (node->network->now - node->last_map < max_age_ms) return TSC_OK;
    return tsc_control_poll(control);
}
const tsc_control_map *tsc_control_get_map(const tsc_control *control)
{
    const adapter *node = control->implementation;
    return node ? &node->map : NULL;
}
const char *tsc_control_last_error(const tsc_control *control)
{
    (void)control;
    return "fake coordinator";
}
void tsc_control_close(tsc_control *control) { control->implementation = NULL; }
int tsc_control_set_endpoints(tsc_control *control, const tsc_endpoint *endpoints,
                              size_t count)
{
    (void)control; (void)endpoints; (void)count;
    return TSC_OK;
}

static int send_packet(void *user, const tsc_endpoint *to,
                         const void *packet, size_t length)
{
    adapter *source = user;
    size_t i, offset;
    CHECK(length <= TSC_MAX_DATAGRAM_SIZE);
    for (offset = 0; offset + sizeof(payload) - 1 <= length; ++offset)
        CHECK(memcmp((const uint8_t *)packet + offset, payload,
                       sizeof(payload) - 1) != 0);
    ++source->tx_count;
    for (i = 0; i < 2; ++i) {
        adapter *target = &source->network->nodes[i];
        queued_packet *slot;
        if (!tsc_endpoint_equal(to, &target->outer)) continue;
        CHECK(target->count < QUEUE_SIZE);
        slot = &target->queue[(target->head + target->count) % QUEUE_SIZE];
        slot->source = source->outer;
        slot->length = length;
        memcpy(slot->bytes, packet, length);
        ++target->count;
        return TSC_OK;
    }
    return TSC_AGAIN;
}

static int receive_packet(void *user, tsc_endpoint *from, void *packet,
                            size_t capacity, size_t *length)
{
    adapter *node = user;
    queued_packet *slot;
    *length = 0;
    if (!node->count) return TSC_AGAIN;
    slot = &node->queue[node->head];
    CHECK(slot->length <= capacity);
    *from = slot->source;
    *length = slot->length;
    memcpy(packet, slot->bytes, slot->length);
    node->head = (node->head + 1) % QUEUE_SIZE;
    --node->count;
    return TSC_OK;
}

static uint64_t now_ms(void *user)
{
    adapter *node = user;
    return node->network->now;
}
static int random_bytes(void *user, void *bytes, size_t length)
{
    (void)user;
    return tsc_crypto_random(bytes, length);
}
static int timestamp(void *user, uint8_t bytes[12])
{
    uint64_t seconds = UINT64_C(0x400000006500000a);
    adapter *node = user;
    size_t i;
    seconds += node->network->now / 1000;
    for (i = 0; i < 8; ++i) bytes[7 - i] = (uint8_t)(seconds >> (i * 8));
    memset(bytes + 8, 0, 4);
    return TSC_OK;
}

static void receive_udp(void *user, tsc_udp *socket, const tsc_endpoint *source,
                          const void *data, size_t length)
{
    size_t index = (size_t)(uintptr_t)user;
    CHECK(length == sizeof(payload) - 1);
    CHECK(memcmp(data, payload, length) == 0);
    ++received[index];
    if (index == 1) CHECK(tsc_udp_send(socket, source, data, length) == TSC_OK);
}
static void receive_denied(void *user, tsc_udp *socket, const tsc_endpoint *source,
                             const void *data, size_t length)
{
    (void)user; (void)socket; (void)source; (void)data; (void)length;
    ++denied_received;
}

static void pump(void)
{
    unsigned i;
    for (i = 0; i < 20; ++i) {
        CHECK(tsc_client_poll(&clients[0]) >= 0);
        CHECK(tsc_client_poll(&clients[1]) >= 0);
        net.now += 10;
    }
}

static void initialize_client(size_t index)
{
    adapter *node = &net.nodes[index];
    tsc_client_config config = {0};
    config.control_url = "http://fake.invalid";
    config.hostname = "unit-test";
    config.identity = &identities[index];
    config.platform.user = node;
    config.platform.udp_send = send_packet;
    config.platform.udp_receive = receive_packet;
    config.platform.monotonic_ms = now_ms;
    config.platform.random_bytes = random_bytes;
    config.tai64n_now = timestamp;
    config.clock_user = node;
    CHECK(tsc_client_init(&clients[index], &config) == TSC_OK);
    CHECK(tsc_client_address(&clients[index], &node->outer) == TSC_AGAIN);
}

static void configure(void)
{
    static const uint8_t allow_server[] =
        "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\","
        "\"Ports\":{\"First\":32123,\"Last\":32123}}],\"IPProto\":[17]}]";
    size_t i, other;
    memset(&net, 0, sizeof(net));
    memset(clients, 0, sizeof(clients));
    net.now = 100000;
    for (i = 0; i < 2; ++i) CHECK(tsc_identity_generate(&identities[i]) == TSC_OK);
    for (i = 0; i < 2; ++i) {
        adapter *node = &net.nodes[i];
        tsc_control_peer *peer = &node->map.peers[0];
        node->network = &net;
        node->index = i;
        node->outer.family = TSC_AF_IPV4;
        node->outer.address[0] = 127;
        node->outer.address[3] = 1;
        node->outer.port = (uint16_t)(41000 + i);
        node->map.has_ipv4 = 1;
        node->map.ipv4[0] = 100;
        node->map.ipv4[1] = 64;
        node->map.ipv4[3] = (uint8_t)(i + 1);
        node->map.generation = 1;
        node->map.peer_count = 1;
        other = 1 - i;
        CHECK(tsc_crypto_x25519_public(peer->public_key,
                                        identities[other].node_private) == TSC_OK);
        CHECK(tsc_crypto_x25519_public(peer->disco_key,
                                        identities[other].disco_private) == TSC_OK);
        memcpy(peer->ipv4, node->map.ipv4, 4);
        peer->ipv4[3] = (uint8_t)(other + 1);
        peer->has_ipv4 = 1;
        peer->endpoint_count = 1;
        peer->endpoints[0] = node->outer;
        peer->endpoints[0].port = (uint16_t)(41000 + other);
        if (i == 1)
            CHECK(tsc_policy_parse_json(&node->map.policy, allow_server,
                                          sizeof(allow_server) - 1) == TSC_OK);
        initialize_client(i);
    }
}

static void send_raw_from_server(const uint8_t src[4], uint16_t source_port,
                                   uint16_t destination_port, int corrupt)
{
    uint8_t inner[TSC_MTU], encrypted[TSC_MAX_DATAGRAM_SIZE];
    size_t length, encrypted_length;
    CHECK(tsc_packet_udp_encode(src, clients[0].ipv4, source_port,
            destination_port, payload, sizeof(payload) - 1, 42,
            inner, sizeof(inner), &length) == TSC_OK);
    if (corrupt) inner[length - 1] ^= 1;
    CHECK(tsc_wg_encrypt(&clients[1].wireguard, 0, inner, length,
                           encrypted, sizeof(encrypted), &encrypted_length) == TSC_OK);
    CHECK(send_packet(&net.nodes[1], &net.nodes[0].outer, encrypted,
                         encrypted_length) == TSC_OK);
}

int main(void)
{
    tsc_endpoint destination = { .family = TSC_AF_IPV4, .port = 32123 };
    tsc_udp extras[TSC_MAX_UDP_PORTS] = {{0}};
    unsigned attempt;
    size_t i;
    int rc = TSC_AGAIN;
    configure();
    CHECK(tsc_udp_open(&clients[0], &sockets[0], 0, receive_udp, (void *)(uintptr_t)0) == TSC_OK);
    CHECK(sockets[0].port >= 49152);
    CHECK(tsc_udp_open(&clients[1], &sockets[1], 32123, receive_udp, (void *)(uintptr_t)1) == TSC_OK);
    CHECK(tsc_udp_open(&clients[1], &denied, 32124, receive_denied, NULL) == TSC_OK);
    CHECK(tsc_udp_open(&clients[0], &unsolicited, 32125, receive_denied, NULL) == TSC_OK);
    memcpy(destination.address, net.nodes[1].map.ipv4, 4);
    CHECK(tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1) == TSC_AGAIN);
    CHECK(net.nodes[0].tx_count == 0);
    net.nodes[0].join_error = TSC_ERR_PROTOCOL;
    CHECK(tsc_client_join(&clients[0]) == TSC_ERR_PROTOCOL);
    CHECK(tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1) == TSC_AGAIN);
    CHECK(net.nodes[0].tx_count == 0);
    net.nodes[0].join_error = 0;
    CHECK(tsc_client_join(&clients[0]) == TSC_OK);
    CHECK(tsc_client_join(&clients[1]) == TSC_OK);
    for (attempt = 0; attempt < 30; ++attempt) {
        rc = tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1);
        CHECK(rc >= 0);
        pump();
        if (received[0]) break;
    }
    CHECK(rc == TSC_OK);
    CHECK(received[0] == 1 && received[1] == 1);
    {
        uint8_t old_sending_key[32];
        unsigned count = received[0];
        memcpy(old_sending_key, clients[0].wg_peers[0].curr_keypair.sending_key, 32);
        /* The remote retains its established session; the restarted listener
         * discards ephemeral session keys while keeping only persisted keys.
         * Neither listener application nor the remote application sends data
         * during recovery: polling alone must replace the stale session. */
        tsc_client_close(&clients[1]);
        net.now += 1000;
        initialize_client(1);
        CHECK(tsc_client_join(&clients[1]) == TSC_OK);
        CHECK(tsc_udp_open(&clients[1], &sockets[1], 32123, receive_udp,
                             (void *)(uintptr_t)1) == TSC_OK);
        CHECK(tsc_udp_open(&clients[1], &denied, 32124,
                             receive_denied, NULL) == TSC_OK);
        for (attempt = 0; attempt < 30; ++attempt) {
            pump();
            if (tsc_wg_peer_established(&clients[1].wireguard, 0)) break;
        }
        CHECK(tsc_wg_peer_established(&clients[0].wireguard, 0));
        CHECK(tsc_wg_peer_established(&clients[1].wireguard, 0));
        CHECK(memcmp(old_sending_key,
                       clients[0].wg_peers[0].curr_keypair.sending_key, 32) != 0);
        CHECK(received[0] == count && received[1] == count);
        CHECK(tsc_udp_send(&sockets[0], &destination, payload,
                             sizeof(payload) - 1) == TSC_OK);
        pump();
        CHECK(received[0] == count + 1 && received[1] == count + 1);
    }
    /* Plain payload is absent from every underlying datagram still buffered. */
    for (i = 0; i < 2; ++i) {
        size_t q, offset;
        for (q = 0; q < net.nodes[i].count; ++q) {
            const queued_packet *packet = &net.nodes[i].queue[(net.nodes[i].head + q) % QUEUE_SIZE];
            for (offset = 0; offset + sizeof(payload) - 1 <= packet->length; ++offset)
                CHECK(memcmp(packet->bytes + offset, payload, sizeof(payload) - 1) != 0);
        }
    }
    /* A suspended application can resume after its session keys expire;
     * the next send initiates rekeying rather than returning a fatal error. */
    net.now += 180001;
    CHECK(tsc_udp_send(&sockets[0], &destination, payload,
                         sizeof(payload) - 1) == TSC_AGAIN);
    for (attempt = 0; attempt < 30; ++attempt) {
        pump();
        rc = tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1);
        CHECK(rc >= 0);
        pump();
        if (received[0] == 3) break;
    }
    CHECK(received[0] == 3 && received[1] == 3);
    destination.port = 32124;
    CHECK(tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1) == TSC_OK);
    pump();
    CHECK(denied_received == 0);
    /* An authenticated peer cannot impersonate another inner source. */
    {
        uint8_t fake_source[4] = {100,64,0,99};
        send_raw_from_server(fake_source, 32123, sockets[0].port, 0);
        send_raw_from_server(clients[1].ipv4, 32123, sockets[0].port, 1);
        send_raw_from_server(clients[1].ipv4, 32123, unsolicited.port, 0);
        pump();
        CHECK(received[0] == 3 && denied_received == 0);
    }
    /* Revoking a policy drops old reverse-flow exceptions. */
    net.nodes[0].map.policy.rule_count = 1;
    CHECK(tsc_client_refresh_map(&clients[0]) == TSC_OK);
    send_raw_from_server(clients[1].ipv4, 32123, sockets[0].port, 0);
    pump();
    CHECK(received[0] == 3);
    net.nodes[0].poll_error = TSC_ERR_PROTOCOL;
    CHECK(tsc_client_refresh_map(&clients[0]) == TSC_ERR_PROTOCOL);
    CHECK(tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1) == TSC_AGAIN);
    net.nodes[0].poll_error = 0;
    CHECK(tsc_client_refresh_map(&clients[0]) == TSC_OK);
    /* Fixed port limits, duplicate binding, close and reuse. */
    CHECK(tsc_udp_open(&clients[0], &extras[0], sockets[0].port, NULL, NULL) == TSC_ERR_ARGUMENT);
    for (i = 2; i < TSC_MAX_UDP_PORTS; ++i)
        CHECK(tsc_udp_open(&clients[0], &extras[i - 2], 0, NULL, NULL) == TSC_OK);
    CHECK(tsc_udp_open(&clients[0], &extras[TSC_MAX_UDP_PORTS - 1], 0, NULL, NULL) == TSC_ERR_SPACE);
    tsc_udp_close(&unsolicited);
    CHECK(!unsolicited.client);
    CHECK(tsc_udp_open(&clients[0], &unsolicited, 32125, NULL, NULL) == TSC_OK);
    /* Maintenance does no network work before max age, then refreshes. */
    {
        uint64_t generation = clients[0].map_generation;
        CHECK(tsc_client_maintain(&clients[0], 5000) == TSC_OK);
        CHECK(clients[0].map_generation == generation);
        net.now += 5000;
        CHECK(tsc_client_maintain(&clients[0], 5000) == TSC_OK);
        CHECK(clients[0].map_generation != generation);
    }
    /* Peer expiry is enforced by a send, even with no control refresh. */
    net.nodes[0].map.peers[0].has_expiry = 1;
    net.nodes[0].map.peers[0].expires_at_ms = net.now + 10;
    CHECK(tsc_client_refresh_map(&clients[0]) == TSC_OK);
    CHECK(clients[0].wg_peers[0].valid);
    net.now += 10;
    CHECK(tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1) == TSC_AGAIN);
    CHECK(!clients[0].wg_peers[0].valid && !clients[0].peers[0].active);
    /* Own expiry disables and erases session state from the nonblocking loop. */
    net.nodes[0].map.has_expiry = 1;
    net.nodes[0].map.expires_at_ms = net.now + 10;
    CHECK(tsc_client_refresh_map(&clients[0]) == TSC_OK);
    net.now += 10;
    CHECK(tsc_client_poll(&clients[0]) == TSC_ERR_PROTOCOL);
    CHECK(!clients[0].allow_traffic);
    CHECK(tsc_udp_send(&sockets[0], &destination, payload, sizeof(payload) - 1) == TSC_AGAIN);
    tsc_client_close(&clients[0]);
    tsc_client_close(&clients[1]);
    CHECK(!sockets[0].client && !sockets[1].client && !unsolicited.client && !denied.client);
    for (i = 0; i < sizeof(clients); ++i) CHECK(((const uint8_t *)clients)[i] == 0);
    puts("client tests passed");
    return 0;
}
#else
int main(void) { return 77; }
#endif
