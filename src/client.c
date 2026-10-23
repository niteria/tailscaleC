#include "tailscalec/client.h"

#if TSC_ENABLE_CLIENT
#include "tailscalec/crypto.h"
#include "tailscalec/packet.h"
#include <string.h>

#define TSC_CLIENT_RECEIVE_BUDGET 16u

static int nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0;
    size_t i;
    for (i = 0; i < length; ++i) any |= bytes[i];
    return any != 0;
}

static int valid_endpoint(const tsc_endpoint *endpoint)
{
    if (!endpoint || !endpoint->port) return 0;
    if (endpoint->family == TSC_AF_IPV4)
        return nonzero(endpoint->address, 4) && endpoint->address[0] < 224;
#if TSC_ENABLE_IPV6
    if (endpoint->family == TSC_AF_IPV6)
        return nonzero(endpoint->address, 16) && endpoint->address[0] != 0xff;
#endif
    return 0;
}

int tsc_identity_generate(tsc_identity *identity)
{
    int rc;
    if (!identity) return TSC_ERR_ARGUMENT;
    rc = tsc_crypto_random(identity, sizeof(*identity));
    if (rc != TSC_OK) tsc_crypto_zero(identity, sizeof(*identity));
    return rc;
}

static int wg_random(void *user, void *buffer, size_t length)
{
    tsc_client *client = user;
    return client->platform.random_bytes(client->platform.user, buffer, length);
}

static uint64_t wg_now(void *user)
{
    tsc_client *client = user;
    return client->platform.monotonic_ms(client->platform.user);
}

static int wg_timestamp(void *user, uint8_t timestamp[12])
{
    tsc_client *client = user;
    return client->tai64n_now(client->clock_user, timestamp);
}

static size_t peer_by_key(const tsc_client *client, const uint8_t key[32])
{
    size_t i;
    for (i = 0; i < TSC_MAX_PEERS; ++i)
        if (client->peers[i].active &&
            memcmp(client->peers[i].public_key, key, 32) == 0) return i;
    return TSC_MAX_PEERS;
}

int tsc_client_set_peer_endpoint(tsc_client *client, const uint8_t node_key[32],
                                  const tsc_endpoint *endpoint)
{
    size_t i;
    if (!client || !client->initialized || !node_key || !valid_endpoint(endpoint))
        return TSC_ERR_ARGUMENT;
    i = peer_by_key(client, node_key);
    if (i == TSC_MAX_PEERS) return TSC_ERR_ARGUMENT;
    client->peers[i].endpoint = *endpoint;
    client->peers[i].has_endpoint = 1;
    client->peers[i].endpoint_millis = wg_now(client);
    if (!client->wg_peers[i].active) client->peers[i].initiate_pending = 1;
    return TSC_OK;
}

#if TSC_ENABLE_DISCO
static void disco_path(void *user, const uint8_t key[32],
                        const tsc_endpoint *endpoint, uint32_t rtt)
{
    (void)rtt;
    (void)tsc_client_set_peer_endpoint(user, key, endpoint);
}

static int disco_relay(void *user, const uint8_t key[32],
                         const void *packet, size_t length)
{
    tsc_client *client = user;
    if (!client->relay_send) return TSC_AGAIN;
    return client->relay_send(client->relay_user, key, packet, length);
}
#endif

int tsc_client_init(tsc_client *client, const tsc_client_config *config)
{
    tsc_wg_hooks hooks;
    int rc;
    if (!client || !config || !config->identity || !config->control_url ||
        !config->hostname || !config->platform.udp_send ||
        !config->platform.udp_receive || !config->platform.monotonic_ms ||
        !config->platform.random_bytes || !config->tai64n_now ||
        config->endpoint_count > TSC_CONTROL_MAX_ENDPOINTS ||
        (!config->endpoints && config->endpoint_count) ||
        !nonzero(config->identity->machine_private, 32) ||
        !nonzero(config->identity->node_private, 32) ||
        !nonzero(config->identity->disco_private, 32) || client->initialized)
        return TSC_ERR_ARGUMENT;
    memset(client, 0, sizeof(*client));
    client->identity = *config->identity;
    client->platform = config->platform;
    client->tai64n_now = config->tai64n_now;
    client->clock_user = config->clock_user;
    client->relay_send = config->relay_send;
    client->relay_user = config->relay_user;
    client->next_port = 49152;
    client->endpoint_count = config->endpoint_count;
    if (config->endpoint_count)
        memcpy(client->endpoints, config->endpoints,
                 config->endpoint_count * sizeof(*config->endpoints));
    client->control_config.url = config->control_url;
    client->control_config.auth_key = config->auth_key;
    if (config->server_public_key) {
        memcpy(client->server_public_key, config->server_public_key, 32);
        client->control_config.server_public_key = client->server_public_key;
    }
    client->control_config.hostname = config->hostname;
    client->control_config.ca_pem = config->ca_pem;
    client->control_config.ca_pem_length = config->ca_pem_length;
    client->control_config.timeout_ms = config->control_timeout_ms;
    client->control_config.platform = &client->platform;
    client->control_config.endpoints = client->endpoints;
    client->control_config.endpoint_count = client->endpoint_count;
    client->control_config.preferred_derp = config->preferred_derp;
    memcpy(client->control_config.machine_private_key,
             client->identity.machine_private, 32);
    memcpy(client->control_config.node_private_key,
             client->identity.node_private, 32);
    rc = tsc_crypto_x25519_public(client->control_config.disco_public_key,
                                   client->identity.disco_private);
    if (rc != TSC_OK) goto fail;
    hooks.user = client;
    hooks.random_bytes = wg_random;
    hooks.monotonic_ms = wg_now;
    hooks.tai64n_now = wg_timestamp;
    rc = tsc_wg_init(&client->wireguard, client->wg_peers, TSC_MAX_PEERS,
                      client->identity.node_private, &hooks);
    if (rc != TSC_OK) goto fail;
#if TSC_ENABLE_DISCO
    {
        tsc_disco_callbacks callbacks = {0};
        callbacks.user = client;
        callbacks.path_changed = disco_path;
        callbacks.relay_send = disco_relay;
        rc = tsc_disco_init(&client->disco, &client->platform, &callbacks,
                             client->identity.disco_private,
                             client->wireguard.public_key);
        if (rc != TSC_OK) goto fail;
    }
#endif
    client->initialized = 1;
    return TSC_OK;
fail:
    tsc_crypto_zero(client, sizeof(*client));
    return rc;
}

static void forget_peer_flows(tsc_client *client, const uint8_t address[4])
{
    size_t i;
    for (i = 0; i < TSC_MAX_FLOWS; ++i)
        if (client->flows[i].active &&
            memcmp(client->flows[i].remote, address, 4) == 0)
            memset(&client->flows[i], 0, sizeof(client->flows[i]));
}

static int install_map(tsc_client *client)
{
    const tsc_control_map *map = tsc_control_get_map(&client->control);
    unsigned retained[TSC_MAX_PEERS] = {0};
    uint8_t policy_digest[32];
    size_t i, j, slot;
    int rc;
    client->allow_traffic = 0;
    if (!map || !map->has_ipv4 || !nonzero(map->ipv4, 4) ||
        map->peer_count > TSC_MAX_PEERS) return TSC_ERR_PROTOCOL;
    rc = tsc_crypto_sha256(&map->policy, sizeof(map->policy), policy_digest);
    if (rc != TSC_OK) return rc;
    /* Validate the complete map before changing any sessions. */
    for (i = 0; i < map->peer_count; ++i) {
        const tsc_control_peer *peer = &map->peers[i];
        if (!nonzero(peer->public_key, 32) ||
            peer->endpoint_count > TSC_CONTROL_MAX_ENDPOINTS ||
            memcmp(peer->public_key, client->wireguard.public_key, 32) == 0 ||
            (peer->has_ipv4 && memcmp(peer->ipv4, map->ipv4, 4) == 0))
            return TSC_ERR_PROTOCOL;
        for (j = 0; j < i; ++j)
            if (memcmp(peer->public_key, map->peers[j].public_key, 32) == 0 ||
                (peer->has_ipv4 && map->peers[j].has_ipv4 &&
                 memcmp(peer->ipv4, map->peers[j].ipv4, 4) == 0))
                return TSC_ERR_PROTOCOL;
    }
    /* Remove absent keys first, so a full map can replace all peers. */
    for (i = 0; i < TSC_MAX_PEERS; ++i) {
        if (!client->peers[i].active) continue;
        for (j = 0; j < map->peer_count; ++j)
            if (memcmp(client->peers[i].public_key,
                         map->peers[j].public_key, 32) == 0) break;
        if (j == map->peer_count) {
            forget_peer_flows(client, client->peers[i].ipv4);
#if TSC_ENABLE_DISCO
            (void)tsc_disco_remove_peer(&client->disco,
                                        client->peers[i].public_key);
#endif
            (void)tsc_wg_peer_remove(&client->wireguard, i);
            memset(&client->peers[i], 0, sizeof(client->peers[i]));
        }
    }
    for (i = 0; i < map->peer_count; ++i) {
        const tsc_control_peer *peer = &map->peers[i];
        slot = peer_by_key(client, peer->public_key);
        if (slot == TSC_MAX_PEERS)
            for (slot = 0; slot < TSC_MAX_PEERS; ++slot)
                if (!client->peers[slot].active && !retained[slot]) break;
        if (slot == TSC_MAX_PEERS) return TSC_ERR_SPACE;
        rc = tsc_wg_peer_set(&client->wireguard, slot, peer->public_key, NULL);
        if (rc != TSC_OK) return rc;
        if (!client->peers[slot].active || !client->wg_peers[slot].active)
            client->peers[slot].initiate_pending = 1;
        if (client->peers[slot].active &&
            memcmp(client->peers[slot].ipv4, peer->ipv4, 4) != 0)
            forget_peer_flows(client, client->peers[slot].ipv4);
        client->peers[slot].active = 1;
        client->peers[slot].has_ipv4 = peer->has_ipv4;
        memcpy(client->peers[slot].public_key, peer->public_key, 32);
        memcpy(client->peers[slot].ipv4, peer->ipv4, 4);
        client->peers[slot].candidate_count = 0;
        for (j = 0; j < peer->endpoint_count; ++j)
            if (valid_endpoint(&peer->endpoints[j]))
                client->peers[slot].candidates[
                    client->peers[slot].candidate_count++] = peer->endpoints[j];
        retained[slot] = 1;
#if TSC_ENABLE_DISCO
        if (nonzero(peer->disco_key, 32)) {
            size_t count = client->peers[slot].candidate_count;
            if (count > TSC_MAX_PEER_ENDPOINTS) count = TSC_MAX_PEER_ENDPOINTS;
            rc = tsc_disco_set_peer(&client->disco, peer->public_key,
                                     peer->disco_key,
                                     client->peers[slot].candidates, count);
            if (rc != TSC_OK) return rc;
        } else {
            (void)tsc_disco_remove_peer(&client->disco, peer->public_key);
        }
#endif
    }
    if (memcmp(client->policy_digest, policy_digest, 32) != 0 ||
        memcmp(client->ipv4, map->ipv4, 4) != 0) {
        memset(client->flows, 0, sizeof(client->flows));
        memcpy(client->policy_digest, policy_digest, 32);
    }
    memcpy(client->ipv4, map->ipv4, 4);
    client->map_generation = map->generation;
    client->joined = 1;
    client->allow_traffic = 1;
    return TSC_OK;
}

static void invalidate_dataplane(tsc_client *client)
{
    size_t i;
    client->allow_traffic = 0;
    for (i = 0; i < TSC_MAX_PEERS; ++i) {
#if TSC_ENABLE_DISCO
        if (client->peers[i].active)
            (void)tsc_disco_remove_peer(&client->disco,
                                        client->peers[i].public_key);
#endif
        (void)tsc_wg_peer_remove(&client->wireguard, i);
    }
    memset(client->peers, 0, sizeof(client->peers));
    memset(client->flows, 0, sizeof(client->flows));
}

static int current_map(tsc_client *client)
{
    const tsc_control_map *map;
    int rc;
    if (!client->joined || !client->allow_traffic) return TSC_AGAIN;
    rc = tsc_control_expire(&client->control);
    if (rc != TSC_OK) {
        invalidate_dataplane(client);
        return rc;
    }
    map = tsc_control_get_map(&client->control);
    if (!map) {
        invalidate_dataplane(client);
        return TSC_ERR_PROTOCOL;
    }
    if (map->generation != client->map_generation) {
        rc = install_map(client);
        if (rc != TSC_OK) invalidate_dataplane(client);
        return rc;
    }
    return TSC_OK;
}

int tsc_client_join(tsc_client *client)
{
    int rc;
    if (!client || !client->initialized) return TSC_ERR_ARGUMENT;
    client->allow_traffic = 0;
    client->joined = 0;
    if (client->control.implementation) tsc_control_close(&client->control);
    rc = tsc_control_join(&client->control, &client->control_config);
    if (rc != TSC_OK) return rc;
    return install_map(client);
}

int tsc_client_refresh_map(tsc_client *client)
{
    int rc;
    if (!client || !client->initialized || !client->joined)
        return TSC_ERR_ARGUMENT;
    client->allow_traffic = 0;
    rc = tsc_control_poll(&client->control);
    if (rc != TSC_OK) {
        invalidate_dataplane(client);
        return rc;
    }
    return install_map(client);
}

int tsc_client_maintain(tsc_client *client, uint32_t max_age_ms)
{
    int rc;
    if (!client || !client->initialized || !client->joined || !max_age_ms)
        return TSC_ERR_ARGUMENT;
    rc = tsc_control_maintain(&client->control, max_age_ms);
    if (rc != TSC_OK) {
        invalidate_dataplane(client);
        return rc;
    }
    if (!client->allow_traffic) return install_map(client);
    return current_map(client);
}

int tsc_client_set_endpoints(tsc_client *client, const tsc_endpoint *endpoints,
                              size_t count)
{
    size_t i;
    int rc;
    if (!client || !client->initialized || count > TSC_CONTROL_MAX_ENDPOINTS ||
        (!endpoints && count)) return TSC_ERR_ARGUMENT;
    for (i = 0; i < count; ++i)
        if (!valid_endpoint(&endpoints[i])) return TSC_ERR_ARGUMENT;
    if (client->control.implementation) {
        rc = tsc_control_set_endpoints(&client->control, endpoints, count);
        if (rc != TSC_OK) return rc;
    }
    if (count) memmove(client->endpoints, endpoints, count * sizeof(*endpoints));
    client->endpoint_count = count;
    client->control_config.endpoint_count = count;
    return TSC_OK;
}

void tsc_client_close(tsc_client *client)
{
    if (!client) return;
    if (client->initialized) {
#if TSC_APP_UDP
        size_t i;
        for (i = 0; i < TSC_MAX_UDP_PORTS; ++i)
            if (client->udp_ports[i])
                memset(client->udp_ports[i], 0, sizeof(*client->udp_ports[i]));
#endif
        tsc_control_close(&client->control);
#if TSC_ENABLE_DISCO
        tsc_disco_clear(&client->disco);
#endif
        tsc_wg_destroy(&client->wireguard);
    }
    tsc_crypto_zero(client, sizeof(*client));
}

int tsc_client_address(const tsc_client *client, tsc_endpoint *address)
{
    if (!client || !address || !client->initialized) return TSC_ERR_ARGUMENT;
    if (!client->joined) return TSC_AGAIN;
    memset(address, 0, sizeof(*address));
    address->family = TSC_AF_IPV4;
    memcpy(address->address, client->ipv4, 4);
    return TSC_OK;
}

const char *tsc_client_last_error(const tsc_client *client)
{
    return client ? tsc_control_last_error(&client->control) : "invalid client";
}

static int transmit(tsc_client *client, size_t peer_index,
                      const void *packet, size_t length)
{
    tsc_client_peer *peer = &client->peers[peer_index];
    size_t i;
    int success = 0, rc, last = TSC_AGAIN;
    rc = current_map(client);
    if (rc != TSC_OK) return rc;
    if (!peer->active) return TSC_AGAIN;
#if TSC_ENABLE_DISCO
    {
        tsc_endpoint endpoint;
        if (tsc_disco_endpoint(&client->disco, peer->public_key, &endpoint) == TSC_OK) {
            peer->endpoint = endpoint;
            peer->has_endpoint = 1;
            peer->endpoint_millis = wg_now(client);
        }
    }
#endif
    if (peer->has_endpoint && wg_now(client) - peer->endpoint_millis > 30000u)
        peer->has_endpoint = 0;
    if (peer->has_endpoint) {
        rc = client->platform.udp_send(client->platform.user, &peer->endpoint,
                                        packet, length);
        if (rc == TSC_OK) return rc;
        last = rc;
        peer->has_endpoint = 0;
    }
    for (i = 0; i < peer->candidate_count; ++i) {
        rc = client->platform.udp_send(client->platform.user,
                                        &peer->candidates[i], packet, length);
        if (rc == TSC_OK) success = 1;
        else last = rc;
    }
    if (client->relay_send) {
        rc = client->relay_send(client->relay_user, peer->public_key,
                                 packet, length);
        if (rc == TSC_OK) success = 1;
        else last = rc;
    }
    return success ? TSC_OK : last;
}

/* Checks the IPv4 envelope before source routing or calling an optional stack.
 * Fragments cannot safely be checked against transport policies, so reject. */
static int ipv4_envelope(const uint8_t *packet, size_t length, size_t *actual)
{
    size_t header, total, i;
    uint32_t sum = 0;
    if (!packet || length < 20 || packet[0] >> 4 != 4) return TSC_ERR_PROTOCOL;
    header = (packet[0] & 15u) * 4u;
    total = ((size_t)packet[2] << 8) | packet[3];
    if (header < 20 || header > length || total < header || total > length ||
        total > TSC_MTU || (packet[6] & 0xbfu) || packet[7])
        return TSC_ERR_PROTOCOL;
    for (i = 0; i < header; i += 2)
        sum += ((uint32_t)packet[i] << 8) | packet[i + 1];
    while (sum >> 16) sum = (sum & 65535u) + (sum >> 16);
    if (sum != 65535u) return TSC_ERR_PROTOCOL;
    *actual = total;
    return TSC_OK;
}

static int transport_valid(const uint8_t *packet, size_t length)
{
    size_t header = (packet[0] & 15u) * 4u;
    const uint8_t *transport = packet + header;
    size_t count = length - header, i;
    uint32_t sum = 0;
    if (packet[9] == 17) {
        if (count < 8u || (((size_t)transport[4] << 8) | transport[5]) != count)
            return 0;
        if (!transport[6] && !transport[7]) return 1; /* IPv4 optional checksum. */
    } else if (packet[9] == 6) {
        if (count < 20u || (transport[12] >> 4) < 5u ||
            (size_t)(transport[12] >> 4) * 4u > count) return 0;
    } else if (packet[9] == 132) {
        /* SCTP requires its own CRC32c validation and association state; no
         * SCTP backend is included. Do not interpret it as a portless IP flow. */
        return 0;
    } else if (packet[9] != 1) return 1;
    if (packet[9] == 1) {
        if (count < 4u) return 0;
    } else {
        for (i = 12; i < 20; i += 2)
            sum += ((uint32_t)packet[i] << 8) | packet[i + 1];
        sum += packet[9] + (uint32_t)count;
    }
    for (i = 0; i + 1 < count; i += 2)
        sum += ((uint32_t)transport[i] << 8) | transport[i + 1];
    if (i < count) sum += (uint32_t)transport[i] << 8;
    while (sum >> 16) sum = (sum & 65535u) + (sum >> 16);
    return sum == 65535u;
}

/* Remember only application-initiated transport tuples. This permits replies
 * under directional ACLs without granting a remote peer a listening port.
 * Policy updates and UDP close revoke the corresponding exceptions. */
static void remember_flow(tsc_client *client, const uint8_t *packet, size_t length)
{
    size_t header = (packet[0] & 15u) * 4u, i, replace = 0;
    uint64_t now = wg_now(client), earliest = UINT64_MAX;
    uint16_t local, remote;
    if ((packet[9] != 6 && packet[9] != 17) || length < header + 4u) return;
    local = (uint16_t)(((uint16_t)packet[header] << 8) | packet[header + 1]);
    remote = (uint16_t)(((uint16_t)packet[header + 2] << 8) | packet[header + 3]);
    for (i = 0; i < TSC_MAX_FLOWS; ++i) {
        tsc_client_flow *flow = &client->flows[i];
        if (flow->active && flow->protocol == packet[9] &&
            flow->local_port == local && flow->remote_port == remote &&
            memcmp(flow->remote, packet + 16, 4) == 0) { replace = i; break; }
        if (!flow->active || flow->expires_ms <= now) { replace = i; earliest = 0; }
        else if (flow->expires_ms < earliest) { replace = i; earliest = flow->expires_ms; }
    }
    client->flows[replace].active = 1;
    client->flows[replace].protocol = packet[9];
    client->flows[replace].local_port = local;
    client->flows[replace].remote_port = remote;
    memcpy(client->flows[replace].remote, packet + 16, 4);
    client->flows[replace].expires_ms = now + (packet[9] == 6 ? 120000u : 30000u);
}

static int reply_flow(tsc_client *client, const uint8_t *packet, size_t length)
{
    size_t header = (packet[0] & 15u) * 4u, i;
    uint16_t local, remote;
    uint64_t now = wg_now(client);
    if ((packet[9] != 6 && packet[9] != 17) || length < header + 4u) return 0;
    /* A reverse TCP opening SYN must acknowledge our prior initiation. */
    if (packet[9] == 6 && (length < header + 20u ||
        ((packet[header + 13] & 2u) && !(packet[header + 13] & 16u)))) return 0;
    remote = (uint16_t)(((uint16_t)packet[header] << 8) | packet[header + 1]);
    local = (uint16_t)(((uint16_t)packet[header + 2] << 8) | packet[header + 3]);
    for (i = 0; i < TSC_MAX_FLOWS; ++i) {
        tsc_client_flow *flow = &client->flows[i];
        if (flow->active && flow->expires_ms > now &&
            flow->protocol == packet[9] && flow->local_port == local &&
            flow->remote_port == remote &&
            memcmp(flow->remote, packet + 12, 4) == 0) {
            flow->expires_ms = now + (packet[9] == 6 ? 120000u : 30000u);
            return 1;
        }
    }
    return 0;
}

static int deliver(tsc_client *client, size_t peer_index,
                     const uint8_t *packet, size_t length)
{
    size_t actual;
    int rc = ipv4_envelope(packet, length, &actual);
    const tsc_control_map *map;
    if (rc != TSC_OK) return rc;
    if (!transport_valid(packet, actual)) return TSC_ERR_PROTOCOL;
    if (!client->peers[peer_index].has_ipv4 ||
        memcmp(packet + 12, client->peers[peer_index].ipv4, 4) != 0 ||
        memcmp(packet + 16, client->ipv4, 4) != 0) return TSC_ERR_PROTOCOL;
    map = tsc_control_get_map(&client->control);
    if (!map) return TSC_AGAIN;
    {
        size_t header = (packet[0] & 15u) * 4u;
        uint16_t port = 0;
        if (packet[9] == 6 || packet[9] == 17) {
            if (actual < header + 4u) return TSC_ERR_PROTOCOL;
            port = (uint16_t)(((uint16_t)packet[header + 2] << 8) |
                              packet[header + 3]);
        }
        if (!tsc_policy_allows(&map->policy, 4, packet + 12, packet + 16,
                                packet[9], port) &&
            !reply_flow(client, packet, actual)) return TSC_AGAIN;
    }
#if TSC_APP_UDP
    if (packet[9] == 17) {
        tsc_udp_packet_view view;
        size_t i;
        rc = tsc_packet_udp_decode(packet, actual, &view);
        if (rc != TSC_OK) return rc;
        for (i = 0; i < TSC_MAX_UDP_PORTS; ++i) {
            tsc_udp *socket = client->udp_ports[i];
            if (socket && socket->port == view.dst_port) {
                if (socket->receive) {
                    tsc_endpoint from = {0};
                    from.family = TSC_AF_IPV4;
                    from.port = view.src_port;
                    memcpy(from.address, view.src, 4);
                    socket->receive(socket->user, socket, &from,
                                      view.payload, view.length);
                }
                return TSC_OK;
            }
        }
    }
#endif
    if (client->ip_receive) client->ip_receive(client->ip_user, packet, actual);
    return TSC_OK;
}

static int receive_wireguard(tsc_client *client, const tsc_endpoint *source,
                               const uint8_t *relay_key,
                               const void *packet, size_t length)
{
    tsc_wg_event event;
    int rc = current_map(client);
    if (rc != TSC_OK) return rc;
    rc = tsc_wg_receive(&client->wireguard, packet, length,
                            client->inner_buffer, sizeof(client->inner_buffer),
                            &event);
    if (rc != TSC_OK) return rc;
    if (event.authenticated) {
        if (event.peer_index >= TSC_MAX_PEERS ||
            !client->peers[event.peer_index].active ||
            (relay_key && memcmp(relay_key,
                client->peers[event.peer_index].public_key, 32) != 0))
            return TSC_ERR_PROTOCOL;
        client->peers[event.peer_index].initiate_pending = 0;
        if (source && valid_endpoint(source)) {
            client->peers[event.peer_index].endpoint = *source;
            client->peers[event.peer_index].has_endpoint = 1;
            client->peers[event.peer_index].endpoint_millis = wg_now(client);
        }
    }
    if (event.kind == TSC_WG_EVENT_TX) {
        if (source)
            return client->platform.udp_send(client->platform.user, source,
                                              client->inner_buffer,event.length);
        if (relay_key && client->relay_send)
            return client->relay_send(client->relay_user, relay_key,
                                       client->inner_buffer, event.length);
        return TSC_AGAIN;
    }
    if (event.kind == TSC_WG_EVENT_RX)
        return deliver(client, event.peer_index, client->inner_buffer,
                         event.length);
    return TSC_OK;
}

int tsc_client_receive_relay(tsc_client *client, const uint8_t node_key[32],
                              const void *packet, size_t length)
{
    int rc;
    if (!client || !client->initialized || !node_key || (!packet && length) ||
        length > TSC_MAX_DATAGRAM_SIZE) return TSC_ERR_ARGUMENT;
    rc = current_map(client);
    if (rc != TSC_OK) return rc;
    if (peer_by_key(client, node_key) == TSC_MAX_PEERS) return TSC_ERR_PROTOCOL;
#if TSC_ENABLE_DISCO
    if (tsc_disco_is_packet(packet, length))
        return tsc_disco_receive_relay(&client->disco, node_key, packet, length);
#endif
    return receive_wireguard(client, NULL, node_key, packet, length);
}

int tsc_client_poll(tsc_client *client)
{
    size_t i, length;
    unsigned budget;
    tsc_endpoint source;
    int rc, activity = 0;
    if (!client || !client->initialized) return TSC_ERR_ARGUMENT;
    rc = current_map(client);
    if (rc != TSC_OK) return rc;
    for (budget = 0; budget < TSC_CLIENT_RECEIVE_BUDGET; ++budget) {
        rc = client->platform.udp_receive(client->platform.user, &source,
                  client->receive_buffer, sizeof(client->receive_buffer),&length);
        if (rc == TSC_AGAIN) break;
        if (rc == TSC_ERR_TRUNCATED) continue;
        if (rc != TSC_OK) return rc;
        rc = current_map(client);
        if (rc != TSC_OK) return rc;
        activity = 1;
#if TSC_ENABLE_DISCO
        if (tsc_disco_is_packet(client->receive_buffer, length)) {
            (void)tsc_disco_receive(&client->disco, &source,
                                    client->receive_buffer, length);
            continue;
        }
#endif
        /* Unauthenticated network input may be malformed, duplicated, or for
         * another protocol. Drop it without stopping application polling. */
        rc = receive_wireguard(client, &source, NULL,
                                 client->receive_buffer, length);
        if (!client->allow_traffic) return rc;
    }
    for (i = 0; i < TSC_MAX_PEERS; ++i) {
        if (!client->peers[i].active) continue;
        /* Proactive startup replaces a remote peer's stale session after our
         * process restarts with its persisted identity. Only authenticated
         * coordinator entries schedule this work; arbitrary UDP cannot. */
        if (client->peers[i].initiate_pending &&
            (client->peers[i].candidate_count || client->peers[i].has_endpoint ||
             client->relay_send)) {
            rc = tsc_wg_start(&client->wireguard, i, client->send_buffer,
                               sizeof(client->send_buffer), &length);
            if (rc == TSC_OK || rc == TSC_AGAIN)
                client->peers[i].initiate_pending = 0;
        } else {
            rc = tsc_wg_tick(&client->wireguard, i, client->send_buffer,
                              sizeof(client->send_buffer), &length);
        }
        if (rc == TSC_AGAIN) continue;
        if (rc != TSC_OK) return rc;
        if (length) {
            rc = transmit(client, i, client->send_buffer, length);
            if (rc < 0) return rc;
            activity = 1;
        }
    }
#if TSC_ENABLE_DISCO
    rc = tsc_disco_tick(&client->disco);
    if (rc < 0 && rc != TSC_ERR_PROTOCOL) return rc;
#endif
    return activity ? TSC_OK : TSC_AGAIN;
}

void tsc_client_set_ip_handler(tsc_client *client, tsc_ip_receive_fn receive,
                                void *user)
{
    if (!client || !client->initialized) return;
    client->ip_receive = receive;
    client->ip_user = user;
}

int tsc_client_send_ip(tsc_client *client, const void *packet, size_t length)
{
    const uint8_t *bytes = packet;
    size_t i, actual, written;
    int rc;
    if (!client || !client->initialized || !packet) return TSC_ERR_ARGUMENT;
    rc = current_map(client);
    if (rc != TSC_OK) return rc;
    rc = ipv4_envelope(bytes, length, &actual);
    if (rc != TSC_OK || actual != length || !transport_valid(bytes, length))
        return TSC_ERR_PROTOCOL;
    if (memcmp(bytes + 12, client->ipv4, 4) != 0) return TSC_ERR_ARGUMENT;
    for (i = 0; i < TSC_MAX_PEERS; ++i)
        if (client->peers[i].active && client->peers[i].has_ipv4 &&
            memcmp(bytes + 16, client->peers[i].ipv4, 4) == 0) break;
    if (i == TSC_MAX_PEERS) return TSC_AGAIN;
    rc = tsc_wg_encrypt(&client->wireguard, i, packet, length,
                         client->send_buffer, sizeof(client->send_buffer),
                         &written);
    if (rc == TSC_AGAIN || rc == TSC_WG_ERR_EXPIRED) {
        rc = tsc_wg_start(&client->wireguard, i, client->send_buffer,
                           sizeof(client->send_buffer), &written);
        if (rc != TSC_OK && rc != TSC_AGAIN) return rc;
        if (written) {
            rc = transmit(client, i, client->send_buffer, written);
            if (rc < 0) return rc;
        }
        return TSC_AGAIN;
    }
    if (rc != TSC_OK) return rc;
    rc = transmit(client, i, client->send_buffer, written);
    if (rc == TSC_OK) remember_flow(client, bytes, length);
    return rc;
}

#if TSC_APP_UDP
static int port_used(const tsc_client *client, uint16_t port)
{
    size_t i;
    for (i = 0; i < TSC_MAX_UDP_PORTS; ++i)
        if (client->udp_ports[i] && client->udp_ports[i]->port == port) return 1;
    return 0;
}

int tsc_udp_open(tsc_client *client, tsc_udp *socket, uint16_t port,
                  tsc_udp_receive_fn receive, void *user)
{
    size_t i;
    unsigned attempts;
    if (!client || !client->initialized || !socket || socket->client)
        return TSC_ERR_ARGUMENT;
    if (port && port_used(client, port)) return TSC_ERR_ARGUMENT;
    for (i = 0; i < TSC_MAX_UDP_PORTS && client->udp_ports[i]; ++i) {}
    if (i == TSC_MAX_UDP_PORTS) return TSC_ERR_SPACE;
    if (!port) {
        for (attempts = 0; attempts <= TSC_MAX_UDP_PORTS; ++attempts) {
            port = client->next_port++;
            if (client->next_port < 49152) client->next_port = 49152;
            if (!port_used(client, port)) break;
        }
        if (attempts > TSC_MAX_UDP_PORTS) return TSC_ERR_SPACE;
    }
    socket->client = client;
    socket->port = port;
    socket->receive = receive;
    socket->user = user;
    client->udp_ports[i] = socket;
    return TSC_OK;
}

void tsc_udp_close(tsc_udp *socket)
{
    size_t i;
    if (!socket || !socket->client) return;
    for (i = 0; i < TSC_MAX_UDP_PORTS; ++i)
        if (socket->client->udp_ports[i] == socket)
            socket->client->udp_ports[i] = NULL;
    for (i = 0; i < TSC_MAX_FLOWS; ++i)
        if (socket->client->flows[i].protocol == 17 &&
            socket->client->flows[i].local_port == socket->port)
            memset(&socket->client->flows[i], 0, sizeof(socket->client->flows[i]));
    memset(socket, 0, sizeof(*socket));
}

int tsc_udp_send(tsc_udp *socket, const tsc_endpoint *destination,
                  const void *payload, size_t length)
{
    tsc_client *client;
    size_t written;
    int rc;
    if (!socket || !socket->client || !destination || !destination->port ||
        (!payload && length)) return TSC_ERR_ARGUMENT;
    client = socket->client;
    if (destination->family != TSC_AF_IPV4) return TSC_ERR_UNSUPPORTED;
    rc = current_map(client);
    if (rc != TSC_OK) return rc;
    if (length > TSC_MTU - 28u) return TSC_ERR_SPACE;
    rc = tsc_packet_udp_encode(client->ipv4, destination->address, socket->port,
               destination->port, payload, length, client->next_identification++,
               client->packet_buffer, sizeof(client->packet_buffer), &written);
    if (rc != TSC_OK) return rc;
    return tsc_client_send_ip(client, client->packet_buffer, written);
}
#endif
#endif /* TSC_ENABLE_CLIENT */
