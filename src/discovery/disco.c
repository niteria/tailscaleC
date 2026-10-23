/* Portable implementation of Tailscale's discovery wire protocol.
 * Wire format: https://github.com/tailscale/tailscale/blob/main/disco/disco.go
 * Only authenticated, transaction-matched direct pong packets select paths. */
#include "tailscalec/disco.h"
#include "tailscalec/crypto.h"
#include "tailscalec/nacl.h"
#include <limits.h>
#include <string.h>

#if TSC_ENABLE_DISCO

#define DISCO_HEADER_SIZE 62u
#define DISCO_OVERHEAD (DISCO_HEADER_SIZE + TSC_NACL_BOX_MACBYTES)
#define DISCO_PING_SIZE 46u
#define DISCO_PONG_SIZE 32u
#define DISCO_CMM_SIZE (2u + 18u * TSC_MAX_PEER_ENDPOINTS)
#define DISCO_PACKET_SIZE (DISCO_OVERHEAD + DISCO_PING_SIZE + DISCO_CMM_SIZE)
#define DISCO_PROBE_TIMEOUT_MS 5000u
#define DISCO_TRUST_MS 6500u
#define DISCO_HEARTBEAT_MS 2000u
#define DISCO_RETRY_MS 5000u
static const uint8_t disco_magic[6] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t x = 0;
    for (size_t i = 0; i < n; ++i) x |= p[i];
    return x == 0;
}

static int endpoint_valid(const tsc_endpoint *ep) {
    if (!ep || !ep->port) return 0;
    if (ep->family == TSC_AF_IPV4) {
        /* Do not reflect probes to unspecified, multicast or broadcast hosts. */
        return ep->address[0] != 0 && ep->address[0] < 224;
    }
#if TSC_ENABLE_IPV6
    if (ep->family == TSC_AF_IPV6)
        return !all_zero(ep->address, 16) && ep->address[0] != 0xff;
#endif
    return 0;
}

static void endpoint_encode(uint8_t out[18], const tsc_endpoint *ep) {
    memset(out, 0, 18);
    if (!ep) return; /* Unspecified source for a relayed pong. */
    if (ep->family == TSC_AF_IPV4) {
        out[10] = 0xff; out[11] = 0xff;
        memcpy(out + 12, ep->address, 4);
    } else memcpy(out, ep->address, 16);
    out[16] = (uint8_t)(ep->port >> 8);
    out[17] = (uint8_t)ep->port;
}

static int endpoint_decode(tsc_endpoint *ep, const uint8_t in[18]) {
    static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    memset(ep, 0, sizeof(*ep));
    if (!memcmp(in, mapped, 12)) {
        ep->family = TSC_AF_IPV4;
        memcpy(ep->address, in + 12, 4);
    } else {
        ep->family = TSC_AF_IPV6;
        memcpy(ep->address, in, 16);
    }
    ep->port = (uint16_t)((uint16_t)in[16] << 8 | in[17]);
    return endpoint_valid(ep);
}

static tsc_disco_peer *find_node(tsc_disco *d, const uint8_t node[32]) {
    for (size_t i = 0; i < TSC_CLIENT_PEER_SLOTS; ++i)
        if (d->peers[i].active && !memcmp(d->peers[i].node_key, node, 32))
            return &d->peers[i];
    return NULL;
}

static tsc_disco_peer *find_disco(tsc_disco *d, const uint8_t key[32]) {
    for (size_t i = 0; i < TSC_CLIENT_PEER_SLOTS; ++i)
        if (d->peers[i].active && !memcmp(d->peers[i].disco_key, key, 32))
            return &d->peers[i];
    return NULL;
}

static void clear_peer_probes(tsc_disco *d, size_t index) {
    for (size_t i = 0; i < TSC_DISCO_MAX_PROBES; ++i)
        if (d->probes[i].active && d->probes[i].peer_index == index)
            tsc_crypto_zero(&d->probes[i], sizeof(d->probes[i]));
}

static uint64_t deadline(uint64_t now, uint64_t delay) {
    return now > UINT64_MAX - delay ? UINT64_MAX : now + delay;
}

static void expire(tsc_disco *d, uint64_t now) {
    for (size_t i = 0; i < TSC_DISCO_MAX_PROBES; ++i) {
        if (d->probes[i].active &&
            (now < d->probes[i].sent_ms ||
             now - d->probes[i].sent_ms >= DISCO_PROBE_TIMEOUT_MS))
            tsc_crypto_zero(&d->probes[i], sizeof(d->probes[i]));
    }
}

static int wrap(tsc_disco *d, const tsc_disco_peer *p,
                const uint8_t *plain, size_t length, uint8_t *packet) {
    int status;
    memcpy(packet, disco_magic, 6);
    memcpy(packet + 6, d->public_key, 32);
    status = d->platform.random_bytes(d->platform.user, packet + 38, 24);
    if (status != TSC_OK) return status < 0 ? status : TSC_ERR_IO;
    return tsc_nacl_box_afternm(packet + DISCO_HEADER_SIZE, plain, length,
                                packet + 38, p->shared_key);
}

int tsc_disco_init(tsc_disco *d, const tsc_platform *platform,
                   const tsc_disco_callbacks *callbacks,
                   const uint8_t private_key[32], const uint8_t node_key[32]) {
    if (!d || !platform || !platform->udp_send || !platform->random_bytes ||
        !platform->monotonic_ms || !private_key || !node_key ||
        all_zero(private_key, 32) || all_zero(node_key, 32)) return TSC_ERR_ARGUMENT;
    memset(d, 0, sizeof(*d));
    d->platform = *platform;
    if (callbacks) d->callbacks = *callbacks;
    memcpy(d->private_key, private_key, 32);
    memcpy(d->node_key, node_key, 32);
    int status = tsc_crypto_x25519_public(d->public_key, private_key);
    if (status != TSC_OK) tsc_disco_clear(d);
    return status;
}

void tsc_disco_clear(tsc_disco *d) {
    if (d) tsc_crypto_zero(d, sizeof(*d));
}

int tsc_disco_is_packet(const void *packet, size_t length) {
    return packet && length >= DISCO_HEADER_SIZE && !memcmp(packet, disco_magic, 6);
}

static int set_peer(tsc_disco *d, const uint8_t node[32],
    const uint8_t key[32], const tsc_endpoint *eps, size_t count, const uint8_t *cached) {
    uint8_t shared[32];
    if (!d || !d->platform.monotonic_ms || !node || !key ||
        all_zero(node, 32) || all_zero(key, 32) || (!eps && count))
        return TSC_ERR_ARGUMENT;
    if (count > TSC_MAX_PEER_ENDPOINTS) return TSC_ERR_SPACE;
    for (size_t i = 0; i < count; ++i)
        if (!endpoint_valid(&eps[i])) return TSC_ERR_ARGUMENT;
    tsc_disco_peer *p = find_node(d, node);
    tsc_disco_peer *same_key = find_disco(d, key);
    /* Ambiguous disco identities need node-key disambiguation; do not silently
     * give an authenticated packet to the wrong node. */
    if (same_key && same_key != p) return TSC_ERR_ARGUMENT;
    if (!p) {
        for (size_t i = 0; i < TSC_CLIENT_PEER_SLOTS; ++i)
            if (!d->peers[i].active) { p = &d->peers[i]; break; }
    }
    if (!p) return TSC_ERR_SPACE;
    int changed = !p->active || memcmp(p->disco_key, key, 32);
    if (changed) {
        int status = TSC_OK;
        if (cached) memcpy(shared, cached, sizeof(shared));
        else status = tsc_nacl_box_beforenm(shared, key, d->private_key);
        if (status != TSC_OK) return status;
        clear_peer_probes(d, (size_t)(p - d->peers));
        tsc_crypto_zero(p, sizeof(*p));
        memcpy(p->shared_key, shared, 32);
        tsc_crypto_zero(shared, sizeof(shared));
        memcpy(p->node_key, node, 32);
        memcpy(p->disco_key, key, 32);
        p->active = 1;
    }
    if (count) memmove(p->endpoints, eps, count * sizeof(*eps));
    p->endpoint_count = count;
    p->probe_cursor = 0;
    p->next_probe_ms = 0;
    return TSC_OK;
}

int tsc_disco_set_peer(tsc_disco *d, const uint8_t node[32],
    const uint8_t key[32], const tsc_endpoint *eps, size_t count) {
    return set_peer(d, node, key, eps, count, NULL);
}
int tsc_disco_set_peer_cached(tsc_disco *d, const uint8_t node[32],
    const uint8_t key[32], const tsc_endpoint *eps, size_t count, const uint8_t shared[32]) {
    if (!shared) return TSC_ERR_ARGUMENT;
    return set_peer(d, node, key, eps, count, shared);
}

int tsc_disco_remove_peer(tsc_disco *d, const uint8_t node[32]) {
    if (!d || !node) return TSC_ERR_ARGUMENT;
    tsc_disco_peer *p = find_node(d, node);
    if (!p) return TSC_AGAIN;
    clear_peer_probes(d, (size_t)(p - d->peers));
    tsc_crypto_zero(p, sizeof(*p));
    return TSC_OK;
}

int tsc_disco_endpoint(tsc_disco *d, const uint8_t node[32], tsc_endpoint *ep) {
    if (!d || !node || !ep || !d->platform.monotonic_ms) return TSC_ERR_ARGUMENT;
    tsc_disco_peer *p = find_node(d, node);
    if (!p || !p->has_best ||
        d->platform.monotonic_ms(d->platform.user) >= p->trusted_until_ms)
        return TSC_AGAIN;
    *ep = p->best_endpoint;
    return TSC_OK;
}

static size_t peer_quota(const tsc_disco *d) {
    size_t active_peers = 0;
    for (size_t i = 0; i < TSC_CLIENT_PEER_SLOTS; ++i) active_peers += d->peers[i].active != 0;
    size_t quota = TSC_DISCO_MAX_PROBES / active_peers;
    return quota ? quota : 1;
}

static int send_probe(tsc_disco *d, tsc_disco_peer *p,
                       const tsc_endpoint *destination, uint64_t now) {
    uint8_t plain[DISCO_PING_SIZE], packet[DISCO_OVERHEAD + DISCO_PING_SIZE];
    tsc_disco_probe_state *probe = NULL;
    size_t outstanding = 0, quota = peer_quota(d);
    for (size_t i = 0; i < TSC_DISCO_MAX_PROBES; ++i) {
        if (d->probes[i].active && d->probes[i].peer_index == (size_t)(p - d->peers) &&
            ((!destination && d->probes[i].via_relay) ||
             (destination && !d->probes[i].via_relay &&
              tsc_endpoint_equal(destination, &d->probes[i].destination))))
            return TSC_AGAIN; /* Do not fill the table with repeated probes. */
        if (d->probes[i].active && d->probes[i].peer_index == (size_t)(p - d->peers))
            ++outstanding;
        if (!d->probes[i].active && !probe) probe = &d->probes[i];
    }
    if (outstanding >= quota) return TSC_ERR_SPACE;
    if (!probe) return TSC_ERR_SPACE;
    plain[0] = 1; plain[1] = 0;
    int status = d->platform.random_bytes(d->platform.user, plain + 2, 12);
    if (status != TSC_OK) return status < 0 ? status : TSC_ERR_IO;
    memcpy(plain + 14, d->node_key, 32);
    status = wrap(d, p, plain, sizeof(plain), packet);
    if (status != TSC_OK) return status;
    memset(probe, 0, sizeof(*probe));
    memcpy(probe->txid, plain + 2, 12);
    probe->peer_index = (size_t)(p - d->peers);
    probe->sent_ms = now;
    probe->active = 1;
    probe->via_relay = destination == NULL;
    if (destination) {
        probe->destination = *destination;
        status = d->platform.udp_send(d->platform.user, destination, packet, sizeof(packet));
    } else status = d->callbacks.relay_send(d->callbacks.user, p->node_key, packet, sizeof(packet));
    if (status != TSC_OK) tsc_crypto_zero(probe, sizeof(*probe));
    return status;
}

int tsc_disco_probe(tsc_disco *d, const uint8_t node[32], int relay) {
    if (!d || !node || !d->platform.monotonic_ms) return TSC_ERR_ARGUMENT;
    tsc_disco_peer *p = find_node(d, node);
    if (!p) return TSC_ERR_ARGUMENT;
    uint64_t now = d->platform.monotonic_ms(d->platform.user);
    expire(d, now);
    int sent = 0, status, last_error = TSC_AGAIN;
    int trusted = p->has_best && now < p->trusted_until_ms;
    if (trusted || (p->has_best && !p->endpoint_count)) {
        status = send_probe(d, p, &p->best_endpoint, now);
        if (status == TSC_OK) ++sent; else last_error = status;
    }
    /* A trusted direct path only needs direct heartbeats/upgrade probes.
     * For an untrusted path, reserve an early slot for the relay probe. */
    int want_relay = relay && d->callbacks.relay_send && !trusted;
    int alternate = want_relay && peer_quota(d) == 1;
    if (alternate && p->relay_next) {
        status = send_probe(d, p, NULL, now);
        if (status == TSC_OK) ++sent; else last_error = status;
        want_relay = 0;
    }
    size_t start = p->endpoint_count ? p->probe_cursor % p->endpoint_count : 0;
    for (size_t n = 0; n < p->endpoint_count; ++n) {
        size_t i = (start + n) % p->endpoint_count;
        if (!(trusted && tsc_endpoint_equal(&p->best_endpoint, &p->endpoints[i]))) {
            status = send_probe(d, p, &p->endpoints[i], now);
            if (status == TSC_OK) {
                ++sent;
                p->probe_cursor = (i + 1) % p->endpoint_count;
            } else last_error = status;
        }
        if (want_relay) {
            status = send_probe(d, p, NULL, now);
            if (status == TSC_OK) ++sent; else last_error = status;
            want_relay = 0;
        }
    }
    if (want_relay) {
        status = send_probe(d, p, NULL, now);
        if (status == TSC_OK) ++sent; else last_error = status;
    }
    if (alternate && sent) p->relay_next = !p->relay_next;
    p->next_probe_ms = deadline(now, p->has_best && now < p->trusted_until_ms ?
                                    DISCO_HEARTBEAT_MS : DISCO_RETRY_MS);
    return sent ? TSC_OK : last_error;
}

int tsc_disco_tick(tsc_disco *d) {
    if (!d || !d->platform.monotonic_ms) return TSC_ERR_ARGUMENT;
    uint64_t now = d->platform.monotonic_ms(d->platform.user);
    expire(d, now);
    for (size_t n = 0; n < TSC_CLIENT_PEER_SLOTS; ++n) {
        size_t i = d->tick_cursor;
        d->tick_cursor = (d->tick_cursor + 1) % TSC_CLIENT_PEER_SLOTS;
        if (d->peers[i].active && now >= d->peers[i].next_probe_ms) {
            int status = tsc_disco_probe(d, d->peers[i].node_key, 1);
            return status == TSC_ERR_SPACE ? TSC_AGAIN : status;
        }
    }
    return TSC_AGAIN;
}

static int receive_inner(tsc_disco *d, const tsc_endpoint *source,
                          const uint8_t relay_node[32],
                          const uint8_t *packet, size_t length) {
    uint8_t plain[TSC_MAX_DATAGRAM_SIZE];
    if (!d || !d->platform.monotonic_ms || !packet ||
        (source && !endpoint_valid(source))) return TSC_ERR_ARGUMENT;
    if (length < DISCO_OVERHEAD + 2 || !tsc_disco_is_packet(packet, length))
        return TSC_ERR_PROTOCOL;
    if (length > TSC_MAX_DATAGRAM_SIZE) return TSC_ERR_SPACE;
    tsc_disco_peer *p = find_disco(d, packet + 6);
    if (!p || (relay_node && memcmp(relay_node, p->node_key, 32)))
        return TSC_ERR_PROTOCOL;
    int status = tsc_nacl_box_open_afternm(plain, packet + DISCO_HEADER_SIZE,
                  length - DISCO_HEADER_SIZE, packet + 38, p->shared_key);
    if (status != TSC_OK) return status;
    size_t n = length - DISCO_OVERHEAD;
    uint64_t now = d->platform.monotonic_ms(d->platform.user);
    if (plain[0] == 1) {
        if (n < 14) return TSC_ERR_PROTOCOL;
        /* Modern pings bind the disco sender to its advertised WireGuard key.
         * Older pings omit this optional key; trailing padding is allowed. */
        if (n >= 46 && !all_zero(plain + 14, 32) && memcmp(plain + 14, p->node_key, 32))
            return TSC_ERR_PROTOCOL;
        uint8_t pong[DISCO_PONG_SIZE], response[DISCO_OVERHEAD + DISCO_PONG_SIZE];
        pong[0] = 2; pong[1] = 0;
        memcpy(pong + 2, plain + 2, 12);
        endpoint_encode(pong + 14, source);
        status = wrap(d, p, pong, sizeof(pong), response);
        if (status != TSC_OK) return status;
        if (source) return d->platform.udp_send(d->platform.user, source,
                                                response, sizeof(response));
        return d->callbacks.relay_send ?
            d->callbacks.relay_send(d->callbacks.user, p->node_key,
                                     response, sizeof(response)) : TSC_ERR_UNSUPPORTED;
    }
    if (plain[0] == 2) {
        if (n < DISCO_PONG_SIZE) return TSC_ERR_PROTOCOL;
        expire(d, now);
        for (size_t i = 0; i < TSC_DISCO_MAX_PROBES; ++i) {
            tsc_disco_probe_state *probe = &d->probes[i];
            if (!probe->active || probe->peer_index != (size_t)(p - d->peers) ||
                memcmp(probe->txid, plain + 2, 12)) continue;
            if ((!source && !probe->via_relay) || (source && probe->via_relay))
                return TSC_AGAIN;
            if (source && !tsc_endpoint_equal(source, &probe->destination))
                return TSC_AGAIN;
            /* Each destination has an independent unpredictable transaction.
             * Consume it once, preventing captured pong replay from renewing
             * trust or choosing an endpoint that was never probed. */
            probe->active = 0;
            if (!source) return TSC_OK;
            uint64_t elapsed = now - probe->sent_ms;
            uint32_t rtt = elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
            if (!p->has_best || now >= p->trusted_until_ms ||
                tsc_endpoint_equal(source, &p->best_endpoint) || rtt <= p->best_rtt_ms) {
                int changed = !p->has_best || !tsc_endpoint_equal(source, &p->best_endpoint);
                p->best_endpoint = *source;
                p->best_rtt_ms = rtt;
                p->has_best = 1;
                p->trusted_until_ms = deadline(now, DISCO_TRUST_MS);
                p->next_probe_ms = deadline(now, DISCO_HEARTBEAT_MS);
                if (changed && d->callbacks.path_changed)
                    d->callbacks.path_changed(d->callbacks.user, p->node_key, source, rtt);
            }
            tsc_endpoint observed;
            if (d->callbacks.observed_endpoint && endpoint_decode(&observed, plain + 14))
                d->callbacks.observed_endpoint(d->callbacks.user, &observed);
            return TSC_OK;
        }
        return TSC_AGAIN; /* Unsolicited/replayed/expired pong. */
    }
    if (plain[0] == 3) {
        /* A direct CallMeMaybe is forbidden: it can solicit endpoint probes
         * without the authenticated DERP node-to-disco binding. */
        if (source) return TSC_ERR_PROTOCOL;
        if (plain[1] != 0 || (n - 2) % 18) return TSC_OK;
        size_t count = (n - 2) / 18;
        if (count > TSC_MAX_PEER_ENDPOINTS) return TSC_ERR_SPACE;
        for (size_t i = 0; i < count; ++i) {
            tsc_endpoint ep;
            if (!endpoint_decode(&ep, plain + 2 + i * 18)) continue;
            int exists = 0;
            for (size_t j = 0; j < p->endpoint_count; ++j)
                if (tsc_endpoint_equal(&p->endpoints[j], &ep)) { exists = 1; break; }
            if (!exists && p->endpoint_count < TSC_MAX_PEER_ENDPOINTS)
                p->endpoints[p->endpoint_count++] = ep;
        }
        return tsc_disco_probe(d, p->node_key, 0);
    }
    return TSC_ERR_UNSUPPORTED;
}

int tsc_disco_receive(tsc_disco *d, const tsc_endpoint *source,
                      const void *packet, size_t length) {
    if (!source) return TSC_ERR_ARGUMENT;
    return receive_inner(d, source, NULL, packet, length);
}

int tsc_disco_receive_relay(tsc_disco *d, const uint8_t relay_node[32],
                            const void *packet, size_t length) {
    if (!relay_node) return TSC_ERR_ARGUMENT;
    return receive_inner(d, NULL, relay_node, packet, length);
}

int tsc_disco_call_me_maybe(tsc_disco *d, const uint8_t node[32],
                            const tsc_endpoint *eps, size_t count) {
    uint8_t plain[DISCO_CMM_SIZE], packet[DISCO_OVERHEAD + DISCO_CMM_SIZE];
    if (!d || !node || (!eps && count)) return TSC_ERR_ARGUMENT;
    if (!d->callbacks.relay_send) return TSC_ERR_UNSUPPORTED;
    if (count > TSC_MAX_PEER_ENDPOINTS) return TSC_ERR_SPACE;
    tsc_disco_peer *p = find_node(d, node);
    if (!p) return TSC_ERR_ARGUMENT;
    plain[0] = 3; plain[1] = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!endpoint_valid(&eps[i])) return TSC_ERR_ARGUMENT;
        endpoint_encode(plain + 2 + 18 * i, &eps[i]);
    }
    size_t n = 2 + 18 * count;
    if (n + DISCO_OVERHEAD > TSC_MAX_DATAGRAM_SIZE) return TSC_ERR_SPACE;
    int status = wrap(d, p, plain, n, packet);
    if (status != TSC_OK) return status;
    return d->callbacks.relay_send(d->callbacks.user, p->node_key, packet,
                                    n + DISCO_OVERHEAD);
}

#endif /* TSC_ENABLE_DISCO */
